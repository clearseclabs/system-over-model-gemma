# Scan: rpcsec_tls/rpctls_impl.c

**Context & Structure**

`rpcsec_tls/rpctls_impl.c` implements the user‐space side of the RPC‑over‑TLS (STARTTLS) helper.  
The module exposes the `sys_rpctls_syscall` kernel interface and a group of helper RPC wrappers (`rpctls_connect`, `rpctls_cl_handlerecord`, etc.).  All TLS‑specific constants (e.g., `RPCTLS_FLAGS_HANDSHFAIL`, `RPCTLS_START_STRING`) are supplied by `<rpc/rpcsec_tls.h>` and `<rpc/rpc_com.h>`, which are not part of this repository but are guaranteed by the official FreeBSD headers.  

The code maintains a *red‑black tree* of `upsock` records (`upcall_sockets`) that map a **socket‐cookie** (opaque pointer) to a running upcall (client or server).  All RSA‑style public interfaces acquire `rpctls_lock` before manipulating the tree and hold the lock across the kernel‑to‑daemon RPC calls that drive the TLS handshake.  

Untrusted input (everything that originates from the user or from a protocol stream) is carried in the following parameters:

| Function | Parameters that come from an untrusted source | Where the data flows |
|----------|----------------------------------------------|--------------------|
| `sys_rpctls_syscall` | `uap->socookie` | Cast to a `struct socket *` and used as a key in the RB tree. |
| `rpctls_connect` | `certname` (string), `so` | Sent to the local daemon via `rpctlscd_connect_2`. |
| `rpctls_*_handlerecord / *\_disconnect` | `socookie` (pointer) | Cast to `uint64_t` and passed to the daemon. |
| `rpctls_server` | `xprt` (SVCXPRT), `res` from daemon | The daemon may supply a huge `res.gid.gid_len`. |

All other helper functions are `static` and only use data that is locally owned or returned from trusted RPC calls.  

---

### Sensitive Code Path Analysis

Below we examine each exposed function and the risk of **invalid data → unchecked buffer use / integer overflow / unchecked discriminants**.  
We use the checklist given in the prompt.

---

#### 1. `sys_rpctls_syscall`

```
upsp = RB_FIND(upsock_t, &upcall_sockets,
    &(struct upsock){ .so = (struct socket *)(uintptr_t)uap->socookie });
```

| Risk | Evidence | Impact |
|------|----------|--------|
| **Invalid user‑supplied pointer** | `uap->socookie` can be any 64‑bit value; the code casts it to a `struct socket *` before tree lookup. | If a forged cookie points to a non‑existent socket, `RB_FIND` simply fails and the function returns `EPERM`. No memory corruption – defensive. |
| **NULL pointer deref** | The returned key is built on the stack; no dereference happens unless `upsp != NULL`. | Safe. |
| **Race / double delete** | The RB tree manipulation is guarded by `rpctls_lock`.  However, the upcall socket is removed *before* the kernel file descriptor is allocated.  If an attacker can kill the daemon (or cause a hang) after lookup but before `soref()`/`falloc()` finishes, `ups.so` may subsequently be freed elsewhere. | Subtle but unlikely; the code calls `soclose(ups.so)` only on failure, which is conservative. |
| **Unbounded recursion/stack overflow** | None. | – |

> **Verdict** – *No direct buffer overflow, but the cookie is completely unmanaged. A rogue caller could craft *any* value, causing repeated EPERM replies. This is a denial‑of‑service (DoS) rather than an exploitable crash.*

---

#### 2. `rpctls_connect`

```
if (certname != NULL) {
    arg.certname.certname_len = strlen(certname);
    arg.certname.certname_val = certname;
}
```

| Risk | Evidence | Impact |
|------|----------|--------|
| **OOB read / page fault** | `strlen` walks the string until a NUL terminator.  No bounds checking is performed. | If an attacker (or a bug in a caller) passes a pointer to non‑paged memory, the kernel will fault, crashing the process that invoked the helper (likely the NFS daemon). |
| **Integer overflow in length passing** | `arg.certname.certname_len` is a 32‑bit integer.  If the real length were >2³¹‑1, it would wrap. | The daemon might treat it as a huge length, allocating massive memory → DoS. |
| **Buffer overflow in the caller’s buffer copy** | The string is never copied into a fixed‑size buffer in this module. | – |

> **Verdict** – *If `rpctls_connect` can be called by untrusted code (e.g., a faulty NFS mount), a crafted `certname` can crash the kernel by causing a page fault inside `strlen`. Even if only internal, an externally exploited local process is still feasible.*

---

#### 3. `rpctls_cl_handlerecord`, `rpctls_srv_handlerecord`, `rpctls_cl_disconnect`, `rpctls_srv_disconnect`

All four functions simply cast a `void *socookie` to a 64‑bit integer and forward it to the local daemon.

| Risk | Evidence | Impact |
|------|----------|--------|
| **Wrong data type** | The kernel expects a real socket pointer; if the caller passes an arbitrary pointer, the daemon receives nonsense. | The daemon will silently ignore or mis‑handle the call. No kernel crash. |
| **No copies into static buffers** | None. | – |

> **Verdict** – *Benign unless the daemon reacts badly to bogus data, which would be a local bug.*

---

#### 4. `rpctls_rpc_failed`

```
if (RB_FIND(upsock_t, &upcall_sockets, ups)) {
    removed = RB_REMOVE(upsock_t, &upcall_sockets, ups);
    ...
    soclose(so);
}
```

| Risk | Evidence | Impact |
|------|----------|--------|
| **Use‑after‑free of `so`** | The socket is removed from the tree *before* it is closed.  If the socket is simultaneously closed elsewhere (e.g., by the daemon or the caller), `soclose` may on a stale reference. | Potential double‑free → memory corruption.  However, all calls to `soclose` are wrapped in `rpctls_lock`, and `soshutdown` is used when the socket is already taken. The race window is small. |
| **Unexpected `upsock` pointer** | If a rogue caller passes a malicious `ups` that contains an arbitrary `so` pointer, `RB_FIND` will look for it.  If `ups` *does not* exist in the tree, the `else` block will do a `soshutdown(so, SHUT_RD)`. | Still no memory corruption – the socket is simply closed by the caller. |
> **Verdict** – *Low probability of crash, but a missing lock upgrade guard in edge cases can expose a double‑free.*

---

#### 5. `rpctls_server`

```
*ngrps = res.gid.gid_len;
*gids = gidp = mem_alloc(*ngrps * sizeof(gid_t));
gidv = res.gid.gid_val;
for (i = 0; i < *ngrps; i++)
        *gidp++ = *gidv++;
...
mem_free(res.gid.gid_val, 0);
```

| Risk | Evidence | Impact |
|------|----------|--------|
| **Integer overflow in allocation** | `*ngrps * sizeof(gid_t)` is done in `size_t`.  If `*ngrps` is > SIZE_MAX/sizeof(gid_t)` it wraps.  The `mem_alloc` would allocate a small buffer, but the subsequent loop writes far beyond it, corrupting adjacent kernel memory. | *Critical* – leads to arbitrary read/write in kernel space, exploitable for privilege escalation.  The attacker can control `*ngrps` via a malicious return from the local daemon (which the attacker could compromise or tamper with). |
| **Out‑of‑bounds read/writes** | Even without overflow, the loop does not verify that `res.gid.gid_val` supplies at least `*ngrps` elements.  If the daemon returns a smaller `gid_len`, the loop will read beyond the supplied data. | Corrupted memory or information leak. |
| **Unchecked return value of `rpctlssd_connect_2`** | If `stat != RPC_SUCCESS`, the block is skipped, but the function still proceeds to call `mem_free(res.gid.gid_val, 0)`.  Since `res.gid.gid_val` would be NULL, `mem_free` is benign. | – |
| **Resource leak / DoS** | If the daemon sends an enormously large `gid_len`, allocation may hog memory and block the stack. | **Denial‑of‑service** (DoS). |
> **Verdict** – *The most serious potential bug: integer overflow + unchecked array copy.  If the local daemon can be controlled, an attacker can cause a known kernel memory corruption or privilege escalation.*

---

#### 6. `_svcauth_rpcsec_tls`

This is the server‑side authentication handler invoked for the NULL‑RPC with `AUTH_TLS`.  All parameters are supplied by the RPC framework and therefore are *trusted*.

| Risk | Evidence | Impact |
|------|----------|--------|
| **Long strings in `rpctls_null_verf`** | `oa_length` set to `strlen(RPCTLS_START_STRING)`.  If the start string were unusually long, the RPC framework might treat it as a large opaque payload.  No direct buffer overflow in this module. | Potential DoS due to huge buffer copy on the client, but not a kernel exploit. |
> **Verdict** – *No kernel‑space vulnerability, only minor DoS possibility.*

---

#### 7. `rpctls_getinfo`

```
kernel_sysctlbyname(curthread, "kern.ipc.tls.enable", &enable, &siz, NULL, 0, NULL, 0);
kernel_sysctlbyname(curthread, "kern.ipc.tls.maxlen", &maxlen, &siz, NULL, 0, NULL, 0);
```

| Risk | Evidence | Impact |
|------|----------|--------|
| **Unvalidated `siz` values** | `siz` is set to `sizeof(enable)` / `sizeof(maxlen)` before calling.  The function receives it by reference and may change it.  If a malicious kernel hook returned a value > expected, later dereference (`*maxlenp`) may be out of bounds. | Still safe – the dereference is on `maxlenp` supplied by the caller; this pointer is user‑controlled? No, it's a stack pointer from the caller so safe. |
| **No buffer overflow** | None. | – |

> **Verdict** – *Safe.*

---

### Summary of High‑Risk Findings

| Severity | Title | Function | Description |
|----------|-------|----------|-------------|
| **Critical** | Integer overflow + unchecked array copy in `rpctls_server` | `rpctls_server()` | The multiplier `*ngrps * sizeof(gid_t)` is unchecked; a malicious daemon that reports a huge `gid_len` can cause overflow and buffer overwrite when copying *gidp*.  This yields arbitrary kernel memory corruption. |
| **High** | OOB read in `rpctls_connect` due to unchecked `strlen` | `rpctls_connect()` | `certname` is dereferenced blindly; an attacker that calls this helper with a non‑paged or non‑NULL‑terminated string can crash the kernel. |
| **Medium** | Unchecked user cookie in `sys_rpctls_syscall` | `sys_rpctls_syscall()` | Any arbitrary 64‑bit value can be used as a socket cookie, causing lookup failures and possible double free race.  Primarily a DoS vector. |
| **Medium** | Optionally unchecked `res.gid.gid_len` array read in `rpctls_server` | `rpctls_server()` | Even without integer overflow, reading *ngrps* entries when less than that were returned can corrupt memory. |
| **Low** | Potential double‑free and race in `rpctls_rpc_failed` | `rpctls_rpc_failed()` | Locking mitigates but a race between `RB_REMOVE` and `soclose` may lead to double free. |

---

### Recommendations

1. **Defend against integer overflow**  
   - Replace `mem_alloc(*ngrps * sizeof(gid_t))` with a checked multiply (e.g., `size_t bytes = *ngrps * sizeof(gid_t); if (bytes / sizeof(gid_t) != *ngrps) return -EFAULT;`).  
   - Verify that `*ngrps` does not exceed a sane upper bound (e.g., `MAX_GIDS`).

2. **Validate incoming UTF‑8/packet data**  
   - In `rpctls_connect`, drop the call to `strlen(certname)` in the kernel; instead let the daemon perform the length check or copy the string into a pre‑allocated buffer of a known maximum size.  
   - Reject a `certname` that is > `MAX_CERTNAME_LEN` or contains illegal characters.

3. **Guard against bad cookies**  
   - Add a hash/validation step before `RB_FIND`: require that `uap->socookie` is a valid socket pointer (`socket_is_ok` or similar).  
   - If lookup fails, return `EINVAL` rather than `EPERM` to avoid leaking whether the socket existed.

4. **Race‑free removal**  
   - In `rpctls_rpc_failed`, perform `RB_REMOVE` inside the lock and only call `soclose` after confirming that the socket is still owned by the daemon.  
   - Consider using `so->so_refcnt` checks or marking the socket as “closed by daemon” before freeing.

5. **Input validation for remote daemon responses**  
   - Treat all data returned from the local daemon as potentially untrusted.  Verify that `res.flags`, `res.gid.gid_len`, and other fields lie within expected ranges before using them.

With these mitigations the module would be safe against the main memory‑corruption avenues the current implementation leaves open.