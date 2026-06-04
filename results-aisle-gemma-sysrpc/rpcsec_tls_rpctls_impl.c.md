# Scan: rpcsec_tls/rpctls_impl.c

### Security Analysis of `rpcsec_tls/rpctls_impl.c`

This file manages the interaction between the kernel's RPC layer and userspace TLS daemons. The primary attack surfaces are the `sys_rpctls_syscall` (called by daemons) and `_svcauth_rpcsec_tls` (triggered by network packets).

#### 1. Integer Overflow and Memory Exhaustion in `rpctls_server`
The function `rpctls_server` handles the result of an RPC call to the `rpctlssd` daemon. 
- **Data Flow:** `res.gid.gid_len` (from the userspace daemon) $\rightarrow$ `*ngrps` $\rightarrow$ `mem_alloc(*ngrps * sizeof(gid_t))`.
- **Vulnerability:** The value `res.gid.gid_len` is an `int` (or similar) provided by the RPC response. If the daemon is compromised or a malicious actor can spoof the RPC response, they can provide a very large value for `gid_len`.
- **Impact:** 
    1. **Integer Overflow:** If `*ngrps * sizeof(gid_t)` overflows, a small buffer will be allocated, but the subsequent `for` loop will write `*ngrps` elements into it, leading to a **kernel heap buffer overflow**.
    2. **DoS:** A large but non-overflowing value can lead to kernel memory exhaustion (DoS).

#### 2. Unchecked User-Provided Pointer in `sys_rpctls_syscall`
The syscall `sys_rpctls_syscall` takes `struct rpctls_syscall_args *uap` from userspace.
- **Data Flow:** `uap->socookie` is cast directly to `struct socket *` and used in `RB_FIND`.
- **Vulnerability:** While `RB_FIND` is relatively safe, the code relies on the `socookie` being a valid pointer that was previously inserted into the `upcall_sockets` tree. If an attacker can guess or leak a kernel pointer, they might influence the RB-tree lookup. More critically, the `uap` pointer itself is dereferenced without checking if it is a valid userspace address (though this depends on the `syscall_helper` framework's implementation of `uap` passing).
- **Impact:** Potential for kernel panic or exploitation if `uap` is invalid.

#### 3. Race Condition and Use-After-Free (UAF) in `sys_rpctls_syscall`
There is a complex interaction between the RB-tree and socket references.
- **Logic:** The code finds an `upsock` entry, removes it from the tree, and copies the structure to the stack: `ups = *upsp;`.
- **Vulnerability:** The comment states: *"The upsp points to stack of NFS mounting thread... the mounting thread may timeout the RPC and unroll its stack."*
- **Race:** If the mounting thread's stack is unrolled (destroying `upsp`) *after* `RB_FIND` succeeds but *before* `ups = *upsp;` completes, the kernel will perform a read from a stale stack frame (Use-After-Free). Although the `rpctls_lock` protects the tree, it does **not** protect the memory of the stack frame where the `upsock` structure actually resides.
- **Impact:** Kernel crash or potential information leak.

#### 4. Missing Type Validation for Union Access
The `struct upsock` uses a union for `CLIENT *cl` and `SVCXPRT *xp`.
- **Logic:** In `sys_rpctls_syscall`, the code checks `if (ups.server)` to determine which union member to access.
- **Vulnerability:** If the `server` boolean is corrupted or improperly initialized in the mounting thread's stack, the kernel will treat a `CLIENT` pointer as a `SVCXPRT` pointer (or vice versa) and attempt to lock `ups.xp->xp_lock`.
- **Impact:** Type confusion leading to an invalid memory access and kernel panic.

---

### Findings Summary

```json
[
  {
    "severity": "critical",
    "title": "Kernel Heap Overflow in rpctls_server",
    "function": "rpctls_server()",
    "description": "The function uses res.gid.gid_len from an RPC response to allocate memory for gids. An integer overflow in the multiplication (*ngrps * sizeof(gid_t)) can lead to a undersized buffer allocation, followed by a heap buffer overflow in the loop copying gid values."
  },
  {
    "severity": "high",
    "title": "Race Condition / Use-After-Free of Stack-Allocated upsock",
    "function": "sys_rpctls_syscall()",
    "description": "The upsock structure is allocated on the stack of a mounting thread. sys_rpctls_syscall removes it from a global RB-tree and then copies it to its own stack. There is a race window where the mounting thread may return and destroy its stack frame before the copy occurs, leading to a Use-After-Free."
  },
  {
    "severity": "medium",
    "title": "Kernel Memory Exhaustion (DoS)",
    "function": "rpctls_server()",
    "description": "Lack of upper-bound validation on res.gid.gid_len allows a malicious or compromised userspace daemon to trigger massive kernel memory allocations via mem_alloc, leading to a Denial of Service."
  }
]
```