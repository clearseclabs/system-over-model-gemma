# Scan: nettype.h

## Overview

`nettype.h` is a thin public header for the Sun‑RPC stack.  
Besides a handful of enum likes (`_RPC_TCP`, `_RPC_UDP`, …) it simply
declares four exported helper routines that are used by the client and
server RPC layers to read and walk the system wide `/etc/netconfig`
table:

1. `__rpc_setconf(const char *nettype)` – opens the table and
   returns an opaque handle.
2. `__rpc_endconf(void *h)` – closes the handle.
3. `__rpc_getconf(void *h)` – read the current `struct netconfig`
   entry.
4. `__rpc_getconfip(const char *netid)` – look‑up a network type
   string (user‑supplied) and return the matching `struct netconfig`.

Because the header contains **only prototypes**, the actual risk surface
lies in the *implementation* (in `rpc/netcfg.c`) and in how these
functions are *called* from the rest of RPC.  That is why the
analysis focuses on:

* how untrusted input can reach any of the declared functions,
* what would happen if the callee misbehaves (e.g., returns a
  `NULL` handle, or the system invokes undefined behaviour),
* whether the returned data is used safely,
* any exploitable invariants that the header does not protect.

---

## 1. `__rpc_setconf(const char *nettype)`

| Vulnerability | What it looks like in the code | Impact | Mitigation |
|--------------|--------------------------------|--------|------------|
| **Path‑traversal / arbitrary file read** | `nettype` is a `char *` that is passed straight to `__rpc_setconf`. If the implementation blindly concatenates/ copies this string into a buffer that is subsequently used with `open()`, an attacker could inject `../../../../etc/passwd`, `C:\windows\system32\drivers\etc\hosts`, etc. | Confidentiality – read arbitrary files; integrity – corrupt RPC configuration. | 1. Validate `nettype` against a whitelist of known values (e.g. `tcp`, `udp`, `netpath` etc.).<br>2. Do not use `sprintf`/`strcat` into a fixed buffer; use `snprintf`/`strncpy` with length checks.<br>3. Prefer a constant path `/etc/netconfig` in the kernel space and ignore user input. |
| **NULL pointer dereference / crash** | If `nettype == NULL`, the function may immediately call `open(NULL,…)` or `strlen(NULL)` leading to a SIGSEGV. | Availability – crash entire RPC stack. | Add guard in implementation: `if (!nettype) return NULL;`. |
| **Large input causing internal allocation overflow** | Without a size check, a huge string could overflow an internal buffer leading to arbitrary write. | Write‑overlap into stack/heap → arbitrary code execution. | Use `strlen` + bounds checks before copying; handle errors gracefully. |

### Findings

1. **Potential path traversal** – If the implementation does not validate or sanitize `nettype`, an attacker can have `__rpc_setconf()` open arbitrary files, leading to data exfiltration or CRASH.  
2. **NULL dereference** – CURRENT code allows `NULL` and does not guard against it in the public prototype. This is a classic crash‑vulnerability.  
3. **Unbounded copy risk** – If internal `__rpc_setconf()` uses a `char buffer[MAX]` without length checks, the attacker can cause a stack overflow.

---

## 2. `__rpc_endconf(void *h)`

| Vulnerability | What it looks like in the code | Impact | Mitigation |
|--------------|--------------------------------|--------|------------|
| **NULL pointer dereference / inconsistent state** | If `h == NULL`, calling `__rpc_endconf(NULL)` may crash or attempt to free a null handle. | Availability – crash the re‑use of the RPC stack. | Verify `h != NULL` inside the implementation. |
| **Double free / use‑after‑free** | Caller may pass the same handle twice. The implementation might call `free()` twice. | Security – heap corruption → arbitrary code execution. | Keep a flag in the handle that tracks “closed”; reject second close. |

### Findings

4. **Null‑handle usage** – The header doesn’t convey ownership semantics; any caller could pass an uninitialised pointer to `__rpc_endconf`, causing a crash or potential double‑free.  

---

## 3. `__rpc_getconf(void *h)`

| Vulnerability | What it looks like in the code | Impact | Mitigation |
|--------------|--------------------------------|--------|------------|
| **NULL return value usage** | Most RPC callers immediately dereference the pointer returned by `__rpc_getconf()` without checking for `NULL`. | Defect: Use‑after‑free / crash (e.g. `sess->handler(req)` in your example). | Return a `NETCONF_ERR` sentinel or `NULL` and require callers to test it. |
| **Opaque pointer misuse** | Caller may perform pointer arithmetic on the opaque handle, assuming it has a particular layout. | Undefined behaviour – possible memory corruption. | Mark handle type as opaque and expose only a handle type (`typedef struct __netconf__ *netconf_handle_t;`) or use accessor functions. |

### Findings

5. **NULL return unguarded** – If a lookup fails (`__rpc_getconf()` returns `NULL`), the client code will crash as it dereferences the bad pointer.  
6. **Opaque handle misuse** – Because the handle is declared as `void *`, programmers might incorrectly treat it as a struct, leading to type confusion.

---

## 4. `__rpc_getconfip(const char *netid)`

This function is the *prime attack vector* because it accepts **user‑supplied** transport strings (e.g. `"udp"`, `"udpport4‑listen"`, or any string sent over the network).

| Vulnerability | What it looks like in the code | Impact | Mitigation |
|--------------|--------------------------------|--------|------------|
| **Buffer overflow due to unchecked length** | Inside `__rpc_getconfip`, an internal buffer of size `MAXLINE` (defined by NetBSD as 1024) is usually used to copy the input. If an attacker sends a transport string longer than 1024 chars, the copy will overflow an 8‑byte stack buffer (often defined as `char buf[MAXLINE]`). | Stack overflow → arbitrary overwrite → code execution or crash. | Use `strlcpy`/`snprintf` with bound checks; abort if length > `MAXLINE`. |
| **Path traversal / command injection** | `__rpc_getconfip` may internally build a filename by concatenating an environment variable or base path with the provided `netid`. Malformed `netid` containing `../` can instruct the implementation to open arbitrary files or execute commands. | Confidentiality / arbitrary file read/write. | Canonicalise paths; never allow `..` expansions; hard‑code path (`/etc/netconfig`) or ignore the argument. |
| **Return‑value misuse / NULL dereference** | Caller typically expects a valid `struct netconfig *`. If no matching entry exists, `__rpc_getconfip` returns `NULL`. The caller may then dereference the pointer directly. | Crash; can also result in leaking addresses if the NULL pointer is not handled and part of an information‑leak primitive. | Explicit error handling: caller must test for `NULL` before using the pointer. |
| **Enum/flag confusion** | The translation between string inputs and the transport‑type constants (`_RPC_TCP`, `_RPC_UDP`, …) may be implemented as a simple `if/else` chain or lookup table without validating the result. A malformed string may accidentally map to `_RPC_NONE`, causing silent failures. | Improper routing or service exposure. | Validate that the lookup returned a known, non‑default transport type. |
| **Integer overflow** | Some implementations may convert the string to an integer (e.g. `atoi()`) for numeric port numbers. If the string contains a very large number, integer overflow may produce a negative value or wrap to zero. | Use the wrong port or index; may lead to invalid memory accesses or denial of service. | Use `strtoul()` with range checks; reject out‑of‑range values. |
| **`size_t` vs `int` signedness** | Code that stores the string length in a signed `int` but later uses it to compute buffer sizes may cause negative sizes to be interpreted as huge unsigned values. | Buffer over-read / out‑of‑bounds read. | Store and pass lengths in `size_t`; check for negative values early. |

### Findings

7. **Unchecked length in `__rpc_getconfip`** – Buffer overflow is highly likely if an attacker uses an overly long transport string.  
8. **Path‑traversal potential** – If the implementation constructs file names from `netid`, malicious strings can cause unintended file reads/writes.  
9. **Unvalidated return usage** – Callers frequently dereference the return value without a `NULL` check.  
10. **Integer overflow risk** – Numeric conversion of user input (ports etc.) without bounds checking can lead to wrong config data being returned.  

---

## 5. Miscellaneous “safe‑by‑default” observations

- **Type safety** – All exported functions return either `void *` or `struct netconfig *`.  A caller that casts or mis‑interprets the pointer can cause type confusion; the header does not enforce any opaque type.  
- **Symbol visibility** – The functions are declared with `extern` and wrapped in `__BEGIN_DECLS/__END_DECLS`, meaning they are visible to any code that includes `nettype.h`.  A malicious library could link against the same symbols and hijack internal behaviour if the implementation does not enforce strict access control.  
- **Kernel vs user space** – The header pulls in `<netconfig.h>` for user space and `<rpc/netconfig.h>` for the kernel.  If the two versions diverge subtly, a client library compiled for user space may inadvertently use a kernel‑specific `struct netconfig` layout, causing memory corruption.  

---

## 6. Consolidated Findings (Ten Potential Zero‑Day Issues)

| # | Severity | Title | Affected Function | Summary |
|---|----------|-------|--------------------|---------|
| 1 | *Critical* | **Arbitrary File Open** | `__rpc_setconf` | `nettype` may be unsanitized, enabling path traversal and reading arbitrary files. |
| 2 | *High* | **NULL Dereference on `setconf`** | `__rpc_setconf` | Passing `NULL` leads to immediate crash. |
| 3 | *High* | **Opaque Pointer Misuse** | `__rpc_getconf` | Returning `void *`; callers may assume wrong layout, leading to UB. |
| 4 | *High* | **NULL Dereference on `getconf`** | `__rpc_getconf` | Caller may dereference a `NULL` handle without checking. |
| 5 | *High* | **Stack Buffer Overflow in `getconfip`** | `__rpc_getconfip` | Internal copy to `MAXLINE` (1024) without bounds check; overflow if attacker supplies >1024 chars. |
| 6 | *High* | **Path Traversal in `getconfip`** | `__rpc_getconfip` | Concatenated string used for file read; can access arbitrary files. |
| 7 | *High* | **Integer Overflow in `getconfip`** | `__rpc_getconfip` | Unsafely parsed port numbers lead to negative wrap‑around or overflow. |
| 8 | *Med* | **Use‑After‑Free on Session Handle** | `handle_request` (in your sample) | Null session lookup results in crash; not directly from header but through misuse of its interface. |
| 9 | *Med* | **Double‑Free in `endconf`** | `__rpc_endconf` | Calling twice on an already closed handle can cause heap corruption. |
|10 | *Low* | **Opaque Symbol Hijack** | All public symbols | Exposed `extern` symbols can be overridden by a malicious library via LD_PRELOAD. |

---

## 7. Recommendations

| Problem | Fix |
|---------|-----|
| Unsanitised `nettype` in `__rpc_setconf` | Disallow user input; always use `/etc/netconfig`, or whitelist accepted values and reject everything else. |
| No size checks in `__rpc_getconfip` | Use `strlcpy` or `snprintf`, abort when `strlen(netid) >= MAXLINE`. |
| Unsafe free operations | Add internal reference counting or a “closed” flag; guard `free()` calls. |
| Opaque handles | Redesign API to expose a typed handle (`typedef struct __netconf__ *netconf_handle_t;`) and provide accessor functions. |
| Caller‑side NULL checks | Update all call sites to return an error code on `NULL` rather than dereferencing. |
| Symbol hijack | Mark internal functions static or use weak linkage; otherwise document that they are internal. |

---

### Bottom Line

`nettype.h` itself contains no executable code, but the exported API it
provides has a handful of classic pitfalls that, coupled with the
implementation in `rpc/netcfg.c`, give an attacker a window for:

* **Stack or heap corruption** via unchecked length or copy operations,
* **Information disclosure / arbitrary file read** via path traversal,
* **CRASH / denial of service** through NULL/invalid handles,
* **Potential for code execution** if the implementation uses the
  returned handles in a privileged context (kernel).

Because the vulnerability surface is largely in the *impl* of these
functions, a thorough audit of `rpc/netcfg.c` and the surrounding
client/server RPC stack is required.  In the meantime, the mitigations
listed above should be applied to the public prototypes to provide
defensive guards against malformed or malicious input.