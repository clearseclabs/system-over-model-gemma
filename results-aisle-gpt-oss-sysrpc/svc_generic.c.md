# Scan: svc_generic.c

```json
[
  {
    "severity": "Critical",
    "title": "Null pointer dereference caused by missing check on taddr in svc_tp_create",
    "function": "svc_tp_create",
    "description": "The function calls uaddr2taddr(nconf,uaddr) to obtain a pointer to a struct netbuf, but it does not verify that the returned pointer is non‑NULL. If uaddr2taddr() fails (e.g., due to allocation failure or malformed address string), the subsequent dereference `bind.addr = *taddr;` will trigger a kernel panic, causing denial‑of‑service. Because the function runs in kernel context, the crash can impair all RPC services."
  },
  {
    "severity": "High",
    "title": "Unvalidated user‑supplied sockaddr passed to bindresvport in svc_tli_create",
    "function": "svc_tli_create",
    "description": "When a bind address is supplied, the buffer from the user‑provided `uaddr` is cast directly to `struct sockaddr *` and passed to `bindresvport()`. There is no length or sanity checking of the buffer contents. An attacker can craft a `uaddr` that yields a netbuf whose `buf` points to an object containing fewer bytes than a valid `struct sockaddr`. `bindresvport()` may read beyond the buffer boundary, corrupt kernel memory, and potentially allow arbitrary kernel code execution."
  },
  {
    "severity": "High",
    "title": "Missing allocation‑failure handling for strdup in svc_tli_create",
    "function": "svc_tli_create",
    "description": "The code duplicates the network ID string with `strdup(nconf->nc_netid, M_RPC)` and assigns the result to `xprt->xp_netid` without checking whether the allocation succeeded. If `strdup()` returns NULL, `xprt->xp_netid` becomes NULL; subsequent code that expects a valid pointer may dereference it, leading to a kernel fault. An attacker could force a memory‑pressure situation to trigger repeated allocation failures."
  },
  {
    "severity": "Medium",
    "title": "Potential logic error from improper success check on bindresvport",
    "function": "svc_tli_create",
    "description": "The code checks `if (bindresvport(so, NULL))` and treats a non‑zero return value as success, which contradicts the typical semantics of `bindresvport()` (zero indicates success). If an early failure is misinterpreted as success, the function may continue with an unbound socket, leading to unpredictable behavior or denial‑of‑service. While not a direct memory corruption, it can cause incorrect service registration."
  },
  {
    "severity": "Low",
    "title": "Negative queue length value passed to solisten",
    "function": "svc_tli_create",
    "description": "In the case where a bind address is supplied, the code sets `bind.qlen = -1` before passing it to `solisten()`. Negative values for queue length are non‑standard and may be misinterpreted by the kernel on certain platforms, potentially leading to under‑allocation or other unexpected behavior. Though unlikely to lead to code execution, it could destabilize the RPC subsystem."
  }
]
```