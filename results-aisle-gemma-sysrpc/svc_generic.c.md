# Scan: svc_generic.c

### Security Analysis: `svc_generic.c`

The analyzed code implements the server-side setup for RPC transport handles. The primary security concerns center around the handling of network addresses and the lifecycle of kernel-allocated memory.

#### 1. Null Pointer Dereference in `svc_tp_create`
In `svc_tp_create`, the function calls `uaddr2taddr(nconf, uaddr)` to convert a user-provided address string into a `netbuf` structure.
```c
taddr = uaddr2taddr(nconf, uaddr);
bind.addr = *taddr; // <--- Potential NULL dereference
```
If `uaddr2taddr` fails (e.g., due to a malformed `uaddr` string or invalid `nconf` configuration), it typically returns `NULL`. The code immediately dereferences `taddr` to assign it to `bind.addr` without checking if the pointer is valid. This would result in a kernel panic (NULL pointer dereference) if an attacker can provide a malformed address string.

#### 2. Memory Leak in `svc_tli_create`
In `svc_tli_create`, if `nconf` is valid, the code allocates memory for `xprt->xp_netid` using `strdup`:
```c
if (nconf) {
    xprt->xp_netid = strdup(nconf->nc_netid, M_RPC);
}
return (xprt);
```
While this is the end of the function, if `xprt` is later released or unregistered via `xprt_unregister` or `SVC_RELEASE` (as seen in `svc_tp_create`), the code must ensure that `xp_netid` is explicitly freed. If the `SVCXPRT` destructor does not handle `xp_netid`, this leads to a kernel memory leak.

#### 3. Signedness/Integer Issues in `solisten`
In `svc_tli_create`, the `bindaddr->qlen` is passed to `solisten`:
```c
solisten(so, (int)bindaddr->qlen, curthread);
```
In `svc_tp_create`, `bind.qlen` is explicitly set to `-1`:
```c
bind.qlen = -1;
```
While many socket implementations treat `-1` as a signal to use a system default, if the underlying `solisten` implementation treats the second argument as an unsigned integer or performs bounds checking against a signed integer without handling negatives, this could lead to unexpected behavior or the allocation of an enormous listen queue, potentially consuming excessive kernel resources (DoS).

#### 4. Potential Use-After-Free / Double-Free Risk
In `svc_tp_create`:
```c
taddr = uaddr2taddr(nconf, uaddr);
bind.addr = *taddr;
free(taddr, M_RPC);
// ...
free(bind.addr.buf, M_RPC);
```
This pattern assumes that `uaddr2taddr` allocates a `netbuf` structure and that the `netbuf` structure contains a pointer `buf` which is also independently allocated. If `uaddr2taddr` returns a structure where `buf` points into the memory of `taddr` itself, the second `free` is a use-after-free or double-free. Based on standard RPC implementations, `buf` is usually a separate allocation, but this remains a fragile dependency on the internal implementation of `uaddr2taddr`.

### Findings

```json
[
  {
    "severity": "critical",
    "title": "Kernel Panic via NULL Pointer Dereference",
    "function": "svc_tp_create()",
    "description": "The return value of uaddr2taddr() is not checked for NULL before being dereferenced. A malformed uaddr string causing uaddr2taddr to fail will result in a kernel panic."
  },
  {
    "severity": "medium",
    "title": "Potential Kernel Memory Leak",
    "function": "svc_tli_create()",
    "description": "xprt->xp_netid is allocated via strdup() at the end of the function. If the SVCXPRT cleanup routine does not specifically free this member, it results in a memory leak."
  },
  {
    "severity": "low",
    "title": "Unsigned/Signed Mismatch in Listen Queue",
    "function": "svc_tli_create()",
    "description": "The qlen value (set to -1 in svc_tp_create) is cast to int and passed to solisten(). Depending on the socket implementation, this may lead to incorrect queue sizing or resource exhaustion."
  }
]
```