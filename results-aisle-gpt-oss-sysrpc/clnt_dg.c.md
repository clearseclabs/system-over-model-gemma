# Scan: clnt_dg.c

```json
[
  {
    "severity":"Critical",
    "title":"Unbounded memcpy of svcaddr during clnt_dg_create()",
    "function":"clnt_dg_create",
    "description":"The RPC client address supplied by the caller is copied into the kernel‑only field `cu->cu_raddr` via\n\n    memcpy(&cu->cu_raddr, svcaddr, (size_t)svcaddr->sa_len);\n\n`svcaddr->sa_len` originates from userland and is not bounded to the size of a `sockaddr_storage`.  An attacker can pass a very large value causing the memcpy to write past the 128‑byte buffer that `cu_raddr` occupies, corrupting arbitrary kernel memory (including the `cs` or `cl` structures) and providing a path to privilege escalation or denial‑of‑service.\n  \n  The same unchecked length is later stored in `cu->cu_rlen` and used for copy operations in `clnt_dg_control()` (see local copy of the socket address), further widening the impact.\n  \n  Fix: Validate `svcaddr->sa_len <= sizeof(cu->cu_raddr)` (or `sizeof(sockaddr_storage)`) before copying and reject the request otherwise.\n  \n  Threat model: An unprivileged user running an RPC client shim could construct a malicious `struct sockaddr` to overwrite kernel memory.\n  \n  Expected impact: Elevation of privilege or complete system compromise.\n  ",
    "impact":"Remote attacker can overflow a 128‑byte buffer in the kernel that stores the RPC client’s remote address."
  },
  {
    "severity":"High",
    "title":"Potential overflow in clnt_dg_control() CLGET_SVC_ADDR",
    "function":"clnt_dg_control",
    "description":"When the user requests the socket address via `CLGET_SVC_ADDR`, the code blindly copies `cu->cu_raddr.ss_len` bytes into the user‑supplied buffer:\n\n    memcpy(info, &cu->cu_raddr, cu->cu_raddr.ss_len);\n\nIf the caller passes a buffer that is smaller than that length (e.g., a stacked `struct sockaddr_in` that only expects 16 bytes), the function will write beyond the supplied buffer, corrupting user space memory and potentially leading to a crash or information leak.\n  \n  Fix: Pass the size of the destination buffer from the caller and perform a length check (`min(destsz, cu->cu_raddr.ss_len)`), or provide a fixed sized copy.\n  \n  Threat model: A malformed RPC client can crash or read adjacent memory of the process calling `clnt_control()`.\n  ",
    "impact":"Buffer overflow in user process memory."
  },
  {
    "severity":"High",
    "title":"Marshalled arguments may overflow the initial mbuf header in clnt_dg_call()",
    "function":"clnt_dg_call",
    "description":"`clnt_dg_call()` allocates a single mbuf header via `m_gethdr()`, which provides a payload space of `MHLEN` bytes.  It then calls `AUTH_MARSHALL()` (which internally uses XDR to encode the user supplied `args`), writing directly into the same mbuf chain without ensuring that the data fits within `MHLEN`.  If the marshalled argument set is larger than `MHLEN`, the XDR implementation will likely allocate new mbufs, but the initial header’s `m_len` is still set to `cu_mcalllen` and later the socket send operation may experience an inconsistent packet length or even truncate the data.\n\n  Even more critically, when sending the packet `sosend()` is called with the mbuf chain that may now contain payload beyond the originally allocated header, causing `sosend()` to process an unexpectedly large packet and potentially overflow network buffers or trigger kernel memory corruption.\n\n  Fix: Use `m_getcl()` to allocate enough mbuf clusters for the expected payload, or verify the length of the marshalled data before calling `sosend()`.  Alternatively, enforce a hard limit on argument size.\n  \n  Threat model: A client can send very large RPC arguments to exhaust kernel memory or trigger a memory corruption bug in the socket send path.\n  ",
    "impact":"Kernel memory corruption / DoS via oversized RPC arguments."
  },
  {
    "severity":"Medium",
    "title":"Potential integer overflow in retransmission timer calculation",
    "function":"clnt_dg_call",
    "description":"The retransmission waiting time grows exponentially based on `retransmit_time`:\n\n    if (retransmit_time < RPC_MAX_BACKOFF * hz)\n        retransmit_time = 2 * retransmit_time;\n\n`retransmit_time` is of type `int` and `hz` can be large (often > 1000).  If an attacker repeatedly causes retransmissions (e.g., by sending bogus XIDs that never match any pending request), `retransmit_time` can overflow the signed 32‑bit range, resulting in a negative or zero value which would cause `msleep()` to wake up immediately, allowing a tight loop that can starve the scheduler or exhaust CPU resources.\n\n  Fix: Use an unsigned type or clamp `retransmit_time` to `RPC_MAX_BACKOFF * hz` before doubling, and check for overflow.\n  \n  Threat model: Denial‑of‑service by forcing the kernel to wake frequently.\n  ",
    "impact":"CPU exhaustion / potential scheduler starvation."
  },
  {
    "severity":"Low",
    "title":"Unchecked return value from AUTH_MARSHALL",
    "function":"clnt_dg_call",
    "description":"The return value of `AUTH_MARSHALL()` is checked, but the function also may leak memory if the XDR operation writes beyond the allocated mbuf chain.  The code does not re‑allocate or abort on such failure, so a malformed `args` may lead to heap corruption.\n\n  Although not a critical flaw, it widens the window for unintended memory writes.\n  ",
    "impact":"Potential heap corruption."
  },
  {
    "severity":"Low",
    "title":"Potential misuse of sockreserve sizes",
    "function":"clnt_dg_create",
    "description":"`soreserve(so, sendsz, recvsz)` is called with sizes derived from user input (`sendsz` and `recvsz`).  If an attacker passes an excessively large size, `soreserve` may allocate huge kernel buffers, leading to memory exhaustion.\n\n  The conversion via `__rpc_get_t_size` only checks for zero, not for exceeding kernel limits.\n  ",
    "impact":"Denial‑of‑service via memory exhaustion."
  }
]
```
