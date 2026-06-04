# Context: svc_generic.c

### Security Briefing: `svc_generic.c`

**1. Role and Location**
`svc_generic.c` provides the high-level server-side initialization for RPC transports. It acts as a factory layer that abstracts the creation of RPC transport handles (`SVCXPRT`) by bridging network configuration (`netconfig`) and socket creation. It sits between the RPC registration API and the transport-specific implementations (Connection-oriented `svc_vc` and Datagram `svc_dg`).

**2. Untrusted Input Path**
Input reaches this code via the **System API/Kernel Interface**. While these functions are typically called during server startup, they process `netconfig` structures and `uaddr` strings. If these are sourced from a configuration file or a management API, they are potentially attacker-controlled.

**3. Attacker-Controlled Data Flow**
*   `uaddr` (string) $\rightarrow$ `uaddr2taddr()` $\rightarrow$ `bind.addr` $\rightarrow$ `svc_tli_create()` $\rightarrow$ `bindresvport()`.
*   `nconf` (`struct netconfig`) $\rightarrow$ `__rpc_nconf2socket()` and `__rpc_nconf2sockinfo()`.
*   `prognum` / `versnum` $\rightarrow$ `rpcb_unset()` and `svc_reg()`.

**4. Fixed-Size Buffers & Constants**
*   `struct sockaddr_storage ss`: Size is determined by the system header (typically 128 bytes).
*   `struct netconfig nconfcopy`: Stack-allocated copy of the `netconfig` structure.

**5. Dangerous Data Flows**
*   **Source:** `uaddr` $\rightarrow$ **Destination:** `bind.addr.buf` $\rightarrow$ **Function:** `uaddr2taddr()` / `bindresvport()`. (Risk: Memory corruption during address conversion/binding).
*   **Source:** `nconf->nc_netid` $\rightarrow$ **Destination:** Heap via `strdup()` $\rightarrow$ **Function:** `svc_tli_create()`.

**6. Potential NULL Dereferences**
*   `nconf`: Checked at entry of both functions.
*   `uaddr`: Handled via `if (uaddr)` check.
*   `taddr`: Returned by `uaddr2taddr()`; if it returns `NULL`, `bind.addr = *taddr` will cause a kernel panic.

**7. Tagged Unions/Variants**
No tagged unions are explicitly managed in this file; however, `si.si_socktype` is used as a discriminant for the `switch` statement to determine the transport creation path (`SOCK_STREAM` vs `SOCK_DGRAM`).

**8. API Visibility**
*   **Public API:** `svc_tp_create()`, `svc_tli_create()`.
*   **Static Helpers:** None defined in this file. It relies on external helpers like `__rpc_nconf2socket` and `svc_vc_create`.

**9. Likely Bug Classes**
*   **Null Pointer Dereference:** Specifically if `uaddr2taddr` fails.
*   **Memory Leaks:** Potential leaks if `svc_tli_create` fails after `strdup` or if `bind.addr.buf` is not cleaned up on all error paths.
*   **Integer Overflows:** `bindaddr->qlen` is cast to `int` in `solisten()`.