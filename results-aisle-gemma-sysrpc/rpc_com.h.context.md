# Context: rpc_com.h

This is a context briefing for `rpc_com.h`, a header file containing common definitions and internal function prototypes used by both the RPC client and server layers.

**1. Role & Location**
This file resides in the topmost layer of the RPC implementation. It acts as a shared interface for internal helper functions (indicated by the `__` prefix) that manage transport, address translation, and XDR stream handling.

**2. Untrusted Input**
Input reaches the functions declared here via network sockets. Specifically, data arrives as RPC requests from remote clients, which are then processed by the XDR and transport layers (`__xdrrec_getrec`, `__rpc_fixup_addr`).

**3. Attacker-Controlled Data**
*   **Network Payloads:** Data read via `__xdrrec_getrec` flows into XDR streams.
*   **Address Strings:** Data passed to `__rpc_uaddr2taddr_af` (via the `const char *` argument) may be sourced from network-provided hostnames or configuration files.
*   **XID:** The `__RPC_GETXID` macro generates transaction IDs, but the corresponding IDs received from the network are attacker-controlled.

**4. Fixed-Size Buffers & Constants**
*   `RPC_MAXDATASIZE`: 9000 bytes.
*   `RPC_MAXADDRSIZE`: 1024 bytes.

**5. Dangerous Data Flows**
*   **Source:** Network packet $\rightarrow$ **Destination:** Internal buffers $\rightarrow$ **Function:** `__xdrrec_getrec` / `__rpc_uaddr2taddr_af` (potential overflows if buffers based on `RPC_MAXDATASIZE` or `RPC_MAXADDRSIZE` are used without bounds checking).

**6. NULL Dereferences**
Potential risk in `__rpc_uaddr2taddr_af` or `__rpc_taddr2uaddr_af` if the `netbuf` pointer or address strings are NULL.

**7. Tagged Unions**
No tagged unions are explicitly defined in this header, but `SVCXPRT` and `XDR` structures (referenced) likely utilize them.

**8. API Visibility**
*   **Public API:** Not explicitly exported here; most functions are internal (`__` prefix).
*   **Internal Helpers:** Functions like `__rpc_fixup_addr` and `__rpc_get_a_size` are helpers used by the core RPC machinery.

**9. Likely Bug Classes**
*   **Buffer Overflows:** Due to the fixed size of `RPC_MAXADDRSIZE` and `RPC_MAXDATASIZE`.
*   **Integer Overflows:** In XDR length calculations (`__svc_maxrec`).
*   **Memory Leaks:** In address translation helpers (`__rpc_uaddr2taddr_af` returns a pointer to `netbuf`).