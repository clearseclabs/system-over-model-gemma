# Context: rpcb_clnt.h

This is a context briefing for `rpcb_clnt.h`, the header defining the client-side interface for the RPC Portmapper (rpcbind) service.

**1. Role & Location**
This file defines the public API for interacting with the RPC portmapper. It sits in the RPC library layer, acting as the bridge between higher-level RPC clients and the portmapper service to resolve program numbers/versions to network addresses.

**2. Untrusted Input Path**
Input reaches these functions via the application calling them. However, the *results* returned by these functions (e.g., from `rpcb_getmaps` or `rpcb_getaddr`) originate from a remote network server and are processed by the local client.

**3. Attacker-Controlled Data**
*   `host` (char *): User-supplied or DNS-resolved hostname.
*   `resp` (caddr_t): Buffer where the remote server writes response data in `rpcb_rmtcall`.
*   `rpcblist` (struct): Returned by `rpcb_getmaps`; contains data sent by the remote portmapper.

**4. Fixed-Size Buffers & Constants**
No fixed-size buffers are declared in this header. Analysis of the corresponding `.c` implementation is required to find internal buffers.

**5. Dangerous Data Flows**
Remote Portmapper $\rightarrow$ `rpcb_getmaps` $\rightarrow$ `rpcblist` structure.
Remote Portmapper $\rightarrow$ `rpcb_rmtcall` $\rightarrow$ `resp` buffer.

**6. NULL Dereferences**
Potential risks include passing `NULL` to `host` or `netconfig` pointers, or receiving a `NULL` return from `rpcb_getmaps` or `rpcb_uaddr2taddr` without validation.

**7. Tagged Unions**
Not present in this header.

**8. API Visibility**
All functions listed (`rpcb_set`, `rpcb_getaddr`, etc.) are `extern` public API functions.

**9. Likely Bug Classes**
*   **Memory Corruption:** Buffer overflows when decoding XDR responses from the remote server into local structures.
*   **Integer Overflows:** When calculating the size of the `rpcblist` returned by `rpcb_getmaps`.
*   **DoS:** Improper handling of malformed network responses leading to null pointer dereferences.