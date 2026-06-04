# Context: rpcsec_tls.h

This is a context briefing for `rpcsec_tls.h`, which defines the kernel-userland interface for RPCSEC_GSS TLS support.

**1. Role & Location**
This header defines the API for the RPC security layer (likely in the kernel) to communicate with TLS daemon helpers (`rpc.tlsclntd` and `rpc.tlsservd`). It acts as the glue between the RPC transport layer and the TLS handshake/certificate validation logic residing in userland.

**2. Untrusted Input**
Untrusted data reaches this code via network packets. Specifically, the kernel receives TLS records and "STARTTLS" strings from remote peers, which are then passed to these functions to be processed or forwarded to the userland daemons.

**3. Data Flow & Attacker Control**
*   `char *certname`: Potentially attacker-controlled if derived from a requested identity or network-provided identifier.
*   `void *socookie`: An opaque handle representing the socket state; while managed by the kernel, it tracks the session associated with untrusted network traffic.
*   **Flow:** Network Packet $\rightarrow$ Kernel RPC Layer $\rightarrow$ `rpctls_cl_handlerecord`/`rpctls_srv_handlerecord` $\rightarrow$ Userland Daemon.

**4. Buffers & Constants**
No fixed-size buffers are defined in this header. Constants are primarily bitflags (e.g., `RPCTLS_FLAGS_HANDSHAKE = 0x01`) and error codes.

**5. Dangerous Data Flows**
None explicitly visible in this header. Analysis should focus on how `certname` and the data pointed to by `socookie` are handled in the corresponding `.c` implementations.

**6. NULL Dereferences**
`CLIENT *newclient` and `struct socket *so` in `rpctls_connect` are critical pointers; if passed NULL from the RPC layer, they may cause crashes in the implementation.

**7. Tagged Unions**
None present in this header.

**8. API Visibility**
*   **Public API (Kernel-to-User):** `rpctls_connect`, `rpctls_cl_handlerecord`, `rpctls_srv_handlerecord`, `rpctls_cl_disconnect`, `rpctls_srv_disconnect`.
*   **System Interface:** `rpctls_syscall` is the entry point for the daemons.

**9. Likely Bug Classes**
*   **Integer Overflows:** In `u_int *maxlen` (in `rpctls_getinfo`).
*   **Race Conditions:** Between the kernel's socket state and the userland daemon's certificate validation.
*   **Memory Corruption:** In the handling of `certname` if passed to `strcpy`/`sprintf` in the implementation.