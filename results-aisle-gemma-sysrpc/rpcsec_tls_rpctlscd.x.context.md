# Context: rpcsec_tls/rpctlscd.x

This is an XDR (External Data Representation) definition file for the **RPC-over-TLS client daemon (rpctlscd)**. It defines the remote procedure call (RPC) interface used for managing TLS connections on the client side.

**1. Role & Location:** This file defines the API surface for the `rpctlscd` service. It sits at the boundary between the network RPC layer and the daemon's internal logic.

**2. Input Path:** Untrusted input arrives via the network as XDR-encoded RPC requests. These are decoded by the RPC runtime and passed as arguments to the corresponding server-side functions.

**3. Attacker-Controlled Data:**
*   `socookie` (uint64_t): Passed in `rpctlscd_connect_arg`, `rpctlscd_handlerecord_arg`, and `rpctlscd_disconnect_arg`.
*   `certname` (variable-length string): Passed in `rpctlscd_connect_arg`.
*   **Flow:** Network $\to$ RPC Runtime $\to$ XDR Decoder $\to$ `RPCTLSCD_CONNECT`/`HANDLERECORD`/`DISCONNECT` functions.

**4. Buffers & Constants:** No fixed-size buffers are defined in this interface file. The `certname` is a variable-length string (denoted by `<>`), meaning the RPC runtime allocates memory based on the length specified in the XDR stream.

**5. Dangerous Flows:** `certname` (attacker-controlled string) $\to$ Destination buffer in the implementation of `RPCTLSCD_CONNECT`.

**6. NULL Dereferences:** `certname` can be a NULL pointer if the XDR stream encodes a null string or if decoding fails.

**7. Unions:** No tagged unions are present in this definition.

**8. API Surface:** All defined procedures (`RPCTLSCD_CONNECT`, `RPCTLSCD_HANDLERECORD`, `RPCTLSCD_DISCONNECT`) are public RPC API endpoints.

**9. Likely Bug Classes:** 
*   **Heap Overflows:** Improper handling of the variable-length `certname` during copy or processing.
*   **Integer Overflows:** Potential issues when using `socookie` as an index or offset.
*   **Null Pointer Dereferences:** Failure to validate `certname` before use.