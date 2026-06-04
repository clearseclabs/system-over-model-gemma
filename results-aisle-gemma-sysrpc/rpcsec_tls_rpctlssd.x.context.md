# Context: rpcsec_tls/rpctlssd.x

This is a security context briefing for `rpcsec_tls/rpctlssd.x`.

**1. Role & Location**
This is an RPC Interface Definition Language (IDL) file used by `rpcgen` to generate server stubs and client headers. It defines the API for the `rpctlssd` daemon, which manages the server-side state of RPC-over-TLS connections.

**2. Untrusted Input Path**
Input arrives via the **network** as serialized XDR (External Data Representation) packets. The RPC runtime deserializes these packets into the `_arg` structures defined here before passing them to the service implementation.

**3. Attacker-Controlled Data**
The following variables are directly controlled by the network caller:
* `rpctlssd_connect_arg.socookie`
* `rpctlssd_handlerecord_arg.socookie`
* `rpctlssd_disconnect_arg.socookie`

**Data Flow:** Network $\rightarrow$ RPC Dispatcher $\rightarrow$ XDR Decoder $\rightarrow$ `socookie` $\rightarrow$ `RPCTLSSD_` implementation functions.

**4. Fixed-Size Buffers**
There are no fixed-size arrays or buffers defined in this IDL file; all fields are fixed-width integers (`uint64_t`, `uint32_t`).

**5. Dangerous Data Flows**
None present in the IDL. The risk lies in how the `socookie` (an opaque handle) is used to index into server-side state tables.

**6. NULL Parameters**
The `_arg` structures are passed by pointer to the generated stubs. While `rpcgen` typically handles the allocation, a malformed XDR stream could potentially result in NULL pointers if the decoder fails.

**7. Tagged Unions**
None present.

**8. API Visibility**
The functions `RPCTLSSD_CONNECT`, `RPCTLSSD_HANDLERECORD`, and `RPCTLSSD_DISCONNECT` are **public RPC endpoints**.

**9. Likely Bug Classes**
* **Integer Overflows/Underflows:** If `socookie` is used in pointer arithmetic.
* **Incorrect State Management:** Use-after-free or double-free if `socookie` refers to a session that was already disconnected.
* **Improper Validation:** If `socookie` is used as a key without verifying that the caller owns that session.