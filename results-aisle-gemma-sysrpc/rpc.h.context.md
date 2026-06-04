# Context: rpc.h

This is a context briefing for `rpc.h`. Note that this file is a **master header**; it does not contain logic but defines the interface and dependencies for the RPC (Remote Procedure Call) subsystem.

**1. Role and Location**
`rpc.h` is the primary umbrella header for the SunRPC implementation. It aggregates definitions for XDR serialization, authentication, client/server stubs, and the portmapper. It sits at the boundary between the network transport layer and the application-level RPC services.

**2. Untrusted Input**
Untrusted input reaches the code referenced here via the **network** (TCP/UDP sockets). Data enters through `svc` (server) functions or is returned to `clnt` (client) functions.

**3. Attacker-Controlled Data**
Data flows from the network $\rightarrow$ `rpc_msg` (message headers) $\rightarrow$ `xdr` (deserializer) $\rightarrow$ application buffers. Key fields include:
* `rpc_msg` fields (version, program, procedure).
* XDR-encoded payloads passed to `xdrproc_t` functions.

**4. Fixed-Size Buffers**
* `UDPMSGSIZE`: Resolved value **8800**. This is used as the size for buffers passed to the `registerrpc` callback: `char (*)(char [UDPMSGSIZE])`.

**5. Dangerous Data Flows**
* **Source:** Network socket $\rightarrow$ **Destination:** `UDPMSGSIZE` buffer $\rightarrow$ **Function:** `registerrpc` callback. (Potential for overflow if the underlying transport doesn't enforce the 8800-byte limit).

**6. NULL Parameters**
Pointers passed to `callrpc` (XDR procedures and data buffers) or `taddr2uaddr` (`netconfig` or `netbuf`) could be NULL if not validated by the caller.

**7. Tagged Unions**
RPC relies heavily on XDR. The correctness of union access depends on the `xdrproc_t` implementation validating the type tag before decoding the union member.

**8. API Visibility**
* **Public API:** `callrpc`, `registerrpc`, `getrpcport`, `get_myaddress`.
* **Internal/Static:** Functions prefixed with `__rpc_` (e.g., `__rpc_nconf2fd`) are internal library helpers.

**9. Likely Bug Classes**
* **Integer Overflows:** In XDR length calculations.
* **Buffer Overflows:** Specifically surrounding the `UDPMSGSIZE` limit.
* **Logic Errors:** Improper validation of RPC version/program tags.
* **Memory Corruption:** Improper handling of `xdr_block` offsets.