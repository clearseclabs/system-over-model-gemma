# Context: rpcsec_gss/rpcsec_gss_int.h

### Security Context Briefing: `rpcsec_gss_int.h`

**1. Role and Location**
This header defines internal data structures and XDR (External Data Representation) serialization prototypes for the `rpcsec_gss` module. It sits in the RPC security layer, facilitating GSS-API (Generic Security Services API) authentication and data wrapping/unwrapping for remote procedure calls.

**2. Untrusted Input Path**
Input arrives via the **network** as XDR-encoded packets. These packets are passed to the XDR decoding functions (`xdr_rpc_gss_cred`, `xdr_rpc_gss_init_res`) and the data unwrapping function (`xdr_rpc_gss_unwrap_data`), which process raw buffers from `mbuf` structures.

**3. Attacker-Controlled Data**
*   **`struct rpc_gss_cred`**: Fields `gc_version`, `gc_proc`, `gc_seq`, `gc_svc`, and `gc_handle`.
*   **`struct rpc_gss_init_res`**: Fields `gr_handle`, `gr_major`, `gr_minor`, `gr_win`, and `gr_token`.
*   **`xdr_rpc_gss_unwrap_data`**: The `mbuf` content containing the encrypted/signed payload.
*   **Trace**: Network $\rightarrow$ `mbuf` $\rightarrow$ XDR Decoder $\rightarrow$ Struct Fields $\rightarrow$ GSS-API implementation.

**4. Fixed-Size Buffers & Constants**
*   `MAXSEQ`: `0x80000000` (Maximum sequence number).
*   `RPCSEC_GSS_VERSION`: `1`.
*   The `gss_buffer_desc` type is used extensively; it typically contains a `length` and a `void *value` pointer.

**5. Dangerous Data Flows**
*   **Network $\rightarrow$ `gss_buffer_desc`**: `xdr_rpc_gss_cred` and `xdr_rpc_gss_init_res` populate buffer descriptors from network data. The destination is the heap-allocated memory pointed to by `gc_handle` or `gr_token`.

**6. Potential NULL Dereferences**
The `XDR *xdrs` pointers and `struct` pointers (`struct rpc_gss_cred *p`, etc.) in XDR functions are critical. If the XDR engine passes a NULL pointer or if `mbuf` chains are malformed, dereferences may occur.

**7. Tagged Unions / Variants**
`rpc_gss_proc_t` acts as a type-tag for the control procedure. The code must validate that `gc_proc` is one of the four defined enum values before processing the associated credential logic.

**8. API Visibility**
*   **Public/Internal API**: `xdr_rpc_gss_cred`, `xdr_rpc_gss_init_res`, `xdr_rpc_gss_wrap_data`, `xdr_rpc_gss_unwrap_data`.
*   **Static/Helper**: `_rpc_gss_num_to_qop`, `_rpc_gss_set_error`.

**9. Likely Bug Classes**
*   **Integer Overflows**: In length calculations for `gss_buffer_desc`.
*   **Memory Leaks**: Failure to free `gss_buffer_desc` values on XDR decoding failure.
*   **Logic Errors**: Sequence number wrap-around or validation bypass using `MAXSEQ`.
*   **Heap Overflows**: Improper sizing of buffers during `mbuf` to GSS-API transition.