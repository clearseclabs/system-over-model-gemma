# Context: rpcsec_gss.h

This briefing covers `rpcsec_gss.h`, the header defining the interface between the RPC layer and the GSS-API (Generic Security Services API) implementation (typically `kgssapi` in the kernel).

**1. Role & Location**
It acts as an abstraction layer for GSS-API security mechanisms in RPC (e.g., NFSv4). It defines the structures and function pointers used to create security contexts, manage credentials, and handle security service negotiations.

**2. Untrusted Input**
Untrusted data enters via network-driven RPC requests. Specifically, `struct svc_req *req` (passed to `rpc_gss_getcred` and `rpc_gss_svc_max_data_length`) contains raw packet data and transport information.

**3. Attacker-Controlled Data**
*   **`struct svc_req *req`**: The primary entry point for network data.
*   **`rpc_gss_rawcred_t`**: Fields like `mechanism`, `qop`, and `client_principal` are derived from the GSS security header of an incoming RPC request.
*   **Data Flow**: Network Packet $\rightarrow$ RPC Layer $\rightarrow$ `rpc_gss_getcred` $\rightarrow$ `rpc_gss_rawcred_t`.

**4. Fixed-Size Buffers & Constants**
*   `rpc_gss_options_ret_t.actual_mechanism[MAX_GSS_MECH]` where `MAX_GSS_MECH=64`.
*   `rpc_gss_principal_t.name[1]` (Flexible array member pattern; size is dynamic, but the base is 1).

**5. Dangerous Data Flows**
*   **Source**: `mechanism` string from network $\rightarrow$ **Destination**: `actual_mechanism` $\rightarrow$ **Function**: `rpc_gss_seccreate` (implementation dependent) $\rightarrow$ **Size**: 64 bytes.

**6. Potential NULL Dereferences**
*   `rpc_gss_entries` function pointers (e.g., `rpc_gss_secfind`) are checked in `_call` helpers, but direct calls to the `rpc_gss_entries` table without checks would crash if the module isn't loaded.
*   `rpc_gss_rawcred_t` pointers (`mechanism`, `qop`, `svc_principal`) may be NULL if the GSS context is malformed.

**7. Tagged Unions**
No tagged unions are present in this header.

**8. API Visibility**
*   **Public API**: `rpc_gss_seccreate`, `rpc_gss_getcred`, etc.
*   **Static Helpers**: `rpc_gss_XXX_call` inline functions. These safely check if the corresponding `rpc_gss_entries` pointer is non-NULL before dereferencing.

**9. Likely Bug Classes**
*   **Stack/Heap Buffer Overflow**: Copying mechanism names into the 64-byte `actual_mechanism` buffer.
*   **Integer Overflows**: `rpc_gss_principal_t.len` usage during memory allocation.
*   **Null Pointer Dereference**: Handling of GSS-API return pointers or optional `options_req`/`options_ret` structs.