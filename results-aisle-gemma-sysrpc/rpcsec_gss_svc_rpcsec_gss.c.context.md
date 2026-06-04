# Context: rpcsec_gss/svc_rpcsec_gss.c

### Security Context Briefing: `rpcsec_gss/svc_rpcsec_gss.c`

**1. Role & Project Location**
This file implements the server-side logic for **RPCSEC_GSS**, providing GSS-API based authentication, integrity, and privacy for RPC services. It manages security contexts, client sessions, and credential mapping within the kernel.

**2. Untrusted Input Entry**
Untrusted data enters via the network as RPC requests. The primary entry point is `svc_rpc_gss()`, which processes the `struct rpc_msg` and `struct svc_req`.

**3. Attacker-Controlled Data Flow**
*   **`gc` (`struct rpc_gss_cred`)**: Decoded from `rqst->rq_cred.oa_base`. Fields `gc_proc`, `gc_seq`, `gc_svc`, and `gc_handle` are directly controlled by the attacker.
*   **`recv_tok` (`gss_buffer_desc`)**: Decoded from `rqst` via `svc_getargs` in `svc_rpc_gss_accept_sec_context` and passed to GSS-API functions.
*   **`msg` (`struct rpc_msg`)**: Used in `svc_rpc_gss_validate` to reconstruct the RPC header for MIC verification.

**4. Fixed-Size Buffers & Constants**
*   `rpchdr[128 / sizeof(int32_t)]`: Size is **128 bytes**.
*   `cl_gid_storage[NGROUPS]`: GREP: `NGROUPS` (typically **32** or **64** depending on architecture).
*   `cl_seqmask[SVC_RPC_GSS_SEQWINDOW/32]`: `SVC_RPC_GSS_SEQWINDOW` is **128**, resulting in a buffer of **4** `uint32_t` elements (**16 bytes**).
*   `numstr[128]`: Size is **128 bytes** (used in DEBUG `gss_oid_to_str`).

**5. Dangerous Data Flows**
*   **`oa->oa_base` $\rightarrow$ `rpchdr`**: In `svc_rpc_gss_validate`, `memcpy` moves `oa_base` into `rpchdr`. The size is limited by `oa->oa_length`, which must be $\le 128 - (8 \times 4) = 96$ bytes.

**6. Potential NULL Dereferences**
*   `client->cl_sname` is accessed in `svc_rpc_gss_accept_sec_context` after a loop; if no matching service name is found, the code returns `FALSE`, but subsequent logic must ensure `client` state is handled.
*   `rqst->rq_clntcred` is cast to `struct svc_rpc_gss_cookedcred *cc`; if the RPC layer fails to allocate this, a NULL dereference occurs.

**7. Tagged Unions/Variants**
*   The code relies on `gc.gc_proc` to determine how to handle `gc.gc_handle`. It checks if `gc_proc == RPCSEC_GSS_INIT` to validate that the handle is empty, and expects a specific size for other procs.

**8. API Visibility**
*   **Public API**: `rpc_gss_set_callback`, `rpc_gss_set_svc_name`, `rpc_gss_get_principal_name`, `rpc_gss_getcred`, `rpc_gss_svc_max_data_length`.
*   **Static Helpers**: `svc_rpc_gss_validate`, `svc_rpc_gss_accept_sec_context`, etc. These are called internally by the main dispatcher `svc_rpc_gss`.

**9. Likely Bug Classes**
*   **Integer Overflows**: Sequence number arithmetic in `svc_rpc_gss_update_seq`.
*   **Memory Management**: Complex reference counting (`cl_refs`) and VNET-specific allocations.
*   **State Machine Errors**: Transitions between `CLIENT_NEW`, `CLIENT_ESTABLISHED`, and `CLIENT_STALE`.

[GREP RESULTS from codebase]:
GREP `architecture`:
```
(no matches in repo)
```