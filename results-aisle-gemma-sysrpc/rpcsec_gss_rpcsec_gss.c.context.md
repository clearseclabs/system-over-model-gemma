# Context: rpcsec_gss/rpcsec_gss.c

### Security Context Briefing: `rpcsec_gss/rpcsec_gss.c`

**1. Role & Location**
This file implements the client-side logic for **RPCSEC_GSS**, providing a security layer for RPC calls using the GSS-API (typically Kerberos). It handles security context establishment (handshaking), credential marshaling, and message integrity/privacy. It sits within the RPC security subsystem of the kernel.

**2. Untrusted Input**
Input reaches this code via:
*   **Network:** Server responses received during the `RPCSEC_GSS_INIT` phase (via `CLNT_CALL_EXT` in `rpc_gss_init`) and server replies during `rpc_gss_refresh`.
*   **API/User-land:** Configuration parameters passed to `rpc_gss_seccreate` (principals, mechanism names, QOP).

**3. Attacker-Controlled Data Flow**
*   **`mechanism` / `qop` (strings):** $\rightarrow$ `rpc_gss_seccreate` $\rightarrow$ `rpc_gss_mech_to_oid`/`rpc_gss_qop_to_num`.
*   **`principal` / `clnt_principal` (strings):** $\rightarrow$ `rpc_gss_seccreate_int` $\rightarrow$ `strdup` $\rightarrow$ `gd->gd_principal`/`gd->gd_clntprincipal`.
*   **Server Tokens (Network):** $\rightarrow$ `rpc_gss_init` $\rightarrow$ `gr.gr_token` $\rightarrow$ `recv_token`.
*   **Verifier (`struct opaque_auth *verf`):** $\rightarrow$ `rpc_gss_validate` $\rightarrow$ `verf->oa_base` / `verf->oa_length`.

**4. Fixed-Size Buffers & Constants**
*   `credbuf[MAX_AUTH_BYTES]`: `MAX_AUTH_BYTES` is a project-wide constant. GREP: `MAX_AUTH_BYTES`
*   `rpc_gss_cache[RPC_GSS_HASH_SIZE]`: `RPC_GSS_HASH_SIZE = 11`.
*   `rpc_gss_count` limit: `RPC_GSS_MAX = 256`.
*   `options_ret->actual_mechanism`: Sized via `sizeof(options_ret->actual_mechanism)`.

**5. Dangerous Data Flows**
*   **Source:** `verf->oa_base` $\rightarrow$ **Destination:** `gd->gd_verf.value` (Heap) via `memcpy` in `rpc_gss_validate`. (Size determined by `verf->oa_length`).
*   **Source:** `mech` (via GSS-API) $\rightarrow$ **Destination:** `options_ret->actual_mechanism` via `strlcpy` in `rpc_gss_init`.

**6. Potential NULL Dereferences**
*   `verf->oa_base` in `rpc_gss_validate` if `verf` is not NULL but its members are malformed.
*   `gd->gd_clntprincipal` is checked in some places but passed to `strlen` in `rpc_gss_init` (though it's guarded by a NULL check).

**7. Tagged Unions / Variants**
*   `AUTH->ah_private` is cast to `struct rpc_gss_data *` using the `AUTH_PRIVATE` macro. This assumes `ah_cred.oa_flavor == RPCSEC_GSS`.

**8. API Visibility**
*   **Public API:** `rpc_gss_secfind`, `rpc_gss_seccreate`, `rpc_gss_set_defaults`, `rpc_gss_refresh_auth`, `rpc_gss_max_data_length`.
*   **Static Helpers:** `rpc_gss_init`, `rpc_gss_validate`, `rpc_gss_marshal`. These are called via the `rpc_gss_ops` function table or internally.

**9. Likely Bug Classes**
*   **Race Conditions:** Heavy use of `sx` and `mtx` locks around a global cache (`rpc_gss_cache`) and per-context data.
*   **Memory Exhaustion:** Allocation of `gd->gd_verf.value` based on `verf->oa_length` (attacker-controlled).
*   **Integer Overflows:** Length calculations during XDR marshaling or GSS buffer handling.

[GREP RESULTS from codebase]:
GREP `MAX_AUTH_BYTES`:
```
(no matches in repo)
```