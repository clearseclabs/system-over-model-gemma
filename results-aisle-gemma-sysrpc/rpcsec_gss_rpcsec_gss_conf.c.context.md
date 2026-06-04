# Context: rpcsec_gss/rpcsec_gss_conf.c

### Security Briefing: `rpcsec_gss/rpcsec_gss_conf.c`

**1. Role & Location**
This file provides configuration and translation utilities for the RPCSEC_GSS security layer. It acts as a bridge between high-level mechanism names (strings) and internal GSS identifiers (OIDs), sitting between the RPC layer and the kernel GSS (`kgss`) framework.

**2. Untrusted Input Path**
Input typically reaches this code via RPC configuration calls or service requests. Data enters as strings (mechanism names or Quality of Protection (QOP) strings) passed from userspace or network-derived configuration.

**3. Attacker-Controlled Data**
*   `mech` (string): Mechanism name. Flow: `rpc_gss_mech_to_oid` / `rpc_gss_is_installed` $\rightarrow$ `kgss_find_mech_by_name`.
*   `qop` (string): QOP identifier. Flow: `rpc_gss_qop_to_num` $\rightarrow$ `strcmp`.
*   `oid` (GSS OID): OID identifier. Flow: `rpc_gss_oid_to_mech` $\rightarrow$ `kgss_find_mech_by_oid`.

**4. Fixed-Size Buffers & Constants**
No fixed-size arrays are defined in this file. Memory for `mech_names` in `rpc_gss_get_mechanisms` is dynamically allocated based on the size of the `kgss_mechs` list.

**5. Dangerous Data Flows**
None identified in this specific file. There are no `strcpy` or `memcpy` calls into fixed buffers.

**6. NULL Dereference Risks**
*   `oid_ret` in `rpc_gss_mech_to_oid`: Dereferenced if `kgss_find_mech_by_name` returns a value.
*   `mech_ret` in `rpc_gss_oid_to_mech`: Dereferenced if `kgss_find_mech_by_oid` returns a value.
*   `num_ret` in `rpc_gss_qop_to_num`: Dereferenced if `qop` is "default".
*   `vers_hi`/`vers_lo` in `rpc_gss_get_versions`: Dereferenced unconditionally.

**7. Tagged Unions**
No tagged unions or variant types are used in this file.

**8. API Surface**
*   **Public API:** `rpc_gss_mech_to_oid`, `rpc_gss_oid_to_mech`, `rpc_gss_qop_to_num`, `rpc_gss_get_mechanisms`, `rpc_gss_get_versions`, `rpc_gss_is_installed`.
*   **Static/Internal Helpers:** `_rpc_gss_num_to_qop` (Helper).

**9. Likely Bug Classes**
*   **NULL Pointer Dereference:** The functions assume the output pointers (`*ret`) are valid.
*   **Race Conditions:** `rpc_gss_get_mechanisms` uses a static pointer `mech_names` without locking, which may lead to issues if the `kgss_mechs` list changes or if called concurrently during initialization.