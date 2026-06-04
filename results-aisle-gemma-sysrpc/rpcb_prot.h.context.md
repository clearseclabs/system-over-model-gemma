# Context: rpcb_prot.h

### Security Context Briefing: `rpcb_prot.h`

**1. Role and Location**
This is a generated header file (`rpcgen`) defining the RPC protocol for `rpcbind`. It sits at the interface between the network transport and the service logic, defining the data structures and function signatures for the portmapper service.

**2. Untrusted Input Path**
Input arrives via the **network** as XDR-encoded RPC requests. These are dispatched by the RPC runtime to the `_svc` functions (e.g., `rpcbproc_set_4_svc`).

**3. Attacker-Controlled Data**
Data is carried in structures decoded by `xdr_*` functions. Key variables include:
*   **`struct rpcb`**: `r_netid`, `r_addr`, `r_owner` (strings).
*   **`struct rpcb_rmtcallargs`**: `prog`, `vers`, `proc`, and the opaque blob `args_val` (or `args_ptr`) with its accompanying `args_len`.
*   **`struct rpcb_entry`**: `r_maddr`, `r_nc_netid`, `r_nc_protofmly`, `r_nc_proto`.
*   **Flow**: `Network` $\rightarrow$ `xdr_rpcb/xdr_rpcb_rmtcallargs` $\rightarrow$ `struct` $\rightarrow$ `rpcbproc_*_svc` $\rightarrow$ Service Logic.

**4. Fixed-Size Buffers**
*   `rpcbs_proc`: Array of size `RPCBSTAT_HIGHPROC` where `RPCBSTAT_HIGHPROC=13`.
*   `rpcb_stat_byvers`: Array of size `RPCBVERS_STAT` where `RPCBVERS_STAT=3`.

**5. Dangerous Data Flows**
*   `rpcb_rmtcallargs.args_val` $\rightarrow$ destination depends on the target `prog` called via `RPCBPROC_CALLIT`.
*   `RPCB` strings (`r_addr`, `r_netid`) $\rightarrow$ potentially internal storage maps.

**6. Potential NULL Dereferences**
Pointers `r_netid`, `r_addr`, `r_owner` in `struct rpcb` and `results_val` in `rpcb_rmtcallres` are XDR-strings which can be NULL if the wire data is malformed or explicitly null.

**7. Tagged Unions/Variants**
No explicit tagged unions are defined in this header; however, `rpcb_rmtcallargs` acts as a generic wrapper for various remote procedures.

**8. API Visibility**
*   **Public API**: `rpcbprog_3`, `rpcbprog_4`, and `rpcbproc_*_svc` (entry points for the RPC server).
*   **XDR Helpers**: `xdr_rpcb`, `xdr_rpcblist_ptr`, etc., are used by the RPC runtime to deserialize data.

**9. Likely Bug Classes**
*   **Memory Corruption**: Integer overflows/underflows related to `args_len` or `results_len` during buffer allocation.
*   **Denial of Service**: Resource exhaustion via large `rpcblist` or `rpcb_entry_list` requests.
*   **Logic Errors**: Improper validation of `prog/vers/proc` triples in `RPCBPROC_CALLIT`.