# Context: rpc_msg.h

This is a context briefing for `rpc_msg.h`, which defines the core data structures for Sun RPC message exchanges.

**1. Function & Location**
This header defines the wire-format structures for RPC calls and replies. It sits at the base of the RPC transport layer, acting as the primary schema for serialization/deserialization.

**2. Untrusted Input Path**
Untrusted data arrives via the **network** (TCP/UDP). It is passed into XDR (External Data Representation) decoding functions, which populate these structures from raw byte streams.

**3. Attacker-Controlled Data**
All fields in `struct rpc_msg` are attacker-controlled when receiving a packet. Key fields include:
* `rm_xid`: Transaction ID.
* `rm_direction`: Determines if the message is a `CALL` or `REPLY`.
* `RM_cmb` (`struct call_body`): `cb_prog`, `cb_vers`, `cb_proc`, and credentials/verifiers.
* `RM_rmb` (`struct reply_body`): `rp_stat` and subsequent union members.

**4. Fixed-Size Buffers**
No fixed-size arrays are defined in this header; however, it uses `caddr_t` (char pointers) in `AR_results.where`, which point to buffers allocated during XDR decoding.

**5. Dangerous Data Flows**
Attacker-controlled input $\rightarrow$ XDR decoder $\rightarrow$ `struct rpc_msg` $\rightarrow$ RPC dispatcher. The primary risk is the flow from `rm_direction` and `rp_stat` into the selection of which union member is accessed.

**6. NULL Dereferences**
`AR_results.where` and `AR_results.proc` are pointers that may be NULL if the XDR stream is malformed or specifically crafted.

**7. Tagged Unions**
The code relies heavily on tagged unions:
* `rm_direction` tags `ru` (`RM_cmb` vs `RM_rmb`).
* `rp_stat` tags `ru` (`RP_ar` vs `RP_dr`).
* `ar_stat` and `rj_stat` conceptually tag their respective unions.
Validation depends entirely on the implementation of the `xdr_*` functions and the logic in the calling dispatchers.

**8. API vs Helpers**
* **Public API:** `xdr_callmsg`, `xdr_callhdr`, `xdr_replymsg`, `xdr_accepted_reply`, `xdr_rejected_reply`.
* **Internal Helper:** `_seterr_reply` (indicated by the underscore prefix).

**9. Likely Bug Classes**
* **Type Confusion:** Accessing `RM_cmb` when `rm_direction` is `REPLY`.
* **Integer Overflows:** In the XDR decoding logic handling the sizes of `opaque_auth` or `where` strings.
* **NULL Pointer Dereference:** Using `where` or `proc` without checking the result of XDR decoding.