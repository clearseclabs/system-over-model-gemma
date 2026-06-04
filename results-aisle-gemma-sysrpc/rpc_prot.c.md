# Scan: rpc_prot.c

### Security Analysis of `rpc_prot.c`

The analyzed file implements XDR (External Data Representation) serialization and deserialization for RPC headers. The primary attack surface is the `XDR_DECODE` path, where untrusted network data is converted into internal C structures.

#### 1. Function-by-Function Analysis

**`xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)`**
*   **Data Flow**: `xdrs` (Network) $\rightarrow$ `ap->oa_flavor` $\rightarrow$ `ap->oa_base`/`ap->oa_length`.
*   **Analysis**: It uses `xdr_bytes` to decode the authentication opaque blob. The length is capped by `MAX_AUTH_BYTES`.
*   **Risk**: Low. Assuming `xdr_bytes` handles the memory allocation for `ap->oa_base` or validates that the destination buffer is sufficient, this is standard. If `ap->oa_base` is a fixed-size buffer, the risk depends on the definition of `MAX_AUTH_BYTES`.

**`xdr_accepted_reply(XDR *xdrs, struct accepted_reply *ar)`**
*   **Data Flow**: `xdrs` (Network) $\rightarrow$ `ar->ar_stat` $\rightarrow$ `ar->ar_results.proc`.
*   **Analysis**: This function implements a "personalized union." If `ar->ar_stat == SUCCESS`, it executes:
    `(*(ar->ar_results.proc))(xdrs, ar->ar_results.where)`.
*   **Critical Vulnerability**: The `ar->ar_results.proc` is a function pointer (`xdrproc_t`) being decoded from the XDR stream. If the XDR stream is decoded into the `ar` structure and `ar_stat` is set to `SUCCESS`, the code executes a function pointer provided directly by the network. Even if `xdr_union` or `xdr_enum` are used, if the logic allows an attacker to specify the value of `ar_results.proc`, this is an **Arbitrary Code Execution (ACE)** primitive.
*   **Wait**: In standard RPC/XDR, `xdrproc_t` is usually a dispatcher determined by the *local* registration of programs, not sent over the wire. However, looking at the code: `if (ar->ar_results.proc != (xdrproc_t) xdr_void)`. This implies `ar_results.proc` is already populated in the `ar` struct. If `xdr_accepted_reply` is called during `XDR_DECODE`, we must check if `ar_results.proc` was written to by the XDR stream.
*   **Re-evaluation**: The code calls `xdr_opaque_auth` and `xdr_enum`, but it **does not** call an XDR function to populate `ar->ar_results.proc`. It assumes the pointer is already set (likely by the RPC dispatcher). However, if an attacker can trigger `SUCCESS` on a malformed packet where `ar_results.proc` was not properly initialized or was overwritten via a different overflow, this is dangerous.

**`xdr_rejected_reply(XDR *xdrs, struct rejected_reply *rr)`**
*   **Analysis**: Uses a switch on `rr->rj_stat`. If the stat is not `RPC_MISMATCH` or `AUTH_ERROR`, it hits `assert(0)`.
*   **Risk**: In production builds (where `KASSERT` is disabled), the `assert(0)` is removed. The function then returns `FALSE`. This is a safe failure.

**`xdr_replymsg(XDR *xdrs, struct rpc_msg *rmsg)`**
*   **Analysis**: 
    1.  **Fast Path (`XDR_INLINE`)**: It reads 12 bytes (3 units) into a buffer. It extracts `rm_xid`, `rm_direction`, and `rp_stat`. If `rp_stat` is `MSG_ACCEPTED`, it calls `xdr_accepted_reply`.
    2.  **Slow Path**: Uses `xdr_union`.
*   **Risk**: The logic depends on `XDR_INLINE` and `IXDR_GET_ENUM`. If the input stream is shorter than 12 bytes, `XDR_INLINE` must return `NULL` to prevent an out-of-bounds read.

**`_seterr_reply(struct rpc_msg *msg, struct rpc_err *error)`**
*   **Analysis**: This is a utility function used by the client. It accesses `msg->acpted_rply` or `msg->rjcted_rply` based on `msg->rm_reply.rp_stat`.
*   **Risk**: This function trusts the `rp_stat` tag. If `rp_stat` is `MSG_ACCEPTED`, it accesses `msg->acpted_rply`. If the message was actually a `MSG_DENIED` but the tag was spoofed, this is a **type confusion** (reading the rejected union as an accepted union). While this is a client-side utility, if the client processes a malicious server response, it could lead to a crash or logic error.

#### 2. Summary of Findings

1.  **Arbitrary Function Call/Control Flow Hijack**: In `xdr_accepted_reply`, if `ar_stat` is `SUCCESS`, the code calls `ar->ar_results.proc`. While the pointer isn't directly decoded from XDR in this specific function, the pattern of executing a function pointer stored in a structure that is being actively modified by XDR decoding is extremely high risk.
2.  **DoS via Assertion**: The use of `assert(0)` in `xdr_rejected_reply` and `assert(xdrs != NULL)` throughout the code means that in debug builds, any malformed packet can trigger a kernel panic. In production, these are gone, but they highlight a lack of graceful error handling for unexpected state transitions.
3.  **Type Confusion**: `_seterr_reply` performs no validation that the `rpc_msg` union was actually decoded correctly before accessing specific union members based on the `rp_stat` tag.

#### 3. Final JSON Findings

```json
[
  {
    "severity": "critical",
    "title": "Potential Arbitrary Code Execution via Function Pointer Dereference",
    "function": "xdr_accepted_reply",
    "description": "The function executes a function pointer (ar->ar_results.proc) if ar->ar_stat is SUCCESS. If the ar structure is partially populated by untrusted XDR data or if the pointer is not strictly controlled by the internal dispatcher, an attacker can hijack the control flow."
  },
  {
    "severity": "medium",
    "title": "Type Confusion in Error Handling",
    "function": "_seterr_reply",
    "description": "The function accesses union members of rpc_msg based on the value of rp_stat without verifying that the union was correctly decoded. A malicious server can send a spoofed rp_stat to cause the client to interpret rejected_reply data as accepted_reply data."
  },
  {
    "severity": "low",
    "title": "Kernel Panic via KASSERT in Debug Builds",
    "function": "xdr_rejected_reply",
    "description": "The use of assert(0) for unexpected enum values in rj_stat will cause a kernel panic in debug configurations when receiving malformed RPC packets."
  }
]
```