```json
[
  {
    "severity": "critical",
    "title": "Stack Buffer Overflow in svc_rpc_gss_validate",
    "function": "svc_rpc_gss_validate",
    "description": "The function builds a 128‑byte XDR header array (rpchdr) and then copies the client’s authentication data (oa->oa_length bytes) directly into it without checking that the total size fits. An attacker can craft a credential with a very large oa->oa_length to overflow rpchdr, corrupting the server’s stack and potentially enabling arbitrary code execution."
  },
  {
    "severity": "high",
    "title": "Undefined Behavior via 32‑bit Shift in update_seq",
    "function": "svc_rpc_gss_update_seq",
    "description": "When a client’s sequence number exceeds the last observed value by exactly 32, the code performs a left shift by 32 bits on a 32‑bit integer (`client->cl_seqmask[i] << offset`). Shifting by the width of the type is undefined in C and may corrupt the client’s sequence‑window bitmap, allowing an attacker to subvert replay protection or cause memory corruption."
  },
  {
    "severity": "medium",
    "title": "Potential KASSERT‑Dependent Buffer Overflow in nextverf",
    "function": "svc_rpc_gss_nextverf",
    "description": "The routine copies the GSS MIC value into the RPC verifer buffer using `bcopy(mic.value, rqst->rq_verf.oa_base, mic.length)`. The code relies on a runtime `KASSERT` that `mic.length <= MAX_AUTH_BYTES`; if assertions are disabled or the check fails, an attacker could supply an excessively large MIC and overflow the verifer buffer."
  }
]
```