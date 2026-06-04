```json
[
  {
    "severity": "critical",
    "title": "Unbounded copy in rpc_gss_ip_to_srv_principal()",
    "function": "rpc_gss_ip_to_srv_principal",
    "description": "The function copies the service name into the caller‑supplied \n`ip_addr` buffer without any size check, then passes the buffer to\n`gss_ip_to_dns()` which can write a DNS name larger than the\noriginal buffer.  An attacker can craft a huge `srv_name` that\ncauses a stack or heap overflow, leading to memory corruption and\npotential remote code execution."
  },
  {
    "severity": "high",
    "title": "Potential MIC overflow in svc_rpc_gss_nextverf()",
    "function": "svc_rpc_gss_nextverf",
    "description": "The GSS MIC length is copied into `rqst->rq_verf.oa_base` without\nverifying that the destination buffer is large enough.  A mechanism\nthat can produce a MIC larger than `MAX_AUTH_BYTES` would trigger\nthe `KASSERT`, crashing the kernel.  This is a denial‑of‑service\nvulnerability that could be triggered by manipulating the GSS\ncontext to produce large MICs."
  },
  {
    "severity": "high",
    "title": "Unrestricted sequence shift in svc_rpc_gss_update_seq()",
    "function": "svc_rpc_gss_update_seq",
    "description": "The function performs left shifts by `offset` (compute\n`seq - cl_seqlast`) without ensuring `offset` is within the 0–31\nrange.  For large differences (e.g., after a sequence wraparound)\nthe shift may be undefined or produce a negative value, leading\nto memory corruption or process crash.  This could be exploited\nby sending a sequence number far outside the last known value."
  },
  {
    "severity": "medium",
    "title": "Potential buffer overrun in rpc_gss_set_principal_name()",
    "function": "rpc_gss_set_principal_name",
    "description": "The function allocates a buffer sized to the concatenated\n`name`, `node`, and `domain` strings but does not check for integer\noverflow in the size calculation.  A maliciously long input can\ncause `mem_alloc()` to be requested with an enormous size, leading\nto memory exhaustion or allocation failure that could be used for\nresource‑denial attacks."
  },
  {
    "severity": "medium",
    "title": "Unsigned integer overflow in svc_rpc_gss_update_seq()",
    "function": "svc_rpc_gss_update_seq",
    "description": "The `offset` variable is defined as an `int` and is the\nresult of unsigned subtraction (`seq - cl_seqlast`).  If the\nresult exceeds `INT_MAX`, the signed integer overflows, causing\nthe subsequent shift logic to misbehave or crash.  This edge case\ncould be triggered by a carefully crafted sequence number."
  },
  {
    "severity": "medium",
    "title": "Bounds check missing for gss_pname_to_unix_cred() output",
    "function": "svc_rpc_gss_build_ucred",
    "description": "The function sets `uc->gidlen` to the value returned by\n`gss_pname_to_unix_cred()`.  If the returned number of groups\nexceeds `NGROUPS`, the code will write beyond the `cl_gid_storage`\narray, causing a buffer overflow.  This could be abused by a\nmalicious GSS credential that claims many groups."
  },
  {
    "severity": "low",
    "title": "NULL callback pointer not validated in rpc_gss_set_callback()",
    "function": "rpc_gss_set_callback",
    "description": "The code stores the callback function pointer directly\nwithout checking if it is NULL.  Later, `svc_rpc_gss_callback()`\nunconditionally invokes `scb->cb_callback.callback`, which could\ncause a kernel crash if a NULL callback is registered.  Though\nunlikely in normal operation, a malformed registration could\nbe exploited."
  },
  {
    "severity": "low",
    "title": "Unvalidated memory allocation for rpc_gss_getcred() objects",
    "function": "rpc_gss_svc_getcred",
    "description": "The `mem_alloc` used for `client->cl_rawcred.client_principal`\nis sized to the length of the exported name, but no sanity check\nis performed on the length value.  If the exported name is absurdly\nlarge (e.g., due to a buggy GSS provider), the allocation could\nfail or consume excessive resources, leading to denial of service."
  }
]
```