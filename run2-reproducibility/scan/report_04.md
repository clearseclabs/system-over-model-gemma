```json
[
  {
    "severity": "high",
    "title": "Null pointer dereference due to missing strdup check in rpc_gss_set_svc_name",
    "function": "rpc_gss_set_svc_name",
    "description": "The function calls `strdup(principal, M_RPC)` and never checks if the return value is NULL. If the kernel runs out of memory it will dereference a NULL pointer when computing `strlen(sname->sn_principal)` inside `rpc_gss_acquire_svc_cred`, causing a kernel race/segfault. An attacker could trigger this by repeatedly adding service names until memory exhaustion, leading to a denial‑of‑service or potential privilege escalation via memory corruption."
  },
  {
    "severity": "high",
    "title": "Dereference of NULL pointer due to unchecked mem_alloc in svc_rpc_gss_create_client",
    "function": "svc_rpc_gss_create_client",
    "description": "The function allocates a `svc_rpc_gss_client` with `mem_alloc` but does not check the return value. Subsequent access to the returned pointer (e.g., setting fields, `refcount_init`) will dereference a NULL pointer if allocation fails, causing a kernel panic. Repeated creation of clients can exhaust memory, enabling a DoS attack."
  },
  {
    "severity": "critical",
    "title": "Double free / use‑after‑free of client structure in svc_rpc_gss DESTROY flow",
    "function": "svc_rpc_gss (DESTROY case)",
    "description": "When handling a `RPCSEC_GSS_DESTROY` request, `svc_rpc_gss_forget_client` removes the client from the hash and LRU lists and then calls `svc_rpc_gss_release_client`, destroying the client. After the switch statement, the generic `out` cleanup also calls `svc_rpc_gss_release_client` again, leading to a second free of the same structure. This double free can corrupt the memory allocator, potentially allowing an attacker to execute arbitrary code or crash the kernel."
  },
  {
    "severity": "medium",
    "title": "Undefined behaviour on 31‑bit shift in svc_rpc_gss_check_replay",
    "function": "svc_rpc_gss_check_replay",
    "description": "The function calculates `client->cl_seqmask[word] & (1 << bit)` where `bit` can equal 31. Shifting a signed 32‑bit integer left by 31 bits is undefined by the C standard and may produce a negative value or wrap. This could cause incorrect replay‑window checks, allowing duplicate or replayed RPC calls to be accepted or legitimate calls to be rejected."
  },
  {
    "severity": "medium",
    "title": "Potential signed overflow in svc_rpc_gss_update_seq during sequence window wrap",
    "function": "svc_rpc_gss_update_seq",
    "description": "When a large sequence number comes in, the function calculates an `offset` and performs a series of left‑shifts and right‑shifts on the `cl_seqmask` array. If `offset` equals 32, the expression `client->cl_seqmask[i] >> (32 - offset)` becomes a shift by 0 which is fine, but the preceding logic does not guard against larger offsets before the loop that reduces them. If a malicious client sends an offset larger than 32 before the loop iterates, the calculation could overflow, corrupting the sequence window and possibly allowing replay attacks."
  }
]
```