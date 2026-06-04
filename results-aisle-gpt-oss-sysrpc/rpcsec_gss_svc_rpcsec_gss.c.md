# Scan: rpcsec_gss/svc_rpcsec_gss.c

```json
[
  {
    "severity": "critical",
    "title": "Undefined behaviour in sequence‑mask update (svc_rpc_gss_update_seq)",
    "function": "svc_rpc_gss_update_seq",
    "description": "The function computes the offset `seq - cl_seqlast` as a signed `int`. When clients transmit large sequence numbers (up to 0x7FFFFFFF, the maximum allowed by RPCSEC_GSS), the subtraction overflows the signed range and produces a negative value. Subsequent shift operations use `(32 - offset)` or `offset` as the shift count, which can exceed the 32‑bit width of the operand. Shifts by a value ≥ 32 are undefined behaviour in C, potentially corrupting the client’s `cl_seqmask` bit array, causing memory corruption or denial‑of‑service. This bug also allows an attacker to trigger the undefined behaviour by simply sending a sequence number close to the maximum permitted value.",
    "recommendation": "Use unsigned arithmetic for offset calculations, clamp the offset to the sequence window, and validate that it never exceeds 32 before performing the shifts."
  },
  {
    "severity": "high",
    "title": "Stack buffer overflow in header reconstruction (svc_rpc_gss_validate)",
    "function": "svc_rpc_gss_validate",
    "description": "The function reconstructs a 128‑byte header (`rpchdr[32]`) and then copies `oa_length` bytes from the request verifier into this buffer without checking that the remaining space is sufficient. If a malicious client supplies an oversized `oa_length`, the `memcpy` writes beyond the end of the stack array, corrupting adjacent stack memory and potentially allowing code execution or a crash. The buffer size is fixed at 128 bytes irrespective of the actual verifier length.",
    "recommendation": "Allocate a buffer large enough for the header and the verifier data, or use a dynamic allocation based on `oa_length`. Perform bounds checks before copying."
  },
  {
    "severity": "medium",
    "title": "Potential verifier buffer overflow (svc_rpc_gss_nextverf)",
    "function": "svc_rpc_gss_nextverf",
    "description": "The function writes a GSS MIC into `rqst->rq_verf.oa_base`. The buffer pointed to by `rqst->rq_verf.oa_base` is the same buffer that originally carried the client’s verifier. Since the server declares the same buffer for the reply, its actual size is determined by the request verifier’s allocation. If the MIC length (up to MAX_AUTH_BYTES = 400) is larger than the original buffer, the `bcopy` will write past its end, corrupting memory. While the code uses a KASSERT to ensure `mic.length <= MAX_AUTH_BYTES`, it does not verify that the caller’s buffer is large enough, leaving an exploitable overflow.",
    "recommendation": "Allocate a dedicated buffer for the reply verifier, or check the size of `rqst->rq_verf.oa_base` before copying."
  },
  {
    "severity": "medium",
    "title": "Unbounded GSS token size in svc_rpc_gss_accept_sec_context",
    "function": "svc_rpc_gss_accept_sec_context",
    "description": "The function receives an arbitrary GSS token from the client and passes it directly to `gss_accept_sec_context` without imposing a size limit. If an attacker sends an excessively large token, the GSS implementation may allocate disproportionate resources or read beyond the supplied buffer, leading to denial‑of‑service or potential memory issues.",
    "recommendation": "Validate the token length against a reasonable upper bound before invoking GSS functions."
  },
  {
    "severity": "low",
    "title": "Missing null pointer check for client reference after lookup",
    "function": "svc_rpc_gss",
    "description": "After deserializing the credential, the code obtains a client pointer via `svc_rpc_gss_find_client`. If the client is not found, the code properly handles the error. However, if a race condition causes the client to be removed between lookup and subsequent use, dereferencing `client->cl_*` fields may lead to a use‑after‑free. The current implementation relies on the global lock and reference counting, but it is easy to miss a guard in future modifications.",
    "recommendation": "Add defensive checks that the client is still present before accessing its fields, or retain a reference until all access is complete."
  }
]
```