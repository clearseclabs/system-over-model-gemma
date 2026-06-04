```json
[
  {
    "severity": "critical",
    "title": "Stack buffer overflow in svc_rpc_gss_validate",
    "function": "svc_rpc_gss_validate",
    "description": "The function builds a 128‑byte stack array `rpchdr` that contains the RPC header and the authentication verifier from `msg->rm_call.cb_cred`. It blindly copies `oa->oa_length` bytes into this array with `memcpy`.  The size of the verifier is controlled by the client; a crafted request can set `oa->oa_length` far beyond 100 bytes, causing the copy to overwrite the entire stack frame, corrupting return addresses, kernel data structures, or other local variables.  This can lead to arbitrary code execution or a kernel crash."
  },
  {
    "severity": "high",
    "title": "Negative‑offset UB in replay protection (svc_rpc_gss_check_replay)",
    "function": "svc_rpc_gss_check_replay",
    "description": "When the client sends a sequence number larger than the current `cl_seqlast`, `offset = client->cl_seqlast - seq` becomes negative.  The code then calculates `bit = offset % 32` and performs `(client->cl_seqmask[word] & (1 << bit))`.  Both the `%` and the left‑shift with a negative `bit` value invoke undefined behaviour in C, potentially producing a memory corruption or kernel panic.  An attacker can trigger this by simply sending a sequence number that exceeds the last observed value."
  },
  {
    "severity": "medium",
    "title": "Unrestricted GSS token length in svc_rpc_gss_accept_sec_context",
    "function": "svc_rpc_gss_accept_sec_context",
    "description": "The token received from the client is extracted into `recv_tok` via XDR and then passed directly to `gss_accept_sec_context` (or the MIT version).  The length of this token is not bounded in this code; a malicious client can supply a very large token that forces the GSS implementation to allocate large amounts of memory or perform excessive parsing, leading to a denial‑of‑service or, if the GSS library contains a buffer overflow, to arbitrary code execution."
  },
  {
    "severity": "medium",
    "title": "Assertion‑based denial of service in svc_rpc_gss_nextverf",
    "function": "svc_rpc_gss_nextverf",
    "description": "The function verifies the MIC size with `KASSERT(mic.length <= MAX_AUTH_BYTES)`.  If an attacker sends a MIC larger than `MAX_AUTH_BYTES`, this assertion will trigger and the kernel will panic, effectively performing a denial‑of‑service.  Although this is not a memory corruption, it is exploitable through crafted network traffic."
  },
  {
    "severity": "medium",
    "title": "Potential memory exhaustion when copying exported name in svc_rpc_gss_accept_sec_context",
    "function": "svc_rpc_gss_accept_sec_context",
    "description": "After a successful context establishment, the code calls `gss_export_name` to produce `export_name`, then allocates `client->cl_rawcred.client_principal` with precisely that length and copies the raw name bytes.  If the exported name length is unreasonably large (e.g., due to a malformed token or mis‑behaving GSS provider), the allocation may succeed or fail inconsistently, causing either a denial of service or, in rare cases, integer overflow when the length is interpreted as a signed `int` in memory.  Clients can trigger this by crafting credentials that cause a very long principal name."
  },
  {
    "severity": "low",
    "title": "Missing NULL check for gss buffer in svc_rpc_gss_accept_sec_context",
    "function": "svc_rpc_gss_accept_sec_context",
    "description": "After obtaining `recv_tok` via `svc_getargs`, the code never checks whether `recv_tok.value` is NULL before passing it to GSS.  While XDR would normally set value to a valid pointer when length > 0, a corrupted or incomplete request could lead to a NULL pointer passed to the GSS API.  The GSS function may then dereference NULL, leading to a crash.  This is an implementation oversight but requires a malformed request to exploit."
  }
]
```