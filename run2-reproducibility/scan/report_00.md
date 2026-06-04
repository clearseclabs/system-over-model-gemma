**Security Analysis – `svc_rpcsec_gss.c`**

The file implements the server‐side of the `RPCSEC_GSS` authentication flavor used by the RPC subsystem.  All data that eventually reaches the functions in this module is deserialized from the network (the `rpc_gss_cred` structure in `rq_cred`) and therefore is completely untrusted.  The implementation also keeps per‑client state (`svc_rpc_gss_client`) in a hash table that is accessed under a global `svc_rpc_gss_lock` but many of the internal routines that manipulate that state still lack defensive bounds checks or type validations.  Below is a systematic walk‑through of the most critical flaw candidates.

| Step | Function | Untrusted input | Check performed | Potential fault | Impact |
|------|----------|-----------------|----------------|-----------------|--------|
| 1 | `svc_rpc_gss_validate` | `oa->oa_length` (cred length) | No validation; data written to the 128‑byte array `rpchdr` using raw `memcpy` | Overflow of `rpchdr` (stack buffer) and of `rpcbuf.length` calculation | Local stack corruption → denial of service or arbitrary code execution (Critical) |
| 2 | `svc_rpc_gss_validate` | `oa->oa_base` (opaque credential body) | No bounds checks; passes directly to `gss_verify_mic` | If `oa_length` is huge, the computed `rpcbuf.length` can exceed the actual amount written to `rpchdr`, possibly feeding a very large buffer length into the GSS API and leading to a denial of service. | High |
| 3 | `svc_rpc_gss_set_callback` | `rpc_gss_callback_t *cb` passed by the caller | Unchecked dereference of `*cb` | Passing `NULL` causes a NULL pointer dereference, potentially triggering a kernel panic (High). |
| 4 | `svc_rpc_gss_update_seq` | Sequence number subtraction | Uses unsigned arithmetic to compute offsets; no checks that `client->cl_seqlast` is initialised | If an attacker sends a very large `gc.gc_seq` during the first authenticated run, the arithmetic can under‑/overflow and leave an inconsistent window mask.  This may be exploited to bypass replay protection. | Medium |
| 5 | `svc_rpc_gss_build_ucred` | Result of `gss_pname_to_unix_cred` | No length checks for the returned group list | Extremely large group lists may overflow the fixed `client->cl_gid_storage[NGROUPS]` buffer, corrupting thread‑local per‑request data structures. | Medium |
| 6 | `svc_rpc_gss_nextverf` | Output `mic.length` | KASSERT verifies `mic.length <= MAX_AUTH_BYTES` | If the GSS provider returns a MIC larger than the negotiated maximum the assertion will trigger a kernel panic – a classic DoS flaw. | Medium |

### Context & Lifecycle
* **Entry point:** `svc_rpc_gss()` – the RPCKernel dispatcher calls this when it detects the `RPCSEC_GSS` flavor.  
* **Data origin:** The packet’s cred section (`rq_cred`) contains a serialized `rpc_gss_cred`; all fields (service type, sequence number, handle, opaque token, etc.) are supplied by the remote client.  
* **Buffer sizes & constants**  
  * `SVC_RPC_GSS_SEQWINDOW = 128` → 4 × 32‑bit window array.  
  * `rpchdr` array size: 32 ints (128 bytes).  
  * `MAX_AUTH_BYTES` is a compile‑time constant defined in `rpcsec_gss.h`; its exact value is platform‑specific but is always smaller than the maximum MIC size (`rpc_msg` credentials have 1024‑byte limits).  
* **Common bug nexus:** Many functions rely on the assumption that the credential data is well‑formed and of bounded size. When the credential is malicious, unchecked copying into fixed‑size arrays is the most tangible vector.

### Recommendations
| Issue | Fix |
|-------|-----|
| 1 ‑ `rpchdr` overflow | Enforce a maximum cred length (`oa->oa_length <= sizeof(rpchdr)`) before `memcpy`; use `min` and `memcpy(&rpchdr[9], ...)` after checking the credential header size. |
| 2 ‑ large `oa_length` handling | Add a sanity check for `oa->oa_length` (e.g., <= `RPC_HDRMAX`) before any copying or `gss_verify_mic`. |
| 3 ‑ callback registration | Validate `cb` to be non‑NULL before dereferencing; otherwise return `FALSE` and log an error. |
| 4 ‑ sequence arithmetic | Initialise `client->cl_seqlast` to a known value (e.g., 0) before the first use; reject any non‑zero sequence on an INIT/CONTINUE_INIT. |
| 5 ‑ group list overflow | Validate the `numgroups` value returned by `gss_pname_to_unix_cred` against `NGROUPS` before copying. |
| 6 ‑ MIC length | Replace the KASSERT with a runtime check and return `FALSE` or `RPCSEC_GSS_CREDPROBLEM` instead of panicking. |

---

```json
[
  {
    "severity": "CRITICAL",
    "title": "Stack buffer overflow in rpc_gss_validate",
    "function": "svc_rpc_gss_validate",
    "description": "The cred opaque field length (oa->oa_length) is copied into the 128‑byte array `rpchdr` without bounds checking.  An attacker can supply a credential with a length greater than 128, causing the stack to overflow, corrupting the return address or other control data, and potentially enabling arbitrary code execution."
  },
  {
    "severity": "HIGH",
    "title": "Unchecked opaque credential length in rpc_gss_validate",
    "function": "svc_rpc_gss_validate",
    "description": "If `oa->oa_length` is extremely large, the computed `rpcbuf.length` will exceed the amount of data actually written to `rpchdr`.  This leads to feeding an oversized buffer into `gss_verify_mic`, which may trigger a failure or DoS condition."
  },
  {
    "severity": "HIGH",
    "title": "Dereference of potentially NULL callback pointer",
    "function": "rpc_gss_set_callback",
    "description": "The function immediately dereferences the supplied callback pointer (`*cb`) without validating it.  Passing `NULL` would cause a kernel panic.  A well‑formed verifier should reject NULL callbacks."
  },
  {
    "severity": "MEDIUM",
    "title": "Integer under/overflow in sequence window update",
    "function": "svc_rpc_gss_update_seq",
    "description": "The calculation of offsets between sequence numbers uses unsigned arithmetic but does not guard against a client sending an extremely large sequence number during the first authenticated request.  This could corrupt the replay‑window mask and potentially allow replay attacks."
  },
  {
    "severity": "MEDIUM",
    "title": "Unbounded group list copy in svc_rpc_gss_build_ucred",
    "function": "svc_rpc_gss_build_ucred",
    "description": "The `gss_pname_to_unix_cred` call may return a group count larger than `NGROUPS`.  The code does not check this before copying into `client->cl_gid_storage`, potentially overflowing the fixed array and corrupting per‑request state."
  },
  {
    "severity": "MEDIUM",
    "title": "MIc size assertion can trigger a kernel panic",
    "function": "svc_rpc_gss_nextverf",
    "description": "A KASSERT checks that the MIC length is at most `MAX_AUTH_BYTES`.  If a malicious client forces the GSS provider to produce a larger MIC, the assertion will abort the kernel, causing a denial‑of‑service."
  }
]
```
