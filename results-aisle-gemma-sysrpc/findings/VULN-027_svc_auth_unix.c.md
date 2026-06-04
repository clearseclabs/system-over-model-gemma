# VULN-027: Potential NULL Dereference

- **File**: `svc_auth_unix.c`
- **Confidence**: 75% [UVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Potential NULL Dereference

#### 5. Potential NULL Dereference
The code retrieves `xcr = rqst->rq_clntcred;`. It then proceeds to write to `xcr->cr_uid`, etc. If `rqst->rq_clntcred` is `NULL`, the kernel/process will crash. Depending on where `rqst` is allocated and how the RPC framework initializes it, this could be a DoS vector if an attacker can trigger this path without a pre-allocated credential structure.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN

The function `_svcauth_unix` retrieves `xcr` from `rqst->rq_clntcred` and immediately performs writes to its members (`xcr->cr_uid`, `xcr->cr_gid`, etc.) if the XDR buffer is successfully processed. The vulnerability depends on whether `rqst->rq_clntcred` can be NULL when `_svcauth_unix` is called. In the SunRPC/TIRPC framework, `svc_req` structures are allocated and initialized by the RPC server's request handling logic. For `AUTH_UNIX` to be processed, the request must have been initialized with a credential structure to hold the decoded identity. If the framework fails to allocate `rq_clntcred` or allows a path where it is NULL, this is a crash. I need to verify where `rqst` is allocated and if `rq_clntcred` is guaranteed to be non-NULL before `_svcauth_unix` is invoked.

CRUX: Whether the RPC request initialization logic guarantees that `rqst->rq_clntcred` is allocated before calling the authentication handler `_svcauth_unix`.
GREP: rq_clntcred

### Round 2: ✅ VALID

The previous reviewer attempted to grep for `rq_clntcred` and found no matches, which is highly suspicious given the code provided explicitly uses `rqst->rq_clntcred`. This indicates the previous search was either flawed or the codebase differs. However, looking at the provided code, `_svcauth_unix` takes `struct svc_req *rqst` and uses `xcr = rqst->rq_clntcred;` followed by `xcr->cr_uid = ...`. There is no NULL check for `xcr` before dereferencing it. In an RPC framework, if the request allocation logic fails to allocate the credential structure or if the authentication handler is called on a request where credentials weren't pre-allocated, this will cause a kernel panic or process crash. Since this is a server-side authentication handler processing network-provided buffers (`msg->rm_call.cb_cred`), it is triggered by untrusted input. Without a guarantee that `rq_clntcred` is always allocated prior to the call to `_svcauth_unix`, this is a viable DoS vector.

CRUX: The function `_svcauth_unix` dereferences `rqst->rq_clntcred` without checking if it is NULL, and it is called during the processing of untrusted RPC network packets.
GREP: svc_req

### Round 3: ✅ VALID

The reported vulnerability is a potential NULL dereference of `xcr = rqst->rq_clntcred`. The provided code snippet explicitly shows `xcr` being dereferenced (`xcr->cr_uid = ...`) without a NULL check. In a typical RPC server, `svc_req` is the primary structure for tracking a request. However, the grep results for both `svc_req` and `rq_clntcred` returned no matches. This indicates that the code provided in the snippet is not present in the indexed codebase, or the symbols are defined in headers/files not covered. Despite this, based on the code provided in the report, the pattern is a classic 'missing NULL check'. However, to determine if it is VALID, we must establish if an attacker can trigger this. In the SunRPC/TIRPC architecture, `_svcauth_unix` is called by the RPC dispatcher. The `svc_req` structure and its `rq_clntcred` member are allocated during the request creation phase (usually in `svc_recv` or `svc_process`). If the allocation for `rq_clntcred` fails or is skipped, the server would crash upon receiving any `AUTH_UNIX` request. Since the code provided shows no check for `xcr` before writing to it, and the input (`msg`) is derived from a network packet, this is a DoS vector unless the caller guarantees allocation. Because the grep results for the struct definitions are missing, I cannot verify the allocation guarantee, but the absence of a check in the handler itself—which is the last line of defense—makes this a high-risk pattern.

CRUX: The function `_svcauth_unix` dereferences `rqst->rq_clntcred` without validation, and it is called during the processing of untrusted network input.
GREP: svc_req

### Round 4: ✅ VALID

[ARBITER] The function `_svcauth_unix` assigns `xcr = rqst->rq_clntcred;` and subsequently performs multiple writes to `xcr` (e.g., `xcr->cr_uid = ...`) without any NULL check for `xcr`. In the context of an RPC server processing network packets, if `rqst->rq_clntcred` is not guaranteed to be allocated by the caller, this results in a NULL pointer dereference and a subsequent crash (DoS). The provided code confirms the absence of any validation before the dereference.

