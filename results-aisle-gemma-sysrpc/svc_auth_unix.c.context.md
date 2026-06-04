# Context: svc_auth_unix.c

This briefing covers `svc_auth_unix.c`, which implements UNIX-style authentication for RPC services.

**1. Functionality & Location**
This file implements the server-side authentication logic for `AUTH_UNIX`. It resides in the RPC layer and is responsible for decoding client credentials (UID, GID, and supplementary groups) from an incoming RPC message to populate the request's credentials structure.

**2. Untrusted Input Path**
Input arrives via the network as an RPC call. The `rpc_msg` structure contains the raw credential buffer (`oa_base`) and its declared length (`oa_length`), which are passed into `_svcauth_unix`.

**3. Attacker-Controlled Data**
*   **`msg->rm_call.cb_cred.oa_length`** $\to$ `auth_len`: Determines the bounds of the XDR stream.
*   **`msg->rm_call.cb_cred.oa_base`** $\to$ `buf`: The raw byte stream containing the authentication payload.
*   **`str_len`**: Extracted from `buf`; controls the pointer offset for credentials.
*   **`supp_ngroups`**: Extracted from `buf`; controls the loop iteration count for supplementary groups.

**4. Fixed-Size Buffers & Constants**
*   `xcr->cr_sgroups`: Array size defined by `XU_NGROUPS`.
GREP: `XU_NGROUPS`
*   `AUTH_SYS_MAX_HOSTNAME`: Used to bound `str_len`.
GREP: `AUTH_SYS_MAX_HOSTNAME`
*   `AUTH_SYS_MAX_GROUPS`: Used to bound `supp_ngroups`.
GREP: `AUTH_SYS_MAX_GROUPS`

**5. Dangerous Data Flows**
*   `supp_ngroups` $\to$ `xcr->cr_sgroups` via `_svcauth_unix`: The loop iterates `supp_ngroups` times, writing to `cr_sgroups` if the index is less than `XU_NGROUPS - 1`.

**6. Potential NULL Dereferences**
*   `xcr` (`rqst->rq_clntcred`): Dereferenced throughout the function. If `rqst` or `rq_clntcred` is NULL, a crash occurs.
*   `buf`: Result of `XDR_INLINE`. The code explicitly checks `if (buf != NULL)`.

**7. Tagged Unions**
Not applicable.

**8. API Visibility**
*   `_svcauth_unix`: Internal helper (likely called by the RPC dispatch mechanism).
*   `_svcauth_short`: Internal helper (currently returns `AUTH_REJECTEDCRED`).

**9. Likely Bug Classes**
*   **Integer Overflows:** Calculations involving `min_len + str_len + (supp_ngroups * 4)` could potentially overflow if not handled by the compiler/type.
*   **Logic Errors in Bounds Checking:** Discrepancies between `AUTH_SYS_MAX_GROUPS` and `XU_NGROUPS` could lead to data truncation or unexpected behavior.
*   **Memory Corruption:** Off-by-one errors in the `cr_sgroups` loop.

[GREP RESULTS from codebase]:
GREP `XU_NGROUPS`:
```
(no matches in repo)
```

GREP `AUTH_SYS_MAX_HOSTNAME`:
```
(no matches in repo)
```

GREP `AUTH_SYS_MAX_GROUPS`:
```
(no matches in repo)
```