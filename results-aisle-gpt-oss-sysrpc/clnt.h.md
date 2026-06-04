# Scan: clnt.h

```json
[
  {
    "severity": "Critical",
    "title": "Unvalidated NULL pointer passed to cl_call via CLNT_CALL",
    "function": "clnt_call_private",
    "description": "The public macro CLNT_CALL expands to `clnt_call_private(rh, NULL, ...)`.  The RPC implementation's `cl_call` callback dereferences fields of the `rpc_callextra` structure (e.g. `ext->rc_auth`) without checking if `ext` is NULL.  If an application abuses the macro, the client handle will invoke `cl_call` with a NULL `ext`, leading to a crash or, if the implementation uses the pointer for authentication, a potential elevation of privilege or denial‑of‑service.  No NULL‑check is performed by the library, so the vulnerability is fully controllable by an attacker feeding a crafted RPC request."
  },
  {
    "severity": "High",
    "title": "Unchecked size parameters in client constructor routines",
    "function": "clnt_dg_create, clnt_vc_create, clnt_reconnect_create",
    "description": "The three client‑creation prototypes accept `size_t sendsz` and `size_t recvsz` to indicate buffer sizes.  The interface imposes no upper bound and the implementation typically allocates internal buffers of these exact sizes.  A malicious caller can supply an astronomically large value, causing the implementation to allocate huge buffers or to perform arithmetic overflows when computing derived limits, potentially exhausting system memory or creating address-space corruption.  Because these parameters are part of the public API, any application that forwards untrusted data (e.g., from a network service that relays user input to the RPC client) can trigger the overflow.")
  },
  {
    "severity": "High",
    "title": "Untagged union in `struct rpc_err` allows misinterpretation of error data",
    "function": "clnt_geterr / client error handling",
    "description": "`struct rpc_err` contains an anonymous union accessed through macros such as `re_errno`, `re_why`, `re_vers`.  The library relies on the caller’s knowledge of which member is valid based on `re_status`.  If a caller reads the wrong member (e.g., assumes `re_errno` is valid when `re_status` is `RPC_PROGUNAVAIL`), the program may use garbage values, leading to incorrect error handling or leaks of internal data.  Moreover, if the implementation writes a value into one member but the caller reads another, this can break program logic and facilitate silent failures or information disclosure.  The absence of a explicit discriminator field is a classic source of type‑confusion vulnerabilities."
  },
  {
    "severity": "Medium",
    "title": "Potential null‑pointer dereference in CLNT_DESTROY macro",
    "function": "CLNT_DESTROY",
    "description": "The macro expands to `((*(rh)->cl_ops->cl_destroy)(rh))`.  No check is performed to ensure that `rh` (the CLIENT pointer) or `rh->cl_ops` is non‑NULL.  If an application mistakenly passes a NULL handle (or a corrupted pointer) to `CLNT_DESTROY`, the process can crash or unwittingly execute arbitrary code.  While this is primarily a misuse scenario, it can be triggered by malformed inputs if a caller receives a pointer from an untrusted source."
  },
  {
    "severity": "Normal",
    "title": "Assumption of initialized reference count in CLNT_ACQUIRE / CLNT_RELEASE",
    "function": "CLNT_ACQUIRE/CLNT_RELEASE",
    "description": "These macros use `&(rh)->cl_refs` directly.  If a CLIENT instance is constructed but its reference counter is not atomically initialized, or if `rh` points to a partially constructed object (e.g., during a race condition), the reference count manipulation may produce undefined behaviour, potentially leading to double‑free or use‑after‑free vulnerabilities.  Proper client initialization must ensure `cl_refs` starts at 1."
  },
  {
    "severity": "Low",
    "title": "Imprecise size limit specified by RPCSMALLMSGSIZE",
    "function": "RPCSMALLMSGSIZE usage",
    "description": "The constant `RPCSMALLMSGSIZE` is defined as 400 bytes and is used in several RPC callers as a maximum packet size.  If this value is sub‑optimally small for a given deployment, legitimate large messages will be truncated or rejected.  While not a direct vulnerability, it can affect reliability and may create a weak point if an attacker crafts messages that intentionally force boundary checks or path‑specific handling."
  }
]
```
