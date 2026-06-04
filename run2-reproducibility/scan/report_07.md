```json
[
  {
    "severity": "critical",
    "title": "Stack buffer overflow in svc_rpc_gss_validate()",
    "function": "svc_rpc_gss_validate",
    "description": "The routine rebuilds the RPC call header into a stack buffer `rpchdr[32]` (128 bytes). It copies the opaque authentication data from `msg->rm_call.cb_cred` directly into this buffer without any length check. An attacker can craft a credential whose length exceeds the 96‑byte space remaining after the fixed header, causing the `memcpy()` to overflow and corrupt memory (including control data or function pointers). This can lead to denial‑of‑service or arbitrary code execution within the kernel."
  },
  {
    "severity": "high",
    "title": "Unbounded write in rpc_gss_ip_to_srv_principal()",
    "function": "rpc_gss_ip_to_srv_principal",
    "description": "The function copies the supplied service name into the caller‑supplied buffer `srv_principal` using `memcpy()` and then writes a terminating '@'. No bounds check is performed against the length of `srv_principal`. A malicious client with a too‑small buffer can overflow a stack or heap region that contains the GSS wrapper’s data structures, potentially corrupting kernel state."
  },
  {
    "severity": "high",
    "title": "Buffer overrun when building ucred group list",
    "function": "svc_rpc_gss_build_ucred",
    "description": "The code calls `gss_pname_to_unix_cred()` passing `uc->gidlist` which has a fixed size of `NGROUPS`. The GSS library may return more GIDs than the array can hold. Nothing limits `numgroups`, so a user with a large group membership could cause a write beyond the bounds of `uc->gidlist`, corrupting the kernel memory that holds per‑client credentials."
  },
  {
    "severity": "medium",
    "title": "Null dereference on client allocation failure",
    "function": "svc_rpc_gss",
    "description": "When processing an `RPCSEC_GSS_INIT` request, `svc_rpc_gss_create_client()` is called, but the code does not verify that the returned pointer is non‑NULL. If memory allocation fails (e.g., under exhaustion or a deliberate DoS), the subsequent dereference of `client->cl_ctx` etc. would crash the kernel or potentially allow an attacker to influence the control flow."
  },
  {
    "severity": "medium",
    "title": "Potential use‑after‑free of client structures",
    "function": ["svc_rpc_gss_release_client","svc_rpc_gss_forget_client"],
    "description": "Client objects are freed only after the reference count reaches zero. If there is a logic error that reduces the count prematurely (for example, a missing `refcount_acquire()` in a code path), the object could be freed while still referenced elsewhere, leading to a use‑after‑free that could be exploited to execute code or corrupt memory."
  }
]
```
