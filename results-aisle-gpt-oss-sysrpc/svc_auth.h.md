# Scan: svc_auth.h

```json
[
  {
    "severity": "critical",
    "title": "Potential NULL dereference in _authenticate",
    "function": "_authenticate",
    "description": "The prototype does not require callers to validate the two request pointers.  If either the incoming `svc_req *` or the `struct rpc_msg *` is NULL, the implementation will likely access members such as `svc_req->sreq_auth` or `rpc_msg->msg_body`.  An attacker can craft a malformed RPC message that causes the kernel to pass a NULL pointer, leading to a crash or denial‑of‑service."
  },
  {
    "severity": "high",
    "title": "Unvalidated pointer arguments in svc_getcred",
    "function": "svc_getcred",
    "description": "The API accepts `struct ucred **crp` and `int *flavorp` without specifying that programmers must check them for NULL before use.  If an application passes a NULL for `crp` or `flavorp`, the function will attempt to dereference the pointer to write the discovered credentials or the flavor.  This results in a kernel fault that an attacker can trigger by manipulating the service registration to call `svc_getcred` with malicious arguments."
  },
  {
    "severity": "medium",
    "title": "Missing return‑value validation for credential extraction",
    "function": "svc_getcred",
    "description": "The documentation states that the function returns non‑zero when credentials were obtained, otherwise zero.  The header alone makes no guarantees that callers will test this value.  If a caller ignores the non‑zero return and proceeds as if credentials were present, an attacker might gain elevated privileges by causing the service to operate on invalid credentials."
  },
  {
    "severity": "medium",
    "title": "Conditional compilation may introduce signature mismatch in svc_auth_reg",
    "function": "svc_auth_reg",
    "description": "Under `_KERNEL` the function accepts a credential‑extraction callback of type `int (*)(struct svc_req *, struct ucred **, int *)`, whereas outside the kernel the signature lacks the third argument.  If a non‑kernel module registers a callback that does not match the expected signature, the resulting function pointer cast can lead to stack corruption or a crash when the callback is invoked."
  },
  {
    "severity": "low",
    "title": "No bounds checking for authentication blobs",
    "function": "_authenticate",
    "description": "The header exposes no explicit size limits for the authentication data that `svc_req` contains.  Implementations typically copy the auth blob into a fixed‑size buffer (e.g., `AUTH_MAXLEN`).  If the blob length is not validated before copying, an attacker can overflow the buffer and corrupt the stack or heap.  While the implementation details are not in this file, the absence of constraints in the interface allows such a bug to surface in the concrete code."
  }
]
```