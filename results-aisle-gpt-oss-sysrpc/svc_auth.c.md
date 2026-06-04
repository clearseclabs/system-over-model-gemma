# Scan: svc_auth.c

```json
[
  {
    "severity": "high",
    "title": "Potential NULL dereference of rqst->rq_clntcred in svc_getcred",
    "function": "svc_getcred",
    "description": "When the requested flavor is AUTH_UNIX, the function blindly casts\n    `rqst->rq_clntcred` to a `struct xucred*` and dereferences\n    `xcr->cr_ngroups`.  The NetBSD RPC message can omit credential data\n    or the service‑request structure may be partially populated (e.g.,\n    during noise or malformed packets).  If `rqst->rq_clntcred` is NULL,\n    any dereference triggers a kernel crash, allowing a remote attacker\n    to perform a denial‑of‑service attack.  No validation of the\n    pointer’s non‑NULLness is performed before use.\n  "
  },
  {
    "severity": "medium",
    "title": "Unchecked size of group list in svc_getcred",
    "function": "svc_getcred",
    "description": "The code calls `crsetgroups_and_egid(cr, xcr->cr_ngroups, ...)`\n    without validating that `xcr->cr_ngroups` is within a sane range.\n    An attacker could construct a request with an excessively large\n    group count, leading to large heap or kernel memory allocations\n    or integer overflows inside `crsetgroups_and_egid`.  This can cause\n    denial‑of‑service or memory corruption if the sub‑routine does\n    not perform its own checks.\n  "
  },
  {
    "severity": "medium",
    "title": "Misleading xp_tls flag handling in svc_getcred",
    "function": "svc_getcred",
    "description": "The check `(xprt->xp_tls & (RPCTLS_FLAGS_CERTUSER | RPCTLS_FLAGS_DISABLED)) == RPCTLS_FLAGS_CERTUSER`\n    accepts only the certificate‑user flag by itself.  If an attacker\n    sets both RPCTLS_FLAGS_CERTUSER and RPCTLS_FLAGS_DISABLED, the\n    expression evaluates to `0x30` and fails, causing the TLS‑derived\n    credentials to be ignored even when they are present.  This can\n    force the server to fall back to RPC header credentials, potentially\n    exposing host‑side authentication bypass if combined with\n    additional weaknesses.\n  "
  },
  {
    "severity": "medium",
    "title": "Lack of validation for RPC flavor in _authenticate",
    "function": "_authenticate",
    "description": "The function switches on `cred_flavor` but treats any value not\n    matching known enums as an error and returns `AUTH_REJECTEDCRED`.\n    There's no check that `cred_flavor` was actually provided by the\n    network layer or that the credential structure is valid for that\n    flavor.  A crafted packet with an out‑of‑range flavor could cause\n    the request to be rejected, losing an opportunity to authenticate\n    legitimate traffic or to exploit buggy downstream authenticators.\n  "
  }
]
```