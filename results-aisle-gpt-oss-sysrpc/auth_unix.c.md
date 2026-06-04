# Scan: auth_unix.c

```json
[
  {
    "severity": "critical",
    "title": "Unbounded encoding of credentials into fixed‑size buffer",
    "function": "marshal_new_auth() / authunix_create()",
    "description": "Both functions pre‑serialize an `AUTH` header into a stack buffer of size `MAX_AUTH_BYTES` (400).  The encoded size is derived from the supplied `struct ucred`.  An attacker can supply a credential containing a large number of group IDs which expands the encoded representation past 400 bytes.  The XDR library will write past the end of `au_marshed`/`mymem`, overwriting adjacent stack data (including function return addresses or adjacent buffers).  This is a classic stack overflow that could lead to arbitrary code execution or kernel panic."
  },
  {
    "severity": "critical",
    "title": "Unbounded allocation for credential data",
    "function": "authunix_create()",
    "description": "After serializing the credential, the code stores the serialized length in `len = XDR_GETPOS(&xdrs)` and calls `mem_alloc((u_int)len)` to allocate memory for `au_origcred.oa_base`.  There is no check that `len` is less than or equal to `MAX_AUTH_BYTES`.  An attacker can construct a credential whose serialized representation exceeds the 400‑byte limit, causing the allocation to consume an arbitrary amount of kernel memory.  Repeated attempts can trigger an out‑of‑memory condition and potentially crash the system (DoS)."
  },
  {
    "severity": "high",
    "title": "Verf buffer length not bounded during deserialization",
    "function": "authunix_validate()",
    "description": "When a verifier with flavor `AUTH_SHORT` is received, the code creates an XDR decoder with `verf->oa_length` bytes using `xdrmem_create`.  The verifier originates from a remote client and can carry an arbitrary length.  The XDR decoder may attempt to read past the provided buffer if `verf->oa_length` is maliciously inflated or if the underlying XDR implementation does not perform strict bounds checking.  This could result in an out‑of‑bounds read or memory corruption, potentially leading to privileged kernel data disclosure or a crash."
  },
  {
    "severity": "high",
    "title": "Authentication for unsupported flavors defaults to success",
    "function": "authunix_validate()",
    "description": "If the verifier’s flavor is not `AUTH_SHORT` (`verf->oa_flavor != AUTH_SHORT`), the function simply returns `TRUE` without inspecting the verifier.  Because this `TRUE` is used by the RPC subsystem to indicate successful authentication, an attacker can send a verifier with an arbitrary, unsupported flavor and bypass authentication entirely.  This effectively turns the authentication mechanism into a no‑op for any attacker who can craft a remote RPC request."
  },
  {
    "severity": "high",
    "title": "Potential memory leak when cache eviction fails gracefully",
    "function": "authunix_create()",
    "description": "During cache eviction, the code removes entries from `auth_unix_cache` and `auth_unix_all` and calls `AUTH_DESTROY(tau->au_auth)` after decrementing `auth_unix_count`.  However, if `AUTH_DESTROY` fails to free the `au_auth` pointers due to a race condition or a bug in `AUTH_DESTROY`, the associated memory for the credential and its derived structures remains allocated.  Repeated creation of many credentials can exhaust kernel memory, leading to a DoS situation.  While not a direct overflow, the lack of guaranteed cleanup can be exploited for resource exhaustion."
  }
]
```
