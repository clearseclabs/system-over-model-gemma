# Scan: svc_auth_unix.c

```json
[
  {
    "severity": "critical",
    "title": "NULL pointer dereference on rqst->rq_clntcred",
    "function": "_svcauth_unix",
    "description": "The function assumes that rqst->rq_clntcred is a valid pointer to a xucred structure and immediately writes to its fields (`cr_uid`, `cr_gid`, `cr_sgroups`, `cr_ngroups`).  If an attacker can cause the RPC framework to supply a null or otherwise invalid credential pointer (e.g., by tampering with the underlying svc_req structure), a dereference of a null pointer will occur, leading to a crash and a denial‑of‑service.  This flaw is exploitable because the credential pointer is not verified before use."
  },
  {
    "severity": "high",
    "title": "Unbounded buffer reads from XDR data",
    "function": "_svcauth_unix",
    "description": "The code reads credentials directly from the XDR buffer using the length field `oa_length` from the network packet: `auth_len = (u_int)msg->rm_call.cb_cred.oa_length;`.  Although several checks are performed against `auth_len`, they rely on `oa_length` being a valid length for the supplied buffer.  An attacker can craft a packet in which `oa_length` is excessively large (or a negative value cast to an unsigned integer), bypassing those checks and causing `XDR_INLINE` to return a pointer that leads to out‑of‑bounds reads or even attempts to read/write memory beyond the packet payload.  The subsequent arithmetic (`auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`) does not protect against the possibility that the supplied `auth_len` is larger than the actual received data, exposing the function to a potential buffer overread or memory corruption exploit."
  },
  {
    "severity": "medium",
    "title": "Insufficient bounds checking before string length based computation",
    "function": "_svcauth_unix",
    "description": "The code uses `RNDUP(str_len)` to round the hostname length up to an XDR word boundary and later verifies the packet length with `auth_len < min_len + str_len`.  However, the check is performed after the rounding operation, and `RNDUP` could produce a slightly larger size than the original `str_len`.  If the maximum allowed hostname length (`AUTH_SYS_MAX_HOSTNAME`) is close to the boundary that forces a rounding up, the calculation could overflow an unsigned integer when computing `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`.  Although the current constants keep the values small, any future change to these limits without re‑evaluating the overflow protection could introduce a silent out‑of‑bounds index, potentially allowing an attacker to influence the subsequent credential parsing logic."
  }
]
```
