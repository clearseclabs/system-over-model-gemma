# Scan: rpcsec_gss/rpcsec_gss_conf.c

```json
[
  {
    "severity": "critical",
    "title": "Unprotected NULL pointer dereference – rpc_gss_qop_to_num",
    "function": "rpc_gss_qop_to_num()",
    "description": "The first operation in the function is `strcmp(qop, \"default\")`.  If the caller passes a NULL pointer for the `qop` argument, `strcmp` will dereference a NULL pointer and crash the kernel.  An attacker can trigger this by sending a malformed RPC request that leaves the `qop` field empty or uninitialized."
  },
  {
    "severity": "critical",
    "title": "Unprotected NULL pointer dereference – rpc_gss_mech_to_oid",
    "function": "rpc_gss_mech_to_oid()",
    "description": "The function forwards the raw `mech` pointer to `kgss_find_mech_by_name()` without validating it.  If `mech` is NULL (malformed RPC data), that helper will receive a NULL argument and is likely to dereference it, causing a kernel fault.  No kernel panic recovery path exposes this in the current code."
  },
  {
    "severity": "critical",
    "title": "Unprotected NULL pointer dereference – rpc_gss_oid_to_mech",
    "function": "rpc_gss_oid_to_mech()",
    "description": "The `oid` argument, typically a `gss_OID` struct, is passed directly into `kgss_find_mech_by_oid()` without any validation.  A crafted request could supply a NULL or otherwise malformed OID, leading the helper to dereference a NULL pointer and crash the kernel."
  },
  {
    "severity": "critical",
    "title": "Unprotected NULL pointer dereference – rpc_gss_get_versions",
    "function": "rpc_gss_get_versions()",
    "description": "The function writes to the callers’ `vers_hi` and `vers_lo` pointers without checking that they are non‑NULL.  If an attacker passes a NULL pointer for either, the kernel will fault.  This could be leveraged to trigger a privilege‑escalation or denial‑of‑service during RPC handshake."
  },
  {
    "severity": "high",
    "title": "Thread‑local static allocation race in rpc_gss_get_mechanisms",
    "function": "rpc_gss_get_mechanisms()",
    "description": "The static variable `mech_names` is written without any synchronisation.  Two concurrent callers that both observe the pointer as NULL will each allocate a new array, overwrite the global pointer, leak the first allocation, and return a corrupt or stale array to one of the threads.  While this does not immediately produce a memory corruption in the current kernel environment, it introduces a data race that can surface under load or in future code changes."
  },
  {
    "severity": "medium",
    "title": "Potential integer overflow in malloc size computation",
    "function": "rpc_gss_get_mechanisms()",
    "description": "The size passed to `malloc()` is `count * sizeof(const char *)`.  If the list of kernel GSS mechanisms grows extremely large, `count` could overflow the multiplication, resulting in a too‑small allocation or undefined behaviour.  In practice the mechanism list is tiny, but the absence of an explicit bounds check is a code smell."
  }
]
```