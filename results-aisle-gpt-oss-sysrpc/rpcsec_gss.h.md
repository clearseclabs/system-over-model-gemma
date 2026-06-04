# Scan: rpcsec_gss.h

**Security Analysis**

The header file `rpcsec_gss.h` defines the public API for RPCSEC‑GSS.  
Most of the implementation is not visible here, but the inline wrappers and the
data structures expose several potential attack vectors that could be triggered
through malformed input supplied by a privileged client or an attacker
distantly able to influence the RPC request.  Below are the most critical
findings ordered by severity.

---

```json
[
  {
    "severity": "critical",
    "title": "Unbounded string copy into rpc_gss_options_ret_t.actual_mechanism",
    "function": "rpc_gss_options_ret_t.actual_mechanism",
    "description": "The field `actual_mechanism` is a fixed array of size\n`MAX_GSS_MECH` (default 64).  The API that fills this buffer\ndoes not expose any length parameter or NUL terminator.  If an\nattacker can control the content of `mechanism` (or an internal\nrpc_gss_module that writes directly into this array), a value longer\nthan `MAX_GSS_MECH` will overflow the array and corrupt the\nstack or heap, potentially allowing arbitrary code execution or\nkernel fault.  The size is only a compile‑time constant and is not\nvalidated by any of the inline wrappers."
  },
  {
    "severity": "high",
    "title": "Negative or too large length in rpc_gss_principal_t",
    "function": "rpc_gss_principal_t struct",
    "description": "The structure representing a principal contains an\n`int len` followed by a variably‑sized array `char name[1]`.  No\nruntime checks enforce that `len` is non‑negative or that the\nbuffer allocated for the structure has space for `len` bytes.\nIf a caller supplies an overly large or negative length (e.g. from\nmalformed RPC data) and the code accesses `principal->name[i]`\nfor `i < len`, the resulting signed over/under‑flow will read or\nwrite beyond the buffer, enabling data corruption or denial of\nservice.  This vector is exploitable because the RPC layer can\nparse client supplied credentials directly into this structure."
  },
  {
    "severity": "high",
    "title": "`rpc_gss_ucred_t.gidlen` signed‑overflow risk",
    "function": "rpc_gss_ucred_t struct",
    "description": "The field `gidlen` is a `short`.  If the credential parser\naccepts arbitrary input, an attacker can set `gidlen` to a value\nthat, when used as an array index into `gidlist`, overflows the\nsigned 16‑bit range or exceeds the actual number of group IDs\nstored.  This can lead to heap corruption or information\nleakage.  The API does not expose any size checks or limits\non this field."
  },
  {
    "severity": "medium",
    "title": "Default success when rpc_gss_* entry point is missing",
    "function": "rpc_gss_set_defaults_call, rpc_gss_max_data_length_call, rpc_gss_mech_to_oid_call, rpc_gss_oid_to_mech_call, rpc_gss_qop_to_num_call, rpc_gss_get_mechanisms_call, rpc_gss_get_versions_call, rpc_gss_is_installed_call, rpc_gss_set_svc_name_call",
    "description": "Each inline wrapper initializes a success return value\n(`1` or a non‑NULL pointer) and only overwrites it if the\ncorresponding function entry is non‑NULL.  When the entry is\nNULL, the wrapper reports success or a non‑NULL pointer even\nthough no operation actually took place.  Code that relies on\nthese return values may incorrectly assume that a feature has\nbeen installed or successfully configured, allowing an attacker\nto bypass critical security checks or manipulate the RPC\nframework into using uninitialized credentials."
  },
  {
    "severity": "medium",
    "title": "Implicit NULL dereference in wrapper functions",
    "function": "rpc_gss_*_call inline wrappers",
    "description": "The wrappers pass all caller‑supplied pointers directly\nto the underlying function pointer without validating them\nfor NULL.  If an attacker can supply a crafted RPC request that\npasses `NULL` for a required argument (e.g. `clnt`, `cred`, or\n`principal`), the target function will receive a NULL pointer,\npotentially causing a kernel fault.  This explains a class of\nDenial‑of‑Service vulnerabilities in environments where the\nRPC stack blindly forwards untrusted data to these handlers."
  },
  {
    "severity": "low",
    "title": "Potential string lack of NUL‑termination",
    "function": "rpc_gss_rawcred_t fields `mechanism`, `qop`, `svc_principal`",
    "description": "These are `const char *` pointers that the API treats as\nstrings.  Without explicit length fields, callers must ensure\nthat the referenced memory contains a NUL terminator.  If an\nattacker supplies a pointer to data without a NUL terminator\nand the underlying code uses standard string functions\n(e.g. `strlen`, `strcmp`), a buffer overflow can occur."
  }
]
```

--- 

**Key Takeaways**

1. The most pressing issue is the fixed‑size `actual_mechanism` buffer; a larger string will corrupt memory.
2. The variably sized principal in `rpc_gss_principal_t` is highly vulnerable to integer‑overflow or buffer over‑read/write if length validation is omitted.
3. Signed overflows in `gidlen` can corrupt the group list pointer or deduce invalid groups.
4. The wrapper functions default to success when the actual implementation is missing, which can be abused to bypass checks.
5. Move-away from inline wrappers that silently forward NULL pointers to prevent accidental kernel faults.