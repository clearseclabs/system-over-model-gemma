# Scan: rpcsec_tls/rpctlscd.x

```json
[
  {
    "severity": "high",
    "title": "Unbounded and unchecked certname length",
    "function": "RPCTLSCD_CONNECT",
    "description": "The request arguments include a variable‑length string 'certname' with no maximum size specified in the XDR definition.  The generated rpcgen stubs encode this as XDR_STRING with a large default maximum (XDR_MAX_STRING).  On the server side, if the implementation copies this string into a fixed‑size buffer or performs string operations without first enforcing a size bound, an attacker can send a very long value (e.g., >64k) causing a heap overflow or exhausting memory (denial‑of‑service).  Since no field length validation is present in the XDR file, the server must explicitly enforce limits; otherwise an adversary can trigger memory corruption or crashes when the server handles the string.\n  \n  Recommendation: validate the length of 'certname' before allocating or copying, enforce a fixed upper bound (e.g., 256 bytes), and avoid copying into small stack buffers."
  },
  {
    "severity": "medium",
    "title": "Potential integer‑overflow or OOM from malicious socookie",
    "function": "RPCTLSCD_CONNECT / RPCTLSCD_HANDLERECORD / RPCTLSCD_DISCONNECT",
    "description": "The argument struct contains a 64‑bit field 'socookie' that is opaque to the receiver.  If server code uses this value arbitrarily for memory allocation or as an index (e.g., `malloc(req->socookie)` or `size_t sz = req->socookie * sizeof(item)`), a crafted request with an exceedingly large number can overflow the arithmetic, wrap around, or request more memory than intended, leading to denial‑of‑service or potential heap corruption.  No bounds checks on 'socookie' are present in the XDR file, so the server must validate that the cookie falls within the expected range and type before using it in size calculations.\n  \n  Recommendation: guard every use of 'socookie' by verifying that it is non‑negative and within the established session‑ID space."
  },
  {
    "severity": "medium",
    "title": "Lack of credence on certname content – potential authentication bypass / path traversal",
    "function": "RPCTLSCD_CONNECT",
    "description": "The 'certname' field is intended to supply the target server’s certificate name used for TLS.  Because the XDR file does not constrain the characters allowed in this string, an attacker can inject specially crafted values (e.g., containing null bytes, slashes, or overly long sequences) that may be interpreted incorrectly by the server’s TLS handling logic.  If the server naively treats the string as a file path or concatenates it with filesystem components without sanitization, it could lead to directory traversal, unauthorized file access, or a crash when processing malformed data.\n  \n  Recommendation: perform strict validation of 'certname' (e.g., accept only DNS‑style identifiers) before using it in file system paths or TLS SNI calls."
  }
]
```