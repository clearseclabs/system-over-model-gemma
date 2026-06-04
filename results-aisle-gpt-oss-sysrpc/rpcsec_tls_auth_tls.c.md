# Scan: rpcsec_tls/auth_tls.c

```json
[
    {
        "severity": "critical",
        "title": "Authentication bypass via missing verifier",
        "function": "authtls_validate",
        "description": "The verifier check accepts an empty verifier (opaque == NULL) as valid.  An attacker can omit the STARTTLS verifier entirely, causing the server to treat the connection as authenticated without TLS negotiation."
    },
    {
        "severity": "high",
        "title": "Potential stack/heap buffer overflow in auth initialization",
        "function": "authtls_init",
        "description": "The function marshals two opaque_auth structures into a fixed 20‑byte buffer using XDR.  If the encoded data exceeds MAX_MARSHAL_SIZE, XDR_PUTBYTES will fail but the code ignores the failure and stores an incorrect mcnt value.  Subsequent calls to authtls_marshal will copy mcnt bytes regardless of the buffer size, potentially overflowing the static mclient array on the stack."
    },
    {
        "severity": "medium",
        "title": "Unchecked NULL pointer dereference in marshal",
        "function": "authtls_marshal",
        "description": "The function assumes the passed AUTH pointer is non‑NULL and uses KASSERT, which in a kernel context will panic if the caller passes a NULL client.  If an attacker can obtain a code path that calls this function with a NULL client, it would result in an OS crash or denial of service."
    },
    {
        "severity": "low",
        "title": "Race condition on global mclient buffer (read‑only)",
        "function": "authtls_marshal",
        "description": "Multiple threads call authtls_marshal concurrently to read from the same global buffer.  Since the buffer is only read after being initialized once at boot, concurrent reads are safe, but the design is fragile if future modifications introduced writer paths.  This does not present an immediate security risk in the current code."
    }
]
```
