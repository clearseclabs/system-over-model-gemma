# Scan: rpcsec_tls/rpctlssd.x

```json
[
  {
    "severity": "high",
    "title": "Unbounded gid vector leads to memory exhaustion",
    "function": "rpctlssd_connect_res",
    "description": "The IDL declares `uint32_t gid<>;` – an unbounded array of 32‑bit integers.  The generated XDR unmarshalling code will read the vector length directly from the client payload.  An attacker can supply an arbitrarily large length, causing the server to allocate a huge buffer (or allocate on the stack) and potentially exhaust memory or trigger a kernel panic.  No server‑side limit checks are present in the specification."
  },
  {
    "severity": "high",
    "title": "Unchecked session identifier (socookie) allows session hijack / denial‑of‑service",
    "function": "RPCTLSSD_* operations",
    "description": "All procedures accept a `uint64_t socookie` that represents an authenticated session.  The specification does not require any validation of the cookie value or a length bound.  If the underlying implementation simply looks up the session by ID without verifying that it is authorized, an attacker can supply a forged or random cookie to either hijack an existing session or cause the lookup routine to fail.  In many implementations a failed lookup could return NULL and the subsequent call `sess->handler(req)` would dereference a null pointer, crashing the server."
  },
  {
    "severity": "medium",
    "title": "Potential null pointer dereference if session lookup fails",
    "function": "handle_request (generated stubs)",
    "description": "The code generated for the RPC dispatch invokes the handler via a pointer returned by `lookup_session(req->session_id)`.  The interface does not guarantee that the returned session is non‑null.  If the lookup fails (e.g., because the cookie is invalid or expired) the dispatch routine may dereference a NULL pointer, resulting in a crash and an out‑of‑band denial‑of‑service.  The specification does not mandate a return‑value checking guard."
  },
  {
    "severity": "medium",
    "title": "Potential replay attack via reuse of socookie",
    "function": "RPCTLSSD_CONNECT/HANDLERECORD/DISCONNECT",
    "description": "The same 64‑bit cookie is reused for all RPC calls.  If the server never expires or revokes the cookie after disconnect, an attacker who captures a valid cookie can replay requests to the server until its internal state can be manipulated or additional operations performed.  The specification does not describe any nonce or timestamp to mitigate such replay."
  }
]
```