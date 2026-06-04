# Scan: clnt_vc.c

**Security Analysis**

The code is trusted (kernel‑space RPC client) but it parses data that ultimately originates from the remote RPC server.  The most critical paths that involve untrusted data are:

* `clnt_vc_create` – initialises the client and serialises the static RPC call header.
* `clnt_vc_call` – builds a request packet and sends it over a TCP socket.  
  The request is partially built from arguments supplied by the caller and the
  request payload will contain server‑controlled bytes after the server
  replies.
* `clnt_vc_soupcall` – receives the server’s reply, strips record markers,
  matches replies to pending requests, and hands the data to `xdr_replymsg`.
* `clnt_vc_dotlsupcall` – runs a helper k‑thread that may read from or free
  `ct` after the client has been destroyed, creating a data‑race.
* `clnt_vc_control` – exposes several configuration values to user space
  functions that are not thoroughly range‑checked.

Below are the most actionable findings.

```json
[
  {
    "severity": "HIGH",
    "title": "Unchecked XDR serialization may overflow ct->ct_mcallc",
    "function": "clnt_vc_create",
    "description": "The request header is serialised into the fixed‑size buffer `ct->ct_mcallc` using `xdr_callhdr`.  No bounds check is performed on the resulting length (`ct->ct_mpos`).  If a malformed request header were ever produced (e.g., by corrupting the global `disrupt` or `ct->ct_addr`), the `memcpy` in `clnt_vc_call` could copy more than MCALL_MSG_SIZE (24) bytes, overwriting adjacent data on the stack.  This could corrupt the CLIENT structure and lead to a kernel crash or privilege escalation."
  },
  {
    "severity": "HIGH",
    "title": "Use‑after‑free race between clnt_vc_destroy and clnt_vc_dotlsupcall",
    "function": "clnt_vc_destroy vs. clnt_vc_dotlsupcall",
    "description": "After `clnt_vc_destroy` frees `ct` and returns, the TLS helper thread launched by `clnt_vc_dotlsupcall` may still be running.  It continues to access fields of `ct` (for example, `ct->ct_socket`, `ct->ct_rcvstate`) after the structure has been freed, which can trigger a kernel panic.  The race is exploitable if an attacker can force the client to be destroyed while the TLS thread is still active, for instance by repeatedly closing the client from user space."
  },
  {
    "severity": "MEDIUM",
    "title": "Unbounded record length from server can cause memory exhaustion",
    "function": "clnt_vc_soupcall",
    "description": "The server provides a record marker via an XDR‐encoded 32‑bit integer.  The high bit denotes termination; the lower 31 bits are treated as the record length and stored in `ct->ct_record_resid`.  No sanity check is performed—an attacker may set this field to a very large value (0x7FFFFFFF).  The kernel will attempt to consume that many bytes before matching a request, keeping large parts of the receive chain in memory and potentially exhausting system memory or delaying response handling."
  },
  {
    "severity": "MEDIUM",
    "title": "Uninitialised error structure may leak kernel data",
    "function": "clnt_vc_geterr",
    "description": "The `ct->ct_error` member of the client data is not zeroed when a new client is created.  If `clnt_vc_geterr` is called before any RPC has completed, the caller receives whatever garbage was in the allocated memory.  This can leak kernel addresses or other sensitive information to user space."
  }
]
```

These issues represent potential rollback or denial‑of‑service attacks that an attacker controlling the RPC server could trigger.  Other parts of the code perform proper bounds checking, proper locking of shared state, and safe XDR parsing, so no further exploitable bugs were found in the provided functions.