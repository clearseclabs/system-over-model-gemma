**Security Analysis of `example/net/parser.c`**

```c
void parse_packet(struct packet *pkt, const char *data, int len) {
    char header[64];
    memcpy(header, data, len);
    process_header(header);
}
```

| Function | Attentions | Why it matters | Suggested fix |
|----------|-----------|----------------|----------------|
| `parse_packet` | `len` comes from the network. `memcpy` copies `len` bytes into a fixed 64‑byte buffer. | Data larger than 64 bytes overflows the buffer on the stack, potentially corrupting return addresses or other locals → stack‑buffer overflow. | Validate `len <= 64` before `memcpy`. Use `memcpy_s` if available. |
| `handle_request` | `lookup_session` can return `NULL`; it is dereferenced immediately (`return sess->handler(req);`). | If `lookup_session` fails (malformed request, session ID that doesn’t exist), a `NULL` pointer dereference occurs → crash. | Check `sess != NULL` before dereferencing; return an error auth status if `NULL`. |
| `process_attr` | `av->value.str_val` is accessed assuming the tag is string. No check on the value type. | If a caller passes a non‑string variant, this reads an arbitrary pointer → use‑after‑free / memory leak or information disclosure. | Verify `av->type == ATTR_STR` before dereferencing; otherwise return error. |

**Potential impact**:  
- `parse_packet` can be triggered by any client sending a large packet; it will cause a kernel panic or can be used for privilege escalation if exploited.  
- `handle_request` can crash the service, DoS.  

**Recommendation**: Add defensive checks and bounds validation in every entry point handling untrusted data. Vulnerabilities identified are **critical** due to the low-level nature of the code.