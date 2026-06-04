# VULN-013: ummary of Findings

- **File**: `rpc_callmsg.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

ummary of Findings

### Summary of Findings

```json
[
  {
    "severity": "medium",
    "title": "Memory Leak on Malformed RPC Packet",
    "function": "xdr_callmsg()",
    "description": "In XDR_DECODE mode, the function allocates memory for oa->oa_base using mem_alloc(). If subsequent decoding steps fail (e.g., xdr_opaque fails or the second auth structure is invalid), the function returns FALSE without freeing the allocated memory, allowing a remote attacker to trigger a Denial of Service via memory exhaustion."
  },
  {
    "severity": "low",
    "title": "Missing NULL Pointer Validation",
    "function": "xdr_callmsg()",
    "description": "The function dereferences the XDR handle (xdrs->x_op) and the message structure (cmsg) without checking if they are NULL, which could lead to a kernel panic if called with invalid pointers."
  }
]
```

---

## Triage reasoning

### Round 1: ✅ VALID

I analyzed the `xdr_callmsg` function for the reported memory leak. In `XDR_DECODE` mode, the code allocates memory for `oa->oa_base` using `mem_alloc(oa->oa_length)` for both the credentials (`cb_cred`) and the verifier (`cb_verf`). 

1. The first allocation occurs for `cb_cred`. If subsequent steps fail—such as the `XDR_INLINE` call returning NULL and `xdr_opaque` returning FALSE, or if the later decoding of the verifier fails—the function returns `FALSE` immediately. 
2. There is no call to `mem_free()` or any cleanup mechanism within `xdr_callmsg` to release the memory allocated to `oa->oa_base` before returning `FALSE`.
3. Since `oa` is a pointer to a member of `cmsg`, and `cmsg` is provided by the caller, the memory allocated to `oa_base` is leaked unless the caller specifically knows to free it upon `xdr_callmsg` returning `FALSE`. However, the standard XDR pattern for this specific structure usually expects the decoding function to handle its own internal allocations or for the object to be fully initialized. 
4. An attacker can trigger this by sending a packet that successfully allocates the credential buffer but then contains an invalid verifier or truncated data, causing the function to return `FALSE` and leak the allocated memory. 
5. The memory leaked is capped by `MAX_AUTH_BYTES`, but repeated requests can lead to memory exhaustion (DoS).

Regarding the NULL pointer validation: `xdrs` and `cmsg` are expected to be valid handles provided by the RPC framework's dispatch layer; missing checks here are typical for internal XDR functions and are generally considered code quality issues unless the entry point is directly exposed to untrusted input without a wrapper.

CRUX: In XDR_DECODE mode, if mem_alloc is called for oa->oa_base and the function subsequently returns FALSE due to a decoding error, the allocated memory is not freed.
GREP: MAX_AUTH_BYTES

### Round 2: ✅ VALID

I analyzed the `xdr_callmsg` function for the reported memory leak. In `XDR_DECODE` mode, the function allocates memory via `mem_alloc(oa->oa_length)` for `cmsg->rm_call.cb_cred.oa_base` and subsequently for `cmsg->rm_call.cb_verf.oa_base`. If the function returns `FALSE` after either of these allocations (e.g., due to `xdr_opaque` failing, the second auth structure being invalid, or `XDR_INLINE` returning NULL), there is no code within `xdr_callmsg` to free the allocated memory. Since `cmsg` is passed by the caller, the caller would need to traverse the structure and free any allocated `oa_base` pointers upon failure. However, `xdr_callmsg` is the primary decoding routine for the RPC message; returning `FALSE` typically signals a malformed packet. An attacker can repeatedly send packets that trigger the first allocation and then fail during the second, leading to memory exhaustion. The leak size is bounded by `MAX_AUTH_BYTES` per packet, but since there is no limit on the number of malformed packets an unauthenticated remote attacker can send, this is a viable DoS vector. The NULL pointer issues are internal API contracts and not security vulnerabilities.

CRUX: The function allocates memory for `oa_base` using `mem_alloc` but fails to free it on subsequent error paths that return `FALSE` during `XDR_DECODE`.
GREP: MAX_AUTH_BYTES

### Round 3: ✅ VALID

The function `xdr_callmsg` in `XDR_DECODE` mode performs two potential memory allocations using `mem_alloc()` for `cmsg->rm_call.cb_cred.oa_base` and `cmsg->rm_call.cb_verf.oa_base`. If the first allocation succeeds but a subsequent step fails (e.g., `xdr_opaque` for the credentials fails, or the verifier decoding fails), the function returns `FALSE` without freeing the allocated memory. Since `cmsg` is an output parameter provided by the caller, the responsibility for cleanup on failure depends on the caller's implementation. In standard RPC XDR implementations, if a decoding function returns `FALSE`, the object being decoded is considered invalid. However, the `opaque_auth` structure is specifically designed to hold pointers to allocated memory. If the caller does not explicitly free `cb_cred.oa_base` and `cb_verf.oa_base` upon receiving a `FALSE` return from `xdr_callmsg`, a memory leak occurs. An unauthenticated remote attacker can trigger this by sending a packet that provides a valid `oa_length` (triggering `mem_alloc`) but contains malformed trailing data (triggering the `FALSE` return). While the leak is capped by `MAX_AUTH_BYTES` per request, the lack of a global limit on the number of requests makes this a viable Denial of Service (DoS) vector via memory exhaustion. The NULL pointer concerns are internal API contracts and not security vulnerabilities.

CRUX: xdr_callmsg() allocates memory for oa->oa_base using mem_alloc() but returns FALSE on subsequent decoding errors without freeing that memory, leading to a leak controllable by a remote attacker.
GREP: MAX_AUTH_BYTES

### Round 4: ✅ VALID

[ARBITER] In the `XDR_DECODE` path, the function `xdr_callmsg` performs memory allocations using `mem_alloc()` for `cmsg->rm_call.cb_cred.oa_base` and `cmsg->rm_call.cb_verf.oa_base`. If a subsequent decoding step fails (e.g., `xdr_opaque` returns FALSE, or a length check against `MAX_AUTH_BYTES` fails for the second auth structure), the function returns FALSE immediately. There is no code to free the previously allocated memory for `oa_base` in these error paths. Because this can be triggered by a malformed RPC packet from a remote attacker, it constitutes a memory leak that can lead to Denial of Service via memory exhaustion.

