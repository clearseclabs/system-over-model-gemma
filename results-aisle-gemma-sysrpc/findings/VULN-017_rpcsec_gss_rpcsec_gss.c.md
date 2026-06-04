# VULN-017: Heap-based Buffer Overflow / Memory Exhaustion in `rpc_gss_validate`

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Heap-based Buffer Overflow / Memory Exhaustion in `rpc_gss_validate`

#### 1. Heap-based Buffer Overflow / Memory Exhaustion in `rpc_gss_validate`
In `rpc_gss_validate`, the function receives a `struct opaque_auth *verf` from the network (via the RPC layer).
```c
if (gd->gd_state == RPCSEC_GSS_CONTEXT) {
    // ...
    gd->gd_verf.value = mem_alloc(verf->oa_length);
    if (gd->gd_verf.value == NULL) {
        // ... error handling ...
    }
    memcpy(gd->gd_verf.value, verf->oa_base, verf->oa_length);
    gd->gd_verf.length = verf->oa_length;
    return (TRUE);
}
```
**Vulnerability:** `verf->oa_length` is an attacker-controlled value from the network packet.
- **Memory Exhaustion:** An attacker can send a packet with a massive `oa_length` to trigger a kernel panic or exhaust the heap.
- **Integer Overflow:** While `mem_alloc` likely takes a `size_t`, if `oa_length` is used in calculations elsewhere or if the allocator has internal size limits, it can lead to unexpected behavior.
- **Lack of Bounds Check:** There is no upper limit checked against `verf->oa_length` before calling `mem_alloc` and `memcpy`.

---

## Triage reasoning

### Round 1: ✅ VALID

The vulnerability is located in `rpc_gss_validate`. When `gd->gd_state == RPCSEC_GSS_CONTEXT`, the code allocates memory for `gd->gd_verf.value` using `mem_alloc(verf->oa_length)` and then performs a `memcpy` of `verf->oa_length` bytes. The `struct opaque_auth *verf` is derived from the RPC layer's authentication verifier, which is provided by the remote server. In an RPC client context, the server controls the verifier sent back to the client. Since there is no upper bound check on `verf->oa_length` before the allocation and copy, a malicious server can provide a very large `oa_length` to cause memory exhaustion (DoS) or potentially trigger an integer overflow if `mem_alloc` or the underlying kernel allocator handles large sizes poorly. The input is externally controllable as it comes from the network via the RPC protocol's verifier field.

CRUX: The function `rpc_gss_validate` performs a `mem_alloc` and `memcpy` using `verf->oa_length` without any upper-bound validation, and `verf` is supplied by the remote server.
GREP: opaque_auth

### Round 2: ✅ VALID

The vulnerability exists in `rpc_gss_validate`. When the GSS state is `RPCSEC_GSS_CONTEXT`, the function takes a `struct opaque_auth *verf` (which is parsed from the network packet by the RPC layer) and uses `verf->oa_length` directly to allocate memory via `mem_alloc` and copy data via `memcpy`. There is no upper-bound check on `verf->oa_length`. Since this is the client-side implementation of RPCSEC_GSS, a malicious or compromised server can send a crafted RPC response with a massive `oa_length`, leading to kernel heap exhaustion and a resulting Denial of Service (kernel panic/crash). I verified that `opaque_auth` is used for network-received verifiers. While `mem_alloc` might fail and return NULL (which is handled), an attacker can send many requests with large lengths or a length just below the failure threshold to exhaust kernel memory. There are no global limits on `oa_length` visible in the provided code or the `opaque_auth` definition.

CRUX: rpc_gss_validate allocates and copies memory based on verf->oa_length, which is provided by the remote server without any upper-bound validation.
GREP: xdr_opaque_auth

### Round 3: ✅ VALID

The vulnerability is in `rpc_gss_validate`. When the state is `RPCSEC_GSS_CONTEXT`, the code performs `gd->gd_verf.value = mem_alloc(verf->oa_length);` and a subsequent `memcpy`. The `verf` object is a `struct opaque_auth` parsed from the network via `xdr_opaque_auth`. In an RPC client context, the server provides the verifier in the response. Since there is no upper bound check on `verf->oa_length`, a malicious server can send a very large length value. While `mem_alloc` returning NULL is handled, the lack of a reasonable upper bound allows an attacker to trigger significant memory pressure or exhaust the kernel heap, leading to a Denial of Service (kernel panic or hang). This is a classic memory exhaustion vulnerability where untrusted length fields from the network are passed directly to an allocator.

CRUX: rpc_gss_validate allocates memory and copies data using verf->oa_length, which is supplied by the remote server, without any upper-bound validation.
GREP: xdr_opaque_auth

### Round 4: ✅ VALID

[ARBITER] In `rpc_gss_validate`, the code allocates memory for `gd->gd_verf.value` using `mem_alloc(verf->oa_length)` and subsequently performs a `memcpy` of `verf->oa_length` bytes. The `verf` pointer refers to a `struct opaque_auth` which is parsed from the network via XDR. Because there is no upper-bound check on `verf->oa_length` before the allocation and copy, a malicious remote server can send a crafted packet with a very large length value to cause memory exhaustion (leading to a kernel panic) or trigger integer-related allocation issues.

