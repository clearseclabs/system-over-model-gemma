# VULN-012: Memory Leak on Decoding Failure

- **File**: `rpc_callmsg.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Memory Leak on Decoding Failure

#### 1. Memory Leak on Decoding Failure
In the `XDR_DECODE` block, the code allocates memory for the opaque authentication structures (`cb_cred` and `cb_verf`) using `mem_alloc(oa->oa_length)`. 

If the function encounters an error after this allocation—for example, if `XDR_INLINE` returns `NULL` and `xdr_opaque` subsequently fails, or if the decoding of the second opaque structure (`cb_verf`) fails—the function returns `FALSE` immediately. There is no mechanism within this function to free the previously allocated `oa->oa_base`. Since this is part of a network-facing RPC parser, an attacker can send a series of malformed packets that trigger these failure paths, leading to a Kernel/System memory exhaustion (DoS).

---

## Triage reasoning

### Round 1: ✅ VALID

The vulnerability report correctly identifies a memory leak pattern in `xdr_callmsg` during `XDR_DECODE`. Specifically, the code allocates memory for `oa->oa_base` using `mem_alloc(oa->oa_length)` for both `cb_cred` and `cb_verf`. If a subsequent decoding step fails (e.g., `xdr_opaque` returns `FALSE`, or the decoding of `cb_verf` fails after `cb_cred` was already allocated), the function returns `FALSE` without calling `mem_free` on the allocated `oa_base` pointers. Since `oa_length` is attacker-controlled (up to `MAX_AUTH_BYTES`), an attacker can repeatedly send malformed packets to exhaust system memory. While `MAX_AUTH_BYTES` limits the leak per packet, the cumulative effect in a network-facing RPC parser is a denial-of-service (DoS).

CRUX: The function allocates memory via mem_alloc for cb_cred and cb_verf but returns FALSE on subsequent decoding failures without freeing that memory.
GREP: MAX_AUTH_BYTES

### Round 2: ✅ VALID

The code in `xdr_callmsg` during `XDR_DECODE` performs allocations for `oa->oa_base` (both for `cb_cred` and `cb_verf`) using `mem_alloc(oa->oa_length)`. There are multiple return paths that return `FALSE` after these allocations are made but before the function successfully returns `TRUE`. Specifically: 
1. If `cb_cred` is allocated, but the subsequent `XDR_INLINE` or `xdr_opaque` call fails, the function returns `FALSE` without freeing `cb_cred->oa_base`.
2. If `cb_cred` is successfully allocated and decoded, but the subsequent decoding of `cb_verf` fails (either during the `XDR_INLINE` check for flavor/length or the actual data allocation/decoding), the function returns `FALSE` without freeing `cb_cred->oa_base` or any partially allocated `cb_verf->oa_base`.

Since this function processes network-sourced RPC messages, an attacker can trigger these failure paths repeatedly. While the individual leak size is capped by `MAX_AUTH_BYTES`, the lack of any cleanup on error paths leads to system memory exhaustion. The provided grep for `MAX_AUTH_BYTES` failed, but this doesn't invalidate the leak; it simply means the constant is likely defined in a header file not yet searched or is part of a different module, but the logic of the leak is evident in the source code provided.

CRUX: Memory is allocated for cb_cred and cb_verf using mem_alloc, but the function returns FALSE on various decoding errors without calling a corresponding free function for these buffers.
GREP: mem_free

### Round 3: ✅ VALID

The bug pattern is real: `xdr_callmsg` allocates memory using `mem_alloc` for `cb_cred->oa_base` and `cb_verf->oa_base` during `XDR_DECODE`. If the function returns `FALSE` due to a subsequent decoding failure (e.g., `xdr_opaque` fails or `cb_verf` decoding fails), these allocations are not freed within the function. The input is untrusted, coming from the network via the `XDR` handle. The reviewer's previous greps for `mem_free` failed, which suggests the memory management system might use a different name (like `free` or a custom RPC allocator), but the lack of *any* cleanup logic in the provided error paths is the critical issue. Since the attacker controls `oa_length` (up to `MAX_AUTH_BYTES`), they can trigger repeated leaks to cause a Denial of Service (DoS) via memory exhaustion. Even if `MAX_AUTH_BYTES` is small, the cumulative effect of repeated malformed requests in a network-facing parser is security-relevant.

CRUX: The function allocates memory for cb_cred and cb_verf during XDR_DECODE but returns FALSE on various error paths without freeing that memory, allowing a remote attacker to exhaust system memory.
GREP: MAX_AUTH_BYTES

### Round 4: ✅ VALID

[ARBITER] In the `XDR_DECODE` block of `xdr_callmsg`, the code allocates memory using `mem_alloc(oa->oa_length)` for `cmsg->rm_call.cb_cred.oa_base` and subsequently for `cmsg->rm_call.cb_verf.oa_base`. There are several error paths following these allocations (e.g., if `xdr_opaque` returns `FALSE`, if the length exceeds `MAX_AUTH_BYTES` for the second structure, or if the second allocation fails) where the function returns `FALSE` without calling a corresponding free function for the allocated memory. This allows a remote attacker to cause system memory exhaustion by sending malformed RPC packets.

