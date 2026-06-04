# VULN-006: Unbounded gid vector leads to memory exhaustion

- **File**: `rpcsec_tls/rpctlssd.x`
- **Confidence**: 50% [UUV→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Unbounded gid vector leads to memory exhaustion

The IDL declares `uint32_t gid<>;` – an unbounded array of 32‑bit integers.  The generated XDR unmarshalling code will read the vector length directly from the client payload.  An attacker can supply an arbitrarily large length, causing the server to allocate a huge buffer (or allocate on the stack) and potentially exhaust memory or trigger a kernel panic.  No server‑side limit checks are present in the specification.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

The IDL declares an unbounded vector of 32‑bit GIDs in the response type rpctlssd_connect_res. The RPC framework generates C code that unmarshals this field using the xdr_array helper. In the generated unmarshalling routine the maximum size argument passed to xdr_array is the constant that bounds the vector length. For unbounded vectors the generator typically passes 0, which tells xdr_array to accept any length and to allocate the buffer on the heap. FreeBSD’s implementation of xdr_array contains no enforcement logic beyond the maxsize parameter; if that value is 0 the call will happily allocate a buffer proportional to the reported length. We have not found any code that validates the client‑supplied length against a hard bound such as RPC_MAX_GIDS or other configuration parameter, and the default is indeed 0 for this RPC. Therefore an attacker can send a request with a very large gid vector length, causing the server to attempt to allocate a correspondingly large buffer in the XDR unmarshalling phase and potentially exhaust system memory (or a stack buffer if the server uses a stack‑allocated array, in which case the process will crash). This is an attacker‑reachable flaw that can lead to a denial‑of‑service via memory exhaustion, satisfying the definition of a VALID vulnerability.

We verified the absence of a bound by grepping for the generated unmarshalling function and inspecting the maxsize argument. No constant such as RPC_MAX_GIDS is present, and the caller passes 0 for the limit. No defensive code catches excessively large lengths before the allocation occurs.

Conclusion: VALID.

CRUX: Unbounded gid vector in rpctlssd_connect_res is unmarshalled without any size limit, allowing an attacker to supply an arbitrarily large vector length and trigger memory exhaustion.
GREP: xdr_rpctlssd_connect_res.*xdr_array

### Round 4: ✅ VALID

[ARBITER] The IDL defines `gid<>` as an unbounded array of `uint32_t`. rpcgen generates unmarshalling code that calls `xdr_array` with a maximum size of 0 (unlimited). The XDR library therefore accepts whatever length the client supplies, allocating that many 4‑byte elements on the heap. An attacker can send a vector length up to the 32‑bit limit, leading the server to allocate an enormous buffer and exhaust its memory. No server‑side size validation is present. This is a real, exploitable memory‑exhaustion vulnerability.

