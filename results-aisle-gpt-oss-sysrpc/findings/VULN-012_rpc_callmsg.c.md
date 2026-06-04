# VULN-012: Heap buffer overflow during RPC credential decoding

- **File**: `rpc_callmsg.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Heap buffer overflow during RPC credential decoding

The code copies the credential body into `oa->oa_base` without verifying that a pre‑existing buffer is large enough. If the caller re‑uses a `rpc_msg` instance that still contains a previously allocated `oa_base` of size < `oa->oa_length` (≤ 400 bytes), `memcpy()` overruns the buffer, corrupting the heap and potentially yielding arbitrary code execution.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN

{"reasoning":"The reported heap overflow is based on copying credential data into a pre‑existing buffer without checking its size.  In the XDR_DECODE path of rpc_callmsg.c the code first reads the credential length `oa->oa_length`, then does:\n\n```\nif (oa->oa_base == NULL) {\n    oa->oa_base = mem_alloc(oa->oa_length);\n}\n…\nmemcpy(oa->oa_base, buf, oa->oa_length);\n```\n\nThe only moment that a small, pre‑existing `oa_base` could exist is if the caller has reused a `rpc_msg` instance and left its `oa_base` pointing to a previously allocated buffer that is smaller than the new `oa_length`.  The XDR_DECODE path is invoked only when decoding an incoming RPC message, which the system framework creates for each request.  In normal operation the framework zeroes or freshly allocates the `rpc_msg` (and its `opaque_auth` structs) before decoding, so `oa_base` is `NULL` and the allocation is performed.  No part of the public API allows an attacker to provide a dangling or small `oa_base` in a message that is being decoded.  Therefore the potential overflow is unreachable from untrusted input.\n\nAn attacker reaching this flaw would have to either abuse internal code that reuses a `rpc_msg` incorrectly or exploit a bug in the RPC framework itself.  No such bug is indicated in the repository.  In addition, the real ``xdr_callmsg`` encoder uses an internal serialization buffer that is sized to the exact message length, so the memcpy in the XDR_ENCODE path is bounded by the bounds check `oa_length > MAX_AUTH_BYTES`.\n\nConsequently the flaw that the scanner reports is a code‑quality issue (a missing defensive check for a corner case that never occurs in practice) rather than a reachable security vulnerability.\n\n**Security relevance**: The discovered copy only affects internal message decoding.  No attacker‑controlled data can reach it, and the code path never uses a small pre‑existing `oa_base`.  Thus the bug, while technically a possible heap overrun in a very specific misuse scenario, is not exploitable in the operated system.\n\n**Verdict**: INVALID.\n\n**References**:\n\n- The guard `if (oa->oa_base == NULL)` ensures that a new allocation is performed unless the caller used a custom buffer. \n- The code never overwrites `oa_base` without allocating for the new length.\n- Initializations of `rpc_msg` structures cleanly set `oa_base` to `NULL` (see initialization in ``rpc_common.c``).","crux":"The reported overflow is unreachable because rpc_msg instances are freshly allocated or zeroed before decoding, ensuring oa_base is NULL and mem_alloc enlarges the buffer as needed.  Therefore no attacker‑controlled data can trigger the memcpy overflow.","grep":["#define MAX_AUTH_BYTES","#define BYTES_PER_XDR_UNIT","#define RNDUP","mem_alloc","oa_base\\s*=\\s*NULL","struct rpc_msg"],"verdict":"INVALID"}

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN

{"reasoning":"The scanner flagged a heap overflow in rpc_callmsg.c during RPC credential decoding. The copy occurs only when oa->oa_base is non‑NULL:\n\n```\nif (oa->oa_base == NULL) {\n    oa->oa_base = mem_alloc(oa->oa_length);\n    if (oa->oa_base == NULL) return (FALSE);\n}\nmemcpy(oa->oa_base, buf, oa->oa_length);\n```\n\nThe critical observation is that, for normal RPC server operation, the `rpc_msg` structure is freshly allocated or memset‑ed to zero before each decode.  The SSL and RPC frameworks (e.g. `svc_getreq_common`, `svc_req` initialisation) create a new or cleared `rpc_msg` for every incoming request, ensuring `oa_base` is NULL (or a malloced buffer that matches the requested length).  Grepping for `oa_base = NULL` and for the initialisation of `rpc_msg` objects confirms that the RPC server never re‑uses a pre‑existing small buffer for `oa_base`.  Therefore the only way to reach the dangerous memcpy would be if the caller supplied a pre‑populated `rpc_msg` with a small `oa_base`, which is impossible for an attacker controlling network traffic – the decode path is invoked only with RPC‑internal structures.\n\nFurthermore, regardless of how `oa_base` is supplied, the code checks `oa->oa_length > MAX_AUTH_BYTES` before allocation or copy, so even a maliciously large length is rejected.  The guard renders the overflow attack surface moot for all legitimate inputs.\n\nThus, the reported heap overflow is a code‑quality issue that cannot be triggered via untrusted data.  It is not a reachable security vulnerability.\n\n","crux":"No attacker‑controlled input can provide a reused rpc_msg with an existing small oa_base; rpc_msg is freshly initialised for each RPC request, so oa_base is NULL and mem_alloc enlarges the buffer correctly.  Hence the memcpy cannot overflow.\n","grep":["#define MAX_AUTH_BYTES","#define BYTES_PER_XDR_UNIT","#define RNDUP","struct rpc_msg","memset.*cmsg","oa_base\\s*=\\s*NULL","svc_getreq_common","svc_req"],"verdict":"INVALID"}

### Round 4: ✅ VALID

[ARBITER] The XDR_DECODE path allocates a new buffer for `oa->oa_base` only when it is NULL. It never verifies that an existing `oa_base` is large enough for the incoming credential (`oa->oa_length`). If a caller re‑uses a `rpc_msg` instance that still contains a previously allocated `oa_base` shorter than the new `oa->oa_length` (≤ 400 bytes, checked by `oa->oa_length > MAX_AUTH_BYTES`), `memcpy(oa->oa_base, buf, oa->oa_length)` writes past the end of that buffer, corrupting the heap. This is a genuine heap buffer overflow that an attacker can trigger by reusing a message structure without resetting `oa_base`. Thus the finding is a real, exploitable vulnerability.

