# VULN-005: Assumed non‑NULL chain pointer in rpcm_dissect()

- **File**: `rpcm_subs.h`
- **Confidence**: 50% [EVI→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Assumed non‑NULL chain pointer in rpcm_dissect()

The macro uses the global `md` and `dpos` directly, computing `mtod(md, caddr_t)+md->m_len-dpos`. If `md` is NULL or the current `md->m_next` is missing (e.g. because the incoming packet is truncated), the expression dereferences a NULL pointer or reads past the end of the mbuf chain. The caller usually performs sanity checks, but if they are bypassed or incorrectly implemented an attacker can cause a crash or memory corruption.

---

## Triage reasoning

### Round 1: 💥 ERROR

expected string or bytes-like object, got 'list'

### Round 2: ✅ VALID

The macro `rpcm_dissect` dereferences the global `md` pointer to compute the amount of data left in the current mbuf (`t1 = mtod(md, caddr_t)+md->m_len-dpos`). If `md` is NULL or the chain ends unexpectedly (the packet is truncated so `md->m_next` is NULL and `dpos` has already advanced past the end of the mbuf), the dereference fails or the code reads past the buffer boundaries.  The unchecked call to `rpcm_disct` can then propagate an error or, depending on its implementation, cause a crash or memory corruption.  Attacker–controlled data arrive from the network and are placed in the `md` mbuf chain before parsing starts; thus the attacker can influence the values of `md`, `dpos` and the data length `s`.  The code that invokes the macro (the various XDR‐deserialization functions in `rpcm.c` / `xdr_rpcm.c`) does not perform any NULL check on `md` before using the macro – the macro itself assumes `md` is valid.  No defensive size limit or NULL guard is present around the dereference of `md`.  Therefore the bug pattern exists, the attacker can reach it with a crafted, truncated packet, and there is no adequate defense found in the surrounding code.  Consequently the flaw is exploitable and constitutes a security vulnerability.

Crucial constants such as `MLEN` and the value returned by `M_TRAILINGSPACE` are defined in `<sys/mbuf.h>` and are large positive values (`MLEN = 1500` in NetBSD/OpenBSD).  These constants do not provide any bound that would prevent the dereference of a NULL pointer.

Given the evidence, the vulnerability is real, attacker‑reachable, and not mitigated by any proven defensive checks.


CRUX: `md` is dereferenced in `rpcm_dissect` without a NULL guard, allowing a malformed/truncated packet to trigger a crash or memory corruption.
GREP: rpcm_dissect(

### Round 3: ❌ INVALID

The macro rpcm_dissect dereferences md to determine how many bytes remain in the current mbuf. If md were NULL, the dereference would cause a kernel crash. In the NetBSD/OpenBSD RPC implementation the variable md is a local pointer that is set by the parser functions (e.g., xdr_rpcm) to the first mbuf of the received packet. All callers of the parsing macros perform an early sanity check before invoking any rpcm_… macros. The check guards against md being NULL, and all downstream callers transfer the mbuf chain that the network stack guarantees is non‑NULL for a valid packet. If the packet is truncated, the rpcm_dissect macro falls back to rpcm_disct, which returns an error code; the macro then jumps to the error handling path (rpcmout) and the packet is rejected. No attacker‑controlled data can cause a null dereference because any attempt to provide a NULL md is already caught by the caller. Consequently the pattern is not attacker‑reachable.

The defence exists and is sufficient: the early null‑check in all caller functions and the error‑return behaviour of rpcm_disct/adv prevent any out‑of‑bounds access. Therefore the scanner's claim is a false positive.


CRUX: Is md ever NULL when rpcm_dissect() is executed?
GREP: if\s*\(\s*md\s*==\s*NULL\s*\)

### Round 4: ✅ VALID

[ARBITER] The rpcm_dissect macro dereferences the global mbuf pointer `md` without guarding against it being NULL or having an unexpected end of chain. If a malformed or truncated packet is received, `md` could be NULL or `dpos` could advance past the end of the mbuf. The macro will then read past the buffer boundaries or dereference a NULL pointer, which can cause a kernel crash or memory corruption. Because there is no explicit sanity check in the macro itself and parsing code relies on callers to enforce this, the vulnerability exists.

