# Triage T0067: Unvalidated host string length in rpcb_getaddr

- **File**: `rpcb_clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unvalidated host string length in rpcb_getaddr

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The header alone does not show the implementation of rpcb_getaddr.  Without the concrete source the existence of an unchecked copy into a 128‑byte buffer cannot be proven.  The code that allocates or checks the destination buffer is missing from the provided evidence.  Therefore the claim of an unvalidated host string length leading to a buffer overflow remains uncertain and cannot be confirmed as a real vulnerability based only on the given snippets.

