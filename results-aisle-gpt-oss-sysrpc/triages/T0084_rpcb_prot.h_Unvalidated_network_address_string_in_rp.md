# Triage T0084: Unvalidated network address string in rpcb_getaddr/_versaddr

- **File**: `rpcb_prot.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unvalidated network address string in rpcb_getaddr/_versaddr

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The provided header only defines RPCXDR interfaces that use the standard XDR `string` type, which inherently validates the length of the string during unmarshalling. There is no evidence in the source that the returned address string is copied or handled without checking its bounds before being used. Consequently, the claim of an unvalidated network‑address string leading to a buffer overflow cannot be substantiated by the available evidence. Hence the vulnerability claim is not considered valid.

