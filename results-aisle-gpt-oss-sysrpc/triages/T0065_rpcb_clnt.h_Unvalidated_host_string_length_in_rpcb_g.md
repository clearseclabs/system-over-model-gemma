# Triage T0065: Unvalidated host string length in rpcb_gettime

- **File**: `rpcb_clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unvalidated host string length in rpcb_gettime

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The supplied snippet is only the public header file declaring the `rpcb_gettime` prototype; no implementation details (such as a 256‑byte static buffer or a string‑copy without length checking) are present. Without the actual source of `rpcb_gettime`, there is no evidence that it performs an unchecked copy into a 256‑byte array. Therefore the claim of an unvalidated host string length overflow cannot be substantiated from the provided code, and the vulnerability cannot be confirmed as valid.

