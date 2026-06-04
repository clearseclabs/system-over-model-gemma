# Triage T0069: Negative or too large length in rpc_gss_principal_t

- **File**: `rpcsec_gss.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Negative or too large length in rpc_gss_principal_t

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The only evidence provided is the header file where `rpc_gss_principal_t` is defined as a pointer to a struct containing `int len` and a one‑byte variably sized array.  No code in the snippet allocates or accesses this structure, nor is any XDR or helper routine shown that checks `len` before using it.  Without seeing the concrete allocation, indexing or bounds checks performed by the implementation, we have no direct evidence that a negative or overly large `len` would result in a buffer over/under‑flow.  Consequently, based solely on the supplied code, the claim that the “negative or too large length” vector is exploitable cannot be confirmed.  Therefore the finding is judged **invalid** pending further source that demonstrates unsafe use of the struct.

