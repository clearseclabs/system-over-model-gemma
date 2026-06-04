# Triage T0004: Untagged union in `struct rpc_err` allows misinterpretation of error data

- **File**: `clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Untagged union in `struct rpc_err` allows misinterpretation of error data

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The anonymous union in `struct rpc_err` is a design choice rather than a security flaw. The RPC library populates the union based on the `re_status` value, and callers are expected to inspect `re_status` before accessing the correct member. Misreading the wrong member would generally result in incorrect error handling or program crashes, but it does not expose memory beyond the small data already provided in the struct, nor does it allow an attacker to manipulate it to leak sensitive information. No numeric values in the source indicate misuse or undefined behavior. Therefore, the claim does not constitute a genuine vulnerability.

