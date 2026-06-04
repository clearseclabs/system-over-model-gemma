# Triage T0081: Unbounded XDR string unmarshalling of rpcb fields

- **File**: `rpcb_prot.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unbounded XDR string unmarshalling of rpcb fields

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The header alone does not expose how the XDR functions for the `rpcb` struct handle string lengths. In standard rpcgen‑generated code the `xdr_string()` call takes an explicit maximum size parameter; this bound is typically defined in the accompanying implementation file (`rpcb_prot.c`). Because that file is not provided, we cannot confirm whether an unsized string is used. Without evidence that the generated XDR routines accept an arbitrary length, the claim of an unbounded allocation cannot be substantiated. Therefore, based on the available code, the vulnerability cannot be considered real.

