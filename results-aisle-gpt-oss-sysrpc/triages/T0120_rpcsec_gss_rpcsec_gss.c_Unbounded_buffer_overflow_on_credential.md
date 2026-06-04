# Triage T0120: Unbounded buffer overflow on credential serialization

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unbounded buffer overflow on credential serialization

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The credential is serialized via XDR into the stack buffer `credbuf[MAX_AUTH_BYTES]`. The XDR library (FreeBSD’s `xdrmem_*` implementation) performs boundary checks before each write; if the serialized size would exceed the buffer it returns FALSE. `rpc_gss_marshal` checks this result and aborts, setting an error. Thus an attacker supplying an oversized GSS token cannot cause a buffer overflow; the serialization simply fails gracefully. Therefore the claim of an unbounded buffer overflow is not supported by the code.

