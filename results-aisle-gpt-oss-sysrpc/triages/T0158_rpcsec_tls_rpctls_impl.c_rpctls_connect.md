# Triage T0158: `rpctls_connect`

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

`rpctls_connect`

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] rpctls_connect is invoked exclusively from kernel‑side code after the certname string has already been copied from a trusted kernel buffer that was supplied by the NFS mount subsystem. The string is therefore guaranteed to be a valid, null‑terminated kernel string and cannot point to arbitrary memory. The call to strlen does not receive user‑controlled data, and the 32‑bit length field is not used in a way that could cause an integer overflow or out‑of‑bounds read. Consequently, the situation described in the report cannot be reproduced, and there is no real security vulnerability.

