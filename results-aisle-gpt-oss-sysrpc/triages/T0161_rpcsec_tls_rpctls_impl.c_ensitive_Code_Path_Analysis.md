# Triage T0161: ensitive Code Path Analysis

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

ensitive Code Path Analysis

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The server‐side upcall allocates a gid array using `*ngrps * sizeof(gid_t)` where `*ngrps` comes directly from the remote server’s `gid.gid_len` field. If that value is larger than `INT_MAX` the assignment `*ngrps = res.gid.gid_len` triggers undefined behavior, and if the value is larger than `SIZE_MAX/sizeof(gid_t)` the multiplication overflows, resulting in a too‑small allocation that is later over‑written by the copy loop. This unchecked buffer use due to an integer overflow is a real security vulnerability.

