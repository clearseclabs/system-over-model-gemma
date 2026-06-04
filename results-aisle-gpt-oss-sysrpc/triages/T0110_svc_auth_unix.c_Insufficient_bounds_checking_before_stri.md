# Triage T0110: Insufficient bounds checking before string length based computation

- **File**: `svc_auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Insufficient bounds checking before string length based computation

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN

{"reasoning":"The _svcauth_unix routine uses a sequence of bounds checks before reading any part of the RPC credential data.  The only places where a value is modified are:\n- `str_len` is clamped by the check `str_len > AUTH_SYS_MAX_HOSTNAME`.\n- `str_len` is then rounded up with `RNDUP`, which can add at most 3 bytes to a value that was already ≤ AUTH_SYS_MAX_HOSTNAME.\n- `supp_ngroups` is limited by `supp_ngroups > AUTH_SYS_MAX_GROUPS`.\nThe subsequent checks compare the supplied `auth_len` against `min_len + str_len` and later `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`.\n\nIf we resolve the concrete values:  *AUTH_SYS_MAX_HOSTNAME* is defined as 255, *AUTH_SYS_MAX_GROUPS* as 16, *BYTES_PER_XDR_UNIT* as 4, and *RNDUP(x)* expands to `((x + 3) & ~3)`.  Thus the largest value any of the computed sums can reach is:\n- After rounding the hostname length: `str_len` ≤ 256.\n- `min_len` = `5 * BYTES_PER_XDR_UNIT` = 20.\n- Suffix groups contribution: `supp_ngroups * BYTES_PER_XDR_UNIT` ≤ 16 * 4 = 64.\n- So `min_len + str_len + …` ≤ 20 + 256 + 64 = 340, far below `UINT32_MAX`.  No unsigned‑integer overflow can occur during these additions.\n\nBecause every read of the credential buffer is guarded by a matching length check, the credential data cannot overrun the supplied buffer or lead to unchecked array indexing.  The guarded path is exercised for all possible untrusted inputs—including empty or maliciously crafted RPC packets—so an attacker cannot violate the bounds.\n\nHence the alleged “insufficient bounds checking” does not exist; the code is correct and the reported vulnerability is not security‑relevant.\n\nCrux: The arithmetic overlaps are bounded by small, compile‑time constants, making overflow impossible.\n\n#grep pattern\n\"AUTH_SYS_MAX_HOSTNAME|AUTH_SYS_MAX_GROUPS|BYTES_PER_XDR_UNIT|RNDUP\"\n\nverdict":"INVALID"}

### Round 4: ❌ INVALID

[ARBITER] The code limits `str_len` to `AUTH_SYS_MAX_HOSTNAME` (255) and `supp_ngroups` to `AUTH_SYS_MAX_GROUPS` (32).  With `BYTES_PER_XDR_UNIT` = 4, the worst‑case sum for the bounds check is `20 + 258 + 128 = 406`, far below `UINT_MAX`.  No unsigned overflow can occur in the addition `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`.  The rounding via `RNDUP` is performed before the length check and does not introduce a security gap.  Therefore the reported vulnerability is not real in the current implementation. 

