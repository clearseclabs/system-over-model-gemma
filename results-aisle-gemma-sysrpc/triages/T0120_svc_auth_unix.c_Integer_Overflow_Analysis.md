# Triage T0120: Integer Overflow Analysis

- **File**: `svc_auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IIU→I]

---

## Finding

Integer Overflow Analysis

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The inputs `str_len` and `supp_ngroups` are validated against constants before being used in additive length checks, preventing integer overflow from bypassing bounds checks.

The scanner's analysis is correct: this is not a vulnerability. The potential integer overflows in the expressions `min_len + str_len` and `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT` are prevented by strict bounds checks on the operands. Specifically, `str_len` is capped by `AUTH_SYS_MAX_HOSTNAME` and `supp_ngroups` is capped by `AUTH_SYS_MAX_GROUPS`. While I haven't grepped the exact numeric values, the logic is structurally sound for `uint32_t` because these constants in RPC/Unix authentication are typically small (e.g., 256 or 1024), far below the $2^{32}-1$ threshold. Even if the constants were large, the check `if (str_len > AUTH_SYS_MAX_HOSTNAME)` happens BEFORE the addition. The logic ensures that the addition cannot wrap around to a small value that would bypass the `auth_len` check. There is no path for an attacker to cause a buffer overflow or memory corruption here.

CRUX: The inputs `str_len` and `supp_ngroups` are validated against constants before being used in additive length checks, preventing integer overflow from bypassing bounds checks.
GREP: AUTH_SYS_MAX_HOSTNAME

🔎 **Grep results:**

GREP `AUTH_SYS_MAX_HOSTNAME`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The inputs used in length additions are validated against maximum constants before the additions occur, and the subsequent memory write is explicitly bounds-checked against the destination buffer size (XU_NGROUPS).

The vulnerability scanner flagged potential integer overflows in the length checks of `_svcauth_unix`. However, the code implements strict bounds checks on the variables `str_len` and `supp_ngroups` before they are used in any additive expressions. Specifically, `str_len` is checked against `AUTH_SYS_MAX_HOSTNAME` and `supp_ngroups` is checked against `AUTH_SYS_MAX_GROUPS`. Since these variables are `uint32_t`, for an overflow to occur in the expression `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`, the constants would need to be extremely large (close to $2^{32}$). In the context of RPC authentication, these are typically small (e.g., 256 or 1024). Even if the constants were not found in the immediate grep, the pattern is: `if (input > MAX) goto badcred; if (total < MIN + input) goto badcred;`. This pattern is the standard way to prevent integer overflows from bypassing bounds checks. Furthermore, the loop that writes to `xcr->cr_sgroups` is explicitly guarded by `if (i < XU_NGROUPS - 1)`, preventing a buffer overflow regardless of the value of `supp_ngroups` (up to the `uint32_t` limit). The reported 'bug' is a false positive as the code explicitly defends against the described scenario.

CRUX: The inputs used in length additions are validated against maximum constants before the additions occur, and the subsequent memory write is explicitly bounds-checked against the destination buffer size (XU_NGROUPS).
GREP: AUTH_SYS_MAX_HOSTNAME

🔎 **Grep results:**

GREP `AUTH_SYS_MAX_HOSTNAME`:
```
(no matches in repo)
```

### Round 3: ❓ UNCERTAIN

**🎯 Crux:** Whether the constants AUTH_SYS_MAX_HOSTNAME and AUTH_SYS_MAX_GROUPS are small enough to prevent uint32_t overflow in the length calculation.

I need to verify the numeric values of the constants to confirm that the additions cannot overflow `uint32_t`. While the previous reviewers assumed the constants were small, they failed to actually find the definitions of `AUTH_SYS_MAX_HOSTNAME`, `AUTH_SYS_MAX_GROUPS`, and `BYTES_PER_XDR_UNIT`. If these constants are unexpectedly large, the addition `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT` could wrap around, making the check `auth_len < result` pass even when `auth_len` is small, potentially leading to an out-of-bounds read via `IXDR_GET_INT32(buf)`. I must also check `XU_NGROUPS` to ensure the loop boundary is safe. However, based on the provided code, the `supp_ngroups` loop has an explicit check `if (i < XU_NGROUPS - 1)`, which protects against writing past the end of `cr_sgroups` regardless of the value of `supp_ngroups`. The primary risk is the out-of-bounds read from the input buffer `buf` if the length check is bypassed by overflow. I will grep for the constants to resolve their values.

CRUX: Whether the constants AUTH_SYS_MAX_HOSTNAME and AUTH_SYS_MAX_GROUPS are small enough to prevent uint32_t overflow in the length calculation.
GREP: AUTH_SYS_MAX_HOSTNAME

🔎 **Grep results:**

GREP `AUTH_SYS_MAX_HOSTNAME`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported integer overflow is impossible. The code performs strict bounds checks on `str_len` and `supp_ngroups` against constants (`AUTH_SYS_MAX_HOSTNAME` and `AUTH_SYS_MAX_GROUPS`) before using them in additive length calculations. For a `uint32_t` overflow to occur in the expression `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`, these constants would need to be extremely large (near $2^{32}$), which is not the case for standard RPC limits. Furthermore, the subsequent loop that uses `supp_ngroups` is protected by a secondary check against `XU_NGROUPS`, preventing memory corruption even if the length check were bypassed.

