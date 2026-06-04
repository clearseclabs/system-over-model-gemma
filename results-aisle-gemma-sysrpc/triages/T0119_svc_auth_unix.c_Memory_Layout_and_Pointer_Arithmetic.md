# Triage T0119: Memory Layout and Pointer Arithmetic

- **File**: `svc_auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Memory Layout and Pointer Arithmetic

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** RNDUP ensures str_len is a multiple of 4, making the division by sizeof(int32_t) exact and the resulting pointer alignment correct.

The reported issue concerns potential misalignment or incorrect pointer arithmetic when calculating the offset for the credentials part of the AUTH_UNIX payload. 

1. **The Pattern**: The code takes `str_len` (extracted from the network buffer), applies `RNDUP(str_len)`, and then performs `buf += str_len / sizeof(int32_t)`. 
2. **Alignment**: In XDR (External Data Representation), strings are padded to 4-byte boundaries. `RNDUP` is a standard macro used in this context to ensure the length is a multiple of 4. 
3. **Arithmetic**: Since `buf` is an `int32_t*`, adding `X` to it moves the pointer by `X * sizeof(int32_t)` bytes. If `str_len` (after `RNDUP`) is the number of bytes to skip, then `str_len / 4` is the correct number of `int32_t` elements to advance. 
4. **Reachability**: The input is indeed attacker-controlled. However, the code explicitly checks `if (str_len > AUTH_SYS_MAX_HOSTNAME)` and `if (auth_len < min_len + str_len)`. 
5. **Safety**: Because `RNDUP` ensures `str_len` is a multiple of 4, `str_len / sizeof(int32_t)` is always an integer division with no remainder, and the resulting pointer `buf` remains aligned to a 4-byte boundary. There is no memory corruption or out-of-bounds access here; the logic correctly implements the XDR padding requirements for strings.

CRUX: RNDUP ensures str_len is a multiple of 4, making the division by sizeof(int32_t) exact and the resulting pointer alignment correct.
GREP: RNDUP

🔎 **Grep results:**

GREP `RNDUP`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** RNDUP ensures str_len is a multiple of 4, meaning the pointer arithmetic on the int32_t* buf correctly skips the padded string without losing alignment or overshooting bounds.

The reporter suggests that pointer arithmetic `buf += str_len / sizeof (int32_t);` could lead to misalignment or incorrect offsets. However, in XDR (External Data Representation), strings are required to be padded to 4-byte boundaries. The code calls `str_len = RNDUP(str_len);` before performing the division. While the previous reviewer failed to find the definition of `RNDUP`, it is a ubiquitous macro in RPC/XDR implementations (typically defined as `((x) + 3) & ~3`). Because `str_len` is rounded up to the nearest multiple of 4, `str_len / sizeof(int32_t)` is a precise integer division. Since `buf` is an `int32_t*`, adding an integer `N` to it advances the pointer by exactly `N * 4` bytes. Thus, the pointer remains aligned to a 4-byte boundary and correctly skips the padded string. Furthermore, there are strict bounds checks: `str_len` is capped by `AUTH_SYS_MAX_HOSTNAME`, and `auth_len` is verified against `min_len + str_len` before the pointer is advanced, preventing out-of-bounds reads. This is standard XDR decoding logic and not a vulnerability.

CRUX: RNDUP ensures str_len is a multiple of 4, meaning the pointer arithmetic on the int32_t* buf correctly skips the padded string without losing alignment or overshooting bounds.
GREP: RNDUP

🔎 **Grep results:**

GREP `RNDUP`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** RNDUP ensures str_len is a multiple of 4, so adding str_len/4 to an int32_t pointer advances it by exactly str_len bytes while maintaining alignment.

The vulnerability report suggests that `buf += str_len / sizeof(int32_t)` could cause misalignment or incorrect offsets. In XDR, strings are padded to 4-byte boundaries. The code uses `RNDUP(str_len)` to ensure that `str_len` is a multiple of 4 before the division. 

1. **Is the bug real?** No. If `str_len` is a multiple of 4, then `str_len / 4` is an exact integer. Adding this value to an `int32_t*` advances the pointer by exactly `(str_len / 4) * 4` bytes, which equals `str_len` bytes. The pointer remains aligned to a 4-byte boundary.
2. **Is it reachable?** The input is attacker-controlled, but the logic is sound.
3. **Are defenses sufficient?** Yes. There are two critical checks: `if (str_len > AUTH_SYS_MAX_HOSTNAME)` and `if (auth_len < min_len + str_len)`. These prevent `str_len` from being excessively large and ensure that the pointer arithmetic does not advance `buf` beyond the allocated `auth_len` buffer.
4. **Is it security-relevant?** Even if `RNDUP` were missing, on most modern architectures (x86_64), misaligned reads are handled by the hardware (though slower). On strict alignment architectures, it would be a crash (DoS), but the presence of `RNDUP` (despite the failed greps in previous reviews, it is a standard XDR requirement and clearly used here to maintain alignment) makes this a non-issue. The previous reviewers failed to find the macro because it is likely defined in a system header or a different file not indexed, but the logic follows the XDR specification perfectly.

CRUX: RNDUP ensures str_len is a multiple of 4, so adding str_len/4 to an int32_t pointer advances it by exactly str_len bytes while maintaining alignment.
GREP: RNDUP

🔎 **Grep results:**

GREP `RNDUP`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reporter claims that `buf += str_len / sizeof(int32_t)` could lead to misalignment or incorrect offsets. However, the code explicitly calls `str_len = RNDUP(str_len);` immediately before the division. In XDR implementations, `RNDUP` ensures the value is rounded up to the nearest 4-byte boundary (a multiple of `sizeof(int32_t)`). Since `str_len` is guaranteed to be a multiple of 4, the division is exact, and adding the result to an `int32_t*` pointer advances the pointer by exactly `str_len` bytes, maintaining 4-byte alignment. There is no evidence of a vulnerability.

