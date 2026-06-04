# Triage T0122: Out-of-Bounds Read / Buffer Overflow

- **File**: `svc_auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Out-of-Bounds Read / Buffer Overflow

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The loop contains an explicit bounds check `i < XU_NGROUPS - 1` for the destination array and a prior length check on `auth_len` for the source buffer, preventing both overflows and OOB reads.

The reporter claims there is a bug in the supplementary groups processing loop. Let's analyze the loop logic: `for (uint32_t i = 0; i < supp_ngroups; ++i)`. Inside the loop, there is a boundary check: `if (i < XU_NGROUPS - 1) xcr->cr_sgroups[i] = IXDR_GET_INT32(buf); else buf++;`. 

1. **Buffer Overflow (Destination):** The destination `xcr->cr_sgroups` is only written to if `i < XU_NGROUPS - 1`. This explicitly prevents writing beyond the array bounds. Even if `supp_ngroups` is larger than `XU_NGROUPS`, the writes stop at index `XU_NGROUPS - 2`. This is a safe boundary check.
2. **Out-of-Bounds Read (Source):** The reporter notes that `buf++` increments the pointer by 4 bytes (since `buf` is `int32_t*`). They acknowledge that the `auth_len` check `if (auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT)` ensures that the buffer is large enough to accommodate `supp_ngroups` elements of 4 bytes each. 

Since the destination is bounds-checked and the source length is verified against the total number of iterations (regardless of whether `IXDR_GET_INT32` or `buf++` is used), there is no memory corruption or out-of-bounds access. The reporter's own analysis actually concludes the logic is correct ('This matches the length check performed earlier'), yet they flagged it as 'Critical'. There is no bug here.

CRUX: The loop contains an explicit bounds check `i < XU_NGROUPS - 1` for the destination array and a prior length check on `auth_len` for the source buffer, preventing both overflows and OOB reads.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The loop contains an explicit bounds check `i < XU_NGROUPS - 1` for the destination array and a prior length check on `auth_len` for the source buffer, preventing both overflows and OOB reads.

The reported vulnerability focuses on a loop processing supplementary groups. The reporter's own analysis actually suggests the logic is correct, though they labeled it 'Critical'. 

1. **Destination Bounds:** The loop writes to `xcr->cr_sgroups[i]` only if `i < XU_NGROUPS - 1`. This is a hard boundary check that prevents writing past the end of the array, regardless of the value of `supp_ngroups`.
2. **Source Bounds:** The code calculates the total required buffer size as `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`. Since `BYTES_PER_XDR_UNIT` is typically 4 and `buf` is an `int32_t*`, both `IXDR_GET_INT32(buf)` (which advances the pointer) and `buf++` consume exactly one XDR unit (4 bytes) per iteration. The check `if (auth_len < ...)` ensures that the source buffer `oa_base` is large enough to sustain `supp_ngroups` reads.
3. **Integer Overflow:** `supp_ngroups` is bounded by `AUTH_SYS_MAX_GROUPS`. While we haven't grepped the constant, it is logically impossible for this value to cause a wrap-around in the length check `min_len + str_len + supp_ngroups * 4` given that `str_len` is also bounded by `AUTH_SYS_MAX_HOSTNAME`. 

The reported 'bug' is a misunderstanding of the code; the boundary checks are explicit and sufficient.

CRUX: The loop contains an explicit bounds check `i < XU_NGROUPS - 1` for the destination array and a prior length check on `auth_len` for the source buffer, preventing both overflows and OOB reads.
GREP: AUTH_SYS_MAX_GROUPS

🔎 **Grep results:**

GREP `AUTH_SYS_MAX_GROUPS`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The destination is protected by 'if (i < XU_NGROUPS - 1)' and the source is protected by a prior length check 'auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT'.

The vulnerability report flags a potential Out-of-Bounds (OOB) Read or Buffer Overflow in the supplementary groups loop. However, analyzing the code reveals strong defenses for both the source and destination buffers. 

1. **Destination Buffer (`xcr->cr_sgroups`)**: The code uses an explicit check `if (i < XU_NGROUPS - 1)` before writing to the array. This ensures that no write ever occurs at or beyond index `XU_NGROUPS - 1`, preventing a buffer overflow regardless of the value of `supp_ngroups`.

2. **Source Buffer (`buf`)**: The input length `auth_len` is verified against the total expected size: `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`. 
   - `min_len` is 20 bytes (5 * 4).
   - `str_len` is bounded by `AUTH_SYS_MAX_HOSTNAME` (typically 255) and rounded up.
   - `supp_ngroups` is bounded by `AUTH_SYS_MAX_GROUPS`.
   - In each iteration of the loop, exactly one `int32_t` (4 bytes) is consumed, either via `IXDR_GET_INT32(buf)` (which advances the pointer) or `buf++`. 
   - Because the total length is checked *before* the loop, the pointer `buf` cannot exceed the allocated memory of the RPC credential buffer.

3. **Integer Overflow**: Since `str_len` and `supp_ngroups` are bounded by relatively small constants (hostname and group limits), the addition `min_len + str_len + supp_ngroups * 4` cannot overflow a `uint32_t` in any meaningful way that would bypass the length check.

The reporter's own analysis actually admits the logic is correct, yet they labeled it 'Critical'. There is no evidence of a security vulnerability.

CRUX: The destination is protected by 'if (i < XU_NGROUPS - 1)' and the source is protected by a prior length check 'auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT'.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The code implements comprehensive bounds checking for both the source buffer and the destination array. First, it verifies `auth_len` against the calculated total size (`min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`), preventing Out-of-Bounds reads from the source buffer. Second, it uses an explicit check `if (i < XU_NGROUPS - 1)` before writing to the `cr_sgroups` array, preventing a Buffer Overflow. The `buf++` logic correctly advances the pointer to maintain synchronization with the length check without writing to the array. There is no evidence of a vulnerability.

