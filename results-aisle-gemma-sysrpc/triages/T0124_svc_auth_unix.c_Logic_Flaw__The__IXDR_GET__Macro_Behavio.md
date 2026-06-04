# Triage T0124: Logic Flaw: The `IXDR_GET` Macro Behavior

- **File**: `svc_auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Logic Flaw: The `IXDR_GET` Macro Behavior

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The loop index `i` is strictly checked against `XU_NGROUPS - 1` before writing to the array, and the input buffer length is verified against the total expected size including `supp_ngroups`.

The report claims there is a 'Logic Flaw' but then concludes 'There is no buffer overflow.' The analysis provided in the report actually proves the code is safe. Specifically, the loop iterates `supp_ngroups` times, but writes to `xcr->cr_sgroups[i]` only if `i < XU_NGROUPS - 1`. This prevents an out-of-bounds write to the `cr_sgroups` array. The `buf` pointer is incremented in both branches of the if/else, ensuring that the input buffer is consumed correctly regardless of whether the value is stored or skipped. The bounds checks on `auth_len` using `min_len`, `str_len`, and `supp_ngroups * BYTES_PER_XDR_UNIT` ensure that the pointer `buf` does not read past the end of the allocated `oa_base` buffer. The scanner report describes the behavior but fails to identify an actual vulnerability.

CRUX: The loop index `i` is strictly checked against `XU_NGROUPS - 1` before writing to the array, and the input buffer length is verified against the total expected size including `supp_ngroups`.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The array access is guarded by `if (i < XU_NGROUPS - 1)` and the buffer read is guarded by a total length check against `auth_len`.

The vulnerability report is contradictory; it describes the pointer arithmetic of the `IXDR_GET` macros and then concludes 'There is no buffer overflow.' I will evaluate if any actual bug exists. 

1. **Array Bounds**: The code writes to `xcr->cr_sgroups[i]` only if `i < XU_NGROUPS - 1`. This is a strict bounds check. Even if `supp_ngroups` is large, the write is guarded. 
2. **Buffer Over-read**: The code performs three length checks on `auth_len`:
   - `auth_len < min_len` (prevents reading `time` and `str_len`)
   - `auth_len < min_len + str_len` (prevents reading UID, GID, and `supp_ngroups`)
   - `auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT` (prevents reading the group list).

3. **Pointer Arithmetic**: The `IXDR_GET` macros (based on standard XDR implementations) advance the pointer. The loop contains an `if/else` where both branches advance the pointer (`IXDR_GET_INT32(buf)` advances it by 4, and `buf++` advances it by `sizeof(int32_t)` if `buf` is an `int32_t *`). Wait—the code says `buf++`. If `buf` is `int32_t *`, `buf++` advances the pointer by 4 bytes. If the macro also advances by 4 bytes, the pointer movement is consistent across both branches. 

4. **Potential Issue**: I need to verify the definition of `XU_NGROUPS` and `BYTES_PER_XDR_UNIT`. However, the logic fundamentally prevents an OOB write to `cr_sgroups` via the `if (i < XU_NGROUPS - 1)` check and prevents an OOB read via the `auth_len` check. The scanner report itself admits 'There is no buffer overflow.'

CRUX: The array access is guarded by `if (i < XU_NGROUPS - 1)` and the buffer read is guarded by a total length check against `auth_len`.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The array write is explicitly guarded by `XU_NGROUPS - 1` and the input buffer read is guarded by a comprehensive `auth_len` check.

The reported vulnerability is contradictory; it traces the pointer arithmetic but concludes 'There is no buffer overflow.' I will verify if any actual flaw exists. 

1. **Array Bounds**: The write to `xcr->cr_sgroups[i]` is guarded by `if (i < XU_NGROUPS - 1)`. This ensures that even if `supp_ngroups` is large, we never write past the end of the `cr_sgroups` array. 
2. **Buffer Read Bounds**: The code performs rigorous checks on `auth_len` before reading. It checks `min_len`, then `min_len + str_len`, and finally `min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`. This prevents any out-of-bounds read from the `oa_base` buffer.
3. **Pointer Logic**: The loop contains `if (i < XU_NGROUPS - 1) xcr->cr_sgroups[i] = IXDR_GET_INT32(buf); else buf++;`. Since `buf` is an `int32_t *`, `buf++` increments the pointer by `sizeof(int32_t)` (typically 4 bytes). Assuming `IXDR_GET_INT32` also increments the pointer by 4 bytes, the pointer movement is consistent in both branches of the loop. Even if it weren't, it would only affect the consumption of the input buffer, not cause a memory safety violation, as the `auth_len` check already bounded the total available data.

The report fails to identify any actual vulnerability, and the code employs standard defensive patterns for parsing XDR streams.

CRUX: The array write is explicitly guarded by `XU_NGROUPS - 1` and the input buffer read is guarded by a comprehensive `auth_len` check.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability is self-contradictory, as the reporter's own analysis concludes 'There is no buffer overflow.' A technical review of the code confirms that the loop is safe: the write to `xcr->cr_sgroups[i]` is strictly guarded by `if (i < XU_NGROUPS - 1)`, and the input buffer access is protected by a comprehensive length check (`auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`) performed before the loop begins. There is no evidence of a logic flaw or memory corruption.

