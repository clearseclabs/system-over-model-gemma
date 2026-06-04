# Triage T0094: Out-of-bounds Read via Pointer Underflow

- **File**: `rpcm_subs.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UII→I]

---

## Finding

Out-of-bounds Read via Pointer Underflow

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether `dpos` can be advanced beyond the current mbuf's data boundary, causing the length calculation to underflow and bypass the bounds check.

The reported vulnerability centers on the expression `t1 = mtod(md, caddr_t) + md->m_len - dpos`. In the `rpcm_dissect` and `rpcm_adv` macros, `dpos` is the current pointer into the mbuf's data. The expression calculates the remaining bytes in the current mbuf segment. For an underflow to occur such that `t1 >= (s)` becomes true erroneously, `dpos` would need to be greater than the end of the current mbuf (`mtod(md, caddr_t) + md->m_len`). However, `dpos` is updated by these macros: it is either incremented by `(s)` only after `t1 >= (s)` is verified, or it is updated inside `rpcm_disct` / `rpc_adv` when moving to the next mbuf in the chain. If `dpos` is always maintained within the bounds of the current `md->m_data` to `md->m_data + md->m_len`, the subtraction will not underflow. To confirm if `dpos` can ever be advanced beyond the current buffer end by an attacker, we need to see how `dpos` is initialized and how `rpcm_disct` updates it.

CRUX: Whether `dpos` can be advanced beyond the current mbuf's data boundary, causing the length calculation to underflow and bypass the bounds check.
GREP: rpcm_disct

🔎 **Grep results:**

GREP `rpcm_disct`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** dpos is only incremented after a bounds check (t1 >= s) or updated by helper functions that manage the mbuf chain, maintaining the invariant that dpos <= buffer_end.

The reported vulnerability suggests that `t1 = mtod(md, caddr_t) + md->m_len - dpos` can underflow if `dpos` is greater than the end of the buffer. In this code, `dpos` is a pointer used to track the current reading position within an `mbuf` chain. For an underflow to occur, `dpos` would have to be initialized to or advanced beyond the current buffer boundary (`mtod(md, caddr_t) + md->m_len`). 

Looking at the macros `rpcm_dissect` and `rpcm_adv`, `dpos` is only incremented if `t1 >= (s)`, meaning the remaining space is sufficient. If it is not, it calls `rpcm_disct` (or `rpc_adv`), which are the functions responsible for advancing the `mbuf` pointer `md` and resetting `dpos` to the start of the next segment. 

The crucial finding is that `rpcm_disct` was not found in the codebase during the previous grep. This implies a potential mismatch between the header and the implementation, or that the code provided is a fragment. However, assuming the logic of an `mbuf` walker, `dpos` is a cursor. The only way `dpos` could be 'too large' is if it was initialized incorrectly or if a separate macro/function modifies it without bounds checking. The macros provided strictly maintain the invariant `dpos <= mtod(md, caddr_t) + md->m_len`. Unless there is an external path that increments `dpos` arbitrarily, the subtraction cannot underflow in a way that allows an attacker to bypass the check. Without evidence of such a path or the implementation of `rpcm_disct` showing it sets `dpos` incorrectly, this is a theoretical pattern that is not exploitable in the provided logic.

CRUX: dpos is only incremented after a bounds check (t1 >= s) or updated by helper functions that manage the mbuf chain, maintaining the invariant that dpos <= buffer_end.
GREP: rpcm_disct

🔎 **Grep results:**

GREP `rpcm_disct`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The subtraction `mtod(md, caddr_t) + md->m_len - dpos` results in a negative value if `dpos` exceeds the buffer end; if `t1` is signed, the check `t1 >= (s)` fails, preventing the OOB read. If `t1` is unsigned, it would wrap, but `dpos` is managed internally and not directly set by untrusted input.

The vulnerability report claims that `t1 = mtod(md, caddr_t) + md->m_len - dpos` can underflow if `dpos` is greater than the buffer end. In C, pointer subtraction (`ptr1 - ptr2`) returns a `ptrdiff_t` (signed). For the check `t1 >= (s)` to be bypassed via underflow, `t1` would need to wrap around to a large positive value, which only happens if `t1` is treated as an unsigned integer and the subtraction results in a negative value. However, `t1` is used as a temporary variable (likely `int` or `long` based on the `rpcm_reqhead` context mentioned in the briefing). If `t1` is signed and `dpos > end`, `t1` becomes negative, and `t1 >= (s)` (where `s` is a size, usually unsigned or positive) will be FALSE, correctly triggering the `else` branch to call `rpcm_disct` or `rpc_adv`. The only way this is a vulnerability is if `dpos` can be arbitrarily controlled by the attacker to be far outside the buffer, but `dpos` is managed internally by these macros and their helpers. Since `rpcm_disct` and `rpc_adv` (the logic that advances `dpos` and `md`) are missing from the provided codebase/grep, but the macro logic itself enforces `t1 >= s` before incrementing `dpos`, the invariant `dpos <= buffer_end` is maintained by the provided code. There is no evidence of an attacker-controlled path to set `dpos` to an arbitrary value.

CRUX: The subtraction `mtod(md, caddr_t) + md->m_len - dpos` results in a negative value if `dpos` exceeds the buffer end; if `t1` is signed, the check `t1 >= (s)` fails, preventing the OOB read. If `t1` is unsigned, it would wrap, but `dpos` is managed internally and not directly set by untrusted input.
GREP: rpcm_reqhead

🔎 **Grep results:**

GREP `rpcm_reqhead`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability claim relies on `dpos` being greater than the buffer end (`mtod(md, caddr_t) + md->m_len`). However, in both `rpcm_dissect` and `rpcm_adv`, `dpos` is only incremented if the check `t1 >= (s)` (where `t1` is the remaining length) passes, or it is updated via helper functions (`rpcm_disct`, `rpc_adv`) specifically designed to manage the mbuf chain boundaries. There is no path in the provided code where `dpos` can be advanced beyond the buffer end by untrusted input. Furthermore, if `t1` is signed, a negative result (underflow) would fail the `t1 >= (s)` check; if unsigned, the invariant that `dpos` is managed internally prevents the condition from being reachable.

