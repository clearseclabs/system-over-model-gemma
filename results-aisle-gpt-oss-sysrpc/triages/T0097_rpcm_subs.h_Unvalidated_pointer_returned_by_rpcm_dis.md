# Triage T0097: Unvalidated pointer returned by rpcm_disct()

- **File**: `rpcm_subs.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unvalidated pointer returned by rpcm_disct()

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The macro delegates all bounds checking to the helper function `rpcm_disct()`.  That function is responsible for ensuring that the returned pointer `cp2` points to a location on the current mbuf chain that can safely hold `s` bytes.  The code as shown does not itself create an unvalidated pointer; it simply relies on `rpcm_disct()` to handle the logic.  Without the implementation of `rpcm_disct()` we have no concrete evidence that it can return a pointer beyond the end of the available data.  Given the surrounding comments and the typical design of the NFS RPC parser, it is highly unlikely that the helper intentionally returns out‑of‑bounds pointers.  Therefore the reported vulnerability cannot be confirmed from the provided source and is judged **INVALID**.

