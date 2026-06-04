# Triage T0108: Unbounded buffer reads from XDR data

- **File**: `svc_auth_unix.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

Unbounded buffer reads from XDR data

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The function trusts oa_length to size the XDR memory buffer.  If a malicious packet advertises an excessively large oa_length, XDR_INLINE() will return a pointer into that non‑existent buffer.  All subsequent IXDR_GET_* calls then read beyond the actual bytes received.  The code’s sanity checks bound only the numeric values read from the buffer (e.g., str_len, supp_ngroups) but never constrain oa_length to the real packet length.  Thus the routine can perform out‑of‑bounds reads, potentially leaking data or causing a crash.  This matches the classic “unbounded buffer read” flaw. The evidence (code analysis and numeric constants) confirms that the length value can exceed the real payload size without being caught by the checks, making the vulnerability real.

