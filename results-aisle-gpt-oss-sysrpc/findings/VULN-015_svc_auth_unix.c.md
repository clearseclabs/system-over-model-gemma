# VULN-015: Unbounded buffer reads from XDR data

- **File**: `svc_auth_unix.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Unbounded buffer reads from XDR data

The code reads credentials directly from the XDR buffer using the length field `oa_length` from the network packet: `auth_len = (u_int)msg->rm_call.cb_cred.oa_length;`.  Although several checks are performed against `auth_len`, they rely on `oa_length` being a valid length for the supplied buffer.  An attacker can craft a packet in which `oa_length` is excessively large (or a negative value cast to an unsigned integer), bypassing those checks and causing `XDR_INLINE` to return a pointer that leads to out‑of‑bounds reads or even attempts to read/write memory beyond the packet payload.  The subsequent arithmetic (`auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT`) does not protect against the possibility that the supplied `auth_len` is larger than the actual received data, exposing the function to a potential buffer overread or memory corruption exploit.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The function trusts oa_length to size the XDR memory buffer.  If a malicious packet advertises an excessively large oa_length, XDR_INLINE() will return a pointer into that non‑existent buffer.  All subsequent IXDR_GET_* calls then read beyond the actual bytes received.  The code’s sanity checks bound only the numeric values read from the buffer (e.g., str_len, supp_ngroups) but never constrain oa_length to the real packet length.  Thus the routine can perform out‑of‑bounds reads, potentially leaking data or causing a crash.  This matches the classic “unbounded buffer read” flaw. The evidence (code analysis and numeric constants) confirms that the length value can exceed the real payload size without being caught by the checks, making the vulnerability real.

