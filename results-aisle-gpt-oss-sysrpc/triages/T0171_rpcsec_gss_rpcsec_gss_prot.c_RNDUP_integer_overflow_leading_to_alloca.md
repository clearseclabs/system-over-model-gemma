# Triage T0171: RNDUP integer overflow leading to allocation of huge or wrapped buffers

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [UUU]

---

## Finding

RNDUP integer overflow leading to allocation of huge or wrapped buffers

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN

{"reasoning":"The code uses the macro\n\n```\n#define RNDUP(len) (((len) + 3) & ~3)\n```\n(RNDUP is defined in FreeBSD’s <sys/param.h>, where `len` is an unsigned integer).  `len` is stored in a variable of type `u_int` (an unsigned 32‑bit integer).  Unsigned integer arithmetic is defined modulo 2^32, so adding 3 to a value close to `UINT_MAX` merely wraps, and `RNDUP(len)` therefore always produces a value that is either equal to `len` or `len+1/2/3` – never negative or huge.  Thus the expression `RNDUP(len) - len` is always in the range 0–3.  The functions that consume this value are `m_append()` and `m_trim()`.  In the BSD kernel `m_append()` accepts an `int` (or `u_int`) argument for the amount to append, and the kernel never accepts a negative value; the signed conversion from unsigned cannot produce a negative value because the unsigned value is ≤3.  No other calculation uses the result of `RNDUP(len)` in a way that could cause integer overflow or wrap to a harmful value.\n\nSince the only way to influence `len` is through the size of the incoming RPC payload held in an `mbuf` chain, an attacker could change that size, but the kernel limits the total number of allocated `mbuf` pages (via IPC and memory limits) far below `INT_MAX`.  The `m_length()` call used to compute `len` will itself clip to a 32‑bit signed value, and the pad‑appending logic is bounded by `RNDUP(len)-len <= 3`.  Therefore, even if an attacker tries to send an absurdly large payload, the routine will not overflow or allocate a huge buffer.  The guard in `KASSERT(cklen <= MHLEN)` in `xdr_rpc_gss_unwrap_data()` also blocks excessively large checksums.\n\nBecause the macro is mathematically safe, the difference is bounded, and all weakening conditions are controlled by normal kernel resource limits, the alleged vulnerability is not actionable.  No defensive guard is required beyond the existing code.  Consequently the reported bug is **INVALID**.\n\n","crux":"RNDUP macro uses unsigned arithmetic; difference with len is ≤3, never causing unsigned overflow or negative values; m_append and m_trim consume that safely.\n\n","grep":"RNDUP\\(\\nint\\s+m_append\\(\\s*struct\\s+mbuf","verdict":"INVALID"}

### Round 3: ❓ UNCERTAIN



