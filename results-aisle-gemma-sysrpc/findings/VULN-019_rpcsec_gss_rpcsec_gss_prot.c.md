# VULN-019: ummary of Findings

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

ummary of Findings

### Summary of Findings

```json
[
  {
    "severity": "critical",
    "title": "Kernel Memory Exhaustion via Unbounded m_split",
    "function": "xdr_rpc_gss_unwrap_data()",
    "description": "The function reads a 32-bit length from untrusted network data and passes it to m_split with M_WAITOK without validation. An attacker can provide a massive length to exhaust kernel memory or cause a system hang."
  },
  {
    "severity": "high",
    "title": "Integer Signedness Mismatch in m_trim",
    "function": "m_trim()",
    "description": "m_trim accepts a signed 'int len' but is called with unsigned 'uint32_t' lengths from the network. A value exceeding INT_MAX will be treated as negative, leading to potential out-of-bounds access in m_getptr."
  },
  {
    "severity": "medium",
    "title": "Bypassed Length Check via KASSERT",
    "function": "xdr_rpc_gss_unwrap_data()",
    "description": "The check 'cklen <= MHLEN' is wrapped in a KASSERT. In production builds, this check is removed, allowing arbitrary 'cklen' values to be passed to m_pullup, which may lead to kernel instability."
  }
]
```

---

## Triage reasoning

### Round 1: ✅ VALID

I analyzed the three reported findings. 

1. **Kernel Memory Exhaustion via `m_split`**: In `xdr_rpc_gss_unwrap_data`, `len` is read from the network via `get_uint32` and passed directly to `m_split(results, len, M_WAITOK)`. `m_split` in BSD-style kernels typically attempts to split the mbuf chain. If `len` is very large (e.g., 2^32-1), it doesn't necessarily allocate `len` bytes immediately, but rather marks the split point. However, the vulnerability scanner's claim of 'unbounded' is technically correct as there is no upper bound check on `len` before calling `m_split`. 

2. **Integer Signedness in `m_trim`**: `m_trim` is defined as `static void m_trim(struct mbuf *m, int len)`. It is called in `xdr_rpc_gss_unwrap_data` as `m_trim(mic, cklen)` and `m_trim(message, len)`. Both `cklen` and `len` are `uint32_t`. If an attacker provides a value > 2,147,483,647 (INT_MAX), it becomes negative when passed to `m_trim`. Inside `m_trim`, this negative value is passed to `m_getptr(m, len, &off)`. In standard mbuf implementations, `m_getptr` takes a `size_t` or `int` for length. If it's treated as a large unsigned value or a negative signed value, it can lead to out-of-bounds access or kernel panics. This is a classic signedness mismatch on attacker-controlled input.

3. **Bypassed Length Check via `KASSERT`**: The code contains `KASSERT(cklen <= MHLEN, ("unexpected large GSS-API checksum"));`. KASSERTs are removed in production builds. Immediately following this, `m_pullup(mic, cklen)` is called. If `cklen` is huge, `m_pullup` will attempt to allocate a contiguous buffer of that size. This is a direct path to kernel memory exhaustion or a crash in production, as the only check protecting `m_pullup` from an arbitrary `uint32_t` is the `KASSERT`.

All three findings originate from `get_uint32(&results)`, which reads directly from the network mbuf chain, making them attacker-reachable. The lack of validation on `len` and `cklen` before they are used in memory management functions (`m_split`, `m_pullup`, `m_trim`) is a security vulnerability.

CRUX: Attacker-controlled uint32_t values (len, cklen) from the network are used in m_split, m_pullup, and m_trim without validation, with the only existing check being a KASSERT which is removed in production.
GREP: MHLEN

### Round 2: ✅ VALID

I analyzed the three findings reported. 

1. **m_split Memory Exhaustion**: `m_split` does not allocate `len` bytes; it splits an existing `mbuf` chain at the specified offset. If `len` exceeds the actual length of the chain, `m_split` typically returns NULL or fails without allocating massive amounts of memory. This is not a memory exhaustion vulnerability.

2. **m_trim Signedness**: `m_trim` takes an `int len`. In `xdr_rpc_gss_unwrap_data`, it is called with `uint32_t len` and `uint32_t cklen`. If `len > INT_MAX`, it becomes negative. Inside `m_trim`, `m_getptr(m, len, &off)` is called. If `len` is negative, `m_getptr` will treat it as a very large unsigned value (since `m_getptr` takes `size_t` for length in BSD). This leads to an out-of-bounds access attempt. However, there is a critical prerequisite: `len` must be greater than `INT_MAX` AND the `mbuf` chain must actually contain that much data for `m_getptr` to not simply return NULL. Since the data comes from the network, the total length of the `mbuf` chain is limited by the network stack's maximum packet size (usually ~64KB or slightly more for jumbo frames), which is far less than `INT_MAX` (2GB). Thus, `len` can never be large enough to wrap into a negative `int` while also being a valid length for an existing mbuf chain. Any value > `INT_MAX` will cause `m_getptr` to return NULL immediately because the chain is too short.

3. **m_pullup and KASSERT**: This is the real issue. `cklen` is read as a `uint32_t` from the network. The only check is `KASSERT(cklen <= MHLEN)`, which is removed in production. Then, `m_pullup(mic, cklen)` is called. `m_pullup` attempts to make `cklen` bytes contiguous. If `cklen` is large (e.g., 1GB), `m_pullup` will attempt to allocate a contiguous buffer of that size using `malloc` or `m_get`. This is a classic 'attacker-controlled allocation size' vulnerability leading to kernel memory exhaustion or a panic (DoS).

Verification of `MHLEN`: The grep shows `MHLEN` is approximately 168 bytes. The `KASSERT` was intended to ensure the checksum fit in a single mbuf, but because it's a `KASSERT`, production code allows any `uint32_t` to reach `m_pullup`.

CRUX: In production builds, the KASSERT is removed, allowing an attacker-controlled uint32_t 'cklen' to be passed to m_pullup, leading to kernel memory exhaustion/DoS.
GREP: m_pullup

### Round 3: ✅ VALID

The report flags three issues. First, `m_split` with an attacker-controlled length is not a memory exhaustion bug because `m_split` only separates an existing mbuf chain; it doesn't allocate new memory proportional to the requested length. Second, the signedness mismatch in `m_trim` is not exploitable because the total length of a network-received mbuf chain is limited (typically ~64KB), meaning a value exceeding `INT_MAX` (2GB) will cause `m_getptr` to return NULL immediately rather than causing an out-of-bounds access. Third, the `m_pullup` issue is a valid DoS. In `xdr_rpc_gss_unwrap_data`, `cklen` is read from the network as a `uint32_t`. The only check against it is `KASSERT(cklen <= MHLEN)`, which is removed in production builds. This allows an attacker to pass an arbitrary 32-bit value to `m_pullup`. `m_pullup` attempts to create a contiguous buffer of the requested size. If an attacker provides a very large `cklen`, the kernel will attempt a massive allocation, leading to kernel memory exhaustion or a panic. This is a classic attacker-controlled allocation size vulnerability.

CRUX: The only check on `cklen` before it is passed to `m_pullup` is a `KASSERT`, which is absent in production builds, allowing attacker-controlled memory allocation requests.
GREP: m_pullup

### Round 4: ✅ VALID

[ARBITER] In `xdr_rpc_gss_unwrap_data`, the variable `cklen` is read directly from the network via `get_uint32`. The only check ensuring `cklen` is reasonable is `KASSERT(cklen <= MHLEN, ...)`, which is stripped in production builds. This allows an attacker to pass an arbitrary `uint32_t` value to `m_pullup(mic, cklen)`. In BSD mbuf implementations, `m_pullup` attempts to make the specified length contiguous, which can lead to significant kernel memory allocation or failure (DoS) when provided with a massive value from an untrusted source.

