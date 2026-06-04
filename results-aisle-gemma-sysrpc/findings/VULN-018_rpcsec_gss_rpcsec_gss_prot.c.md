# VULN-018: Potential Kernel Panic / Memory Corruption (`m_pullup`)

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Confidence**: 100% [VVV]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Potential Kernel Panic / Memory Corruption (`m_pullup`)

#### 2. Potential Kernel Panic / Memory Corruption (`m_pullup`)
The `cklen` (checksum length) is also read via `get_uint32(&results)`.
*   **Vulnerability:** While there is a `KASSERT(cklen <= MHLEN, ...)` check, `KASSERT` is typically compiled out in production (non-debug) kernels. 
*   **Impact:** If `cklen` is larger than the current mbuf's `m_len`, `m_pullup(mic, cklen)` is called. If `cklen` is an extremely large value, `m_pullup` may fail or, depending on the kernel's `m_pullup` implementation, lead to an integer overflow during size calculations, potentially causing a kernel panic or heap corruption.

---

## Triage reasoning

### Round 1: ✅ VALID

The vulnerability report correctly identifies that `cklen` is read from an untrusted network mbuf via `get_uint32(&results)`. The only check against `cklen` is `KASSERT(cklen <= MHLEN, ...)`, which is compiled out in production kernels. Consequently, an attacker can provide a very large `cklen` value (up to 2^32-1). This value is passed directly to `m_pullup(mic, cklen)`. In most BSD-derived kernels, `m_pullup` attempts to ensure that the first `N` bytes of an mbuf chain are contiguous. If `N` is excessively large (e.g., larger than the total length of the mbuf chain or exceeding available kernel memory/limits), `m_pullup` typically returns NULL. The code handles the NULL return case (`if (!mic) { m_freem(message); return (FALSE); }`), preventing a NULL pointer dereference. However, the request for a massive contiguous buffer can trigger a kernel panic due to memory exhaustion or integer overflows within the `m_pullup` implementation's internal size calculations before it returns NULL. Given that `cklen` is fully attacker-controlled and the only bound is a debug-only assertion, this is a reachable path to a denial-of-service (kernel panic).

CRUX: The variable `cklen` is controlled by the attacker and passed to `m_pullup` without a production-grade bound check, as `KASSERT` is removed in production builds.
GREP: MHLEN

### Round 2: ✅ VALID

The vulnerability is real. The variable `cklen` is read directly from the network using `get_uint32(&results)`, making it attacker-controlled. The only check against `cklen` is `KASSERT(cklen <= MHLEN, ...)`. As noted, `KASSERT` is a debug-only macro and is removed in production builds. This allows an attacker to pass a very large value (up to 2^32-1) to `m_pullup(mic, cklen)`. In the BSD mbuf architecture, `m_pullup` attempts to make the first `N` bytes of a chain contiguous. If `N` is excessively large, it can lead to an attempt to allocate a massive amount of kernel memory or trigger integer overflows in the internal length calculations of `m_pullup`. While the code checks if `m_pullup` returns NULL, the failure typically happens inside the kernel's memory allocator or mbuf management logic when handling an unreasonable size request, leading to a kernel panic (DoS). The lack of a production-grade bound check on a value used for memory manipulation is a security vulnerability.

CRUX: The attacker-controlled `cklen` is passed to `m_pullup` without any production-grade boundary check, as the only check is a `KASSERT` which is compiled out in production.
GREP: MHLEN

### Round 3: ✅ VALID

The vulnerability exists because `cklen` is read from an untrusted network mbuf via `get_uint32()` and passed to `m_pullup(mic, cklen)`. The only boundary check is `KASSERT(cklen <= MHLEN, ...)`, and as is standard in BSD-derived kernels, `KASSERT` is compiled out in production builds. While the code checks if `m_pullup` returns NULL, `m_pullup` is an operation that attempts to make the first `N` bytes of an mbuf chain contiguous. In the BSD mbuf implementation, requesting an excessively large contiguous region (e.g., near 2^32) can lead to integer overflows in size calculations or attempts to allocate massive amounts of kernel memory before the function can safely return NULL. This creates a reachable path for a remote attacker to cause a kernel panic (Denial of Service). The previous reviewers correctly identified the flow; I have verified that `MHLEN` is a small constant (typically around 168 bytes based on the grep results), making the lack of a production-grade check for a `uint32_t` input a critical failure.

CRUX: An attacker-controlled uint32 `cklen` is passed to `m_pullup` without any production-grade boundary check, as the only check is a `KASSERT` which is removed in production builds.
GREP: m_pullup

