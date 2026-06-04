# Scan: rpcsec_gss/rpcsec_gss_prot.c

### Security Analysis

The file `rpcsec_gss_prot.c` handles the wrapping and unwrapping of RPCSEC_GSS data using `mbuf` chains. The most critical vulnerabilities are found in `xdr_rpc_gss_unwrap_data`, where attacker-controlled lengths are used to manipulate memory buffers.

#### 1. Denial of Service via Memory Exhaustion (`m_split`)
In `xdr_rpc_gss_unwrap_data`, the function reads a `uint32_t len` from the untrusted `results` mbuf using `get_uint32()`. This `len` is passed directly to `m_split(results, len, M_WAITOK)`.
*   **Vulnerability:** There is no upper bound check on `len`. An attacker can provide a very large value (e.g., `0xFFFFFFFF`).
*   **Impact:** `m_split` with `M_WAITOK` will attempt to allocate or reorganize mbufs to satisfy the length requirement. This can lead to kernel memory exhaustion or cause the system to hang/panic while trying to allocate a massive amount of memory.

#### 2. Potential Kernel Panic / Memory Corruption (`m_pullup`)
The `cklen` (checksum length) is also read via `get_uint32(&results)`.
*   **Vulnerability:** While there is a `KASSERT(cklen <= MHLEN, ...)` check, `KASSERT` is typically compiled out in production (non-debug) kernels. 
*   **Impact:** If `cklen` is larger than the current mbuf's `m_len`, `m_pullup(mic, cklen)` is called. If `cklen` is an extremely large value, `m_pullup` may fail or, depending on the kernel's `m_pullup` implementation, lead to an integer overflow during size calculations, potentially causing a kernel panic or heap corruption.

#### 3. Logic Error in `m_trim` leading to Out-of-Bounds Access
The `m_trim` function is used to handle RPC padding:
```c
static void m_trim(struct mbuf *m, int len) {
    // ...
    n = m_getptr(m, len, &off);
    if (n) {
        n->m_len = off;
        // ...
    }
}
```
*   **Vulnerability:** `m_getptr` returns a pointer to the `len`-th byte of the mbuf chain. The `off` variable returns the offset within the mbuf where that byte resides. Setting `n->m_len = off` effectively truncates the mbuf to the start of the segment containing the `len`-th byte.
*   **Impact:** If `len` is provided by an attacker and is not validated against the actual total length of the mbuf chain, `m_getptr` might return `NULL` (handled) or a pointer that results in an incorrect `m_len`. In `xdr_rpc_gss_unwrap_data`, if `len` is larger than the actual data provided, `m_trim` may not behave as intended, potentially leaving the mbuf in an inconsistent state before being passed to GSS-API functions.

#### 4. Integer Signedness Mismatch
The function `m_trim` takes `int len`, but is called with `uint32_t` values (`len` and `cklen`).
*   **Vulnerability:** If an attacker provides a value for `len` that is larger than `INT_MAX`, it will be interpreted as a negative number inside `m_trim`.
*   **Impact:** Passing a negative length to `m_getptr` (which usually expects a size_t/u_int) can lead to undefined behavior, typically resulting in a massive unsigned value being used, leading to an out-of-bounds memory access or immediate kernel panic.

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