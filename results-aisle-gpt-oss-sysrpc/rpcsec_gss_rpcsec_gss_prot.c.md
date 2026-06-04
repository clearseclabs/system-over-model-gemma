# Scan: rpcsec_gss/rpcsec_gss_prot.c

**Security Analysis**

The file **rpcsec_gss/rpcsec_gss_prot.c** implements the RPCSEC_GSS protocol in the FreeBSD kernel.  
All operations performed on mbuf chains originate from the network, so attacker supplied data may flow into every helper that manipulates these chains. The most critical areas are:

| Function | Vulnerability | What is checked / how it can be abused |
|----------|----------------|----------------------------------------|
| `xdr_rpc_gss_unwrap_data()` | **KASSERT on untrusted mi­check-length** | After reading the MIC length (`cklen`) from the wire, the code asserts `cklen <= MHLEN`. If an attacker supplies a value larger than `MHLEN`, the assertion triggers a kernel panic, giving a DoS vector. |
| `xdr_rpc_gss_wrap_data()` / `xdr_rpc_gss_unwrap_data()` | **RNDUP overflow** | `RNDUP(x)` expands lengths to the next 4‑byte boundary. The macro is not protected against 32‑bit signed‑overflow. A crafted length close to `INT_MAX` can overflow `RNDUP(len)` to a negative value which is cast to unsigned when used with `m_append` or `m_trim`. This may cause an enormous allocation or silently wrap the size, leading to a crash or memory corruption. |
| `xdr_rpc_gss_wrap_data()` | **Unbounded payload** | The function appends sequence numbers, lengths, and GSS tokens without imposing a hard maximum on the total size of the response. An attacker can send a packet containing a very large buffer; the kernel will allocate a correspondingly huge `mbuf` chain for the GSS operations, exhausting memory and producing a denial‑of‑service. |
| `xdr_rpc_gss_unwrap_data()` | **Memory leak on decryption failure** | If `gss_unwrap_mbuf()` fails, the function returns `FALSE` **without** freeing the original `results` chain. If the caller does not free this chain again, each failed request leaks kernel memory, contributing to a DoS over time. |
| `xdr_rpc_gss_unwrap_data()` | **Unvalidated padding removal** | The function calls `m_trim(message, len)` whenever the payload isn’t 4‑byte aligned. `len` comes directly from the packet; an attacker can give a length that is larger than the actual message. `m_trim` will therefore truncate the buffer to zero length, which may silently bypass checks or lead to a subsequent crash. |

All other helper functions (`get_uint32`, `put_uint32`, `m_trim`) contain proper checks for `NULL` pointers or negative lengths, and XDR serialization functions apply their own size limits.  
The identified bugs primarily facilitate denial‑of‑service and, in the case of the assertion and integer overflow, a kernel panic that can be triggered with a single malformed packet.

---

### Findings (JSON)

```json
[
  {
    "severity": "critical",
    "title": "Kernel panic via unvalidated checksum length",
    "function": "xdr_rpc_gss_unwrap_data()",
    "description": "During integrity unwrapping, the MIC length field (cklen) is read directly from the network packet and then asserted to be less than or equal to MHLEN. No pre‑check on the value is performed. An attacker can supply a cklen larger than MHLEN, causing KASSERT to fail and a kernel panic (DoS)."
  },
  {
    "severity": "high",
    "title": "RNDUP integer overflow leading to allocation of huge or wrapped buffers",
    "function": "xdr_rpc_gss_wrap_data() / xdr_rpc_gss_unwrap_data()",
    "description": "The macro RNDUP(len) rounds len up to the next 4‑byte boundary without masking for signed overflow. If len is close to INT_MAX, RNDUP(len) can wrap to a negative value, which is then cast to unsigned for m_append or m_trim. This can result in allocating an astronomically large buffer, a crash, or silent truncation."
  },
  {
    "severity": "medium",
    "title": "Unbounded GSS payload allocation allows memory exhaustion",
    "function": "xdr_rpc_gss_wrap_data()",
    "description": "The function appends sequence, length, and GSS token data to an mbuf chain without enforcing a maximum total size. A client may send a packet with arbitrarily large data, causing the kernel to allocate a correspondingly large mbuf chain for the GSS wrappers, potentially exhausting kernel memory and causing a DoS."
  },
  {
    "severity": "medium",
    "title": "Memory leak on decryption failure",
    "function": "xdr_rpc_gss_unwrap_data()",
    "description": "When gss_unwrap_mbuf() returns an error, the function returns FALSE without freeing the original 'results' mbuf chain, which was taken from the caller and not freed elsewhere. Repeated failure can leak kernel memory, contributing to a DoS."
  },
  {
    "severity": "medium",
    "title": "Potential zero-length message via unchecked padding trim",
    "function": "xdr_rpc_gss_unwrap_data()",
    "description": "After decrypting a privacy payload, the code calls m_trim(message, len) if the length is not a 4‑byte multiple. Since len originates from the network, an attacker can set it larger than the actual message size, causing m_trim to truncate the message to zero and potentially bypass downstream checks or crash the unwinder."
  }
]
```

This set of findings captures the most exploitable paths in the file that could be abused to disrupt the kernel, corrupt memory, or cause persistent denial‑of‑service.