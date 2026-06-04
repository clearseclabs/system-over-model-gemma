# Scan: svc_dg.c

**Security Analysis Commentary**

- **svc_dg_create**  
  - The function does **not check whether `svc_xprt_alloc()` returned a non‑NULL pointer**. If the allocation fails, the subsequent use of `xprt` (e.g. dereferencing `xprt->xp_lock`, `xprt->xp_pool`, etc.) would result in a kernel crash. The error path falls into `freedata`, where `svc_xprt_free(xprt)` is called regardless of `xprt`’s validity.  
  - The input parameters `sendsize` and `recvsize` are cast from `size_t` to `int` without validation. If a caller passes a value larger than `INT_MAX`, the cast will wrap, producing an incorrect (negative or tiny) buffer size, which can lead to under‑allocation of receive buffers and subsequent read or write overflows in the underlying RPC layer.  
  - `sosockaddr()` obtains the local address of the socket. The function does **not validate** that the returned address does not exceed the size of `xprt->xp_ltaddr`, which is already set to `sizeof(xprt->xp_ltaddr)`. However, because the sockaddr structure is passed by reference, the kernel could potentially store larger data than the buffer size, leading to stack corruption.  
  - No bounds checks are performed on the string formatting prints (`printf(svc_dg_err1)` and `printf(svc_dg_str, __no_mem_str)`), though the format strings are constant and thus safe.

- **svc_dg_recv**  
  - The `uio` structure is initialized with an arbitrarily large `uio_resid` (`1,000,000,000`). Consequently, the socket may allocate a very large mbuf chain to satisfy the request, which can exhaust kernel memory and lead to a DoS.  
  - There is **no validation that the received packet is at least as large as the expected minimum RPC message size** before invoking `xdr_callmsg`. A malicious caller could send a truncated or otherwise malformed packet that causes `xdr_callmsg` to read past the end of the mbuf chain, potentially exposing memory or corrupting the kernel’s address space.  
  - The return value of `xdr_callmsg()` is checked, but the function also calls `xdrmbuf_getall()` *even if* `xdr_callmsg()` succeeded. If `xdrmbuf_getall()` unexpectedly returns NULL (e.g., due to allocation failure), the code still writes this NULL into `*mp`, leaking the value to the calling code.  

- **svc_dg_reply**  
  - `m_gethdr(M_WAITOK, MT_DATA)` is used to allocate an mbuf for the reply. The return value is **not verified**; if the allocation failed, `mrep` would be NULL, and the subsequent `xdrmbuf_create()` would dereference a NULL pointer, causing a kernel panic. `M_WAITOK` guarantees the allocation will block until memory is available, but a deliberate DoS can still exhaust the memory pool and force `m_gethdr()` to fail.  
  - The reply logic uses `xdr_replymsg()` to serialize the RPC response. No bounds checks are performed on the size of the serialized data relative to the underlying socket buffer; a corrupted RPC message could cause the reply to exceed the socket’s send buffer, potentially resulting in a data truncation or silent failure.  

- **svc_dg_destroy**  
  - The function frees `xprt->xp_netid` using `mem_free(xprt->xp_netid, strlen(xprt->xp_netid) + 1);` only when `xprt->xp_netid` is non‑NULL. If the string pointer is invalid (e.g., not NUL‑terminated), `strlen()` can read beyond the valid memory region, leading to memory corruption. The code assumes that `xprt->xp_netid` always points to a valid NUL‑terminated string.  

- **svc_dg_control** / **svc_dg_soupcall**  
  - These functions are no‑ops or trivial; they do not introduce additional vulnerabilities.

**Key Vulnerabilities**

1. **NULL Pointer Dereference (svc_dg_create / svc_dg_reply)** – Lack of allocation checks leads to kernel panic under memory pressure or allocation failure.  
2. **Integer Truncation (svc_dg_create)** – Casting large `size_t` values to `int` can corrupt buffer sizes, enabling buffer overflows during RPC data transfer.  
3. **Unbounded Memory Allocation (svc_dg_recv)** – The enormous `uio_resid` allows attackers to drain kernel memory through large, malformed packets.  
4. **Unchecked Data Parsing (svc_dg_recv)** – Malformed RPC messages can cause out‑of‑bounds reads inside XDR functions, exposing kernel memory.  
5. **Potential String Corruption (svc_dg_destroy)** – Improper validation of `xprt->xp_netid` can lead to memory overruns during deallocation.

These issues are exploitable by a knowledgeable attacker with the ability to send crafted RPC packets to the NetBSD kernel’s datagram RPC service, leading to denial‑of‑service or local kernel compromise.

**JSON Findings**

```json
[
  {
    "severity": "Critical",
    "title": "Null pointer dereference due to unchecked memory allocation in svc_dg_reply",
    "function": "svc_dg_reply",
    "description": "The call to m_gethdr(M_WAITOK, MT_DATA) is not checked for NULL. If low memory causes the allocation to fail, the subsequent xdrmbuf_create will dereference a NULL pointer, potentially causing a kernel panic and allowing denial‑of‑service or privilege escalation."
  },
  {
    "severity": "Critical",
    "title": "Null pointer dereference due to unchecked allocation in svc_dg_create",
    "function": "svc_dg_create",
    "description": "svc_xprt_alloc() may return NULL on allocation failure. The code proceeds to dereference the returned pointer (e.g., xprt->xp_lock) without validation, which can cause a kernel crash if allocation fails."
  },
  {
    "severity": "High",
    "title": "Integer truncation of send/receive buffer sizes in svc_dg_create",
    "function": "svc_dg_create",
    "description": "The parameters sendsize and recvsize are cast from size_t to int. Passing a value larger than INT_MAX causes a wrap‑around, resulting in a negative or tiny buffer size. Subsequent RPC buffer allocations use these incorrect sizes, potentially leading to buffer overflows during packet processing."
  },
  {
    "severity": "High",
    "title": "Unbounded memory allocation via oversized uio_resid in svc_dg_recv",
    "function": "svc_dg_recv",
    "description": "The uio.uio_resid field is hard‑coded to 1,000,000,000, allowing a malicious actor to send an arbitrarily large packet that the kernel will attempt to copy into an mbuf chain. This can exhaust kernel memory, leading to a denial‑of‑service attack."
  },
  {
    "severity": "High",
    "title": "Potential out‑of‑bounds reads in XDR parsing of svc_dg_recv",
    "function": "svc_dg_recv",
    "description": "After receiving data, the code calls xdr_callmsg(&xdrs, msg) on a possibly malformed packet. If the packet is incomplete or tampered with, xdr_callmsg may read beyond the mbuf bounds, potentially leaking kernel memory or causing corruption."
  },
  {
    "severity": "Medium",
    "title": "String length assumption in svc_dg_destroy",
    "function": "svc_dg_destroy",
    "description": "The deallocation of xprt->xp_netid uses strlen(xprt->xp_netid) + 1 to compute the length. If xp_netid is not a NUL‑terminated string, strlen will read past bounds, corrupting memory during deallocation."
  }
]
```
