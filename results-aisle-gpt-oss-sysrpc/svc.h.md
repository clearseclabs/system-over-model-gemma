# Scan: svc.h

**Detailed Security Analysis**

The `svc.h` header defines the structures and macros that form the core of NetBSD’s RPC server.  Most of the potentially dangerous code lies in the macros that dereference pointers that are supplied (or may be supplied) by untrusted input – e.g. the operation table `xp_ops`, the private data `xp_p3`, and the handler function pointers.  The structures themselves also contain hard‑coded buffers (`rq_credarea`) and fields that can be overwritten if callers fail to validate input length.  Below is a systematic walk‑through of the most critical paths that an attacker controlling a remote RPC request or a corrupted service registration can exploit.

| # | Function / Macro | Potential Input | Vulnerability | Typical Exploit |
|---|------------------|----------------|--------------|-----------------|
| 1 | `SVC_EXT(xprt)`  | `xp_p3` field of a `SVCXPRT` | Dereference of a pointer that is not checked for NULL or for the expected type (`SVCXPRT_EXT`).  An attacker can supply a service that registers an `SVCXPRT` whose `xp_p3` is NULL, or points to unrelated data, and then triggers any macro that uses `SVC_EXT`. | Crash (NULL ptr), memory corruption, or data leak if `xp_p3` points to writable data. |
| 2 | `SVC_AUTH(xprt)` | `xp_p3` of a `SVCXPRT` | Same as above – the macro casts to a `SVCXPRT_EXT` and then accesses `xp_auth`.  If `xp_p3` is NULL or not a valid `SVCXPRT_EXT`, the server will crash the thread handling the request. | Denial‑of‑Service (DoS) by causing the server to crash before a reply can be sent. |
| 3 | `SVC_RELEASE(xprt)`  | `xprt` from client input | `refcount_release()` returns 1 when the last reference is released, and `SVC_DESTROY(xprt)` is called unconditionally.  If `xp_ops` is NULL, the `SVC_DESTROY` macro will dereference a NULL pointer. | Crash a thread that supplied the last reference, leading to DoS. |
| 4 | `SVC_RECEIVE`, `SVC_REPLY`, `SVC_STAT`, `SVC_ACK` | `xprt` from client input | All of these macros dereference `xprt->xp_ops` without checking that it is non‑NULL.  Attackers could register a service with an `xp_ops` table that contains NULL function pointers, or a partially‑initialized table, and then perform an RPC that triggers the corresponding macro. | Crash the request‑handling thread; a malicious service can also cause untrusted data to be written to arbitrary locations if the wrong function pointer is invoked. |
| 5 | `struct svc_req::rq_credarea` | Authentication data supplied by the client | The buffer has a fixed size `3 * MAX_AUTH_BYTES` (a compile‑time constant).  The RPC implementation might copy authentication data into this buffer without validating that the incoming data length does not exceed the buffer.  Since the buffer is on the stack, an overflow can corrupt return addresses or local variables. | Stack smashing that can lead to arbitrary code execution or denial of service. |
| 6 | `struct svc_req::rq_p1`, `rq_p2`, `rq_p3` | Service‑specific data stored in `svc_req` | These fields are declared as opaque “workspace” for the service.  The implementation may write between 0 and the maximum allowed size without bounds checks.  A malicious service or a corrupted registration could supply a `SVCXPRT` that points to a small stack buffer via `xp_p1`.  Subsequent uses of `rq_p1` in the service may write past the buffer boundary. | Memory corruption, leading to crash or code execution, depending on the data written. |
| 7 | `struct svc_req::rq_size` | Size of the incoming request payload | The field is set by the transport layer based on client data.  A corrupted or malicious client may send a negative or excessively large value.  If the RPC server uses this value without validation for allocations or copying, buffer overflows or integer overflow can occur. | Heap corruption or overflow, potential arbitrary code execution. |
| 8 | `svc_getrpccaller(rq)` | `rq_addr` or `rq_xprt->xp_rtaddr` | The macro casts `rq_addr` (or `xp_rtaddr`) to a non‑aligned `struct sockaddr *`.  If the address is not properly aligned or the pointer is uninitialized (e.g., `rq_addr == NULL` while `xp_rtaddr` is not properly set), dereferencing it can cause a fault. | Crash the server thread; combined with the other null‑pointer checks this could become a DoS. |

**Common Themes**

* **Unvalidated function pointers** – All SVC macros assume that the function pointers in `xp_ops` are non‑NULL and correctly typed.  The RPC server itself does not protect against a service registering a partially initialized operations table; if an attacker managed to overwrite the table, any RPC call could crash the server.

* **Unchecked private data** – `xp_p3` and the “workspace” fields are free‑form.  The RPC code treats them as writable storage but does not enforce a size guarantee.  If a malicious service is coded incorrectly, it can overflow these buffers.

* **Fixed‑size stack buffers** – `rq_credarea` is a classic candidate for an overflow if the implementation blindly copies authentication bytes there.

* **Null pointer dereference in macros** – Several macros, such as `SVC_EXT` and `SVC_AUTH`, dereference pointers without preparatory checks, leading to crashes on malformed service input.

* **Potential integer overflows** – `rq_size` and the size parameters passed to RPC creation functions are not validated for portability; an attacker could send a request with a huge size that can overflow an unsigned `size_t` during allocation or copy operations in the implementation.

**Recommendations**

1. Add defensive checks (NULL, type, size) around all dereferences of `xp_ops`, `xp_p3`, and other opaque pointers.
2. During service registration (`svc_reg`, `svc_tp_create`, etc.), validate that the private workspace pointers meet a minimum size requirement.
3. Enforce bounds on `rq_credarea` copies by using `memcpy_s` or similar safe copy primitives or by capping the input authentication size.
4. In request handling, verify that `rq_size` is within a reasonable bound before allocating memory or copying data.
5. Provide a seagull‑style “safe‑RPC” mode that validates all pointers and sizes during development builds.

---

```json
[
  {
    "severity": "medium",
    "title": "Unvalidated dereference in SVC_EXT macro",
    "function": "SVC_EXT(xprt)",
    "description": "xp_p3 is cast to a SVCXPRT_EXT without checking for NULL or the correct type.  An attacker can register a service with xp_p3 set to NULL or bogus data, causing a crash or memory corruption when the macro is used."
  },
  {
    "severity": "medium",
    "title": "Unvalidated dereference in SVC_AUTH macro",
    "function": "SVC_AUTH(xprt)",
    "description": "This macro dereferences the private data xp_p3.  If xp_p3 is NULL or not a valid SVCXPRT_EXT, the server will crash when an authentication operation is requested."
  },
  {
    "severity": "medium",
    "title": "NULL xp_ops pointer dereference in SVC macros",
    "function": "SVC_RECEIVE / SVC_REPLY / SVC_STAT / SVC_ACK",
    "description": "All these macros dereference xprt->xp_ops without verifying that it is non‑NULL.  A malformed service that supplies a NULL operations table will cause the server thread to crash upon handling any request."
  },
  {
    "severity": "medium",
    "title": "Unvalidated buffer write to rq_credarea",
    "function": "svc_req structure",
    "description": "The rq_credarea buffer has a fixed size but its use in the implementation is not bounds‑checked.  An attacker can send authentication data larger than 3*MAX_AUTH_BYTES, causing a stack overflow and potential code execution."
  },
  {
    "severity": "medium",
    "title": "Potential overflow from rq_size",
    "function": "svc_req::rq_size",
    "description": "rq_size is set from client data.  If it is not validated before use (e.g., for heap allocation or copy), an attacker could cause integer overflow or huge memory allocations, leading to denial‑of‑service or memory corruption."
  },
  {
    "severity": "medium",
    "title": "Workspace pointer overrun (rq_p1 / xp_p1)",
    "function": "svc_req::rq_p1 / SVCXPRT::xp_p1",
    "description": "These opaque workspace fields are treated as writable buffers by service implementations.  A service that points them to a small stack buffer can overflow it when writing without bounds checks."
  },
  {
    "severity": "medium",
    "title": "Potential crash via svc_getrpccaller macro",
    "function": "svc_getrpccaller(rq)",
    "description": "The macro may dereference an uninitialized or misaligned sockaddr pointer, causing a fault in the RPC thread."
  }
]
```