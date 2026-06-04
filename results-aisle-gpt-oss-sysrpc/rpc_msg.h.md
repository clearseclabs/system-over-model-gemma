# Scan: rpc_msg.h

**Security analysis**

The file `rpc_msg.h` declares the public data structures and XDR helper
prototypes for Sun RPC.  It contains no executable code, but its
definitions influence how untrusted network data is interpreted by the
RPC stack.  The main risk points are the use of tagged unions that
must be inspected before accessing the correct member, the lack of
size/length validations in the opaque authentication blobs, and the
absence of bounds checks on the fields that are directly copied from
network data.  These design choices can lead to memory corruption,
information disclosure, or direct code execution if an attacker
crafts a malformed RPC message that bypasses the intended validation
logic in the unmarshalling code.

| Severity | Title | Function/Location | Description |
|----------|-------|-------------------|-------------|
| **CRITICAL** | **Unvalidated `rm_direction` can lead to arbitrary union access** | `struct rpc_msg` (`rm_direction`, `rm_call`/`rm_reply`) | `rm_direction` is an enum tag that decides which member of the union is valid. The header does not enforce a check before accessing `rm_call` or `rm_reply`. If an attacker sends an RPC packet with an out‑of‑range `rm_direction` value (e.g. 0xFFFFFFFF), the unmarshalling code might read or write the wrong part of the union, causing undefined behaviour, memory corruption, or crash. |
| **CRITICAL** | **Missing validation of `ar_stat` before using `accepted_reply` union** | `struct accepted_reply` (`ar_stat`, `ar_results`/`ar_vers`) | The union `ru` contains either version limits (`AR_versions`) or result information (`AR_results`). The tag `ar_stat` must be inspected first. If a caller (or the XDR routine) uses `ar_results.where` without checking that `ar_stat == SUCCESS`, it may read an uninitialized pointer, potentially revealing memory or triggering a fault. |
| **HIGH** | **Potential misuse of `rpc_call_body::cb_cred` and `cb_verf` opaque auth blobs** | `struct opaque_auth` in `call_body` | `opaque_auth` (definition omitted) stores an authorization `length` and a data pointer. No bounds checking on the length is shown in this header, and the XDR routine must allocate memory accordingly. A large or malformed `length` can cause the XDR code to copy millions of bytes, leading to a buffer overflow, denial of service, or memory exhaustion. |
| **HIGH** | **`accepted_reply::ar_results.where` can point to arbitrary memory** | `struct accepted_reply` (`ar_results` union) | The `where` field is a raw pointer (`caddr_t`) that is expected to point to pre‑allocated data. In a crafted RPC reply, the attacker can control this pointer. If the client code dereferences it without validation, it can cause arbitrary memory access or trigger a crash. |
| **MEDIUM** | **Possibility of integer overflow when computing RPC format lengths** | `xdr_callhdr`, `xdr_callmsg`, `xdr_replymsg` | These XDR routines calculate data sizes based on the fields of `rpc_msg`. If the code multiplies or adds fields (e.g. `5 * some_length`) without using a 64‑bit intermediate type, an overflow can wrap, causing the routine to think a message is smaller than it actually is, leading to truncated reads or writes. |
| **MEDIUM** | **No runtime check on `cb_rpcvers` against `RPC_MSG_VERSION`** | `struct call_body` (`cb_rpcvers`) | Message parsing code expects `cb_rpcvers == RPC_MSG_VERSION`. An attacker could send a different value, causing parsing logic that expects a newer or older protocol version to read wrong fields, which may produce under‑reads or over‑writes. |
| **LOW** | **Typo in macro name (`acpted_rply`) may result in confusing code paths** | `#define acpted_rply ...` | This typo does not directly cause a security flaw but can lead to maintenance errors where the intended macro `accepted_rply` is not used, potentially resulting in using an uninitialized part of the union. |
| **LOW** | **Unspecified alignment/packing of structs could lead to platform‑specific padding** | All structs (`rpc_msg`, `call_body`, `accepted_reply`, etc.) | Mis‑aligned structs may expose padding bytes that can be manipulated by an attacker if the XDR unmarshalling does not zero‑initialize them, leading to leakage of uninitialised memory. |

**Key takeaways**

* The public API relies heavily on union tags; callers must perform exhaustive checks before accessing union members. The header itself does not provide safety wrappers.
* Opaque authentication blobs are potentially dangerous if the length field is exploited. The XDR implementation must perform strict bounds checking.
* Integer overflows in size calculations, while not shown, are a common vector in RPC unmarshalling code and should be audited.

**Recommended mitigations**

1. Add helper inline functions that validate `rm_direction`, `ar_stat`, `rp_stat`, and `cb_rpcvers` before accessing the corresponding union elements.
2. Enforce bounds checks on all length fields in `opaque_auth`, and zero‑initialize the data before copying.
3. Use 64‑bit intermediate types for size calculations to prevent integer overflows.
4. Document the required invariant checks for callers and consider annotating the code with `__attribute__((nonnull))` or `__attribute__((warn_unused_result))` to aid static checkers.

These observations should guide any further implementation review or patching of the corresponding XDR routines.