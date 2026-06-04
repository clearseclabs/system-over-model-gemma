# Scan: rpc_prot.c

**Detailed Security Analysis**

The file implements XDR serialization helpers for RPC messages. The functions generally perform strict argument checks (`assert`) and rely on the XDR library to validate the data itself. Nevertheless, after a thorough line‑by‑line review several areas can potentially be abused by an attacker who can control the raw XDR payload:

1. **Unvalidated Enum values** – `xdr_enum` is used to decode enumeration fields (e.g. `oa_flavor`, `auth_stat`, `reply_stat`). The XDR standard does not automatically validate that the decoded value is one of the named enum members. This can lead to:
   * Wrong flavor values being accepted for authentication (`xdr_opaque_auth`).
   * Unknown reply/discriminator values that are blindly used to drive control flow in `xdr_replymsg`, `xdr_accepted_reply`, or `xdr_rejected_reply`.

2. **Hard‑coded Buffer Size in `xdr_opaque_auth`** – The function copies the authentication token length directly from the XDR stream into a local struct member (`oa_length`) and then calls `xdr_bytes`. The safety of this operation depends entirely on the XDR library checking that the length is ≤ `MAX_AUTH_BYTES`. If the library is patched or replaced with a buggy version, an attacker could set an arbitrarily large length, causing the library to allocate a huge buffer (heap exhaustion) or return an error that propagates to higher‑level code that assumes success.

3. **Dereference of Potentially NULL Session** – `handle_request` calls `lookup_session(req->session_id)` and immediately dereferences the returned pointer (`sess->handler(req)`). If `lookup_session` can legitimately return `NULL` for an unknown session, the code will crash. While this is a safety issue rather than a memory corruption, it can be exploited for denial‑of‑service.

4. **Implicit Trust in Union Discriminant** – `_seterr_reply` reads `msg->acpted_rply` or `msg->rjcted_rply` based on `msg->rm_reply.rp_stat`. If the incoming message is malformed and sets a valid `rp_stat` but does not contain a serialized value for the chosen discriminant, the subsequent accesses (`ar->ar_vers.low`, `rj->rj_vers.low`, etc.) will read uninitialized memory. Because the XDR decoding functions do not set the respective fields until the corresponding subtype is decoded, a malformed packet could lead to out‑of‑bounds reads that influence application logic.

5. **Dependency on Assertions** – The use of the macro `assert` means that, when compiled with NDEBUG, the functions will not guard against `NULL` arguments. Allegedly trusted callers can therefore pass `NULL` and cause a crash. While not a memory corruption per se, it can lead to a denial‑of‑service attack vector.

**Summary of Potential Vulnerabilities**

| Severity | Title | Function | Description |
|----------|-------|----------|-------------|
| High | Invalid enum values accepted | `xdr_opaque_auth`, `xdr_replymsg`, `xdr_rejected_reply` | `xdr_enum` does not check that decoded values belong to the intended enum set. An attacker can inject arbitrary values that trick the library into treating an authentication flavor or reply type as something else, potentially bypassing security checks or causing logic errors. |
| Medium | Lack of guard against oversized auth blobs | `xdr_opaque_auth` | The function relies on the XDR library to enforce `MAX_AUTH_BYTES`. A buggy or replaced library could allow huge allocations or trigger a crash, enabling a denial‑of‑service or heap corruption. |
| Medium | NULL dereference of session lookup | `handle_request` | If `lookup_session` is allowed to return `NULL`, the code blindly dereferences it, leading to a crash that can be triggered by malformed requests. |
| Low | Improper union processing on malformed input | `_seterr_reply` | A packet that specifies a valid discriminant but does not contain the expected data will cause the code to read uninitialized memory, potentially corrupting application state or causing erroneous error reporting. |
| Low | Dependence on `assert` | All functions with `assert` | When built with NDEBUG, NULL or invalid arguments bypass assertion checks and may lead to crashes or undefined behaviour. |

**Recommendation**

* Validate enumeration values after decoding (e.g., check that `oa_flavor` is one of the supported flavors).
* Add explicit size checks on authentication blobs or rely on defensive allocations.
* Guard against `NULL` from `lookup_session` and return an error instead of dereferencing.
* Ensure that all unions are correctly initialized before reading their fields.
* Prefer compile‑time and run‑time checks over bare assertions for publicly exposed API.