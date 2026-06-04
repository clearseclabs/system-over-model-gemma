# Scan: rpc_callmsg.c

**Security Analysis – `rpc_callmsg.c`**

1. **Purpose & Context**  
   `xdr_callmsg()` serialises / deserialises RPC call messages for the Sun RPC protocol.  It is invoked by the RPC subsystem whenever a request is sent or received.  The function works with a `struct rpc_msg *cmsg` that may be supplied by user code or the kernel, and an `XDR *xdrs` that represents either the encoding or decoding stream.

2. **Untrusted Input**  
   * `cmsg` is populated from data that ultimately comes from the network (the wire‑format of an RPC request).  
   * All length fields (`oa_length`, `cb_rpcvers`, etc.) are read directly from the serialized stream and later used in
     memory allocation, buffer arithmetic, and looping.  
   * The `oa->oa_base` pointer may be provided by client code; it is **not** guaranteed to be NULL.

3. **Key Parameter Validations**  
   * In the **XDR_ENCODE** path the code verifies that the credential and verifier lengths are ≤ `MAX_AUTH_BYTES` (400).  
   * Buffer size for inline serialisation is calculated as  
     `8 * BYTES_PER_XDR_UNIT + RNDUP(cb_cred.oa_length) + 2 * BYTES_PER_XDR_UNIT + RNDUP(cb_verf.oa_length)`  
     which is bounded by the same 400‑byte limit.  
   * In the **XDR_DECODE** path the same length check is performed and `mem_alloc()` is called only when `oa->oa_base == NULL`.  
   * The code *does not* verify that a non‑NULL `oa->oa_base` points to a buffer large enough for `oa->oa_length`.

4. **Faulty Buffer Handling (Decode Path)**  
   * When `oa->oa_base` is **already non‑NULL**, the code skips `mem_alloc()` and **unconditionally** copies  
     `oa->oa_length` bytes into it via `memcpy(oa->oa_base, buf, oa->oa_length)`.  
   * If the previously allocated buffer was smaller than the new `oa->oa_length` (still ≤ 400), the `memcpy()` overruns memory, corrupting the heap or stack and allowing an attacker to inject arbitrary data or a crafted string that could be executed or used to influence subsequent logic.

5. **Other Observations**  
   * The function relies on `XDR_INLINE()` to provide a buffer; if it returns NULL during the **ENCODE** path, the function winds into the **DECODE** branch without performing any encoding, returning `FALSE`.  This is graceful but may hide encoding bugs.  
   * All calls to `xdr_*` helpers are checked for failure; no unchecked return values remain.  
   * No unsigned integer arithmetic overflows can occur given the strict `MAX_AUTH_BYTES` guard and the 32‑bit arithmetic used.  
   * Access to tagged unions (`oa->oa_flavor`, `oa->oa_length`) is via the XDR helpers, which perform the necessary type checks.  
   * `cmsg` itself is never validated for NULL, but callers in the trusted client library always provide a valid pointer; an attacker can force a crash only by sending malformed data that corrupts the structure such that the look‑ups inside `xdr_callmsg()` address invalid memory, which is a legitimate Denial‑of‑Service vector but not an exploit that yields arbitrary code execution.

6. **Potential Impact**  
   * **Heap overflow** from copying too much data into an existing `oa->oa_base` buffer can lead to arbitrary code execution or data corruption in the RPC subsystem, which runs with kernel or elevated privileges on many platforms.  
   * The overflow is *triggerable* by crafting an RPC request with a credential verifier length under 400 but larger than the caller‑supplied buffer, causing the memcpy to write past the buffer boundaries.

7. **Mitigation Recommendations**  
   * **Always reallocate** or re‑validate the buffer size: when `oa->oa_base` is non‑NULL, check its current allocation size (if known) or simply free & reallocate for safety.  
   * Add a guard that rejects any credential length that exceeds the buffer’s capacity (if the buffer is a stack‑allocated array), or add logic to detect uninitialised base pointers.  
   * Consider using safer dynamic‑array helpers (`xdr_opaque` already does this in the NULL case) that accept the allocated size beforehand.  
   * Validate the `cmsg` pointer against NULL at the start of the function to defend against accidental crashes.

------------------------------------------------------------------  

```json
[
  {
    "severity": "critical",
    "title": "Heap buffer overflow during RPC credential decoding",
    "function": "xdr_callmsg() – XDR_DECODE path",
    "description": "The code copies the credential body into `oa->oa_base` without verifying that a pre‑existing buffer is large enough. If the caller re‑uses a `rpc_msg` instance that still contains a previously allocated `oa_base` of size < `oa->oa_length` (≤ 400 bytes), `memcpy()` overruns the buffer, corrupting the heap and potentially yielding arbitrary code execution."
  },
  {
    "severity": "medium",
    "title": "Silent XDR_ENCODE failure when inline buffer unavailable",
    "function": "xdr_callmsg() – XDR_ENCODE path",
    "description": "When `XDR_INLINE()` returns NULL, the function skips encoding the message and falls through to the decode logic, ultimately returning FALSE. This may silence errors but can also hide malformed input, leading to denial‑of‑service or subtle protocol desynchronisation."
  },
  {
    "severity": "low",
    "title": "Missing null‑pointer check for cmsg",
    "function": "xdr_callmsg()",
    "description": "The function assumes that the caller always passes a non‑NULL `cmsg`. A malformed call could cause a crash, but this is only a denial‑of‑service vector and is not exploitable for privilege escalation."
  }
]
```