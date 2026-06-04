# Scan: rpc_callmsg.c

### Security Analysis of `rpc_callmsg.c`

The `xdr_callmsg` function implements the serialization (ENCODE) and deserialization (DECODE) of RPC call messages. The primary attack surface is the `XDR_DECODE` path, where data arrives from the network.

#### 1. Memory Leak on Decoding Failure
In the `XDR_DECODE` block, the code allocates memory for the opaque authentication structures (`cb_cred` and `cb_verf`) using `mem_alloc(oa->oa_length)`. 

If the function encounters an error after this allocation—for example, if `XDR_INLINE` returns `NULL` and `xdr_opaque` subsequently fails, or if the decoding of the second opaque structure (`cb_verf`) fails—the function returns `FALSE` immediately. There is no mechanism within this function to free the previously allocated `oa->oa_base`. Since this is part of a network-facing RPC parser, an attacker can send a series of malformed packets that trigger these failure paths, leading to a Kernel/System memory exhaustion (DoS).

#### 2. Potential Buffer Overflow in `XDR_ENCODE`
In the `XDR_ENCODE` block, the code calculates the size for `XDR_INLINE`:
```c
buf = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT
    + RNDUP(cmsg->rm_call.cb_cred.oa_length)
    + 2 * BYTES_PER_XDR_UNIT
    + RNDUP(cmsg->rm_call.cb_verf.oa_length));
```
While there are checks against `MAX_AUTH_BYTES`, the code later performs a `memcpy`:
```c
if (oa->oa_length) {
    memcpy(buf, oa->oa_base, oa->oa_length);
    buf += RNDUP(oa->oa_length) / sizeof (int32_t);
}
```
Crucially, `buf` is a pointer to the XDR buffer. The `memcpy` copies `oa_length` bytes. If `oa->oa_base` is not properly null-terminated or if the internal XDR buffer management does not strictly enforce the bounds provided to `XDR_INLINE` during the pointer arithmetic (`buf += ...`), this could lead to out-of-bounds writes. However, the most immediate risk in the encoding path is generally lower than the decoding path unless `cmsg` is constructed from untrusted internal sources.

#### 3. Integer Overflow in `RNDUP`
The `RNDUP(x)` macro is defined as `((((x) + 3) / 4) * 4)`. 
In the `XDR_DECODE` path:
```c
buf = XDR_INLINE(xdrs, RNDUP(oa->oa_length));
```
If `oa->oa_length` is very large (near `UINT32_MAX`), `oa->oa_length + 3` can overflow, resulting in a small value. While `oa->oa_length` is checked against `MAX_AUTH_BYTES` (400) before this call, the check is:
```c
if (oa->oa_length > MAX_AUTH_BYTES) { return (FALSE); }
```
This protects against the overflow. However, if `MAX_AUTH_BYTES` were ever increased or if the check were bypassed, this would be a critical vulnerability.

#### 4. NULL Pointer Dereferences
The function does not verify if `xdrs` or `cmsg` are `NULL` upon entry. While these are often guaranteed by the caller in XDR frameworks, a NULL `xdrs` would lead to an immediate crash when accessing `xdrs->x_op`.

### Summary of Findings

```json
[
  {
    "severity": "medium",
    "title": "Memory Leak on Malformed RPC Packet",
    "function": "xdr_callmsg()",
    "description": "In XDR_DECODE mode, the function allocates memory for oa->oa_base using mem_alloc(). If subsequent decoding steps fail (e.g., xdr_opaque fails or the second auth structure is invalid), the function returns FALSE without freeing the allocated memory, allowing a remote attacker to trigger a Denial of Service via memory exhaustion."
  },
  {
    "severity": "low",
    "title": "Missing NULL Pointer Validation",
    "function": "xdr_callmsg()",
    "description": "The function dereferences the XDR handle (xdrs->x_op) and the message structure (cmsg) without checking if they are NULL, which could lead to a kernel panic if called with invalid pointers."
  }
]
```