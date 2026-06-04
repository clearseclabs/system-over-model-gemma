# VULN-029: ummary of Findings

- **File**: `xdr.h`
- **Confidence**: 50% [UIV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

ummary of Findings

### Summary of Findings

```json
[
  {
    "severity": "high",
    "title": "Out-of-Bounds Read via XDR_INLINE pointer arithmetic",
    "function": "IXDR_GET_* macros",
    "description": "The IXDR_GET macros perform pointer increments (*(buf)++) without verifying that the current position is within the bounds established by the initial XDR_INLINE call, allowing OOB reads if the stream length is malformed."
  },
  {
    "severity": "medium",
    "title": "Integer Overflow in RNDUP macro",
    "function": "RNDUP(x)",
    "description": "The RNDUP macro performs addition before division. If 'x' is close to the maximum value of its type, an integer overflow occurs, potentially leading to undersized buffer allocations and subsequent heap overflows."
  },
  {
    "severity": "medium",
    "title": "Potential NULL pointer dereference in XDR macros",
    "function": "XDR_GETLONG / XDR_GETBYTES / XDR_INLINE",
    "description": "The XDR operation macros dereference (xdrs)->x_ops without validation. If an uninitialized XDR handle is passed, the system will crash."
  }
]
```

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN

I will analyze the three reported findings separately. 

1. **IXDR_GET_* OOB Read**: The `IXDR_GET_*` macros perform `*(buf)++`. These are designed for performance and rely on the caller to have called `XDR_INLINE(xdrs, len)` first. The vulnerability is real if a caller uses these macros without ensuring the buffer returned by `XDR_INLINE` actually contains enough bytes. Since `XDR_INLINE` implementations (like in `xdr_mem.c` or `xdr_mbuf.c`) typically return a pointer to a contiguous block of memory of size `len`, and the macros increment this pointer, an attacker providing a malformed stream can trigger OOB reads if the decode logic doesn't strictly track the remaining bytes against the `len` passed to `XDR_INLINE`. 

2. **RNDUP Integer Overflow**: `RNDUP(x)` is defined as `((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) * BYTES_PER_XDR_UNIT)`. With `BYTES_PER_XDR_UNIT = 4`, this is `((x + 3) / 4) * 4`. If `x` is `UINT_MAX`, `x + 3` overflows. If this result is used for a buffer allocation (e.g., `malloc(RNDUP(len))`), an overflow leads to a small allocation followed by a large write, which is a classic heap overflow. I need to check where `RNDUP` is used.

3. **NULL pointer dereference**: The macros `XDR_GETLONG` etc. dereference `(xdrs)->x_ops`. In a kernel or system RPC implementation, `XDR` handles are typically initialized by a factory function (like `xdrmem_create`) before being passed to decode routines. A NULL `x_ops` would only occur if an uninitialized `XDR` struct was passed, which is generally a programmer error (code quality) rather than an attacker-controlled trigger, unless the `XDR` struct itself is placed in attacker-writable memory.

I will start by searching for usages of `RNDUP` and `IXDR_GET` to see if they are exposed to untrusted lengths.

CRUX: Whether RNDUP is used on attacker-controlled lengths without bounds checking, or if IXDR_GET is used without verifying the inline buffer size.
GREP: RNDUP

### Round 2: ❌ INVALID

I analyzed the three reported findings. 

1. **IXDR_GET_* OOB Read**: The `IXDR_GET_*` macros are designed for high-performance decoding from a buffer previously obtained via `XDR_INLINE(xdrs, len)`. The macros themselves do not perform bounds checking because they are intended to be used within a block where the caller has already verified that `len` bytes are available. Whether this is a vulnerability depends on whether any call sites fail to validate the `len` passed to `XDR_INLINE` or the subsequent number of `IXDR_GET` calls. Without seeing a specific call site that violates this contract, the pattern itself is a design choice, not a bug.

2. **RNDUP Integer Overflow**: The `RNDUP(x)` macro is `((((x) + 3) / 4) * 4)`. If `x` is a `u_int` (typically 32-bit) and is very large (e.g., `0xFFFFFFFF`), `x + 3` will overflow. However, the grep results show that `RNDUP` is primarily used in `xdr.h` and related headers. Most usages in the provided grep (like `NFSM_RNDUP`) are applied to constants (e.g., `NFSX_V4PNFSFH`), which are not attacker-controlled. To be a security vulnerability, `RNDUP` must be used on an attacker-controlled variable that is subsequently used for memory allocation without prior bounds checking. I found no such evidence in the provided context.

3. **NULL pointer dereference**: The macros dereference `(xdrs)->x_ops`. In the XDR framework, the `XDR` handle is created by functions like `xdrmem_create` or `xdrmbuf_create`, which initialize the `x_ops` table. For an attacker to trigger a NULL dereference, they would need to control the `XDR` handle pointer itself or cause a factory function to fail in a way that returns a partially initialized handle that is then used. This is a code quality/programmer error issue, not a vulnerability reachable via network input.

Conclusion: None of the findings are demonstrated to be reachable and exploitable security vulnerabilities based on the provided code and grep results. They are either design patterns requiring caller discipline or potential bugs that only trigger under conditions (like uninitialized handles) that are not attacker-controllable.

CRUX: The reported 'vulnerabilities' are either design patterns (IXDR_GET), potential overflows on constants (RNDUP), or require control over internal state structures (NULL x_ops) rather than network input.
GREP: XDR_INLINE

### Round 3: ✅ VALID

I have analyzed the three reported findings. 

1. **IXDR_GET_* OOB Read**: The macros `IXDR_GET_*` perform pointer arithmetic (`*(buf)++`) without bounds checking. This is a performance optimization designed to be used after `XDR_INLINE(xdrs, len)` returns a pointer to a contiguous block of memory. The security of this pattern depends on the caller ensuring that the number of `IXDR_GET` calls does not exceed the `len` passed to `XDR_INLINE`. Grep results show multiple call sites (e.g., `sys/rpc/rpc_callmsg.c:128` and `164`) where `XDR_INLINE` is called with `RNDUP(oa->oa_length)`. If `oa_length` is attacker-controlled and the subsequent decoding logic reads more than `RNDUP(oa_length)` bytes, an OOB read occurs. However, the macros themselves are just tools; the vulnerability would be in the specific XDR procedure. Without a concrete example of a procedure that reads past the inline buffer, this is a pattern, not a demonstrated bug.

2. **RNDUP Integer Overflow**: `RNDUP(x)` is defined as `((((x) + 3) / 4) * 4)`. If `x` is a 32-bit unsigned integer, `x = 0xFFFFFFFF` causes an overflow (`0xFFFFFFFF + 3 = 2`). This results in `(2 / 4) * 4 = 0`. If this result is passed to a memory allocator (e.g., `malloc(0)`), it could lead to a heap overflow when the subsequent code writes `x` bytes into the resulting buffer. Grep results show `RNDUP` is used in `rpc_callmsg.c` and `rpcsec_gss.c` as an argument to `XDR_INLINE`. In `XDR_INLINE`, this value represents the number of bytes to ensure are available in the buffer. If `RNDUP` overflows to 0, `XDR_INLINE` will likely return a pointer to the current position without verifying any length, and subsequent `IXDR_GET` calls will read OOB. Since `oa->oa_length` (from `rpc_callmsg.c`) is derived from the network packet, an attacker can trigger this overflow.

3. **NULL pointer dereference**: The macros dereference `(xdrs)->x_ops`. As noted by previous reviewers, `XDR` handles are initialized by factory functions. A NULL `x_ops` would require an uninitialized handle to be passed, which is a code quality issue/programmer error, not a vulnerability reachable via untrusted network input.

Focusing on `RNDUP`, the overflow is real and reachable via `oa_length` in `rpc_callmsg.c`. If `RNDUP(oa->oa_length)` overflows to a small value, `XDR_INLINE` will not validate the buffer size sufficiently, leading to OOB reads during the subsequent `IXDR_GET` calls.

CRUX: The RNDUP macro overflows when x is near UINT_MAX (e.g., 0xFFFFFFFF), and it is used on attacker-controlled lengths (oa->oa_length) in rpc_callmsg.c to determine the size of the inline buffer, leading to insufficient bounds checking.
GREP: oa_length

### Round 4: ✅ VALID

[ARBITER] The RNDUP macro defined as `((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) * BYTES_PER_XDR_UNIT)` is susceptible to integer overflow if `x` is near `UINT_MAX`. Specifically, `(x + 3)` will wrap around. Evidence from `rpc_callmsg.c` shows this macro is used on `oa->oa_length`, which is derived from network input. When `RNDUP(oa->oa_length)` overflows, it results in a small value being passed to `XDR_INLINE`. Because `XDR_INLINE` returns a pointer to a buffer of that (now small) size, subsequent `IXDR_GET` calls or `memcpy` operations using the original large `oa->oa_length` will result in an Out-of-Bounds read/write.

