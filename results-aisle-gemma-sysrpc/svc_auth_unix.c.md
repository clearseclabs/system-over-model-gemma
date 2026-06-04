# Scan: svc_auth_unix.c

### Security Analysis of `svc_auth_unix.c`

The `_svcauth_unix` function is responsible for decoding UNIX credentials from an RPC message. The primary attack surface is the raw credential buffer (`oa_base`) and its length (`oa_length`).

#### 1. Memory Layout and Pointer Arithmetic
The code utilizes `XDR_INLINE` to obtain a pointer (`buf`) to the underlying data. It then performs pointer arithmetic to skip the hostname string:
`buf += str_len / sizeof (int32_t);`

**Potential Issue: Misalignment/Incorrect Offset**
`str_len` is rounded up using `RNDUP(str_len)`. If `RNDUP` ensures the value is a multiple of 4 (the size of `int32_t`), the division is safe. However, if `str_len` is manipulated such that the pointer arithmetic lands in the middle of a 4-byte word (though unlikely given `RNDUP`), it could cause alignment faults on certain architectures. More importantly, the code relies on the assumption that `str_len` (the length of the hostname) is a byte count, while `buf` is an `int32_t*`.

#### 2. Integer Overflow Analysis
The function performs several length checks:
1. `if (auth_len < min_len)`
2. `if (auth_len < min_len + str_len)`
3. `if (auth_len < min_len + str_len + supp_ngroups * BYTES_PER_XDR_UNIT)`

**Analysis:**
* `min_len` is a constant (20 bytes).
* `str_len` is capped by `AUTH_SYS_MAX_HOSTNAME`.
* `supp_ngroups` is capped by `AUTH_SYS_MAX_GROUPS`.

Because these values are strictly capped by constants before being used in additions, the expressions `min_len + str_len` and `min_len + str_len + (supp_ngroups * 4)` cannot overflow a `uint32_t` (assuming standard values for `AUTH_SYS_MAX_HOSTNAME` and `AUTH_SYS_MAX_GROUPS`).

#### 3. Out-of-Bounds Read / Buffer Overflow
The loop processing supplementary groups is the most critical section:
```c
for (uint32_t i = 0; i < supp_ngroups; ++i) {
    if (i < XU_NGROUPS - 1)
        xcr->cr_sgroups[i] = IXDR_GET_INT32(buf);
    else
        buf++;
}
```
**Analysis:**
* **Destination (`xcr->cr_sgroups`):** The check `if (i < XU_NGROUPS - 1)` prevents writing past the end of the `cr_sgroups` array. This is a safe boundary check.
* **Source (`buf`):** The code verifies that `auth_len` is sufficient to cover `min_len + str_len + (supp_ngroups * 4)`.
* **The `buf++` logic:** When `i >= XU_NGROUPS - 1`, the code executes `buf++`. Since `buf` is an `int32_t*`, `buf++` increments the pointer by **4 bytes**.
* **The Logic Error:** The loop iterates `supp_ngroups` times. For each iteration, it consumes 4 bytes from the buffer (either via `IXDR_GET_INT32` or `buf++`). This matches the length check performed earlier.

#### 4. Logic Flaw: The `IXDR_GET` Macro Behavior
A critical vulnerability exists in how the `buf` pointer is managed.
The `IXDR_GET_UINT32(buf)` and `IXDR_GET_INT32(buf)` macros typically read the value at the current pointer and **increment the pointer** automatically.

Let's trace the pointer `buf`:
1. `time = IXDR_GET_UINT32(buf);` $\to$ `buf` moves +4.
2. `str_len = IXDR_GET_UINT32(buf);` $\to$ `buf` moves +4.
3. `buf += str_len / sizeof (int32_t);` $\to$ `buf` moves +`str_len`.
4. `xcr->cr_uid = IXDR_GET_UINT32(buf);` $\to$ `buf` moves +4.
5. `xcr->cr_gid = IXDR_GET_UINT32(buf);` $\to$ `buf` moves +4.
6. `supp_ngroups = IXDR_GET_UINT32(buf);` $\to$ `buf` moves +4.

Total pointer movement before the loop: $4 + 4 + \text{str\_len} + 4 + 4 + 4 = 20 + \text{str\_len}$.
This matches `min_len + str_len`.

However, inside the loop:
```c
if (i < XU_NGROUPS - 1)
    xcr->cr_sgroups[i] = IXDR_GET_INT32(buf); // Moves buf +4
else
    buf++; // Moves buf +4
```
The logic is consistent. There is no buffer overflow.

#### 5. Potential NULL Dereference
The code retrieves `xcr = rqst->rq_clntcred;`. It then proceeds to write to `xcr->cr_uid`, etc. If `rqst->rq_clntcred` is `NULL`, the kernel/process will crash. Depending on where `rqst` is allocated and how the RPC framework initializes it, this could be a DoS vector if an attacker can trigger this path without a pre-allocated credential structure.

### Findings

```json
[
  {
    "severity": "medium",
    "title": "Potential NULL Pointer Dereference",
    "function": "_svcauth_unix",
    "description": "The function assigns xcr = rqst->rq_clntcred and immediately dereferences it to write credentials. If the RPC request structure is not properly initialized or if rq_clntcred is NULL, this will result in a null pointer dereference and a denial-of-service (crash)."
  }
]
```