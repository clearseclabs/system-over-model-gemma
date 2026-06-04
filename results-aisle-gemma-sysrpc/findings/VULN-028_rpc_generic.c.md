# VULN-028: Address Translation Analysis

- **File**: `rpc_generic.c`
- **Confidence**: 50% [VUU→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Address Translation Analysis

#### 1. Address Translation Analysis

**`__rpc_taddr2uaddr_af` (Binary $\rightarrow$ String)**
*   **Potential Buffer Over-read**: In the `AF_LOCAL` case:
    ```c
    case AF_LOCAL:
        sun = nbuf->buf;
        if (sbuf_printf(&sb, "%.*s", (int)(sun->sun_len - 
            offsetof(struct sockaddr_un, sun_path)),
            sun->sun_path) < 0)
            return (NULL);
        break;
    ```
    The function trusts `sun->sun_len`. If `nbuf->buf` is provided by an untrusted source or is corrupted, and `sun_len` is excessively large, `sbuf_printf` will read past the end of the `nbuf->buf` buffer. While `nbuf->len` is checked for `AF_INET/6`, it is **not** checked for `AF_LOCAL`.

**`__rpc_uaddr2taddr_af` (String $\rightarrow$ Binary)**
*   **Integer Overflow/Logic Error in Port Parsing**:
    ```c
    portlo = (unsigned)strtol(p + 1, NULL, 10);
    // ...
    porthi = (unsigned)strtol(p + 1, NULL, 10);
    // ...
    port = (porthi << 8) | portlo;
    ```
    The use of `strtol` without checking for overflows or negative values allows an attacker to pass very large strings. While the result is cast to `unsigned`, the logic `(porthi << 8) | portlo` could produce unexpected port numbers.
*   **Memory Leak on Error Paths**:
    The function calls `addrstr = strdup(uaddr, M_RPC)`. In several error cases (e.g., `p == NULL` during port parsing), it uses `goto out;` which calls `free(addrstr)`. However, if `inet_pton` fails for `AF_INET` or `AF_INET6`, it frees `sin`/`sin6` and `ret`, then hits `goto out;`. This flow is generally correct, but the complexity of the nested `mallocs` (`ret`, then `sin`) increases the risk of leaks if future modifications add more error paths.
*   **`strncpy` and Null Termination**:
    ```c
    strncpy(sun->sun_path, addrstr, sizeof(sun->sun_path) - 1);
    ```
    `strncpy` does not guarantee null termination if the source string is longer than the limit. While `memset(sun, 0, sizeof *sun)` is called earlier, ensuring the buffer is clean, the `sun_path` will be truncated without a null terminator at the end if `addrstr` is long. This might lead to over-reads in functions that expect a null-terminated string.

---

## Triage reasoning

### Round 1: ✅ VALID

I analyzed the reported vulnerabilities in `rpc_generic.c`. 

1. **`__rpc_taddr2uaddr_af` (Buffer Over-read)**: In the `AF_LOCAL` case, `sbuf_printf` uses `sun->sun_len` to determine the number of bytes to read from `sun->sun_path`. `sun` is derived from `nbuf->buf`. The report claims `nbuf->len` is not checked for `AF_LOCAL`. Looking at the code, for `AF_INET` and `AF_INET6`, there are explicit checks: `if (nbuf->len < sizeof(*sin))`. For `AF_LOCAL`, there is no such check. If `nbuf->buf` contains a `sockaddr_un` where `sun_len` is larger than the actual buffer provided in `nbuf`, `sbuf_printf` will perform an out-of-bounds read. Since `nbuf` is described as potentially coming from untrusted sources, this is a valid over-read pattern. 

2. **`__rpc_uaddr2taddr_af` (Port Parsing)**: The logic `port = (porthi << 8) | portlo` using `strtol` is sloppy, but `strtol` returns a `long`. Casting to `unsigned` and shifting doesn't lead to a memory corruption or crash; it just leads to a potentially incorrect port number, which is not a security vulnerability. 

3. **`__rpc_uaddr2taddr_af` (strncpy/Null Termination)**: `strncpy` is used as `strncpy(sun->sun_path, addrstr, sizeof(sun->sun_path) - 1);`. Because `memset(sun, 0, sizeof *sun)` is called immediately before, the buffer is zero-initialized. `strncpy` will not overwrite the final byte (index `sizeof(sun->sun_path) - 1`), ensuring the string is always null-terminated regardless of the length of `addrstr`. This is a safe pattern.

4. **Memory Leaks**: The report mentions complexity in error paths, but this is a code quality issue, not a security vulnerability.

The crux is the missing bounds check on `nbuf->len` for `AF_LOCAL` in `__rpc_taddr2uaddr_af`, allowing `sun_len` to drive an over-read.

CRUX: In `__rpc_taddr2uaddr_af`, the `AF_LOCAL` case trusts `sun->sun_len` without verifying that `nbuf->len` is large enough to contain the indicated length, leading to a potential buffer over-read.
GREP: void __rpc_taddr2uaddr_af

### Round 2: ❓ UNCERTAIN

I examined the `AF_LOCAL` case in `__rpc_taddr2uaddr_af`. The code reads `sun = nbuf->buf` and then uses `sun->sun_len` to calculate the precision for `sbuf_printf` (`%.*s`). There is no check to ensure that `nbuf->len` is at least as large as `sun->sun_len`. If an attacker can provide a `netbuf` structure where `sun_len` is large but the actual buffer `nbuf->buf` is small, `sbuf_printf` will read past the end of the buffer. To determine if this is reachable, I need to find the callers of `taddr2uaddr` (which calls `__rpc_taddr2uaddr_af`). If `taddr2uaddr` is used to process data received from the network or from an untrusted user-supplied `netbuf` (e.g., via a syscall), it is a valid vulnerability. If it is only used for local kernel-generated addresses, it is not. The security context mentions `nbuf->buf` as untrusted input, which I must verify by tracing the callers.

CRUX: Whether `taddr2uaddr` is called with `netbuf` structures originating from untrusted input, as there is no validation that `nbuf->len >= sun->sun_len` for `AF_LOCAL` addresses.
GREP: taddr2uaddr

### Round 3: ❓ UNCERTAIN

I analyzed the reported buffer over-read in `__rpc_taddr2uaddr_af` for the `AF_LOCAL` case. The code indeed uses `sun->sun_len` to determine the length of the string to print via `sbuf_printf` without verifying that `nbuf->len` is sufficient to cover that length. This is a classic buffer over-read pattern. To determine if this is a security vulnerability, I must verify if an attacker can control the `nbuf` structure passed to this function. The previous reviewers failed to find callers of `taddr2uaddr` because they likely searched for the exact string, but the code shows `taddr2uaddr` is a wrapper for `__rpc_taddr2uaddr_af`. I need to find where `taddr2uaddr` or `__rpc_taddr2uaddr_af` are called. If these are used to translate addresses provided in RPC requests (e.g., in a `clnt` handle or a registration request), it is VALID. If they are only used for internal kernel-managed addresses, it is INVALID. I will search for all references to these functions to trace the data flow.

CRUX: Whether the `nbuf` structure passed to `__rpc_taddr2uaddr_af` can be constructed from untrusted network input, as the `AF_LOCAL` path trusts `sun_len` without bounds checking against `nbuf->len`.
GREP: taddr2uaddr

### Round 4: ✅ VALID

[ARBITER] In `__rpc_taddr2uaddr_af`, the `AF_LOCAL` case accesses `sun->sun_len` to determine the number of bytes to read from `sun->sun_path` via `sbuf_printf`. Unlike the `AF_INET` and `AF_INET6` cases, which explicitly check `if (nbuf->len < sizeof(*sin))`, the `AF_LOCAL` path performs no validation to ensure `nbuf->len` is sufficient to encompass the length specified by `sun_len`. An attacker providing a crafted `netbuf` where `sun_len` is large but the actual buffer is small can trigger a buffer over-read.

