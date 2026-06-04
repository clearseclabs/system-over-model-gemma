# Scan: rpc_generic.c

### Security Analysis of `rpc_generic.c`

The provided code implements helper functions for the Kernel RPC (kRPC) subsystem, primarily focusing on address translation (`uaddr` $\leftrightarrow$ `taddr`) and network configuration management.

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

#### 2. Network Configuration Analysis

**`__rpc_nconf2sockinfo`**
*   **NULL Dereference**: The function takes `const struct netconfig *nconf`. There is no check to ensure `nconf` is not NULL before accessing `nconf->nc_netid` in `strcmp`. If `getnetconfig()` or a similar upstream caller returns NULL, this will cause a kernel panic.

**`__rpc_getconf`**
*   **Uninitialized Memory Access**: The function relies on `handle->nettype` and `handle->nflag`. These are set in `__rpc_setconf`. If `__rpc_getconf` is called with a pointer that was not produced by `__rpc_setconf` (or is corrupted), it will lead to undefined behavior.

#### 3. Other Observations

*   **`bindresvport`**: This function performs `memset(sa, 0, sa->sa_len)` if `sa` is NULL. However, it relies on `sa->sa_len` from `sosockaddr`. If the socket address is malformed, `sa_len` could be an unexpectedly large value, leading to an out-of-bounds `memset` on the stack-allocated `struct sockaddr_storage ss`.

### Summary of Findings

| Severity | Title | Function | Description |
| :--- | :--- | :--- | :--- |
| **High** | Kernel Heap Over-read | `__rpc_taddr2uaddr_af` | In the `AF_LOCAL` case, `sun->sun_len` is used to determine the length of the string to print without verifying it against the actual buffer size `nbuf->len`, allowing an attacker to read adjacent kernel memory. |
| **High** | Kernel NULL Dereference | `__rpc_nconf2sockinfo` | The function dereferences the `nconf` pointer without checking for NULL, which can be triggered if the network configuration lookup fails. |
| **Medium** | Potential Out-of-Bounds Memset | `bindresvport` | If `sa` is NULL, the function uses `sa->sa_len` (derived from `sosockaddr`) as the length for `memset` on a stack buffer. A malformed socket address could trigger a stack overflow. |
| **Low** | String Truncation/Non-termination | `__rpc_uaddr2taddr_af` | `strncpy` is used to copy the path to `sun_path`. If the input is exactly `sizeof(sun->sun_path) - 1`, it is safe, but the lack of explicit null-termination after `strncpy` is a risky pattern in the kernel. |

```json
[
  {
    "severity": "high",
    "title": "Kernel Heap Over-read in AF_LOCAL address translation",
    "function": "__rpc_taddr2uaddr_af",
    "description": "The function uses sun->sun_len to calculate the length of the path string to print via sbuf_printf for AF_LOCAL addresses, but it fails to validate that sun_len is within the bounds of nbuf->len, leading to a potential kernel information leak."
  },
  {
    "severity": "high",
    "title": "NULL Pointer Dereference in netconfig translation",
    "function": "__rpc_nconf2sockinfo",
    "description": "The function dereferences the nconf parameter to access nc_netid without verifying that nconf is not NULL, which can cause a kernel panic if called with a NULL pointer."
  },
  {
    "severity": "medium",
    "title": "Potential Stack Over-write in bindresvport",
    "function": "bindresvport",
    "description": "When sa is NULL, the function uses the length returned by sosockaddr (sa->sa_len) to perform a memset on a stack-allocated sockaddr_storage buffer. If sa_len is larger than sizeof(struct sockaddr_storage), this results in a stack overflow."
  }
]
```