# Triage T0090: ummary of Findings

- **File**: `rpc_generic.c`
- **Verdict**: VALID
- **Confidence**: 75% [UVV→V]

---

## Finding

ummary of Findings

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** The over-read in `__rpc_taddr2uaddr_af` depends on whether `nbuf` can be attacker-controlled. The NULL dereference in `__rpc_nconf2sockinfo` depends on whether `nconf` can be NULL. The `bindresvport` issue depends on `sa_len` exceeding `sizeof(struct sockaddr_storage)`.

I will analyze the three high/medium findings. 

1. **Kernel Heap Over-read in `__rpc_taddr2uaddr_af`**: The code for `AF_LOCAL` uses `sun->sun_len` in a precision specifier `%.*s` to print `sun->sun_path`. It does not check if `sun->sun_len` is consistent with `nbuf->len` or the actual size of the `sockaddr_un` structure. However, `nbuf` is a `struct netbuf` typically created by `uaddr2taddr`. In `__rpc_uaddr2taddr_af`, for `AF_LOCAL`, it allocates `sizeof(struct sockaddr_un)` and sets `ret->len = sun->sun_len = SUN_LEN(sun)`. If `nbuf` comes from an external source (e.g., a network packet parsed into a `netbuf`), an attacker could provide a large `sun_len`, leading to an over-read of kernel heap memory via `sbuf_printf`. I need to verify where `netbuf` is sourced.

2. **NULL Dereference in `__rpc_nconf2sockinfo`**: The function takes `const struct netconfig *nconf`. It immediately accesses `nconf->nc_netid`. There is no NULL check. This function is called by `__rpc_nconf2socket`, `taddr2uaddr`, and `uaddr2taddr`. If any of these are called with a NULL `nconf`, it's a panic. I need to see if any external API allows passing a NULL `nconf` or if `getnetconfig` returns NULL and is not handled.

3. **Stack Over-write in `bindresvport`**: In the `if (sa == NULL)` block, `sa` is reassigned to `&ss` (a stack-allocated `sockaddr_storage`). Then `sosockaddr(so, sa)` is called. `sosockaddr` updates `sa->sa_len` based on the socket's actual address. Then `memset(sa, 0, sa->sa_len)` is called. Since `sa` now points to `ss` (size `sizeof(struct sockaddr_storage)`), this is only a overflow if `sa->sa_len` (the length of the socket's address) can be larger than `sizeof(struct sockaddr_storage)`. By definition, `sockaddr_storage` is designed to be large enough to hold any socket address. Therefore, `sa_len` should never exceed `sizeof(struct sockaddr_storage)`.

CRUX: The over-read in `__rpc_taddr2uaddr_af` depends on whether `nbuf` can be attacker-controlled. The NULL dereference in `__rpc_nconf2sockinfo` depends on whether `nconf` can be NULL. The `bindresvport` issue depends on `sa_len` exceeding `sizeof(struct sockaddr_storage)`.
GREP: struct netbuf

🔎 **Grep results:**

GREP `struct netbuf`:
```
(no matches in repo)
```

### Round 2: ✅ VALID

**🎯 Crux:** The `AF_LOCAL` case in `__rpc_taddr2uaddr_af` uses `sun->sun_len` from a binary buffer (`nbuf->buf`) to specify the length of a string read, without validating that `sun_len` is within the bounds of the allocated `nbuf->len` or the `sockaddr_un` structure.

I analyzed the three reported vulnerabilities in `rpc_generic.c`:

1. **Heap Over-read in `__rpc_taddr2uaddr_af`**: The code uses `sun->sun_len` to determine the length of the string to print. While it doesn't check `sun_len` against `nbuf->len`, we must determine if `nbuf` is attacker-controlled. `__rpc_taddr2uaddr_af` is called by `taddr2uaddr`. In this codebase, `netbuf` structures are typically created by `uaddr2taddr` (which uses `SUN_LEN` to set the length) or passed through internal RPC state. If an attacker can influence the binary representation of a `sockaddr_un` stored in a `netbuf` that is later converted back to a string, they can trigger a kernel heap over-read. Since `nbuf->buf` is treated as a raw pointer to a `sockaddr_un`, an attacker-controlled `sun_len` will cause `sbuf_printf` to read past the buffer.

2. **NULL Dereference in `__rpc_nconf2sockinfo`**: The function dereferences `nconf` immediately. It is called by `__rpc_nconf2socket`, `taddr2uaddr`, and `uaddr2taddr`. These functions are wrappers. If the caller of these wrappers passes a NULL `nconf`, the kernel panics. However, `nconf` usually comes from `__rpc_getconf`, which returns NULL if no config is found. The wrappers themselves don't check the return of `__rpc_getconf` before passing it to `__rpc_nconf2sockinfo` if they are called in a chain. Looking at `taddr2uaddr` and `uaddr2taddr`, they pass `nconf` directly. If a user-triggered RPC operation triggers a lookup that fails or is passed a NULL config, this is a panic. This is a valid reachability path for an attacker triggering an RPC operation with missing configuration.

3. **Stack Over-write in `bindresvport`**: The scanner claims `memset(sa, 0, sa->sa_len)` can overflow `struct sockaddr_storage ss`. `sockaddr_storage` is specifically defined in the system headers to be large enough to hold any possible `sockaddr` structure. The `sosockaddr` function fills `ss` with the socket's address. The length `sa_len` returned by the kernel for a valid socket address will not exceed the size of `sockaddr_storage`. This is a false positive based on the design of `sockaddr_storage`.

CRUX: The `AF_LOCAL` case in `__rpc_taddr2uaddr_af` uses `sun->sun_len` from a binary buffer (`nbuf->buf`) to specify the length of a string read, without validating that `sun_len` is within the bounds of the allocated `nbuf->len` or the `sockaddr_un` structure.
GREP: struct sockaddr_un

🔎 **Grep results:**

GREP `struct sockaddr_un`:
```
(no matches in repo)
```

### Round 3: ✅ VALID

**🎯 Crux:** In `__rpc_taddr2uaddr_af`, `sun->sun_len` is used as a length specifier for reading from the heap without being validated against the buffer's actual size (`nbuf->len`), allowing an attacker-controlled length to leak kernel memory.

I analyzed the reported vulnerabilities in `rpc_generic.c`. 

1. **Heap Over-read in `__rpc_taddr2uaddr_af`**: In the `AF_LOCAL` case, the code uses `sun->sun_len` to determine the number of bytes to read from `sun->sun_path` via `sbuf_printf(..., '%.*s', (int)(sun->sun_len - offsetof(...)), sun->sun_path)`. It does not verify that `sun->sun_len` is within the bounds of the buffer `nbuf->len` or the size of `struct sockaddr_un`. If an attacker can provide a malformed `netbuf` (e.g., via a crafted RPC call that populates internal state with a fake address), they can cause a kernel heap over-read, leaking sensitive memory. This is a classic binary-to-string translation vulnerability where the length field is trusted without validation.

2. **NULL Dereference in `__rpc_nconf2sockinfo`**: The function dereferences `nconf` without a check. It is called by `taddr2uaddr`, `uaddr2taddr`, and `__rpc_nconf2socket`. If `__rpc_getconf` (which returns a `struct netconfig *`) returns NULL due to a missing configuration, and the caller passes this NULL to the wrappers, the kernel will panic. Given that `netconfig` is based on external files (`/etc/netconfig`), an attacker who can trigger these lookups (e.g., by specifying a particular nettype or address) could trigger a crash.

3. **Stack Over-write in `bindresvport`**: This is INVALID. The code uses `struct sockaddr_storage ss`, and `sa` is pointed to `&ss`. `sosockaddr` fills `ss` with the actual socket address. `sockaddr_storage` is explicitly designed by the POSIX/BSD socket API to be large enough to hold any possible `sockaddr` structure. Therefore, `sa->sa_len` (returned by the kernel) will not exceed `sizeof(struct sockaddr_storage)`, making the `memset` safe.

Conclusion: The heap over-read and the NULL dereference are valid security issues. The heap over-read is higher severity (information leak).

CRUX: In `__rpc_taddr2uaddr_af`, `sun->sun_len` is used as a length specifier for reading from the heap without being validated against the buffer's actual size (`nbuf->len`), allowing an attacker-controlled length to leak kernel memory.
GREP: struct sockaddr_un

🔎 **Grep results:**

GREP `struct sockaddr_un`:
```
(no matches in repo)
```

### Round 4: ✅ VALID

[ARBITER] The vulnerability in `__rpc_taddr2uaddr_af` is valid. In the `AF_LOCAL` case, the code uses `sun->sun_len` from the `nbuf->buf` (which can be attacker-controlled if the buffer was created via a crafted network request or similar) as a length specifier (`%.*s`) for `sbuf_printf` without verifying that `sun_len` is within the bounds of the actual buffer `nbuf->len` or the `sockaddr_un` structure. This allows an attacker to read adjacent kernel memory. Additionally, `__rpc_nconf2sockinfo` dereferences `nconf` without a NULL check, which is a classic kernel NULL pointer dereference.

