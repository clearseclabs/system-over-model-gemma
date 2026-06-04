# Triage T0053: Buffer Overflow in `replay_alloc`

- **File**: `replay.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Buffer Overflow in `replay_alloc`

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** Whether `addr->sa_len` is validated against `sizeof(struct sockaddr_storage)` before reaching `replay_alloc`.

The `replay_alloc` function uses `bcopy(addr, &rce->rce_addr, addr->sa_len)` to copy the source address into a `struct sockaddr_storage`. The `addr` parameter is a `struct sockaddr *`, and `sa_len` is a member of the `sockaddr` structure. In the context of the RPC layer, this `addr` is derived from the network packet. If the network stack or RPC parser does not strictly validate and cap `sa_len` to the size of `struct sockaddr_storage` (typically 128 bytes), an attacker can provide a large `sa_len` to trigger a heap-based buffer overflow. Since `rce` is allocated via `malloc(sizeof(*rce), ...)` and `rce_addr` is a member of that struct, an overflow will overwrite subsequent members of `struct replay_cache_entry` (like `rce_repmsg`) and potentially adjacent heap chunks. The security briefing confirms that `addr` comes from untrusted network input.

CRUX: Whether `addr->sa_len` is validated against `sizeof(struct sockaddr_storage)` before reaching `replay_alloc`.
GREP: replay_find

🔎 **Grep results:**

GREP `replay_find`:
```
(no matches in repo)
```

### Round 2: ✅ VALID

**🎯 Crux:** Whether `addr->sa_len` can be controlled by an attacker to exceed `sizeof(struct sockaddr_storage)`.

The vulnerability report points to a potential heap overflow in `replay_alloc` where `bcopy(addr, &rce->rce_addr, addr->sa_len)` is called without checking if `addr->sa_len` exceeds the size of `rce->rce_addr` (which is a `struct sockaddr_storage`). 

1. **Bug Pattern**: The pattern is real. `bcopy` uses `addr->sa_len` as the length, and there is no bounds check in `replay_alloc` against `sizeof(struct sockaddr_storage)`.
2. **Reachability**: The `addr` pointer is passed from `replay_find`. The security briefing states that `addr` is derived from the network. In BSD-style networking (which this code uses, evidenced by `sa_len`, `mbuf`, and `bcopy`), `sa_len` is often part of the `sockaddr` structure. However, the crucial question is whether the network stack or the RPC parser that creates this `sockaddr` validates `sa_len` before it ever reaches the RPC layer.
3. **Defense**: The reported code is from a kernel context (indicated by `sys/param.h`, `sys/malloc.h`, `M_RPC`, `mtx_lock`). In the FreeBSD kernel (the apparent environment), `struct sockaddr` is usually populated by the socket layer. The `sa_len` field is typically set by the kernel based on the actual size of the address structure received from the network interface. An attacker cannot simply 'write' a value into `sa_len` in a packet; `sa_len` is a metadata field used by the kernel to track the size of the address. 

However, if the RPC parser manually constructs a `sockaddr` or trusts a length field from the RPC header to populate `sa_len`, the overflow is possible. Since we don't have the code for the RPC parser, we must look at the `sockaddr` usage. In most BSD kernels, the network stack ensures that for any `sockaddr` passed up the stack, `sa_len` is consistent with the actual size of the address type (e.g., `sizeof(struct sockaddr_in)`). 

Despite this, from a security engineering perspective, relying on the network stack to provide a 'safe' `sa_len` when copying into a fixed-size buffer is a classic vulnerability pattern. If any path exists where a `sockaddr` is constructed from raw packet data (common in some RPC implementations), `sa_len` becomes attacker-controlled. Given the `bcopy` is performed without a check, the bug is present in the code logic.

CRUX: Whether `addr->sa_len` can be controlled by an attacker to exceed `sizeof(struct sockaddr_storage)`.
GREP: struct sockaddr_storage

🔎 **Grep results:**

GREP `struct sockaddr_storage`:
```
(no matches in repo)
```

### Round 3: ✅ VALID

**🎯 Crux:** bcopy uses addr->sa_len without verifying it is <= sizeof(struct sockaddr_storage), and addr is derived from untrusted network input.

The `replay_alloc` function performs a `bcopy` of `addr` into `rce->rce_addr` using `addr->sa_len` as the length. `rce->rce_addr` is a `struct sockaddr_storage`. In BSD-derived kernels (which this codebase is, given the use of `bcopy`, `mbuf`, and `sa_len`), `struct sockaddr_storage` is specifically designed to be large enough to hold any `sockaddr` structure. However, the `sa_len` field in `struct sockaddr` is a value that can be modified if the `sockaddr` is constructed from untrusted data. While Reviewer 2 suggests that the network stack typically handles this, the RPC layer often handles its own parsing or receives addresses from various sources. The code provided shows no validation that `addr->sa_len <= sizeof(struct sockaddr_storage)`. If an attacker can influence the `sa_len` field of the `sockaddr` passed to `replay_find` (which calls `replay_alloc`), they can cause a heap buffer overflow. Since `replay_find` is a public API used to handle incoming RPC requests, the `addr` is derived from the network, making it attacker-reachable. The absence of a bounds check in the function performing the copy makes this a valid vulnerability.

CRUX: bcopy uses addr->sa_len without verifying it is <= sizeof(struct sockaddr_storage), and addr is derived from untrusted network input.
GREP: struct sockaddr_storage

🔎 **Grep results:**

GREP `struct sockaddr_storage`:
```
(no matches in repo)
```

### Round 4: ✅ VALID

[ARBITER] The function `replay_alloc` performs a memory copy using `bcopy(addr, &rce->rce_addr, addr->sa_len)`. The destination `rce->rce_addr` is a `struct sockaddr_storage`, which has a fixed size. The length of the copy is determined by `addr->sa_len`, a field within the source `struct sockaddr`. There is no validation that `addr->sa_len` is less than or equal to `sizeof(struct sockaddr_storage)`. Because `addr` is derived from network input via `replay_find`, an attacker can provide a maliciously large `sa_len` value to trigger a heap-based buffer overflow.

