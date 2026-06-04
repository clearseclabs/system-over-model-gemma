# VULN-011: ummary of Findings

- **File**: `replay.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

ummary of Findings

### Summary of Findings

```json
[
  {
    "severity": "critical",
    "title": "Heap Buffer Overflow in replay_alloc",
    "function": "replay_alloc()",
    "description": "The function uses bcopy to copy a socket address into rce_addr using addr->sa_len as the length. Since sa_len is attacker-controlled and not validated against the size of struct sockaddr_storage, this leads to a heap-based buffer overflow."
  },
  {
    "severity": "medium",
    "title": "Integer Overflow in Cache Size Tracking",
    "function": "replay_setreply()",
    "description": "The addition to rc->rc_size in replay_setreply does not check for overflow. A wrap-around of the size counter would bypass the memory limit checks in replay_prune, leading to potential kernel memory exhaustion."
  },
  {
    "severity": "medium",
    "title": "Kernel Panic via NULL Pointer Dereference",
    "function": "replay_find() / replay_setreply()",
    "description": "The functions dereference the msg/repmsg and addr pointers without NULL checks. If the upstream RPC parser passes NULL due to malformed input, it will cause a system crash."
  }
]
```

---

## Triage reasoning

### Round 1: ✅ VALID

The function `replay_alloc` performs a `bcopy(addr, &rce->rce_addr, addr->sa_len)`. The destination `rce->rce_addr` is of type `struct sockaddr_storage`, which is a fixed-size buffer designed to hold any socket address. The length `addr->sa_len` comes from the `sockaddr` structure provided by the RPC parser, which is derived from network input. In many BSD-derived kernels (where this code originates), `sa_len` is a field in the `sockaddr` structure that is populated from the network packet. If `sa_len` exceeds `sizeof(struct sockaddr_storage)`, a heap buffer overflow occurs. While the RPC parser might perform some validation, the `replay_alloc` function itself does not verify that `addr->sa_len <= sizeof(rce->rce_addr)`. Given that `sockaddr_storage` is typically 128 bytes and `sa_len` is a `u_char` (max 255) or `int` depending on the platform, an attacker providing a maliciously crafted address length can overflow the `replay_cache_entry` structure on the heap, potentially corrupting adjacent entries or kernel metadata.

CRUX: bcopy in replay_alloc uses addr->sa_len without validating it against the size of rce->rce_addr (struct sockaddr_storage).
GREP: struct sockaddr_storage

### Round 2: ✅ VALID

The vulnerability report identifies a heap buffer overflow in `replay_alloc` where `bcopy` uses `addr->sa_len` to copy data into `rce->rce_addr` (a `struct sockaddr_storage`). 

1. **Bug Pattern**: The pattern is real. `bcopy(addr, &rce->rce_addr, addr->sa_len)` copies `addr->sa_len` bytes. There is no check in `replay_alloc` that `addr->sa_len <= sizeof(rce->rce_addr)`.
2. **Reachability**: The security context confirms that `addr` comes from the RPC parser, which processes network input. In BSD-style kernels, `sa_len` is part of the `sockaddr` structure and can be influenced by the network packet. If an attacker can provide a `sockaddr` with a `sa_len` greater than `sizeof(struct sockaddr_storage)`, they can overflow the heap.
3. **Defense**: No defense is present in `replay_alloc`. The previous reviewer's grep for `struct sockaddr_storage` failed likely because it is defined in a system header (like `<sys/socket.h>`), not the local repo, but `sockaddr_storage` is a standard BSD/POSIX structure typically sized to 128 bytes. Since `sa_len` can typically be larger (e.g., `u_char` up to 255), the overflow is possible.
4. **Security Relevance**: A heap overflow in the kernel is critical, leading to memory corruption, potential privilege escalation, or kernel panic. 

Regarding the other findings: The integer overflow in `rc_size` is possible but less critical than the direct heap overflow. The NULL pointer dereferences are likely invalid as they depend on the RPC parser's contract, whereas the buffer overflow is a direct failure to validate a length field used in a copy operation.

CRUX: replay_alloc calls bcopy with addr->sa_len without verifying that sa_len is less than or equal to sizeof(struct sockaddr_storage), and addr is derived from untrusted network input.
GREP: sizeof(struct sockaddr_storage)

### Round 3: ✅ VALID

The vulnerability in `replay_alloc` is a classic heap buffer overflow. The function performs `bcopy(addr, &rce->rce_addr, addr->sa_len)`. The destination `rce_addr` is of type `struct sockaddr_storage`, which is a fixed-size structure (standardly 128 bytes in BSD/POSIX). The length `addr->sa_len` is provided by the `sockaddr` structure. In BSD-style kernels, `sa_len` is a member of the `sockaddr` struct and is populated during the receipt of a packet. While the RPC parser might perform some checks, `replay_alloc` itself performs no validation of `sa_len` against the size of the destination buffer. Because `sa_len` can be larger than `sizeof(struct sockaddr_storage)` (as it is often an unsigned char or int), an attacker can cause a heap overflow. The security context explicitly states that `addr` is derived from untrusted network input. The other reported bugs (integer overflow in `rc_size` and NULL dereferences) are secondary to this direct memory corruption primitive.

CRUX: replay_alloc uses addr->sa_len as the length for bcopy into a fixed-size struct sockaddr_storage without validating that sa_len <= sizeof(struct sockaddr_storage), and addr is attacker-controlled.
GREP: sockaddr_storage

### Round 4: ✅ VALID

[ARBITER] In `replay_alloc`, the code executes `bcopy(addr, &rce->rce_addr, addr->sa_len)`. The destination `rce->rce_addr` is a `struct sockaddr_storage`, which has a fixed size. The length `addr->sa_len` is taken directly from the `sockaddr` structure provided by the RPC parser (derived from network input). There is no validation to ensure `addr->sa_len` does not exceed the size of `struct sockaddr_storage`, allowing a remote attacker to trigger a heap-based buffer overflow.

