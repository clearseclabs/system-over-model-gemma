# Context: replay.c

### Security Context Briefing: `replay.c`

**1. Function & Project Location**
`replay.c` implements an RPC replay cache. It stores previous RPC requests and their corresponding responses to avoid re-processing identical requests and to quickly return cached replies. It sits in the RPC layer of the kernel.

**2. Untrusted Input Entry**
Untrusted input reaches this code via the network. External RPC requests are parsed into `struct rpc_msg` and `struct sockaddr` before being passed to the replay cache functions.

**3. Attacker-Controlled Data Flow**
*   **`msg` (`struct rpc_msg*`)**: Contains `rm_xid` (Transaction ID) and `rm_call` (program, version, procedure).
*   **`addr` (`struct sockaddr*`)**: Contains the source address and `sa_len`.
*   **Flow**: Network $\rightarrow$ RPC Parser $\rightarrow$ `replay_find()` / `replay_setreply()`. Data is used for hash calculation, cache lookup (`bcmp`), and storage in `struct replay_cache_entry`.

**4. Fixed-Size Buffers & Constants**
*   `REPLAY_HASH_SIZE`: 256 (Size of `rc_cache` array).
*   `REPLAY_MAX`: 1024 (Maximum number of entries before `replay_prune` triggers).
*   `rce_addr` (`struct sockaddr_storage`): Typically 128 bytes (platform dependent).

**5. Dangerous Data Flows**
*   **`addr` $\rightarrow$ `rce_addr`**: In `replay_alloc`, `bcopy(addr, &rce->rce_addr, addr->sa_len)` copies attacker-controlled length `sa_len` into a fixed-size `sockaddr_storage`.

**6. Potential NULL Dereferences**
*   `replay_find`: `msg` and `addr` are dereferenced without NULL checks.
*   `replay_setreply`: `repmsg` and `addr` are dereferenced without NULL checks.

**7. Tagged Unions/Variants**
No tagged unions are explicitly used in this file.

**8. API Visibility**
*   **Public API**: `replay_newcache`, `replay_setsize`, `replay_freecache`, `replay_find`, `replay_setreply`.
*   **Static Helpers**: `replay_alloc`, `replay_free`, `replay_prune`. These are called within the lock scope of the public APIs.

**9. Likely Bug Classes**
*   **Buffer Overflow**: Potential overflow in `bcopy` if `addr->sa_len` exceeds `sizeof(struct sockaddr_storage)`.
*   **DoS**: Memory exhaustion if `rc_maxsize` is set too high or if `m_length` reports inaccurate sizes.
*   **Race Conditions**: Potential issues if locking is bypassed in callers.