# Scan: replay.c

```json
[
  {
    "severity": "Critical",
    "title": "Heap Buffer Overflow via Unchecked sockaddr_length",
    "function": "replay_alloc",
    "description": "The code copies the caller‑provided socket address into the fixed‑size `sockaddr_storage rce_addr` field using `bcopy(addr, &rce->rce_addr, addr->sa_len)` without validating that `addr->sa_len` is less than or equal to `sizeof(sockaddr_storage)` (typically 128 bytes).  An attacker can supply a sockaddr with a `sa_len` larger than the buffer size, causing an out‑of‑bounds write that corrupts adjacent heap objects (including `rce_msg`, `rce_repmsg`, or the hashed list pointers).  Overwriting these structures can lead to kernel crash, arbitrary code execution, or privilege escalation.  This overflow is not mitigated by any bounds checks or size constraints on the input."
  },
  {
    "severity": "High",
    "title": "Unsigned Size Overflow in Replay Cache Size Accounting",
    "function": "replay_setreply",
    "description": "When a reply body is cached, the code updates the global cache size with `rc->rc_size += m_length(m, NULL);`.  `m_length` returns a `size_t` and `rc_size` is also a `size_t`.  There is no check for overflow or for `m_length` exceeding the remaining quota.  If an attacker continuously sends large reply bodies, the addition can wrap around, turning `rc_size` into a small value.  The prune routine checks `rc->rc_size > rc->rc_maxsize` to trigger eviction, so after overflow it will never think the cache is over‑size.  The cache can grow without bound, potentially exhausting kernel memory and leading to denial of service."
  },
  {
    "severity": "High",
    "title": "Unsigned Size Underflow During Cache Entry Free",
    "function": "replay_free",
    "description": "The function decreases the cached body size with `rc->rc_size -= m_length(rce->rce_repbody, NULL);`.  If the cached reply body length exceeds the current `rc_size` (possible through a race or corruption), the subtraction underflows the unsigned value, producing a huge `rc_size`.  The prune logic will then think the cache is far too large and repeatedly free entries, potentially leading to forced eviction of valid entries or a consistency break in the cache bookkeeping."
  },
  {
    "severity": "Medium",
    "title": "Potential Unchecked NULL Pointer Dereference when Reply Body Copying Fails",
    "function": "replay_setreply",
    "description": "When `m_copym` fails, the code simply discards the original `mbuf *m` and assigns the result (NULL) back to `m`.  The caller’s `m` pointer is not freed, causing a memory leak.  While not immediately exploitable, repeated failures under attack could exhaust memory resources, contributing to a denial‑of‑service condition."
  },
  {
    "severity": "Medium",
    "title": "Race Condition in Cache Pruning",
    "function": "replay_prune",
    "description": "The reverse traversal used to find a freeable entry accesses the `rc_cache` lists while holding the lock, but it does not protect against simultaneous insertions from `replay_alloc` or deletions from `replay_free`.  If the attacker triggers a prune while another thread is inserting or deleting entries, the reverse loop may access freed or stale memory, potentially leading to a race‑condition crash or a subtle corruption that can affect cache integrity."
  }
]
```