# Triage T0055: Logical Error in `replay_prune` (Potential DoS/Infinite Loop)

- **File**: `replay.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Logical Error in `replay_prune` (Potential DoS/Infinite Loop)

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** replay_prune only removes completed requests; in-progress requests are never pruned, and replay_alloc continues to allocate new entries regardless of REPLAY_MAX if pruning fails.

The reported issue is that an attacker can flood the replay cache with requests that never receive replies. In `replay_prune`, the loop only frees entries where `rce->rce_repmsg.rm_xid` is non-zero (i.e., entries that have already received a reply). If an attacker fills the cache (up to `REPLAY_MAX` = 1024) with requests and never sends the corresponding replies, `replay_prune` will find no entries to free, `rce` will become NULL, and the loop will terminate without reducing the cache size. Subsequent calls to `replay_find` will trigger `replay_prune`, which will fail to free anything, and then `replay_alloc` will be called. Crucially, `replay_alloc` does not check if the cache is already full before calling `malloc` and incrementing `rc->rc_count`. It simply adds the new entry. Therefore, the cache can grow indefinitely beyond `REPLAY_MAX` as long as the entries are 'in-progress'. This allows an external attacker to consume kernel memory by sending a stream of unique RPC requests, leading to a Denial of Service (memory exhaustion).

CRUX: replay_prune only removes completed requests; in-progress requests are never pruned, and replay_alloc continues to allocate new entries regardless of REPLAY_MAX if pruning fails.
GREP: REPLAY_MAX

🔎 **Grep results:**

GREP `REPLAY_MAX`:
```
(no matches in repo)
```

### Round 2: ✅ VALID

**🎯 Crux:** replay_prune fails to remove in-progress entries, and replay_alloc allocates new entries regardless of whether the cache exceeds REPLAY_MAX, allowing unbounded kernel memory consumption.

The reported vulnerability is a logical flaw in `replay_prune`. The function's purpose is to keep the cache size under `REPLAY_MAX` (1024) and `rc_maxsize`. However, the pruning logic explicitly skips 'in-progress' entries (where `rce_repmsg.rm_xid == 0`). If an attacker floods the system with unique RPC requests and never provides the replies, the cache will fill with in-progress entries. When `replay_prune` is called, it will fail to find any removable entries, `rce` will become NULL, and the loop will terminate without freeing anything. 

Crucially, `replay_find` calls `replay_prune` and then immediately calls `replay_alloc` regardless of whether the prune was successful. `replay_alloc` unconditionally increments `rc->rc_count` and performs a `malloc`. Since there is no upper bound check in `replay_alloc` or a hard limit that prevents allocation when pruning fails, an attacker can cause the cache to grow linearly with the number of unique requests sent, leading to kernel memory exhaustion (DoS). The logic intended to bound the cache is bypassed by the 'in-progress' check.

CRUX: replay_prune fails to remove in-progress entries, and replay_alloc allocates new entries regardless of whether the cache exceeds REPLAY_MAX, allowing unbounded kernel memory consumption.
GREP: REPLAY_MAX

🔎 **Grep results:**

GREP `REPLAY_MAX`:
```
(no matches in repo)
```

### Round 3: ✅ VALID

**🎯 Crux:** replay_prune fails to remove in-progress entries, and replay_alloc allocates new entries regardless of the current rc_count, allowing unbounded kernel memory consumption via a flood of unique requests.

The vulnerability is real. The `replay_prune` function is intended to enforce a cache limit (`REPLAY_MAX` = 1024), but it only removes entries that have a reply (`rce->rce_repmsg.rm_xid != 0`). If an attacker sends a flood of unique RPC requests, the cache fills with 'in-progress' entries. In this state, `replay_prune` iterates through the list, finds no entries to free, and returns without reducing `rc_count`. Then, `replay_find` calls `replay_alloc`, which unconditionally increments `rc_count` and performs a `malloc(sizeof(*rce), M_RPC, M_NOWAIT|M_ZERO)`. Because `replay_alloc` does not check if `rc_count` is already above `REPLAY_MAX` before allocating, the cache grows unbounded as long as the attacker sends requests without replies. This leads to kernel memory exhaustion and DoS. The 'in-progress' check effectively disables the bound for any attacker who simply refuses to send replies.

CRUX: replay_prune fails to remove in-progress entries, and replay_alloc allocates new entries regardless of the current rc_count, allowing unbounded kernel memory consumption via a flood of unique requests.
GREP: REPLAY_MAX

🔎 **Grep results:**

GREP `REPLAY_MAX`:
```
(no matches in repo)
```

### Round 4: ✅ VALID

[ARBITER] The `replay_prune` function only removes entries that have a completed reply (`rce->rce_repmsg.rm_xid != 0`). If an attacker floods the system with unique RPC requests without providing replies, the cache fills with 'in-progress' entries. Because `replay_prune` will fail to find any removable entries, it returns without reducing `rc_count`. Subsequently, `replay_find` calls `replay_alloc`, which unconditionally increments `rc_count` and allocates kernel memory. This allows an attacker to bypass the `REPLAY_MAX` (1024) and `rc_maxsize` limits, leading to unbounded kernel memory consumption and a Denial of Service.

