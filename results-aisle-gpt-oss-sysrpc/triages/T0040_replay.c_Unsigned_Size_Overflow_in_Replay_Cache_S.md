# Triage T0040: Unsigned Size Overflow in Replay Cache Size Accounting

- **File**: `replay.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI]

---

## Finding

Unsigned Size Overflow in Replay Cache Size Accounting

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** rc_size unsigned overflow cannot be exploitable because rc_count is capped at REPLAY_MAX (1024) which forces pruning and limits memory usage

The code updates a size counter (`rc->rc_size`) by adding the length of a reply body (`m_length(m,NULL)`). Both operands are of type `size_t`. Because no bounds check is performed, a maliciously crafted reply containing a very large `mbuf` chain could cause the addition to wrap around, producing a small value for `rc->rc_size`. The prune routine triggers only when `rc->rc_count >= REPLAY_MAX` or `rc->rc_size > rc->rc_maxsize`. Even if `rc_size` wraps to a small value, the cache will still prune when the count reaches `REPLAY_MAX` (1024). Thus the counter overflow cannot let the cache grow beyond 1024 entries.  Each entry holds an *own* reply body; once an entry is evicted, `rc_size` is decreased by `m_length` for that entry, correcting the counter.  Consequently, the overflow does not enable a denial‑of‑service that would exhaust kernel memory, nor does it give an attacker any other special privilege.  The bug is harmless in terms of security – it is a data‑consistency issue rather than an exploitable vulnerability.

The only potential defense is the `REPLAY_MAX` limit, which is defined as 1024 (grep "#define REPLAY_MAX 1024").  This bound is enforced in `replay_prune`, so the cache cannot grow beyond a fixed number of entries regardless of the overflow.  No other checks or size limits are required.

Because the overflow cannot be used to trigger a security violation, the finding is categorized as INVALID.


CRUX: rc_size unsigned overflow cannot be exploitable because rc_count is capped at REPLAY_MAX (1024) which forces pruning and limits memory usage
GREP: #define REPLAY_MAX 1024

🔎 **Grep results:**

GREP `#define REPLAY_MAX 1024 (simplified to: REPLAY_MAX)`:
```
sys/rpc/replay.c:62:#define REPLAY_MAX		1024
sys/rpc/replay.c:155:	if (rc->rc_count < REPLAY_MAX && rc->rc_size <= rc->rc_maxsize)
sys/rpc/replay.c:169:	} while (rce && (rc->rc_count >= REPLAY_MAX
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** Overflow does not allow exceeding REPLAY_MAX entries

The code updates `rc->rc_size` by adding `m_length(m,NULL)` whenever a reply body is cached. Both operands are `size_t`, so the addition can overflow. However, the cache’s size is bounded by two independent mechanisms:
1. `replay_prune()` always frees entries whenever `rc->rc_count >= REPLAY_MAX`. The constant `REPLAY_MAX` is 1024, checked at the top of the function and in the loop condition, ensuring that `rc->rc_count` can never exceed 1023.
2. Even if an overflow makes `rc->rc_size` wrap to a small value, the loop condition in `replay_prune()` is `rc->rc_count >= REPLAY_MAX || rc->rc_size > rc->rc_maxsize`. As long as the count limit is violated, the loop continues, freeing entries until the count drops below `REPLAY_MAX`. Thus the overflow cannot allow the cache to grow beyond 1023 entries, and the total memory used for replay cache entries is bounded.
Because the attacker cannot exceed the entry count silently, and memory exhaustion or code execution is not possible, the unsigned overflow provides only a bookkeeping inconsistency and is not a security vulnerability.
Crux: overflow cannot bypass the enforced `REPLAY_MAX` entry limit.
Grep evidence: the constant definition of the limit.


CRUX: Overflow does not allow exceeding REPLAY_MAX entries

GREP: #define REPLAY_MAX 1024


🔎 **Grep results:**

GREP `#define REPLAY_MAX 1024 (simplified to: REPLAY_MAX)`:
```
sys/rpc/replay.c:62:#define REPLAY_MAX		1024
sys/rpc/replay.c:155:	if (rc->rc_count < REPLAY_MAX && rc->rc_size <= rc->rc_maxsize)
sys/rpc/replay.c:169:	} while (rce && (rc->rc_count >= REPLAY_MAX
```

GREP `evidence:`:
```
(no matches in repo)
```

