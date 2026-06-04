# Context: replay.c

**Replay Cache Context Briefing – replay.c**  

1. **What it does / Where it lives**  
   `replay.c` implements the RPC replay‑cache used in FreeBSD’s RPC subsystem to detect duplicate outbound requests and to return cached replies. It lives in the kernel’s `rpc` module and is invoked from the generic RPC dispatcher (network → `rpc_dispatch`, which then calls the `replay_*` helpers).  

2. **Untrusted input path**  
   The cache is populated from the network: a client’s `struct rpc_msg` (`msg`), the client address (`addr`) from the receiving socket, and optionally the reply‐body `mbuf *m` from a later inbound reply.  All come from the attacker.  

3. **Attacker‑controlled variables and data flow**  
   * `msg->rm_xid`, `msg->rm_call.cb_prog`, `.cb_vers`, `.cb_proc` – used as the cache key.  
   * `addr` (including `addr->sa_addr`, `sa_len`) – stored in `rce->rce_addr`.  
   * `repmsg` (reply headers) – copied into `rce->rce_repmsg`.  
   * `m` – reply body, copied into `rce->rce_repbody`.  
   The flow: network → `replay_find`/`replay_setreply` → `replay_alloc` copies `msg`/`addr` into a new `replay_cache_entry`, then later `replay_setreply` fills the reply fields.  

4. **Fixed‑size buffers & size constants**  
   * `struct replay_cache_entry rce;` – all fields fixed size except the pointer.  
   * `struct replay_cache rc;` – contains an array `rc_cache[REPLAY_HASH_SIZE]`.  
   * `REPLAY_HASH_SIZE = 256` (GREP: `#define REPLAY_HASH_SIZE 256`)  
   * `REPLAY_MAX = 1024` (GREP: `#define REPLAY_MAX 1024`)  
   * `struct sockaddr_storage rce_addr;` – size `sizeof(sockaddr_storage)` (generally 128).  
   * No character buffers inside `rce`.  

5. **Dangerous data flows**  
   * **Source → Dest**: `addr->sa_len` → `bcopy(addr, &rce->rce_addr, addr->sa_len)` (buffer: `rce_addr`, size `sizeof(sockaddr_storage)` – 128). The caller may set a `sa_len` larger than 128, causing an overflow.  

6. **NULL parameters that are dereferenced**  
   * `rce->rce_repbody` is NULL‑checked before use.  
   * `m_copym` may return NULL; `replay_setreply` checks `if (m)`.  

7. **Tagged unions / type tags**  
   * `struct rpc_msg` contains a union for call/reply but the helper simply checks `rce_repmsg.rm_xid`; no type‑tag validation beyond the XID.  

8. **API vs static helpers**  
   * Public API: `replay_newcache`, `replay_setsize`, `replay_freecache`, `replay_find`, `replay_setreply`.  
   * Static helpers: `replay_alloc`, `replay_free`, `replay_prune`; all are called only while holding `rc_lock`.  

9. **Likely bug classes**  
   * **Buffer overrun** via `sa_len` in `bcopy`.  
   * **Race condition** in `replay_prune` (reverse traversal with possible concurrent modifications).  
   * Potential **memory leak** if `rc_size` is mis‑synchronised when entries are freed.  

*(All numeric values resolved via grep: `REPLAY_HASH_SIZE=256`, `REPLAY_MAX=1024`.)*

[GREP RESULTS from codebase]:
GREP `#define REPLAY_HASH_SIZE 256`) (simplified to: REPLAY_HASH_SIZE)`:
```
sys/rpc/replay.c:61:#define REPLAY_HASH_SIZE	256
sys/rpc/replay.c:65:	struct replay_cache_list	rc_cache[REPLAY_HASH_SIZE];
sys/rpc/replay.c:80:	for (i = 0; i < REPLAY_HASH_SIZE; i++)
sys/rpc/replay.c:177:	int h = HASHSTEP(HASHINIT, msg->rm_xid) % REPLAY_HASH_SIZE;
sys/rpc/replay.c:231:	int h = HASHSTEP(HASHINIT, repmsg->rm_xid) % REPLAY_HASH_SIZE;
```

GREP `#define REPLAY_MAX 1024`) (simplified to: REPLAY_MAX)`:
```
sys/rpc/replay.c:62:#define REPLAY_MAX		1024
sys/rpc/replay.c:155:	if (rc->rc_count < REPLAY_MAX && rc->rc_size <= rc->rc_maxsize)
sys/rpc/replay.c:169:	} while (rce && (rc->rc_count >= REPLAY_MAX
```

GREP `REPLAY_HASH_SIZE`:
```
sys/rpc/replay.c:61:#define REPLAY_HASH_SIZE	256
sys/rpc/replay.c:65:	struct replay_cache_list	rc_cache[REPLAY_HASH_SIZE];
sys/rpc/replay.c:80:	for (i = 0; i < REPLAY_HASH_SIZE; i++)
sys/rpc/replay.c:177:	int h = HASHSTEP(HASHINIT, msg->rm_xid) % REPLAY_HASH_SIZE;
sys/rpc/replay.c:231:	int h = HASHSTEP(HASHINIT, repmsg->rm_xid) % REPLAY_HASH_SIZE;
```