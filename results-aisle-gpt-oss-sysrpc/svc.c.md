# Scan: svc.c

```json
[
  {
    "severity": "high",
    "title": "Integer overflow in space‑usage accounting",
    "function": "svc_change_space_used",
    "description": "The function updates pool->sp_space_used using an unsigned long arithmetic expression:\n    value = atomic_fetchadd_long(&pool->sp_space_used, delta) + delta;\nIf an attacker can force `delta` to be a large value (e.g. by crafting a request with an excessively large payload so that `rq_size` overflows into a negative long), the addition will wrap around the unsigned long.  This can cause `sp_space_used` to become small or even zero, temporarily disabling the throttling logic in `svc_request_space_available`.  Consequently the server can be flooded with requests, exhausting system resources without ever triggering the normal throttling controls.  The vulnerability is exploitable via the network interface of any RPC service that uses this pool and can lead to a denial‑of‑service or a potential resource exhaustion that may trigger further code execution paths while the pool is busy."
  },
  {
    "severity": "medium",
    "title": "Uninitialised memory in newly allocated transport objects",
    "function": "svc_xprt_alloc",
    "description": "The function allocates a new `SVCXPRT` and its extension but does not zero the allocated blocks.  The struct members such as `xp_flags`, `xp_netid`, `xp_p3`, `xp_socket`, etc. may contain garbage values.  Subsequent code paths (e.g. `SVC_DEBUG`, `SVC_EXT(xp)->xp_flags`, `SVC_AUTH_*` macros) read these fields without checking validity, potentially leading to undefined behaviour, crashes, or information disclosure through log contents.  Attackers could inject crafted RPC packets that interact with these uninitialised fields and trigger code that behaves unpredictably or leaks internal state."
  },
  {
    "severity": "medium",
    "title": "Incorrect pointer cleanup in failed request registration",
    "function": "svc_reg / svc_unreg",
    "description": "When a service registration fails after allocating the `struct svc_callout`, the code frees `netid` if it was allocated. However, the `svc_callout` structure itself is not always freed in every failure path: in `svc_reg`, if `malloc` for the callout fails after copying `netid`, the caller returns without freeing `netid`.  Similarly, when a duplicate dispatch is found (`s->sc_dispatch == dispatch`) the function returns `TRUE` without freeing the new allocation.  These logic gaps can lead to subtle memory leaks or stale pointers that may later be dereferenced by the service dispatcher, potentially causing crashes or data corruption if the freed memory is reused for another allocation."
  }
]
```