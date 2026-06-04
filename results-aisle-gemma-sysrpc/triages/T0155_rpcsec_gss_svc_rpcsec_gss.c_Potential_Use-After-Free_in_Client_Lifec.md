# Triage T0155: Potential Use-After-Free in Client Lifecycle

- **File**: `rpcsec_gss/svc_rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Potential Use-After-Free in Client Lifecycle

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The client uses a reference counting mechanism (`cl_refs`) that prevents the object from being freed as long as any thread (request handler) holds a reference, regardless of whether it has been removed from the global lookup lists.

The report suggests a Use-After-Free (UAF) occurs when a client is removed from the global list but its reference count is released outside the lock. Let's examine `svc_rpc_gss_forget_client` and `svc_rpc_gss_timeout_clients`. In `svc_rpc_gss_forget_client`, the code locks `svc_rpc_gss_lock`, removes the client from the hash and LRU lists via `svc_rpc_gss_forget_client_locked`, unlocks, and then calls `svc_rpc_gss_release_client`. 

Crucially, the `svc_rpc_gss_client` structure is managed by a reference count (`cl_refs`). In `svc_rpc_gss()`, when a client is found via `svc_rpc_gss_find_client`, the reference count is incremented while holding the lock. If the client is being used for a request (`RPCSEC_GSS_DATA`), an additional reference is acquired (`refcount_acquire(&client->cl_refs)`) and held until `svc_rpc_gss_release` is called at the end of the RPC request lifecycle. 

The 'gap' described by the scanner exists (removing from list then releasing ref), but it is not a vulnerability because the reference count ensures the memory is not freed while any thread is still using the client. The global list is merely a way to *find* the client; once a thread has a pointer and has incremented the reference count, the client's existence in the global list is irrelevant to its memory safety. The only way for `svc_rpc_gss_destroy_client` to be called is if `refcount_release` returns true, meaning all references (including the one held by the global list and any active request threads) have been dropped.

CRUX: The client uses a reference counting mechanism (`cl_refs`) that prevents the object from being freed as long as any thread (request handler) holds a reference, regardless of whether it has been removed from the global lookup lists.
GREP: refcount_acquire

🔎 **Grep results:**

GREP `refcount_acquire`:
```
sys/dev/tcp_log/tcp_log_dev.c:73:#define	TCP_LOG_DEV_QUEUE_REF(tldq)	refcount_acquire(&((tldq)->tldq_refcnt))
sys/sys/socketvar.h:388:#define	soref(so)	refcount_acquire(&(so)->so_count)
sys/netipsec/key.c:801:#define	IPSEC_ADDREF(t, p)	refcount_acquire(&(p)->refcnt)
sys/netinet/tcp_log_buf.c:277:#define	TCPID_BUCKET_REF(tlb)		refcount_acquire(&((tlb)->tlb_refcnt))
sys/netgraph/netgraph.h:155:#define	_NG_HOOK_REF(hook)	refcount_acquire(&(hook)->hk_refs)
sys/netgraph/netgraph.h:417:#define	_NG_NODE_REF(node)	refcount_acquire(&(node)->nd_refs)
sys/net/if_geneve.c:154:#define GENEVE_SO_ACQUIRE(_gnvso)		refcount_acquire(&(_gnvso)->gnvso_refcnt)
sys/net/if_geneve.c:259:#define GENEVE_ACQUIRE(_sc)	refcount_acquire(&(_sc)->gnv_refcnt)
sys/net/if_vxlan.c:128:#define VXLAN_SO_ACQUIRE(_vso)		refcount_acquire(&(_vso)->vxlso_refcnt)
sys/net/if_vxlan.c:229:#define VXLAN_ACQUIRE(_sc)	refcount_acquire(&(_sc)->vxl_refcnt)
sys/fs/fuse/fuse_ipc.h:325:	refcount_acquire(&ftick->tk_refcount);
sys/fs/fuse/fuse_ipc.h:335:	refcount_acquire(&ftick->tk_refcount);
sys/fs/fuse/fuse_ipc.h:363:	refcount_acquire(&ftick->tk_refcount);
sys/dev/nvmf/controller/nvmft_var.h:170:	refcount_acquire(&np->refs);
sys/dev/drm2/drmP.h:1448:	refcount_acquire(&obj->refcount);
sys/dev/drm2/ttm/ttm_bo_api.h:310:	refcount_acquire(&bo->kref);
sys/rpc/clnt.h:173:	refcount_acquire(&(rh)->cl_refs)
sys/rpc/svc.h:353:	refcount_acquire(&(xprt)->xp_refs)
sys/sys/refcount.h:73:refcount_acquire(volatile u_int *count)
sys/sys/refcount.h:85:refcount_acquiren(volatile u_int *count, u_int n)
sys/sys/refcount.h:90:	    ("refcount_acquiren: n=%u too large", n));
sys/sys/refcount.h:99:refcount_acquire_checked(volatile u_int *count)
sys/sys/refcount.h:118:refcount_acquire_if_gt(volatile u_int *count, u_int n)
sys/sys/refcount.h:134:refcount_acquire_if_not_zero(volatile u_int *count)
sys/sys/refcount.h:137:	return (refcount_acquire_if_gt(count, 0));
sys/sys/ktls.h:276:		refcount_acquire(&tls->refcount);
sys/sys/sglist.h:82:	refcount_acquire(&sg->sg_refs);
sys/sys/mbuf.h:1507:	refcount_acquire(&mst->refcount);
sys/sys/file.h:322:	return (refcount_acquire_checked(&fp->f_count));
sys/compat/linuxkpi/common/include/linux/fs.h:279:	refcount_acquire(f->_file == NULL ? &f->f_count : &f->_file->f_count);
```

### Round 2: ❌ INVALID

**🎯 Crux:** The client object uses reference counting (`cl_refs`) that ensures it is only freed when all active references (including those from request handlers and the global list) are dropped, making the order of list removal and ref-release safe.

The scanner identifies a race condition in the client lifecycle where a client is removed from global lists before its reference count is released. However, the code implements a robust reference counting mechanism (`cl_refs`) using `refcount_acquire` and `refcount_release`. 

1. When a client is looked up in `svc_rpc_gss_find_client`, the reference count is incremented while holding `svc_rpc_gss_lock`. This ensures that the object cannot be freed while the lookup thread holds a pointer.
2. For data requests (`RPCSEC_GSS_DATA`), an additional reference is acquired via `refcount_acquire(&client->cl_refs)` before setting the `svc_ah_ops` to `svc_auth_gss_ops`. This reference is only released in `svc_rpc_gss_release` at the end of the RPC request's processing lifecycle.
3. The functions `svc_rpc_gss_forget_client` and `svc_rpc_gss_timeout_clients` remove the client from the global lists (stopping new lookups) and then call `svc_rpc_gss_release_client`. 
4. `svc_rpc_gss_release_client` calls `refcount_release`. The memory is only freed in `svc_rpc_gss_destroy_client` if the reference count reaches zero.

Because every thread that accesses the `svc_rpc_gss_client` structure holds a reference, the fact that the object is no longer reachable via the global lists is irrelevant to its memory safety. No UAF is possible as long as the reference counting is correct, and the trace shows the count is consistently managed for all access paths.

CRUX: The client object uses reference counting (`cl_refs`) that ensures it is only freed when all active references (including those from request handlers and the global list) are dropped, making the order of list removal and ref-release safe.
GREP: refcount_release

🔎 **Grep results:**

GREP `refcount_release`:
```
sys/netipsec/key.c:802:#define	IPSEC_DELREF(t, p)	refcount_release(&(p)->refcnt)
sys/dev/tcp_log/tcp_log_dev.c:74:#define	TCP_LOG_DEV_QUEUE_UNREF(tldq)	refcount_release(&((tldq)->tldq_refcnt))
sys/sys/refcount.h:174:#define	_refcount_release_if_cond(cond, name)				\
sys/netinet/tcp_log_buf.c:278:#define	TCPID_BUCKET_UNREF(tlb)		refcount_release(&((tlb)->tlb_refcnt))
sys/net/if_geneve.c:155:#define GENEVE_SO_RELEASE(_gnvso)		refcount_release(&(_gnvso)->gnvso_refcnt)
sys/net/if_geneve.c:260:#define GENEVE_RELEASE(_sc)	refcount_release(&(_sc)->gnv_refcnt)
sys/net/if_vxlan.c:129:#define VXLAN_SO_RELEASE(_vso)		refcount_release(&(_vso)->vxlso_refcnt)
sys/net/if_vxlan.c:230:#define VXLAN_RELEASE(_sc)	refcount_release(&(_sc)->vxl_refcnt)
sys/dev/nvmf/controller/nvmft_var.h:176:	if (refcount_release(&np->refs))
sys/dev/drm2/drmP.h:1457:	if (refcount_release(&obj->refcount))
sys/dev/drm2/ttm/ttm_object.h:103: * @refcount_release: A function to be called when there are
sys/dev/drm2/ttm/ttm_object.h:127:	void (*refcount_release) (struct ttm_base_object **base);
sys/dev/drm2/ttm/ttm_object.h:140: * @refcount_release: See the struct ttm_base_object description.
sys/dev/drm2/ttm/ttm_object.h:150:				void (*refcount_release) (struct ttm_base_object
sys/rpc/clnt.h:175:	if (refcount_release(&(rh)->cl_refs))	\
sys/rpc/svc.h:356:	if (refcount_release(&(xprt)->xp_refs))	\
sys/sys/socketvar.h:391:	if (!refcount_release_if_not_last(&(so)->so_count)) {		\
sys/sys/refcount.h:141:refcount_releasen(volatile u_int *count, u_int n)
sys/sys/refcount.h:146:	    ("refcount_releasen: n=%u too large", n));
sys/sys/refcount.h:168:refcount_release(volatile u_int *count)
sys/sys/refcount.h:171:	return (refcount_releasen(count, 1));
sys/sys/refcount.h:176:_refcount_release_if_##name(volatile u_int *count, u_int n)		\
sys/sys/refcount.h:191:_refcount_release_if_cond(old > n, gt)
sys/sys/refcount.h:192:_refcount_release_if_cond(old == n, eq)
sys/sys/refcount.h:195:refcount_release_if_gt(volatile u_int *count, u_int n)
sys/sys/refcount.h:198:	return (_refcount_release_if_gt(count, n));
sys/sys/refcount.h:202:refcount_release_if_last(volatile u_int *count)
sys/sys/refcount.h:205:	if (_refcount_release_if_eq(count, 1)) {
sys/sys/refcount.h:206:		/* See the comment in refcount_releasen(). */
sys/sys/refcount.h:214:refcount_release_if_not_last(volatile u_int *count)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The `cl_refs` reference counter ensures the `svc_rpc_gss_client` is not destroyed as long as any thread (either the global list or an active request handler) holds a reference, regardless of its presence in the lookup lists.

The reported vulnerability suggests a Use-After-Free (UAF) due to the gap between removing a client from global lists and releasing its reference count. However, the code uses a robust reference counting mechanism (`cl_refs`). 

1. **Lifecycle Acquisition**: When a client is found in `svc_rpc_gss_find_client`, the reference count is incremented (`refcount_acquire`) while the global lock `svc_rpc_gss_lock` is held. This ensures the object cannot be freed before the caller receives the pointer.
2. **Request Duration**: For `RPCSEC_GSS_DATA` requests, an additional reference is acquired (`refcount_acquire(&client->cl_refs)`) before the request is dispatched. This reference is only released in `svc_rpc_gss_release` after the RPC request processing is complete.
3. **Removal Logic**: In `svc_rpc_gss_forget_client` and `svc_rpc_gss_timeout_clients`, the client is first removed from the hash and LRU lists under the global lock. This prevents *new* lookups from finding the client. After unlocking, `svc_rpc_gss_release_client` is called, which decrements the reference count.
4. **Safety**: Memory is only freed in `svc_rpc_gss_destroy_client` if `refcount_release` returns true (indicating the count reached zero). If a request handler is still processing a request using that client, the reference count will be at least 1, preventing the UAF.

The gap between list removal and reference release is a standard pattern for safely removing objects from global registries while they are still in use by active threads.

CRUX: The `cl_refs` reference counter ensures the `svc_rpc_gss_client` is not destroyed as long as any thread (either the global list or an active request handler) holds a reference, regardless of its presence in the lookup lists.
GREP: refcount_acquire

🔎 **Grep results:**

GREP `refcount_acquire`:
```
sys/dev/tcp_log/tcp_log_dev.c:73:#define	TCP_LOG_DEV_QUEUE_REF(tldq)	refcount_acquire(&((tldq)->tldq_refcnt))
sys/netipsec/key.c:801:#define	IPSEC_ADDREF(t, p)	refcount_acquire(&(p)->refcnt)
sys/sys/socketvar.h:388:#define	soref(so)	refcount_acquire(&(so)->so_count)
sys/netinet/tcp_log_buf.c:277:#define	TCPID_BUCKET_REF(tlb)		refcount_acquire(&((tlb)->tlb_refcnt))
sys/netgraph/netgraph.h:155:#define	_NG_HOOK_REF(hook)	refcount_acquire(&(hook)->hk_refs)
sys/netgraph/netgraph.h:417:#define	_NG_NODE_REF(node)	refcount_acquire(&(node)->nd_refs)
sys/net/if_geneve.c:154:#define GENEVE_SO_ACQUIRE(_gnvso)		refcount_acquire(&(_gnvso)->gnvso_refcnt)
sys/net/if_geneve.c:259:#define GENEVE_ACQUIRE(_sc)	refcount_acquire(&(_sc)->gnv_refcnt)
sys/net/if_vxlan.c:128:#define VXLAN_SO_ACQUIRE(_vso)		refcount_acquire(&(_vso)->vxlso_refcnt)
sys/net/if_vxlan.c:229:#define VXLAN_ACQUIRE(_sc)	refcount_acquire(&(_sc)->vxl_refcnt)
sys/fs/fuse/fuse_ipc.h:325:	refcount_acquire(&ftick->tk_refcount);
sys/fs/fuse/fuse_ipc.h:335:	refcount_acquire(&ftick->tk_refcount);
sys/fs/fuse/fuse_ipc.h:363:	refcount_acquire(&ftick->tk_refcount);
sys/rpc/clnt.h:173:	refcount_acquire(&(rh)->cl_refs)
sys/rpc/svc.h:353:	refcount_acquire(&(xprt)->xp_refs)
sys/dev/nvmf/controller/nvmft_var.h:170:	refcount_acquire(&np->refs);
sys/dev/drm2/drmP.h:1448:	refcount_acquire(&obj->refcount);
sys/dev/drm2/ttm/ttm_bo_api.h:310:	refcount_acquire(&bo->kref);
sys/sys/refcount.h:73:refcount_acquire(volatile u_int *count)
sys/sys/refcount.h:85:refcount_acquiren(volatile u_int *count, u_int n)
sys/sys/refcount.h:90:	    ("refcount_acquiren: n=%u too large", n));
sys/sys/refcount.h:99:refcount_acquire_checked(volatile u_int *count)
sys/sys/refcount.h:118:refcount_acquire_if_gt(volatile u_int *count, u_int n)
sys/sys/refcount.h:134:refcount_acquire_if_not_zero(volatile u_int *count)
sys/sys/refcount.h:137:	return (refcount_acquire_if_gt(count, 0));
sys/sys/ktls.h:276:		refcount_acquire(&tls->refcount);
sys/sys/sglist.h:82:	refcount_acquire(&sg->sg_refs);
sys/sys/mbuf.h:1507:	refcount_acquire(&mst->refcount);
sys/sys/file.h:322:	return (refcount_acquire_checked(&fp->f_count));
sys/net/pfvar.h:2766:	refcount_acquire(&s->refs);
```

### Round 4: ❌ INVALID

[ARBITER] The code implements a standard and robust reference counting mechanism (`cl_refs`) to manage the lifecycle of `svc_rpc_gss_client` objects. When a client is retrieved via `svc_rpc_gss_find_client`, its reference count is incremented while holding the `svc_rpc_gss_lock`. The removal of a client from global lists in `svc_rpc_gss_forget_client_locked` merely removes the list's reference; the actual memory is only freed in `svc_rpc_gss_destroy_client` when the reference count reaches zero via `svc_rpc_gss_release_client`. Any thread holding a pointer to the client (e.g., a request handler) has already incremented the reference count, ensuring the object remains valid regardless of its presence in the global lists. There is no gap that allows a Use-After-Free.

