# Triage T0141: ummary of Findings

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

ummary of Findings

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The alleged 'invalid free' is actually a correct call to an XDR free routine designed to free a member of the provided struct, and the cache 'UAF' is prevented by a refcount.

I analyzed the three reported findings. 

1. **Heap Overflow in `rpc_gss_validate`**: The code does `gd->gd_verf.value = mem_alloc(verf->oa_length);` followed by `memcpy(gd->gd_verf.value, verf->oa_base, verf->oa_length);`. While `verf->oa_length` comes from the network, `mem_alloc` will fail and return NULL if the length is excessively large, which is explicitly handled by the subsequent `if (gd->gd_verf.value == NULL)` check. This prevents a heap overflow. Memory exhaustion is a possibility, but in kernel contexts, an allocator failure leading to a rejected request (as seen here) is generally not considered a critical vulnerability unless it causes a panic, which it doesn't here.

2. **Invalid Free in `rpc_gss_init`**: The report claims `xdr_free` is called on `&recv_token` (the address of a stack variable). Looking at the code: `xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_token);`. `recv_token` is a `gss_buffer_desc` struct. In XDR, the `xdr_free` function for a buffer description typically frees the *member* (the actual buffer `value`) inside the struct, not the struct itself. The pointer passed to `xdr_free` is the pointer to the object to be processed by the XDR routine. Since `xdr_gss_buffer_desc` is designed to handle `gss_buffer_desc` objects, it will correctly free `recv_token.value`. This is standard XDR pattern and not a bug.

3. **Race Condition in `rpc_gss_secfind`**: The code removes an entry from the cache and calls `AUTH_DESTROY(tgd->gd_auth)`. However, `gd->gd_refs` is a refcount. `AUTH_DESTROY` calls `rpc_gss_destroy`, which first performs `if (!refcount_release(&gd->gd_refs)) return;`. The entry is only actually freed when the last reference is released. Since other threads that found the object in the cache call `refcount_acquire(&gd->gd_refs)`, the memory remains valid until all threads are done. The lock `rpc_gss_lock` protects the list manipulation. This is a standard refcounted cache implementation.

CRUX: The alleged 'invalid free' is actually a correct call to an XDR free routine designed to free a member of the provided struct, and the cache 'UAF' is prevented by a refcount.
GREP: xdr_gss_buffer_desc

🔎 **Grep results:**

GREP `xdr_gss_buffer_desc`:
```
lib/librpcsec_gss/rpcsec_gss_int.h:77:bool_t  xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p);
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:57:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p)
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:85:	    xdr_gss_buffer_desc(xdrs, &p->gc_handle));
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:96:	return (xdr_gss_buffer_desc(xdrs, &p->gr_handle) &&
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:100:	    xdr_gss_buffer_desc(xdrs, &p->gr_token));
sys/rpc/rpcsec_gss/rpcsec_gss.c:644:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:910:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:933:			    (xdrproc_t)xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:958:				xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1021:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1132:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1165:		xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:955:		(xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1019:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1059:	xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_tok);
sys/kgssapi/gssd_prot.c:44:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *buf)
sys/kgssapi/gssd_prot.c:201:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:204:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:206:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:225:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:228:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:230:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:242:			xdr_gss_buffer_desc(xdrs, &ch->initiator_address);
sys/kgssapi/gssd_prot.c:243:			xdr_gss_buffer_desc(xdrs, &ch->acceptor_address);
sys/kgssapi/gssd_prot.c:244:			xdr_gss_buffer_desc(xdrs, &ch->application_data);
lib/librpcsec_gss/rpcsec_gss_prot.c:51:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p)
lib/librpcsec_gss/rpcsec_gss_prot.c:78:	    xdr_gss_buffer_desc(xdrs, &p->gc_handle));
lib/librpcsec_gss/rpcsec_gss_prot.c:89:	return (xdr_gss_buffer_desc(xdrs, &p->gr_handle) &&
lib/librpcsec_gss/rpcsec_gss_prot.c:93:	    xdr_gss_buffer_desc(xdrs, &p->gr_token));
lib/librpcsec_gss/rpcsec_gss_prot.c:139:		xdr_stat = xdr_gss_buffer_desc(xdrs, &wrapbuf);
```

### Round 2: ❌ INVALID

**🎯 Crux:** The alleged 'invalid free' is the correct XDR pattern for freeing struct members, and the UAF is prevented by refcounting.

I have evaluated the three reported findings:

1. **Heap Overflow in `rpc_gss_validate`**: The report claims that `verf->oa_length` is used unchecked for memory allocation. In the code, `gd->gd_verf.value = mem_alloc(verf->oa_length);` is followed immediately by `if (gd->gd_verf.value == NULL)`. This is the standard way to handle allocation failure in the kernel. An attacker cannot trigger a heap overflow because the code only performs the `memcpy` if the allocation succeeds. Memory exhaustion (DoS) is possible, but in this context, it results in a failed request and an error return, not a system-wide crash or exploit.

2. **Invalid Free in `rpc_gss_init`**: The scanner flagged `xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_token);` as freeing a stack address. However, this is the correct usage of the XDR framework. In XDR, the `xdr_free` function is passed a pointer to the *object* that needs cleaning up. For a `gss_buffer_desc`, the actual heap-allocated data is stored in the `.value` member of the struct. The `xdr_gss_buffer_desc` routine is specifically implemented to access that member and free it. Passing the address of the struct on the stack is required so the routine can access the pointer inside it.

3. **Race Condition in `rpc_gss_secfind`**: The report claims a UAF when entries are evicted from the cache. The implementation uses a reference counting mechanism (`gd->gd_refs`). When a thread finds an entry in the cache, it calls `refcount_acquire`. When an entry is evicted, `AUTH_DESTROY` is called, which in turn calls `rpc_gss_destroy`. Inside `rpc_gss_destroy`, the code checks `if (!refcount_release(&gd->gd_refs)) return;`. This means the memory is not actually freed until the last thread holding a reference releases it. The list operations are protected by `rpc_gss_lock` (an `sx` lock). This is a correct refcounted cache pattern.

All three findings are false positives based on a misunderstanding of the XDR framework, kernel memory allocation patterns, and reference counting.

CRUX: The alleged 'invalid free' is the correct XDR pattern for freeing struct members, and the UAF is prevented by refcounting.
GREP: xdr_gss_buffer_desc

🔎 **Grep results:**

GREP `xdr_gss_buffer_desc`:
```
lib/librpcsec_gss/rpcsec_gss_int.h:77:bool_t  xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p);
lib/librpcsec_gss/rpcsec_gss_prot.c:51:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p)
lib/librpcsec_gss/rpcsec_gss_prot.c:78:	    xdr_gss_buffer_desc(xdrs, &p->gc_handle));
lib/librpcsec_gss/rpcsec_gss_prot.c:89:	return (xdr_gss_buffer_desc(xdrs, &p->gr_handle) &&
lib/librpcsec_gss/rpcsec_gss_prot.c:93:	    xdr_gss_buffer_desc(xdrs, &p->gr_token));
lib/librpcsec_gss/rpcsec_gss_prot.c:139:		xdr_stat = xdr_gss_buffer_desc(xdrs, &wrapbuf);
lib/librpcsec_gss/rpcsec_gss_prot.c:152:		xdr_stat = xdr_gss_buffer_desc(xdrs, &wrapbuf);
lib/librpcsec_gss/rpcsec_gss_prot.c:177:		if (!xdr_gss_buffer_desc(xdrs, &databuf)) {
lib/librpcsec_gss/rpcsec_gss_prot.c:182:		if (!xdr_gss_buffer_desc(xdrs, &wrapbuf)) {
lib/librpcsec_gss/rpcsec_gss_prot.c:199:		if (!xdr_gss_buffer_desc(xdrs, &wrapbuf)) {
lib/librpcsec_gss/rpcsec_gss_prot.c:228:		xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &databuf);
lib/librpcsec_gss/rpcsec_gss.c:287:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:366:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:382:			    (xdrproc_t)xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:407:				xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:474:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:531:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:556:		xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/svc_rpcsec_gss.c:608:		(xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/svc_rpcsec_gss.c:639:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/svc_rpcsec_gss.c:658:	xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_tok);
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:57:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p)
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:85:	    xdr_gss_buffer_desc(xdrs, &p->gc_handle));
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:96:	return (xdr_gss_buffer_desc(xdrs, &p->gr_handle) &&
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:100:	    xdr_gss_buffer_desc(xdrs, &p->gr_token));
sys/rpc/rpcsec_gss/rpcsec_gss.c:644:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:910:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:933:			    (xdrproc_t)xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:958:				xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1021:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
```

### Round 3: ❌ INVALID

**🎯 Crux:** The alleged 'invalid free' is actually the correct XDR pattern for freeing a heap-allocated member within a stack-allocated struct, and the UAF is prevented by a reference count.

I have evaluated the three findings reported by the scanner. 

1. **Heap Overflow/Exhaustion in `rpc_gss_validate`**: The code performs `gd->gd_verf.value = mem_alloc(verf->oa_length);` and immediately checks `if (gd->gd_verf.value == NULL)`. If the allocation fails (which it will for excessively large values), the function returns `FALSE` and does not perform the `memcpy`. This prevents a heap overflow. While a malicious actor could attempt to exhaust memory, kernel allocators typically handle this gracefully by returning NULL, and the code handles that NULL correctly. This is not a critical vulnerability.

2. **Invalid Free in `rpc_gss_init`**: The scanner flagged `xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_token);` as freeing a stack address. However, `xdr_free` in the XDR framework is designed to call the provided XDR routine (`xdr_gss_buffer_desc`) to clean up the *members* of the object. The `xdr_gss_buffer_desc` routine handles a `gss_buffer_desc` struct and frees the heap-allocated buffer pointed to by its `.value` field. Passing the address of the struct (even if it's on the stack) is the correct and necessary way to allow the XDR routine to access and free the internal pointer. This is a false positive.

3. **Race Condition/UAF in `rpc_gss_secfind`**: The cache eviction removes an entry and calls `AUTH_DESTROY`. `AUTH_DESTROY` calls `rpc_gss_destroy`, which uses `refcount_release(&gd->gd_refs)`. The object is only actually freed if the reference count reaches zero. Since any thread using the entry from the cache has already performed a `refcount_acquire`, the memory remains valid until the last user is finished. The lists are protected by `rpc_gss_lock` (an `sx` lock). This is a standard, safe refcounted cache implementation.

CRUX: The alleged 'invalid free' is actually the correct XDR pattern for freeing a heap-allocated member within a stack-allocated struct, and the UAF is prevented by a reference count.
GREP: xdr_gss_buffer_desc

🔎 **Grep results:**

GREP `xdr_gss_buffer_desc`:
```
lib/librpcsec_gss/rpcsec_gss_int.h:77:bool_t  xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p);
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:57:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p)
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:85:	    xdr_gss_buffer_desc(xdrs, &p->gc_handle));
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:96:	return (xdr_gss_buffer_desc(xdrs, &p->gr_handle) &&
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:100:	    xdr_gss_buffer_desc(xdrs, &p->gr_token));
sys/rpc/rpcsec_gss/rpcsec_gss.c:644:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:910:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:933:			    (xdrproc_t)xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:958:				xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1021:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1132:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1165:		xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:955:		(xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1019:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1059:	xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_tok);
sys/kgssapi/gssd_prot.c:44:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *buf)
sys/kgssapi/gssd_prot.c:201:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:204:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:206:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:225:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:228:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:230:			    || !xdr_gss_buffer_desc(xdrs,
sys/kgssapi/gssd_prot.c:242:			xdr_gss_buffer_desc(xdrs, &ch->initiator_address);
sys/kgssapi/gssd_prot.c:243:			xdr_gss_buffer_desc(xdrs, &ch->acceptor_address);
sys/kgssapi/gssd_prot.c:244:			xdr_gss_buffer_desc(xdrs, &ch->application_data);
lib/librpcsec_gss/rpcsec_gss.c:287:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:366:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:382:			    (xdrproc_t)xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:407:				xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:474:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
```

### Round 4: ❌ INVALID

[ARBITER] All three reported findings are incorrect based on the provided code: 1) Heap Overflow in rpc_gss_validate: The code checks if mem_alloc returns NULL immediately after allocation and before memcpy, preventing overflow. 2) Invalid Free in rpc_gss_init: The call xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_token) is the correct pattern for XDR routines designed to free the heap-allocated members inside a stack-allocated descriptor struct. 3) Race Condition in rpc_gss_secfind: The cache entry is protected by a reference count (gd_refs), and AUTH_DESTROY is only called when the refcount reaches zero (via rpc_gss_destroy), preventing Use-After-Free.

