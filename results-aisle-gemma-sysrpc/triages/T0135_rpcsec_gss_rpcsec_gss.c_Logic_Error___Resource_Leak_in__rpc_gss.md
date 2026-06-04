# Triage T0135: Logic Error / Resource Leak in `rpc_gss_init`

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 25% [VII→I]

---

## Finding

Logic Error / Resource Leak in `rpc_gss_init`

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The code calls `xdr_free` on the address of a stack-allocated `gss_buffer_desc` structure instead of the buffer it points to, and this is triggered by receiving a token from a remote RPC server.

The vulnerability report identifies a call to `xdr_free` in `rpc_gss_init` that passes the address of a local variable `recv_token` (`&recv_token`) rather than the pointer to the heap-allocated buffer it contains (`recv_token.value`). 

1. **Bug Pattern**: The code is `xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_token);`. `recv_token` is declared as `gss_buffer_desc recv_token;` on the stack. `xdr_free` is designed to call the XDR procedure (`xdr_gss_buffer_desc`) to free the contents of the structure. If `xdr_gss_buffer_desc` (the XDR free routine) internally calls `free()` or a similar kernel allocator on the address passed to it, it will be attempting to free a stack address, leading to a kernel panic/crash. 

2. **Reachability**: The data flow is: Remote Server $ightarrow$ `CLNT_CALL_EXT` $ightarrow$ `gr.gr_token` $ightarrow$ `recv_token` $ightarrow$ `xdr_free(&recv_token)`. An attacker controlling a malicious RPC server can send a token during the GSS context establishment phase. If the server sends a token (`gr.gr_token.length != 0`), the code sets `recv_token = gr.gr_token` and `recv_tokenp = &recv_token`. In the next iteration of the loop, `recv_tokenp != GSS_C_NO_BUFFER` is true, and `xdr_free` is called on `&recv_token`. This is directly reachable via untrusted network input.

3. **Security Relevance**: This is a kernel-mode invalid free (freeing a stack address), which typically results in an immediate system crash (DoS). In some kernel allocators, this could potentially be leveraged for more severe corruption, but a crash is sufficient for a VALID security vulnerability.

CRUX: The code calls `xdr_free` on the address of a stack-allocated `gss_buffer_desc` structure instead of the buffer it points to, and this is triggered by receiving a token from a remote RPC server.
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
sys/rpc/rpcsec_gss/rpcsec_gss.c:644:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:910:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:933:			    (xdrproc_t)xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:958:				xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1021:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1132:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss.c:1165:		xdr_free((xdrproc_t) xdr_gss_buffer_desc,
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:57:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p)
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:85:	    xdr_gss_buffer_desc(xdrs, &p->gc_handle));
```

### Round 2: ❌ INVALID

**🎯 Crux:** xdr_free passes the pointer to the structure to the XDR procedure, which then frees the heap-allocated member within that structure; it does not free the structure pointer itself.

The vulnerability report describes a case where `xdr_free` is called on the address of a stack-allocated `gss_buffer_desc` structure (`&recv_token`) rather than on the pointer to the heap-allocated buffer it contains. In `rpc_gss_init`, `recv_token` is a local variable. When a token is received from the remote server (`gr.gr_token`), it is assigned to `recv_token`, and `recv_tokenp` is set to `&recv_token`. On the next loop iteration, `xdr_free` is called with `(char *) &recv_token`. 

To determine if this is a security vulnerability, we must understand how `xdr_free` and `xdr_gss_buffer_desc` behave. In the RPC XDR framework, `xdr_free(proc, obj)` uses the provided XDR procedure (`proc`) to determine how to free the object. If `xdr_gss_buffer_desc` is implemented to free the `value` field of the `gss_buffer_desc` structure, then passing the address of the structure is the CORRECT pattern, as the procedure expects a pointer to the structure to access its members. If the procedure were to call `free()` on the pointer passed to it directly, it would be a bug. However, XDR procedures are designed to operate on the structures they marshal. Thus, `xdr_free` passing `&recv_token` to `xdr_gss_buffer_desc` allows the latter to see `recv_token.value` and free that heap buffer. This is a standard XDR pattern and not an invalid free of the stack address itself.

CRUX: xdr_free passes the pointer to the structure to the XDR procedure, which then frees the heap-allocated member within that structure; it does not free the structure pointer itself.
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
lib/librpcsec_gss/svc_rpcsec_gss.c:608:		(xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/svc_rpcsec_gss.c:639:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/svc_rpcsec_gss.c:658:	xdr_free((xdrproc_t) xdr_gss_buffer_desc, (char *) &recv_tok);
lib/librpcsec_gss/rpcsec_gss.c:287:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:366:			xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:382:			    (xdrproc_t)xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:407:				xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:474:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:531:	xdr_free((xdrproc_t) xdr_gss_buffer_desc,
lib/librpcsec_gss/rpcsec_gss.c:556:		xdr_free((xdrproc_t) xdr_gss_buffer_desc,
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

**🎯 Crux:** xdr_free uses the XDR procedure to free the internal members of the structure; it does not attempt to free the pointer to the structure itself.

The reported vulnerability is a misunderstanding of how the XDR (External Data Representation) framework's `xdr_free` function operates. The reporter claims that calling `xdr_free` on the address of a local `gss_buffer_desc` structure (`&recv_token`) leads to an invalid free of a stack address. However, in XDR, `xdr_free` does not call `free()` on the pointer passed to it. Instead, it calls the provided XDR procedure (in this case, `xdr_gss_buffer_desc`) and passes that pointer as the second argument. The XDR procedure is responsible for knowing the internal structure of the object and freeing its members. For a `gss_buffer_desc`, the procedure `xdr_gss_buffer_desc` is designed to free the `value` field (which is a heap-allocated buffer) while the structure containing the pointer itself can be located anywhere (stack or heap). This is the standard and intended pattern for XDR memory management. Since the `xdr_gss_buffer_desc` procedure correctly handles the internal buffer and not the structure pointer itself, no invalid free of the stack occurs.

CRUX: xdr_free uses the XDR procedure to free the internal members of the structure; it does not attempt to free the pointer to the structure itself.
GREP: xdr_gss_buffer_desc

🔎 **Grep results:**

GREP `xdr_gss_buffer_desc`:
```
lib/librpcsec_gss/rpcsec_gss_int.h:77:bool_t  xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p);
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
lib/librpcsec_gss/rpcsec_gss_prot.c:51:xdr_gss_buffer_desc(XDR *xdrs, gss_buffer_desc *p)
lib/librpcsec_gss/rpcsec_gss_prot.c:78:	    xdr_gss_buffer_desc(xdrs, &p->gc_handle));
lib/librpcsec_gss/rpcsec_gss_prot.c:89:	return (xdr_gss_buffer_desc(xdrs, &p->gr_handle) &&
lib/librpcsec_gss/rpcsec_gss_prot.c:93:	    xdr_gss_buffer_desc(xdrs, &p->gr_token));
lib/librpcsec_gss/rpcsec_gss_prot.c:139:		xdr_stat = xdr_gss_buffer_desc(xdrs, &wrapbuf);
```

### Round 4: ❌ INVALID

[ARBITER] The reporter misunderstood the XDR framework's `xdr_free` mechanism. In XDR, `xdr_free(proc, ptr)` does not call `free(ptr)`. Instead, it calls the specified XDR procedure (`proc`) and passes `ptr` as an argument. The procedure `xdr_gss_buffer_desc` is designed to handle a pointer to a `gss_buffer_desc` structure and free the internal heap-allocated buffer (`p->value`), not the structure itself. Therefore, passing the address of a stack-allocated structure (`&recv_token`) is the correct and intended usage of the XDR API.

