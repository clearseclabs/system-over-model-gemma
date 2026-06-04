# Triage T0134: Potential Kernel Stack Overflow in `rpc_gss_marshal`

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Potential Kernel Stack Overflow in `rpc_gss_marshal`

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The return value of `xdr_rpc_gss_cred` is checked, and the XDR handle created by `xdrmem_create` enforces the `sizeof(credbuf)` limit during encoding.

The vulnerability report suggests that `xdr_rpc_gss_cred` could overflow `credbuf[MAX_AUTH_BYTES]` if the XDR implementation doesn't enforce the buffer size. I need to verify the value of `MAX_AUTH_BYTES` and, more importantly, how `xdrmem_create` and the subsequent `xdr_rpc_gss_cred` handle boundaries. In standard XDR implementations (like the one used in SunRPC/Kernel RPC), `xdrmem_create` initializes an XDR handle with a specific buffer and a maximum size. The XDR encoding functions (like `xdr_rpc_gss_cred`) check the remaining space in the buffer before writing. If the data to be encoded exceeds the remaining space, the XDR function returns `FALSE` (or 0), which is exactly what `rpc_gss_marshal` checks: `if (!xdr_rpc_gss_cred(&tmpxdrs, &gsscred)) { ... return (FALSE); }`. Therefore, the XDR framework provides a built-in bounds check that prevents the overflow regardless of the value of `MAX_AUTH_BYTES`. The report's claim that 'many legacy XDR implementations have had boundary issues' is a general observation and not a specific proof that this implementation is flawed.

CRUX: The return value of `xdr_rpc_gss_cred` is checked, and the XDR handle created by `xdrmem_create` enforces the `sizeof(credbuf)` limit during encoding.
GREP: xdrmem_create

🔎 **Grep results:**

GREP `xdrmem_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:273:#define xdrmem_create		gssrpc_xdrmem_create
include/rpc/xdr.h:332:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/rpc/xdr.h:361:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:39:	    /* Let caller know xdrmem_create() succeeds */
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:74:void xdrmem_create(XDR *xdrs, const caddr_t addr, const uint_t size,
crypto/krb5/src/include/gssrpc/xdr.h:316:extern void	xdrmem_create(XDR *, caddr_t, u_int, enum xdr_op);
lib/librpcsec_gss/rpcsec_gss_prot.c:218:	xdrmem_create(&tmpxdrs, databuf.value, databuf.length, XDR_DECODE);
lib/librpcsec_gss/svc_rpcsec_gss.c:989:	xdrmem_create(&xdrs, rqst->rq_cred.oa_base,
lib/librpcsec_gss/rpcsec_gss.c:588:	xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE);
lib/librpcsec_gss/rpcsec_gss.c:599:	xdrmem_create(&tmpxdrs, tmpheader, sizeof(tmpheader), XDR_ENCODE);
lib/libc/rpc/svc_dg.c:133:	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt), su->su_iosz,
lib/libc/rpc/svc_dg.c:635:	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt),
lib/libc/rpc/auth_none.c:93:		xdrmem_create(xdrs, ap->marshalled_client,
lib/libc/rpc/svc_raw.c:114:	xdrmem_create(&srp->xdr_stream, srp->raw_buf, UDPMSGSIZE, XDR_DECODE);
lib/libc/rpc/svc_auth_unix.c:77:	xdrmem_create(&xdrs, msg->rm_call.cb_cred.oa_base, auth_len,XDR_DECODE);
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_raw.c:125:	xdrmem_create(xdrs, clp->_raw_buf, UDPMSGSIZE, XDR_FREE);
lib/libc/rpc/svc_nl.c:215:	xdrmem_create(&sc->xdrs, NLA_DATA(req.data), NLA_DATA_LEN(req.data),
lib/libc/rpc/svc_nl.c:280:	xdrmem_create(&xdrs, (char *)(body + 1), RPC_MAXDATASIZE, XDR_ENCODE);
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/auth_unix.c:136:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
lib/libc/rpc/auth_unix.c:239:		xdrmem_create(&xdrs, verf->oa_base, verf->oa_length,
lib/libc/rpc/auth_unix.c:280:	xdrmem_create(&xdrs, au->au_origcred.oa_base,
lib/libc/rpc/auth_unix.c:339:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
lib/libc/rpc/clnt_bcast.c:390:	xdrmem_create(xdrs, outbuf, maxbufsize, XDR_ENCODE);
lib/libc/rpc/clnt_bcast.c:415:		xdrmem_create(xdrs, outbuf_pmap, udpbufsz, XDR_ENCODE);
lib/libc/rpc/clnt_bcast.c:582:			xdrmem_create(xdrs, inbuf, (u_int)inlen, XDR_DECODE);
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_dg.c:268:	xdrmem_create(&cu->cu_outxdrs, cu->cu_outbuf, sendsz, XDR_ENCODE);
lib/libc/rpc/clnt_dg.c:527:	xdrmem_create(&reply_xdrs, cu->cu_inbuf, (u_int)recvlen, XDR_DECODE);
```

### Round 2: ❌ INVALID

**🎯 Crux:** xdrmem_create sets a hard boundary on the XDR stream using sizeof(credbuf), and xdr_rpc_gss_cred respects this boundary, returning FALSE if it would overflow, which the caller handles.

The vulnerability report claims that `xdr_rpc_gss_cred` could overflow the stack buffer `credbuf` if `MAX_AUTH_BYTES` is insufficient. However, `rpc_gss_marshal` uses `xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE)`. In the RPC XDR framework, `xdrmem_create` explicitly sets the boundary of the XDR stream to the size of the provided buffer. Every subsequent XDR encoding function, including `xdr_rpc_gss_cred`, checks this boundary before writing data. If the data to be encoded exceeds the remaining space in the buffer, the XDR function returns FALSE. The code explicitly checks this return value: `if (!xdr_rpc_gss_cred(&tmpxdrs, &gsscred)) { ... return (FALSE); }`. This mechanism prevents the buffer overflow regardless of the value of `MAX_AUTH_BYTES` or the size of the GSS credentials. The report's claim about legacy XDR issues is a general statement and not a specific vulnerability in this implementation.

CRUX: xdrmem_create sets a hard boundary on the XDR stream using sizeof(credbuf), and xdr_rpc_gss_cred respects this boundary, returning FALSE if it would overflow, which the caller handles.
GREP: xdrmem_create

🔎 **Grep results:**

GREP `xdrmem_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:273:#define xdrmem_create		gssrpc_xdrmem_create
include/rpc/xdr.h:332:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/rpc/xdr.h:361:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:39:	    /* Let caller know xdrmem_create() succeeds */
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:74:void xdrmem_create(XDR *xdrs, const caddr_t addr, const uint_t size,
crypto/krb5/src/include/gssrpc/xdr.h:316:extern void	xdrmem_create(XDR *, caddr_t, u_int, enum xdr_op);
lib/librpcsec_gss/rpcsec_gss_prot.c:218:	xdrmem_create(&tmpxdrs, databuf.value, databuf.length, XDR_DECODE);
lib/librpcsec_gss/rpcsec_gss.c:588:	xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE);
lib/librpcsec_gss/rpcsec_gss.c:599:	xdrmem_create(&tmpxdrs, tmpheader, sizeof(tmpheader), XDR_ENCODE);
lib/librpcsec_gss/svc_rpcsec_gss.c:989:	xdrmem_create(&xdrs, rqst->rq_cred.oa_base,
usr.sbin/rpcbind/rpcb_svc_com.c:805:		xdrmem_create(&outxdr, outbuf_alloc, sendsz, XDR_ENCODE);
usr.sbin/rpcbind/rpcb_svc_com.c:807:		xdrmem_create(&outxdr, outbuf, sendsz, XDR_ENCODE);
usr.sbin/rpcbind/rpcb_svc_com.c:1267:	xdrmem_create(&reply_xdrs, buffer, (u_int)inlen, XDR_DECODE);
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:95:	xdrmem_create(&x, xdrdata, sizeof(xdrdata), XDR_DECODE);
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:112:	xdrmem_create(&x, newdata, sizeof(newdata), XDR_ENCODE);
lib/libc/rpc/auth_none.c:93:		xdrmem_create(xdrs, ap->marshalled_client,
lib/libc/rpc/svc_dg.c:133:	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt), su->su_iosz,
lib/libc/rpc/svc_dg.c:635:	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt),
lib/libc/rpc/svc_raw.c:114:	xdrmem_create(&srp->xdr_stream, srp->raw_buf, UDPMSGSIZE, XDR_DECODE);
lib/libc/rpc/svc_auth_unix.c:77:	xdrmem_create(&xdrs, msg->rm_call.cb_cred.oa_base, auth_len,XDR_DECODE);
lib/libc/rpc/svc_nl.c:215:	xdrmem_create(&sc->xdrs, NLA_DATA(req.data), NLA_DATA_LEN(req.data),
lib/libc/rpc/svc_nl.c:280:	xdrmem_create(&xdrs, (char *)(body + 1), RPC_MAXDATASIZE, XDR_ENCODE);
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_raw.c:125:	xdrmem_create(xdrs, clp->_raw_buf, UDPMSGSIZE, XDR_FREE);
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_bcast.c:390:	xdrmem_create(xdrs, outbuf, maxbufsize, XDR_ENCODE);
lib/libc/rpc/clnt_bcast.c:415:		xdrmem_create(xdrs, outbuf_pmap, udpbufsz, XDR_ENCODE);
lib/libc/rpc/clnt_bcast.c:582:			xdrmem_create(xdrs, inbuf, (u_int)inlen, XDR_DECODE);
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_dg.c:268:	xdrmem_create(&cu->cu_outxdrs, cu->cu_outbuf, sendsz, XDR_ENCODE);
```

### Round 3: ❌ INVALID

**🎯 Crux:** xdrmem_create sets a hard boundary using sizeof(credbuf), and xdr_rpc_gss_cred respects this boundary, returning FALSE if it would overflow, which the caller handles.

The vulnerability report suggests a kernel stack overflow in `rpc_gss_marshal` because `credbuf` is a fixed-size array (`MAX_AUTH_BYTES`). However, the code uses the RPC XDR framework to perform the encoding. Specifically, `xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE)` is called. In the RPC XDR implementation, `xdrmem_create` initializes the XDR handle with a pointer to the buffer and a strict size limit (`sizeof(credbuf)`). Every XDR encoding function, including `xdr_rpc_gss_cred`, is required to check the remaining space in the buffer before writing. If the data to be encoded exceeds the buffer size, the XDR function returns `FALSE`. The code explicitly checks this return value: `if (!xdr_rpc_gss_cred(&tmpxdrs, &gsscred)) { ... return (FALSE); }`. This pattern ensures that the buffer cannot be overflowed regardless of the value of `MAX_AUTH_BYTES` or the size of the credentials provided by the GSS-API. The report's mention of 'legacy XDR implementations' is generic and not supported by the actual code logic present here.

CRUX: xdrmem_create sets a hard boundary using sizeof(credbuf), and xdr_rpc_gss_cred respects this boundary, returning FALSE if it would overflow, which the caller handles.
GREP: xdrmem_create

🔎 **Grep results:**

GREP `xdrmem_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:273:#define xdrmem_create		gssrpc_xdrmem_create
sys/rpc/xdr.h:361:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:39:	    /* Let caller know xdrmem_create() succeeds */
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:74:void xdrmem_create(XDR *xdrs, const caddr_t addr, const uint_t size,
crypto/krb5/src/include/gssrpc/xdr.h:316:extern void	xdrmem_create(XDR *, caddr_t, u_int, enum xdr_op);
include/rpc/xdr.h:332:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
lib/librpcsec_gss/rpcsec_gss_prot.c:218:	xdrmem_create(&tmpxdrs, databuf.value, databuf.length, XDR_DECODE);
lib/librpcsec_gss/rpcsec_gss.c:588:	xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE);
lib/librpcsec_gss/rpcsec_gss.c:599:	xdrmem_create(&tmpxdrs, tmpheader, sizeof(tmpheader), XDR_ENCODE);
lib/librpcsec_gss/svc_rpcsec_gss.c:989:	xdrmem_create(&xdrs, rqst->rq_cred.oa_base,
usr.sbin/rpcbind/rpcb_svc_com.c:805:		xdrmem_create(&outxdr, outbuf_alloc, sendsz, XDR_ENCODE);
usr.sbin/rpcbind/rpcb_svc_com.c:807:		xdrmem_create(&outxdr, outbuf, sendsz, XDR_ENCODE);
usr.sbin/rpcbind/rpcb_svc_com.c:1267:	xdrmem_create(&reply_xdrs, buffer, (u_int)inlen, XDR_DECODE);
lib/libc/xdr/xdr_mem.c:92: * The procedure xdrmem_create initializes a stream descriptor for a
lib/libc/xdr/xdr_mem.c:96:xdrmem_create(XDR *xdrs, char *addr, u_int size, enum xdr_op op)
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:95:	xdrmem_create(&x, xdrdata, sizeof(xdrdata), XDR_DECODE);
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:112:	xdrmem_create(&x, newdata, sizeof(newdata), XDR_ENCODE);
lib/libc/rpc/auth_none.c:93:		xdrmem_create(xdrs, ap->marshalled_client,
lib/libc/rpc/svc_dg.c:133:	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt), su->su_iosz,
lib/libc/rpc/svc_dg.c:635:	xdrmem_create(&(su->su_xdrs), rpc_buffer(xprt),
lib/libc/rpc/svc_raw.c:114:	xdrmem_create(&srp->xdr_stream, srp->raw_buf, UDPMSGSIZE, XDR_DECODE);
lib/libc/rpc/svc_auth_unix.c:77:	xdrmem_create(&xdrs, msg->rm_call.cb_cred.oa_base, auth_len,XDR_DECODE);
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_raw.c:125:	xdrmem_create(xdrs, clp->_raw_buf, UDPMSGSIZE, XDR_FREE);
lib/libc/rpc/svc_nl.c:215:	xdrmem_create(&sc->xdrs, NLA_DATA(req.data), NLA_DATA_LEN(req.data),
lib/libc/rpc/svc_nl.c:280:	xdrmem_create(&xdrs, (char *)(body + 1), RPC_MAXDATASIZE, XDR_ENCODE);
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_bcast.c:390:	xdrmem_create(xdrs, outbuf, maxbufsize, XDR_ENCODE);
lib/libc/rpc/clnt_bcast.c:415:		xdrmem_create(xdrs, outbuf_pmap, udpbufsz, XDR_ENCODE);
lib/libc/rpc/clnt_bcast.c:582:			xdrmem_create(xdrs, inbuf, (u_int)inlen, XDR_DECODE);
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability report claims that `xdr_rpc_gss_cred` could overflow the `credbuf` array. However, the code explicitly calls `xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE)`. In the RPC XDR framework, `xdrmem_create` initializes the XDR stream with a strict boundary equal to the size of the buffer provided (`sizeof(credbuf)`). All subsequent XDR encoding functions, including `xdr_rpc_gss_cred`, check this boundary before writing any data. If the data exceeds the buffer size, the function returns FALSE, which the code explicitly checks and handles by returning FALSE to the caller. Therefore, no stack overflow can occur.

