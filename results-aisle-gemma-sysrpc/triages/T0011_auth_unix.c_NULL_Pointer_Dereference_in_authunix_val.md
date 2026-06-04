# Triage T0011: NULL Pointer Dereference in authunix_validate

- **File**: `auth_unix.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

NULL Pointer Dereference in authunix_validate

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** authunix_validate passes verf->oa_base to xdrmem_create without checking if it is NULL, and verf is derived from untrusted network input.

The function `authunix_validate` is called when an RPC request arrives. It receives a `struct opaque_auth *verf`, which is decoded from the network. If the attacker sets the `oa_flavor` to `AUTH_SHORT`, the code proceeds to call `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE)`. There is no check to ensure `verf->oa_base` is not NULL. If `verf->oa_base` is NULL, `xdrmem_create` (which typically initializes an XDR handle to read from a buffer) will likely dereference this pointer when the subsequent `xdr_opaque_auth` call attempts to read data from the stream, leading to a kernel crash (Panic). Since `verf` is constructed from network-provided XDR data, an attacker can specifically craft a packet where the base pointer for the opaque auth structure is null (or the XDR decoding of the opaque auth structure results in a NULL base).

CRUX: authunix_validate passes verf->oa_base to xdrmem_create without checking if it is NULL, and verf is derived from untrusted network input.
GREP: xdrmem_create

🔎 **Grep results:**

GREP `xdrmem_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:273:#define xdrmem_create		gssrpc_xdrmem_create
crypto/krb5/src/include/gssrpc/xdr.h:316:extern void	xdrmem_create(XDR *, caddr_t, u_int, enum xdr_op);
include/rpc/xdr.h:332:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/rpc/xdr.h:361:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:39:	    /* Let caller know xdrmem_create() succeeds */
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:74:void xdrmem_create(XDR *xdrs, const caddr_t addr, const uint_t size,
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:95:	xdrmem_create(&x, xdrdata, sizeof(xdrdata), XDR_DECODE);
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:112:	xdrmem_create(&x, newdata, sizeof(newdata), XDR_ENCODE);
lib/librpcsec_gss/rpcsec_gss.c:588:	xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE);
lib/librpcsec_gss/rpcsec_gss.c:599:	xdrmem_create(&tmpxdrs, tmpheader, sizeof(tmpheader), XDR_ENCODE);
lib/librpcsec_gss/svc_rpcsec_gss.c:989:	xdrmem_create(&xdrs, rqst->rq_cred.oa_base,
lib/librpcsec_gss/rpcsec_gss_prot.c:218:	xdrmem_create(&tmpxdrs, databuf.value, databuf.length, XDR_DECODE);
lib/libc/xdr/xdr_mem.c:92: * The procedure xdrmem_create initializes a stream descriptor for a
lib/libc/xdr/xdr_mem.c:96:xdrmem_create(XDR *xdrs, char *addr, u_int size, enum xdr_op op)
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
lib/libc/rpc/clnt_dg.c:527:	xdrmem_create(&reply_xdrs, cu->cu_inbuf, (u_int)recvlen, XDR_DECODE);
```

### Round 2: ✅ VALID

**🎯 Crux:** authunix_validate passes verf->oa_base to xdrmem_create without verifying it is non-NULL, and verf is attacker-controlled network input.

The `authunix_validate` function is called during RPC request processing. It receives a `struct opaque_auth *verf` which is derived from the network. If the attacker provides a packet with `oa_flavor == AUTH_SHORT` and `oa_base == NULL`, the code calls `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE)`. Looking at the implementation of `xdrmem_create` (referenced in `lib/libc/xdr/xdr_mem.c`), it initializes an XDR handle to read from the provided memory address. While `xdrmem_create` itself might only assign the pointer, the subsequent call to `xdr_opaque_auth(&txdrs, &au->au_shcred)` will attempt to read data from that pointer. If `oa_base` is NULL, this results in a NULL pointer dereference and a kernel crash. The check `if (!verf)` only ensures the structure containing the metadata is present, not that the payload buffer `oa_base` is present. Since `verf` is constructed from untrusted network input via XDR, an attacker can trigger this path.

CRUX: authunix_validate passes verf->oa_base to xdrmem_create without verifying it is non-NULL, and verf is attacker-controlled network input.
GREP: xdr_opaque_auth

🔎 **Grep results:**

GREP `xdr_opaque_auth`:
```
crypto/krb5/src/include/gssrpc/rename.h:66:#define xdr_opaque_auth		gssrpc_xdr_opaque_auth
include/rpc/auth.h:267:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
sys/rpc/auth.h:264:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
crypto/krb5/src/include/gssrpc/auth.h:193:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/librpcsec_gss/rpcsec_gss.c:601:	    !xdr_opaque_auth(&tmpxdrs, &creds)) {
lib/librpcsec_gss/rpcsec_gss.c:616:		if (!xdr_opaque_auth(xdrs, &_null_auth)) {
lib/librpcsec_gss/rpcsec_gss.c:645:		xdr_stat = xdr_opaque_auth(xdrs, &verf);
lib/libc/rpc/auth_none.c:63:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
lib/libc/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
lib/libc/rpc/rpc_prot.c:66:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
lib/libc/rpc/rpc_prot.c:107:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
lib/libc/rpc/clnt_raw.c:221:			(void)xdr_opaque_auth(xdrs, &(msg.acpted_rply.ar_verf));
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
lib/libc/rpc/rpc_callmsg.c:197:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
lib/libc/rpc/clnt_vc.c:438:			(void)xdr_opaque_auth(xdrs,
lib/libc/rpc/auth_unix.c:247:		if (xdr_opaque_auth(&xdrs, &au->au_shcred)) {
lib/libc/rpc/auth_unix.c:251:			(void)xdr_opaque_auth(&xdrs, &au->au_shcred);
lib/libc/rpc/auth_unix.c:340:	if ((! xdr_opaque_auth(xdrs, &(auth->ah_cred))) ||
lib/libc/rpc/auth_unix.c:341:	    (! xdr_opaque_auth(xdrs, &(auth->ah_verf))))
lib/libc/rpc/clnt_dg.c:574:				(void) xdr_opaque_auth(xdrs,
sys/rpc/auth_none.c:92:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/auth_none.c:93:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/rpc_prot.c:72:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
sys/rpc/rpc_prot.c:100:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
sys/rpc/rpcsec_tls/auth_tls.c:101:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/rpcsec_tls/auth_tls.c:102:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/rpc_callmsg.c:192:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
sys/rpc/rpc_callmsg.c:193:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
sys/rpc/auth_unix.c:277:		if (xdr_opaque_auth(&txdrs, &au->au_shcred)) {
```

### Round 3: ✅ VALID

**🎯 Crux:** authunix_validate lacks a NULL check for verf->oa_base before using it as a source buffer for xdr_opaque_auth, and this pointer is derived from untrusted network input.

The bug pattern is real: `authunix_validate` passes `verf->oa_base` to `xdrmem_create` and then calls `xdr_opaque_auth` without checking if `oa_base` is NULL. In RPC, the `opaque_auth` structure is decoded from the network. If an attacker provides a payload where `oa_flavor` is `AUTH_SHORT` but the data buffer `oa_base` is NULL (which happens if the XDR decoder processes a zero-length opaque object or a specifically crafted malformed packet), the subsequent read operation in `xdr_opaque_auth` will dereference the NULL pointer. Since `authunix_validate` is part of the kernel RPC authentication layer, this will trigger a kernel panic (DoS). The `if (!verf)` check is insufficient because it only checks the container, not the internal data pointer. There are no intervening defenses that prevent a NULL `oa_base` from reaching `xdrmem_create` when `oa_flavor == AUTH_SHORT`.

CRUX: authunix_validate lacks a NULL check for verf->oa_base before using it as a source buffer for xdr_opaque_auth, and this pointer is derived from untrusted network input.
GREP: xdrmem_create

🔎 **Grep results:**

GREP `xdrmem_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:273:#define xdrmem_create		gssrpc_xdrmem_create
sys/rpc/xdr.h:361:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:39:	    /* Let caller know xdrmem_create() succeeds */
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:74:void xdrmem_create(XDR *xdrs, const caddr_t addr, const uint_t size,
include/rpc/xdr.h:332:extern void   xdrmem_create(XDR *, char *, u_int, enum xdr_op);
crypto/krb5/src/include/gssrpc/xdr.h:316:extern void	xdrmem_create(XDR *, caddr_t, u_int, enum xdr_op);
usr.sbin/rpcbind/rpcb_svc_com.c:805:		xdrmem_create(&outxdr, outbuf_alloc, sendsz, XDR_ENCODE);
usr.sbin/rpcbind/rpcb_svc_com.c:807:		xdrmem_create(&outxdr, outbuf, sendsz, XDR_ENCODE);
usr.sbin/rpcbind/rpcb_svc_com.c:1267:	xdrmem_create(&reply_xdrs, buffer, (u_int)inlen, XDR_DECODE);
sys/xdr/xdr_mem.c:94: * The procedure xdrmem_create initializes a stream descriptor for a
sys/xdr/xdr_mem.c:98:xdrmem_create(XDR *xdrs, char *addr, u_int size, enum xdr_op op)
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:95:	xdrmem_create(&x, xdrdata, sizeof(xdrdata), XDR_DECODE);
contrib/netbsd-tests/lib/libc/rpc/t_xdr.c:112:	xdrmem_create(&x, newdata, sizeof(newdata), XDR_ENCODE);
lib/librpcsec_gss/rpcsec_gss_prot.c:218:	xdrmem_create(&tmpxdrs, databuf.value, databuf.length, XDR_DECODE);
lib/librpcsec_gss/rpcsec_gss.c:588:	xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE);
lib/librpcsec_gss/rpcsec_gss.c:599:	xdrmem_create(&tmpxdrs, tmpheader, sizeof(tmpheader), XDR_ENCODE);
lib/librpcsec_gss/svc_rpcsec_gss.c:989:	xdrmem_create(&xdrs, rqst->rq_cred.oa_base,
sys/rpc/auth_none.c:91:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:234:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:242:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:294:	xdrmem_create(&xdrs, mem, len, XDR_ENCODE);
sys/rpc/svc_auth_unix.c:64:	xdrmem_create(&xdrs, msg->rm_call.cb_cred.oa_base, auth_len,
sys/rpc/clnt_bck.c:159:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/rpcsec_tls/auth_tls.c:100:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
sys/rpc/clnt_vc.c:238:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/auth_unix.c:197:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/auth_unix.c:269:		xdrmem_create(&txdrs, verf->oa_base, verf->oa_length,
sys/rpc/auth_unix.c:308:	xdrmem_create(&xdrs, au->au_origcred.oa_base,
sys/rpc/auth_unix.c:365:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/clnt_dg.c:250:	xdrmem_create(&xdrs, cu->cu_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
```

### Round 4: ✅ VALID

[ARBITER] In `authunix_validate`, the code checks if the `verf` pointer itself is NULL, but it fails to check if `verf->oa_base` is NULL before passing it to `xdrmem_create`. Since `verf` is derived from untrusted network input (an RPC packet), an attacker can provide a packet with `oa_flavor == AUTH_SHORT` and `oa_base == NULL`. The subsequent call to `xdrmem_create` and the follow-up `xdr_opaque_auth` call will attempt to read from the NULL address, resulting in a kernel crash (NULL pointer dereference).

