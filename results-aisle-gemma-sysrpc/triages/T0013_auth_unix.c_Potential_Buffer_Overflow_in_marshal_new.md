# Triage T0013: Potential Buffer Overflow in marshal_new_auth

- **File**: `auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Potential Buffer Overflow in marshal_new_auth

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The XDR engine (`xdrmem_create` and `xdr_opaque_auth`) performs bounds checking against the provided buffer size (`MAX_AUTH_BYTES`), preventing any overflow regardless of the input size.

The vulnerability report claims that `marshal_new_auth` can overflow `au->au_marshed` because it calls `xdr_opaque_auth` twice without checking the remaining buffer space. In `marshal_new_auth`, `xdrmem_create` is called with `MAX_AUTH_BYTES` as the buffer size. The XDR engine (as implemented in standard RPC) tracks the current position and the buffer limit. If `xdr_opaque_auth` attempts to write beyond `MAX_AUTH_BYTES`, the XDR function will return `FALSE` and stop writing. The code then checks the return value of `xdr_opaque_auth`: if either call fails (including failure due to buffer overflow), it prints a fatal error message but does not perform any unsafe memory operation; it simply fails to update `au->au_mpos`. There is no 'overflow check performed after' the operations; the bounds check is intrinsic to the XDR encoding process. Thus, a buffer overflow is prevented by the XDR engine itself.

CRUX: The XDR engine (`xdrmem_create` and `xdr_opaque_auth`) performs bounds checking against the provided buffer size (`MAX_AUTH_BYTES`), preventing any overflow regardless of the input size.
GREP: MAX_AUTH_BYTES

🔎 **Grep results:**

GREP `MAX_AUTH_BYTES`:
```
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/svc.h:228:	char		rq_credarea[3*MAX_AUTH_BYTES];
sys/rpc/krpc.h:58:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
include/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/svc_dg.h:46:	char		su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
crypto/krb5/src/include/gssrpc/auth.h:89:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
lib/librpcsec_gss/rpcsec_gss.c:568:	char			 credbuf[MAX_AUTH_BYTES];
lib/librpcsec_gss/rpcsec_gss.c:569:	char			 tmpheader[MAX_AUTH_BYTES];
sys/rpc/svc.c:933:	msg.rm_call.cb_verf.oa_base = &r->rq_credarea[MAX_AUTH_BYTES];
sys/rpc/svc.c:934:	r->rq_clntcred = &r->rq_credarea[2*MAX_AUTH_BYTES];
sys/rpc/rpc_prot.c:80:			&ap->oa_length, MAX_AUTH_BYTES));
sys/rpc/rpc_callmsg.c:58:		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:61:		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:119:				if (oa->oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:155:				if (oa->oa_length > MAX_AUTH_BYTES) {
sys/rpc/auth_unix.c:92:	char			au_marshed[MAX_AUTH_BYTES];
sys/rpc/auth_unix.c:127:	char mymem[MAX_AUTH_BYTES];
sys/rpc/auth_unix.c:197:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/auth_unix.c:365:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/clnt_dg.c:103:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
sys/rpc/rpcsec_gss/rpcsec_gss.c:518:	char			 credbuf[MAX_AUTH_BYTES];
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1249:	KASSERT(mic.length <= MAX_AUTH_BYTES,
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
```

### Round 2: ❌ INVALID

**🎯 Crux:** xdrmem_create establishes a hard bound of MAX_AUTH_BYTES which is enforced by the XDR engine during every write operation in xdr_opaque_auth.

The vulnerability report claims that `marshal_new_auth` can overflow `au->au_marshed` because `xdr_opaque_auth` is called twice. However, `marshal_new_auth` initializes the XDR stream using `xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE)`. In the RPC XDR implementation, `xdrmem_create` sets the boundary of the memory buffer. Any subsequent XDR encoding functions (like `xdr_opaque_auth`) check the current position (`x_cur`) against the end of the buffer (`x_max`). If a write would exceed `MAX_AUTH_BYTES`, the XDR function returns `FALSE` and does not perform the write. The code in `marshal_new_auth` explicitly checks the return value of both `xdr_opaque_auth` calls. If either fails (which they would if the buffer is exhausted), it prints an error and does not update `au->au_mpos`. Therefore, the buffer is never overflowed.

CRUX: xdrmem_create establishes a hard bound of MAX_AUTH_BYTES which is enforced by the XDR engine during every write operation in xdr_opaque_auth.
GREP: MAX_AUTH_BYTES

🔎 **Grep results:**

GREP `MAX_AUTH_BYTES`:
```
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
include/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/svc_dg.h:46:	char		su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
crypto/krb5/src/include/gssrpc/auth.h:89:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/svc.h:228:	char		rq_credarea[3*MAX_AUTH_BYTES];
sys/rpc/krpc.h:58:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
lib/librpcsec_gss/rpcsec_gss.c:568:	char			 credbuf[MAX_AUTH_BYTES];
lib/librpcsec_gss/rpcsec_gss.c:569:	char			 tmpheader[MAX_AUTH_BYTES];
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
lib/libc/rpc/svc_vc.c:95:	char verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_callmsg.c:62:		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:65:		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:123:				if (oa->oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:159:				if (oa->oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/auth_unix.c:79:	char			au_marshed[MAX_AUTH_BYTES];
lib/libc/rpc/auth_unix.c:92:	char mymem[MAX_AUTH_BYTES];
lib/libc/rpc/auth_unix.c:136:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
lib/libc/rpc/auth_unix.c:339:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
usr.bin/genl/parser_rpc.c:104:		if (oa->oa_length > MAX_AUTH_BYTES) {
usr.bin/genl/parser_rpc.c:140:		if (oa->oa_length > MAX_AUTH_BYTES) {
crypto/krb5/src/lib/rpc/svc_raw.c:55:	char	verf_body[MAX_AUTH_BYTES];
crypto/krb5/src/lib/rpc/rpc_prot.c:65:			&ap->oa_length, MAX_AUTH_BYTES));
crypto/krb5/src/lib/rpc/svc_auth_gss.c:300:	u_char			 rpchdr[32 + MAX_AUTH_BYTES];
```

### Round 3: ❌ INVALID

**🎯 Crux:** xdrmem_create establishes a hard limit (MAX_AUTH_BYTES) that is enforced by the XDR engine during all subsequent encoding operations, preventing memory corruption.

The vulnerability report suggests that `marshal_new_auth` can overflow the `au->au_marshed` buffer because `xdr_opaque_auth` is called twice. However, `marshal_new_auth` initializes the XDR stream using `xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE)`. In the standard RPC XDR implementation, `xdrmem_create` binds the XDR stream to a specific memory buffer and a maximum size. Every subsequent XDR write operation (including `xdr_opaque_auth`) checks the current buffer pointer against the boundary established by `MAX_AUTH_BYTES`. If the write would exceed this limit, the XDR function returns `FALSE` and stops writing. The code in `marshal_new_auth` explicitly checks the return values of both `xdr_opaque_auth` calls; if either fails (e.g., due to buffer exhaustion), it prints an error and does not update `au->au_mpos`. Therefore, the XDR engine's internal bounds checking prevents the overflow.

CRUX: xdrmem_create establishes a hard limit (MAX_AUTH_BYTES) that is enforced by the XDR engine during all subsequent encoding operations, preventing memory corruption.
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
sys/rpc/auth_none.c:91:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
sys/rpc/svc_auth_unix.c:64:	xdrmem_create(&xdrs, msg->rm_call.cb_cred.oa_base, auth_len,
sys/rpc/clnt_nl.c:234:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:242:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:294:	xdrmem_create(&xdrs, mem, len, XDR_ENCODE);
sys/rpc/clnt_bck.c:159:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/rpcsec_tls/auth_tls.c:100:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
sys/rpc/auth_unix.c:197:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/auth_unix.c:269:		xdrmem_create(&txdrs, verf->oa_base, verf->oa_length,
sys/rpc/auth_unix.c:308:	xdrmem_create(&xdrs, au->au_origcred.oa_base,
sys/rpc/auth_unix.c:365:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/rpcsec_gss/rpcsec_gss.c:532:	xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE);
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1427:	xdrmem_create(&xdrs, rqst->rq_cred.oa_base,
sys/rpc/clnt_dg.c:250:	xdrmem_create(&xdrs, cu->cu_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_vc.c:238:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/contrib/openzfs/module/os/linux/spl/spl-xdr.c:136:xdrmem_create(XDR *xdrs, const caddr_t addr, const uint_t size,
sys/contrib/openzfs/module/os/linux/spl/spl-xdr.c:159:EXPORT_SYMBOL(xdrmem_create);
sys/contrib/openzfs/module/nvpair/nvpair.c:3176:		xdrmem_create(xdr, buf, (uint_t)buflen, XDR_ENCODE);
sys/contrib/openzfs/module/nvpair/nvpair.c:3180:		xdrmem_create(xdr, buf, (uint_t)buflen, XDR_DECODE);
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability claims a buffer overflow occurs in `marshal_new_auth` because `xdr_opaque_auth` is called twice. However, the code uses `xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE)`. In the RPC XDR implementation, `xdrmem_create` initializes the XDR stream with a strict boundary (`MAX_AUTH_BYTES`). Every subsequent write operation via the XDR engine (including `xdr_opaque_auth`) checks the current position against this maximum size before writing. If the combined size of the credentials and verifier exceeds 400 bytes, the XDR functions will return FALSE and stop writing, preventing any memory corruption. The check for failure happens after the XDR calls, but since the engine itself prevents the overflow, no vulnerability exists.

