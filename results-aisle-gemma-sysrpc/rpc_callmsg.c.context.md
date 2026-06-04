# Context: rpc_callmsg.c

This briefing covers `rpc_callmsg.c`, which implements the XDR (External Data Representation) serialization and deserialization for RPC call messages.

**1. Project Role:** This code is part of the RPC (Remote Procedure Call) layer. It handles the translation of `struct rpc_msg` between memory and a network-ready stream.

**2. Input Vector:** Untrusted input arrives via the network, passed into `xdr_callmsg` through the `XDR *xdrs` handle during `XDR_DECODE` operations.

**3. Attacker-Controlled Data:**
*   **Data Flow:** Network $\rightarrow$ `xdrs` $\rightarrow$ `IXDR_GET_*` / `xdr_*` helpers $\rightarrow$ `struct rpc_msg *cmsg`.
*   **Key Fields:** `cmsg->rm_xid`, `cmsg->rm_direction`, `cmsg->rm_call.cb_rpcvers`, `cmsg->rm_call.cb_prog`, `cmsg->rm_call.cb_vers`, `cmsg->rm_call.cb_proc`, and the `opaque_auth` structures `cb_cred` and `cb_verf` (specifically `oa_flavor`, `oa_length`, and the data at `oa_base`).

**4. Fixed-Size Buffers & Constants:**
*   `MAX_AUTH_BYTES`: GREP: `MAX_AUTH_BYTES` (Likely 1024 or 2048; requires grep for exact value).
*   `BYTES_PER_XDR_UNIT`: GREP: `BYTES_PER_XDR_UNIT` (Standard XDR is 4 bytes).
*   `RPC_MSG_VERSION`: GREP: `RPC_MSG_VERSION` (Standard is 2).

**5. Dangerous Data Flows:**
*   **Source:** `IXDR_GET_UINT32(buf)` $\rightarrow$ **Destination:** `oa->oa_length` $\rightarrow$ **Function:** `mem_alloc(oa->oa_length)`.
*   **Source:** `xdrs` stream $\rightarrow$ **Destination:** `oa->oa_base` $\rightarrow$ **Function:** `memcpy(oa->oa_base, buf, oa->oa_length)`. Buffer size is determined by the `mem_alloc` call based on the attacker-supplied `oa_length` (capped by `MAX_AUTH_BYTES`).

**6. NULL Dereferences:**
*   `cmsg` is dereferenced throughout without a NULL check.
*   `xdrs` is dereferenced (`xdrs->x_op`) without a NULL check.

**7. Tagged Unions:**
*   `struct rpc_msg` uses a union for different message types. The code checks `cmsg->rm_direction == CALL` before accessing `rm_call` members.

**8. API Visibility:**
*   `xdr_callmsg`: Public API (XDR dispatcher).
*   `IXDR_*` and `xdr_*` functions: External helper utilities.

**9. Likely Bug Classes:**
*   **Integer Overflows:** Specifically in `RNDUP(oa->oa_length)` calculations.
*   **Memory Leaks:** `oa->oa_base` is allocated via `mem_alloc` but not freed within this function if subsequent decoding fails.
*   **Heap Overflows:** If `RNDUP` or `XDR_INLINE` calculations mismatch the `memcpy` size.

[GREP RESULTS from codebase]:
GREP `MAX_AUTH_BYTES`:
```
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/svc.h:228:	char		rq_credarea[3*MAX_AUTH_BYTES];
sys/rpc/krpc.h:58:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
crypto/krb5/src/include/gssrpc/auth.h:89:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/svc_dg.h:46:	char		su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
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
lib/librpcsec_gss/rpcsec_gss.c:568:	char			 credbuf[MAX_AUTH_BYTES];
lib/librpcsec_gss/rpcsec_gss.c:569:	char			 tmpheader[MAX_AUTH_BYTES];
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
```

GREP `BYTES_PER_XDR_UNIT` (Standard XDR is 4 bytes). (simplified to: BYTES_PER_XDR_UNIT)`:
```
crypto/krb5/src/include/gssrpc/xdr.h:90:#define BYTES_PER_XDR_UNIT	(4)
crypto/krb5/src/include/gssrpc/xdr.h:91:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
include/rpc/xdr.h:87:#define BYTES_PER_XDR_UNIT	(4)
include/rpc/xdr.h:88:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
sys/rpc/xdr.h:89:#define BYTES_PER_XDR_UNIT	(4)
sys/rpc/xdr.h:90:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
crypto/krb5/src/include/gssrpc/xdr.h:92:		    * BYTES_PER_XDR_UNIT)
include/rpc/xdr.h:89:		    * BYTES_PER_XDR_UNIT)
sys/rpc/xdr.h:91:		    * BYTES_PER_XDR_UNIT)
lib/librpcsec_gss/svc_rpcsec_gss.c:763:	if (oa->oa_length > sizeof(rpchdr) - 8 * BYTES_PER_XDR_UNIT) {
lib/libc/xdr/xdr_sizeof.c:51:	xdrs->x_handy += BYTES_PER_XDR_UNIT;
lib/libc/xdr/xdr_rec.c:640:	i = (u_int32_t)((u_long)rstrm->in_boundry % BYTES_PER_XDR_UNIT);
lib/libc/xdr/xdr.c:68:static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };
lib/libc/xdr/xdr.c:508:	static int crud[BYTES_PER_XDR_UNIT];
lib/libc/xdr/xdr.c:519:	rndup = cnt % BYTES_PER_XDR_UNIT;
lib/libc/xdr/xdr.c:521:		rndup = BYTES_PER_XDR_UNIT - rndup;
lib/libc/rpc/rpcb_st_xdr.c:90:		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/rpcb_st_xdr.c:128:		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/svc_auth_unix.c:105:		if ((5 + gid_len) * BYTES_PER_XDR_UNIT + str_len > auth_len) {
lib/libc/rpc/rpcb_prot.c:239:	buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/auth_des.c:328:		len = ((1 + 1 + 2 + 1)*BYTES_PER_XDR_UNIT + ad->ad_fullnamelen);
lib/libc/rpc/auth_des.c:330:		len = (1 + 1)*BYTES_PER_XDR_UNIT;
lib/libc/rpc/auth_des.c:333:	if ((ixdr = xdr_inline(xdrs, 2*BYTES_PER_XDR_UNIT))) {
lib/libc/rpc/auth_des.c:342:	len = (2 + 1)*BYTES_PER_XDR_UNIT; 
lib/libc/rpc/auth_des.c:343:	if ((ixdr = xdr_inline(xdrs, 2*BYTES_PER_XDR_UNIT))) {
lib/libc/rpc/auth_des.c:368:	if (rverf->oa_length != (2 + 1) * BYTES_PER_XDR_UNIT) {
lib/libc/rpc/rpc_callmsg.c:68:		buf = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT
lib/libc/rpc/rpc_callmsg.c:70:			+ 2 * BYTES_PER_XDR_UNIT
lib/libc/rpc/rpc_callmsg.c:105:		buf = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/rpc_callmsg.c:148:			buf = XDR_INLINE(xdrs, 2 * BYTES_PER_XDR_UNIT);
```

GREP `RPC_MSG_VERSION` (Standard is 2). (simplified to: RPC_MSG_VERSION)`:
```
sys/rpc/rpc_msg.h:43:#define RPC_MSG_VERSION		((uint32_t) 2)
contrib/tcpdump/rpc_msg.h:41:#define SUNRPC_MSG_VERSION	((uint32_t) 2)
include/rpc/rpc_msg.h:43:#define RPC_MSG_VERSION		((u_int32_t) 2)
crypto/krb5/src/include/gssrpc/rpc_msg.h:46:#define RPC_MSG_VERSION		((uint32_t) 2)
usr.sbin/rpcbind/rpcb_svc_com.c:789:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
sys/rpc/clnt_bck.c:152:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
sys/rpc/rpc_prot.c:229:	cmsg->rm_call.cb_rpcvers = RPC_MSG_VERSION;
sys/rpc/rpc_callmsg.c:75:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
sys/rpc/rpc_callmsg.c:109:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
sys/rpc/rpc_callmsg.c:188:	    (cmsg->rm_call.cb_rpcvers == RPC_MSG_VERSION) &&
sys/rpc/clnt_nl.c:216:			.cb_rpcvers = RPC_MSG_VERSION,
sys/rpc/clnt_vc.c:231:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/rpc_prot.c:210:	cmsg->rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/clnt_raw.c:112:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/rpc_callmsg.c:79:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
lib/libc/rpc/rpc_callmsg.c:113:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
lib/libc/rpc/rpc_callmsg.c:192:	    (cmsg->rm_call.cb_rpcvers == RPC_MSG_VERSION) &&
lib/libc/rpc/clnt_bcast.c:376:	msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/clnt_vc.c:269:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
contrib/tcpdump/print-sunrpc.c:200:	if (x != SUNRPC_MSG_VERSION)
crypto/krb5/src/lib/rpc/rpc_prot.c:165:	cmsg->rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/clnt_raw.c:110:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/rpc_callmsg.c:74:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
crypto/krb5/src/lib/rpc/rpc_callmsg.c:110:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
crypto/krb5/src/lib/rpc/rpc_callmsg.c:187:	    (cmsg->rm_call.cb_rpcvers == RPC_MSG_VERSION) &&
crypto/krb5/src/lib/rpc/pmap_rmt.c:305:	msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/clnt_tcp.c:208:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/clnt_udp.c:171:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
```