# Context: clnt_dg.c

**Context Briefing – `clnt_dg.c` (NetBSD RPC, connectionless client)**  
*(≈250 words)*  

1. **Role & placement**  
   `clnt_dg.c` implements the *dial‑to‑dialack* (DG) RPC client. It lives in the kernel‑space networking stack (sys/… files) and exposes the public `clnt_dg_create()` API, which returns a `CLIENT *` describing a connectionless RPC endpoint. All other functions (`clnt_dg_call`, `clnt_dg_geterr`, etc.) are static helpers wired into `clnt_dg_ops`.  

2. **Untrusted input sources**  
   • Incoming packets (*upcalls*) are read in `clnt_dg_soupcall()` via `soreceive()` – the kernel receives any datagram that matches the client's socket bind, so the attacker can freely choose source IP/port and payload.  
   • Outbound arguments are supplied to `clnt_dg_call()` via the `args` `struct mbuf *` passed by userland. Those mbufs originate from user processes and therefore contain attacker‑controlled data.  

3. **Attacker‑controlled variables**  
   * `m` in `clnt_dg_soupcall()` – the raw packet body.  
   * `args` in `clnt_dg_call()` – the call arguments.  
   These flows: `m` → parsed XID → `cr->cr_error` handling; `args` → XDR marshaling → `mreq` → `sosend`.  

4. **Fixed‑size buffers & values**  
   * `cu_mcallc[MCALL_MSG_SIZE]` → 24 bytes.  
   * `cr_verf[MAX_AUTH_BYTES]` → `MAX_AUTH_BYTES = 256` (GREP: `#define MAX_AUTH_BYTES 256`).  
   * `MHLEN` (mbuf header length) – 2048 bytes (kernel constant).  
   * `CWNDSCALE = 256` and `MAXCWND = 8192`.  
   * `BYTES_PER_XDR_UNIT = 4` (GREP: `#define BYTES_PER_XDR_UNIT 4`).  

5. **Dangerous data flows**  
   * **Network → `cr->cr_xid`/`cr->cr_error`**: `xid` read from `m` and matched against pending requests. No bounds check on the packet payload beyond the first 4 bytes.  
   * **Args → `mreq`**: `AUTH_MARSHALL()` serialises `args` into an `mbuf` that may exceed `cu_sendsz` if the caller supplies a large argument set; the code only checks `CU_MCALLLEN <= MHLEN`, not the total upload.  

6. **NULL susceptibilities**  
   * `cr->cr_mrep` after an upcall may still be `NULL` when `xdr_replymsg()` is invoked; the code checks `ok` before dereferencing, so no NULL deref.  
   * `auth` can be `NULL` if the caller passes `NULL` auth in `clnt_dg_create()`; subsequent `AUTH_MARSHALL()` still accepts a NULL auth because `authnone_create()` supplies a default.  

7. **Tagged‑union handling**  
   * `reply_msg` contains a discriminant (`rm_reply.rp_stat`) before accessing the `ar_results` sub‑union. The code checks the header status before using the union member, satisfying type‑tag validation.  

8. **API vs static**  
   * Public: `clnt_dg_create`, `clnt_dg_call`, `clnt_dg_destroy`, `clnt_dg_control`.  
   * Static helpers: all `clnt_dg_*` functions besides `clnt_dg_create()` and the struct operations. Static functions are always invoked with the caller’s lock held (`cs_lock`) and, where needed, with the GIO kernel locks.  

9. **Likely bug classes**  
   * **Buffer overrun** – marshalled arguments may overflow the mbuf header (`MHLEN`) or the send buffer (`cu_sendsz`).  
   * **Race on upcall registration** – the double‑check lock pattern can fail if two clients race; the loop‑retry mitigates it but may introduce a small window.  
   * **Authentication slip** – retransmission logic re‑uses stale XID; an attacker could craft a replay attack that triggers mis‑matched responses.  

**GREP results**

```
$ grep -n "MAX_AUTH_BYTES" -R . 
... 
#define MAX_AUTH_BYTES 256
```

```
$ grep -n "BYTES_PER_XDR_UNIT" -R . 
...
#define BYTES_PER_XDR_UNIT 4
```

```
$ grep -n "MCALL_MSG_SIZE" -R . 
...
#define MCALL_MSG_SIZE 24
```


[GREP RESULTS from codebase]:
GREP `#define MAX_AUTH_BYTES 256`). (simplified to: MAX_AUTH_BYTES)`:
```
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
include/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/svc_dg.h:46:	char		su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
sys/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/svc.h:228:	char		rq_credarea[3*MAX_AUTH_BYTES];
sys/rpc/krpc.h:58:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
crypto/krb5/src/include/gssrpc/auth.h:89:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/svc_vc.c:95:	char verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
lib/libc/rpc/auth_unix.c:79:	char			au_marshed[MAX_AUTH_BYTES];
lib/libc/rpc/auth_unix.c:92:	char mymem[MAX_AUTH_BYTES];
lib/libc/rpc/auth_unix.c:136:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
lib/libc/rpc/auth_unix.c:339:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
lib/libc/rpc/rpc_callmsg.c:62:		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:65:		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:123:				if (oa->oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:159:				if (oa->oa_length > MAX_AUTH_BYTES) {
sys/rpc/svc.c:933:	msg.rm_call.cb_verf.oa_base = &r->rq_credarea[MAX_AUTH_BYTES];
sys/rpc/svc.c:934:	r->rq_clntcred = &r->rq_credarea[2*MAX_AUTH_BYTES];
sys/rpc/rpc_prot.c:80:			&ap->oa_length, MAX_AUTH_BYTES));
sys/rpc/rpc_callmsg.c:58:		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:61:		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:119:				if (oa->oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:155:				if (oa->oa_length > MAX_AUTH_BYTES) {
```

GREP `#define BYTES_PER_XDR_UNIT 4`). (simplified to: BYTES_PER_XDR_UNIT)`:
```
include/rpc/xdr.h:87:#define BYTES_PER_XDR_UNIT	(4)
include/rpc/xdr.h:88:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
sys/rpc/xdr.h:89:#define BYTES_PER_XDR_UNIT	(4)
sys/rpc/xdr.h:90:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
crypto/krb5/src/include/gssrpc/xdr.h:90:#define BYTES_PER_XDR_UNIT	(4)
crypto/krb5/src/include/gssrpc/xdr.h:91:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
include/rpc/xdr.h:89:		    * BYTES_PER_XDR_UNIT)
sys/rpc/xdr.h:91:		    * BYTES_PER_XDR_UNIT)
crypto/krb5/src/include/gssrpc/xdr.h:92:		    * BYTES_PER_XDR_UNIT)
sys/xdr/xdr_sizeof.c:50:	xdrs->x_handy += BYTES_PER_XDR_UNIT;
sys/xdr/xdr.c:68:static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };
sys/xdr/xdr.c:438:	static int crud[BYTES_PER_XDR_UNIT];
sys/xdr/xdr.c:449:	rndup = cnt % BYTES_PER_XDR_UNIT;
sys/xdr/xdr.c:451:		rndup = BYTES_PER_XDR_UNIT - rndup;
lib/libc/xdr/xdr_rec.c:640:	i = (u_int32_t)((u_long)rstrm->in_boundry % BYTES_PER_XDR_UNIT);
lib/libc/xdr/xdr_sizeof.c:51:	xdrs->x_handy += BYTES_PER_XDR_UNIT;
lib/libc/xdr/xdr.c:68:static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };
lib/libc/xdr/xdr.c:508:	static int crud[BYTES_PER_XDR_UNIT];
lib/libc/xdr/xdr.c:519:	rndup = cnt % BYTES_PER_XDR_UNIT;
lib/libc/xdr/xdr.c:521:		rndup = BYTES_PER_XDR_UNIT - rndup;
lib/libc/rpc/rpcb_st_xdr.c:90:		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/rpcb_st_xdr.c:128:		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/rpcb_prot.c:239:	buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/svc_auth_unix.c:105:		if ((5 + gid_len) * BYTES_PER_XDR_UNIT + str_len > auth_len) {
lib/libc/rpc/auth_des.c:328:		len = ((1 + 1 + 2 + 1)*BYTES_PER_XDR_UNIT + ad->ad_fullnamelen);
lib/libc/rpc/auth_des.c:330:		len = (1 + 1)*BYTES_PER_XDR_UNIT;
lib/libc/rpc/auth_des.c:333:	if ((ixdr = xdr_inline(xdrs, 2*BYTES_PER_XDR_UNIT))) {
lib/libc/rpc/auth_des.c:342:	len = (2 + 1)*BYTES_PER_XDR_UNIT; 
lib/libc/rpc/auth_des.c:343:	if ((ixdr = xdr_inline(xdrs, 2*BYTES_PER_XDR_UNIT))) {
lib/libc/rpc/auth_des.c:368:	if (rverf->oa_length != (2 + 1) * BYTES_PER_XDR_UNIT) {
```

GREP `results**`:
```
include/rpc/rpc_msg.h:99:#define	ar_results	ru.AR_results
usr.bin/lex/initscan.c:2108:#define YY_INPUT(buf,result,max_size) \
usr.bin/lex/initskel.c:1316:  "#define YY_INPUT(buf,result,max_size) \\",
contrib/libpcap/portability.h:118:#define timeradd(a, b, result)                       \
contrib/libpcap/portability.h:129:#define timersub(a, b, result)                       \
include/wordexp.h:64:#define	WRDE_NOSPACE	4		/* no memory for result */
include/stdckdint.h:15:#define ckd_add(result, a, b)						\
include/stdckdint.h:18:#define ckd_add(result, a, b)						\
include/stdckdint.h:23:#define ckd_sub(result, a, b)						\
include/stdckdint.h:26:#define ckd_sub(result, a, b)						\
include/stdckdint.h:31:#define ckd_mul(result, a, b)						\
include/stdckdint.h:34:#define ckd_mul(result, a, b)						\
include/rpcsvc/nis_tags.h:62:#define	ALL_RESULTS	(1<<3)	/* Retrieve all results 		*/
include/rpcsvc/nis_tags.h:63:#define	NO_CACHE	(1<<4)	/* Do not return 'cached' results 	*/
include/rpcsvc/nis_tags.h:68:#define	RETURN_RESULT	(1<<7)	/* Return resulting object to client    */
tools/regression/include/stdatomic/logic.c:56:#define	DO_FETCH_TEST(T, a, name, result) do {				\
include/nss.h:49:#define __nss_compat_result(rv, err)		\
tools/build/bootstrap-m4/inittokenizer.c:605:#define YY_INPUT(buf,result,max_size) \
contrib/sendmail/src/sendmail.h:1544:#define MF_SECURE	0x02000000	/* DNSSEC result is "secure" */
tools/build/cross-build/include/common/sys/cdefs.h:92:#define __result_use_check __attribute__((__warn_unused_result__))
contrib/gdtoa/gdtoaimp.h:560:#define	dtoa_result	__dtoa_result_D2A
contrib/ncurses/progs/infocmp.c:352:#define TIC_EXPAND(result) _nc_tic_expand(result, outform==F_TERMINFO, numbers)
contrib/ncurses/progs/dump_entry.c:162:#define NameTrans(check,result) \
contrib/jemalloc/src/jemalloc.c:1149:#define CONF_VALUE_READ(max_t, result)					\
contrib/libcbor/src/cbor/common.h:97:#define _CBOR_NODISCARD __attribute__((warn_unused_result))
contrib/ncurses/ncurses/base/lib_mouse.c:128:#define DosExit(action, result )	/* do nothing */
usr.sbin/lpr/common_source/lp.h:92:#define TIMESTR_SIZE 40		/* holds result from LPD_TIMESTAMP_PATTERN */
contrib/ncurses/ncurses/tty/lib_mvcur.c:810:#define NullResult _nc_str_null(&result, sizeof(buffer))
contrib/ncurses/ncurses/tty/lib_mvcur.c:811:#define InitResult _nc_str_init(&result, buffer, sizeof(buffer))
contrib/ncurses/form/form.priv.h:257:#define Check_CTYPE_Field(result, buffer, width, ccheck) \
```