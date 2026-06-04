# Triage T0131: Heap-based Buffer Overflow / Memory Exhaustion in `rpc_gss_validate`

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Heap-based Buffer Overflow / Memory Exhaustion in `rpc_gss_validate`

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The function `rpc_gss_validate` performs a `mem_alloc` and `memcpy` using `verf->oa_length` without any upper-bound validation, and `verf` is supplied by the remote server.

The vulnerability is located in `rpc_gss_validate`. When `gd->gd_state == RPCSEC_GSS_CONTEXT`, the code allocates memory for `gd->gd_verf.value` using `mem_alloc(verf->oa_length)` and then performs a `memcpy` of `verf->oa_length` bytes. The `struct opaque_auth *verf` is derived from the RPC layer's authentication verifier, which is provided by the remote server. In an RPC client context, the server controls the verifier sent back to the client. Since there is no upper bound check on `verf->oa_length` before the allocation and copy, a malicious server can provide a very large `oa_length` to cause memory exhaustion (DoS) or potentially trigger an integer overflow if `mem_alloc` or the underlying kernel allocator handles large sizes poorly. The input is externally controllable as it comes from the network via the RPC protocol's verifier field.

CRUX: The function `rpc_gss_validate` performs a `mem_alloc` and `memcpy` using `verf->oa_length` without any upper-bound validation, and `verf` is supplied by the remote server.
GREP: opaque_auth

🔎 **Grep results:**

GREP `opaque_auth`:
```
crypto/krb5/src/include/gssrpc/rename.h:66:#define xdr_opaque_auth		gssrpc_xdr_opaque_auth
sys/rpc/auth.h:166:struct opaque_auth {
sys/rpc/auth.h:178:	struct	opaque_auth	ah_cred;
sys/rpc/auth.h:179:	struct	opaque_auth	ah_verf;
sys/rpc/auth.h:188:		    struct opaque_auth *, struct mbuf **);
sys/rpc/auth.h:204: * struct opaque_auth verf;
sys/rpc/auth.h:222:extern struct opaque_auth _null_auth;
sys/rpc/auth.h:264:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
sys/rpc/rpc_msg.h:86:	struct opaque_auth	ar_verf;
sys/rpc/rpc_msg.h:140:	struct opaque_auth cb_cred;
sys/rpc/rpc_msg.h:141:	struct opaque_auth cb_verf; /* protocol specific - provided by client */
sys/rpc/svc.h:218:	struct opaque_auth rq_cred;	/* raw creds from the wire */
sys/rpc/svc.h:219:	struct opaque_auth rq_verf;	/* verifier for the reply */
contrib/tcpdump/rpc_auth.h:67:struct sunrpc_opaque_auth {
contrib/tcpdump/rpc_msg.h:109:	struct sunrpc_opaque_auth cb_cred;
crypto/krb5/src/include/gssrpc/auth.h:86:struct opaque_auth {
crypto/krb5/src/include/gssrpc/auth.h:99:	struct	opaque_auth	ah_cred;
crypto/krb5/src/include/gssrpc/auth.h:100:	struct	opaque_auth	ah_verf;
crypto/krb5/src/include/gssrpc/auth.h:108:				       struct opaque_auth *);
crypto/krb5/src/include/gssrpc/auth.h:130: * struct opaque_auth verf;
crypto/krb5/src/include/gssrpc/auth.h:173:extern struct opaque_auth gssrpc__null_auth;
crypto/krb5/src/include/gssrpc/auth.h:193:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
crypto/krb5/src/include/gssrpc/auth_unix.h:77:	struct opaque_auth new_cred;
crypto/krb5/src/include/gssrpc/svc.h:102:	struct opaque_auth xp_verf;	 /* raw response verifier */
crypto/krb5/src/include/gssrpc/svc.h:171:	struct opaque_auth rq_cred;	/* raw creds from the wire */
crypto/krb5/src/include/gssrpc/rpc_msg.h:89:	struct opaque_auth	ar_verf;
crypto/krb5/src/include/gssrpc/rpc_msg.h:143:	struct opaque_auth cb_cred;
crypto/krb5/src/include/gssrpc/rpc_msg.h:144:	struct opaque_auth cb_verf; /* protocol specific - provided by client */
include/rpc/auth_unix.h:78:	struct opaque_auth new_cred;
include/rpc/auth.h:166:struct opaque_auth {
```

### Round 2: ✅ VALID

**🎯 Crux:** rpc_gss_validate allocates and copies memory based on verf->oa_length, which is provided by the remote server without any upper-bound validation.

The vulnerability exists in `rpc_gss_validate`. When the GSS state is `RPCSEC_GSS_CONTEXT`, the function takes a `struct opaque_auth *verf` (which is parsed from the network packet by the RPC layer) and uses `verf->oa_length` directly to allocate memory via `mem_alloc` and copy data via `memcpy`. There is no upper-bound check on `verf->oa_length`. Since this is the client-side implementation of RPCSEC_GSS, a malicious or compromised server can send a crafted RPC response with a massive `oa_length`, leading to kernel heap exhaustion and a resulting Denial of Service (kernel panic/crash). I verified that `opaque_auth` is used for network-received verifiers. While `mem_alloc` might fail and return NULL (which is handled), an attacker can send many requests with large lengths or a length just below the failure threshold to exhaust kernel memory. There are no global limits on `oa_length` visible in the provided code or the `opaque_auth` definition.

CRUX: rpc_gss_validate allocates and copies memory based on verf->oa_length, which is provided by the remote server without any upper-bound validation.
GREP: xdr_opaque_auth

🔎 **Grep results:**

GREP `xdr_opaque_auth`:
```
crypto/krb5/src/include/gssrpc/rename.h:66:#define xdr_opaque_auth		gssrpc_xdr_opaque_auth
sys/rpc/auth.h:264:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
include/rpc/auth.h:267:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
crypto/krb5/src/include/gssrpc/auth.h:193:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/librpcsec_gss/rpcsec_gss.c:601:	    !xdr_opaque_auth(&tmpxdrs, &creds)) {
lib/librpcsec_gss/rpcsec_gss.c:616:		if (!xdr_opaque_auth(xdrs, &_null_auth)) {
lib/librpcsec_gss/rpcsec_gss.c:645:		xdr_stat = xdr_opaque_auth(xdrs, &verf);
sys/rpc/auth_none.c:92:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/auth_none.c:93:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/rpc_prot.c:72:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
sys/rpc/rpc_prot.c:100:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
sys/rpc/rpcsec_tls/auth_tls.c:101:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/rpcsec_tls/auth_tls.c:102:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/rpc_callmsg.c:192:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
sys/rpc/rpc_callmsg.c:193:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
sys/rpc/auth_unix.c:277:		if (xdr_opaque_auth(&txdrs, &au->au_shcred)) {
sys/rpc/auth_unix.c:281:			(void)xdr_opaque_auth(&txdrs, &au->au_shcred);
sys/rpc/auth_unix.c:366:	if ((! xdr_opaque_auth(xdrs, &(auth->ah_cred))) ||
sys/rpc/auth_unix.c:367:	    (! xdr_opaque_auth(xdrs, &(auth->ah_verf))))
sys/rpc/rpcsec_gss/rpcsec_gss.c:543:	xdr_opaque_auth(xdrs, &creds);
sys/rpc/rpcsec_gss/rpcsec_gss.c:547:		if (!xdr_opaque_auth(xdrs, &_null_auth)) {
sys/rpc/rpcsec_gss/rpcsec_gss.c:591:		xdr_stat = xdr_opaque_auth(xdrs, &verf);
lib/libc/rpc/auth_none.c:63:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
lib/libc/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
lib/libc/rpc/rpc_prot.c:66:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
lib/libc/rpc/rpc_prot.c:107:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
lib/libc/rpc/clnt_raw.c:221:			(void)xdr_opaque_auth(xdrs, &(msg.acpted_rply.ar_verf));
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
lib/libc/rpc/rpc_callmsg.c:197:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
```

### Round 3: ✅ VALID

**🎯 Crux:** rpc_gss_validate allocates memory and copies data using verf->oa_length, which is supplied by the remote server, without any upper-bound validation.

The vulnerability is in `rpc_gss_validate`. When the state is `RPCSEC_GSS_CONTEXT`, the code performs `gd->gd_verf.value = mem_alloc(verf->oa_length);` and a subsequent `memcpy`. The `verf` object is a `struct opaque_auth` parsed from the network via `xdr_opaque_auth`. In an RPC client context, the server provides the verifier in the response. Since there is no upper bound check on `verf->oa_length`, a malicious server can send a very large length value. While `mem_alloc` returning NULL is handled, the lack of a reasonable upper bound allows an attacker to trigger significant memory pressure or exhaust the kernel heap, leading to a Denial of Service (kernel panic or hang). This is a classic memory exhaustion vulnerability where untrusted length fields from the network are passed directly to an allocator.

CRUX: rpc_gss_validate allocates memory and copies data using verf->oa_length, which is supplied by the remote server, without any upper-bound validation.
GREP: xdr_opaque_auth

🔎 **Grep results:**

GREP `xdr_opaque_auth`:
```
crypto/krb5/src/include/gssrpc/rename.h:66:#define xdr_opaque_auth		gssrpc_xdr_opaque_auth
sys/rpc/auth.h:264:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
include/rpc/auth.h:267:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
crypto/krb5/src/include/gssrpc/auth.h:193:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
sys/rpc/auth_none.c:92:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/auth_none.c:93:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/rpc_prot.c:72:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
sys/rpc/rpc_prot.c:100:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
sys/rpc/rpc_callmsg.c:192:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
sys/rpc/rpc_callmsg.c:193:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
sys/rpc/rpcsec_tls/auth_tls.c:101:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/rpcsec_tls/auth_tls.c:102:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/auth_unix.c:277:		if (xdr_opaque_auth(&txdrs, &au->au_shcred)) {
sys/rpc/auth_unix.c:281:			(void)xdr_opaque_auth(&txdrs, &au->au_shcred);
sys/rpc/auth_unix.c:366:	if ((! xdr_opaque_auth(xdrs, &(auth->ah_cred))) ||
sys/rpc/auth_unix.c:367:	    (! xdr_opaque_auth(xdrs, &(auth->ah_verf))))
sys/rpc/rpcsec_gss/rpcsec_gss.c:543:	xdr_opaque_auth(xdrs, &creds);
sys/rpc/rpcsec_gss/rpcsec_gss.c:547:		if (!xdr_opaque_auth(xdrs, &_null_auth)) {
sys/rpc/rpcsec_gss/rpcsec_gss.c:591:		xdr_stat = xdr_opaque_auth(xdrs, &verf);
lib/librpcsec_gss/rpcsec_gss.c:601:	    !xdr_opaque_auth(&tmpxdrs, &creds)) {
lib/librpcsec_gss/rpcsec_gss.c:616:		if (!xdr_opaque_auth(xdrs, &_null_auth)) {
lib/librpcsec_gss/rpcsec_gss.c:645:		xdr_stat = xdr_opaque_auth(xdrs, &verf);
lib/libc/rpc/auth_none.c:63:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
lib/libc/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
lib/libc/rpc/rpc_prot.c:66:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
lib/libc/rpc/rpc_prot.c:107:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
lib/libc/rpc/clnt_raw.c:221:			(void)xdr_opaque_auth(xdrs, &(msg.acpted_rply.ar_verf));
lib/libc/rpc/clnt_vc.c:438:			(void)xdr_opaque_auth(xdrs,
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
```

### Round 4: ✅ VALID

[ARBITER] In `rpc_gss_validate`, the code allocates memory for `gd->gd_verf.value` using `mem_alloc(verf->oa_length)` and subsequently performs a `memcpy` of `verf->oa_length` bytes. The `verf` pointer refers to a `struct opaque_auth` which is parsed from the network via XDR. Because there is no upper-bound check on `verf->oa_length` before the allocation and copy, a malicious remote server can send a crafted packet with a very large length value to cause memory exhaustion (leading to a kernel panic) or trigger integer-related allocation issues.

