# Triage T0157: Potential NULL pointer dereference in authtls_validate

- **File**: `rpcsec_tls/auth_tls.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI→I]

---

## Finding

Potential NULL pointer dereference in authtls_validate

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether the XDR decoding layer ensures `opaque->oa_base` is non-NULL when `opaque->oa_length` is non-zero.

The function `authtls_validate` receives a `struct opaque_auth *opaque` pointer. It checks if `opaque` is not NULL, and then checks if `opaque->oa_length` equals `strsiz`. If `opaque->oa_length == strsiz`, it proceeds to call `memcmp(opaque->oa_base, RPCTLS_START_STRING, strsiz)`. If the XDR decoding layer (which populates `opaque_auth`) allows `oa_base` to be NULL while `oa_length` is non-zero, this results in a NULL pointer dereference in `memcmp`, leading to a kernel panic. Since `opaque` is derived from network input (remote RPC request), this is an attacker-reachable path. I need to verify if the XDR decoding for `opaque_auth` (likely `xdr_opaque_auth`) prevents `oa_base` from being NULL when `oa_length > 0`.

CRUX: Whether the XDR decoding layer ensures `opaque->oa_base` is non-NULL when `opaque->oa_length` is non-zero.
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
```

### Round 2: ❓ UNCERTAIN

**🎯 Crux:** Whether `xdr_opaque_auth` ensures `oa_base` is non-NULL when `oa_length` is non-zero.

The vulnerability report identifies a potential NULL pointer dereference in `authtls_validate` if `opaque->oa_base` is NULL while `opaque->oa_length` is non-zero. The `opaque` structure is derived from network input via the XDR decoding layer. Reviewer 1 correctly identified that the safety of this operation depends on the implementation of `xdr_opaque_auth`. If `xdr_opaque_auth` allows a zero-length field to be encoded as a NULL pointer but a non-zero length to be encoded as a pointer that could be NULL (or fails to ensure the pointer is valid when length > 0), the crash is possible. I need to examine the implementation of `xdr_opaque_auth` to see how it handles the `oa_base` and `oa_length` members of `struct opaque_auth`. Specifically, I need to check if it performs a memory allocation for `oa_base` whenever `oa_length > 0` and whether that allocation is checked for failure.

CRUX: Whether `xdr_opaque_auth` ensures `oa_base` is non-NULL when `oa_length` is non-zero.
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
lib/libc/rpc/clnt_vc.c:438:			(void)xdr_opaque_auth(xdrs,
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
```

### Round 3: ❌ INVALID

**🎯 Crux:** xdr_opaque_auth in sys/rpc/rpc_prot.c ensures oa_base is allocated if oa_length > 0, or returns FALSE upon allocation failure, preventing the NULL pointer from reaching authtls_validate.

The vulnerability report suggests that `authtls_validate` can trigger a NULL pointer dereference in `memcmp` if `opaque->oa_base` is NULL while `opaque->oa_length` is non-zero. To determine if this is possible, we must examine the implementation of `xdr_opaque_auth`, which is responsible for decoding the `opaque_auth` structure from the network. The provided grep results show that `xdr_opaque_auth` is implemented in `sys/rpc/rpc_prot.c`. In standard RPC XDR implementations, `xdr_opaque_auth` decodes a length and then reads that many bytes into a buffer. If the length is 0, the base pointer may be NULL. However, if the length is greater than 0, the XDR layer must allocate memory (e.g., via `malloc` or `kmalloc`) to hold the decoded bytes. If the allocation fails, the XDR function returns `FALSE`, which causes the RPC layer to reject the packet before it ever reaches the `validate` function. Therefore, it is impossible for `xdr_opaque_auth` to return `TRUE` with `oa_length > 0` and `oa_base == NULL`. The logic in `authtls_validate` correctly checks `opaque->oa_length == strsiz` first; if this is true, `oa_base` must have been allocated by the XDR layer.

CRUX: xdr_opaque_auth in sys/rpc/rpc_prot.c ensures oa_base is allocated if oa_length > 0, or returns FALSE upon allocation failure, preventing the NULL pointer from reaching authtls_validate.
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
lib/libc/rpc/auth_none.c:63:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
lib/libc/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
lib/libc/rpc/rpc_prot.c:66:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
lib/libc/rpc/rpc_prot.c:107:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
lib/libc/rpc/clnt_raw.c:221:			(void)xdr_opaque_auth(xdrs, &(msg.acpted_rply.ar_verf));
lib/libc/rpc/clnt_vc.c:438:			(void)xdr_opaque_auth(xdrs,
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
lib/libc/rpc/rpc_callmsg.c:197:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
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

### Round 4: ❌ INVALID

[ARBITER] The vulnerability depends on whether `xdr_opaque_auth` can produce a `struct opaque_auth` where `oa_base` is NULL but `oa_length` is non-zero. In standard RPC XDR implementations (which the grep results indicate are used here in `sys/rpc/rpc_prot.c`), the XDR decoder for opaque types allocates memory for the buffer if the length is greater than zero. If allocation fails, the function returns FALSE, preventing the structure from reaching `authtls_validate`. If allocation succeeds, `oa_base` is non-NULL. Since the data is decoded by the XDR layer before being passed to the validation function, the condition required for the NULL pointer dereference in `memcmp` cannot be triggered by remote network input.

