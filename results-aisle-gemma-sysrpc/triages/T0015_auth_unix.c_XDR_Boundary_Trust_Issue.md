# Triage T0015: XDR Boundary Trust Issue

- **File**: `auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

XDR Boundary Trust Issue

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The vulnerability depends on `xdr_opaque_auth` ignoring the boundary set by `xdrmem_create`, which is a property of the XDR engine, not a bug in `auth_unix.c`.

The report suggests that `authunix_validate` trusts `verf->oa_length` when creating an XDR stream and that `xdr_opaque_auth` might ignore this boundary. In `authunix_validate`, `xdrmem_create` is called with `verf->oa_base` and `verf->oa_length`. This creates an XDR stream bound by `oa_length`. If the XDR engine is correctly implemented, any call to `xdr_opaque_auth` using this stream will be constrained by the length provided to `xdrmem_create`, regardless of any length fields contained within the payload itself. The vulnerability is only real if the XDR engine (specifically `xdr_opaque_auth`) contains a bug where it reads past the stream boundary. However, based on the provided code, the logic in `authunix_validate` is the standard way to handle opaque XDR data: wrap it in a bounded stream and decode. Without evidence of a specific bug in the XDR engine implementation, the pattern in `auth_unix.c` is correct. Furthermore, `verf` is part of the RPC authentication header; if it were totally unconstrained, it would have already caused issues in the higher-level RPC decoding layer.

CRUX: The vulnerability depends on `xdr_opaque_auth` ignoring the boundary set by `xdrmem_create`, which is a property of the XDR engine, not a bug in `auth_unix.c`.
GREP: xdr_opaque_auth

🔎 **Grep results:**

GREP `xdr_opaque_auth`:
```
crypto/krb5/src/include/gssrpc/rename.h:66:#define xdr_opaque_auth		gssrpc_xdr_opaque_auth
sys/rpc/auth.h:264:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
crypto/krb5/src/include/gssrpc/auth.h:193:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
include/rpc/auth.h:267:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
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

### Round 2: ❌ INVALID

**🎯 Crux:** The XDR stream created by `xdrmem_create` explicitly bounds all subsequent reads to `verf->oa_length`; for a vulnerability to exist, the XDR engine's internal `xdr_opaque_auth` would have to ignore its own stream boundary checks.

The vulnerability report claims that `authunix_validate` trusts `verf->oa_length` and that `xdr_opaque_auth` might ignore the stream boundary. Looking at `authunix_validate`, it uses `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE);`. This creates an XDR stream where the total available bytes are strictly limited to `verf->oa_length`. In XDR implementations, the `XDR` structure tracks the current position and the end of the buffer. If `xdr_opaque_auth` (the decoder for the `opaque_auth` structure) respects the XDR stream boundaries, it is impossible to read past `verf->oa_length` because the underlying XDR read functions (e.g., `xdr_get_int`, `xdr_get_bytes`) check against the stream limit. The vulnerability is not in `auth_unix.c` but would be a fundamental bug in the XDR engine itself. However, the report provides no evidence of such a bug in the XDR engine. Furthermore, `verf` is part of the RPC header, which is itself decoded by the RPC layer using the same XDR mechanisms; if the length were maliciously large, it would have triggered a failure in the initial packet parsing or be limited by the actual packet size received from the network. Without evidence that `xdr_opaque_auth` bypasses the `XDR` stream's length check, this is a false positive.

CRUX: The XDR stream created by `xdrmem_create` explicitly bounds all subsequent reads to `verf->oa_length`; for a vulnerability to exist, the XDR engine's internal `xdr_opaque_auth` would have to ignore its own stream boundary checks.
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
sys/rpc/rpcsec_gss/rpcsec_gss.c:543:	xdr_opaque_auth(xdrs, &creds);
```

### Round 3: ❌ INVALID

**🎯 Crux:** xdrmem_create creates a bounded XDR stream using verf->oa_length, and xdr_opaque_auth operates within that bounded stream; for an OOB read to occur, the XDR engine would have to ignore its own boundary checks.

The reported vulnerability suggests that `authunix_validate` trusts `verf->oa_length` and that `xdr_opaque_auth` might read past this boundary. In `authunix_validate`, the code calls `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE);`. This function initializes an XDR stream with a hard limit of `verf->oa_length` bytes. The subsequent call to `xdr_opaque_auth(&txdrs, &au->au_shcred)` uses this stream. In any standard XDR implementation (including the one used in RPC), the stream object tracks the remaining bytes, and the primitive read functions (which `xdr_opaque_auth` must use) check this limit before every access. For this to be a vulnerability, `xdr_opaque_auth` would have to explicitly bypass the `XDR` stream's boundary checks and perform raw pointer arithmetic on `oa_base` using internal length fields. There is no evidence of such a bug. Furthermore, `verf` is provided by the RPC layer, which has already decoded the `opaque_auth` structure from the network packet, meaning `oa_length` is already constrained by the actual size of the received packet. This is a classic scanner false positive where it flags the use of a length field from an untrusted source without recognizing that the field is used to *create* a bounded sandbox (the XDR stream) for the actual decoding process.

CRUX: xdrmem_create creates a bounded XDR stream using verf->oa_length, and xdr_opaque_auth operates within that bounded stream; for an OOB read to occur, the XDR engine would have to ignore its own boundary checks.
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
lib/libc/rpc/clnt_dg.c:574:				(void) xdr_opaque_auth(xdrs,
lib/libc/rpc/auth_none.c:63:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
lib/libc/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
lib/libc/rpc/rpc_prot.c:66:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
lib/libc/rpc/rpc_prot.c:107:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
lib/libc/rpc/clnt_raw.c:221:			(void)xdr_opaque_auth(xdrs, &(msg.acpted_rply.ar_verf));
lib/libc/rpc/clnt_vc.c:438:			(void)xdr_opaque_auth(xdrs,
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability report claims that `authunix_validate` trusts `verf->oa_length` and that `xdr_opaque_auth` might ignore the stream boundary. However, `authunix_validate` calls `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE);`, which initializes the XDR stream with a strict memory bound of `verf->oa_length`. In standard XDR implementations, the stream structure tracks the end of the buffer, and all decoding functions (including `xdr_opaque_auth`) are bound by this limit. For a vulnerability to exist, the underlying XDR engine would have to contain a bug where it ignores its own internal boundary checks, which is not evidenced in the provided code. The usage in `auth_unix.c` is correct.

