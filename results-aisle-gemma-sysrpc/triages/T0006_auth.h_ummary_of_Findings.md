# Triage T0006: ummary of Findings

- **File**: `auth.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

ummary of Findings

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether `_svcauth_unix` or `xdr_opaque_auth` validates `oa_length` against the expected size of the flavor-specific structure before processing it.

The scanner reports three primary issues. 
1. **Flavor Type Confusion/Over-read**: The `struct opaque_auth` uses `oa_flavor` to cast `oa_base`. This is a common pattern in RPC. The security of this depends on whether the functions implementing `ah_validate` or `_svcauth_*` check `oa_length` before accessing `oa_base`. Since the data flows from `xdr_opaque_auth`, we need to see the implementation of the decoder and the validators.
2. **Null Pointer Dereference in Macros**: The `AUTH_*` macros dereference `ah_ops`. In this architecture, `AUTH` handles are typically created via `authunix_create`, `authnone_create`, etc., which initialize the `ah_ops` table. A NULL `ah_ops` would only occur if an uninitialized or corrupted `AUTH` handle is used. Since `AUTH` handles are internal state managed by the RPC library (not directly sent over the wire), this is likely a code quality issue or requires a separate memory corruption bug to be exploitable.
3. **Fixed-size Buffer Overflow**: The report mentions `authunix_create` and `AUTH_SYS_MAX_HOSTNAME`. `authunix_create` is a client-side function used to *create* credentials. The server-side equivalent (where untrusted input is processed) would be `_svcauth_unix`. We need to check how `_svcauth_unix` handles the incoming `opaque_auth` and if it uses `strncpy`/`memcpy` with the constants provided.

CRUX: Whether `_svcauth_unix` or `xdr_opaque_auth` validates `oa_length` against the expected size of the flavor-specific structure before processing it.
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
sys/rpc/rpc_callmsg.c:192:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
sys/rpc/rpc_callmsg.c:193:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
sys/rpc/rpcsec_tls/auth_tls.c:101:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/rpcsec_tls/auth_tls.c:102:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/auth_unix.c:277:		if (xdr_opaque_auth(&txdrs, &au->au_shcred)) {
```

### Round 2: ❓ UNCERTAIN

**🎯 Crux:** Whether `_svcauth_unix` or `xdr_opaque_auth` validates `oa_length` against the size requirements of the `oa_flavor` before accessing `oa_base`.

I have analyzed the reported vulnerabilities. 

1. **Null Pointer Dereference in Macros**: These macros (`AUTH_NEXTVERF`, etc.) operate on `AUTH` handles. As noted by Reviewer 1, these handles are internal state managed by the RPC library. They are created by specific factory functions (e.g., `authunix_create`) which populate the `ah_ops` table. An attacker cannot provide a raw `AUTH` structure over the wire; they provide `opaque_auth` credentials. Therefore, triggering a NULL `ah_ops` dereference would require a pre-existing memory corruption vulnerability. This is a code quality/internal API issue, not a direct external vulnerability.

2. **Fixed-size Buffer Overflow in `authunix_create`**: The scanner flags `authunix_create` and constants like `AUTH_SYS_MAX_HOSTNAME`. However, `authunix_create` is a client-side function used to generate credentials for an outgoing request. Untrusted input is processed on the server side, primarily in `_svcauth_unix`. The presence of a constant in a header does not prove an overflow exists; it often indicates the presence of a bound. 

3. **Buffer Over-read via `oa_flavor`**: This is the most plausible concern. The `opaque_auth` structure contains a flavor and a length. If `_svcauth_unix` (or other flavor handlers) casts `oa_base` to a structure without verifying `oa_length` is sufficient for that structure, an over-read occurs. However, `xdr_opaque_auth` is the entry point for this data. I need to verify if `xdr_opaque_auth` or the subsequent `_svcauth_*` handlers perform the necessary length checks against the flavor's expected size.

Since I haven't seen the implementation of `xdr_opaque_auth` or `_svcauth_unix`, I must verify if they enforce `MAX_AUTH_BYTES` and flavor-specific lengths.

CRUX: Whether `_svcauth_unix` or `xdr_opaque_auth` validates `oa_length` against the size requirements of the `oa_flavor` before accessing `oa_base`.
GREP: _svcauth_unix

🔎 **Grep results:**

GREP `_svcauth_unix`:
```
sys/rpc/auth.h:342:enum auth_stat _svcauth_unix (struct svc_req *, struct rpc_msg *);
crypto/krb5/src/include/gssrpc/svc_auth.h:91:/* RENAMED: should be _svcauth_unix. */
crypto/krb5/src/include/gssrpc/svc_auth.h:92:enum auth_stat gssrpc__svcauth_unix(struct svc_req *,
include/rpc/auth.h:346:enum auth_stat _svcauth_unix (struct svc_req *, struct rpc_msg *);
sys/rpc/svc_auth_unix.c:36: * _svcauth_unix does full blown unix style uid,gid+gids auth,
sys/rpc/svc_auth_unix.c:54:_svcauth_unix(struct svc_req *rqst, struct rpc_msg *msg)
sys/rpc/svc_auth.c:95:		dummy = _svcauth_unix(rqst, msg);
lib/libc/rpc/svc_auth_unix.c:35: * _svcauth_unix does full blown unix style uid,gid+gids auth,
lib/libc/rpc/svc_auth_unix.c:54:_svcauth_unix(struct svc_req *rqst, struct rpc_msg *msg)
lib/libc/rpc/svc_auth.c:112:		dummy = _svcauth_unix(rqst, msg);
crypto/krb5/src/lib/rpc/svc_auth_unix.c:42: * _svcauth_unix does full blown unix style uid,gid+gids auth,
crypto/krb5/src/lib/rpc/svc_auth_unix.c:55:gssrpc__svcauth_unix(
crypto/krb5/src/lib/rpc/svc_auth.c:62:     {AUTH_UNIX, gssrpc__svcauth_unix},		/* AUTH_UNIX */
```

### Round 3: ❓ UNCERTAIN

**🎯 Crux:** Whether `_svcauth_unix` or `xdr_opaque_auth` validates `oa_length` against the minimum required size for the specified `oa_flavor` before accessing `oa_base`.

I have analyzed the three reported issues. 

1. **Null Pointer Dereference in AUTH Macros**: As previously noted, the `AUTH` handle is an internal client-side state structure created by library factory functions (e.g., `authunix_create`). It is not deserialized from the network. A NULL `ah_ops` pointer would only be possible if the library failed to initialize its own internal state or if there was a separate memory corruption bug. This is an internal API usage issue, not a direct external vulnerability. INVALID.

2. **Fixed-size Buffer Overflow in `authunix_create`**: `authunix_create` is used on the client side to prepare credentials. The scanner flags constants like `AUTH_SYS_MAX_HOSTNAME`, but these are bounds, not vulnerabilities. The server-side processing occurs in `_svcauth_unix`. Without evidence of an unsafe `memcpy` or `strcpy` that ignores these bounds, this is speculative. INVALID.

3. **Buffer Over-read via `oa_flavor`**: This is the critical path. Untrusted network data is decoded by `xdr_opaque_auth` into a `struct opaque_auth`, which is then passed to handlers like `_svcauth_unix`. The vulnerability exists if the handler trusts `oa_flavor` to cast `oa_base` to a specific struct (e.g., a Unix credential struct) without first verifying that `oa_length` is at least as large as that struct. Since `oa_length` is attacker-controlled (up to `MAX_AUTH_BYTES`), providing a small `oa_length` with a flavor that expects a larger structure would cause an out-of-bounds read of the heap/stack where `oa_base` resides. I need to examine the implementation of `xdr_opaque_auth` to see if it enforces a minimum length per flavor, or `_svcauth_unix` to see if it validates the length before casting.

CRUX: Whether `_svcauth_unix` or `xdr_opaque_auth` validates `oa_length` against the minimum required size for the specified `oa_flavor` before accessing `oa_base`.
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

### Round 4: ❌ INVALID

[ARBITER] The reported issues are either internal API architectural patterns or lack evidence of exploitability. 1) The Null Pointer Dereference in AUTH macros occurs on the `AUTH` handle, which is an internal state structure created by library factory functions (e.g., `authunix_create`), not deserialized from network input. 2) The 'Flavor Type Confusion' is a common RPC pattern; without a specific implementation (like `_svcauth_unix`) showing a failure to check `oa_length` before casting `oa_base`, it is a theoretical risk rather than a demonstrated vulnerability. 3) The mention of fixed-size buffers (`MAXNETNAMELEN`) is a design characteristic, and without evidence of an unsafe `strcpy` or `memcpy` lacking bounds checks in the provided source or grep results, it is not a vulnerability.

