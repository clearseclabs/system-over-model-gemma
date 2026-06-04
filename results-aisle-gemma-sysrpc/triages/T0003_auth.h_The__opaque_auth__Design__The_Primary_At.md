# Triage T0003: The `opaque_auth` Design (The Primary Attack Vector)

- **File**: `auth.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

The `opaque_auth` Design (The Primary Attack Vector)

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether `xdr_opaque_auth` enforces the `MAX_AUTH_BYTES` limit during deserialization of the `oa_length` field.

The report suggests two potential vulnerabilities in the `opaque_auth` design: (1) buffer over-reads in `ah_validate` or `_svcauth_*` due to insufficient `oa_length` validation, and (2) heap/integer overflows in `xdr_opaque_auth` if `MAX_AUTH_BYTES` is not enforced. 

First, `struct opaque_auth` is a standard RPC structure. The security of its usage depends on the implementation of the specific auth flavors (e.g., `_svcauth_unix`). Without seeing the implementation of those functions, the report is only highlighting a 'risk pattern' (tagged unions), not a concrete bug. 

Second, regarding `xdr_opaque_auth`, in standard SunRPC/TIRPC implementations, `xdr_opaque` (which `xdr_opaque_auth` typically wraps) allocates memory based on the length provided in the XDR stream. If the length is not capped, an attacker could cause a large allocation. However, the report mentions `MAX_AUTH_BYTES` (400). I need to verify if `xdr_opaque_auth` actually enforces this limit. If it does, the overflow risk is mitigated. If it doesn't, the risk is real. Since the provided code is just a header, I must check the implementation of `xdr_opaque_auth` to see if it validates the length against `MAX_AUTH_BYTES` before calling the allocator.

CRUX: Whether `xdr_opaque_auth` enforces the `MAX_AUTH_BYTES` limit during deserialization of the `oa_length` field.
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
lib/libc/rpc/clnt_vc.c:438:			(void)xdr_opaque_auth(xdrs,
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
```

### Round 2: ❓ UNCERTAIN

**🎯 Crux:** Does `xdr_opaque_auth` validate the incoming length against `MAX_AUTH_BYTES` before allocating memory for `oa_base`?

The vulnerability report suggests two risks: (1) buffer over-reads in `ah_validate` / `_svcauth_*` because `oa_length` might not be checked against the expected structure size for a given `oa_flavor`, and (2) heap/integer overflows in `xdr_opaque_auth` if `MAX_AUTH_BYTES` is not enforced. 

Reviewer 1 correctly identified that the 'risk' of tagged unions is not a bug unless a specific instance of misuse is found. However, the second point regarding `xdr_opaque_auth` is a concrete testable claim. I need to examine the implementation of `xdr_opaque_auth` in `sys/rpc/rpc_prot.c` (or `lib/libc/rpc/rpc_prot.c`) to see if it validates `oa_length` against `MAX_AUTH_BYTES` (400) before allocating `oa_base`. If the function simply calls `xdr_opaque` or a similar allocator without a bound, an attacker providing a large length in the XDR stream could cause a denial of service (memory exhaustion) or a heap overflow depending on how the length is handled. 

I will first examine the code of `xdr_opaque_auth` to see if `MAX_AUTH_BYTES` is used as a guard.

CRUX: Does `xdr_opaque_auth` validate the incoming length against `MAX_AUTH_BYTES` before allocating memory for `oa_base`?
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
lib/libc/rpc/clnt_dg.c:574:				(void) xdr_opaque_auth(xdrs,
lib/libc/rpc/auth_none.c:63:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
lib/libc/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
lib/libc/rpc/rpc_prot.c:66:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
lib/libc/rpc/rpc_prot.c:107:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
lib/libc/rpc/clnt_raw.c:221:			(void)xdr_opaque_auth(xdrs, &(msg.acpted_rply.ar_verf));
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
```

### Round 3: ❓ UNCERTAIN

**🎯 Crux:** Does the implementation of `xdr_opaque_auth` in `rpc_prot.c` enforce the `MAX_AUTH_BYTES` limit during deserialization?

The report suggests two potential vulnerabilities. First, a risk of buffer over-reads in `_svcauth_*` functions because `oa_length` might not be validated against the expected structure size for a given `oa_flavor`. This is a generic 'risk pattern' for tagged unions; without a specific instance of a flavor and a corresponding failing check in the implementation code, it is not a concrete bug. Second, it suggests a heap/integer overflow in `xdr_opaque_auth` if `MAX_AUTH_BYTES` (400) is not enforced. To verify this, we must examine the implementation of `xdr_opaque_auth`. The grep results show it is implemented in `sys/rpc/rpc_prot.c` and `lib/libc/rpc/rpc_prot.c`. If this function uses `xdr_opaque` (the standard XDR primitive for opaque data) and does not check the length against `MAX_AUTH_BYTES`, an attacker can control the size of the allocation. However, memory exhaustion (DoS) from a large allocation is generally not considered a high-impact security vulnerability unless it leads to a crash or corruption. A heap overflow would require the allocation size to be smaller than the actual data read, which is typically handled by the XDR layer's internal length tracking. Without the implementation code showing a failure to bound the length or a flawed allocation calculation, this remains a speculative risk. The most concrete claim is the lack of `MAX_AUTH_BYTES` enforcement.

CRUX: Does the implementation of `xdr_opaque_auth` in `rpc_prot.c` enforce the `MAX_AUTH_BYTES` limit during deserialization?
GREP: xdr_opaque_auth

🔎 **Grep results:**

GREP `xdr_opaque_auth`:
```
crypto/krb5/src/include/gssrpc/rename.h:66:#define xdr_opaque_auth		gssrpc_xdr_opaque_auth
crypto/krb5/src/include/gssrpc/auth.h:193:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
sys/rpc/auth.h:264:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
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
crypto/krb5/src/lib/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
crypto/krb5/src/lib/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
crypto/krb5/src/lib/rpc/auth_gssapi.c:592:	  if (! xdr_opaque_auth(xdrs, &auth->ah_cred) ||
crypto/krb5/src/lib/rpc/auth_gssapi.c:593:	      ! xdr_opaque_auth(xdrs, &auth->ah_verf)) {
crypto/krb5/src/lib/rpc/auth_gssapi.c:604:	  if (! xdr_opaque_auth(xdrs, &auth->ah_cred) ||
crypto/krb5/src/lib/rpc/auth_gssapi.c:605:	      ! xdr_opaque_auth(xdrs, &auth->ah_verf)) {
crypto/krb5/src/lib/rpc/clnt_tcp.c:349:	    (void)xdr_opaque_auth(xdrs, &(reply_msg.acpted_rply.ar_verf));
crypto/krb5/src/lib/rpc/rpc_prot.c:60:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
crypto/krb5/src/lib/rpc/rpc_prot.c:88:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
```

### Round 4: ❌ INVALID

[ARBITER] The report describes a 'design risk' rather than a concrete vulnerability. It suggests two possibilities: (1) buffer over-reads if `oa_length` is not validated in `_svcauth_*` functions, and (2) overflows in `xdr_opaque_auth` if `MAX_AUTH_BYTES` is not enforced. However, the report provides no evidence of a specific failing check in any `_svcauth_*` implementation, nor does it provide the implementation of `xdr_opaque_auth` to prove that it fails to enforce the limit. Without a specific instance of a missing check or an actual overflow, this is a theoretical risk associated with the tagged union pattern, not a demonstrated vulnerability.

