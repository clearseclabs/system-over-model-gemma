# Triage T0103: NULL pointer dereference on rqst->rq_clntcred

- **File**: `svc_auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UIU→I]

---

## Finding

NULL pointer dereference on rqst->rq_clntcred

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** `rqst->rq_clntcred` must never be NULL before entering `_svcauth_unix`; verify that the RPC framework always initializes this field to a valid `struct xucred` and never assigns NULL in any error or success path.

The NULL‑dereference occurs only when the pointer `rqst->rq_clntcred` is NULL, but the RPC stack guarantees that this field is initialized to point to a valid `struct xucred` before `_svcauth_unix` is called.  The pointer is never set to NULL by any external or untrusted code path, nor is there any code that can overwrite it via malformed input.  Consequently an attacker cannot influence the pointer value to trigger the crash.  No other defensive check inside `_svcauth_unix` is required because the assumption holds at the call site.

CRUX: `rqst->rq_clntcred` must never be NULL before entering `_svcauth_unix`; verify that the RPC framework always initializes this field to a valid `struct xucred` and never assigns NULL in any error or success path.
GREP: rq_clntcred

🔎 **Grep results:**

GREP `rq_clntcred`:
```
include/rpc/svc.h:156:	void		*rq_clntcred;	/* read only cooked cred */
include/rpc/auth_kerb.h:63: *  cooked credential stored in rq_clntcred
sys/rpc/svc.h:220:	void		*rq_clntcred;	/* read only cooked cred */
crypto/krb5/src/include/gssrpc/svc.h:172:	void *		rq_clntcred;	/* read only cooked client cred */
usr.sbin/rpcbind/rpcb_svc_com.c:829:		au = (struct authunix_parms *)rqstp->rq_clntcred;
usr.sbin/rpc.ypupdated/ypupdated_server.c:73:		des_cred = (struct authdes_cred *) svcreq->rq_clntcred;
usr.sbin/rpc.ypupdated/ypupdated_server.c:110:	des_cred = (struct authdes_cred *) svcreq->rq_clntcred;
usr.sbin/rpc.ypupdated/ypupdated_server.c:144:	des_cred = (struct authdes_cred *) svcreq->rq_clntcred;
usr.sbin/rpc.ypupdated/ypupdated_server.c:178:	des_cred = (struct authdes_cred *) svcreq->rq_clntcred;
usr.sbin/rpc.ypupdated/ypupdated_server.c:212:	des_cred = (struct authdes_cred *) svcreq->rq_clntcred;
usr.sbin/ypbind/ypbind.c:319:			creds = (struct authunix_parms *)rqstp->rq_clntcred;
lib/librpcsec_gss/svc_rpcsec_gss.c:325:	client = req->rq_clntcred;
lib/librpcsec_gss/svc_rpcsec_gss.c:338:	struct svc_rpc_gss_client *client = req->rq_clntcred;
lib/librpcsec_gss/svc_rpcsec_gss.c:1021:	rqst->rq_clntcred = client;
sys/rpc/svc.c:934:	r->rq_clntcred = &r->rq_credarea[2*MAX_AUTH_BYTES];
sys/rpc/svc_auth_unix.c:62:	xcr = rqst->rq_clntcred;
sys/rpc/svc_auth.c:205:		xcr = (struct xucred *) rqst->rq_clntcred;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:162: * results for a given request. We use the rq_clntcred area for this
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:499:	cc = req->rq_clntcred;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:525:	cc = req->rq_clntcred;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:551:	struct svc_rpc_gss_cookedcred *cc = req->rq_clntcred;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1462:	cc = rqst->rq_clntcred;
crypto/krb5/src/kadmin/server/server_stubs.c:1664:        return rqstp->rq_clntcred;
lib/libc/rpc/svc.c:569: * the "cooked" credentials (rqst->rq_clntcred).
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/svc_auth_unix.c:72:	area = (struct area *) rqst->rq_clntcred;
lib/libc/rpc/svc_auth_des.c:132:	area = (struct area *)rqst->rq_clntcred;
crypto/krb5/src/lib/rpc/svc_auth_gssapi.c:638:	       rqst->rq_clntcred = (char *)client_data->client_name;
crypto/krb5/src/lib/rpc/svc.c:377: * the "cooked" credentials (rqst->rq_clntcred).
crypto/krb5/src/lib/rpc/svc.c:467:	r.rq_clntcred = cookedcred;
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] In the FreeBSD RPC framework, `rqst->rq_clntcred` is always initialized to point to a valid `struct xucred` area before any authentication routine runs. The code in `sys/rpc/svc.c` explicitly assigns `rqst->rq_clntcred = &r->rq_credarea[2*MAX_AUTH_BYTES]` during request processing, and there is no code path that sets this pointer to NULL or an attacker‑controlled value. Consequently, dereferencing `rqst->rq_clntcred` in `_svcauth_unix()` cannot occur with a NULL pointer, and the reported NULL dereference is not a realistic vulnerability under normal operation. Thus the finding is deemed INVALID. 

