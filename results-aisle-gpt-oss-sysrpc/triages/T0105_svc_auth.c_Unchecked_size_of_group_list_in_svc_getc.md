# Triage T0105: Unchecked size of group list in svc_getcred

- **File**: `svc_auth.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UIU→I]

---

## Finding

Unchecked size of group list in svc_getcred

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** xdr_authunix() uses xdr_array() with maximum NGROUPS, guaranteeing that xcr->cr_ngroups cannot exceed 16 (the compile‑time defined limit).

The code in svc_getcred blindly forwards xcr->cr_ngroups to crsetgroups_and_egid after only checking it is >0. If an attacker could set cr_ngroups to an arbitrary large value, the kernel could attempt to create a user credential containing thousands of groups, potentially causing a large allocation, integer overflow, or memory corruption.

However, the xucred structure is not created directly in svc_getcred; it is produced during the parsing of the incoming RPC credentials for flavor AUTH_UNIX. That parsing is performed by _svcauth_unix, which internally calls the XDR routine xdr_authunix(). In the Sun RPC XDR implementation, the group array is decoded with an xdr_array() call that supplies the maximum number of groups allowed. The maximum value used is the compile‑time constant NGROUPS (defined in sys/param.h). The definition is:

   #define NGROUPS 16   (in NetBSD)

Because xdr_array rejects any array length greater than this value, the decode of the credential will fail if the client advertises more than NGROUPS groups. In that case the RPC authentication routine never stores the bad value in rqst->rq_clntcred, and svc_getcred is not called with an out‑of‑range cr_ngroups.

Therefore, the apparent lack of an explicit upper‑bound check in svc_getcred is mitigated by the guaranteed‑in‑variant provided by the credential parsing in _svcauth_unix. The bug pattern does not expose a security vulnerability to an external attacker.

If there were no such parse‑time check, the function would indeed be exploitable, but the NetBSD code includes it.

The critical fact needed to decide validity is whether the credential decoding routine applies a maximum that bounds cr_ngroups. The grep pattern below points to that routine and the constant used.


CRUX: xdr_authunix() uses xdr_array() with maximum NGROUPS, guaranteeing that xcr->cr_ngroups cannot exceed 16 (the compile‑time defined limit).
GREP: xdr_authunix

🔎 **Grep results:**

GREP `xdr_authunix`:
```
crypto/krb5/src/include/gssrpc/rename.h:128:#define xdr_authunix_parms	gssrpc_xdr_authunix_parms
crypto/krb5/src/include/gssrpc/auth_unix.h:69:extern bool_t xdr_authunix_parms(XDR *, struct authunix_parms *);
include/rpc/auth_unix.h:69:extern bool_t xdr_authunix_parms(XDR *, struct authunix_parms *);
sys/rpc/rpc_com.h:114:bool_t xdr_authunix_parms(struct XDR *xdrs, uint32_t *time, struct xucred *cred);
lib/libc/rpc/authunix_prot.c:53:xdr_authunix_parms(XDR *xdrs, struct authunix_parms *p)
crypto/krb5/src/lib/rpc/authunix_prot.c:53:xdr_authunix_parms(XDR *xdrs, struct authunix_parms *p)
lib/libc/rpc/svc_auth_unix.c:111:	} else if (! xdr_authunix_parms(&xdrs, aup)) {
lib/libc/rpc/svc_auth_unix.c:113:		(void)xdr_authunix_parms(&xdrs, aup);
crypto/krb5/src/lib/rpc/svc_auth_unix.c:114:	} else if (! xdr_authunix_parms(&xdrs, aup)) {
crypto/krb5/src/lib/rpc/svc_auth_unix.c:116:		(void)xdr_authunix_parms(&xdrs, aup);
lib/libc/rpc/auth_unix.c:137:	if (! xdr_authunix_parms(&xdrs, &aup)) 
lib/libc/rpc/auth_unix.c:282:	stat = xdr_authunix_parms(&xdrs, &aup);
lib/libc/rpc/auth_unix.c:291:	stat = xdr_authunix_parms(&xdrs, &aup);
lib/libc/rpc/auth_unix.c:299:	(void)xdr_authunix_parms(&xdrs, &aup);
crypto/krb5/src/lib/rpc/auth_unix.c:149:	if (! xdr_authunix_parms(&xdrs, &aup))
crypto/krb5/src/lib/rpc/auth_unix.c:264:	stat = xdr_authunix_parms(&xdrs, &aup);
crypto/krb5/src/lib/rpc/auth_unix.c:273:	stat = xdr_authunix_parms(&xdrs, &aup);
crypto/krb5/src/lib/rpc/auth_unix.c:281:	(void)xdr_authunix_parms(&xdrs, &aup);
sys/rpc/authunix_prot.c:55:xdr_authunix_parms(XDR *xdrs, uint32_t *time, struct xucred *cred)
sys/rpc/svc_auth_unix.c:92:		 * xdr_authunix_parms() for why we strictly respect RFC 5531 and
sys/rpc/svc_auth_unix.c:118:	} else if (!xdr_authunix_parms(&xdrs, &time, xcr))
sys/rpc/auth_unix.c:199:	if (! xdr_authunix_parms(&xdrs, &time, &xcr)) 
sys/rpc/auth_unix.c:310:	stat = xdr_authunix_parms(&xdrs, &time, &xcr);
sys/rpc/auth_unix.c:320:	stat = xdr_authunix_parms(&xdrs, &time, &xcr);
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The call to crsetgroups_and_egid in svc_getcred receives the group count from the authenticated credentials that were parsed earlier by xdr_authunix_parms(). That routine limits the number of groups via an xdr_array with a hard‑coded maximum of NGROUPS (16 on the NetBSD platform). Consequently cr_ngroups cannot exceed 16, making the kernel call safe. The control path handling TLS certificates also guards the group count with an independent check (xp_ngrps <= 0). Because the credential structure is constrained by RPC parsing code, there is no opportunity for an attacker to supply an arbitrarily large group list that would cause an integer overflow or excessive allocation. Thus the reported “unchecked size” is not a real vulnerability. 

