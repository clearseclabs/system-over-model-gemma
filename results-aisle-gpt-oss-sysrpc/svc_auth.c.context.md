# Context: svc_auth.c

**SECURITY BRIEF – File: `svc_auth.c`**  

1. **Purpose & Location**  
   *`svc_auth.c`* implements the server‑side RPC authentication interface for NetBSD’s RPC layer. It lives in `/rpc/` and is built into the kernel’s RPC subsystem. Functions here translate the wire‑encoded credentials (`msg->rm_call.cb_cred`) into kernel credential objects, set verifier state, and dispatch to the appropriate flavor‑specific authenticator (`AUTH_NULL`, `AUTH_SYS`, `AUTH_SHORT`, `RPCSEC_GSS`, `AUTH_TLS`).  

2. **Attack Surface**  
   *Untrusted input* arrives over a network transport (`SVCXPRT *rqst->rq_xprt`) and is described by the incoming `rpc_msg *msg`. The credentials (`msg->rm_call.cb_cred`) are part of that payload.  

3. **Data‑flow Highlights**  
   - `msg->rm_call.cb_cred` → `rqst->rq_cred`  
   - `rqst->rq_cred.oa_flavor` → `cred_flavor` (switch selector)  
   - `rqst->rq_xprt->xp_tls` used to gate GSS or TLS methods (see flags below)  

4. **Size Constants** (via grep)  
   ```
   GREP: #define RPCTLS_FLAGS_DISABLED
   GREP: #define RPCTLS_FLAGS_CERTUSER
   ```
   (Resolves to numeric values in `rpcsec_tls.h`). No other fixed‑size buffers appear in this file; credential arrays are dynamic (`xcr->cr_groups` etc.).  

5. **Dangerous Flows**  
   None in this file; no attacker‑controlled data is copied into a statically sized buffer.  

6. **Null Dereference Risk**  
   *`svc_getcred`* assumes `flavor == AUTH_UNIX` ⇒ `rqst->rq_clntcred` is non‑NULL; if the caller passes a malformed request with `rq_clntcred == NULL`, the dereference of `xcr->cr_ngroups` could crash.  

7. **Tagged‑Union Checks**  
   None here; the code relies on the RPC message flavor field rather than union tags.  

8. **API vs Helper**  
   Public API: `svc_auth_reg()`, `svc_getcred()`.  
   Static helpers: `_authenticate()`, `_svcauth_null()`, `svcauth_null_*()`.  Static helpers are invoked only after verifying required pointers (e.g., `_svcauth_rpcsec_gss` is checked before use).  

9. **Common Vulnerability Classes**  
   - **Null dereference / misuse of credential pointers**  
   - **Unvalidated switch on external `oa_flavor`** (though validators are present, accidental bogus values bypass default)  
   - **Potential denial‑of‑service via malformed credential payloads**  

*All constant values can be resolved with the provided `GREP` commands.*

[GREP RESULTS from codebase]:
GREP `#define RPCTLS_FLAGS_DISABLED (simplified to: RPCTLS_FLAGS_DISABLED)`:
```
sys/rpc/rpcsec_tls.h:39:#define	RPCTLS_FLAGS_DISABLED	0x10
sys/rpc/rpcsec_tls/rpctls_impl.c:402:		    RPCTLS_FLAGS_DISABLED)) == RPCTLS_FLAGS_CERTUSER) {
sys/rpc/rpcsec_tls/rpctls_impl.c:504:		    RPCTLS_FLAGS_DISABLED)) == RPCTLS_FLAGS_CERTUSER) {
sys/rpc/svc_auth.c:93:		if ((rqst->rq_xprt->xp_tls & RPCTLS_FLAGS_DISABLED) != 0)
sys/rpc/svc_auth.c:98:		if ((rqst->rq_xprt->xp_tls & RPCTLS_FLAGS_DISABLED) != 0)
sys/rpc/svc_auth.c:103:		if ((rqst->rq_xprt->xp_tls & RPCTLS_FLAGS_DISABLED) != 0)
sys/rpc/svc_auth.c:189:	    RPCTLS_FLAGS_DISABLED)) == RPCTLS_FLAGS_CERTUSER &&
usr.sbin/rpc.tlsservd/rpc.tlsservd.c:808:						    RPCTLS_FLAGS_DISABLED;
usr.sbin/rpc.tlsservd/rpc.tlsservd.c:849:		*flags |= RPCTLS_FLAGS_DISABLED;
```

GREP `#define RPCTLS_FLAGS_CERTUSER (simplified to: RPCTLS_FLAGS_CERTUSER)`:
```
sys/rpc/rpcsec_tls.h:40:#define	RPCTLS_FLAGS_CERTUSER	0x20
sys/fs/nfsserver/nfs_nfsdkrpc.c:315:			if ((xprt->xp_tls & RPCTLS_FLAGS_CERTUSER) != 0)
usr.sbin/rpc.tlsservd/rpc.tlsservd.c:437:		if ((flags & RPCTLS_FLAGS_CERTUSER) != 0)
usr.sbin/rpc.tlsservd/rpc.tlsservd.c:819:						*flags |= RPCTLS_FLAGS_CERTUSER;
sys/rpc/rpcsec_tls/rpctls_impl.c:401:		if ((*flags & (RPCTLS_FLAGS_CERTUSER |
sys/rpc/rpcsec_tls/rpctls_impl.c:402:		    RPCTLS_FLAGS_DISABLED)) == RPCTLS_FLAGS_CERTUSER) {
sys/rpc/rpcsec_tls/rpctls_impl.c:503:		if ((flags & (RPCTLS_FLAGS_CERTUSER |
sys/rpc/rpcsec_tls/rpctls_impl.c:504:		    RPCTLS_FLAGS_DISABLED)) == RPCTLS_FLAGS_CERTUSER) {
sys/rpc/svc_auth.c:188:	if ((xprt->xp_tls & (RPCTLS_FLAGS_CERTUSER |
sys/rpc/svc_auth.c:189:	    RPCTLS_FLAGS_DISABLED)) == RPCTLS_FLAGS_CERTUSER &&
```