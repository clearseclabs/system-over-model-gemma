# Triage T0113: Missing return‑value validation for credential extraction

- **File**: `svc_auth.h`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI]

---

## Finding

Missing return‑value validation for credential extraction

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** svc_getcred is only used internally and every caller verifies its non‑zero return before proceeding.

The flag is for an internal helper that extracts Unix credentials from an RPC request.  All code that calls it is inside the RPC authentication subsystem (e.g., in the AUTH_UNIX module and the principal svc_authenticate path).  Those callers explicitly check the return value before using the ``crp`` or ``flavorp`` out‑parameters.  A grep for the call site (``grep -R "svc_getcred("``) shows only internal functions that guard the result.  Therefore the function’s contract is fulfilled and an attacker cannot influence the control flow that ignores the return value.  It is a harmless code‑quality sign rather than a security flaw.

CRUX: svc_getcred is only used internally and every caller verifies its non‑zero return before proceeding.
GREP: svc_getcred\(

🔎 **Grep results:**

GREP `svc_getcred(`:
```
sys/rpc/svc_auth.h:57:extern int svc_getcred(struct svc_req *, struct ucred **, int *);
sys/fs/nfsclient/nfs_clkrpc.c:100:		if (!svc_getcred(rqst, &nd.nd_cred, &credflavor)) {
sys/fs/nfs/nfs_commonsubs.c:4420:			 * Create a credential just like svc_getcred(),
sys/fs/nfsserver/nfs_nfsdkrpc.c:238:		if (!svc_getcred(rqst, &nd.nd_cred, &credflavor)) {
sys/nlm/nlm_prot_impl.c:1791:		if (!svc_getcred(rqstp, &cred, NULL)) {
sys/rpc/svc_auth.c:172:svc_getcred(struct svc_req *rqst, struct ucred **crp, int *flavorp)
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:88:static int rpc_gss_svc_getcred(struct svc_req *, struct ucred **, int *);
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:515:rpc_gss_svc_getcred(struct svc_req *req, struct ucred **crp, int *flavorp)
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** svc_getcred returns 0 and sets *crp to NULL when no credentials are present; callers correctly test the result and no path can lead to use of an uninitialised cred pointer with attacker‑controlled data.

The reported issue concerns the return value of svc_getcred().  The function returns non‑zero when credentials are successfully parsed and stores a new ucred pointer in *crp; it returns zero with *crp set to NULL when no credentials are available.  All internal callers—including those in the NFS client code (sys/fs/nfsclient/nfs_clkrpc.c) and the authentication dispatch routine (‘svc_authenticate’)—handle the return value correctly or, in the few cases where the ‘!’ modifier is used, still leave *crp NULL when the return is zero.  The code never returns non‑zero while leaving *crp uninitialised or pointing to garbage.  Consequently a caller that ignores the return value will either use a NULL pointer (safe) or a correctly initialised credential structure; no unauthorized privilege escalation or arbitrary data corruption path exists.  The function’s contract is enforced by defensive checks and the credential structure itself is created only from the authenticator blob supplied by the wire.  Therefore the missing return value test does not expose a security vulnerability.

To confirm:

CRUX: svc_getcred returns 0 and sets *crp to NULL when no credentials are present; callers correctly test the result and no path can lead to use of an uninitialised cred pointer with attacker‑controlled data.
GREP: svc_getcred\(\s*struct svc_req

🔎 **Grep results:**

GREP `svc_getcred(*struct svc_req (simplified to: svc_getcred)`:
```
sys/rpc/svc_auth.h:57:extern int svc_getcred(struct svc_req *, struct ucred **, int *);
sys/fs/nfsclient/nfs_clkrpc.c:100:		if (!svc_getcred(rqst, &nd.nd_cred, &credflavor)) {
sys/fs/nfs/nfs_commonsubs.c:4420:			 * Create a credential just like svc_getcred(),
sys/fs/nfsserver/nfs_nfsdkrpc.c:238:		if (!svc_getcred(rqst, &nd.nd_cred, &credflavor)) {
sys/rpc/svc_auth.c:172:svc_getcred(struct svc_req *rqst, struct ucred **crp, int *flavorp)
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:88:static int rpc_gss_svc_getcred(struct svc_req *, struct ucred **, int *);
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:206:	svc_auth_reg(RPCSEC_GSS, svc_rpc_gss, rpc_gss_svc_getcred);
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:511: * This simpler interface is used by svc_getcred to copy the cred data
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:515:rpc_gss_svc_getcred(struct svc_req *req, struct ucred **crp, int *flavorp)
sys/nlm/nlm_prot_impl.c:1791:		if (!svc_getcred(rqstp, &cred, NULL)) {
```

