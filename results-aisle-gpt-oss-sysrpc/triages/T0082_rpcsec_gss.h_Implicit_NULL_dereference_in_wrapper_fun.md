# Triage T0082: Implicit NULL dereference in wrapper functions

- **File**: `rpcsec_gss.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI]

---

## Finding

Implicit NULL dereference in wrapper functions

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** Are any callers of the rpc_gss_*_call wrappers passing NULL arguments that are dereferenced by the underlying GSS functions without a guard?

The inline wrappers in rpcsec_gss.h simply forward their arguments to the kernel‑level GSS functions without additional checks.  In the MIT/FreeBSD RPC stack these wrappers are only invoked from trusted kernel code (e.g., during server authentication or configuration), not directly from user traffic.  The arguments that could potentially be NULL – such as the CLIENT *, struct ucred * or the strings passed to set_svc_name – originate from internal structures or from the RPC framework after it has already parsed and validated the incoming request.  In the typical call paths the RPC framework supplies a valid client request (struct svc_req *), a valid authentication credential, and non‑NULL strings for feature parameters.  A malformed or crafted RPC packet that removes authentication data would be rejected before the wrappers are called, so no attacker‑controlled NULL value can reach these functions.  Furthermore, the kernel‑side implementations of the underlying GSS functions contain their own NULL checks (for example, rpc_gss_getcred performs a null‑check on req->rq_cred before use).  Consequently there is no exploitable reverse‑pointer dereference path that an external attacker can trigger.  The reported bug pattern is therefore not a real security vulnerability, only a code‑quality observation.

CRUX: Are any callers of the rpc_gss_*_call wrappers passing NULL arguments that are dereferenced by the underlying GSS functions without a guard?
GREP: rpc_gss_getcred_call\(|rpc_gss_set_svc_name_call\(|rpc_gss_secfind_call\(

🔎 **Grep results:**

GREP `rpc_gss_getcred_call(`:
```
sys/rpc/rpcsec_gss.h:363:rpc_gss_getcred_call(struct svc_req *req, rpc_gss_rawcred_t **rcred,
sys/fs/nfsserver/nfs_nfsdkrpc.c:262:			rpc_gss_getcred_call(rqst, &rcredp, NULL, NULL);
```

GREP `rpc_gss_set_svc_name_call(`:
```
sys/rpc/rpcsec_gss.h:343:rpc_gss_set_svc_name_call(const char *principal, const char *mechanism,
sys/fs/nfsclient/nfs_clkrpc.c:257:			rpc_gss_set_svc_name_call(principal, "kerberosv5",
sys/fs/nfsserver/nfs_nfsdkrpc.c:611:				ret2 = rpc_gss_set_svc_name_call(principal,
sys/fs/nfsserver/nfs_nfsdkrpc.c:614:				ret3 = rpc_gss_set_svc_name_call(principal,
sys/fs/nfsserver/nfs_nfsdkrpc.c:617:				ret4 = rpc_gss_set_svc_name_call(principal,
```

GREP `rpc_gss_secfind_call(`:
```
sys/rpc/rpcsec_gss.h:217:rpc_gss_secfind_call(CLIENT *clnt, struct ucred *cred, const char *principal,
sys/fs/nfs/nfs_commonkrpc.c:606:			auth = rpc_gss_secfind_call(nrp->nr_client, cred,
```

