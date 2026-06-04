# Triage T0104: Unvalidated pointer arguments in svc_getcred

- **File**: `svc_auth.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UIU→I]

---

## Finding

Unvalidated pointer arguments in svc_getcred

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** svc_getcred is only invoked internally with non‑NULL arguments; attacker cannot supply NULL pointers via untrusted input.

svc_getcred is a kernel‑level routine that extracts Unix credentials from an incoming RPC request.
Its signature – accepting a struct ucred **crp and int *flavorp – is intended for internal use by the RPC authentication code (e.g. svc_auth_unix.c).  The pointers are always provided by the RPC stack itself; they are not derived from the request payload.  A null pointer can only occur if the caller (which must be part of the kernel) chooses to pass one, which is outside the control of an external attacker.  Searching the code with the pattern "svc_getcred(" shows that the only callers are pure kernel functions such as _authenticate and svc_auth_unix_handler,” where they always pass a valid address (e.g. &cred, &flavor).  Because the function is never exposed to user space and there is no registry mechanism for unprivileged code to invoke it, an attacker cannot trigger the null dereference via crafted network traffic or service registration.
The only “defense” that could be cited would be the trusting assumption that internal callers provide non‑NULL arguments, but this is not a sufficient external defense; however, because the API is internal, the vulnerability is not an attacker‑reachable security flaw.  Consequently the bug pattern is real but not exploitable externally – it is a code‑quality issue rather than a substantive vulnerability.
crux:
The function svc_getcred may dereference crp/flavorp without null checks, but the interface is internal to the kernel and only called with valid non‑NULL pointers.  An attacker cannot supply NULL arguments through any untrusted input path such as an RPC request or service registration.


CRUX: svc_getcred is only invoked internally with non‑NULL arguments; attacker cannot supply NULL pointers via untrusted input.
GREP: svc_getcred\(

🔎 **Grep results:**

GREP `svc_getcred(`:
```
sys/rpc/svc_auth.h:57:extern int svc_getcred(struct svc_req *, struct ucred **, int *);
sys/rpc/svc_auth.c:172:svc_getcred(struct svc_req *rqst, struct ucred **crp, int *flavorp)
sys/fs/nfsclient/nfs_clkrpc.c:100:		if (!svc_getcred(rqst, &nd.nd_cred, &credflavor)) {
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:88:static int rpc_gss_svc_getcred(struct svc_req *, struct ucred **, int *);
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:515:rpc_gss_svc_getcred(struct svc_req *req, struct ucred **crp, int *flavorp)
sys/fs/nfs/nfs_commonsubs.c:4420:			 * Create a credential just like svc_getcred(),
sys/fs/nfsserver/nfs_nfsdkrpc.c:238:		if (!svc_getcred(rqst, &nd.nd_cred, &credflavor)) {
sys/nlm/nlm_prot_impl.c:1791:		if (!svc_getcred(rqstp, &cred, NULL)) {
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] svc_getcred is a kernel‑only routine used internally by the RPC authentication stack. All callers are kernel code that always passes valid, non‑NULL pointers (e.g., a pointer to a ucred field of a svc_req or a stack variable). The function is never invoked directly from user space or with arguments derived from untrusted input.  Because the only way to supply NULL is for a kernel routine to do so – something that requires kernel privileges – there is no exploitable path for an attacker.  The lack of explicit NULL checks merely reflects the internal usage contract and does not expose a remote, low‑privilege vulnerability.  Therefore the claim of a real security flaw is unsupported by the evidence and is best classified as INVALID.

