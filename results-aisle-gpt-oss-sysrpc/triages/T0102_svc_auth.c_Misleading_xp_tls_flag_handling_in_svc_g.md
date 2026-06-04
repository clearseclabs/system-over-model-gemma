# Triage T0102: Misleading xp_tls flag handling in svc_getcred

- **File**: `svc_auth.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [UIU]

---

## Finding

Misleading xp_tls flag handling in svc_getcred

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** xp_tls flags are internal and cannot be set by an attacker; the check simply implements the intended behaviour of disabling TLS credentials when the DISABLED flag is present.

The conditional in svc_getcred correctly uses the xp_tls field to decide whether TLS‑derived credentials should be used. XP_TLS flags are set only by the RPC transport routines during TLS negotiation and are not influenced by any client‑supplied data. A malicious caller cannot set RPCTLS_FLAGS_CERTUSER or RPCTLS_FLAGS_DISABLED because xp_tls resides in kernel‑space SVCXPRT state, and the only place those flags are assigned is in the transport initialization code that runs after the TLS handshake.

Because the DISABLED flag is meant to force the server to ignore TLS credentials, the fact that (CERTUSER|DISABLED) != CERTUSER simply results in the intended fallback to RPC‑header credentials. The server’s behaviour is, therefore, correct from a security standpoint; there is no exploitable path that lets an attacker manipulate the flag combination to bypass authentication.

No external defense is missing, and the logic does not produce an undefined behaviour or vulnerability. The bug pattern exists in the code, but it is intentionally defensive and unreachable by an attacker.

Conclusion: The scanner’s claim is a false positive.



CRUX: xp_tls flags are internal and cannot be set by an attacker; the check simply implements the intended behaviour of disabling TLS credentials when the DISABLED flag is present.
GREP: #define RPCTLS_FLAGS_DISABLED
#define RPCTLS_FLAGS_CERTUSER
xp_tls

🔎 **Grep results:**

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

### Round 3: ❓ UNCERTAIN



