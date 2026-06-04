# Triage T0157: Use‑after‑free on gd->gd_verf during validation

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [IUU]

---

## Finding

Use‑after‑free on gd->gd_verf during validation

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** All invocations of rpc_gss_destroy_context are internal to trusted code paths and cannot be triggered by an attacker via untrusted input.

The only code that reads or frees gss_verf in rpc_gss_validate does so without holding the gd_lock. A use‑after‑free could occur if rpc_gss_destroy_context frees gss_verf while another thread is executing the RPCSEC_GSS_CONTEXT part of rpc_gss_validate. However rpc_gss_destroy_context is only called internally from rpc_gss_validate itself (when a GSS_S_CONTEXT_EXPIRED is seen) or from rpc_gss_destroy (a cleanup routine invoked by trusted internal code). No external, untrusted input can cause the client to call rpc_gss_destroy_context or otherwise trigger the concurrent unlinking of gss_verf. Consequently, an attacker cannot control the input that leads to the race; it would require concurrent threads within the same process misusing the AUTH object, which is outside the control of an attacker. Therefore the bug pattern is neither attacker‑reachable nor security‑relevant.

Thus the finding is classified as INVALID.

The grep pattern below confirms the programmatic callers of rpc_gss_destroy_context.


CRUX: All invocations of rpc_gss_destroy_context are internal to trusted code paths and cannot be triggered by an attacker via untrusted input.
GREP: rpc_gss_destroy_context(

🔎 **Grep results:**

GREP `rpc_gss_destroy_context(`:
```
lib/librpcsec_gss/rpcsec_gss.c:83:static void	rpc_gss_destroy_context(AUTH *, bool_t);
lib/librpcsec_gss/rpcsec_gss.c:312:			rpc_gss_destroy_context(auth, TRUE);
lib/librpcsec_gss/rpcsec_gss.c:448:					rpc_gss_destroy_context(auth, TRUE);
lib/librpcsec_gss/rpcsec_gss.c:502:		rpc_gss_destroy_context(auth, FALSE);
lib/librpcsec_gss/rpcsec_gss.c:511:rpc_gss_destroy_context(AUTH *auth, bool_t send_destroy)
lib/librpcsec_gss/rpcsec_gss.c:516:	log_debug("in rpc_gss_destroy_context()");
lib/librpcsec_gss/rpcsec_gss.c:551:	rpc_gss_destroy_context(auth, TRUE);
lib/librpcsec_gss/rpcsec_gss.c:635:				rpc_gss_destroy_context(auth, TRUE);
sys/rpc/rpcsec_gss/rpcsec_gss.c:96:static void	rpc_gss_destroy_context(AUTH *, bool_t);
sys/rpc/rpcsec_gss/rpcsec_gss.c:581:				rpc_gss_destroy_context(auth, TRUE);
sys/rpc/rpcsec_gss/rpcsec_gss.c:694:				rpc_gss_destroy_context(auth, TRUE);
sys/rpc/rpcsec_gss/rpcsec_gss.c:999:					rpc_gss_destroy_context(auth, TRUE);
sys/rpc/rpcsec_gss/rpcsec_gss.c:1079:		rpc_gss_destroy_context(auth, FALSE);
sys/rpc/rpcsec_gss/rpcsec_gss.c:1088:rpc_gss_destroy_context(AUTH *auth, bool_t send_destroy)
sys/rpc/rpcsec_gss/rpcsec_gss.c:1095:	rpc_gss_log_debug("in rpc_gss_destroy_context()");
sys/rpc/rpcsec_gss/rpcsec_gss.c:1157:	rpc_gss_destroy_context(auth, TRUE);
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



