# Triage T0127: Potential NULL pointer dereference in QOP parsing

- **File**: `rpcsec_gss/rpcsec_gss_conf.c`
- **Verdict**: VALID
- **Confidence**: 25% [UIU→V]

---

## Finding

Potential NULL pointer dereference in QOP parsing

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether callers of `rpc_gss_qop_to_num` ensure `qop` is not NULL before passing it to `strcmp`.

The function `rpc_gss_qop_to_num` calls `strcmp(qop, "default")` without checking if the `qop` pointer is NULL. According to the security briefing, the `qop` parameter is derived from network-derived configuration or userspace RPC configuration calls, making it potentially attacker-controllable. If an attacker can provide a NULL value for the QOP string, it will result in a NULL pointer dereference in `strcmp`, leading to a kernel panic. I need to verify the callers of `rpc_gss_qop_to_num` to see if they perform a NULL check before calling this function.

CRUX: Whether callers of `rpc_gss_qop_to_num` ensure `qop` is not NULL before passing it to `strcmp`.
GREP: rpc_gss_qop_to_num

🔎 **Grep results:**

GREP `rpc_gss_qop_to_num`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The function `rpc_gss_qop_to_num` has no callers in the codebase, making the potential NULL dereference unreachable.

The function `rpc_gss_qop_to_num` indeed lacks a NULL check for the `qop` parameter before passing it to `strcmp`. However, the grep results show that `rpc_gss_qop_to_num` is not called anywhere in the codebase. In a kernel environment, a function that is defined but never called cannot be reached by an attacker, regardless of whether the function's internal implementation is flawed. Since there is no path from any untrusted input to this function, the vulnerability is not reachable and therefore not security-relevant.

CRUX: The function `rpc_gss_qop_to_num` has no callers in the codebase, making the potential NULL dereference unreachable.
GREP: rpc_gss_qop_to_num

🔎 **Grep results:**

GREP `rpc_gss_qop_to_num`:
```
sys/rpc/rpcsec_gss.h:167:typedef bool_t	rpc_gss_qop_to_num_ftype(const char *qop, const char *mech,
sys/rpc/rpcsec_gss.h:199:	rpc_gss_qop_to_num_ftype	*rpc_gss_qop_to_num;
sys/rpc/rpcsec_gss.h:303:rpc_gss_qop_to_num_call(const char *qop, const char *mech, u_int *num_ret)
sys/rpc/rpcsec_gss.h:307:	if (rpc_gss_entries.rpc_gss_qop_to_num != NULL)
sys/rpc/rpcsec_gss.h:308:		ret = (*rpc_gss_entries.rpc_gss_qop_to_num)(qop, mech, num_ret);
sys/rpc/rpcsec_gss.h:457:bool_t	rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret);
include/rpc/rpcsec_gss.h:153:bool_t	rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret);
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:68:rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret)
sys/rpc/rpcsec_gss/rpcsec_gss.c:325:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num))
sys/rpc/rpcsec_gss/rpcsec_gss.c:456:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num)) {
sys/kgssapi/gss_impl.c:269:		rpc_gss_entries.rpc_gss_qop_to_num = rpc_gss_qop_to_num;
lib/librpcsec_gss/rpcsec_gss_conf.c:330:rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret)
lib/librpcsec_gss/rpcsec_gss.c:139:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num))
lib/librpcsec_gss/rpcsec_gss.c:240:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num)) {
```

### Round 3: ❓ UNCERTAIN

{}

### Round 4: ✅ VALID

[ARBITER] The function `rpc_gss_qop_to_num` in `sys/rpc/rpcsec_gss/rpcsec_gss_conf.c` calls `strcmp(qop, "default")` without verifying that `qop` is not NULL. While the reviewer in Round 2 claimed the function was unreachable, the GREP results from that same round explicitly prove it is called in multiple locations, including `sys/rpc/rpcsec_gss/rpcsec_gss.c` (lines 325 and 456) and `lib/librpcsec_gss/rpcsec_gss.c` (lines 139 and 240). Since the `qop` parameter is derived from network-derived configuration or userspace calls, a NULL value will trigger a kernel panic.

