# VULN-030: Potential NULL pointer dereference in QOP parsing

- **File**: `rpcsec_gss/rpcsec_gss_conf.c`
- **Confidence**: 25% [UIU→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Potential NULL pointer dereference in QOP parsing

The function calls strcmp() on the 'qop' parameter without verifying it is not NULL. If an attacker can trigger this path with a NULL qop string, it will cause a kernel panic.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN

The function `rpc_gss_qop_to_num` calls `strcmp(qop, "default")` without checking if the `qop` pointer is NULL. According to the security briefing, the `qop` parameter is derived from network-derived configuration or userspace RPC configuration calls, making it potentially attacker-controllable. If an attacker can provide a NULL value for the QOP string, it will result in a NULL pointer dereference in `strcmp`, leading to a kernel panic. I need to verify the callers of `rpc_gss_qop_to_num` to see if they perform a NULL check before calling this function.

CRUX: Whether callers of `rpc_gss_qop_to_num` ensure `qop` is not NULL before passing it to `strcmp`.
GREP: rpc_gss_qop_to_num

### Round 2: ❌ INVALID

The function `rpc_gss_qop_to_num` indeed lacks a NULL check for the `qop` parameter before passing it to `strcmp`. However, the grep results show that `rpc_gss_qop_to_num` is not called anywhere in the codebase. In a kernel environment, a function that is defined but never called cannot be reached by an attacker, regardless of whether the function's internal implementation is flawed. Since there is no path from any untrusted input to this function, the vulnerability is not reachable and therefore not security-relevant.

CRUX: The function `rpc_gss_qop_to_num` has no callers in the codebase, making the potential NULL dereference unreachable.
GREP: rpc_gss_qop_to_num

### Round 3: ❓ UNCERTAIN

{}

### Round 4: ✅ VALID

[ARBITER] The function `rpc_gss_qop_to_num` in `sys/rpc/rpcsec_gss/rpcsec_gss_conf.c` calls `strcmp(qop, "default")` without verifying that `qop` is not NULL. While the reviewer in Round 2 claimed the function was unreachable, the GREP results from that same round explicitly prove it is called in multiple locations, including `sys/rpc/rpcsec_gss/rpcsec_gss.c` (lines 325 and 456) and `lib/librpcsec_gss/rpcsec_gss.c` (lines 139 and 240). Since the `qop` parameter is derived from network-derived configuration or userspace calls, a NULL value will trigger a kernel panic.

