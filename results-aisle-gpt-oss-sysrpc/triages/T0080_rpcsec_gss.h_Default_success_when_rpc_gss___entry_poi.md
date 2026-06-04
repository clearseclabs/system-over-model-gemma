# Triage T0080: Default success when rpc_gss_* entry point is missing

- **File**: `rpcsec_gss.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Default success when rpc_gss_* entry point is missing

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The inline wrappers intentionally return a default success value when the kgssapi module has not yet been loaded.  This design allows RPC services to fall back to alternate authentication (AUTH_SYS) without requiring GSS support.  Since the wrappers only return a success flag and the caller must still use the rest of the GSS API to perform real authentication, the default success does not enable an attacker to bypass security checks.  The logic is a benign expected behaviour rather than an exploitable flaw, so the finding is not a real vulnerability.

