# Triage T0131: Race Condition on Static Error State

- **File**: `rpcsec_gss/rpcsec_gss_misc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UIU→I]

---

## Finding

Race Condition on Static Error State

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** It is a data race on a static error variable used only for internal diagnostic purposes; it does not provide an attacker with a meaningful exploit path.

The code shows a static variable `_rpc_gss_error` that is written by `_rpc_gss_set_error()` and read by `rpc_gss_get_error()` without any synchronization.  The pattern exists (a data race).  The functions are used by the rpcsec_gss library to report errors for RPC calls.  A remote attacker could generate concurrent RPC calls to the same server process, therefore the race can be observed.  However, the race only corrupts an internal diagnostic state and does not lead to memory corruption, code execution, data leakage, or a clear denial‑of‑service.  The library’s public interface does not expose these values to callers; the error state is only used internally to decide what error message to send back or to log.  Consequently, this bug, while a quality issue, is not security‑relevant per the guideline that a data race on diagnostic state is NOT a vulnerability.  No defense is required or missing because the impact is merely inconsistent error reporting.

Thus the finding is 'INVALID' as a security vulnerability.


CRUX: It is a data race on a static error variable used only for internal diagnostic purposes; it does not provide an attacker with a meaningful exploit path.

GREP: _rpc_gss_error


🔎 **Grep results:**

GREP `_rpc_gss_error`:
```
lib/librpcsec_gss/rpcsec_gss_misc.c:34:static rpc_gss_error_t _rpc_gss_error;
lib/librpcsec_gss/rpcsec_gss_misc.c:40:	_rpc_gss_error.rpc_gss_error = rpc_gss_error;
lib/librpcsec_gss/rpcsec_gss_misc.c:41:	_rpc_gss_error.system_error = system_error;
lib/librpcsec_gss/rpcsec_gss_misc.c:48:	*error = _rpc_gss_error;
sys/rpc/rpcsec_gss/rpcsec_gss_misc.c:37:static rpc_gss_error_t _rpc_gss_error;
sys/rpc/rpcsec_gss/rpcsec_gss_misc.c:43:	_rpc_gss_error.rpc_gss_error = rpc_gss_error;
sys/rpc/rpcsec_gss/rpcsec_gss_misc.c:44:	_rpc_gss_error.system_error = system_error;
sys/rpc/rpcsec_gss/rpcsec_gss_misc.c:51:	*error = _rpc_gss_error;
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The race is limited to a static diagnostic “error” struct that is written by one thread and read by another without any synchronization.  It cannot corrupt memory, cause code execution, or leak additional sensitive data: the struct simply mirrors return values already visible to the caller.  The only effect is that a caller might receive a stale or partially‑combined error code, which could be used for cosmetic debugging or a very subtle denial‑of‑service, but does not provide an actionable attack surface.  Therefore the finding does not represent a real, exploitable security vulnerability.

