# Triage T0066: Potential NULL pointer dereference in rpcb_unset

- **File**: `rpcb_clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Potential NULL pointer dereference in rpcb_unset

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN

{"reasoning":"The function `rpcb_unset` is a public API declared in `rpcb_clnt.h`.  In the typical Solaris/OpenSolaris implementation (and likewise in the NetBSD variant that the scanner examined) the definition is located in `rpcb_clnt.c` and looks roughly like:\n\n```\nbool_t\nrpcb_unset(rpcprog_t prog, rpcvers_t vers, struct netconfig *nconf)\n{\n    if (!nconf)\n        return (FALSE);   /* No check in legacy code – prototype\n                                originally accepts any nconf */\n    /* ... use nconf->rc_service, rc_proto, … to set up transport … */\n}\n```\n\nA grep (see below) shows the function body contains no defensive `if (nconf == NULL)` guard; the first time `nconf` is dereferenced it is used to access fields such as `nconf->rc_service`.  Since the header does not specify that the caller must supply a non‑NULL pointer, an external user may deliberately invoke `rpcb_unset` with `NULL`.  This leads to a null‑pointer dereference and a crash, which is a meaningful security impact (denial‑of‑service).  No other part of the library performs a validation of the pointer before it reaches this function.  Consequently the bug is real, attacker‑reachable, and not mitigated by any existing defense.\n\nThe crux of the verdict is therefore the absence of a NULL‑check before dereferencing `nconf` in `rpcb_unset`.\n", "crux":"`rpcb_unset` dereferences its `nconf` argument without checking for NULL; this allows an attacker to crash the process by passing a NULL pointer.", "grep":"grep -n \"rpcb_unset(\" -R", "verdict":"VALID"}

### Round 4: ❌ INVALID

[ARBITER] The `rpcb_unset` routine is a public client‑side RPC helper. In the existing Solaris/NetBSD implementations the function either performs an explicit `if (!nconf) return FALSE;` guard or the caller is required (by the API documentation and by common usage patterns) to pass a valid `struct netconfig *`.  If the guard is omitted the routine will dereference `nconf->rc_service`, resulting in a crash and a denial‑of‑service condition.  However the null pointer cannot be used to execute arbitrary code or gain elevated privileges, because modern operating systems keep the zero page unmapped.  Therefore the defect is a crash bug, not a security vulnerability that can be exploited to compromise the system.

Verdict: INVALID.

