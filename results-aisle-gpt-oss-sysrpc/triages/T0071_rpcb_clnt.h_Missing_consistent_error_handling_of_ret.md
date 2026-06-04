# Triage T0071: Missing consistent error handling of return values

- **File**: `rpcb_clnt.h`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [IUU]

---

## Finding

Missing consistent error handling of return values

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** Ignoring return values from RPC bind client functions cannot be leveraged by an attacker to cause a crash, code execution, or other meaningful damage.

The reported issue concerns client‑side functions such as `rpcb_set`, `rpcb_unset`, `rpcb_getmaps`, `rpcb_rmtcall`, etc.  All of these functions are declared in `rpcb_clnt.h` and are meant for use by other system libraries or programs.  They return a `bool_t` or a value of type `enum clnt_stat` to indicate success or failure.  The scanner flagged that callers might ignore these values, potentially allowing partially constructed structures to be used later.

1. **Existence of the bug pattern** – The code defines these functions; the return types are clearly documented.  There is no defensive requirement in the API that mandates callers to check the return value.  Therefore the *pattern* “ignoring a return value” exists in the interface.

2. **Attacker reachability** – The API is intended mainly for internal libraries and services.  A typical caller would be a program that performs RPC bind operations; it has no way to influence the success of those operations beyond normal network or configuration errors.  An attacker controlling an untrusted client could call the functions, but ignoring the return value would simply cause the client program to continue in an erroneous state.  No subsequent step uses attacker‑controlled data to perform a memory overwrite or execute arbitrary code.  The only possible consequence is a crash or a duplicated bind entry, which does not give the attacker any actionable privilege or persistent state.

3. **Defences** – There are no compile‑time or runtime checks that force a program to examine the return value.  The library itself merely propagates the result of the underlying network call; it does not employ defensive programming to avoid use of partially initialised values.  Consequently, any program that wishes to use these functions must explicitly test the result.  The lack of a compulsory check is a documentation omission, not a logical defect that can be exploited.

4. **Security relevance** – Ignoring a returned status code may cause a program to crash or misbehave, but that is a classical “use‑after‑failure” bug that is a maintenance/security‑quality issue, not an exploitable vulnerability.  The indicated risk (undefined behaviour from partially constructed structures) cannot be achieved by an attacker; it would only be triggered by a buggy caller who simply forgets to check the function return.

Given the above, the scanner’s flag is a *code‑quality* issue rather than a real security vulnerability.  No practical exploit can be derived from an attacker’s ability to ignore the return values.

**Verdict:** INVALID.

**Crux:** Ignoring the status return from the RPC bind client API does not provide an attacker with a useful attack surface; it can only produce crashes or incorrect program logic.

**Grep to verify the crux**: searching for the function definitions provides evidence that the API exists and that there is no enforced error‑checking mechanism.  The pattern "rpcb_set" (and its siblings) locates the function prototypes in the header and their corresponding implementations in `rpcb_clnt.c`.

CRUX: Ignoring return values from RPC bind client functions cannot be leveraged by an attacker to cause a crash, code execution, or other meaningful damage.
GREP: rpcb_set

🔎 **Grep results:**

GREP `rpcb_set`:
```
include/rpc/rpcb_clnt.h:44: *	success = rpcb_set(program, version, nconf, address);
include/rpc/rpcb_clnt.h:64:extern bool_t rpcb_set(const rpcprog_t, const rpcvers_t,
sys/rpc/rpcb_clnt.h:44: *	success = rpcb_set(program, version, nconf, address);
sys/rpc/rpcb_clnt.h:66:extern bool_t rpcb_set(const rpcprog_t, const rpcvers_t,
usr.sbin/ypserv/yp_main.c:438:		rpcb_set(YPPROG, YPOLDVERS, nconf, &svcaddr);
usr.sbin/ypserv/yp_main.c:441:	rpcb_set(YPPROG, YPVERS, nconf, &svcaddr);
usr.sbin/mountd/mountd.c:1121:			rpcb_set(MOUNTPROG, MOUNTVERS, nconf, &servaddr);
usr.sbin/mountd/mountd.c:1122:			rpcb_set(MOUNTPROG, MOUNTVERS3, nconf, &servaddr);
lib/libc/rpc/svc.c:226:		dummy = rpcb_set(prog, vers, (struct netconfig *) nconf,
usr.sbin/rpc.lockd/lockd.c:812:			rpcb_set(NLM_PROG, NLM_SM, nconf, &servaddr);
usr.sbin/rpc.lockd/lockd.c:813:			rpcb_set(NLM_PROG, NLM_VERS, nconf, &servaddr);
usr.sbin/rpc.lockd/lockd.c:814:			rpcb_set(NLM_PROG, NLM_VERSX, nconf, &servaddr);
usr.sbin/rpc.lockd/lockd.c:815:			rpcb_set(NLM_PROG, NLM_VERS4, nconf, &servaddr);
lib/libc/rpc/rpcb_clnt.c:518:rpcb_set(rpcprog_t program, rpcvers_t version, const struct netconfig *nconf,
lib/libc/rpc/pmap_clnt.c:79:	rslt = rpcb_set((rpcprog_t)program, (rpcvers_t)version, nconf, na);
lib/libc/rpc/svc_simple.c:186:			/* so that svc_reg does not call rpcb_set() */
usr.sbin/nfsd/nfsd.c:342:				if (!rpcb_set(NFS_PROGRAM, 2, nconf_udp,
usr.sbin/nfsd/nfsd.c:344:					err(1, "rpcb_set udp failed");
usr.sbin/nfsd/nfsd.c:346:				if (!rpcb_set(NFS_PROGRAM, 3, nconf_udp,
usr.sbin/nfsd/nfsd.c:348:					err(1, "rpcb_set udp failed");
usr.sbin/nfsd/nfsd.c:366:				if (!rpcb_set(NFS_PROGRAM, 2, nconf_udp6,
usr.sbin/nfsd/nfsd.c:368:					err(1, "rpcb_set udp6 failed");
usr.sbin/nfsd/nfsd.c:370:				if (!rpcb_set(NFS_PROGRAM, 3, nconf_udp6,
usr.sbin/nfsd/nfsd.c:372:					err(1, "rpcb_set udp6 failed");
usr.sbin/nfsd/nfsd.c:390:				if (!rpcb_set(NFS_PROGRAM, 2, nconf_tcp,
usr.sbin/nfsd/nfsd.c:392:					err(1, "rpcb_set tcp failed");
usr.sbin/nfsd/nfsd.c:394:				if (!rpcb_set(NFS_PROGRAM, 3, nconf_tcp,
usr.sbin/nfsd/nfsd.c:396:					err(1, "rpcb_set tcp failed");
usr.sbin/nfsd/nfsd.c:414:				if (!rpcb_set(NFS_PROGRAM, 2, nconf_tcp6,
usr.sbin/nfsd/nfsd.c:416:					err(1, "rpcb_set tcp6 failed");
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



