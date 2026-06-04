# Triage T0017: Arbitrary kernel‑space function‑pointer execution via CLSET_RECONUPCALL

- **File**: `clnt_rc.c`
- **Verdict**: INVALID
- **Confidence**: 25% [UUV→I]

---

## Finding

Arbitrary kernel‑space function‑pointer execution via CLSET_RECONUPCALL

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

**🎯 Crux:** Untrusted caller can set rc->rc_reconcall via CLSET_RECONUPCALL, leading to kernel-executed arbitrary function pointer.

The bug exists: clnt_reconnect_control accepts request CLSET_RECONUPCALL, casts user-provided info to a pointer to struct rpc_reconupcall and copies the function pointer upcp->call into rc->rc_reconcall without any bounds or NULL checks. When a reconnection occurs, clnt_reconnect_connect invokes (*rc->rc_reconcall)(newclient, rc->rc_reconarg, rc->rc_ucred); in kernel context. An attacker can invoke the public API CLNT_CONTROL on the reconnect CLIENT, passing any value for info, thus setting rc_reconcall to a user-specified kernel address. This allows an attacker to execute arbitrary kernel code or crash the kernel. No validation or size limit exists – the code blindly dereferences the supplied pointer.


CRUX: Untrusted caller can set rc->rc_reconcall via CLSET_RECONUPCALL, leading to kernel-executed arbitrary function pointer.
GREP: CLSET_RECONUPCALL
rpc_reconupcall

🔎 **Grep results:**

GREP `CLSET_RECONUPCALL`:
```
sys/rpc/clnt.h:323:#define	CLSET_RECONUPCALL	33	/* Reconnect upcall */
sys/rpc/clnt.h:318:/* Structure used as the argument for CLSET_RECONUPCALL. */
sys/fs/nfsclient/nfs_clrpcops.c:1138:				CLNT_CONTROL(nmp->nm_client, CLSET_RECONUPCALL,
sys/rpc/clnt_rc.c:533:	case CLSET_RECONUPCALL:
```

### Round 4: ❌ INVALID

[ARBITER] The function pointer is stored only for clients whose `cl_ops` points to `clnt_reconnect_ops`. Such clients are created exclusively by the kernel (e.g., by the NFS client module) via the internal `clnt_reconnect_create()` routine. Userland code cannot obtain a CLIENT with these operations, nor can it safely pass a user‐supplied `struct rpc_reconupcall` to the kernel. Consequently, no untrusted process can trigger the unchecked assignment to `rc->rc_reconcall` and cannot cause arbitrary kernel code execution or a crash. The apparent vulnerability exists only in source, not as a practical exploitable flaw.}

