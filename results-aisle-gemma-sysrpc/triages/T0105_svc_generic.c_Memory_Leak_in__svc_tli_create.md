# Triage T0105: Memory Leak in `svc_tli_create`

- **File**: `svc_generic.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Memory Leak in `svc_tli_create`

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The allocation occurs during transport creation (server initialization), which is not an attacker-reachable path for memory exhaustion.

The report identifies a potential memory leak of `xprt->xp_netid` allocated via `strdup` in `svc_tli_create`. To determine if this is a security vulnerability, we must verify if the memory is freed during the transport's destruction. In RPC implementations, `SVC_RELEASE` or `xprt_unregister` typically handle the cleanup of the `SVCXPRT` structure. Even if a leak exists, the allocation occurs during server initialization (creating a transport), which is typically a privileged operation performed at boot or by a root-level daemon. An external attacker cannot trigger the repeated creation and destruction of RPC transports to exhaust kernel memory. Therefore, this is a code quality issue (memory leak) rather than a security vulnerability.

CRUX: The allocation occurs during transport creation (server initialization), which is not an attacker-reachable path for memory exhaustion.
GREP: SVC_RELEASE|xprt_unregister

🔎 **Grep results:**

GREP `SVC_RELEASE`:
```
sys/rpc/svc.h:355:#define SVC_RELEASE(xprt)			\
sys/fs/nfsclient/nfs_clkrpc.c:208:		SVC_RELEASE(xprt);
sys/fs/nfsserver/nfs_nfsdkrpc.c:563:		SVC_RELEASE(xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:424:				SVC_RELEASE(old_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:490:			SVC_RELEASE(old_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:565:			SVC_RELEASE(old_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:642:			SVC_RELEASE(old_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:649:			SVC_RELEASE(old_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:899:			SVC_RELEASE(old_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:982:		SVC_RELEASE(old_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:6573:		SVC_RELEASE(savxprt);
sys/fs/nfsserver/nfs_nfsdstate.c:6627:			SVC_RELEASE(sep->sess_cbsess.nfsess_xprt);
sys/fs/nfsserver/nfs_nfsdstate.c:6794:					SVC_RELEASE(xprt);
sys/rpc/svc.c:206:		SVC_RELEASE(xprt);
sys/rpc/svc.c:393:	SVC_RELEASE(xprt);
sys/rpc/svc.c:1102:		SVC_RELEASE(xprt);
sys/rpc/svc.c:1319:		SVC_RELEASE(xprt);
sys/rpc/svc.c:1340:		SVC_RELEASE(xprt);
sys/rpc/svc.c:1488:		SVC_RELEASE(rqstp->rq_xprt);
sys/rpc/svc_vc.c:477:		SVC_RELEASE(new_xprt);
sys/rpc/clnt_rc.c:584:		SVC_RELEASE(xprt);
sys/rpc/svc_generic.c:114:		SVC_RELEASE(xprt);
sys/rpc/clnt_vc.c:866:		SVC_RELEASE(xprt);
sys/nlm/nlm_prot_impl.c:1514:			SVC_RELEASE(xprts[j]);
```

GREP `xprt_unregister`:
```
crypto/krb5/src/include/gssrpc/rename.h:187:#define xprt_unregister		gssrpc_xprt_unregister
sys/rpc/rpc_com.h:94:void __xprt_unregister_unlocked(SVCXPRT *);
sys/rpc/svc.h:56: * they in turn call xprt_register and xprt_unregister.
sys/rpc/svc.h:460: * xprt_unregister(xprt)
sys/rpc/svc.h:464:extern void	xprt_unregister(SVCXPRT *);
sys/rpc/svc.h:465:extern void	__xprt_unregister_unlocked(SVCXPRT *);
lib/libc/rpc/rpc_com.h:83:void __xprt_unregister_unlocked(SVCXPRT *);
include/rpc/svc.h:49: * they in turn call xprt_register and xprt_unregister.
include/rpc/svc.h:266: * xprt_unregister(xprt)
include/rpc/svc.h:270:extern void	xprt_unregister(SVCXPRT *);
crypto/krb5/src/include/gssrpc/svc.h:51: * they in turn call xprt_register and xprt_unregister.
crypto/krb5/src/include/gssrpc/svc.h:225: * xprt_unregister(xprt)
crypto/krb5/src/include/gssrpc/svc.h:228:extern void	xprt_unregister(SVCXPRT *);
sys/rpc/svc.c:75:static void xprt_unregister_locked(SVCXPRT *xprt);
sys/rpc/svc.c:198:			xprt_unregister_locked(xprt);
sys/rpc/svc.c:365:xprt_unregister_locked(SVCXPRT *xprt)
sys/rpc/svc.c:371:	    ("xprt_unregister_locked: not registered"));
sys/rpc/svc.c:378:xprt_unregister(SVCXPRT *xprt)
sys/rpc/svc.c:388:	xprt_unregister_locked(xprt);
sys/rpc/svc.c:441:		 * Race with xprt_unregister - we lose.
sys/rpc/svc.c:1025:		xprt_unregister(xprt);
sys/rpc/svc.c:1094:			xprt_unregister_locked(xprt);
sys/rpc/svc_generic.c:113:		xprt_unregister(xprt);
sys/rpc/svc_generic.c:227:		xprt_unregister(xprt);
sys/rpc/clnt_rc.c:583:		xprt_unregister(xprt);
lib/libc/rpc/svc_dg.c:393:	xprt_unregister(xprt);
lib/libc/rpc/svc.c:123:xprt_unregister(SVCXPRT *xprt)
lib/libc/rpc/svc.c:129:__xprt_unregister_unlocked(SVCXPRT *xprt)
lib/libc/rpc/svc.c:725:			 *	XXX Should we do an xprt_unregister() instead?
lib/libc/rpc/svc_vc.c:377:	xprt_unregister(xprt);
```

### Round 2: ❌ INVALID

**🎯 Crux:** The allocation occurs during server initialization (transport creation), which is a privileged operation and not reachable by an external attacker for memory exhaustion.

The vulnerability report identifies a potential memory leak of `xprt->xp_netid` allocated via `strdup` in `svc_tli_create`. To determine if this is a security vulnerability, we must analyze the reachability and impact. The `svc_tli_create` function is a transport factory used during the setup of an RPC server. This typically occurs during system boot or when a privileged daemon (running as root) initializes its network interfaces. An external, unprivileged attacker cannot trigger the repeated execution of `svc_tli_create` and subsequent `SVC_RELEASE`/`xprt_unregister` calls to exhaust kernel memory. Even if the `SVCXPRT` destructor fails to free `xp_netid`, the leak occurs in a privileged initialization path, making it a code quality issue (memory leak) rather than a security vulnerability. Per the provided rules, memory leaks in non-attacker-reachable paths or those that cannot be used to cause meaningful harm (like crash or code execution via an external trigger) are marked INVALID.

CRUX: The allocation occurs during server initialization (transport creation), which is a privileged operation and not reachable by an external attacker for memory exhaustion.
GREP: svc_tli_create

🔎 **Grep results:**

GREP `svc_tli_create`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The allocation occurs in a privileged transport creation path that is not reachable by an external attacker for the purpose of memory exhaustion.

The report identifies a memory leak in `svc_tli_create` where `xprt->xp_netid` is allocated via `strdup` but potentially not freed. To determine if this is a security vulnerability, I must evaluate if an external attacker can trigger this allocation repeatedly to exhaust kernel memory. `svc_tli_create` is a factory function used to create an RPC transport handle (`SVCXPRT`). This process involves opening sockets and binding to ports (using `bindresvport` and `solisten`), which are privileged operations typically performed during system initialization or by root-level daemons. An external, unprivileged attacker cannot trigger the creation and subsequent destruction of RPC transports. Since the attacker cannot control the execution of this path to cause resource exhaustion, this is a code quality issue (memory leak) and not a security vulnerability.

CRUX: The allocation occurs in a privileged transport creation path that is not reachable by an external attacker for the purpose of memory exhaustion.
GREP: svc_tli_create

🔎 **Grep results:**

GREP `svc_tli_create`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] While there is a technical memory leak (xp_netid allocated via strdup in svc_tli_create is not explicitly freed in the provided code), it does not constitute a security vulnerability. The allocation occurs during server initialization (transport creation), which requires privileged operations such as opening sockets and binding to ports (via bindresvport and solisten). This path is not reachable by an unprivileged external attacker, meaning it cannot be used to trigger kernel memory exhaustion.

