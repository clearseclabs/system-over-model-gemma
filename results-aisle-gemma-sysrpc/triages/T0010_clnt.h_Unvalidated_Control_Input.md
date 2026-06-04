# Triage T0010: Unvalidated Control Input

- **File**: `clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Unvalidated Control Input

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** CLNT_CONTROL is a client-side configuration API; its input comes from the local application, not from remote network input.

The reported vulnerability focuses on `CLNT_CONTROL` and specifically the `CLSET_WAITCHAN` operation. `CLNT_CONTROL` is a client-side API used by an application to configure its own RPC client handle. The `info` parameter is provided by the application calling the RPC library, not by a remote server via the network. For this to be a security vulnerability, an attacker would need to control the input to the application that then calls `CLNT_CONTROL`. In standard RPC usage, `CLNT_CONTROL` is used for local configuration (e.g., setting timeouts or XIDs) and is not exposed to remote network input. The claim that it could lead to a kernel buffer overflow is speculative and depends on the transport-specific implementation of `cl_control`. However, since the data flow originates from the local application's control logic and not from untrusted network data received by the client, it does not meet the criteria for a reachable remote vulnerability.

CRUX: CLNT_CONTROL is a client-side configuration API; its input comes from the local application, not from remote network input.
GREP: CLNT_CONTROL

🔎 **Grep results:**

GREP `CLNT_CONTROL`:
```
include/rpc/clnt.h:199:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
sys/rpc/clnt.h:272:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
crypto/krb5/src/include/gssrpc/clnt.h:200:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
include/rpc/clnt.h:194: * CLNT_CONTROL(cl, request, info)
sys/rpc/clnt.h:267: * CLNT_CONTROL(cl, request, info)
crypto/krb5/src/include/gssrpc/clnt.h:195: * CLNT_CONTROL(cl, request, info)
lib/libc/rpc/clnt_simple.c:176:		(void) CLNT_CONTROL(rcp->client,
lib/libc/rpc/clnt_simple.c:178:		if (CLNT_CONTROL(rcp->client, CLGET_FD, (char *)(void *)&fd))
lib/libc/rpc/rpc_soc.c:135:			(void) CLNT_CONTROL(cl, CLSET_FD_CLOSE, NULL);
lib/libc/rpc/rpc_soc.c:166:	(void) CLNT_CONTROL(cl, CLSET_RETRY_TIMEOUT, &wait);
lib/libc/rpc/rpcb_clnt.c:447:		(void) CLNT_CONTROL(client, CLSET_FD_CLOSE, NULL);
lib/libc/rpc/rpcb_clnt.c:767:		CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *)&rpcbrmttime);
lib/libc/rpc/rpcb_clnt.c:768:		CLNT_CONTROL(client, CLSET_VERS, (char *)&pmapvers);
lib/libc/rpc/rpcb_clnt.c:792:		CLNT_CONTROL(client, CLGET_SVC_ADDR, (char *)&remote);
lib/libc/rpc/rpcb_clnt.c:869:			CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:880:		CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *)&rpcbrmttime);
lib/libc/rpc/rpcb_clnt.c:890:				CLNT_CONTROL(client, CLGET_SVC_ADDR,
lib/libc/rpc/rpcb_clnt.c:939:	CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *) &rpcbrmttime);
lib/libc/rpc/rpcb_clnt.c:942:		CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:967:			CLNT_CONTROL(client, CLGET_SVC_ADDR,
lib/libc/rpc/rpcb_clnt.c:1075:	CLNT_CONTROL(client, CLGET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:1078:		CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:1125:	CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *)(void *)&rmttimeout);
lib/libc/rpc/rpcb_clnt.c:1136:		CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&rpcb_vers);
lib/libc/rpc/rpcb_clnt.c:1221:		CLNT_CONTROL(client, CLGET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:1225:			CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&vers);
lib/libc/rpc/clnt_generic.c:125:		CLNT_CONTROL(clnt, CLSET_VERS, (char *)&vers_high);
lib/libc/rpc/clnt_generic.c:298:		if (CLNT_CONTROL(cl, CLSET_SVC_ADDR, (void *)svcaddr) == TRUE) {
lib/libc/rpc/clnt_generic.c:303:			(void) CLNT_CONTROL(cl, CLSET_PROG, (void *)&prog);
lib/libc/rpc/clnt_generic.c:304:			(void) CLNT_CONTROL(cl, CLSET_VERS, (void *)&vers);
```

### Round 2: ❌ INVALID

**🎯 Crux:** CLNT_CONTROL is a client-side API whose input is derived from local application logic and internal constants, not from untrusted network input.

The vulnerability report suggests that `CLNT_CONTROL` can be used to trigger a buffer overflow in the kernel via `CLSET_WAITCHAN`. However, `CLNT_CONTROL` is a client-side configuration API. The provided grep results show that it is called exclusively by internal library functions (`clnt_simple.c`, `rpc_soc.c`, `rpcb_clnt.c`, `clnt_generic.c`) using hardcoded constants, internal state variables (like `rpcbrmttime`, `pmapvers`), or pointers to local variables. There is no evidence of any path where an external network packet or untrusted user input is passed into the `info` parameter of `CLNT_CONTROL`. Since the input is controlled by the local application/library and not by a remote attacker, this is not a reachable security vulnerability.

CRUX: CLNT_CONTROL is a client-side API whose input is derived from local application logic and internal constants, not from untrusted network input.
GREP: CLNT_CONTROL

🔎 **Grep results:**

GREP `CLNT_CONTROL`:
```
include/rpc/clnt.h:199:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
sys/rpc/clnt.h:272:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
crypto/krb5/src/include/gssrpc/clnt.h:200:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
include/rpc/clnt.h:194: * CLNT_CONTROL(cl, request, info)
sys/rpc/clnt.h:267: * CLNT_CONTROL(cl, request, info)
crypto/krb5/src/include/gssrpc/clnt.h:195: * CLNT_CONTROL(cl, request, info)
lib/libc/rpc/clnt_simple.c:176:		(void) CLNT_CONTROL(rcp->client,
lib/libc/rpc/clnt_simple.c:178:		if (CLNT_CONTROL(rcp->client, CLGET_FD, (char *)(void *)&fd))
lib/libc/rpc/rpc_soc.c:135:			(void) CLNT_CONTROL(cl, CLSET_FD_CLOSE, NULL);
lib/libc/rpc/rpc_soc.c:166:	(void) CLNT_CONTROL(cl, CLSET_RETRY_TIMEOUT, &wait);
lib/libc/rpc/clnt_generic.c:125:		CLNT_CONTROL(clnt, CLSET_VERS, (char *)&vers_high);
lib/libc/rpc/clnt_generic.c:298:		if (CLNT_CONTROL(cl, CLSET_SVC_ADDR, (void *)svcaddr) == TRUE) {
lib/libc/rpc/clnt_generic.c:303:			(void) CLNT_CONTROL(cl, CLSET_PROG, (void *)&prog);
lib/libc/rpc/clnt_generic.c:304:			(void) CLNT_CONTROL(cl, CLSET_VERS, (void *)&vers);
lib/libc/rpc/clnt_generic.c:396:		(void) CLNT_CONTROL(cl, CLSET_FD_CLOSE, NULL);
lib/libc/rpc/clnt_generic.c:397:/*		(void) CLNT_CONTROL(cl, CLSET_POP_TIMOD, NULL);  */
lib/libc/rpc/rpcb_clnt.c:447:		(void) CLNT_CONTROL(client, CLSET_FD_CLOSE, NULL);
lib/libc/rpc/rpcb_clnt.c:767:		CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *)&rpcbrmttime);
lib/libc/rpc/rpcb_clnt.c:768:		CLNT_CONTROL(client, CLSET_VERS, (char *)&pmapvers);
lib/libc/rpc/rpcb_clnt.c:792:		CLNT_CONTROL(client, CLGET_SVC_ADDR, (char *)&remote);
lib/libc/rpc/rpcb_clnt.c:869:			CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:880:		CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *)&rpcbrmttime);
lib/libc/rpc/rpcb_clnt.c:890:				CLNT_CONTROL(client, CLGET_SVC_ADDR,
lib/libc/rpc/rpcb_clnt.c:939:	CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *) &rpcbrmttime);
lib/libc/rpc/rpcb_clnt.c:942:		CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:967:			CLNT_CONTROL(client, CLGET_SVC_ADDR,
lib/libc/rpc/rpcb_clnt.c:1075:	CLNT_CONTROL(client, CLGET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:1078:		CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&vers);
lib/libc/rpc/rpcb_clnt.c:1125:	CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, (char *)(void *)&rmttimeout);
lib/libc/rpc/rpcb_clnt.c:1136:		CLNT_CONTROL(client, CLSET_VERS, (char *)(void *)&rpcb_vers);
```

### Round 3: ❌ INVALID

**🎯 Crux:** CLNT_CONTROL is a client-side configuration API; its input is provided by the local application, not by a remote attacker via the network.

The reported vulnerability claims that the `info` parameter in `CLNT_CONTROL` is unvalidated and could lead to a kernel buffer overflow, specifically mentioning `CLSET_WAITCHAN` and `msleep`. 

1. **Bug Pattern**: The `CLNT_CONTROL` macro is indeed a pass-through to a transport-specific `cl_control` function. Whether this is a 'bug' depends entirely on the implementation of that function. 

2. **Reachability**: The crucial point is who calls `CLNT_CONTROL`. As shown in the provided grep results, `CLNT_CONTROL` is called by the RPC client library itself (e.g., `rpcb_clnt.c`, `clnt_generic.c`, `rpc_soc.c`). These calls use internal state (like `rpcbrmttime` or `pmapvers`) or hardcoded constants. 

3. **Attacker Control**: For this to be a security vulnerability, a remote attacker must be able to control the `info` argument. The RPC client library is used by a local application to communicate with a remote server. `CLNT_CONTROL` is the mechanism the *local application* uses to configure its *own* client handle. It is not a function that processes data received from the network. While the report suggests that `info` could be derived from external input, there is no evidence in the codebase of any path where network-received data is passed into `CLNT_CONTROL`. 

4. **Verdict**: Since the input to `CLNT_CONTROL` originates from the trusted local application/library and not from an untrusted remote source, the attack vector is not reachable. Even if the underlying `cl_control` implementation were vulnerable to a buffer overflow, it would require the local process to intentionally pass a malicious string to its own RPC library, which is not a remote security vulnerability.

CRUX: CLNT_CONTROL is a client-side configuration API; its input is provided by the local application, not by a remote attacker via the network.
GREP: CLNT_CONTROL

🔎 **Grep results:**

GREP `CLNT_CONTROL`:
```
include/rpc/clnt.h:199:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
sys/rpc/clnt.h:272:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
crypto/krb5/src/include/gssrpc/clnt.h:200:#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
include/rpc/clnt.h:194: * CLNT_CONTROL(cl, request, info)
sys/rpc/clnt.h:267: * CLNT_CONTROL(cl, request, info)
crypto/krb5/src/include/gssrpc/clnt.h:195: * CLNT_CONTROL(cl, request, info)
sys/fs/nfsclient/nfs_clrpcops.c:1139:				CLNT_CONTROL(nmp->nm_client, CLSET_RECONUPCALL,
sys/fs/nfs/nfs_commonkrpc.c:377:	CLNT_CONTROL(client, CLSET_WAITCHAN, "nfsreq");
sys/fs/nfs/nfs_commonkrpc.c:380:			CLNT_CONTROL(client, CLSET_INTERRUPTIBLE, &one);
sys/fs/nfs/nfs_commonkrpc.c:382:			CLNT_CONTROL(client, CLSET_PRIVPORT, &one);
sys/fs/nfs/nfs_commonkrpc.c:384:			CLNT_CONTROL(client, CLSET_TLS, &one);
sys/fs/nfs/nfs_commonkrpc.c:386:				CLNT_CONTROL(client, CLSET_TLSCERTNAME,
sys/fs/nfs/nfs_commonkrpc.c:425:					CLNT_CONTROL(client, CLSET_TIMEOUT,
sys/fs/nfs/nfs_commonkrpc.c:438:					CLNT_CONTROL(client, CLSET_BACKCHANNEL,
sys/fs/nfs/nfs_commonkrpc.c:465:				CLNT_CONTROL(client, CLSET_TIMEOUT, &timo);
sys/fs/nfs/nfs_commonkrpc.c:478:			CLNT_CONTROL(client, CLSET_PRIVPORT, &one);
sys/fs/nfs/nfs_commonkrpc.c:483:			CLNT_CONTROL(client, CLSET_TLS, &one);
sys/fs/nfs/nfs_commonkrpc.c:485:	CLNT_CONTROL(client, CLSET_RETRIES, &retries);
sys/fs/nfs/nfs_commonkrpc.c:505:		CLNT_CONTROL(client, CLSET_RETRY_TIMEOUT, &timo);
sys/fs/nfs/nfs_commonkrpc.c:531:			CLNT_CONTROL(client, CLSET_CONNECT, &one);
sys/rpc/rpcsec_tls/rpctls_impl.c:209:		CLNT_CONTROL(ups.cl, CLSET_TLS, &(int){RPCTLS_INHANDSHAKE});
sys/rpc/rpcsec_tls/rpctls_impl.c:285:	CLNT_CONTROL(newclient, CLSET_BLOCKRCV, &(int){1});
sys/rpc/rpcsec_tls/rpctls_impl.c:301:	CLNT_CONTROL(newclient, CLSET_BLOCKRCV, &(int){0});
sys/rpc/clnt_rc.c:206:			CLNT_CONTROL(newclient, CLSET_FD_CLOSE, 0);
sys/rpc/clnt_rc.c:223:			CLNT_CONTROL(newclient, CLSET_TLS,
sys/rpc/clnt_rc.c:245:	CLNT_CONTROL(newclient, CLSET_CONNECT, &one);
sys/rpc/clnt_rc.c:246:	CLNT_CONTROL(newclient, CLSET_TIMEOUT, &rc->rc_timeout);
sys/rpc/clnt_rc.c:247:	CLNT_CONTROL(newclient, CLSET_RETRY_TIMEOUT, &rc->rc_retry);
sys/rpc/clnt_rc.c:248:	CLNT_CONTROL(newclient, CLSET_WAITCHAN, rc->rc_waitchan);
sys/rpc/clnt_rc.c:249:	CLNT_CONTROL(newclient, CLSET_INTERRUPTIBLE, &rc->rc_intr);
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability claims that the `info` parameter in `CLNT_CONTROL` is unvalidated and could lead to a kernel buffer overflow. However, evidence from the codebase shows that `CLNT_CONTROL` is a client-side configuration API. Its inputs are derived exclusively from internal library functions, hardcoded constants (e.g., `CLNT_CONTROL(client, CLSET_WAITCHAN, "nfsreq")`), or internal state variables. There is no evidence of a path where untrusted external or network input reaches the `info` parameter. Consequently, there is no viable attack vector for a remote attacker to trigger the suggested overflow.

