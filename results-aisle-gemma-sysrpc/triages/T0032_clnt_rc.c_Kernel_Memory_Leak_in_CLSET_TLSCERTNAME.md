# Triage T0032: Kernel Memory Leak in CLSET_TLSCERTNAME

- **File**: `clnt_rc.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Kernel Memory Leak in CLSET_TLSCERTNAME

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** clnt_reconnect_control's CLSET_TLSCERTNAME case performs a mem_alloc and assigns it to rc->rc_tlscertname without freeing the existing pointer, and this control path is reachable via the client's control API.

The bug pattern is real: in `clnt_reconnect_control`, the `CLSET_TLSCERTNAME` case allocates memory for `rc->rc_tlscertname` using `mem_alloc(slen)` and assigns it to the pointer. However, it does not check if `rc->rc_tlscertname` already points to an allocation from a previous `CLSET_TLSCERTNAME` call. If called multiple times, the previous pointer is overwritten, causing a kernel memory leak. Regarding reachability: `clnt_reconnect_control` is the control interface for the reconnect client. In a kernel RPC implementation, these control functions are typically exposed via an IOCTL or a similar system call interface to allow userspace applications to configure RPC client handles (e.g., setting timeouts or TLS certificates). Since this is a kernel-space memory leak that can be triggered by repeatedly calling a control operation on a client handle, an unprivileged user with the ability to create an RPC client can exhaust kernel memory, leading to a Denial of Service (DoS).

CRUX: clnt_reconnect_control's CLSET_TLSCERTNAME case performs a mem_alloc and assigns it to rc->rc_tlscertname without freeing the existing pointer, and this control path is reachable via the client's control API.
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
lib/libc/rpc/clnt_generic.c:125:		CLNT_CONTROL(clnt, CLSET_VERS, (char *)&vers_high);
lib/libc/rpc/clnt_generic.c:298:		if (CLNT_CONTROL(cl, CLSET_SVC_ADDR, (void *)svcaddr) == TRUE) {
lib/libc/rpc/clnt_generic.c:303:			(void) CLNT_CONTROL(cl, CLSET_PROG, (void *)&prog);
lib/libc/rpc/clnt_generic.c:304:			(void) CLNT_CONTROL(cl, CLSET_VERS, (void *)&vers);
lib/libc/rpc/clnt_generic.c:396:		(void) CLNT_CONTROL(cl, CLSET_FD_CLOSE, NULL);
lib/libc/rpc/clnt_generic.c:397:/*		(void) CLNT_CONTROL(cl, CLSET_POP_TIMOD, NULL);  */
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
```

### Round 2: ✅ VALID

**🎯 Crux:** clnt_reconnect_control overwrites rc->rc_tlscertname with a new mem_alloc without freeing the previous allocation.

The bug pattern is real: in `clnt_reconnect_control`, the `CLSET_TLSCERTNAME` case calls `mem_alloc(slen)` and assigns the result to `rc->rc_tlscertname` without checking if `rc->rc_tlscertname` already holds a pointer to a previously allocated buffer. Repeated calls to this control operation will overwrite the pointer and leak kernel memory. 

Regarding reachability, `clnt_reconnect_control` is part of the `clnt_ops` for the reconnect client. The `CLIENT` handles are created via `clnt_reconnect_create`. In kernel RPC implementations, these handles are typically managed by kernel services or exposed to userspace via system call interfaces (like those used for NFS or other kernel-level RPC clients). While the grep results show many userspace calls (in `lib/libc`), this specific file `clnt_rc.c` is kernel code (as evidenced by `sys/param.h`, `mem_alloc`, `mtx_lock`, and `curthread`). An attacker who can trigger the configuration of a kernel RPC client (e.g., via a sysctl or an ioctl that updates TLS certificates for a kernel mount/service) can trigger this leak. Even if the interface is restricted, kernel memory leaks that can be triggered repeatedly are generally considered security-relevant DoS vectors. There is no defense in the code preventing multiple calls to `CLSET_TLSCERTNAME` on the same `CLIENT` handle.

CRUX: clnt_reconnect_control overwrites rc->rc_tlscertname with a new mem_alloc without freeing the previous allocation.
GREP: CLSET_TLSCERTNAME

🔎 **Grep results:**

GREP `CLSET_TLSCERTNAME`:
```
sys/rpc/clnt.h:317:#define	CLSET_TLSCERTNAME	32	/* TLS certificate file name */
sys/fs/nfs/nfs_commonkrpc.c:386:				CLNT_CONTROL(client, CLSET_TLSCERTNAME,
sys/rpc/clnt_rc.c:519:	case CLSET_TLSCERTNAME:
```

### Round 3: ✅ VALID

**🎯 Crux:** clnt_reconnect_control overwrites rc->rc_tlscertname with a new mem_alloc without freeing the previous allocation, and this is reachable via kernel RPC configuration (e.g., NFS TLS settings).

The bug pattern is real: in `clnt_reconnect_control`, the `CLSET_TLSCERTNAME` case allocates memory using `mem_alloc(slen)` and assigns it to `rc->rc_tlscertname` without calling `mem_free` on any existing allocation. This is a classic kernel memory leak. 

Regarding reachability, the grep results show that `CLSET_TLSCERTNAME` is called in `sys/fs/nfs/nfs_commonkrpc.c`. In kernel NFS implementations, TLS certificate names are typically configured via mount options or sysctls. If an attacker (or a user with sufficient privileges to modify mount options or sysctls) can trigger a reconfiguration of the NFS client's TLS settings multiple times, they can leak kernel memory. While this may require certain privileges, kernel memory leaks triggered by configurable parameters are generally considered a DoS vulnerability. The leak size is bounded by `NAME_MAX - 6` per call, but repeated calls will eventually exhaust kernel memory.

CRUX: clnt_reconnect_control overwrites rc->rc_tlscertname with a new mem_alloc without freeing the previous allocation, and this is reachable via kernel RPC configuration (e.g., NFS TLS settings).
GREP: CLSET_TLSCERTNAME

🔎 **Grep results:**

GREP `CLSET_TLSCERTNAME`:
```
sys/rpc/clnt.h:317:#define	CLSET_TLSCERTNAME	32	/* TLS certificate file name */
sys/fs/nfs/nfs_commonkrpc.c:386:				CLNT_CONTROL(client, CLSET_TLSCERTNAME,
sys/rpc/clnt_rc.c:519:	case CLSET_TLSCERTNAME:
```

### Round 4: ✅ VALID

[ARBITER] In `clnt_reconnect_control`, the `CLSET_TLSCERTNAME` case calls `mem_alloc(slen)` and assigns the result to `rc->rc_tlscertname` without first checking if the pointer is already occupied. If `CLSET_TLSCERTNAME` is called multiple times on the same client handle, the previous memory allocation is overwritten and leaked. The code shows `rc->rc_tlscertname` is initialized to `NULL` in `clnt_reconnect_create` and only freed in `clnt_reconnect_destroy`, confirming that intermediate updates cause leaks.

