# Triage T0019: indings Summary

- **File**: `clnt_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

indings Summary

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** clnt_dg_control is an internal API for the RPC client; its 'info' parameter is not reachable by a remote attacker, making the memcpy overflows invalid as security vulnerabilities.

I evaluated the three reported findings. 

1. **CLSET_SVC_ADDR Overflow**: The code in `clnt_dg_control` does `memcpy(&cu->cu_raddr, addr, addr->sa_len)`. `cu->cu_raddr` is a `struct sockaddr_storage`, which is designed to hold any socket address. However, `addr` is a pointer to a `struct sockaddr` provided via the `info` argument. In this kernel implementation, `clnt_dg_control` is an internal API used by the RPC client. The `info` pointer comes from the caller of the RPC client library. In a kernel-space RPC client, the callers are other kernel components. If this is exposed to user-space via a syscall or ioctl, it could be a vulnerability. However, the provided context indicates this is the client-side transport. The `sa_len` is read from the `sockaddr` structure itself. Since `struct sockaddr_storage` is the largest possible sockaddr, and `addr` is cast from `info`, an attacker providing a crafted `sockaddr` with a large `sa_len` could indeed overflow `cu_raddr`. But we must determine if `info` is attacker-reachable. In most BSD/Solaris-style kernels, `clnt_control` is not a direct syscall; it is used by kernel services (like NFS). If the kernel is acting as an RPC client, the 'attacker' would need to control the server address the kernel is connecting to. While `CLSET_SVC_ADDR` allows changing the address, the `info` buffer is provided by the internal kernel caller, not by a remote network packet.

2. **CLGET_SVC_ADDR Overflow**: The code does `memcpy(info, &cu->cu_raddr, cu->cu_raddr.ss_len)`. The `info` buffer is provided by the caller. This is a classic buffer overflow if the caller provides a buffer smaller than `ss_len`. Again, this depends on whether a user-space attacker can trigger this via a system call. In the context of a kernel RPC client, this is an internal API.

3. **Predictable XID**: The code uses `atomic_fetchadd_32(&rpc_xid, 1)`. This is strictly sequential. For a client, this allows an attacker to predict the XID of a pending request and inject a forged response. This is a known weakness in RPC, but since the client only accepts responses that match a pending XID and are validated via `AUTH_VALIDATE`, the attacker must also bypass authentication. If `AUTH_NULL` is used, this is a valid security issue (spoofing). However, the prompt asks for a 'meaningful harm' trigger. Predictable XIDs in a kernel client are a significant risk for services like NFS.

Comparing the three, the memory corruption bugs in `clnt_dg_control` depend on the `info` pointer being attacker-reachable. In kernel-space RPC clients, `clnt_control` is almost always called by trusted kernel code. The XID issue is a real architectural flaw in the provided code, but the memory overflows are the 'Critical/High' findings. Since the `info` parameter is not derived from network input (the network input is handled in `clnt_dg_soupcall`), the memory overflows are not remotely triggerable. The XID issue is a protocol-level weakness, but the most 'real' bug in the provided C code snippet is the lack of bounds checking in `CLSET_SVC_ADDR`. However, since `clnt_dg_control` is an internal management function for the RPC client handle, and not a packet-processing function, it is not reachable by a remote attacker.

CRUX: clnt_dg_control is an internal API for the RPC client; its 'info' parameter is not reachable by a remote attacker, making the memcpy overflows invalid as security vulnerabilities.
GREP: clnt_control

🔎 **Grep results:**

GREP `clnt_control`:
```
sys/rpc/clnt.h:273:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
include/rpc/clnt.h:200:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
crypto/krb5/src/include/gssrpc/clnt.h:201:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
sys/rpc/clnt_bck.c:108: * Default options are set, which the user can change using clnt_control()'s.
sys/rpc/rpcsec_tls/rpctls_impl.c:123:	clnt_control(cl, CLSET_RETRIES, &(int){1});
sys/rpc/rpcsec_tls/rpctls_impl.c:124:	clnt_control(cl, CLSET_TIMEOUT, &(struct timeval){.tv_sec = 15});
sys/rpc/rpcsec_tls/rpctls_impl.c:125:	clnt_control(cl, CLSET_WAITCHAN, __DECONST(char *, group));
sys/rpc/clnt_vc.c:114: * Default options are set, which the user can change using clnt_control()'s.
sys/rpc/rpcb_clnt.c:69:	clnt_control(rpcb_clnt, CLSET_RETRIES, &(int){6});
sys/rpc/rpcb_clnt.c:70:	clnt_control(rpcb_clnt, CLSET_WAITCHAN, "rpcb");
sys/rpc/clnt_dg.c:161: * Default options are set, which the user can change using clnt_control().
sys/rpc/clnt_dg.c:228:	/* Other values can also be set through clnt_control() */
sys/rpc/clnt_dg.c:260:	 * to do a close on it, else the user may use clnt_control
sys/kgssapi/gss_impl.c:73:	clnt_control(cl, CLSET_RETRIES, &(int){30});
sys/kgssapi/gss_impl.c:74:	clnt_control(cl, CLSET_TIMEOUT, &(struct timeval){.tv_sec = 300});
sys/kgssapi/gss_impl.c:79:	clnt_control(cl, CLSET_WAITCHAN, "gssd");
usr.sbin/yppush/yppush_main.c:340:	if (clnt_control(clnt, CLSET_TIMEOUT, (char *)&timeout) == FALSE)
usr.sbin/spray/spray.c:133:	clnt_control(cl, CLSET_TIMEOUT, &NO_DEFAULT);
usr.sbin/ypserv/yp_server.c:296:	if (clnt_control(clnt, CLSET_TIMEOUT, &timeout) == FALSE)
usr.sbin/ypbind/yp_ping.c:262:	clnt_control(clnt, CLSET_TIMEOUT, (char *)&tv);
usr.sbin/ypbind/yp_ping.c:264:	clnt_control(clnt, CLSET_ASYNC, (char *)&async);
usr.sbin/ypbind/yp_ping.c:270:			clnt_control(clnt, CLSET_XID, (char *)&reqs[i]->xid);
usr.sbin/ypbind/yp_ping.c:273:			clnt_control(clnt, CLSET_SVC_ADDR, &addr);
usr.sbin/ypbind/yp_ping.c:282:	clnt_control(clnt, CLGET_XID, (char *)&xid_lookup);
usr.sbin/rpc.lockd/test.c:7:/* Default timeout can be changed using clnt_control() */
usr.sbin/rpc.lockd/test.c:313:	clnt_control(cli, CLGET_TIMEOUT, &tim);
usr.sbin/rpc.lockd/test.c:317:	clnt_control(cli, CLSET_TIMEOUT, &tim);
usr.sbin/rpc.lockd/test.c:318:	clnt_control(cli, CLGET_TIMEOUT, &tim);
usr.sbin/rpc.lockd/lock_proc.c:276:	clnt_control(client, CLGET_FD, &clnt_fd);
usr.sbin/rpc.lockd/lock_proc.c:313:	clnt_control(client, CLSET_TIMEOUT, (char *)&retry_time);
```

### Round 2: ❌ INVALID

**🎯 Crux:** clnt_dg_control is an internal API called by trusted kernel components or the RPC library; it is not exposed to untrusted remote or local user input via a syscall/ioctl.

The reported memory overflows occur in `clnt_dg_control`. This function is accessed via the `clnt_control` macro, which calls the `cl_control` operation for a given `CLIENT` handle. The code is located in a kernel-space implementation (`sys/rpc/clnt_dg.c`), and the provided grep results show that `clnt_control` is used by other kernel components (e.g., `rpctls_impl.c`, `rpcb_clnt.c`, `gss_impl.c`) and user-space utilities (e.g., `yp_ping.c`, `yppush_main.c`). For a user-space utility to call `clnt_control`, it must be linking against the RPC library; the call then happens in the process's own address space (if it's a user-space library) or via a system call if it's a kernel-wrapped service. In the provided kernel code, `clnt_dg_control` operates on `struct cu_data`, which is allocated via `mem_alloc`. The `info` pointer is passed directly from the caller. In `CLSET_SVC_ADDR`, the code performs `memcpy(&cu->cu_raddr, addr, addr->sa_len)`. Because `addr` is cast from `info`, and `addr->sa_len` is read from the buffer provided by the caller, a caller can provide a `sa_len` larger than `sizeof(struct sockaddr_storage)`, leading to a kernel heap overflow. However, `clnt_control` is a management API for the RPC client handle. In this architecture, the 'attacker' would need to be a local user with the ability to call this API on a kernel-managed RPC handle. There is no evidence that this internal kernel function is exposed to untrusted user-space input via a syscall or ioctl. It is an API for the RPC client library itself. Since it is not reachable by a remote network attacker (the network path is exclusively in `clnt_dg_soupcall`), and not exposed to unprivileged local users via a syscall, it is an internal API issue. The XID predictability is a known protocol weakness but requires bypassing `AUTH_VALIDATE` to be exploitable, and the reported 'critical' bugs are not remotely reachable.

CRUX: clnt_dg_control is an internal API called by trusted kernel components or the RPC library; it is not exposed to untrusted remote or local user input via a syscall/ioctl.
GREP: clnt_control

🔎 **Grep results:**

GREP `clnt_control`:
```
sys/rpc/clnt.h:273:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
include/rpc/clnt.h:200:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
crypto/krb5/src/include/gssrpc/clnt.h:201:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
sys/rpc/rpcb_clnt.c:69:	clnt_control(rpcb_clnt, CLSET_RETRIES, &(int){6});
sys/rpc/rpcb_clnt.c:70:	clnt_control(rpcb_clnt, CLSET_WAITCHAN, "rpcb");
sys/rpc/clnt_bck.c:108: * Default options are set, which the user can change using clnt_control()'s.
sys/rpc/rpcsec_tls/rpctls_impl.c:123:	clnt_control(cl, CLSET_RETRIES, &(int){1});
sys/rpc/rpcsec_tls/rpctls_impl.c:124:	clnt_control(cl, CLSET_TIMEOUT, &(struct timeval){.tv_sec = 15});
sys/rpc/rpcsec_tls/rpctls_impl.c:125:	clnt_control(cl, CLSET_WAITCHAN, __DECONST(char *, group));
sys/rpc/clnt_vc.c:114: * Default options are set, which the user can change using clnt_control()'s.
sys/rpc/clnt_dg.c:161: * Default options are set, which the user can change using clnt_control().
sys/rpc/clnt_dg.c:228:	/* Other values can also be set through clnt_control() */
sys/rpc/clnt_dg.c:260:	 * to do a close on it, else the user may use clnt_control
sys/kgssapi/gss_impl.c:73:	clnt_control(cl, CLSET_RETRIES, &(int){30});
sys/kgssapi/gss_impl.c:74:	clnt_control(cl, CLSET_TIMEOUT, &(struct timeval){.tv_sec = 300});
sys/kgssapi/gss_impl.c:79:	clnt_control(cl, CLSET_WAITCHAN, "gssd");
usr.sbin/yppush/yppush_main.c:340:	if (clnt_control(clnt, CLSET_TIMEOUT, (char *)&timeout) == FALSE)
usr.sbin/spray/spray.c:133:	clnt_control(cl, CLSET_TIMEOUT, &NO_DEFAULT);
usr.sbin/ypserv/yp_server.c:296:	if (clnt_control(clnt, CLSET_TIMEOUT, &timeout) == FALSE)
usr.sbin/ypbind/yp_ping.c:262:	clnt_control(clnt, CLSET_TIMEOUT, (char *)&tv);
usr.sbin/ypbind/yp_ping.c:264:	clnt_control(clnt, CLSET_ASYNC, (char *)&async);
usr.sbin/ypbind/yp_ping.c:270:			clnt_control(clnt, CLSET_XID, (char *)&reqs[i]->xid);
usr.sbin/ypbind/yp_ping.c:273:			clnt_control(clnt, CLSET_SVC_ADDR, &addr);
usr.sbin/ypbind/yp_ping.c:282:	clnt_control(clnt, CLGET_XID, (char *)&xid_lookup);
lib/libc/rpc/clnt_generic.c:253: * change using the rpc equivalent of _ioctl()'s : clnt_control()
lib/libc/rpc/clnt_generic.c:319: * change using the rpc equivalent of _ioctl()'s : clnt_control().
lib/libc/rpc/clnt_vc.c:106:	bool_t          ct_waitset;	/* wait set by clnt_control? */
lib/libc/rpc/clnt_vc.c:183: * Default options are set, which the user can change using clnt_control()'s.
lib/libc/rpc/key_call.c:345:		clnt_control(kcp->client, CLSET_VERS, (void *)&vers);
lib/libc/rpc/key_call.c:403:	(void) clnt_control(kcp->client, CLSET_RETRY_TIMEOUT,
```

### Round 3: ❌ INVALID

**🎯 Crux:** clnt_dg_control is an internal API used by trusted kernel components; its parameters are not reachable by an untrusted remote or local attacker.

I analyzed the three reported vulnerabilities. 

1. **CLSET_SVC_ADDR & CLGET_SVC_ADDR**: Both bugs exist in `clnt_dg_control`. `CLSET_SVC_ADDR` performs a `memcpy` into `cu->cu_raddr` (a `sockaddr_storage`) using `addr->sa_len` without validation, and `CLGET_SVC_ADDR` copies from it into a caller-provided buffer without knowing the buffer size. However, `clnt_dg_control` is an internal management function. The `info` parameter is provided by the caller of the RPC client handle. In the provided kernel context (`clnt_dg.c`), these handles are used by other kernel components (e.g., NFS, RPCBind). There is no evidence that `clnt_control` is exposed to untrusted user-space input via a syscall or ioctl. Therefore, these are not reachable by an external attacker.

2. **Predictable XID**: While the XID is generated using a sequential atomic counter, this is a known property of many RPC implementations. For a remote attacker to inject a forged reply, they must not only predict the XID but also pass `AUTH_VALIDATE`. If the client is using a secure authentication flavor (like RPCSEC_GSS), predicting the XID is insufficient. Even with `AUTH_NULL`, the impact is limited to spoofing responses to pending requests. In a kernel-to-server context, this is a protocol weakness but not a direct memory corruption or privilege escalation vulnerability in this specific code.

Since the critical memory corruption bugs are not reachable by an attacker, and the XID issue is a protocol-level weakness requiring specific authentication contexts, the findings are invalid as security vulnerabilities in this code.

CRUX: clnt_dg_control is an internal API used by trusted kernel components; its parameters are not reachable by an untrusted remote or local attacker.
GREP: clnt_control

🔎 **Grep results:**

GREP `clnt_control`:
```
sys/rpc/clnt.h:273:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
include/rpc/clnt.h:200:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
crypto/krb5/src/include/gssrpc/clnt.h:201:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
usr.sbin/yppush/yppush_main.c:340:	if (clnt_control(clnt, CLSET_TIMEOUT, (char *)&timeout) == FALSE)
usr.sbin/spray/spray.c:133:	clnt_control(cl, CLSET_TIMEOUT, &NO_DEFAULT);
usr.sbin/ypserv/yp_server.c:296:	if (clnt_control(clnt, CLSET_TIMEOUT, &timeout) == FALSE)
usr.sbin/ypbind/yp_ping.c:262:	clnt_control(clnt, CLSET_TIMEOUT, (char *)&tv);
usr.sbin/ypbind/yp_ping.c:264:	clnt_control(clnt, CLSET_ASYNC, (char *)&async);
usr.sbin/ypbind/yp_ping.c:270:			clnt_control(clnt, CLSET_XID, (char *)&reqs[i]->xid);
usr.sbin/ypbind/yp_ping.c:273:			clnt_control(clnt, CLSET_SVC_ADDR, &addr);
usr.sbin/ypbind/yp_ping.c:282:	clnt_control(clnt, CLGET_XID, (char *)&xid_lookup);
usr.sbin/rpc.lockd/test.c:7:/* Default timeout can be changed using clnt_control() */
usr.sbin/rpc.lockd/test.c:313:	clnt_control(cli, CLGET_TIMEOUT, &tim);
usr.sbin/rpc.lockd/test.c:317:	clnt_control(cli, CLSET_TIMEOUT, &tim);
usr.sbin/rpc.lockd/test.c:318:	clnt_control(cli, CLGET_TIMEOUT, &tim);
usr.sbin/rpc.lockd/lock_proc.c:276:	clnt_control(client, CLGET_FD, &clnt_fd);
usr.sbin/rpc.lockd/lock_proc.c:313:	clnt_control(client, CLSET_TIMEOUT, (char *)&retry_time);
usr.sbin/rpc.statd/test.c:7:/* Default timeout can be changed using clnt_control() */
sys/rpc/clnt_bck.c:108: * Default options are set, which the user can change using clnt_control()'s.
sys/rpc/clnt_vc.c:114: * Default options are set, which the user can change using clnt_control()'s.
sys/rpc/rpcb_clnt.c:69:	clnt_control(rpcb_clnt, CLSET_RETRIES, &(int){6});
sys/rpc/rpcb_clnt.c:70:	clnt_control(rpcb_clnt, CLSET_WAITCHAN, "rpcb");
sys/rpc/clnt_dg.c:161: * Default options are set, which the user can change using clnt_control().
sys/rpc/clnt_dg.c:228:	/* Other values can also be set through clnt_control() */
sys/rpc/clnt_dg.c:260:	 * to do a close on it, else the user may use clnt_control
sys/rpc/rpcsec_tls/rpctls_impl.c:123:	clnt_control(cl, CLSET_RETRIES, &(int){1});
sys/rpc/rpcsec_tls/rpctls_impl.c:124:	clnt_control(cl, CLSET_TIMEOUT, &(struct timeval){.tv_sec = 15});
sys/rpc/rpcsec_tls/rpctls_impl.c:125:	clnt_control(cl, CLSET_WAITCHAN, __DECONST(char *, group));
sys/kgssapi/gss_impl.c:73:	clnt_control(cl, CLSET_RETRIES, &(int){30});
sys/kgssapi/gss_impl.c:74:	clnt_control(cl, CLSET_TIMEOUT, &(struct timeval){.tv_sec = 300});
```

### Round 4: ❌ INVALID

[ARBITER] The memory overflows occur in `clnt_dg_control`, which is an internal function used to configure an RPC client handle. The `info` parameter is provided by the caller of the RPC library. In the provided kernel implementation, this is used by trusted kernel components or internally by the RPC client. There is no evidence that an untrusted remote or local user can control the `info` pointer or the `sa_len` field via a system call or network packet to trigger the overflow. The predictable XID is a known characteristic of some RPC implementations but does not constitute a critical vulnerability in this context without a demonstrated attack vector.

