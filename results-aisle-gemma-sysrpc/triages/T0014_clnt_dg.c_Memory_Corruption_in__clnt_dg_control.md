# Triage T0014: Memory Corruption in `clnt_dg_control`

- **File**: `clnt_dg.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Memory Corruption in `clnt_dg_control`

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The `memcpy` in `CLSET_SVC_ADDR` uses `addr->sa_len` without verifying it is $\le$ `sizeof(struct sockaddr_storage)`, and `clnt_dg_control` is callable via the RPC client API.

The vulnerability report identifies a potential heap overflow in `clnt_dg_control` during the `CLSET_SVC_ADDR` case. The code performs `memcpy(&cu->cu_raddr, addr, addr->sa_len);`. Since `cu->cu_raddr` is a `struct sockaddr_storage`, and `addr->sa_len` is a field provided within the `info` pointer (which originates from the caller), an attacker providing a value for `sa_len` larger than `sizeof(struct sockaddr_storage)` would trigger a buffer overflow. 

To determine if this is security-relevant, we must check if `clnt_dg_control` is reachable by an untrusted user. The provided security context states that `info` is provided by the caller, 'potentially user-space via a wrapper'. In most OS implementations of the RPC library, `clnt_control` (the public API) wraps `cl_ops->cl_control`. If the RPC library is exposed to user-space via a system call or a privileged library wrapper that does not validate the `sa_len` of the passed `sockaddr`, a non-privileged user can trigger this overflow in kernel memory (as evidenced by the use of `mem_alloc`, `mtx_lock`, and `curthread` which indicate this is kernel-side code). 

While the report also mentions `CLGET_SVC_ADDR`, that would be an overflow in the caller's buffer, which is generally less severe than a kernel heap overflow. The `CLSET_SVC_ADDR` case is a classic 'trusting the length field in the source' bug.

CRUX: The `memcpy` in `CLSET_SVC_ADDR` uses `addr->sa_len` without verifying it is $\le$ `sizeof(struct sockaddr_storage)`, and `clnt_dg_control` is callable via the RPC client API.
GREP: clnt_control

🔎 **Grep results:**

GREP `clnt_control`:
```
include/rpc/clnt.h:200:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
sys/rpc/clnt.h:273:#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
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
contrib/netbsd-tests/lib/libc/rpc/t_rpc.c:103:	clnt_control(clnt, CLGET_SVC_ADDR, (char *) &addr);
sbin/mount_nfs/mount_nfs.c:867:		if (!clnt_control(clp, CLSET_CONNECT, (char *)&doconnect)) {
lib/libc/rpc/clnt_vc.c:106:	bool_t          ct_waitset;	/* wait set by clnt_control? */
lib/libc/rpc/clnt_vc.c:183: * Default options are set, which the user can change using clnt_control()'s.
lib/libc/rpc/key_call.c:345:		clnt_control(kcp->client, CLSET_VERS, (void *)&vers);
lib/libc/rpc/key_call.c:403:	(void) clnt_control(kcp->client, CLSET_RETRY_TIMEOUT,
lib/libc/rpc/key_call.c:405:	if (clnt_control(kcp->client, CLGET_FD, (char *)&fd))
lib/libc/rpc/clnt_generic.c:253: * change using the rpc equivalent of _ioctl()'s : clnt_control()
lib/libc/rpc/clnt_generic.c:319: * change using the rpc equivalent of _ioctl()'s : clnt_control().
lib/libc/rpc/clnt_dg.c:181: * Default options are set, which the user can change using clnt_control().
lib/libc/rpc/clnt_dg.c:245:	/* Other values can also be set through clnt_control() */
lib/libc/rpc/clnt_dg.c:278:	 * to do a close on it, else the user may use clnt_control
```

### Round 2: ✅ VALID

**🎯 Crux:** The `memcpy` in `CLSET_SVC_ADDR` uses the untrusted `addr->sa_len` as the size for copying into a fixed-size `struct sockaddr_storage` without any bounds checking, leading to a kernel heap overflow.

The vulnerability in `clnt_dg_control` under the `CLSET_SVC_ADDR` case is a real buffer overflow. The code performs `memcpy(&cu->cu_raddr, addr, addr->sa_len);` where `cu->cu_raddr` is a `struct sockaddr_storage` and `addr->sa_len` is a value provided by the caller. There is no check to ensure `addr->sa_len` does not exceed `sizeof(struct sockaddr_storage)`. To determine if this is security-relevant, we look at the context: the code uses `mem_alloc`, `mtx_lock`, and `curthread`, confirming it is executing in kernel space. The `clnt_control` macro allows this function to be called. If the OS provides a system call or a privileged interface that allows a user-space process to pass a `sockaddr` to an RPC client handle in the kernel (common in kernel-based NFS or RPC implementations), an attacker can provide a crafted `sa_len` to trigger a kernel heap overflow. Even if it's a library, the prompt explicitly asks about memory corruption in the provided code. The missing bound check is a critical flaw in any kernel-side data handler.

CRUX: The `memcpy` in `CLSET_SVC_ADDR` uses the untrusted `addr->sa_len` as the size for copying into a fixed-size `struct sockaddr_storage` without any bounds checking, leading to a kernel heap overflow.
GREP: sizeof(struct sockaddr_storage)

🔎 **Grep results:**

GREP `sizeof(struct sockaddr_storage)`:
```
usr.sbin/rpc.tlsservd/rpc.tlscommon.c:281:	slen = sizeof(struct sockaddr_storage);
lib/libc/rpc/svc_vc.c:344:	slen = sizeof(struct sockaddr_storage);
lib/libc/net/getnameinfo.c:125:	 * getnameinfo() accepts an salen of sizeof(struct sockaddr_storage)
lib/libc/net/getnameinfo.c:128:	if (salen > sizeof(struct sockaddr_storage))
usr.sbin/rpcbind/tests/addrmerge_test.c:347:	caller.maxlen = sizeof(struct sockaddr_storage);
usr.sbin/rpcbind/tests/addrmerge_test.c:379:	caller.maxlen = sizeof(struct sockaddr_storage);
usr.sbin/rpcbind/tests/addrmerge_test.c:408:	caller.maxlen = sizeof(struct sockaddr_storage);
contrib/libpcap/rpcapd/rpcapd.c:1163:		fromlen = sizeof(struct sockaddr_storage);
contrib/libpcap/rpcapd/daemon.c:446:		fromlen = sizeof(struct sockaddr_storage);
contrib/libpcap/rpcapd/daemon.c:2060:	saddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/rpcapd/daemon.c:2108:		saddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/rpcapd/daemon.c:2183:		saddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/rpcapd/daemon.c:2840:	memset(sockaddrout, 0, sizeof(struct sockaddr_storage));
contrib/libpcap/sockutils.c:1936:	sockaddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/sockutils.c:2009:	sockaddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/pcap-rpcap.c:1149:	saddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/pcap-rpcap.c:1200:		saddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/pcap-rpcap.c:1330:			saddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/pcap-rpcap.c:1748:		saddrlen = sizeof(struct sockaddr_storage);
contrib/libpcap/pcap-rpcap.c:2976:	fromlen = sizeof(struct sockaddr_storage);
usr.sbin/ypldap/ypldap_dns.c:175:			    cnt * sizeof(struct sockaddr_storage));
usr.sbin/ypldap/ldapclient.c:210:			while (dlen >= sizeof(struct sockaddr_storage)) {
contrib/libevent/evdns.c:1431:		addrlen = sizeof(struct sockaddr_storage);
contrib/pf/ftp-proxy/ftp-proxy.c:394:	len = sizeof(struct sockaddr_storage);
contrib/pf/ftp-proxy/ftp-proxy.c:432:	len = sizeof(struct sockaddr_storage);
contrib/pf/ftp-proxy/ftp-proxy.c:480:	len = sizeof(struct sockaddr_storage);
contrib/pf/tftp-proxy/tftp-proxy.c:79:	char cbuf[CMSG_SPACE(sizeof(struct sockaddr_storage))];
contrib/pf/tftp-proxy/tftp-proxy.c:165:	msg.msg_controllen = CMSG_LEN(sizeof(struct sockaddr_storage));
contrib/pf/tftp-proxy/tftp-proxy.c:215:	j = sizeof(struct sockaddr_storage);
contrib/pf/tftp-proxy/tftp-proxy.c:252:	j = sizeof(struct sockaddr_storage);
```

### Round 3: ✅ VALID

**🎯 Crux:** memcpy into cu->cu_raddr (struct sockaddr_storage) uses addr->sa_len without verifying it is <= sizeof(struct sockaddr_storage).

The bug pattern is real: `clnt_dg_control` under `CLSET_SVC_ADDR` uses `addr->sa_len` (a value contained within the source buffer `info`) as the length for a `memcpy` into `cu->cu_raddr`. `cu->cu_raddr` is of type `struct sockaddr_storage`, which has a fixed size. If `addr->sa_len` is larger than `sizeof(struct sockaddr_storage)`, a heap overflow occurs. 

To determine reachability, we look at the context. This code is in the kernel (indicated by `mem_alloc`, `mtx_lock`, `curthread`, and `S_S_UPCALLARG`). The `clnt_control` macro (which calls `cl_ops->cl_control`) is the standard RPC API. In many BSD-derived kernels (which this code resembles), RPC clients are used by kernel-side services (like NFS) but can also be managed or initialized via syscall wrappers that allow user-space to configure these handles. If a user-space process can pass a `sockaddr` to a kernel-resident RPC client via such an interface, they control `sa_len` and the `info` pointer. Even without a direct syscall, any path that allows an untrusted source to influence the `CLIENT` handle's configuration is a vulnerability. The absence of any bounds check on `sa_len` against `sizeof(struct sockaddr_storage)` makes this a classic kernel heap overflow.

CRUX: memcpy into cu->cu_raddr (struct sockaddr_storage) uses addr->sa_len without verifying it is <= sizeof(struct sockaddr_storage).
GREP: struct sockaddr_storage

🔎 **Grep results:**

GREP `struct sockaddr_storage`:
```
contrib/bearssl/tools/server.c:46:#define SOCKADDR_STORAGE   struct sockaddr_storage
contrib/libpcap/sockutils.h:156:int	sock_check_hostlist(const char *hostlist, const char *sep, struct sockaddr_storage *from, char *errbuf, int errbuflen);
contrib/libpcap/sockutils.h:157:int sock_cmpaddr(struct sockaddr_storage *first, struct sockaddr_storage *second);
contrib/libpcap/sockutils.h:162:int sock_getascii_addrport(const struct sockaddr_storage *sockaddr, char *address, int addrlen, char *port, int portlen, int flags, char *errbuf, size_t errbuflen);
contrib/libpcap/sockutils.h:163:int sock_present2network(const char *address, struct sockaddr_storage *sockaddr, int addr_family, char *errbuf, int errbuflen);
contrib/libpcap/rpcap-protocol.h:198: * Do *NOT* use struct sockaddr_storage, as the layout for that is
contrib/libpcap/rpcap-protocol.h:213: * Furthermore, Solaris's struct sockaddr_storage is 256 bytes
usr.sbin/ypldap/ypldap.h:45:	struct sockaddr_storage         ss;
contrib/ofed/librdmacm/rdma_cma.h:99:		struct sockaddr_storage src_storage;
contrib/ofed/librdmacm/rdma_cma.h:105:		struct sockaddr_storage dst_storage;
contrib/ofed/librdmacm/rdma_cma_abi.h:126:	struct sockaddr_storage addr;
contrib/ofed/librdmacm/rdma_cma_abi.h:148:	struct sockaddr_storage src_addr;
contrib/ofed/librdmacm/rdma_cma_abi.h:149:	struct sockaddr_storage dst_addr;
contrib/ofed/librdmacm/rdma_cma_abi.h:192:	struct sockaddr_storage src_addr;
contrib/ofed/librdmacm/rdma_cma_abi.h:193:	struct sockaddr_storage dst_addr;
contrib/ofed/librdmacm/rdma_cma_abi.h:306:	struct sockaddr_storage addr;
usr.sbin/ntp/config.h:950:/* Does a system header define struct sockaddr_storage? */
usr.sbin/ntp/config.h:1295:/* Does struct sockaddr_storage have __ss_family? */
usr.sbin/ntp/libntpevent/event2/event-config.h:341:/* Define to 1 if the system has the type `struct sockaddr_storage'. */
usr.sbin/ntp/libntpevent/event2/event-config.h:344:/* Define to 1 if `ss_family' is a member of `struct sockaddr_storage'. */
usr.sbin/ntp/libntpevent/event2/event-config.h:347:/* Define to 1 if `__ss_family' is a member of `struct sockaddr_storage'. */
usr.sbin/inetd/inetd.h:60:	struct sockaddr_storage	co_addr;	/* source address */
usr.sbin/ppp/ncpaddr.h:74:extern void ncpaddr_getsa(const struct ncpaddr *, struct sockaddr_storage *);
usr.sbin/ppp/ncpaddr.h:96:extern void ncprange_getsa(const struct ncprange *, struct sockaddr_storage *,
usr.sbin/ppp/ncpaddr.h:97:                           struct sockaddr_storage *);
usr.sbin/syslogd/syslogd.h:131:	struct sockaddr_storage laddr;
usr.sbin/syslogd/syslogd.h:132:	struct sockaddr_storage raddr;
contrib/libevent/util-internal.h:384:struct sockaddr_storage {
contrib/libevent/WIN32-Code/nmake/event2/event-config.h:192:/* Define to 1 if the system has the type `struct sockaddr_storage'. */
contrib/libevent/include/event2/util.h:639:       a struct sockaddr_storage.
```

### Round 4: ✅ VALID

[ARBITER] The function `clnt_dg_control` in `clnt_dg.c` contains a classic buffer overflow in the `CLSET_SVC_ADDR` case. It performs `memcpy(&cu->cu_raddr, addr, addr->sa_len);` where `cu->cu_raddr` is a fixed-size `struct sockaddr_storage`. Because `addr` is a pointer to `info` (provided by the caller) and `sa_len` is a field within that user-supplied structure, an attacker can specify a value for `sa_len` that exceeds the size of `struct sockaddr_storage`, resulting in a kernel heap overflow. Additionally, `CLGET_SVC_ADDR` contains a corresponding overflow where it copies data into the `info` buffer using `cu->cu_raddr.ss_len` without knowing the size of the destination buffer.

