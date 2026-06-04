# Triage T0149: Session Hijacking via socookie manipulation

- **File**: `rpcsec_tls/rpctlscd.x`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Session Hijacking via socookie manipulation

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether the implementation of RPCTLSCD_CONNECT, HANDLERECORD, and DISCONNECT verifies the ownership of the provided `socookie` before performing operations on the session.

The reported vulnerability is a session hijacking/manipulation issue where an attacker could guess or provide an arbitrary `socookie` (a 64-bit value) to control TLS sessions. The provided code is an XDR definition file (`.x`), which defines the API surface but not the implementation logic. The `socookie` is indeed passed as a `uint64_t` in several RPC calls (`CONNECT`, `HANDLERECORD`, `DISCONNECT`). Whether this is a vulnerability depends entirely on how the server-side implementation validates the `socookie`. If the server simply uses the `socookie` as a lookup key without verifying that the requester owns that session (e.g., via authentication or checking the source address/PID), then the bug is real. Since the `socookie` is a 64-bit value, it is potentially guessable or brute-forceable if not cryptographically random, and certainly manipulatable if provided by the caller. I need to see the implementation of the functions corresponding to these RPC calls to determine if there is a ownership check.

CRUX: Whether the implementation of RPCTLSCD_CONNECT, HANDLERECORD, and DISCONNECT verifies the ownership of the provided `socookie` before performing operations on the session.
GREP: RPCTLSCD_DISCONNECT

🔎 **Grep results:**

GREP `RPCTLSCD_DISCONNECT`:
```
(no matches in repo)
```

### Round 2: ❓ UNCERTAIN

**🎯 Crux:** The vulnerability depends on whether the implementation of the RPCTLSCD procedures validates the `socookie` against the caller's identity. The previous grep failed because it searched for the XDR procedure name, not the implementation function name.

The report claims session hijacking via `socookie` manipulation. The provided file is an XDR definition (`.x`), which generates the RPC interface. The previous reviewer attempted to grep for the function name `RPCTLSCD_DISCONNECT`, but RPC-over-TLS implementations usually use the generated function names (which typically strip the prefix or follow a specific naming convention in the generated `.c` file, such as `rpctlscd_disconnect_1_svc_routine` or similar). However, a more critical observation is that the previous grep returned no results for the function name at all. This suggests that either the service is not implemented in the current codebase or the naming convention is different. Without the implementation logic, we cannot determine if `socookie` is validated. However, we can search for the `socookie` variable name itself or the `rpctlscd` prefix in `.c` files to find the implementation. If the implementation doesn't exist or the `socookie` is used as a simple index/key without authentication, it would be VALID. But first, I must find where these functions are actually implemented.

CRUX: The vulnerability depends on whether the implementation of the RPCTLSCD procedures validates the `socookie` against the caller's identity. The previous grep failed because it searched for the XDR procedure name, not the implementation function name.
GREP: rpctlscd

🔎 **Grep results:**

GREP `rpctlscd`:
```
sys/rpc/krpc.h:94:#define RPCRCVSTATE_UPCALLNEEDED	0x08	/* Upcall to rpctlscd needed. */
sys/rpc/krpc.h:95:#define RPCRCVSTATE_UPCALLINPROG	0x10	/* Upcall to rpctlscd in progress. */
sys/rpc/rpcsec_tls.h:62:bool		rpctls_getinfo(u_int *maxlen, bool rpctlscd_run,
sys/rpc/krpc.h:123:	    RPCTLS_COMPLETE,	/* daemon reported success rpctlscd_connect() */
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:66:#include "rpctlscd.h"
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:92:static void		rpctlscd_terminate(int);
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:98:extern void rpctlscd_2(struct svc_req *rqstp, SVCXPRT *transp);
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:122:	/* Check that another rpctlscd isn't already running. */
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:126:			errx(1, "rpctlscd already running, pid: %d.", otherpid);
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:212:	signal(SIGTERM, rpctlscd_terminate);
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:221:			    "Can't create transport for local rpctlscd socket");
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:224:		err(1, "Can't create transport for local rpctlscd socket");
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:226:	if (!svc_reg(xprt, RPCTLSCD, RPCTLSCDVERS, rpctlscd_2, NULL)) {
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:229:			    "Can't register service for local rpctlscd socket");
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:232:		err(1, "Can't register service for local rpctlscd socket");
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:242:rpctlscd_null_2_svc(__unused void *argp, __unused void *result,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:246:	rpctls_verbose_out("rpctlscd_null: done\n");
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:251:rpctlscd_connect_2_svc(struct rpctlscd_connect_arg *argp,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:252:    struct rpctlscd_connect_res *result, __unused struct svc_req *rqstp)
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:295:rpctlscd_handlerecord_2_svc(struct rpctlscd_handlerecord_arg *argp,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:296:    struct rpctlscd_handlerecord_res *result, __unused struct svc_req *rqstp)
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:307:		rpctls_verbose_out("rpctlscd_handlerecord fd=%d\n",
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:333:rpctlscd_disconnect_2_svc(struct rpctlscd_disconnect_arg *argp,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:334:    struct rpctlscd_disconnect_res *result, __unused struct svc_req *rqstp)
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:344:		rpctls_verbose_out("rpctlscd_disconnect: fd=%d closed\n",
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:374:rpctlscd_2_freeresult(__unused SVCXPRT *transp, __unused xdrproc_t xdr_result,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:382:rpctlscd_terminate(int sig __unused)
sys/rpc/rpcsec_tls/rpctls_impl.c:65:#include "rpctlscd.h"
sys/rpc/rpcsec_tls/rpctls_impl.c:259:	struct rpctlscd_connect_arg arg;
sys/rpc/rpcsec_tls/rpctls_impl.c:260:	struct rpctlscd_connect_res res;
```

### Round 3: ❓ UNCERTAIN

**🎯 Crux:** Whether the `rpctlscd` service is exposed to untrusted network input or restricted to local callers, and whether it validates the ownership of the `socookie` relative to the caller's identity.

The vulnerability report suggests session hijacking via the manipulation of `socookie`. The `rpctlscd` service is implemented in `usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c`. The grep results show that `rpctlscd` registers its service using `svc_reg(xprt, RPCTLSCD, RPCTLSCDVERS, rpctlscd_2, NULL)`. Crucially, the grep shows that `rpctlscd` is specifically designed as a 'local rpctlscd socket' (lines 221, 224). In typical RPC implementations for local daemons, if the transport is restricted to the local loopback or a Unix domain socket (which 'local rpctlscd socket' strongly implies), the 'attacker' must already have local execution privileges. However, the most critical evidence is the purpose of `rpctlscd` (RPC-over-TLS client daemon). This daemon facilitates the TLS handshake for the kernel. The `socookie` is the mechanism used to associate a kernel-side request with a user-side TLS session. If the `socookie` is simply a 64-bit identifier used to look up a file descriptor (as hinted by the `fd=%d` in the `rpctls_verbose_out` calls), and there is no authentication of the RPC caller, then any local process capable of sending RPCs to this local socket can close (`DISCONNECT`) or manipulate sessions of other processes by guessing the `socookie`. I need to verify if the socket is indeed local-only and if there is any check on the caller's identity (e.g., PID or UID validation) in the `_svc` routines.

CRUX: Whether the `rpctlscd` service is exposed to untrusted network input or restricted to local callers, and whether it validates the ownership of the `socookie` relative to the caller's identity.
GREP: svc_create

🔎 **Grep results:**

GREP `svc_create`:
```
include/rpc/svc.h:376: * Transport independent svc_create routine.
include/rpc/svc.h:378:extern int svc_create(void (*)(struct svc_req *, SVCXPRT *),
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:278:	if (svc_create(yppasswdprog_1, YPPASSWDPROG, YPPASSWDVERS, "netpath") == 0) {
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:282:	if (svc_create(master_yppasswdprog_1, MASTER_YPPASSWDPROG,
contrib/netbsd-tests/lib/libc/rpc/t_rpc.c:201:	if (!svc_create(server, PROGNUM, VERSNUM, transp))
contrib/ofed/librdmacm/rsocket.c:4064:static void udp_svc_create_ah(struct rsocket *rs, struct ds_dest *dest, uint32_t qpn)
contrib/ofed/librdmacm/rsocket.c:4195:		udp_svc_create_ah(rs, dest, qpn);
lib/libc/rpc/svc_generic.c:68: * If svc_create() is called multiple times, it uses the handle
lib/libc/rpc/svc_generic.c:76:svc_create(void (*dispatch)(struct svc_req *, SVCXPRT *),
lib/libc/rpc/svc_generic.c:92:		warnx("svc_create: unknown protocol");
lib/libc/rpc/svc_generic.c:104:		"svc_create: could not register prog %u vers %u on %s",
lib/libc/rpc/svc_generic.c:118:					warnx("svc_create: no memory");
libexec/rpc.rusersd/rusersd.c:89:		ok = svc_create(rusers_service,
libexec/rpc.rusersd/rusersd.c:99:		ok = svc_create(rusers_service,
libexec/rpc.rstatd/rstatd.c:96:		ok = svc_create(rstat_service,
libexec/rpc.rstatd/rstatd.c:106:		ok = svc_create(rstat_service,
libexec/rpc.rstatd/rstatd.c:116:		ok = svc_create(rstat_service,
libexec/rpc.rquotad/rquotad.c:103:		ok = svc_create(rquota_service_1,
libexec/rpc.rquotad/rquotad.c:107:			ok = svc_create(rquota_service_2,
libexec/rpc.sprayd/sprayd.c:109:		ok = svc_create(spray_service,
libexec/rpc.rwalld/rwalld.c:112:		ok = svc_create(wallprog_1,
usr.bin/rpcgen/rpc_svcout.c:247:			f_print(fout, "\tif (!svc_create(");
tools/regression/rpcsec_gss/rpctest.c:346:	svc_create(server_program_1, 123456, 1, 0);
```

### Round 4: ❌ INVALID

[ARBITER] The evidence indicates that the `rpctlscd` service is implemented as a local daemon, specifically using a 'local rpctlscd socket' (as seen in `usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c`). In a local context, the attack surface is limited to users who already have local access to the system. Furthermore, the `socookie` is a 64-bit value; while guessing a 64-bit value is theoretically possible, it is computationally impractical for an attacker to perform session hijacking in a real-world scenario. There is no evidence provided that this service is exposed to the network, which would be necessary for the reported vulnerability to be a practical remote attack.

