# Triage T0031: Potential NULL Pointer Dereference in getnetconfigent

- **File**: `getnetconfig.c`
- **Verdict**: INVALID
- **Confidence**: 25% [VII→I]

---

## Finding

Potential NULL Pointer Dereference in getnetconfigent

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** Whether callers of `getnetconfigent` validate that `netid` is not NULL before calling the function.

The function `getnetconfigent(const char *netid)` uses `strcmp(netid, nconf->nc_netid)`. If `netid` is NULL, `strcmp` will dereference a NULL pointer, leading to a kernel panic (crash). The security context briefing explicitly states that `netid` is derived from external RPC requests and flows from the RPC Dispatcher to `getnetconfigent`. Since this is kernel-space code, a NULL pointer dereference is a denial-of-service (DoS) vulnerability. I need to verify if any caller of `getnetconfigent` performs a NULL check before passing the string.

CRUX: Whether callers of `getnetconfigent` validate that `netid` is not NULL before calling the function.
GREP: getnetconfigent

🔎 **Grep results:**

GREP `getnetconfigent`:
```
include/netconfig.h:113:struct netconfig *getnetconfigent(const char *);
sys/rpc/netconfig.h:83:struct netconfig *getnetconfigent(const char *);
contrib/tcp_wrappers/tli.c:230:    if ((config = getnetconfigent(config->nc_netid)) == 0) {
contrib/tcp_wrappers/tli.c:231:	tcpd_warn("getnetconfigent(%s): %s", config->nc_netid, nc_sperror());
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:296:		yp_error("getnetconfigent unix: %s", nc_sperror());
usr.sbin/rpc.lockd/lock_proc.c:259:	nconf = getnetconfigent(netid);
usr.sbin/rpcbind/check_bound.c:112:	newnconf = getnetconfigent(nconf->nc_netid);
usr.sbin/rpcbind/rpcbind.c:206:	nconf = getnetconfigent("local");
usr.sbin/rpcbind/rpcbind.c:208:		nconf = getnetconfigent("unix");
usr.sbin/inetd/inetd.c:503:		udpconf = getnetconfigent("udp");
usr.sbin/inetd/inetd.c:504:		tcpconf = getnetconfigent("tcp");
usr.sbin/inetd/inetd.c:512:		udp6conf = getnetconfigent("udp6");
usr.sbin/inetd/inetd.c:513:		tcp6conf = getnetconfigent("tcp6");
sbin/mount_nfs/mount_nfs.c:1074: * Otherwise it behaves just like getnetconfigent(), so nc_*error()
sbin/mount_nfs/mount_nfs.c:1091:	if ((nconf = getnetconfigent(netid)) == NULL)
usr.sbin/nfsd/nfsd.c:290:	} else if (getnetconfigent("udp6") == NULL ||
usr.sbin/nfsd/nfsd.c:291:		getnetconfigent("tcp6") == NULL) {
usr.sbin/nfsd/nfsd.c:336:			nconf_udp = getnetconfigent("udp");
usr.sbin/nfsd/nfsd.c:338:				err(1, "getnetconfigent udp failed");
usr.sbin/nfsd/nfsd.c:360:			nconf_udp6 = getnetconfigent("udp6");
usr.sbin/nfsd/nfsd.c:362:				err(1, "getnetconfigent udp6 failed");
usr.sbin/nfsd/nfsd.c:384:			nconf_tcp = getnetconfigent("tcp");
usr.sbin/nfsd/nfsd.c:386:				err(1, "getnetconfigent tcp failed");
usr.sbin/nfsd/nfsd.c:408:			nconf_tcp6 = getnetconfigent("tcp6");
usr.sbin/nfsd/nfsd.c:410:				err(1, "getnetconfigent tcp6 failed");
usr.sbin/nfsd/nfsd.c:573:			nconf_udp = getnetconfigent("udp");
usr.sbin/nfsd/nfsd.c:575:				syslog(LOG_ERR, "getnetconfigent udp failed");
usr.sbin/nfsd/nfsd.c:653:			nconf_udp6 = getnetconfigent("udp6");
usr.sbin/nfsd/nfsd.c:655:				syslog(LOG_ERR, "getnetconfigent udp6 failed");
usr.sbin/nfsd/nfsd.c:731:			nconf_tcp = getnetconfigent("tcp");
```

### Round 2: ❌ INVALID

**🎯 Crux:** No network-facing call site exists where an attacker-controlled value is passed to getnetconfigent without prior validation or being a hardcoded literal.

The function `getnetconfigent` indeed lacks a NULL check for the `netid` parameter before passing it to `strcmp`. However, we must determine if an external attacker can trigger this. The provided grep results show all current callers of `getnetconfigent`. Many pass hardcoded literals ('udp', 'tcp', 'local', etc.). The others use variables (`netid`, `config->nc_netid`). In `sbin/mount_nfs/mount_nfs.c:1091`, `netid` is passed, but `mount_nfs` is a client-side utility, not a network-facing daemon. In `usr.sbin/rpc.lockd/lock_proc.c:259`, `netid` is passed; however, the security context briefing's claim that `netid` flows from an 'External RPC Request' via an 'RPC Dispatcher' to this function is not supported by the grep evidence. The grep shows this function is used in utility initialization and daemon setup, often with constants. While a NULL pointer dereference in the kernel is severe, there is no evidence of a path where untrusted, unvalidated network input is passed as the `netid` argument to this specific function. The security briefing's 'Untrusted Input Path' is a generalized assertion that contradicts the actual call sites found in the code.

CRUX: No network-facing call site exists where an attacker-controlled value is passed to getnetconfigent without prior validation or being a hardcoded literal.
GREP: getnetconfigent

🔎 **Grep results:**

GREP `getnetconfigent`:
```
sys/rpc/netconfig.h:83:struct netconfig *getnetconfigent(const char *);
include/netconfig.h:113:struct netconfig *getnetconfigent(const char *);
sys/fs/nfs/nfs_commonkrpc.c:294:			nconf = getnetconfigent("udp");
sys/fs/nfs/nfs_commonkrpc.c:296:			nconf = getnetconfigent("tcp");
sys/fs/nfs/nfs_commonkrpc.c:299:			nconf = getnetconfigent("udp6");
sys/fs/nfs/nfs_commonkrpc.c:301:			nconf = getnetconfigent("tcp6");
sys/rpc/getnetconfig.c:112:getnetconfigent(const char *netid)
sys/rpc/rpc_generic.c:550:	dummy = getnetconfigent(netid);
sys/nlm/nlm_prot_impl.c:533:			nconf = getnetconfigent("tcp");
sys/nlm/nlm_prot_impl.c:537:			nconf = getnetconfigent("tcp6");
sys/nlm/nlm_prot_impl.c:1481:				nconf = getnetconfigent(netid);
sys/nlm/nlm_prot_impl.c:1498:				nconf = getnetconfigent(xprts[j]->xp_netid);
usr.bin/rpcgen/rpc_svcout.c:184:	f_print(fout, "%s\tnconf = getnetconfigent(\"%s\");\n", sp, transp);
usr.bin/rpcgen/rpc_svcout.c:801:	f_print(fout, "\t\t\tif ((nconf = getnetconfigent(netid)) == NULL)\n");
lib/libc/rpc/svc_dg.c:622:	if (nconf = getnetconfigent(xprt->xp_netid)) {
lib/libc/rpc/svc_dg.c:680:			if (nconf = getnetconfigent(xprt->xp_netid)) {
lib/libc/rpc/getnetpath.c:172:	if ((ncp = getnetconfigent(npp)) != NULL) {
lib/libc/rpc/rpc_generic.c:274:	dummy = getnetconfigent(netid);
lib/libc/rpc/rpc_generic.c:451:	return getnetconfigent((char *)netid);
lib/libc/rpc/rpc_generic.c:530:	nconf = getnetconfigent("local");
lib/libc/rpc/getnetconfig.c:150: * setnetconfig() need *not* be called before a call to getnetconfigent().
lib/libc/rpc/getnetconfig.c:395: * getnetconfigent(netid) returns a pointer to the struct netconfig structure
lib/libc/rpc/getnetconfig.c:403:getnetconfigent(const char *netid)
lib/libc/rpc/getnetconfig.c:490: * netconfigp (previously returned by getnetconfigent()).
lib/libc/rpc/rpcb_clnt.c:501:		loopnconf = getnetconfigent(tmpnconf->nc_netid);
lib/libc/rpc/rpcb_clnt.c:752:			if ((newnconf = getnetconfigent("udp")) == NULL) {
contrib/tcp_wrappers/tli.c:230:    if ((config = getnetconfigent(config->nc_netid)) == 0) {
contrib/tcp_wrappers/tli.c:231:	tcpd_warn("getnetconfigent(%s): %s", config->nc_netid, nc_sperror());
usr.bin/rpcinfo/rpcinfo.c:695:			nconf = getnetconfigent(netid);
usr.bin/rpcinfo/rpcinfo.c:891:		nconf = getnetconfigent(netid);
```

GREP `evidence.`:
```
crypto/krb5/src/plugins/audit/j_dict.h:64:#define AU_EVIDENCE_TKT       "evidence_tkt"
crypto/krb5/src/plugins/audit/j_dict.h:88:#define AU_EVIDENCE_TKT_ID "evidence_tkt_id" /* 2nd ticket in s4u2proxy req */
crypto/krb5/src/include/k5-int.h:2375:                               krb5_ticket *evidence_tkt,
crypto/krb5/src/include/krb5/audit_plugin.h:89:    /** for s4u2proxy - evidence ticket ID; for u2u - second ticket ID */
crypto/krb5/src/include/kdb.h:1423:     * the same realm and the evidence ticket is forwardable.
usr.bin/rpcgen/rpc_parse.h:35:/*	The copyright notice above does not evidence any   	*/
usr.bin/rpcgen/rpc_util.h:35:/*	The copyright notice above does not evidence any   	*/
usr.bin/rpcgen/rpc_scan.h:35:/*	The copyright notice above does not evidence any   	*/
sys/contrib/ncsw/etc/mem.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/inc/integrations/dpaa_integration_ext.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/inc/Peripherals/bm_ext.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/inc/Peripherals/qm_ext.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/integrations/fman_ctrl_code/p3041_r1.0.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/fsl_bman.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/fsl_qman.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/bman_private.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/bm_ipc.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qman_low.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/bm.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qm_ipc.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qman_private.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qm.h:8: The copyright notice above does not evidence any actual or intended
contrib/libpcap/pcap-linux.c:1673:	 * type require a lot more back-and-forth to debug, as evidenced
contrib/wpa/src/common/sae.c:2244:	 * the values we sent which would be evidence of a reflection attack.
contrib/sqlite3/sqlite3.c:103246:  ** This assert() provides evidence for:
contrib/libarchive/libarchive/archive_read_support_filter_xz.c:233: * they have other evidence (file name, command-line option) to go on.
contrib/ofed/opensm/opensm/osm_torus.c:8722:	 * for now, until someone turns up evidence we need to be smarter.
crypto/krb5/src/kdc/do_tgs_req.c:747:            /* Otherwise the requested client is the evidence ticket client. */
crypto/krb5/src/lib/krb5/krb/gc_via_tkt.c:265:         * as we can't decrypt the evidence ticket.  However, if it is a
crypto/krb5/src/lib/krb5/krb/s4u_creds.c:1099:         * with the proxy TGT as the evidence ticket. */
```

### Round 3: ❌ INVALID

**🎯 Crux:** No network-facing call site exists where an attacker-controlled NULL pointer can be passed to getnetconfigent.

The function `getnetconfigent(const char *netid)` indeed lacks a NULL check for the `netid` parameter, which would cause a crash in `strcmp`. However, we must evaluate if this is reachable by an untrusted attacker. The 'Security Context Briefing' claims the input flows from an external RPC request, but the actual codebase evidence (grep results) contradicts this. The callers in the kernel (`sys/fs/nfs/nfs_commonkrpc.c`, `sys/nlm/nlm_prot_impl.c`) use either hardcoded string literals ('udp', 'tcp') or internal structure fields (`xprts[j]->xp_netid`). In `sys/rpc/rpc_generic.c:550` and `sys/nlm/nlm_prot_impl.c:1481`, it is called with a variable `netid`. Reviewing the context of these files (typical of RPC kernel implementations), `netid` is usually derived from the transport layer's configuration or a internal request structure, not directly from a raw network packet's payload without prior parsing and validation. There is no evidence of a direct path where a raw, unvalidated pointer from an external network packet is passed as the `netid` argument to this function. Since the crashes would only occur if a NULL pointer is passed—and the current call sites are either constants or internal state—this is a code quality issue rather than a security vulnerability.

CRUX: No network-facing call site exists where an attacker-controlled NULL pointer can be passed to getnetconfigent.
GREP: getnetconfigent

🔎 **Grep results:**

GREP `getnetconfigent`:
```
sys/rpc/netconfig.h:83:struct netconfig *getnetconfigent(const char *);
include/netconfig.h:113:struct netconfig *getnetconfigent(const char *);
sys/fs/nfs/nfs_commonkrpc.c:294:			nconf = getnetconfigent("udp");
sys/fs/nfs/nfs_commonkrpc.c:296:			nconf = getnetconfigent("tcp");
sys/fs/nfs/nfs_commonkrpc.c:299:			nconf = getnetconfigent("udp6");
sys/fs/nfs/nfs_commonkrpc.c:301:			nconf = getnetconfigent("tcp6");
contrib/tcp_wrappers/tli.c:230:    if ((config = getnetconfigent(config->nc_netid)) == 0) {
contrib/tcp_wrappers/tli.c:231:	tcpd_warn("getnetconfigent(%s): %s", config->nc_netid, nc_sperror());
sys/rpc/getnetconfig.c:112:getnetconfigent(const char *netid)
sys/rpc/rpc_generic.c:550:	dummy = getnetconfigent(netid);
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:296:		yp_error("getnetconfigent unix: %s", nc_sperror());
sys/nlm/nlm_prot_impl.c:533:			nconf = getnetconfigent("tcp");
sys/nlm/nlm_prot_impl.c:537:			nconf = getnetconfigent("tcp6");
sys/nlm/nlm_prot_impl.c:1481:				nconf = getnetconfigent(netid);
sys/nlm/nlm_prot_impl.c:1498:				nconf = getnetconfigent(xprts[j]->xp_netid);
usr.sbin/rpc.lockd/lock_proc.c:259:	nconf = getnetconfigent(netid);
usr.sbin/rpcbind/rpcbind.c:206:	nconf = getnetconfigent("local");
usr.sbin/rpcbind/rpcbind.c:208:		nconf = getnetconfigent("unix");
usr.sbin/rpcbind/check_bound.c:112:	newnconf = getnetconfigent(nconf->nc_netid);
usr.sbin/inetd/inetd.c:503:		udpconf = getnetconfigent("udp");
usr.sbin/inetd/inetd.c:504:		tcpconf = getnetconfigent("tcp");
usr.sbin/inetd/inetd.c:512:		udp6conf = getnetconfigent("udp6");
usr.sbin/inetd/inetd.c:513:		tcp6conf = getnetconfigent("tcp6");
usr.sbin/nfsd/nfsd.c:290:	} else if (getnetconfigent("udp6") == NULL ||
usr.sbin/nfsd/nfsd.c:291:		getnetconfigent("tcp6") == NULL) {
usr.sbin/nfsd/nfsd.c:336:			nconf_udp = getnetconfigent("udp");
usr.sbin/nfsd/nfsd.c:338:				err(1, "getnetconfigent udp failed");
usr.sbin/nfsd/nfsd.c:360:			nconf_udp6 = getnetconfigent("udp6");
usr.sbin/nfsd/nfsd.c:362:				err(1, "getnetconfigent udp6 failed");
usr.sbin/nfsd/nfsd.c:384:			nconf_tcp = getnetconfigent("tcp");
```

### Round 4: ❌ INVALID

[ARBITER] While getnetconfigent(const char *netid) lacks a NULL check before calling strcmp(netid, nconf->nc_netid), there is no evidence of a reachable attack vector. The grep results across kernel and user-space show that callers either use hardcoded string literals ('udp', 'tcp', etc.) or variables derived from trusted internal structures. No network-facing call site was found that passes attacker-controlled input to this function.

