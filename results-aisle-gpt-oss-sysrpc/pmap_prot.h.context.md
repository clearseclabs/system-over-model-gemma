# Context: pmap_prot.h

**Context Briefing – `pmap_prot.h`**  
*(~250 words)*  

1. **Role** – `pmap_prot.h` declares the RPC protocol for the local “binder” service (`pmap`) that listens on port 111.  It defines the service’s procedures (NULL, SET, UNSET, GETPORT, DUMP, CALLIT), the data structures (`portmap`, `pmaplist`), and the XDR serialization helpers (`xdr_portmap`, `xdr_pmaplist`, `xdr_pmaplist_ptr`).  The header is included by modules that implement or call the local `rpcbind` service.  

2. **Untrusted Input Path** – Input originates on the network (UDP/TCP socket 111).  The RPC runtime decodes the raw RPC packet using XDR, then calls `xdr_portmap()` (or `xdr_pmaplist*()`) to materialise the `struct portmap` from the attacker‑supplied byte stream.  Thus all fields of `struct portmap` are populated directly from the network.  

3. **Attacker‑controlled Variables** –  
   * `pm_prog` – program number requested.  
   * `pm_vers` – program version.  
   * `pm_prot` – protocol (TCP/UDP).  
   * `pm_port` – port to bind or query.  
   These fields flow from the XDR buffer → local `struct portmap` → any subsequent `rpcbind` logic, e.g., lookup table or registration table manipulation.  

4. **Fixed‑size Buffers / Size Constants** – No buffers exist in this header.  The only constants are macro values, shown below:  
```
GREP: PMAPPORT
// #define PMAPPORT ((u_short)111)
GREP: PMAPPROG
// #define PMAPPROG ((u_long)100000)
GREP: PMAPVERS
// #define PMAPVERS ((u_long)2)
```
(Other constants have identical literal values.)  

5. **Dangerous Flows** –  
   • **Source**: Network XDR blob  
   • **Destination**: `struct portmap` fields (`pm_*`) during `xdr_portmap()`  
   • **Function**: `xdr_portmap()`  
   • **Buffer**: No explicit buffer; the danger is the XDR decoder copying arbitrary bytes into fixed‑size 32‑bit integers.  

6. **Potential NULL deref** – `XDR *` and `struct portmap *` parameters to `xdr_portmap()` are not validated in the header; the implementation may dereference them without checks.  

7. **Tagged Unions** – None present.  

8. **API vs Static** – All listed functions are `extern` (public).  No static helper functions are declared in this header.  

9. **Likely Bug Classes** –  
   * Invalid argument handling (NULL pointers).  
   * XDR deserialization misuse (size/endianness).  
   * Integer overflows or mismatched type casts.  

This summary supplies the key variable names, constant values, data‑flow points, and structural hints useful for assessing potential vulnerabilities in RPCXDR decoding and `rpcbind` registration logic.

[GREP RESULTS from codebase]:
GREP `PMAPPORT`:
```
stand/libsa/rpc.h:37:#define	PMAPPORT		111
contrib/tcpdump/print-sunrpc.c:134:#define SUNRPC_PMAPPORT		((uint16_t)111)
sys/nfs/krpc.h:22:#define	PMAPPORT		111
sys/rpc/pmap_prot.h:74:#define PMAPPORT		((u_short)111)
crypto/krb5/src/include/gssrpc/pmap_prot.h:74:#define PMAPPORT		((u_short)111)
include/rpc/pmap_prot.h:74:#define PMAPPORT		((u_short)111)
contrib/tcpdump/print-sunrpc.c:176:		snprintf(dstid, sizeof(dstid), "0x%x", SUNRPC_PMAPPORT);
stand/libsa/rpc.c:393:		port = PMAPPORT;
usr.bin/rpcinfo/rpcinfo.c:477:		server_addr.sin_port = htons(PMAPPORT);
sys/nfs/krpc_subr.c:151:		*portp = htons(PMAPPORT);
sys/nfs/krpc_subr.c:165:	sin->sin_port = htons(PMAPPORT);
crypto/krb5/src/lib/rpc/pmap_getport.c:74:	address->sin_port = htons(PMAPPORT);
crypto/krb5/src/lib/rpc/pmap_rmt.c:97:	addr->sin_port = htons(PMAPPORT);
crypto/krb5/src/lib/rpc/pmap_rmt.c:298:	baddr.sin_port = htons(PMAPPORT);
crypto/krb5/src/lib/rpc/get_myaddress.c:60:	addr->sin_port = htons(PMAPPORT);
crypto/krb5/src/lib/rpc/get_myaddress.c:113:			addr->sin_port = htons(PMAPPORT);
crypto/krb5/src/lib/rpc/pmap_getmaps.c:76:	address->sin_port = htons(PMAPPORT);
usr.sbin/ypbind/yp_ping.c:114:	address->sin_port = htons(PMAPPORT);
lib/libc/rpc/pmap_getport.c:74:	address->sin_port = htons(PMAPPORT);
lib/libc/rpc/rpc_soc.c:280:	addr->sin_port = htons(PMAPPORT);
lib/libc/rpc/pmap_rmt.c:87:	addr->sin_port = htons(PMAPPORT);
lib/libc/rpc/pmap_getmaps.c:79:	address->sin_port = htons(PMAPPORT);
usr.sbin/rpcbind/rpcbind.c:594:		pml->pml_map.pm_port = PMAPPORT;
```

GREP `PMAPPROG`:
```
include/rpc/pmap_prot.h:75:#define PMAPPROG		((u_long)100000)
stand/libsa/rpc.h:38:#define	PMAPPROG		100000
crypto/krb5/src/include/gssrpc/pmap_prot.h:75:#define PMAPPROG		((rpcprog_t)100000)
sys/nfs/krpc.h:23:#define	PMAPPROG		100000
sys/rpc/pmap_prot.h:75:#define PMAPPROG		((u_long)100000)
crypto/krb5/src/lib/rpc/pmap_getport.c:75:	client = clntudp_bufcreate(address, PMAPPROG,
crypto/krb5/src/lib/rpc/pmap_getmaps.c:77:	client = clnttcp_create(address, PMAPPROG,
crypto/krb5/src/lib/rpc/pmap_clnt.c:75:	client = clntudp_bufcreate(&myaddress, PMAPPROG, PMAPVERS,
crypto/krb5/src/lib/rpc/pmap_clnt.c:156:	client = clntudp_bufcreate(&myaddress, PMAPPROG, PMAPVERS,
crypto/krb5/src/lib/rpc/pmap_rmt.c:98:	client = clntudp_create(addr, PMAPPROG, PMAPVERS, timeout, &sock);
crypto/krb5/src/lib/rpc/pmap_rmt.c:306:	msg.rm_call.cb_prog = PMAPPROG;
usr.bin/rpcinfo/rpcinfo.c:478:		client = clnttcp_create(&server_addr, PMAPPROG, PMAPVERS,
usr.bin/rpcinfo/rpcinfo.c:481:		client = local_rpcb(PMAPPROG, PMAPVERS);
usr.bin/rpcinfo/rpcinfo.c:705:		client = local_rpcb(PMAPPROG, RPCBVERS);
usr.bin/rpcinfo/rpcinfo.c:1009:		client = local_rpcb(PMAPPROG, RPCBVERS4);
stand/libsa/bootparam.c:160:	len = rpc_call(d, PMAPPROG, PMAPVERS, PMAPPROC_CALLIT,
stand/libsa/rpc.c:392:	if (prog == PMAPPROG) {
stand/libsa/rpc.c:409:	cc = rpc_call(d, PMAPPROG, PMAPVERS, PMAPPROC_GETPORT,
lib/libc/rpc/pmap_getport.c:75:	client = clntudp_bufcreate(address, PMAPPROG,
lib/libc/rpc/pmap_rmt.c:88:	client = clntudp_create(addr, PMAPPROG, PMAPVERS, timeout, &sock);
lib/libc/rpc/clnt_bcast.c:404:		msg.rm_call.cb_prog = PMAPPROG;
lib/libc/rpc/pmap_getmaps.c:80:	client = clnttcp_create(address, PMAPPROG,
usr.sbin/ypbind/yp_ping.c:116:	client = clntudp_bufcreate(address, PMAPPROG,
sys/nfs/krpc_subr.c:150:	if (prog == PMAPPROG) {
sys/nfs/krpc_subr.c:166:	error = krpc_call(sin, PMAPPROG, PMAPVERS,
usr.sbin/rpcbind/rpcbind.c:581:		if (!svc_register(my_xprt, PMAPPROG, PMAPVERS,
usr.sbin/rpcbind/rpcbind.c:592:		pml->pml_map.pm_prog = PMAPPROG;
usr.sbin/rpcbind/rpcbind.c:651:		rbllist_add(PMAPPROG, PMAPVERS, nconf, &taddr.addr);
```

GREP `PMAPVERS`:
```
stand/libsa/rpc.h:39:#define	PMAPVERS		2
include/rpc/pmap_prot.h:76:#define PMAPVERS		((u_long)2)
include/rpc/pmap_prot.h:77:#define PMAPVERS_PROTO		((u_long)2)
include/rpc/pmap_prot.h:78:#define PMAPVERS_ORIG		((u_long)1)
sys/rpc/pmap_prot.h:76:#define PMAPVERS		((u_long)2)
sys/rpc/pmap_prot.h:77:#define PMAPVERS_PROTO		((u_long)2)
sys/rpc/pmap_prot.h:78:#define PMAPVERS_ORIG		((u_long)1)
sys/nfs/krpc.h:24:#define	PMAPVERS		2
crypto/krb5/src/include/gssrpc/pmap_prot.h:76:#define PMAPVERS		((rpcvers_t)2)
crypto/krb5/src/include/gssrpc/pmap_prot.h:77:#define PMAPVERS_PROTO		((rpcprot_t)2)
crypto/krb5/src/include/gssrpc/pmap_prot.h:78:#define PMAPVERS_ORIG		((rpcvers_t)1)
usr.bin/rpcinfo/rpcinfo.c:478:		client = clnttcp_create(&server_addr, PMAPPROG, PMAPVERS,
usr.bin/rpcinfo/rpcinfo.c:481:		client = local_rpcb(PMAPPROG, PMAPVERS);
usr.bin/rpcinfo/rpcinfo.c:507:			if (err.re_vers.low > PMAPVERS) {
usr.bin/rpcinfo/rpcinfo.c:733:		    if (err.re_vers.high == PMAPVERS) {
usr.bin/rpcinfo/rpcinfo.c:738:			vers = PMAPVERS;
stand/libsa/bootparam.c:160:	len = rpc_call(d, PMAPPROG, PMAPVERS, PMAPPROC_CALLIT,
stand/libsa/rpc.c:409:	cc = rpc_call(d, PMAPPROG, PMAPVERS, PMAPPROC_GETPORT,
usr.sbin/rpcbind/security.c:77:		if (rpcbvers > PMAPVERS) {
usr.sbin/rpcbind/rpcb_svc_com.c:450:	if (cap->rmt_localvers == PMAPVERS) {
usr.sbin/rpcbind/rpcb_svc_com.c:674:		    __func__, versnum == PMAPVERS ? "pmap_rmtcall" :
usr.sbin/rpcbind/rpcbind.c:581:		if (!svc_register(my_xprt, PMAPPROG, PMAPVERS,
usr.sbin/rpcbind/rpcbind.c:593:		pml->pml_map.pm_vers = PMAPVERS;
usr.sbin/rpcbind/rpcbind.c:651:		rbllist_add(PMAPPROG, PMAPVERS, nconf, &taddr.addr);
usr.sbin/rpcbind/pmap_svc.c:76:		check_access(xprt, rqstp->rq_proc, NULL, PMAPVERS);
usr.sbin/rpcbind/pmap_svc.c:126:		rpcbproc_callit_com(rqstp, xprt, PMAPPROC_CALLIT, PMAPVERS);
usr.sbin/rpcbind/pmap_svc.c:183:	if (!check_access(xprt, op, &reg, PMAPVERS)) {
usr.sbin/rpcbind/pmap_svc.c:271:	if (!check_access(xprt, PMAPPROC_GETPORT, &reg, PMAPVERS)) {
usr.sbin/rpcbind/pmap_svc.c:344:	if (!check_access(xprt, PMAPPROC_DUMP, NULL, PMAPVERS)) {
usr.sbin/rpcbind/rpcb_stat.c:67:	case PMAPVERS:		/* version 2 */
```