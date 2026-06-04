# Context: rpc_generic.c

This briefing covers `rpc_generic.c`, which provides miscellaneous helper routines for the Kernel RPC (kRPC) implementation, focusing on network configuration, address translation, and socket management.

### 1. Role & Location
`rpc_generic.c` is a support module for the RPC subsystem. It manages the translation between human-readable address strings and binary socket structures, handles `netconfig` lookups, and provides XDR-style calling wrappers.

### 2. Untrusted Input
Untrusted input enters via:
* **Network/API**: `uaddr` strings passed to `uaddr2taddr` (likely from configuration files or network-provided addresses).
* **Netconfig**: Data from `setnetconfig()` and `getnetconfig()`, which typically read from `/etc/netconfig`.

### 3. Attacker-Controlled Data
* **`uaddr`** $\rightarrow$ `__rpc_uaddr2taddr_af`: Passed as a string; used to parse IP/Port or Unix paths.
* **`nettype`** $\rightarrow$ `getnettype` $\rightarrow$ `__rpc_setconf`: Passed as a string to determine RPC network semantics.
* **`nbuf->buf`** $\rightarrow$ `__rpc_taddr2uaddr_af`: Binary address data used to generate strings.

### 4. Fixed-Size Buffers & Constants
* **`namebuf[INET_ADDRSTRLEN]`**: `INET_ADDRSTRLEN` = 16
* **`namebuf6[INET6_ADDRSTRLEN]`**: `INET6_ADDRSTRLEN` = 46
* **`sun->sun_path`**: Size determined by `struct sockaddr_un` (typically 108 bytes).
* **`defsize` (TCP)**: 64 * 1024 (65536)
* **`defsize` (UDP)**: `UDPMSGSIZE` (GREP: `UDPMSGSIZE`)
* **`defsize` (Default)**: `RPC_MAXDATASIZE` (GREP: `RPC_MAXDATASIZE`)
* **`__rpc_get_a_size` fallback**: `RPC_MAXADDRSIZE` (GREP: `RPC_MAXADDRSIZE`)

### 5. Dangerous Data Flows
* **`uaddr`** $\rightarrow$ **`sun->sun_path`** via `strncpy` in `__rpc_uaddr2taddr_af`. Buffer size: `sizeof(sun->sun_path)`.
* **`nbuf->buf`** $\rightarrow$ **`namebuf`/`namebuf6`** via `inet_ntop` in `__rpc_taddr2uaddr_af`.

### 6. NULL Dereferences
* **`vhandle`** in `__rpc_getconf` and `__rpc_endconf` is checked.
* **`uaddr`** in `__rpc_uaddr2taddr_af` is checked.
* **`nconf`** in `__rpc_nconf2sockinfo` is not explicitly NULL-checked before accessing `nconf->nc_netid`.

### 7. Tagged Unions/Variants
No explicit tagged unions; however, `sockaddr` is treated as a variant based on `ss_family` (AF_INET, AF_INET6, AF_LOCAL) in `__rpc_sockisbound` and `bindresvport`. Type checks are performed via `switch(af)`.

### 8. API vs. Helpers
* **Public API**: `__rpc_setconf`, `__rpc_getconf`, `__rpc_endconf`, `taddr2uaddr`, `uaddr2taddr`, `clnt_call_private`, `bindresvport`.
* **Static Helpers**: `getnettype`, `krpc_modevent`. These are called internally and generally safely.

### 9. Likely Bug Classes
* **Buffer Over-read/Overflow**: Specifically in `__rpc_taddr2uaddr_af` where `sun->sun_len` is used to calculate length for `sbuf_printf`.
* **Integer Overflows**: In port parsing logic (`porthi << 8 | portlo`).
* **Resource Leaks**: Potential `strdup` or `malloc` leaks if error paths in `__rpc_uaddr2taddr_af` are triggered.

[GREP RESULTS from codebase]:
GREP `UDPMSGSIZE`) (simplified to: UDPMSGSIZE)`:
```
lib/libc/rpc/svc_raw.c:54:#define	UDPMSGSIZE 8800
include/rpc/clnt_soc.h:52:#define UDPMSGSIZE      8800    /* rpc imposed limit on udp msg size */  
sys/rpc/rpc.h:84:#define UDPMSGSIZE 8800
crypto/krb5/src/include/gssrpc/clnt.h:341:#define UDPMSGSIZE	8800	/* rpc imposed limit on udp msg size */
include/rpc/rpc.h:81:extern int registerrpc(int, int, int, char *(*)(char [UDPMSGSIZE]),
sys/rpc/rpc.h:83:#ifndef UDPMSGSIZE
sys/rpc/rpc.h:92:extern int registerrpc(int, int, int, char *(*)(char [UDPMSGSIZE]),
lib/libc/rpc/svc_raw.c:53:#ifndef UDPMSGSIZE
lib/libc/rpc/svc_raw.c:93:			__rpc_rawcombuf = calloc(UDPMSGSIZE, sizeof (char));
lib/libc/rpc/svc_raw.c:114:	xdrmem_create(&srp->xdr_stream, srp->raw_buf, UDPMSGSIZE, XDR_DECODE);
lib/libc/rpc/rpc_soc.c:176:					UDPMSGSIZE, UDPMSGSIZE);
lib/libc/rpc/rpc_soc.c:264:	return svc_com_create(fd, UDPMSGSIZE, UDPMSGSIZE, "udp");
lib/libc/rpc/rpc_soc.c:302:    char *(*progname)(char [UDPMSGSIZE]),
lib/libc/rpc/clnt_raw.c:101:			    (char *)calloc(UDPMSGSIZE, sizeof (char));
lib/libc/rpc/clnt_raw.c:125:	xdrmem_create(xdrs, clp->_raw_buf, UDPMSGSIZE, XDR_FREE);
lib/libc/rpc/rpc_generic.c:125:		defsize = UDPMSGSIZE;
usr.sbin/rpcbind/rpcb_svc_com.c:626:	sendsz = __rpc_get_t_size(si.si_af, si.si_proto, UDPMSGSIZE);
sys/rpc/rpc_generic.c:129:		defsize = UDPMSGSIZE;
crypto/krb5/src/lib/rpc/svc_raw.c:52:	char	_raw_buf[UDPMSGSIZE];
crypto/krb5/src/lib/rpc/svc_raw.c:89:	xdrmem_create(&srp->xdr_stream, srp->_raw_buf, UDPMSGSIZE, XDR_FREE);
crypto/krb5/src/lib/rpc/svc_udp.c:182:	return(svcudp_bufcreate(sock, UDPMSGSIZE, UDPMSGSIZE));
crypto/krb5/src/lib/rpc/clnt_raw.c:57:	char	_raw_buf[UDPMSGSIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:123:	xdrmem_create(xdrs, clp->_raw_buf, UDPMSGSIZE, XDR_FREE);
crypto/krb5/src/lib/rpc/svc_simple.c:111:	char xdrbuf[UDPMSGSIZE];
crypto/krb5/src/lib/rpc/pmap_rmt.c:269:	char inbuf[MAX (UDPMSGSIZE, GIFCONF_BUFSIZE)];
crypto/krb5/src/lib/rpc/pmap_rmt.c:368:		inlen = recvfrom(sock, inbuf, UDPMSGSIZE, 0,
crypto/krb5/src/lib/rpc/clnt_udp.c:224:	    UDPMSGSIZE, UDPMSGSIZE));
```

GREP `RPC_MAXDATASIZE`) (simplified to: RPC_MAXDATASIZE)`:
```
lib/libc/rpc/rpc_com.h:52:#define	RPC_MAXDATASIZE 9000
include/rpc/rpc_com.h:51:#define	RPC_MAXDATASIZE 9000
sys/rpc/rpc_com.h:53:#define	RPC_MAXDATASIZE 9000
usr.sbin/ypserv/yp_main.c:399:			transp = svc_vc_create(slep->sle_sock, RPC_MAXDATASIZE,
usr.sbin/ypserv/yp_main.c:400:			    RPC_MAXDATASIZE);
usr.sbin/mountd/mountd.c:429:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/mountd/mountd.c:1082:			transp = svc_vc_create(fd, RPC_MAXDATASIZE,
usr.sbin/mountd/mountd.c:1083:			    RPC_MAXDATASIZE);
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:172:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.lockd/lockd.c:125:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.lockd/lockd.c:292:			xprt = svc_vc_create(fd, RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.lockd/lockd.c:762:		    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
lib/libc/xdr/xdr.c:705:		maxsize = RPC_MAXDATASIZE;
lib/libc/xdr/xdr.c:767:	return xdr_string(xdrs, cpp, RPC_MAXDATASIZE);
lib/libc/rpc/rpc_generic.c:128:		defsize = RPC_MAXDATASIZE;
lib/libc/rpc/rpcb_st_xdr.c:66:	if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:118:		if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:156:		if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:184:	if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:60:	if (!xdr_string(xdrs, &objp->r_netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:63:	if (!xdr_string(xdrs, &objp->r_addr, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:66:	if (!xdr_string(xdrs, &objp->r_owner, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:160:	if (!xdr_string(xdrs, &objp->r_maddr, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:163:	if (!xdr_string(xdrs, &objp->r_nc_netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:169:	if (!xdr_string(xdrs, &objp->r_nc_protofmly, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:172:	if (!xdr_string(xdrs, &objp->r_nc_proto, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:287:	if (!xdr_string(xdrs, &objp->addr, RPC_MAXDATASIZE)) {
lib/libc/rpc/svc_nl.c:278:	body = snl_reserve_msg_attr_raw(&nw, RPCNL_REPLY_BODY, RPC_MAXDATASIZE);
lib/libc/rpc/svc_nl.c:280:	xdrmem_create(&xdrs, (char *)(body + 1), RPC_MAXDATASIZE, XDR_ENCODE);
usr.sbin/rpc.statd/statd.c:91:  int maxrec = RPC_MAXDATASIZE;
```

GREP `RPC_MAXADDRSIZE`) (simplified to: RPC_MAXADDRSIZE)`:
```
lib/libc/rpc/rpc_com.h:53:#define	RPC_MAXADDRSIZE 1024
include/rpc/rpc_com.h:52:#define	RPC_MAXADDRSIZE 1024
sys/rpc/rpc_com.h:54:#define	RPC_MAXADDRSIZE 1024
lib/libc/rpc/rpc_generic.c:156:	return ((u_int)RPC_MAXADDRSIZE);
sys/rpc/rpc_generic.c:160:	return ((u_int)RPC_MAXADDRSIZE);
```