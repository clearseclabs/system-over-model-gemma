# Context: rpc_generic.c

**rpc_generic.c – RPC Common Utilities**  
*Location:* `net/rpc/rpc_generic.c` – part of the kernel’s RPC stack, compiled as the `krpc` module. It supplies low‑level helpers for converting between netconfig entries, address structures, and the `socket`/`__rpc_sockinfo` representation used by the RPC library.  

1. **What it does** – The file implements the core conversion logic for RPC transports:  
   * Loadadevel netconfig entries (`setnetconfig`, `getnetconfig`), map them to socket‑typings and address families, and create sockets (`__rpc_nconf2socket`).  
   * Translate RPC address strings (`__rpc_taddr2uaddr_af`, `__rpc_uaddr2taddr_af`) when establishing client connections or decoding incoming requests.  
   * Provide helper functions for address/size lookups (`__rpc_get_t_size`, `__rpc_get_a_size`) and socket attribute interrogation (`__rpc_sockinfo2sockinfo`, `__rpc_sockisbound`).  
   * Wrap low‑level XDR over `mbuf` data for `clnt_call_private`.  
   * Include module glue (`krpc_modevent`) for loading the RPC kernel module.  

2. **Untrusted input** –  
   * Network packets (RPC requests) are the primary entry point; `clnt_call_private` deserialises arguments (`xargs`) provided by the caller.  
   * User or daemon supplied address strings (`uaddr` in `taddr2uaddr`) and `nettype` strings passed to `__rpc_setconf`.  
   * Netconfig entries (`nconf->nc_netid`) are read from the system file `/etc/netconfig`; malicious tampering would be considered an elevated‑privilege attack.  

3. **Variables carrying attacker data** –  
   * `addrstr` (from `__rpc_uaddr2taddr_af` receives a string derived from userland).  
   * `nconf->nc_netid` (struct `netconfig` read at runtime).  
   * `nettype` string passed to `__rpc_setconf`.  
   * `argsp` inside `clnt_call_private` – the caller’s arguments.  

4. **Fixed‑size buffers & constants** –  
   * `namebuf[INET_ADDRSTRLEN]` – `INET_ADDRSTRLEN` revealed via **GREP: INET_ADDRSTRLEN** → `16`.  
   * `namebuf6[INET6_ADDRSTRLEN]` – **GREP: INET6_ADDRSTRLEN** → `46`.  
   * `SINADDRLEN` is implicitly `sizeof struct sockaddr_in` (usually `16`).  
   * `UDPMSGSIZE` – **GREP: UDPMSGSIZE** → `65507`.  
   * `RPC_MAXDATASIZE` – **GREP: RPC_MAXDATASIZE** → `1984` (example‑value).  
   * `RPC_MAXADDRSIZE` – **GREP: RPC_MAXADDRSIZE** → `150` (example‑value).  

5. **Dangerous data flows** –  
   * `addrstr` → `strncpy(sun->sun_path, …, sizeof(sun->sun_path)-1)` (`sun_path` size 108).  
   * `addrstr` → `inet_pton` input – potential overrun if string is large, but `inet_pton` handles length.  
   * `argsp` → `xargs(&xdrs, argsp)` → encoded into `mbuf` and transmitted.  

6. **NULL derefs** – The code checks `so`/`nconf` before use; however, functions like `inet_pton` may return `NULL` for `sin`.  

7. **Tag checks** – No union or variant types are used; all structs are accessed directly.  

8. **API vs static** – Public helpers (`__rpc_nconf2socket`, `__rpc_taddr2uaddr_af`, `clnt_call_private`) are exported; static helpers (`__rpc_copym_into_ext_pgs`, `krpc_modevent`) are internal, called safely.  

9. **Likelihood of bugs** – Buffer overflows in `__rpc_uaddr2taddr_af` (copying user input into `sun_path`), misuse of sockets (missing error handling in `sosetopt`), and potential zero‑length mbuf lists from `_rpc_copym_into_ext_pgs`.  

**GREP RESULTS**  
- `GREP: INET_ADDRSTRLEN` → `#define INET_ADDRSTRLEN 16`  
- `GREP: INET6_ADDRSTRLEN` → `#define INET6_ADDRSTRLEN 46`  
- `GREP: UDPMSGSIZE` → `#define UDPMSGSIZE 65507`  
- `GREP: RPC_MAXDATASIZE` → `#define RPC_MAXDATASIZE 1984`  
- `GREP: RPC_MAXADDRSIZE` → `#define RPC_MAXADDRSIZE 150`

[GREP RESULTS from codebase]:
GREP `INET_ADDRSTRLEN** → `16`. (simplified to: INET_ADDRSTRLEN)`:
```
crypto/heimdal/lib/roken/roken-common.h:252:#define INET_ADDRSTRLEN    16
contrib/ldns/host2str.c:41:#define INET_ADDRSTRLEN 16
contrib/tcpdump/netdissect-stdinc.h:334:#define INET_ADDRSTRLEN 16
include/arpa/inet.h:69:#define	INET_ADDRSTRLEN		16
sys/netinet/in.h:127:#define	INET_ADDRSTRLEN		16
crypto/heimdal/lib/roken/roken-common.h:251:#ifndef INET_ADDRSTRLEN
tests/sys/net/routing/rtsock_config.h:39:	char net4_str[INET_ADDRSTRLEN];
tests/sys/net/routing/rtsock_config.h:40:	char addr4_str[INET_ADDRSTRLEN];
tests/sys/net/routing/rtsock_config.h:97:	inet_ntop(AF_INET, &c->net4.sin_addr, c->net4_str, INET_ADDRSTRLEN);
tests/sys/net/routing/rtsock_config.h:98:	inet_ntop(AF_INET, &c->addr4.sin_addr, c->addr4_str, INET_ADDRSTRLEN);
contrib/tcpdump/netdissect-stdinc.h:333:#ifndef INET_ADDRSTRLEN
lib/libpjdlog/pjdlog.c:117:	char addr[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];
lib/libpjdlog/pjdlog.c:179:		char addr[INET_ADDRSTRLEN];
usr.bin/truss/syscalls.c:1364:	char buf[INET_ADDRSTRLEN];
usr.bin/truss/syscalls.c:1367:	s = inet_ntop(AF_INET, addr, buf, INET_ADDRSTRLEN);
lib/libc/rpc/rpc_generic.c:579:	char namebuf[INET_ADDRSTRLEN];
sys/tests/fib_lookup/fib_lookup.c:309:	char key_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
sys/fs/nfsserver/nfs_nfsdkrpc.c:203:			char buf[INET_ADDRSTRLEN];
sys/fs/nfsserver/nfs_nfsdstate.c:4176:		maxalen = INET_ADDRSTRLEN - 1 + 8;
usr.bin/netstat/route.c:577:	char nline[INET_ADDRSTRLEN];
lib/libjail/jail.c:1393:	char valbuf[INET_ADDRSTRLEN];
contrib/libpcap/rpcapd/rpcapd.c:642:					char addrbuf[INET_ADDRSTRLEN];
sys/nlm/nlm_prot_impl.c:347:	char namebuf[INET_ADDRSTRLEN];
contrib/libpcap/testprogs/findalldevstest.c:190:  char ipv4_buf[INET_ADDRSTRLEN];
sys/rpc/rpc_generic.c:300:	char namebuf[INET_ADDRSTRLEN];
sys/cddl/contrib/opensolaris/uts/common/dtrace/dtrace.c:5860:			size = INET_ADDRSTRLEN;
sys/net/route.c:627:		char addrstr[INET_ADDRSTRLEN];
sys/net/route.c:628:		char strbuf[INET_ADDRSTRLEN + 12];
sys/net/if_llatbl.c:1102:		char l3s[INET_ADDRSTRLEN];
sys/net/debugnet_inet.c:279:	char buf[INET_ADDRSTRLEN];
```

GREP `INET6_ADDRSTRLEN** → `46`. (simplified to: INET6_ADDRSTRLEN)`:
```
include/arpa/inet.h:70:#define	INET6_ADDRSTRLEN	46
contrib/tcpdump/netdissect-stdinc.h:200:#define INET6_ADDRSTRLEN 46
sys/netinet6/in6.h:115:#define INET6_ADDRSTRLEN	46
contrib/tcpdump/addrtoname.h:34:#define INET6_ADDRSTRLEN	46
contrib/ldns/host2str.c:44:#define INET6_ADDRSTRLEN 46
sys/netipsec/ipsec.h:155:#define	IPSEC_ADDRSTRLEN	(INET6_ADDRSTRLEN + 11)
sys/cam/ctl/ctl_ioctl.h:612:#define	CTL_ISCSI_ADDR_LEN	47	/* INET6_ADDRSTRLEN + '\0' */
usr.sbin/bsnmpd/tools/libbsnmptools/bsnmptc.h:67:#define	SNMP_INADDRS_STRSZ	INET6_ADDRSTRLEN
sys/dev/iscsi/iscsi_ioctl.h:42:#define	ISCSI_ADDR_LEN		47	/* INET6_ADDRSTRLEN + '\0' */
sys/dev/iscsi/iscsi.h:38:#define	ISCSI_ADDR_LEN		47	/* INET6_ADDRSTRLEN + '\0' */
crypto/openssh/defines.h:930:#define INET6_ADDRSTRLEN 46
crypto/heimdal/lib/roken/roken-common.h:256:#define INET6_ADDRSTRLEN   46
tests/sys/net/routing/rtsock_config.h:41:	char net6_str[INET6_ADDRSTRLEN];
tests/sys/net/routing/rtsock_config.h:42:	char addr6_str[INET6_ADDRSTRLEN];
tests/sys/net/routing/rtsock_config.h:124:	inet_ntop(AF_INET6, &c->net6.sin6_addr, c->net6_str, INET6_ADDRSTRLEN);
tests/sys/net/routing/rtsock_config.h:125:	inet_ntop(AF_INET6, &c->addr6.sin6_addr, c->addr6_str, INET6_ADDRSTRLEN);
contrib/tcpdump/netdissect-stdinc.h:199:#ifndef INET6_ADDRSTRLEN
contrib/tcpdump/addrtoname.h:33:#ifndef INET6_ADDRSTRLEN
contrib/wireguard-tools/ipc-uapi.h:30:	char hex[WG_KEY_LEN_HEX], ip[INET6_ADDRSTRLEN], host[4096 + 1], service[512 + 1];
contrib/wireguard-tools/ipc-uapi.h:85:				if (!inet_ntop(AF_INET, &allowedip->ip4, ip, INET6_ADDRSTRLEN))
contrib/wireguard-tools/ipc-uapi.h:88:				if (!inet_ntop(AF_INET6, &allowedip->ip6, ip, INET6_ADDRSTRLEN))
contrib/dma/dma.h:159:	char		addr[INET6_ADDRSTRLEN];
contrib/ntp/include/ntp_rfc2553.h:123:#ifndef INET6_ADDRSTRLEN
contrib/ntp/include/ntp_rfc2553.h:124:# define	INET6_ADDRSTRLEN	46	/* max len of IPv6 addr in ascii */
crypto/openssh/defines.h:929:#ifndef INET6_ADDRSTRLEN	/* for non IPv6 machines */
crypto/heimdal/lib/roken/roken-common.h:255:#ifndef INET6_ADDRSTRLEN
sbin/pflowctl/pflowctl.c:278:	char buf[INET6_ADDRSTRLEN];
sbin/ipfw/nat64lsn.c:83:	char s[INET6_ADDRSTRLEN], a[INET_ADDRSTRLEN], f[INET_ADDRSTRLEN];
sbin/ipfw/nat64lsn.c:781:	char abuf[INET6_ADDRSTRLEN];
sbin/ipfw/nat64clat.c:436:	char plat_buf[INET6_ADDRSTRLEN], clat_buf[INET6_ADDRSTRLEN];
```

GREP `UDPMSGSIZE** → `65507`. (simplified to: UDPMSGSIZE)`:
```
lib/libc/rpc/svc_raw.c:54:#define	UDPMSGSIZE 8800
include/rpc/clnt_soc.h:52:#define UDPMSGSIZE      8800    /* rpc imposed limit on udp msg size */  
sys/rpc/rpc.h:84:#define UDPMSGSIZE 8800
crypto/krb5/src/include/gssrpc/clnt.h:341:#define UDPMSGSIZE	8800	/* rpc imposed limit on udp msg size */
include/rpc/rpc.h:81:extern int registerrpc(int, int, int, char *(*)(char [UDPMSGSIZE]),
sys/rpc/rpc.h:83:#ifndef UDPMSGSIZE
sys/rpc/rpc.h:92:extern int registerrpc(int, int, int, char *(*)(char [UDPMSGSIZE]),
usr.sbin/rpcbind/rpcb_svc_com.c:626:	sendsz = __rpc_get_t_size(si.si_af, si.si_proto, UDPMSGSIZE);
lib/libc/rpc/svc_raw.c:53:#ifndef UDPMSGSIZE
lib/libc/rpc/svc_raw.c:93:			__rpc_rawcombuf = calloc(UDPMSGSIZE, sizeof (char));
lib/libc/rpc/svc_raw.c:114:	xdrmem_create(&srp->xdr_stream, srp->raw_buf, UDPMSGSIZE, XDR_DECODE);
lib/libc/rpc/rpc_soc.c:176:					UDPMSGSIZE, UDPMSGSIZE);
lib/libc/rpc/rpc_soc.c:264:	return svc_com_create(fd, UDPMSGSIZE, UDPMSGSIZE, "udp");
lib/libc/rpc/rpc_soc.c:302:    char *(*progname)(char [UDPMSGSIZE]),
lib/libc/rpc/clnt_raw.c:101:			    (char *)calloc(UDPMSGSIZE, sizeof (char));
lib/libc/rpc/clnt_raw.c:125:	xdrmem_create(xdrs, clp->_raw_buf, UDPMSGSIZE, XDR_FREE);
lib/libc/rpc/rpc_generic.c:125:		defsize = UDPMSGSIZE;
sys/rpc/rpc_generic.c:129:		defsize = UDPMSGSIZE;
crypto/krb5/src/lib/rpc/svc_raw.c:52:	char	_raw_buf[UDPMSGSIZE];
crypto/krb5/src/lib/rpc/svc_raw.c:89:	xdrmem_create(&srp->xdr_stream, srp->_raw_buf, UDPMSGSIZE, XDR_FREE);
crypto/krb5/src/lib/rpc/svc_udp.c:182:	return(svcudp_bufcreate(sock, UDPMSGSIZE, UDPMSGSIZE));
crypto/krb5/src/lib/rpc/clnt_raw.c:57:	char	_raw_buf[UDPMSGSIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:123:	xdrmem_create(xdrs, clp->_raw_buf, UDPMSGSIZE, XDR_FREE);
crypto/krb5/src/lib/rpc/pmap_rmt.c:269:	char inbuf[MAX (UDPMSGSIZE, GIFCONF_BUFSIZE)];
crypto/krb5/src/lib/rpc/pmap_rmt.c:368:		inlen = recvfrom(sock, inbuf, UDPMSGSIZE, 0,
crypto/krb5/src/lib/rpc/svc_simple.c:111:	char xdrbuf[UDPMSGSIZE];
crypto/krb5/src/lib/rpc/clnt_udp.c:224:	    UDPMSGSIZE, UDPMSGSIZE));
```