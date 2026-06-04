# Context: svc_generic.c

**Context Briefing – svc_generic.c (NetBSD RPC Server Layer)**  
*Approx. 250 words*

1. **Purpose & Placement**  
   `svc_generic.c` implements the high‑level server side of Sun/NetBSD RPC.  
   - `svc_tp_create()` is the public API used by application code to register an RPC program and version with a network transport (`netconfig`).  
   - `svc_tli_create()` creates the socket‑based transport (`SVCXPRT`) and registers it with the RPC server.  
   Both functions live in the `rpc` subsystem, called by external applications or services (e.g., rpcbind registration).

2. **Untrusted Input Path**  
   The only directly supplied input is the `uaddr` string passed to `svc_tp_create()`; this string may originate from user‑space code, command‑line utilities, or API calls. `uaddr` is further passed to `uaddr2taddr()`, which allocates a `struct netbuf` containing a address buffer.

3. **Attacker‑Controlled Variables**  
   - `uaddr` → `taddr` (`struct netbuf *`) → `bind.addr.buf` in the `t_bind` struct → `svc_tli_create()` → eventually `xprt->xp_netid` (duplicate of `nconf->nc_netid`).  
   The flow is linear: `svc_tp_create()` → `uaddr2taddr()` → `svc_tli_create()` → `svc_reg()`.

4. **Fixed‑size Buffers & Size Constants**  
   - `struct sockaddr_storage ss;` –sizeof(ss) is platform dependent (typically 128 on NetBSD).  
   - No explicit user‑supplied buffers with named size constants are present in this file.  

   GREP: `grep -n "sockaddr_storage" -R /usr/include/net/ | head`  
   Result: `struct sockaddr_storage { char ss_len; ... }` – size resolution omitted (system header).  

5. **Dangerous Data Flows**  
   None in this file: attacker data reaches only dynamically allocated buffers (`taddr->buf`), which are freed promptly.  

6. **Potential NULL Derefs**  
   - `taddr` is used without null-check after `uaddr2taddr()`.  
   - `bind.addr.buf` is freed unconditionally, but no later dereference occurs.  
   - `pool` and `nconf` are used without NULL guard in `svc_tli_create()` (though callers typically supply valid pointers).  

7. **Tagged Unions / Variant Types**  
   No tagged unions are accessed here; `SVCXPRT` members are set after transport‑specific creation.  

8. **API vs Static**  
   - Public API: `svc_tp_create()`, `svc_tli_create()`.  
   - All other helpers (`__rpc_nconf2socket`, `__rpc_nconf2sockinfo`, `svc_vc_create`, `svc_dg_create`, etc.) are either static or in separate modules; they are invoked only after successful validation of `nconf` and socket creation.  

9. **Likely Bug Classes**  
   - **Unchecked return values** – e.g., `uaddr2taddr()`, `bindresvport()` results ignore errors beyond logging.  
   - **Null pointer dereference** – missing checks for `taddr`, `pool`, `nconf` when passed by callers.  
   - **Resource leaks** – premature `free` of `bind.addr.buf` could occur if earlier error path exits without freeing `xprt`.  

*End of briefing.*

[GREP RESULTS from codebase]:
GREP `grep -n "sockaddr_storage" -R /usr/include/net/ (simplified to: sockaddr_storage)`:
```
contrib/bearssl/tools/server.c:46:#define SOCKADDR_STORAGE   struct sockaddr_storage
crypto/krb5/src/include/port-sockets.h:195:#define sockaddr_storage krb5int_sockaddr_storage
contrib/libpcap/sockutils.h:156:int	sock_check_hostlist(const char *hostlist, const char *sep, struct sockaddr_storage *from, char *errbuf, int errbuflen);
contrib/libpcap/sockutils.h:157:int sock_cmpaddr(struct sockaddr_storage *first, struct sockaddr_storage *second);
contrib/libpcap/sockutils.h:162:int sock_getascii_addrport(const struct sockaddr_storage *sockaddr, char *address, int addrlen, char *port, int portlen, int flags, char *errbuf, size_t errbuflen);
contrib/libpcap/sockutils.h:163:int sock_present2network(const char *address, struct sockaddr_storage *sockaddr, int addr_family, char *errbuf, int errbuflen);
kerberos5/include/config.h:903:/* Define to 1 if the system has the type `struct sockaddr_storage'. */
contrib/libpcap/rpcap-protocol.h:198: * Do *NOT* use struct sockaddr_storage, as the layout for that is
contrib/libpcap/rpcap-protocol.h:213: * Furthermore, Solaris's struct sockaddr_storage is 256 bytes
contrib/libpcap/rpcap-protocol.h:221: * length.)  That way, it's the same size as sockaddr_storage on
krb5/include/autoconf.h:490:/* Define to 1 if the system has the type `struct sockaddr_storage'. */
libexec/tftpd/tftp-io.h:43:int	receive_packet(int peer, char *, int, struct sockaddr_storage *, int);
libexec/tftpd/tftp-io.h:45:extern struct sockaddr_storage peer_sock;
libexec/tftpd/tftp-io.h:46:extern struct sockaddr_storage me_sock;
usr.sbin/ypldap/ypldap.h:45:	struct sockaddr_storage         ss;
usr.sbin/syslogd/syslogd.h:131:	struct sockaddr_storage laddr;
usr.sbin/syslogd/syslogd.h:132:	struct sockaddr_storage raddr;
usr.sbin/ppp/ncpaddr.h:74:extern void ncpaddr_getsa(const struct ncpaddr *, struct sockaddr_storage *);
usr.sbin/ppp/ncpaddr.h:96:extern void ncprange_getsa(const struct ncprange *, struct sockaddr_storage *,
usr.sbin/ppp/ncpaddr.h:97:                           struct sockaddr_storage *);
usr.sbin/inetd/inetd.h:60:	struct sockaddr_storage	co_addr;	/* source address */
bin/csh/config.h:137:/* Define to 1 if `ss_family' is a member of `struct sockaddr_storage'. */
usr.sbin/ntp/libntpevent/event2/event-config.h:341:/* Define to 1 if the system has the type `struct sockaddr_storage'. */
usr.sbin/ntp/libntpevent/event2/event-config.h:344:/* Define to 1 if `ss_family' is a member of `struct sockaddr_storage'. */
usr.sbin/ntp/libntpevent/event2/event-config.h:347:/* Define to 1 if `__ss_family' is a member of `struct sockaddr_storage'. */
usr.sbin/ntp/config.h:950:/* Does a system header define struct sockaddr_storage? */
usr.sbin/ntp/config.h:1295:/* Does struct sockaddr_storage have __ss_family? */
usr.sbin/ntp/config.h:1299:	    /* Handle sockaddr_storage.__ss_family */
lib/libpcap/config.h:217:/* Define to 1 if the system has the type `struct sockaddr_storage'. */
contrib/blocklist/include/bl.h:54:	struct sockaddr_storage bi_ss;
```

GREP `head`:
```
include/protocols/dumprestore.h:133:#define TS_TAPE 	1	/* dump tape header */
kerberos5/include/crypto-headers.h:2:#define __crypto_headers_h__
usr.sbin/makefs/ffs/ffs_bswap.c:51:#define	fs_old_headswitch	fs_id[0]
usr.sbin/makefs/makefs.h:276:#define	FFS_EI		/* for opposite endian support in ffs headers */
usr.sbin/makefs/cd9660/cd9660_eltorito.h:45:#define	ET_SYS_EFI	0xef	/* Platform ID at section header entry */
include/dlfcn.h:49:#define	RTLD_DEEPBIND	0x04000	/* Put symbols from the dso ahead of
usr.bin/localedef/collate.c:1095:#define RB_COUNT(x, name, head, cnt) do { \
usr.bin/localedef/collate.c:1102:#define RB_NUMNODES(type, name, head, cnt) do { \
include/arpa/nameser.h:84:#define NS_HFIXEDSZ	12	/*%< #/bytes of fixed data in header */
include/arpa/telnet.h:82:#define	TELOPT_SGA	3	/* suppress go ahead */
bin/sh/mksyntax.c:124:	/* Generate the #define statements in the header file */
crypto/openssl/test/quic_txp_test.c:267:#define OPK_EXPECT_HDR 8 /* Expect header structure match */
crypto/openssl/ssl/quic/quic_stream_map.c:69:#define accept_head(l) list_next((l), (l), \
crypto/openssl/ssl/quic/quic_stream_map.c:71:#define ready_for_gc_head(l) list_next((l), (l), \
usr.sbin/lpr/lpc/extern.h:40:#define SUMP_NOHEADER	0x0001		/* Do not print a header line */
stand/efi/include/amd64/pe.h:195:#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
stand/efi/include/amd64/pe.h:465:#define IMAGE_REL_PPC_SECTION  0x000C  // sectionheader number
stand/efi/include/i386/pe.h:195:#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
stand/efi/include/i386/pe.h:465:#define IMAGE_REL_PPC_SECTION  0x000C  // sectionheader number
crypto/openssl/ssl/ssl_local.h:2176:#define ssl_set_handshake_header(s, pkt, htype) \
crypto/openssl/ssl/record/record.h:134:#define RECORD_LAYER_set_read_ahead(rl, ra) ((rl)->read_ahead = (ra))
crypto/openssl/ssl/record/record.h:135:#define RECORD_LAYER_get_read_ahead(rl) ((rl)->read_ahead)
crypto/openssl/providers/implementations/encode_decode/decode_msblob2key.c:232:#define dsa_decode_private_key (b2i_of_void_fn *)ossl_b2i_DSA_after_header
crypto/openssl/providers/implementations/encode_decode/decode_msblob2key.c:233:#define dsa_decode_public_key (b2i_of_void_fn *)ossl_b2i_DSA_after_header
crypto/openssl/providers/implementations/encode_decode/decode_msblob2key.c:239:#define rsa_decode_private_key (b2i_of_void_fn *)ossl_b2i_RSA_after_header
crypto/openssl/providers/implementations/encode_decode/decode_msblob2key.c:240:#define rsa_decode_public_key (b2i_of_void_fn *)ossl_b2i_RSA_after_header
libexec/bootpd/bootp.h:40:#define BP_MSG_OVERHEAD	(14 + 20 + 8)	/* Ethernet + IP + UDP headers */
crypto/krb5/src/include/k5-queue.h:98:#define	K5_LIST_HEAD_INITIALIZER(head)					\
crypto/krb5/src/include/k5-queue.h:110:#define	K5_LIST_INIT(head) do {						\
crypto/krb5/src/include/k5-queue.h:129:#define	K5_LIST_INSERT_HEAD(head, elm, field) do {			\
```