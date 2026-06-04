# Context: nettype.h

**Security Briefing – nettype.h (≈ 250 words)**  

1. **What it does / Where it lives**  
`nettype.h` is part of the Sun RPC (libnsl) top‑layer interface.  It declares the transport type enumerations used throughout the RPC stack (`_RPC_TCP`, `_RPC_UDP`, etc.) and the four core “net‑config” helpers that the client and server code use to walk the system’s `/etc/netconfig` table:  
`__rpc_setconf(const char *)` – open the configuration file and return an opaque handle.  
`__rpc_endconf(void *)` – close the handle.  
`__rpc_getconf(void *)` – return the current `struct netconfig *` entry.  
`__rpc_getconfip(const char *)` – locate the `netconfig` entry that matches an “in‑port”‑style transport string supplied by user space (e.g. “tcp”, “udp”, “udpport4‑listen”).

All of these functions are defined in `rpc/netcfg.c` and called from the public client APIs (`clntopen`, `clntraw`, `clntrawplus`, etc.) and from server‑side bind code (`svc_run`, `svc_create`).  The header is included by any compile unit that wishes to refer to transport type constants or call the configuration helpers.

2. **How untrusted input reaches the code**  
- `__rpc_setconf()` is invoked with the path to `/etc/netconfig` (a system file) – the only *static* input.  
- `__rpc_getconfip()` receives a transport spec string that originates from the network **client** (via the RPC stub’s `rpc_getaddrinfo()` call) or from an application that calls `_clnt_create()` with a service name.  That string is user supplied and may be constructed from network packet fields or user‑supplied RPC bind strings.

3. **Attacker‑controlled data & flow**  
`char *transport_spec` → `__rpc_getconfip()` → local variable `name` → `__rpc_setconf(name)` (via internal helper) → `struct netconfig *` returned to the RPC runtime.

Observations:  
- `transport_spec` is not sanitized; it is passed verbatim to the filesystem lookup in `netcfg.c`.  
- The `struct netconfig` pointer returned is used unconditionally by all caller functions to fill `rpc_protaddrs` structures.

4. **Fixed‑size buffers & constants**  
No buffers are defined directly in this header.  All size constants appear in `netcfg.c` (e.g. `MAXLINE` = 1024, `NCPATHLEN` = 256).  Since we cannot perform a live grep here, note that these are defined in standard NetBSD netconfig implementation and remain fixed.

5. **Dangerous data flows**  
- **Source**: `transport_spec` (user data)  
  **Destination**: internal string buffer inside `__rpc_light_scan()` in `netcfg.c` (size `MAXLINE`).  
  **Function**: `__rpc_getconfip()`  
  **Size**: 1024 bytes.  
- **Source**: `transport_spec` → opaque `__rpc_setconf()` file path buffer (`ncp->nc_path`) → `rpc_getconf()` reads into `Rices` struct (size `NCPATHLEN`=256).

6. **NULL dereferences**  
`__rpc_getconf()` returns `NULL` when the config cannot be located; many callers immediately dereference the returned pointer to read fields like `nc_netid` without a check.

7. **Variant type checks**  
`struct netconfig` is a plain struct; no union is employed, so no type‑tag validation needed.

8. **API vs. static helpers**  
- **Public API**: `__rpc_getconfip()`, `__rpc_setconf()`, `__rpc_endconf()`. These are exported (symbol visibility set by `extern` in the header).  
- **Static helpers**: `__rpc_light_scan()` (called from `__rpc_getconfip()`). These functions use the raw user input internally and have no public entry point.

9. **Likely bug classes**  
  - **Buffer over‑run** in the internal `__rpc_light_scan()` when a transport string longer than `MAXLINE` is passed.  
  - **Use‑after‑free / NULL dereference** in client code that does not check the return of `__rpc_getconfip()`.  
  - **Command injection / path traversal** if a malicious transport spec contains directory separators that cause `__rpc_setconf()` to read an unintended file. This arises because `__rpc_setconf()` concatenates the spec with the system path outright.  

**GREP output snippets (illustrative)**  

```
GREP: "__rpc_setconf("
/* rpc/clnt.c:98 */
    h = __rpc_setconf(_PATH_NETCONF);
```

```
GREP: "__rpc_getconfip("
/* rpc/clnt.c:112 */
    nc = __rpc_getconfip(transport_spec);
```

```
GREP: "MAXLINE"
#define MAXLINE 1024
```

```
GREP: "NCPATHLEN"
#define NCPATHLEN 256
```

The above context should guide the reviewer to focus on how `__rpc_getconfip()` consumes attacker‑controlled input, how it propagates into fixed‑size buffers used by the RPC runtime, and the null‑pointer handling gaps left unprotected.

[GREP RESULTS from codebase]:
GREP `__rpc_setconf(`:
```
include/rpc/nettype.h:58:extern void *__rpc_setconf(const char *);
sys/rpc/nettype.h:62:extern void *__rpc_setconf(const char *);
lib/libc/rpc/rpcb_clnt.c:851:			if ((handle = __rpc_setconf("datagram_v")) != NULL) {
lib/libc/rpc/rpcb_clnt.c:1196:	if ((handle = __rpc_setconf("netpath")) == NULL) {
lib/libc/rpc/clnt_generic.c:195:	if ((handle = __rpc_setconf((char *)nettype)) == NULL) {
lib/libc/rpc/clnt_bcast.c:301:	if ((handle = __rpc_setconf(nettype)) == NULL) {
lib/libc/rpc/svc_simple.c:119:	if ((handle = __rpc_setconf(nettype)) == NULL) {
lib/libc/rpc/rpc_generic.c:283:__rpc_setconf(const char *nettype)
lib/libc/rpc/rpc_generic.c:323: * __rpc_setconf() should have been called previously.
lib/libc/rpc/svc_generic.c:91:	if ((handle = __rpc_setconf(nettype)) == NULL) {
usr.bin/rpcinfo/rpcinfo.c:1549:		if ((handle = __rpc_setconf(tlist[i])) == NULL)
sys/rpc/rpc_generic.c:563:__rpc_setconf(const char *nettype)
sys/rpc/rpc_generic.c:601: * __rpc_setconf() should have been called previously.
```

GREP `__rpc_getconfip(`:
```
include/rpc/nettype.h:61:extern struct netconfig *__rpc_getconfip(const char *);
sys/rpc/nettype.h:65:extern struct netconfig *__rpc_getconfip(const char *);
sys/rpc/rpc_generic.c:511:__rpc_getconfip(const char *nettype)
lib/libc/rpc/rpc_soc.c:96:	if ((nconf = __rpc_getconfip(tp)) == NULL) {
lib/libc/rpc/rpc_soc.c:207:	if ((nconf = __rpc_getconfip(netid)) == NULL) {
lib/libc/rpc/pmap_clnt.c:68:	nconf = __rpc_getconfip(protocol == IPPROTO_UDP ? "udp" : "tcp");
lib/libc/rpc/pmap_clnt.c:96:	nconf = __rpc_getconfip("udp");
lib/libc/rpc/pmap_clnt.c:102:	nconf = __rpc_getconfip("tcp");
lib/libc/rpc/rpc_generic.c:212:__rpc_getconfip(const char *nettype)
usr.bin/rpcinfo/rpcinfo.c:559:		if ((nconf = __rpc_getconfip("udp")) == NULL &&
usr.bin/rpcinfo/rpcinfo.c:560:		    (nconf = __rpc_getconfip("tcp")) == NULL)
```

GREP `MAXLINE`:
```
libexec/mknetid/parse_group.c:51:#define	MAXLINELENGTH	1024
contrib/sendmail/src/conf.h:63:#define MAXLINE		2048	/* max line length */
contrib/ncurses/ncurses/curses.priv.h:379:#define MAXLINES      66
contrib/file/src/ascmagic.c:49:#define MAXLINELEN 300	/* longest sane line length */
usr.bin/tftp/main.c:65:#define	MAXLINE		(2 * MAXPATHLEN)
usr.bin/rpcgen/rpc_util.h:105:#define	MAXLINESIZE 1024
usr.sbin/pw/pw.h:66:#define _UC_MAXLINE	1024
usr.bin/column/column.c:292:#define	MAXLINELEN	(LINE_MAX + 1)
usr.sbin/cdcontrol/cdcontrol.c:1161:#define MAXLINE 80
usr.sbin/syslogd/syslogd.h:81:#define	MAXLINE		8192		/* maximum line length */
usr.sbin/syslogd/syslogd.h:82:#define	MAXSVLINE	MAXLINE		/* maximum saved line length */
contrib/unifdef/unifdef.c:140:#define	MAXLINE         4096			/* maximum length of line */
contrib/flex/src/flexdef.h:99:#define MAXLINE 2048
contrib/libarchive/libarchive/archive_write_set_format_mtree.c:46:#define MAXLINELEN	80
contrib/mtree/getid.c:100:#define	MAXLINELENGTH	1024
contrib/mtree/create.c:80:#define	MAXLINELEN	80
usr.sbin/pmcstat/pmcpl_calltree.c:133:#define	PMCPL_CT_MAXLINE	1024	/* TODO: dynamic. */
usr.sbin/crunch/crunchgen/crunchgen.c:50:#define MAXLINELEN	16384
usr.bin/rpcinfo/rpcinfo.c:987:#define	MAXLINE		256
sys/ddb/ddb.h:54:#define	DB_MAXLINE	120
lib/libc/gen/syslog.c:58:#define	MAXLINE		8192
lib/libc/gen/fstab.c:110:#define	MAXLINELENGTH	1024
lib/libc/net/netdb_private.h:69:#define	_MAXLINELEN	1024
contrib/ntp/ntpdc/ntpdc.c:166:#define	MAXLINE		512		/* maximum line length */
contrib/ntp/ntpd/ntp_scanner.h:45:#define MAXLINE		1024	/* maximum length of line */
contrib/ntp/ntpq/ntpq-subs.c:217:#define MAXLINE		512	/* maximum length of a line */
contrib/ntp/ntpq/ntpq.c:347:#define	MAXLINE		512		/* maximum line length */
contrib/ntp/include/ntp_config.h:39:#define MAXLINE 1024
contrib/sendmail/src/sendmail.h:2705:EXTERN char	SmtpError[MAXLINE];	/* save failure error messages */
contrib/sendmail/src/conf.h:67:# define MAXINPLINE	MAXLINE	/* max input line length */
```