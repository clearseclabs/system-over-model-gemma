# Context: authunix_prot.c

**Security Briefing: `authunix_prot.c`**

**1. Function & Location**
This file implements XDR (External Data Representation) serialization and deserialization for UNIX-style authentication parameters (`AUTH_SYS`). It sits in the RPC layer, providing the translation between network wire formats and internal `xucred` structures.

**2. Untrusted Input Path**
Untrusted input reaches this code via the network. An attacker sends an RPC request; the RPC transport layer passes the payload to the XDR engine, which invokes `xdr_authunix_parms` during the decoding phase (`xdrs->x_op != XDR_ENCODE`).

**3. Attacker-Controlled Data**
Data flows from the `XDR *xdrs` stream into the following variables:
* `time` (uint32_t): Directly decoded.
* `namelen` (uint32_t): Decoded; used to skip the hostname in the stream.
* `cred->cr_uid` (uint32_t): Decoded into the credential structure.
* `cred->cr_gid` (uint32_t): Decoded into the credential structure.
* `supp_ngroups` (uint32_t): Decoded; controls the loop for supplementary groups.
* `cred->cr_sgroups[]` (uint32_t array): Decoded in a loop based on `supp_ngroups`.

**4. Fixed-Size Buffers & Constants**
* `hostbuf[MAXHOSTNAMELEN]`: GREP: `MAXHOSTNAMELEN`
* `cred->cr_sgroups` (part of `struct xucred`): GREP: `XU_NGROUPS`
* `AUTH_SYS_MAX_HOSTNAME`: GREP: `AUTH_SYS_MAX_HOSTNAME`
* `AUTH_SYS_MAX_GROUPS`: GREP: `AUTH_SYS_MAX_GROUPS`

**5. Dangerous Data Flows**
* **Source:** `supp_ngroups` (Network) $\rightarrow$ **Destination:** `cred->cr_sgroups` (Buffer).
* **Function:** `xdr_authunix_parms`.
* **Mechanism:** A `for` loop iterates `supp_ngroups` times. If `i >= XU_NGROUPS - 1`, data is diverted to `junk`, but the boundary depends on `XU_NGROUPS`.

**6. NULL Dereferences**
* `xdrs`: The `XDR` pointer is dereferenced immediately (`xdrs->x_op`).
* `cred`: The `xucred` pointer is dereferenced without a NULL check.

**7. Tagged Unions**
None present in this file.

**8. API Visibility**
* `xdr_authunix_parms`: Public API (used by the RPC XDR framework).
* No static helpers are defined in this file.

**9. Likely Bug Classes**
* **Integer Overflows:** Calculation of `supp_ngroups + 1`.
* **Off-by-one Errors:** The logic surrounding `XU_NGROUPS - 1` and `supp_ngroups` limits.
* **Logic Errors:** Discrepancies between RFC 5531 and internal `XU_NGROUPS` limits.

[GREP RESULTS from codebase]:
GREP `MAXHOSTNAMELEN`:
```
usr.sbin/cron/cron/macros.h:70:#define MAXHOSTNAMELEN 256
usr.sbin/traceroute/traceroute.c:258:#define MAXHOSTNAMELEN	64
contrib/telnet/telnet/commands.c:78:#define       MAXHOSTNAMELEN 256
contrib/tcpdump/netdissect-stdinc.h:213:#define MAXHOSTNAMELEN	64
contrib/tcp_wrappers/workarounds.c:46:#define MAXHOSTNAMELEN  256             /* storage for host name */
contrib/mtree/extern.h:59:#define MAXHOSTNAMELEN 256
lib/libunbound/config.h:1392:#define MAXHOSTNAMELEN 256
krb5/include/gssrpc/types.h:123:#define        MAXHOSTNAMELEN  64
lib/libc/rpc/clnt_simple.c:56:#define	MAXHOSTNAMELEN 64
lib/libc/rpc/netname.c:56:#define MAXHOSTNAMELEN 256
sys/sys/param.h:137:#define MAXHOSTNAMELEN	256		/* max hostname size */
libexec/rbootd/defs.h:55:#define	MAXHOSTNAMELEN 256
crypto/krb5/src/include/win-mac.h:105:#define MAXHOSTNAMELEN  512
crypto/krb5/src/appl/simple/client/sim_client.c:48:#define MAXHOSTNAMELEN 64
crypto/krb5/src/appl/simple/server/sim_server.c:53:#define MAXHOSTNAMELEN 64
crypto/krb5/src/lib/kadm5/logger.c:43:#define MAXHOSTNAMELEN  256
crypto/krb5/src/lib/krb5/os/dnsglue.h:72:#define MAXDNAME (16 * MAXHOSTNAMELEN)
crypto/krb5/src/clients/ksu/main.c:78:#define MAXHOSTNAMELEN 64
usr.sbin/pkg/dns_utils.h:39:	char host[MAXHOSTNAMELEN];
usr.sbin/cron/cron/macros.h:69:#ifndef MAXHOSTNAMELEN
usr.sbin/lpr/common_source/lp.h:166:     * likely to be much longer than MAXHOSTNAMELEN).
usr.sbin/lpr/common_source/lp.h:168:extern char	 local_host[MAXHOSTNAMELEN];
contrib/sendmail/include/sm/conf.h:2855:# if !defined(MAXHOSTNAMELEN) && !defined(_SCO_unix_) && !defined(NonStop_UX_BXX) && !defined(ALTOS_SYSTEM_V)
contrib/sendmail/include/sm/conf.h:2856:#  define MAXHOSTNAMELEN	256
contrib/sendmail/include/sm/conf.h:2860:# if defined(__linux__) && MAXHOSTNAMELEN < 255
contrib/sendmail/include/sm/conf.h:2869:#  undef MAXHOSTNAMELEN
contrib/sendmail/include/sm/conf.h:2870:#  define MAXHOSTNAMELEN	256
contrib/sendmail/include/sm/conf.h:2871:# endif /* defined(__linux__) && MAXHOSTNAMELEN < 255 */
contrib/tcsh/sh.h:431:#  undef MAXHOSTNAMELEN	/* Busted headers? */
contrib/tcsh/sh.h:526:#ifndef MAXHOSTNAMELEN
```

GREP `XU_NGROUPS`:
```
sys/sys/ucred.h:104:#define	XU_NGROUPS	16
sys/contrib/openzfs/include/os/freebsd/spl/sys/vfs.h:61:#define	XU_NGROUPS	16
sys/sys/ucred.h:128:			gid_t	cr_sgroups[XU_NGROUPS - 1];
sys/sys/ucred.h:130:		gid_t	cr_groups[XU_NGROUPS];	/* groups */
sys/fs/nfsserver/nfs_nfsdport.c:4310:			if (export.export.ex_ngroups > XU_NGROUPS ||
sys/rpc/authunix_prot.c:109:		MPASS(cred->cr_ngroups <= XU_NGROUPS);
sys/rpc/authunix_prot.c:120:	 * Because we cannot store more than XU_NGROUPS in total (16 at time of
sys/rpc/authunix_prot.c:125:	 * size limits.  Although AUTH_SYS_MAX_GROUPS and XU_NGROUPS are equal,
sys/rpc/authunix_prot.c:137:		if (!xdr_uint32_t(xdrs, i < XU_NGROUPS - 1 ?
sys/rpc/authunix_prot.c:142:		cred->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/rpc/svc_auth_unix.c:112:			if (i < XU_NGROUPS - 1)
sys/rpc/svc_auth_unix.c:117:		xcr->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/kern/vfs_mount.c:1499:				if (export.ex_ngroups <= XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:73:	if (xucred->cr_ngroups > XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:75:		    xucred->cr_ngroups, XU_NGROUPS);
```

GREP `AUTH_SYS_MAX_HOSTNAME`:
```
sys/rpc/auth.h:358:#define AUTH_SYS_MAX_HOSTNAME	255
sys/rpc/authunix_prot.c:69:		if (namelen > AUTH_SYS_MAX_HOSTNAME)
sys/rpc/authunix_prot.c:70:			namelen = AUTH_SYS_MAX_HOSTNAME;
sys/rpc/authunix_prot.c:84:		if (namelen > AUTH_SYS_MAX_HOSTNAME)
sys/rpc/svc_auth_unix.c:76:		if (str_len > AUTH_SYS_MAX_HOSTNAME)
```