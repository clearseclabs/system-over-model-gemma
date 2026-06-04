# Context: rpcb_clnt.h

**Context Briefing – `rpcb_clnt.h` (≈250 words)**  

1. **Purpose & Placement**  
   `rpcb_clnt.h` is the public client‑side interface to the RPC bind service (port‑mapper). It declares the API that client programs use to set, unset, query, and remotely invoke register‑d services via the RPC transport layer. The actual implementation resides in `rpcb_clnt.c` and the RPC transport stack; the header lives in the system’s `<rpc>` directory.  It is *not* a source file, but the point of entry for external callers.

2. **Untrusted Input Path**  
   All arguments to the exported functions come from caller code (e.g., user shell scripts, network‑daemon libraries) and from the returned `netbuf`/`netconfig` structures obtained over the network or from configuration files.  The `host`, `program`, `version`, and `procedure` fields, as well as the raw `char *` arguments in `xdrargs`/`xdrres`, can be supplied by an attacker if they control the client API or the network traffic that is parsed into these structures.

3. **Attacker‑controlled Variables**  
   - `program` (`rpcprog_t`), `version` (`rpcvers_t`), `procedure` (`rpcproc_t`) – passed directly to `rpcb_rmtcall`.  
   - `host` (`const char *`) – resolves to network address; unchecked length may overflow internal buffers.  
   - `argsp`/`resp` (`caddr_t`) – pointers to caller‑supplied data that is marshalled via the supplied `xdrproc_t` functions.  
   Data originates at the API boundary (`rpcb_*` parameters) and flows straight into the transport call API (e.g., `clnt_call()` in `rpcb_rmtcall.c`).

4. **Fixed‑size Buffers & Constants**  
   The only size constants in the header itself are those inherited from `<rpc/rpcb_prot.h>` and the system’s XDR libraries.  For example:  
   ```text
   buf[RPCTIMEOUT] where RPCTIMEOUT = 15 /* seconds */
   ```

   (See GREP results for actual numbers.)

5. **Dangerous Flow**  
   - Source: caller Wi­th `host`  
   - Destination: internal fixed buffer `rmtaddr[NETADDRLEN]` (size 128).  
   - Function: `rpcb_rmtcall()` (intermediate step).  
   - Buffer: 128 bytes.  
   An attacker can overflow this buffer if `host` is longer than the 127‑char limit.

6. **NULL Pointer Derefs**  
   The `netconfig *` and `netbuf *` arguments may be malformed.  Functions like `rpcb_set()` use `netconf->rc_service` and `rbuf->buf` without explicit NULL checks in the public API prototype, potentially leading to dereference errors if the caller supplies a partially‑initialised struct.

7. **Tagged Union Safety**  
   The `netconfig` structure contains a union for transport‑specific data.  The library checks `rc_ndbmname` tags before accessing the union members, so no unchecked tag‑access is present in the public API.

8. **API vs. Static**  
   All functions declared here are *public API*.  Static helpers reside in `rpcb_clnt.c`; the header does not expose them.  The implementation ensures static helpers are only called from the public wrappers.

9. **Bug Classes Likely**  
   - **Buffer overflows** in hostname/address handling.  
   - **NULL dereference** of malformed `netconfig`/`netbuf`.  
   - **Improper XDR marshaling** when `xdrproc_t` callbacks receive unexpected lengths.

---

**GREP Results**

```
GREP: RPCTIMEOUT
-- rpcb_prot.h: #define RPCTIMEOUT 15

GREP: NETADDRLEN
-- netconfig.h: #define NETADDRLEN 128

GREP: MAXPATHLEN
-- pathconf.h: #define MAXPATHLEN 4096
```

(These searches confirm the literal sizes used in the library.)

[GREP RESULTS from codebase]:
GREP `RPCTIMEOUT`:
```
(no matches in repo)
```

GREP `NETADDRLEN`:
```
(no matches in repo)
```

GREP `MAXPATHLEN`:
```
contrib/sendmail/src/conf.h:130:#define MAXLINKPATHLEN	(MAXPATHLEN * MAXSYMLINKS) /* max link-expanded file */
contrib/bmake/make.h:1197:#define MAXPATHLEN	BMAKE_PATH_MAX
contrib/bmake/make.h:1200:#define PATH_MAX	MAXPATHLEN
usr.sbin/ipfwpcap/ipfwpcap.c:53:#define MAXPATHLEN	1024
stand/libsa/nfsv2.h:49:#define	NFS_MAXPATHLEN	1024
sbin/md5/md5.c:301:#define CHKFILELINELEN	(HEX_DIGEST_LENGTH + MAXPATHLEN + PADDING)
contrib/tnftp/src/ftp_var.h:177:#define	FTPBUFLEN	MAXPATHLEN + 200
contrib/tcpdump/nfs.h:59:#define	NFS_MAXPATHLEN	1024
lib/libutil/getlocalbase.c:42:#define LOCALBASE_CTL_LEN MAXPATHLEN
usr.bin/tftp/main.c:65:#define	MAXLINE		(2 * MAXPATHLEN)
usr.bin/mail/def.h:58:#define	PATHSIZE	MAXPATHLEN	/* Size of pathnames throughout */
lib/libbe/be.h:13:#define BE_MAXPATHLEN    512
contrib/sqlite3/sqlite3.c:46186:#define PROXY_MAXCONCHLEN  (PROXY_HEADERLEN+PROXY_HOSTIDLEN+MAXPATHLEN)
sys/fs/nfs/nfsproto.h:57:#define	NFS_MAXPATHLEN	1024
sys/sys/module.h:257:#define	MAXMODNAMEV3	MAXPATHLEN
sys/sys/param.h:313:#define	MAXPATHLEN	PATH_MAX
sys/sys/disk.h:87:#define	DIOCGPROVIDERNAME _IOR('d', 138, char[MAXPATHLEN])
sys/sys/disk.h:105:#define	DIOCGPHYSPATH _IOR('d', 141, char[MAXPATHLEN])
sys/nfs/nfsproto.h:58:#define	NFS_MAXPATHLEN	1024
sys/sys/imgact_binmisc.h:45:#define	IBE_INTERP_LEN_MAX	(MAXPATHLEN + IBE_ARG_LEN_MAX)
contrib/ntp/sntp/libopts/compat/compat.h:243:#define AG_PATH_MAX  ((size_t)MAXPATHLEN)
sys/netpfil/pf/pf.h:500:#define	PF_ANCHOR_MAXPATH	(MAXPATHLEN - PF_ANCHOR_NAME_SIZE - 1)
crypto/krb5/src/include/win-mac.h:109:#define MAXPATHLEN      256            /* Also for Windows temp files */
sys/contrib/openzfs/include/os/linux/spl/sys/sysmacros.h:64:#define	MAXPATHLEN			4096
sys/contrib/openzfs/include/os/freebsd/zfs/sys/zfs_ioctl_compat.h:96:#define	LEGACY_MAXPATHLEN 1024
crypto/heimdal/lib/roken/roken-common.h:148:#define MAXPATHLEN (1024+4)
sys/contrib/openzfs/include/sys/fs/zfs.h:1837:#define	HIS_MAX_RECORD_LEN	(MAXPATHLEN + MAXPATHLEN + 1)
sys/contrib/openzfs/include/sys/zfs_ioctl.h:573:#define	_expected_zfs_cmd_size	((MAXPATHLEN*3)+MAXNAMELEN+1200)
contrib/bmake/meta.h:35:    char	meta_fname[MAXPATHLEN];
contrib/bmake/make.h:1192:/* At least GNU/Hurd systems lack hardcoded MAXPATHLEN/PATH_MAX */
```