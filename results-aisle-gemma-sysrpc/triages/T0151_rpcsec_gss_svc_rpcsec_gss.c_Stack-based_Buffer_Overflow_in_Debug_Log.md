# Triage T0151: Stack-based Buffer Overflow in Debug Logging

- **File**: `rpcsec_gss/svc_rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Stack-based Buffer Overflow in Debug Logging

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The vulnerable function `gss_oid_to_str` is wrapped in `#ifdef DEBUG`, meaning it is not present in production builds.

The reported bug is a stack-based buffer overflow in the `gss_oid_to_str` function, where `sprintf` is used to write into a 128-byte buffer `numstr`. However, `gss_oid_to_str` is enclosed within `#ifdef DEBUG` blocks. In production kernel builds, this code is not compiled and is therefore unreachable. Even if it were compiled, the `gss_oid_to_str` function is called within `svc_rpc_gss_accept_sec_context` only after `gss_accept_sec_context` (or its lucid variant) has successfully returned `GSS_S_COMPLETE`. The `mech` OID passed to `gss_oid_to_str` is an output of the GSS-API's `gss_accept_sec_context`, meaning it is a mechanism OID validated/provided by the GSS library, not a raw string provided by the attacker. Regardless, the primary factor is that the code is guarded by `#ifdef DEBUG`, making it a code quality issue in debug builds rather than a security vulnerability in the shipped product.

CRUX: The vulnerable function `gss_oid_to_str` is wrapped in `#ifdef DEBUG`, meaning it is not present in production builds.
GREP: grep -C 5 "gss_oid_to_str" rpcsec_gss/svc_rpcsec_gss.c

🔎 **Grep results:**

GREP `grep -C 5 "gss_oid_to_str" rpcsec_gss/svc_rpcsec_gss.c (simplified to: gss_oid_to_str)`:
```
crypto/krb5/src/lib/gssapi/generic/gssapiP_generic.h:160:generic_gss_oid_to_str(
crypto/heimdal/lib/gssapi/gssapi/gssapi.h:748:gss_oid_to_str(
include/gssapi/gssapi.h:797:OM_uint32 gss_oid_to_str
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:797:gss_oid_to_str(OM_uint32 *minor_status, gss_OID oid, gss_buffer_t oid_str)
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1143:			gss_oid_to_str(&min_stat, mech, &mechname);
lib/libgssapi/gss_display_status.c:306:		maj_junk = gss_oid_to_str(&min_junk, mech_type, &oid);
lib/libgssapi/gss_oid_to_str.c:45:gss_oid_to_str(OM_uint32 *minor_status, gss_OID oid, gss_buffer_t oid_str)
lib/librpcsec_gss/svc_rpcsec_gss.c:489:gss_oid_to_str(OM_uint32 *minor_status, gss_OID oid, gss_buffer_t oid_str)
lib/librpcsec_gss/svc_rpcsec_gss.c:731:			gss_oid_to_str(&min_stat, mech, &mechname);
crypto/krb5/src/lib/rpc/svc_auth_gss.c:259:			gss_oid_to_str(&min_stat, mech, &mechname);
crypto/krb5/src/lib/gssapi/generic/oid_ops.c:237:generic_gss_oid_to_str(OM_uint32 *minor_status,
crypto/krb5/src/lib/gssapi/generic/util_errmap.c:116:    if (generic_gss_oid_to_str(&minor, &value.mech, &str)) {
crypto/krb5/src/lib/gssapi/generic/util_errmap.c:120:    /* Note: generic_gss_oid_to_str returns a null-terminated string.  */
crypto/krb5/src/lib/gssapi/mechglue/g_oid_ops.c:87:gss_oid_to_str(OM_uint32 *minor_status, gss_OID oid, gss_buffer_t oid_str)
crypto/krb5/src/lib/gssapi/mechglue/g_oid_ops.c:101:    status = generic_gss_oid_to_str(minor_status, oid, oid_str);
crypto/krb5/src/appl/gss-sample/gss-client.c:466:        maj_stat = gss_oid_to_str(&min_stat, name_type, &oid_name);
crypto/krb5/src/appl/gss-sample/gss-client.c:483:        maj_stat = gss_oid_to_str(&min_stat, mechanism, &oid_name);
crypto/krb5/src/appl/gss-sample/gss-client.c:494:            maj_stat = gss_oid_to_str(&min_stat,
crypto/krb5/src/appl/gss-sample/gss-server.c:264:            maj_stat = gss_oid_to_str(&min_stat, doid, &oid_name);
crypto/heimdal/lib/gssapi/gsstool.c:101:	maj_stat = gss_oid_to_str(&min_stat, &mechs->elements[i], &str);
crypto/heimdal/lib/gssapi/gsstool.c:103:	    errx(1, "gss_oid_to_str failed");
crypto/heimdal/lib/gssapi/mech/gss_display_status.c:187:		maj_junk = gss_oid_to_str(&min_junk, mech_type, &oid);
crypto/heimdal/lib/gssapi/mech/gss_oid_to_str.c:37:gss_oid_to_str(OM_uint32 *minor_status, gss_OID oid, gss_buffer_t oid_str)
crypto/heimdal/lib/gssapi/test_oid.c:52:    maj_stat = gss_oid_to_str(&minor_status, GSS_KRB5_MECHANISM, &data);
crypto/heimdal/lib/gssapi/test_oid.c:54:	errx(1, "gss_oid_to_str failed");
crypto/heimdal/lib/gssapi/test_oid.c:61:    maj_stat = gss_oid_to_str(&minor_status, GSS_C_NT_EXPORT_NAME, &data);
crypto/heimdal/lib/gssapi/test_oid.c:63:	errx(1, "gss_oid_to_str failed");
```

### Round 2: ❌ INVALID

**🎯 Crux:** The vulnerable function `gss_oid_to_str` and its call site are enclosed in `#ifdef DEBUG` blocks, meaning the code is not present in production builds.

The vulnerability report identifies a potential stack overflow in `gss_oid_to_str` due to the use of `sprintf` on a fixed-size 128-byte buffer (`numstr`). Analyzing the code in `rpcsec_gss/svc_rpcsec_gss.c`, the function `gss_oid_to_str` is explicitly wrapped in `#ifdef DEBUG` (line 796) and its caller in `svc_rpc_gss_accept_sec_context` is also wrapped in `#ifdef DEBUG` (line 1140). Per the provided rules, undefined behavior or bugs that only occur in debug builds are considered code quality issues, NOT security vulnerabilities. Furthermore, the `mech` OID passed to the function is an output from the GSS-API's `gss_accept_sec_context`, meaning it is provided by the trusted security library rather than directly by the attacker, although the `#ifdef DEBUG` guard is the primary and sufficient reason for invalidation.

CRUX: The vulnerable function `gss_oid_to_str` and its call site are enclosed in `#ifdef DEBUG` blocks, meaning the code is not present in production builds.
GREP: DEBUG

🔎 **Grep results:**

GREP `DEBUG`:
```
usr.sbin/rmt/rmt.c:57:#define	DEBUG(f)	if (debug) fprintf(debug, f)
usr.sbin/rmt/rmt.c:58:#define	DEBUG1(f,a)	if (debug) fprintf(debug, f, a)
usr.sbin/rmt/rmt.c:59:#define	DEBUG2(f,a1,a2)	if (debug) fprintf(debug, f, a1, a2)
usr.sbin/makefs/makefs.h:221:#define	DEBUG_TIME			0x00000001
usr.sbin/makefs/makefs.h:223:#define	DEBUG_WALK_DIR			0x00000010
usr.sbin/makefs/makefs.h:224:#define	DEBUG_WALK_DIR_NODE		0x00000020
usr.sbin/makefs/makefs.h:225:#define	DEBUG_WALK_DIR_LINKCHECK	0x00000040
usr.sbin/makefs/makefs.h:226:#define	DEBUG_DUMP_FSNODES		0x00000080
usr.sbin/makefs/makefs.h:227:#define	DEBUG_DUMP_FSNODES_VERBOSE	0x00000100
usr.sbin/makefs/makefs.h:228:#define	DEBUG_FS_PARSE_OPTS		0x00000200
usr.sbin/makefs/makefs.h:229:#define	DEBUG_FS_MAKEFS			0x00000400
usr.sbin/makefs/makefs.h:230:#define	DEBUG_FS_VALIDATE		0x00000800
usr.sbin/makefs/makefs.h:231:#define	DEBUG_FS_CREATE_IMAGE		0x00001000
usr.sbin/makefs/makefs.h:232:#define	DEBUG_FS_SIZE_DIR		0x00002000
usr.sbin/makefs/makefs.h:233:#define	DEBUG_FS_SIZE_DIR_NODE		0x00004000
usr.sbin/makefs/makefs.h:234:#define	DEBUG_FS_SIZE_DIR_ADD_DIRENT	0x00008000
usr.sbin/makefs/makefs.h:235:#define	DEBUG_FS_POPULATE		0x00010000
usr.sbin/makefs/makefs.h:236:#define	DEBUG_FS_POPULATE_DIRBUF	0x00020000
usr.sbin/makefs/makefs.h:237:#define	DEBUG_FS_POPULATE_NODE		0x00040000
usr.sbin/makefs/makefs.h:238:#define	DEBUG_FS_WRITE_FILE		0x00080000
usr.sbin/makefs/makefs.h:239:#define	DEBUG_FS_WRITE_FILE_BLOCK	0x00100000
usr.sbin/makefs/makefs.h:240:#define	DEBUG_FS_MAKE_DIRBUF		0x00200000
usr.sbin/makefs/makefs.h:241:#define	DEBUG_FS_WRITE_INODE		0x00400000
usr.sbin/makefs/makefs.h:242:#define	DEBUG_BUF_BREAD			0x00800000
usr.sbin/makefs/makefs.h:243:#define	DEBUG_BUF_BWRITE		0x01000000
usr.sbin/makefs/makefs.h:244:#define	DEBUG_BUF_GETBLK		0x02000000
usr.sbin/makefs/makefs.h:245:#define	DEBUG_APPLY_SPECFILE		0x04000000
usr.sbin/makefs/makefs.h:246:#define	DEBUG_APPLY_SPECENTRY		0x08000000
usr.sbin/makefs/makefs.h:247:#define	DEBUG_APPLY_SPECONLY		0x10000000
usr.sbin/makefs/makefs.h:248:#define	DEBUG_MSDOSFS			0x20000000
```

### Round 3: ❌ INVALID

**🎯 Crux:** The function `gss_oid_to_str` and its call site are guarded by `#ifdef DEBUG`, meaning the code is not present in production builds.

The reported vulnerability is a stack-based buffer overflow in `gss_oid_to_str` due to the use of `sprintf` with a fixed-size 128-byte buffer (`numstr`). Reviewing the provided code for `rpcsec_gss/svc_rpcsec_gss.c`, the function `gss_oid_to_str` is entirely enclosed within an `#ifdef DEBUG` block (lines 796-923). Furthermore, the call site within `svc_rpc_gss_accept_sec_context` is also enclosed within an `#ifdef DEBUG` block (lines 1140-1153). According to the provided rules, undefined behavior or bugs that only occur in debug builds are categorized as code quality issues and are marked as INVALID. Since this code is not compiled into production builds, it is not reachable by an external attacker in a security-relevant context.

CRUX: The function `gss_oid_to_str` and its call site are guarded by `#ifdef DEBUG`, meaning the code is not present in production builds.
GREP: DEBUG

🔎 **Grep results:**

GREP `DEBUG`:
```
lib/libproc/proc_sym.c:57:#define	PATH_DEBUG_DIR	"/usr/lib/debug"
sys/arm64/coresight/coresight_etm4x.c:45:#define	ETM_DEBUG
sys/arm64/freescale/imx/imx8mp_ccm.h:227:#define IMX8MP_CLK_DEBUG_ROOT			187
sys/arm64/freescale/imx/imx8mp_ccm.h:290:#define IMX8MP_CLK_SEC_DEBUG_ROOT		238
sys/arm64/include/debug_monitor.h:30:#define	_MACHINE_DEBUG_MONITOR_H_
sys/arm64/include/vmm_dev.h:139:#define	VM_DEBUG_CPUS		2
sys/arm64/rockchip/rk3568_pcie.c:78:#define	PCIE_CLIENT_GENERAL_DEBUG_INFO	0x0104
sys/arm64/coresight/coresight_tmc.c:44:#define	TMC_DEBUG
sys/arm64/coresight/coresight_funnel.c:45:#define	FUNNEL_DEBUG
sys/arm64/spe/arm_spe_dev.h:44:#define        ARM_SPE_DEBUG
sys/fs/smbfs/smbfs_subr.h:39:#define SMBVDEBUG(format, args...) printf("%s: "format, __func__ ,## args)
sys/fs/smbfs/smbfs_subr.h:41:#define SMBVDEBUG(format, args...)
sys/fs/p9fs/p9_debug.h:28:#define FS_P9FS_P9_DEBUG_H
sys/fs/p9fs/p9_debug.h:33:#define P9_DEBUG_TRANS			0x0001	/* Trace transport */
sys/fs/p9fs/p9_debug.h:34:#define P9_DEBUG_SUBR			0x0002	/* Trace driver submissions */
sys/fs/p9fs/p9_debug.h:35:#define P9_DEBUG_LPROTO			0x0004	/* Low level protocol tracing */
sys/fs/p9fs/p9_debug.h:36:#define P9_DEBUG_PROTO			0x0008	/* High level protocol tracing */
sys/fs/p9fs/p9_debug.h:37:#define P9_DEBUG_VOPS			0x0010	/* VOPs tracing */
sys/fs/p9fs/p9_debug.h:38:#define P9_DEBUG_ERROR			0x0020	/* verbose error messages */
sys/fs/p9fs/p9_debug.h:40:#define P9_DEBUG(category, fmt, ...) do {			\
sys/fs/nfsclient/nfs.h:61:#define	NFS_DEBUG_ASYNCIO	1 /* asynchronous i/o */
sys/fs/nfsclient/nfs.h:62:#define	NFS_DEBUG_WG		2 /* server write gathering */
sys/fs/nfsclient/nfs.h:63:#define	NFS_DEBUG_RC		4 /* server request caching */
sys/fs/nullfs/null.h:100:#define NULLFSDEBUG(format, args...) printf(format ,## args)
sys/fs/nullfs/null.h:102:#define NULLFSDEBUG(format, args...)
sys/fs/tarfs/tarfs_dbg.h:39:#define	TARFS_DEBUG_ALLOC	0x01
sys/fs/tarfs/tarfs_dbg.h:40:#define	TARFS_DEBUG_CHECKSUM	0x02
sys/fs/tarfs/tarfs_dbg.h:41:#define	TARFS_DEBUG_FS		0x04
sys/fs/tarfs/tarfs_dbg.h:42:#define	TARFS_DEBUG_LOOKUP	0x08
sys/fs/tarfs/tarfs_dbg.h:43:#define	TARFS_DEBUG_VNODE	0x10
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerable function `gss_oid_to_str` (lines 796-923) and its only call site within `svc_rpc_gss_accept_sec_context` (lines 1152-1166) are both enclosed within `#ifdef DEBUG` blocks. This means the code is not compiled into production builds. According to standard vulnerability assessment practices, bugs that exist only in debug-enabled builds and are unreachable in production are not considered security vulnerabilities.

