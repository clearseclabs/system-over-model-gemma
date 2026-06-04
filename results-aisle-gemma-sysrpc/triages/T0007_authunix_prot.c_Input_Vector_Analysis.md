# Triage T0007: Input Vector Analysis

- **File**: `authunix_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Input Vector Analysis

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The loop writing to cred->cr_sgroups uses a ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` to strictly prevent buffer overflows, regardless of the value of supp_ngroups.

The scanner flags potential input vector issues. Looking at the loop that processes supplementary groups: `for (i = 0; i < supp_ngroups; ++i)`. The destination of the `xdr_uint32_t` call is determined by a ternary operator: `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk`. This explicitly prevents an out-of-bounds write to `cred->cr_sgroups` by redirecting any input beyond the index `XU_NGROUPS - 2` (which is the last valid index for supplementary groups if the first group is the effective GID) into a local variable `junk`. Additionally, there is an explicit check `if (xdrs->x_op != XDR_ENCODE && supp_ngroups > AUTH_SYS_MAX_GROUPS) return (FALSE);`, which further limits the loop iterations to a reasonable constant. Even if `AUTH_SYS_MAX_GROUPS` were larger than `XU_NGROUPS`, the ternary operator inside the loop provides a hard boundary. Regarding the NULL checks for `xdrs` and `cred`, these are typical for XDR dispatch functions where the XDR engine manages the context; however, the memory safety concern (the primary 'Input Vector' risk) is mitigated by the bounds check.

CRUX: The loop writing to cred->cr_sgroups uses a ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` to strictly prevent buffer overflows, regardless of the value of supp_ngroups.
GREP: XU_NGROUPS

🔎 **Grep results:**

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

### Round 2: ❌ INVALID

**🎯 Crux:** The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` ensures that writes are redirected to a local variable once the `cr_sgroups` array (size XU_NGROUPS - 1) is full, regardless of the value of `supp_ngroups`.

The scanner identifies an input vector analysis issue, specifically targeting the deserialization of supplementary groups. The code uses a `for` loop governed by `supp_ngroups`, which is provided by the untrusted network stream. To prevent a buffer overflow of `cred->cr_sgroups`, the code implements two defenses: (1) An explicit check `if (xdrs->x_op != XDR_ENCODE && supp_ngroups > AUTH_SYS_MAX_GROUPS) return (FALSE);`, and (2) A ternary operator inside the loop: `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk`. 

From the grep results, `XU_NGROUPS` is defined as 16. The `struct xucred` defines `cr_sgroups` as `gid_t cr_sgroups[XU_NGROUPS - 1]`, meaning it has 15 elements (indices 0-14). The ternary operator checks `i < 16 - 1` (i.e., `i < 15`). This means for indices 0 through 14, it writes to the array, and for index 15 and above, it writes to the local variable `junk`. This perfectly matches the array bounds. Even if `AUTH_SYS_MAX_GROUPS` were unexpectedly large or missing, the ternary operator provides a hard stop against memory corruption. The NULL dereferences mentioned in the briefing are architectural (XDR dispatch functions expect valid contexts provided by the engine) and not attacker-controllable in this context. No other dangerous data flows are present.

CRUX: The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` ensures that writes are redirected to a local variable once the `cr_sgroups` array (size XU_NGROUPS - 1) is full, regardless of the value of `supp_ngroups`.
GREP: XU_NGROUPS

🔎 **Grep results:**

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

### Round 3: ❌ INVALID

**🎯 Crux:** The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` strictly prevents out-of-bounds writes to the `cr_sgroups` array (which has size `XU_NGROUPS - 1`) by redirecting excess input to a local variable.

I have analyzed the code and the provided grep evidence. The vulnerability scanner flagged an 'Input Vector Analysis' issue, likely referring to the loop processing supplementary groups (`supp_ngroups`). The critical area is the loop: `for (i = 0; i < supp_ngroups; ++i)`. The code uses a ternary operator to determine the destination of the decoded `uint32_t`: `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk`. 

From grep results, `XU_NGROUPS` is 16. The `struct xucred` defines `cr_sgroups` as `gid_t cr_sgroups[XU_NGROUPS - 1]`, which is an array of 15 elements (indices 0-14). The condition `i < 15` ensures that indices 0 through 14 are written to the array, and any index 15 or greater is written to the local variable `junk`. This is a robust defense against buffer overflows regardless of the `supp_ngroups` value received from the network. Additionally, the code explicitly checks `if (xdrs->x_op != XDR_ENCODE && supp_ngroups > AUTH_SYS_MAX_GROUPS) return (FALSE);`, providing a second layer of defense. The NULL dereferences of `xdrs` and `cred` are typical for XDR internal dispatch functions and are not attacker-controllable.

CRUX: The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` strictly prevents out-of-bounds writes to the `cr_sgroups` array (which has size `XU_NGROUPS - 1`) by redirecting excess input to a local variable.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
sys/contrib/openzfs/include/os/freebsd/spl/sys/vfs.h:61:#define	XU_NGROUPS	16
sys/sys/ucred.h:104:#define	XU_NGROUPS	16
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

GREP `evidence.`:
```
crypto/krb5/src/plugins/audit/j_dict.h:64:#define AU_EVIDENCE_TKT       "evidence_tkt"
crypto/krb5/src/plugins/audit/j_dict.h:88:#define AU_EVIDENCE_TKT_ID "evidence_tkt_id" /* 2nd ticket in s4u2proxy req */
sys/contrib/ncsw/etc/mem.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/inc/integrations/dpaa_integration_ext.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/inc/Peripherals/bm_ext.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/inc/Peripherals/qm_ext.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/fsl_bman.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/bman_private.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/bm.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/BM/bm_ipc.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qman_low.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qm_ipc.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qman_private.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/qm.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/Peripherals/QM/fsl_qman.h:8: The copyright notice above does not evidence any actual or intended
sys/contrib/ncsw/integrations/fman_ctrl_code/p3041_r1.0.h:8: The copyright notice above does not evidence any actual or intended
usr.bin/rpcgen/rpc_parse.h:35:/*	The copyright notice above does not evidence any   	*/
usr.bin/rpcgen/rpc_util.h:35:/*	The copyright notice above does not evidence any   	*/
usr.bin/rpcgen/rpc_scan.h:35:/*	The copyright notice above does not evidence any   	*/
crypto/krb5/src/include/k5-int.h:2375:                               krb5_ticket *evidence_tkt,
crypto/krb5/src/include/krb5/audit_plugin.h:89:    /** for s4u2proxy - evidence ticket ID; for u2u - second ticket ID */
crypto/krb5/src/include/kdb.h:1423:     * the same realm and the evidence ticket is forwardable.
contrib/libpcap/pcap-linux.c:1673:	 * type require a lot more back-and-forth to debug, as evidenced
contrib/wpa/src/common/sae.c:2244:	 * the values we sent which would be evidence of a reflection attack.
contrib/sqlite3/sqlite3.c:103246:  ** This assert() provides evidence for:
contrib/libarchive/libarchive/archive_read_support_filter_xz.c:233: * they have other evidence (file name, command-line option) to go on.
sys/dev/tsec/if_tsec.c:404:	 * XXX kludge - use circumstancial evidence to program ECNTRL
sys/dev/tsec/if_tsec.c:1651:	/* XXX kludge - use circumstantial evidence for reduced mode. */
sys/dev/atkbdc/psm.c:1150:	 * doesn't show any evidence of such a command.
sys/netpfil/ipfilter/netinet/ip_state.c:3894:/* - (try to) base state transitions on real evidence only,                 */
```

### Round 4: ❌ INVALID

[ARBITER] The analysis of the code in `authunix_prot.c` confirms that there is no buffer overflow. The loop processing `supp_ngroups` uses a ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` to ensure that any value of `i` exceeding the bounds of the `cr_sgroups` array is written to a local 'junk' variable. Additionally, there is an explicit check `if (xdrs->x_op != XDR_ENCODE && supp_ngroups > AUTH_SYS_MAX_GROUPS) return (FALSE);` which limits the number of iterations. The `cr_ngroups` value is also safely capped using `MIN(supp_ngroups + 1, XU_NGROUPS)`. There is no evidence of an exploitable vulnerability.

