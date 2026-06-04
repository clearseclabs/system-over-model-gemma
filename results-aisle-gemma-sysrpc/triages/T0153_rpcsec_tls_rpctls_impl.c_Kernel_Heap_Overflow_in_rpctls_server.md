# Triage T0153: Kernel Heap Overflow in rpctls_server

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV]

---

## Finding

Kernel Heap Overflow in rpctls_server

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The kernel performs `mem_alloc(*ngrps * sizeof(gid_t))` and a subsequent copy loop based on `*ngrps` without verifying that `*ngrps` is within reasonable bounds or checking for integer overflow, where `*ngrps` is provided by the userspace `rpctlssd` daemon.

The vulnerability report identifies a potential integer overflow in `rpctls_server` when calculating the allocation size: `*ngrps * sizeof(gid_t)`, where `*ngrps` comes from `res.gid.gid_len` (returned by the `rpctlssd` userspace daemon). If `*ngrps` is large enough, the multiplication can overflow, leading to an undersized buffer allocation and a subsequent heap overflow in the loop `for (i = 0; i < *ngrps; i++) *gidp++ = *gidv++;`. 

Tracing the data flow: `_svcauth_rpcsec_tls` (triggered by an external network request) calls `rpctls_server`. `rpctls_server` calls `rpctlssd_connect_2`, which performs an RPC call to the `rpctlssd` daemon. The `res` structure contains data returned by this daemon. While the daemon is technically a local process, the kernel must treat its responses as untrusted if it is possible for an attacker to compromise the daemon or if the daemon itself forwards attacker-controlled data from the TLS handshake. More importantly, in a security analysis of a kernel, we must assume any value coming from userspace (even a helper daemon) is untrusted unless there is a hard check in the kernel. 

There are no checks on `res.gid.gid_len` (stored in `*ngrps`) before the multiplication or the allocation. A value of `ngrps` such as `(SIZE_MAX / sizeof(gid_t)) + 1` would cause an overflow. Given that `gid_t` is typically 4 or 8 bytes, this is easily reachable if the daemon is compromised or malicious. The kernel blindly trusts the length reported by the daemon and uses it to drive a loop that writes to the heap.

CRUX: The kernel performs `mem_alloc(*ngrps * sizeof(gid_t))` and a subsequent copy loop based on `*ngrps` without verifying that `*ngrps` is within reasonable bounds or checking for integer overflow, where `*ngrps` is provided by the userspace `rpctlssd` daemon.
GREP: sizeof(gid_t)

🔎 **Grep results:**

GREP `sizeof(gid_t)`:
```
sys/sys/socket.h:540:	(sizeof(struct sockcred) + (sizeof(gid_t) * ((ngrps) - 1)))
sys/sys/socket.h:556:	(sizeof(struct sockcred2) + (sizeof(gid_t) * ((ngrps) - 1)))
include/ssp/unistd.h:54:	return (ptrsize / sizeof(gid_t));
contrib/lib9p/backend/fs.c:937:	ai = malloc(sizeof(*ai) + (size_t)ngroups * sizeof(gid_t));
contrib/lib9p/backend/fs.c:952:	memcpy(ai->ai_gids, gids, (size_t)ngroups * sizeof(gid_t));
lib/libkvm/kvm_proc.c:161:			    (kp->ki_ngroups - 1) * sizeof(gid_t));
sys/fs/nfs/nfs_commonsubs.c:4460:			grps = malloc(sizeof(gid_t) * nidp->nid_ngroup, M_TEMP,
sys/fs/nfs/nfs_commonsubs.c:4463:			    sizeof(gid_t) * nidp->nid_ngroup);
sys/fs/nfsserver/nfs_nfsdport.c:4288:				    sizeof(gid_t), M_TEMP, M_WAITOK);
sys/fs/nfsserver/nfs_nfsdport.c:4290:				    export.export.ex_ngroups * sizeof(gid_t));
sys/fs/nfsserver/nfs_nfsdport.c:4315:				    export.export.ex_ngroups * sizeof(gid_t),
sys/rpc/rpcsec_tls/rpctls_impl.c:405:			*gids = gidp = mem_alloc(*ngrps * sizeof(gid_t));
lib/libpam/modules/pam_login_access/login_access.c:193:    if ((grouplist = calloc(ngroups, sizeof(gid_t))) == NULL) {
sys/kern/imgact_elf.c:2614:	    (1 + p->p_ucred->cr_ngroups) * sizeof(gid_t);
sys/kern/imgact_elf.c:2617:		structsize = sizeof(gid_t);
sys/kern/imgact_elf.c:2619:		sbuf_bcat(sb, &p->p_ucred->cr_gid, sizeof(gid_t));
sys/kern/imgact_elf.c:2621:		    sizeof(gid_t));
sys/kern/kern_proc.c:1120:		    (kp->ki_ngroups - 1) * sizeof(gid_t));
sys/kern/kern_proc.c:2950:	error = SYSCTL_OUT(req, &cred->cr_gid, sizeof(gid_t));
sys/kern/kern_proc.c:2953:		    cred->cr_ngroups * sizeof(gid_t));
sys/kern/kern_prot.c:329:	error = copyout(&cred->cr_gid, uap->gidset, sizeof(gid_t));
sys/kern/kern_prot.c:332:		    (ngrp - 1) * sizeof(gid_t));
sys/kern/kern_prot.c:363:	error = copyout(cred->cr_groups, uap->gidset, ngrp * sizeof(gid_t));
sys/kern/kern_prot.c:559:	    smallgroups : malloc(wcred->sc_supp_groups_nb * sizeof(gid_t),
sys/kern/kern_prot.c:562:	    wcred->sc_supp_groups_nb * sizeof(gid_t));
sys/kern/kern_prot.c:1218:		groups = malloc(gidsetsize * sizeof(gid_t), M_TEMP, M_WAITOK);
sys/kern/kern_prot.c:1222:	error = copyin(uap->gidset, groups, gidsetsize * sizeof(gid_t));
sys/kern/kern_prot.c:1265:		groups = malloc(gidsetsize * sizeof(gid_t), M_TEMP, M_WAITOK);
sys/kern/kern_prot.c:1269:	error = copyin(uap->gidset, groups, gidsetsize * sizeof(gid_t));
sys/kern/kern_prot.c:2894:	nbytes = n * sizeof(gid_t);
```

### Round 2: ✅ VALID

**🎯 Crux:** The kernel performs an unchecked multiplication `*ngrps * sizeof(gid_t)` using a value from a userspace RPC response, leading to a potential integer overflow and subsequent heap buffer overflow.

The vulnerability exists in `rpctls_server` where `res.gid.gid_len` (an integer from an RPC response) is used to calculate an allocation size: `mem_alloc(*ngrps * sizeof(gid_t))`. There is no check on `*ngrps` before this multiplication, making it susceptible to an integer overflow. If `*ngrps` is large enough, `mem_alloc` will allocate a small buffer, and the subsequent loop `for (i = 0; i < *ngrps; i++) *gidp++ = *gidv++;` will write `*ngrps` elements into that buffer, causing a heap overflow. The input originates from the `rpctlssd` daemon via the `rpctlssd_connect_2` RPC call. While the daemon is a local process, the kernel is acting as a client to this daemon; if the daemon is compromised or if it transmits data derived from the TLS handshake (which is triggered by an external network request to `_svcauth_rpcsec_tls`), the attacker can control these values. Even if the daemon is considered 'trusted', kernel-to-userspace boundaries require rigorous validation to prevent a compromised userspace process from escalating privileges in the kernel. There are no guards (like `MAX_GROUPS`) seen in the provided code or common in this path to prevent this.

CRUX: The kernel performs an unchecked multiplication `*ngrps * sizeof(gid_t)` using a value from a userspace RPC response, leading to a potential integer overflow and subsequent heap buffer overflow.
GREP: gid_t

🔎 **Grep results:**

GREP `gid_t`:
```
contrib/sendmail/include/sm/mbdb.h:25:#define SM_NO_GID	((gid_t)(-1))
contrib/sqlite3/sqlite3.c:39373:#define osFchown    ((int(*)(int,uid_t,gid_t))aSyscall[20].pCurrent)
usr.sbin/pwd_mkdb/bootstrap/pwd.h:57:#define	gid_t	_bootstrap_gid_t
krb5/include/autoconf.h:60:#define GETGROUPS_T gid_t
sys/fs/nfs/nfsdport.h:41:#define	NFSVNO_NOTSETGID(n)		((n)->na_gid == ((gid_t)VNOVAL))
sys/fs/nfs/nfsdport.h:42:#define	NFSVNO_ISSETGID(n)		((n)->na_gid != ((gid_t)VNOVAL))
sys/sys/limits.h:103:#define	GID_MAX		UINT_MAX	/* max value for a gid_t */
sys/netsmb/smb_conn.h:64:#define	SMBM_ANY_GROUP		((gid_t)-1)
sys/contrib/openzfs/lib/libzfs/libzfs_status.c:98:#define	NMSGID	(sizeof (zfs_msgid_table) / sizeof (zfs_msgid_table[0]))
tools/build/cross-build/include/linux/limits.h:67:#define GID_MAX ((gid_t)-1)
tools/regression/security/access/testaccess.c:57:#define	WHEEL_GID	(gid_t)0
tools/regression/security/access/testaccess.c:59:#define	TEST_GID_ONE	(gid_t)500
tools/regression/security/access/testaccess.c:61:#define	TEST_GID_TWO	(gid_t)501
bin/csh/config.h:6:#define GETGROUPS_T gid_t
libexec/mknetid/hash.h:37:	gid_t groupid;
contrib/sendmail/src/sendmail.h:385:	gid_t		q_gid;		/* group-id of receiver (if known) */
contrib/sendmail/src/sendmail.h:597:	gid_t	m_gid;		/* GID to run as */
contrib/sendmail/src/sendmail.h:2645:EXTERN gid_t	DefGid;		/* default gid to run as */
contrib/sendmail/src/sendmail.h:2646:EXTERN gid_t	RealGid;	/* real gid of caller */
contrib/sendmail/src/sendmail.h:2647:EXTERN gid_t	RunAsGid;	/* GID to become for bulk of run */
contrib/sendmail/src/sendmail.h:2648:EXTERN gid_t	EffGid;		/* effective gid */
contrib/sendmail/include/sm/shm.h:31:extern int sm_shmsetowner __P((int, uid_t, gid_t, MODE_T));
contrib/sendmail/include/sm/types.h:40:#  define gid_t		int
contrib/sendmail/include/sm/mbdb.h:30:	gid_t	mbdb_gid;
contrib/sendmail/include/sm/config.h:74:**  Does <sys/types.h> define uid_t and gid_t?
contrib/sendmail/include/sm/sem.h:50:extern int sm_semsetowner __P((int, uid_t, gid_t, MODE_T));
contrib/sendmail/include/libsmdb/smdb.h:159:typedef int (*db_set_owner_func) __P((SMDB_DATABASE *db, uid_t uid, gid_t gid));
contrib/sendmail/include/libsmdb/smdb.h:295:	gid_t	smdbu_group_id;
contrib/sendmail/include/sm/conf.h:100:#  define GIDSET_T	gid_t
contrib/sendmail/include/sm/conf.h:218:#  define GIDSET_T	gid_t
```

### Round 3: ✅ VALID

**🎯 Crux:** The kernel performs an unchecked multiplication `*ngrps * sizeof(gid_t)` using `*ngrps` from a userspace RPC response and subsequently uses the same potentially overflowing `*ngrps` as a loop limit for memory writes.

The bug pattern is real: `rpctls_server` uses `res.gid.gid_len` (provided by the userspace `rpctlssd` daemon) to calculate an allocation size `*ngrps * sizeof(gid_t)` and then uses `*ngrps` as the loop limit for copying data into that buffer. If `*ngrps` is large enough to cause an integer overflow during the multiplication, `mem_alloc` will allocate a buffer smaller than required, leading to a kernel heap overflow. The input is attacker-reachable because `_svcauth_rpcsec_tls` is triggered by any external network request (NULL RPC with AUTH_TLS). While the value comes from the `rpctlssd` daemon, kernel security best practices mandate that data crossing the kernel-userspace boundary be treated as untrusted. A compromised or malicious daemon, or one that forwards data from a malicious TLS handshake, could trigger this. There are no bounds checks on `res.gid.gid_len` in the provided code.

CRUX: The kernel performs an unchecked multiplication `*ngrps * sizeof(gid_t)` using `*ngrps` from a userspace RPC response and subsequently uses the same potentially overflowing `*ngrps` as a loop limit for memory writes.
GREP: gid_t

🔎 **Grep results:**

GREP `gid_t`:
```
sys/fs/nfs/nfsdport.h:41:#define	NFSVNO_NOTSETGID(n)		((n)->na_gid == ((gid_t)VNOVAL))
sys/fs/nfs/nfsdport.h:42:#define	NFSVNO_ISSETGID(n)		((n)->na_gid != ((gid_t)VNOVAL))
contrib/sendmail/include/sm/mbdb.h:25:#define SM_NO_GID	((gid_t)(-1))
contrib/sqlite3/sqlite3.c:39373:#define osFchown    ((int(*)(int,uid_t,gid_t))aSyscall[20].pCurrent)
usr.sbin/pwd_mkdb/bootstrap/pwd.h:57:#define	gid_t	_bootstrap_gid_t
sys/sys/limits.h:103:#define	GID_MAX		UINT_MAX	/* max value for a gid_t */
sys/contrib/openzfs/lib/libzfs/libzfs_status.c:98:#define	NMSGID	(sizeof (zfs_msgid_table) / sizeof (zfs_msgid_table[0]))
sys/netsmb/smb_conn.h:64:#define	SMBM_ANY_GROUP		((gid_t)-1)
krb5/include/autoconf.h:60:#define GETGROUPS_T gid_t
tools/regression/security/access/testaccess.c:57:#define	WHEEL_GID	(gid_t)0
tools/regression/security/access/testaccess.c:59:#define	TEST_GID_ONE	(gid_t)500
tools/regression/security/access/testaccess.c:61:#define	TEST_GID_TWO	(gid_t)501
tools/build/cross-build/include/linux/limits.h:67:#define GID_MAX ((gid_t)-1)
bin/csh/config.h:6:#define GETGROUPS_T gid_t
usr.sbin/cron/cron/structs.h:25:	gid_t		gid;
sys/fs/p9fs/p9_client.h:154:int p9_create_symlink(struct p9_fid *fid, char *name, char *symtgt, gid_t gid);
sys/fs/p9fs/p9fs.h:64:	gid_t n_gid;            /* 9p2000.u extensions */
sys/fs/p9fs/p9_protocol.h:197:	gid_t n_gid;		/* 9p2000.u extensions */
sys/fs/p9fs/p9_protocol.h:207:	gid_t st_gid;		/* group ID of owner */
sys/fs/p9fs/p9_protocol.h:230:	gid_t gid;		/* group id */
sys/fs/tarfs/tarfs.h:69:	gid_t			 gid;
sys/fs/tarfs/tarfs.h:230:	    time_t mtime, uid_t uid, gid_t gid, mode_t mode,
sys/fs/smbfs/smbfs.h:53:	gid_t 		gid;
sys/fs/smbfs/smbfs.h:72:	gid_t 			sm_gid;
sys/fs/tmpfs/tmpfs.h:211:	gid_t			tn_gid;		/* (v) */
sys/fs/tmpfs/tmpfs.h:468:	    uid_t uid, gid_t gid, mode_t mode, struct tmpfs_node *,
sys/fs/tmpfs/tmpfs.h:500:int	tmpfs_chown(struct vnode *, uid_t, gid_t, struct ucred *,
sys/fs/msdosfs/msdosfsmount.h:82:	gid_t pm_gid;		/* gid to set as owner of the files */
sys/fs/msdosfs/msdosfsmount.h:258:	gid_t	gid;		/* gid that owns msdosfs files */
sys/fs/unionfs/union.h:64:	gid_t		um_gid;
```

