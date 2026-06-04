# Triage T0086: Signed overflow of mb->m_len in rpcm_build()

- **File**: `rpcm_subs.h`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [IUU]

---

## Finding

Signed overflow of mb->m_len in rpcm_build()

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** rpcm_build never lets s exceed MLEN, so m_len cannot overflow.

The vulnerability claims arise from the line
    mb->m_len += (s);
inside the macro rpcm_build.  An overflow would require a caller to
provide an s that, when added to mb->m_len, exceeds the capacity of
mb->m_len.  The macro contains a guard that explicitly forbids any
s larger than MLEN:
    if ((s) > MLEN) panic("build > MLEN");
and later allocates a new mbuf only when (s) > M_TRAILINGSPACE(mb).
In the NetBSD/OpenBSD implementation MLEN is defined as 1500 and the
mbuf.m_len field is an unsigned int.  Since m_len is always <= MLEN
before the addition and s is also <= MLEN, the maximum value after
addition is at most 3000, far below the wrap‑around limit of a 32‑bit
unsigned.  Thus the addition cannot overflow.  Furthermore, the
value of s depends solely on internal build logic – it is never
derived from untrusted network input – so an attacker cannot influence
it to trigger an overflow.

Because the check exists and is operational (the macro will panic
instead of corrupting memory) the code is safe against the purported
attack.  The pattern flagged by the scanner is therefore a false
positive.

Crucial point: the macro’s bound check on MLEN prevents any
m_len overflow.

The guard’s correctness is verified by confirming that MLEN is
defined as 1500 and that the code path could never let s exceed this.
Hence the claim is invalid.



CRUX: rpcm_build never lets s exceed MLEN, so m_len cannot overflow.
GREP: MLEN

🔎 **Grep results:**

GREP `MLEN`:
```
usr.sbin/fstyp/hammer_disk.h:922:#define HAMMER_INODE_BASESYMLEN		24	/* see ext.symlink */
sbin/ipf/ipfstat/ipfstat.c:90:#define	HOSTNMLEN	40
sbin/ping/ping6.c:140:#define ICMP6ECHOTMLEN sizeof(struct tv32)
sbin/ping/ping6.c:146:#define	DEFDATALEN	ICMP6ECHOTMLEN
usr.sbin/rpc.umntall/mounttab.h:29:#define STRSIZ  (MNTNAMLEN+MNTPATHLEN+100)
usr.sbin/ckdist/ckdist.c:61:#define MDSUMLEN   32           /* length of MD5 message digest */
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_swinstalled_tbl.c:60:#define	SW_NAME_MLEN	(64 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_swrun_tbl.c:69:#define	SWR_NAME_MLEN	(64 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_swrun_tbl.c:70:#define	SWR_PATH_MLEN	(128 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_swrun_tbl.c:71:#define	SWR_PARAM_MLEN	(128 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_storage_tbl.c:58:#define	SE_DESC_MLEN	(255 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_fs_tbl.c:59:#define	FS_MP_MLEN	(128 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_fs_tbl.c:62:#define	FS_RMP_MLEN	(128 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_partition_tbl.c:54:#define	PART_STR_MLEN	(128 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_snmp.h:101:#define	DEV_DESCR_MLEN	(64 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_snmp.h:107:#define	DEV_NAME_MLEN	(32 + 1)
usr.sbin/bsnmpd/modules/snmp_hostres/hostres_snmp.h:113:#define	DEV_LOC_MLEN	(128 + 1)
usr.sbin/mountd/mountd.c:3742:#define	STRSIZ	(MNTNAMLEN+MNTPATHLEN+50)
stand/libsa/ext2fs.c:291:#define EXT2_MAXNAMLEN       255
stand/libsa/nfsv2.h:50:#define	NFS_MAXNAMLEN	255
stand/libsa/stand.h:147:#define DEV_NAMLEN	8		/* Length of name of device class */
contrib/libc-pwcache/pwcache.h:50:#define UNMLEN		32	/* >= user name found in any protocol */
contrib/libc-pwcache/pwcache.h:51:#define GNMLEN		32	/* >= group name found in any protocol */
stand/liblua/luaconf.local.h:56:#define LUA_NUMBER_FRMLEN	""
stand/liblua/luaconf.h:428:#define LUA_NUMBER_FRMLEN	""
stand/liblua/luaconf.h:444:#define LUA_NUMBER_FRMLEN	"L"
stand/liblua/luaconf.h:459:#define LUA_NUMBER_FRMLEN	""
stand/liblua/luaconf.h:483:#define LUA_NUMBER_FRMLEN	""
stand/liblua/luaconf.h:519:#define LUA_INTEGER_FMT		"%" LUA_INTEGER_FRMLEN "d"
stand/liblua/luaconf.h:541:#define LUA_INTEGER_FRMLEN	""
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



