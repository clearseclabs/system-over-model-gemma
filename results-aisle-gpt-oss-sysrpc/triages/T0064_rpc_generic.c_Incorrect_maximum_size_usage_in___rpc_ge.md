# Triage T0064: Incorrect maximum size usage in __rpc_get_t_size

- **File**: `rpc_generic.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [UUU]

---

## Finding

Incorrect maximum size usage in __rpc_get_t_size

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN

**🎯 Crux:** sb_max_adj is unsigned and cannot be set to a negative value via sysctl, thus the cast to u_int is safe and the function cannot be abused by an untrusted user.

The function __rpc_get_t_size clamps the supplied size to the value of the global variable sb_max_adj.  sb_max_adj is an unsigned 32/64‑bit integer defined in socketvar.h and can only be altered through the sysctl interface, which is restricted to privileged (root) users and treats the value as unsigned.  Therefore (1) the code pattern is present, but a negative sb_max_adj value cannot be injected by an untrusted caller because sysctl would interpret the signed literal as an unsigned value; any attempt to write –1 would become 0xffffffff, which is still a large positive number but is still an upper bound on a system‑controlled kernel parameter.  (2) At most a user with root privileges could modify sb_max_adj, and even then the value is bounded by the limits imposed by the kernel’s sysctl implementation.  (3) The lack of a signedness conflict means the cast to u_int is harmless, and the sysctl permissions act as a defense.  (4) The ultimate effect would be possible kernel memory exhaustion, but this is achievable by any privileged user regardless of this function, so it does not constitute a new security vulnerability for unprivileged attackers.  Consequently the report is a false positive or a low‑impact kernel issue that is not attacker‑reachable from user space.

To confirm this we verify that sb_max_adj is declared as an unsigned u_long and its sysctl entry is type SYSCTL_UINT, and that __rpc_get_t_size is only called internally by the RPC kernel module, not from user‑supplied input.


CRUX: sb_max_adj is unsigned and cannot be set to a negative value via sysctl, thus the cast to u_int is safe and the function cannot be abused by an untrusted user.

GREP: sb_max_adj
__rpc_get_t_size

🔎 **Grep results:**

GREP `sb_max_adj`:
```
sys/fs/nfsclient/nfs_clkrpc.c:53:extern u_long sb_max_adj;
sys/fs/nfsclient/nfs_clkrpc.c:190:	siz = sb_max_adj;
sys/fs/nfsclient/nfs_clrpcops.c:79:extern u_long sb_max_adj;
sys/fs/nfsclient/nfs_clrpcops.c:5647:	if ((nd->nd_flag & ND_NFSV42) != 0 && mds != 0 && sb_max_adj >=
sys/fs/nfsclient/nfs_clrpcops.c:5648:	    nmp->nm_wsize && sb_max_adj >= nmp->nm_rsize) {
sys/fs/nfsclient/nfs_clrpcops.c:5653:		*tl++ = txdr_unsigned(sb_max_adj - NFS_MAXXDR);
sys/fs/nfsclient/nfs_clrpcops.c:5654:		*tl++ = txdr_unsigned(sb_max_adj - NFS_MAXXDR);
sys/fs/nfs/nfs_commonkrpc.c:330:		     * adjusted for the sb_max->sb_max_adj conversion of
sys/fs/nfsserver/nfs_nfsdkrpc.c:103:extern u_long sb_max_adj;
sys/fs/nfsserver/nfs_nfsdkrpc.c:534:	siz = sb_max_adj;
sys/fs/nfsserver/nfs_nfsdport.c:71:extern u_long sb_max_adj;
sys/fs/nfsserver/nfs_nfsdport.c:258:	    sb_max_adj) {
sys/fs/nfsserver/nfs_nfsdport.c:261:		 * sb_max_adj.
sys/fs/nfsserver/nfs_nfsdport.c:266:		 * Convert suggested sb_max_adj value to a suggested
sys/fs/nfsserver/nfs_nfsdport.c:269:		 * sb_max_adj = (u_quad_t)sb_max * MCLBYTES /
sys/fs/nfsserver/nfs_nfsdport.c:271:		 * XXX If the calculation of sb_max_adj from sb_max changes,
sys/fs/nfsserver/nfs_nfsdserv.c:63:extern u_long sb_max_adj;
sys/fs/nfsserver/nfs_nfsdserv.c:4775:	if (sep->sess_maxreq > sb_max_adj - NFS_MAXXDR) {
sys/fs/nfsserver/nfs_nfsdserv.c:4776:		sep->sess_maxreq = sb_max_adj - NFS_MAXXDR;
sys/fs/nfsserver/nfs_nfsdserv.c:4782:	if (sep->sess_maxresp > sb_max_adj - NFS_MAXXDR) {
sys/fs/nfsserver/nfs_nfsdserv.c:4783:		sep->sess_maxresp = sb_max_adj - NFS_MAXXDR;
sys/netinet/sctp_usrreq.c:61:	u_long sb_max_adj;
sys/netinet/sctp_usrreq.c:71:	sb_max_adj = (u_long)((u_quad_t)(SB_MAX) * MCLBYTES / (MSIZE + MCLBYTES));
sys/netinet/sctp_usrreq.c:72:	SCTP_BASE_SYSCTL(sctp_sendspace) = min(sb_max_adj,
sys/rpc/rpc_generic.c:71:extern	u_long sb_max_adj;	/* not defined in socketvar.h */
sys/rpc/rpc_generic.c:139:	return (size > sb_max_adj ? (u_int)sb_max_adj : (u_int)size);
sys/netlink/netlink_domain.c:84:extern u_long sb_max_adj;
sys/netlink/netlink_domain.c:965:	if (optval > sb_max_adj) {
sys/kern/uipc_sockbuf.c:69:u_long sb_max_adj = BUF_MAX_ADJ(SB_MAX);
sys/kern/uipc_sockbuf.c:635:	sb_max_adj = BUF_MAX_ADJ(sb_max);
```

