# Triage T0140: ecurity Analysis

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

ecurity Analysis

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The attacker-controlled lengths `len` and `cklen` are used as arguments to `m_split` and `m_pullup`, both of which return NULL if the requested length is unavailable, and the code explicitly checks for these NULL returns before proceeding.

The scanner flags potential memory manipulation issues in `xdr_rpc_gss_unwrap_data`. Looking at the `rpc_gss_svc_integrity` path, `len` is read from the network via `get_uint32(&results)` and passed to `m_split(results, len, M_WAITOK)`. In BSD mbuf implementations, `m_split` is designed to split a chain at a specific length; if `len` exceeds the total length of the mbuf chain, `m_split` typically returns NULL or handles it gracefully without an out-of-bounds write. Similarly, `cklen` is checked via `KASSERT(cklen <= MHLEN, ...)`. While `KASSERT` is often removed in production builds, `m_pullup(mic, cklen)` is subsequently called. `m_pullup` is a standard mbuf operation that ensures a contiguous region of `cklen` bytes; if the chain is shorter than `cklen`, `m_pullup` returns NULL, which the code explicitly checks (`if (!mic) return (FALSE);`). Therefore, the attacker-controlled lengths are passed to mbuf management functions that are specifically designed to handle size mismatches by returning NULL, and these return values are checked. There is no evidence of an unchecked buffer overflow or an arbitrary memory write.

CRUX: The attacker-controlled lengths `len` and `cklen` are used as arguments to `m_split` and `m_pullup`, both of which return NULL if the requested length is unavailable, and the code explicitly checks for these NULL returns before proceeding.
GREP: m_split

🔎 **Grep results:**

GREP `m_split`:
```
sys/sys/mbuf.h:866:struct mbuf	*m_split(struct mbuf *, int, int);
sys/netinet/tcp_stacks/tcp_bbr.h:720:	uint32_t rc_num_split_allocs;		/* num split map entries allocated */
sys/netinet/tcp_stacks/tcp_rack.h:434:	uint32_t rc_num_split_allocs;	/* num split map entries allocated */
sys/fs/nfsclient/nfs_clrpcops.c:234:static struct mbuf *nfsm_split(struct mbuf *, uint64_t);
sys/fs/nfsclient/nfs_clrpcops.c:7108:					m2 = nfsm_split(mp, xfer);
sys/fs/nfsclient/nfs_clrpcops.c:9777: * Split an mbuf list.  For non-M_EXTPG mbufs, just use m_split().
sys/fs/nfsclient/nfs_clrpcops.c:9780:nfsm_split(struct mbuf *mp, uint64_t xfer)
sys/fs/nfsclient/nfs_clrpcops.c:9788:		m = m_split(mp, xfer, M_WAITOK);
sys/fs/nfsclient/nfs_clrpcops.c:9819:		panic("nfsm_split: erroneous ext_pgs mbuf");
sys/net80211/ieee80211_superg.c:327:	n = m_split(m, framelen, IEEE80211_M_NOWAIT);
sys/kgssapi/krb5/krb5_mech.c:1820:	*mp = m = m_split(m, 16 + cklen, M_WAITOK);
sys/kgssapi/krb5/krb5_mech.c:1929:		*mp = m = m_split(m, 16, M_WAITOK);
sys/kgssapi/krb5/krb5_mech.c:1954:			*mp = m = m_split(m, RRC, M_WAITOK);
sys/kgssapi/krb5/krb5_mech.c:2028:		cm = m_split(m, plen, M_WAITOK);
sys/dev/iwm/if_iwm.c:5372:			 * Use m_copym instead of m_split, because that
sys/dev/nvmf/nvmf_tcp.c:1366:			n = m_split(m, space, M_WAITOK);
sys/dev/nvmf/nvmf_tcp.c:1843:			n = m_split(m, qp->max_tx_data, M_WAITOK);
sys/net80211/ieee80211_ht.c:497:		n = m_split(m, framelen, IEEE80211_M_NOWAIT);
sys/dev/iscsi/icl_soft.c:364:	*r = m_split(request->ip_ahs_mbuf, request->ip_ahs_len, M_WAITOK);
sys/dev/iscsi/icl_soft.c:511:		*r = m_split(m, len + padding, M_WAITOK);
sys/dev/cxgbe/t4_netmap.c:107:static int nm_split_rss = 0;
sys/dev/cxgbe/t4_netmap.c:108:SYSCTL_INT(_hw_cxgbe, OID_AUTO, nm_split_rss, CTLFLAG_RWTUN,
sys/dev/cxgbe/t4_netmap.c:109:    &nm_split_rss, 0, "Split the netmap rx queues into two groups.");
sys/dev/cxgbe/t4_netmap.c:598:	MPASS(nm_split_rss != 0);
sys/dev/cxgbe/t4_netmap.c:685:	if (nm_split_rss == 0 || vi->nnmrxq == 1)
sys/dev/cxgbe/nvmf/nvmf_che.c:3058:			n = m_split(m, qp->max_tx_data, M_WAITOK);
sys/rpc/svc_vc.c:686:	 * we run out of data. We use m_split to pull
sys/rpc/svc_vc.c:694:			cd->mpending = m_split(cd->mpending,
sys/netpfil/ipfw/nat64/nat64_translate.c:594:			n = m_split(m, len, M_NOWAIT);
sys/netpfil/pf/pf.c:4064:	if ((n = m_split(m, off, M_NOWAIT)) == NULL)
```

### Round 2: ❌ INVALID

**🎯 Crux:** Attacker-controlled lengths are passed to mbuf functions (m_split, m_pullup) that return NULL on failure, and these return values are explicitly checked before the buffers are used.

The reported vulnerability suggests that attacker-controlled lengths (`len` and `cklen`) are used unsafely in `xdr_rpc_gss_unwrap_data`. However, analyzing the code shows that these lengths are passed to standard BSD mbuf functions (`m_split`, `m_pullup`) which are designed to handle length requests that exceed the actual available data by returning NULL. The code explicitly checks the return values of these functions: if `m_split` returns NULL, it frees the message and returns FALSE; if `m_pullup` returns NULL, it does the same. The `KASSERT` on `cklen` is indeed a debug-only check, but it is followed by `m_pullup`, which provides the actual safety boundary by verifying the buffer has enough contiguous memory. The `m_trim` function also includes a NULL check. There is no path where an attacker-supplied length leads to an out-of-bounds write or read because the mbuf API manages the boundaries and the return values are validated.

CRUX: Attacker-controlled lengths are passed to mbuf functions (m_split, m_pullup) that return NULL on failure, and these return values are explicitly checked before the buffers are used.
GREP: m_split

🔎 **Grep results:**

GREP `m_split`:
```
sys/sys/mbuf.h:866:struct mbuf	*m_split(struct mbuf *, int, int);
sys/netinet/tcp_stacks/tcp_bbr.h:720:	uint32_t rc_num_split_allocs;		/* num split map entries allocated */
sys/netinet/tcp_stacks/tcp_rack.h:434:	uint32_t rc_num_split_allocs;	/* num split map entries allocated */
usr.sbin/pmcstudy/pmcstudy.c:724:	struct counters *mem_split;
usr.sbin/pmcstudy/pmcstudy.c:727:	mem_split = find_counter(cpu, "MEM_UOP_RETIRED.SPLIT_STORES");
usr.sbin/pmcstudy/pmcstudy.c:730:		memsplit = mem_split->vals[pos] * 1.0;
usr.sbin/pmcstudy/pmcstudy.c:733:		memsplit = mem_split->sum * 1.0;
usr.sbin/pmcstudy/pmcstudy.c:748:	struct counters *mem_split;
usr.sbin/pmcstudy/pmcstudy.c:751:	mem_split = find_counter(cpu, "MEM_UOPS_RETIRED.SPLIT_STORES");
usr.sbin/pmcstudy/pmcstudy.c:754:		memsplit = mem_split->vals[pos] * 1.0;
usr.sbin/pmcstudy/pmcstudy.c:757:		memsplit = mem_split->sum * 1.0;
usr.sbin/cxgbetool/reg_defs_t7.c:16480:		{ "cim_split_enable", 6, 1 },
usr.sbin/cxgbetool/reg_defs_t7.c:16518:		{ "cim_split_opcode_program", 8, 1 },
usr.sbin/cxgbetool/reg_defs_t5.c:40334:		{ "cim_split_enable", 6, 1 },
usr.sbin/cxgbetool/reg_defs_t5.c:40365:		{ "cim_split_opcode_program", 8, 1 },
usr.sbin/cxgbetool/reg_defs_t6.c:38587:		{ "cim_split_enable", 6, 1 },
usr.sbin/cxgbetool/reg_defs_t6.c:38618:		{ "cim_split_opcode_program", 8, 1 },
contrib/bc/src/num.c:680:bc_num_split(const BcNum* restrict n, size_t idx, BcNum* restrict a,
contrib/bc/src/num.c:1412:	bc_num_split(a, max2, &l1, &h1);
contrib/bc/src/num.c:1413:	bc_num_split(b, max2, &l2, &h2);
sys/fs/nfsclient/nfs_clrpcops.c:234:static struct mbuf *nfsm_split(struct mbuf *, uint64_t);
sys/fs/nfsclient/nfs_clrpcops.c:7108:					m2 = nfsm_split(mp, xfer);
sys/fs/nfsclient/nfs_clrpcops.c:9777: * Split an mbuf list.  For non-M_EXTPG mbufs, just use m_split().
sys/fs/nfsclient/nfs_clrpcops.c:9780:nfsm_split(struct mbuf *mp, uint64_t xfer)
sys/fs/nfsclient/nfs_clrpcops.c:9788:		m = m_split(mp, xfer, M_WAITOK);
sys/fs/nfsclient/nfs_clrpcops.c:9819:		panic("nfsm_split: erroneous ext_pgs mbuf");
sys/rpc/svc_vc.c:686:	 * we run out of data. We use m_split to pull
sys/rpc/svc_vc.c:694:			cd->mpending = m_split(cd->mpending,
sys/netpfil/ipfw/nat64/nat64_translate.c:594:			n = m_split(m, len, M_NOWAIT);
sys/netpfil/pf/pf.c:4064:	if ((n = m_split(m, off, M_NOWAIT)) == NULL)
```

### Round 3: ❌ INVALID

**🎯 Crux:** m_split and m_pullup return NULL if the attacker-supplied length is invalid, and the code explicitly handles these NULL returns.

The vulnerability report suggests that attacker-controlled lengths (`len`, `cklen`) used in `xdr_rpc_gss_unwrap_data` lead to memory corruption. I analyzed the data flow: `get_uint32` reads a 32-bit value from the untrusted mbuf chain. This value is passed to `m_split` and `m_pullup`. In BSD-style mbuf implementations, `m_split` splits the chain at the given length and returns the remainder; if the length exceeds the chain size, it returns NULL. Similarly, `m_pullup` ensures a contiguous region of the requested size; if it cannot satisfy the request, it returns NULL. The code explicitly checks these return values: `if (!results) { m_freem(message); return (FALSE); }` after `m_split`, and `if (!mic) { m_freem(message); return (FALSE); }` after `m_pullup`. The `m_trim` function also contains a NULL check. While `KASSERT(cklen <= MHLEN)` is a debug-only check, the subsequent `m_pullup` call provides the necessary runtime safety. There is no path where an unchecked length leads to a buffer overflow or arbitrary memory access.

CRUX: m_split and m_pullup return NULL if the attacker-supplied length is invalid, and the code explicitly handles these NULL returns.
GREP: m_split

🔎 **Grep results:**

GREP `m_split`:
```
sys/sys/mbuf.h:866:struct mbuf	*m_split(struct mbuf *, int, int);
sys/netinet/tcp_stacks/tcp_bbr.h:720:	uint32_t rc_num_split_allocs;		/* num split map entries allocated */
sys/netinet/tcp_stacks/tcp_rack.h:434:	uint32_t rc_num_split_allocs;	/* num split map entries allocated */
usr.sbin/pmcstudy/pmcstudy.c:724:	struct counters *mem_split;
usr.sbin/pmcstudy/pmcstudy.c:727:	mem_split = find_counter(cpu, "MEM_UOP_RETIRED.SPLIT_STORES");
usr.sbin/pmcstudy/pmcstudy.c:730:		memsplit = mem_split->vals[pos] * 1.0;
usr.sbin/pmcstudy/pmcstudy.c:733:		memsplit = mem_split->sum * 1.0;
usr.sbin/pmcstudy/pmcstudy.c:748:	struct counters *mem_split;
usr.sbin/pmcstudy/pmcstudy.c:751:	mem_split = find_counter(cpu, "MEM_UOPS_RETIRED.SPLIT_STORES");
usr.sbin/pmcstudy/pmcstudy.c:754:		memsplit = mem_split->vals[pos] * 1.0;
usr.sbin/pmcstudy/pmcstudy.c:757:		memsplit = mem_split->sum * 1.0;
contrib/bc/src/num.c:680:bc_num_split(const BcNum* restrict n, size_t idx, BcNum* restrict a,
contrib/bc/src/num.c:1412:	bc_num_split(a, max2, &l1, &h1);
contrib/bc/src/num.c:1413:	bc_num_split(b, max2, &l2, &h2);
usr.sbin/cxgbetool/reg_defs_t7.c:16480:		{ "cim_split_enable", 6, 1 },
usr.sbin/cxgbetool/reg_defs_t7.c:16518:		{ "cim_split_opcode_program", 8, 1 },
usr.sbin/cxgbetool/reg_defs_t6.c:38587:		{ "cim_split_enable", 6, 1 },
usr.sbin/cxgbetool/reg_defs_t6.c:38618:		{ "cim_split_opcode_program", 8, 1 },
usr.sbin/cxgbetool/reg_defs_t5.c:40334:		{ "cim_split_enable", 6, 1 },
usr.sbin/cxgbetool/reg_defs_t5.c:40365:		{ "cim_split_opcode_program", 8, 1 },
sys/fs/nfsclient/nfs_clrpcops.c:234:static struct mbuf *nfsm_split(struct mbuf *, uint64_t);
sys/fs/nfsclient/nfs_clrpcops.c:7108:					m2 = nfsm_split(mp, xfer);
sys/fs/nfsclient/nfs_clrpcops.c:9777: * Split an mbuf list.  For non-M_EXTPG mbufs, just use m_split().
sys/fs/nfsclient/nfs_clrpcops.c:9780:nfsm_split(struct mbuf *mp, uint64_t xfer)
sys/fs/nfsclient/nfs_clrpcops.c:9788:		m = m_split(mp, xfer, M_WAITOK);
sys/fs/nfsclient/nfs_clrpcops.c:9819:		panic("nfsm_split: erroneous ext_pgs mbuf");
sys/dev/iwm/if_iwm.c:5372:			 * Use m_copym instead of m_split, because that
sys/dev/nvmf/nvmf_tcp.c:1366:			n = m_split(m, space, M_WAITOK);
sys/dev/nvmf/nvmf_tcp.c:1843:			n = m_split(m, qp->max_tx_data, M_WAITOK);
sys/net80211/ieee80211_ht.c:497:		n = m_split(m, framelen, IEEE80211_M_NOWAIT);
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability report claims that attacker-controlled lengths ('len' and 'cklen') used in 'xdr_rpc_gss_unwrap_data' cause memory corruption. However, the code shows these lengths are passed to standard BSD mbuf functions: 'm_split' and 'm_pullup'. Both functions are designed to return NULL if the requested length exceeds the available data in the mbuf chain. The code explicitly checks the return value of 'm_split' (if (!results)) and 'm_pullup' (if (!mic)) and frees the associated memory before returning FALSE. There is no evidence of an out-of-bounds write or read occurring before these checks.

