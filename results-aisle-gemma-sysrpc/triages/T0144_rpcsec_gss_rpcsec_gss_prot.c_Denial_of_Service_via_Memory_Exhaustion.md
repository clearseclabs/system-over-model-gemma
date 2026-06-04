# Triage T0144: Denial of Service via Memory Exhaustion (`m_split`)

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: INVALID
- **Confidence**: 25% [VII→I]

---

## Finding

Denial of Service via Memory Exhaustion (`m_split`)

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The variable `len` is read from untrusted network data via `get_uint32` and passed to `m_split` without any upper-bound validation.

In `xdr_rpc_gss_unwrap_data`, the code calls `len = get_uint32(&results)`, which reads a 32-bit integer directly from the network mbuf. This `len` is then passed to `m_split(results, len, M_WAITOK)`. 

1. **Bug Pattern:** `m_split` in BSD-derived kernels (where this code originates) attempts to split an mbuf chain. If `len` is larger than the actual length of the mbuf chain, `m_split` typically returns NULL or fails. However, the use of `M_WAITOK` indicates the kernel may attempt to allocate resources or wait for memory to satisfy the request. 
2. **Reachability:** The `results` mbuf is derived from network input, and `len` is read directly from it via `get_uint32`. This is fully attacker-controlled.
3. **Defense:** There is no check on `len` before it is passed to `m_split`. The `KASSERT` later in the function only checks `cklen` (the checksum length), not `len` (the message length).
4. **Security Relevance:** While `m_split` might simply fail if `len` exceeds the available data, providing a massive `len` (e.g., 4GB) can trigger expensive allocation attempts or internal kernel panic/exhaustion depending on the specific kernel's `m_split` and `m_pullup` implementation. In many BSD mbuf implementations, `m_split` does not allocate new memory for the data itself but reorganizes the chain; however, an unchecked 32-bit length used in memory operations is a classic DoS vector.

CRUX: The variable `len` is read from untrusted network data via `get_uint32` and passed to `m_split` without any upper-bound validation.
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
sys/netpfil/ipfw/nat64/nat64_translate.c:594:			n = m_split(m, len, M_NOWAIT);
sys/netpfil/pf/pf.c:4064:	if ((n = m_split(m, off, M_NOWAIT)) == NULL)
sys/dev/iwm/if_iwm.c:5372:			 * Use m_copym instead of m_split, because that
sys/dev/nvmf/nvmf_tcp.c:1366:			n = m_split(m, space, M_WAITOK);
```

### Round 2: ❌ INVALID

**🎯 Crux:** m_split splits an existing mbuf chain; if 'len' is larger than the chain, it returns NULL, which the code handles, rather than allocating 'len' bytes of memory.

In `xdr_rpc_gss_unwrap_data`, the code reads a `uint32_t len` from the untrusted `results` mbuf using `get_uint32()`. This `len` is then passed directly to `m_split(results, len, M_WAITOK)`. In the BSD mbuf implementation, `m_split` does not allocate a new buffer for the content itself; rather, it splits an existing chain of mbufs at a given offset. If the requested `len` exceeds the actual length of the mbuf chain, `m_split` typically fails and returns NULL. The code explicitly checks for this return value: `if (!results) { m_freem(message); return (FALSE); }`. Therefore, providing a large `len` does not cause the kernel to allocate a massive amount of memory; it simply results in a failure to split because the chain is shorter than `len`. There is no path where `M_WAITOK` triggers a massive allocation based on the value of `len` in this specific context, as `m_split` operates on existing data.

CRUX: m_split splits an existing mbuf chain; if 'len' is larger than the chain, it returns NULL, which the code handles, rather than allocating 'len' bytes of memory.
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
sys/fs/nfsclient/nfs_clrpcops.c:234:static struct mbuf *nfsm_split(struct mbuf *, uint64_t);
sys/fs/nfsclient/nfs_clrpcops.c:7108:					m2 = nfsm_split(mp, xfer);
sys/fs/nfsclient/nfs_clrpcops.c:9777: * Split an mbuf list.  For non-M_EXTPG mbufs, just use m_split().
sys/fs/nfsclient/nfs_clrpcops.c:9780:nfsm_split(struct mbuf *mp, uint64_t xfer)
sys/fs/nfsclient/nfs_clrpcops.c:9788:		m = m_split(mp, xfer, M_WAITOK);
sys/fs/nfsclient/nfs_clrpcops.c:9819:		panic("nfsm_split: erroneous ext_pgs mbuf");
sys/rpc/clnt_vc.c:1091:				m = m_split(ct->ct_raw, ct->ct_record_resid,
sys/rpc/svc_vc.c:686:	 * we run out of data. We use m_split to pull
sys/rpc/svc_vc.c:694:			cd->mpending = m_split(cd->mpending,
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:245:		results = m_split(results, len, M_WAITOK);
sys/dev/iwm/if_iwm.c:5372:			 * Use m_copym instead of m_split, because that
sys/dev/nvmf/nvmf_tcp.c:1366:			n = m_split(m, space, M_WAITOK);
sys/dev/nvmf/nvmf_tcp.c:1843:			n = m_split(m, qp->max_tx_data, M_WAITOK);
sys/netpfil/pf/pf.c:4064:	if ((n = m_split(m, off, M_NOWAIT)) == NULL)
sys/netpfil/ipfw/nat64/nat64_translate.c:594:			n = m_split(m, len, M_NOWAIT);
sys/dev/iscsi/icl_soft.c:364:	*r = m_split(request->ip_ahs_mbuf, request->ip_ahs_len, M_WAITOK);
sys/dev/iscsi/icl_soft.c:511:		*r = m_split(m, len + padding, M_WAITOK);
sys/dev/cxgbe/t4_netmap.c:107:static int nm_split_rss = 0;
sys/dev/cxgbe/t4_netmap.c:108:SYSCTL_INT(_hw_cxgbe, OID_AUTO, nm_split_rss, CTLFLAG_RWTUN,
```

### Round 3: ❌ INVALID

**🎯 Crux:** m_split splits an existing chain at an offset; if the offset exceeds the chain length, it returns NULL without allocating 'len' bytes of memory.

The vulnerability report claims that passing an attacker-controlled `len` to `m_split` can cause memory exhaustion. In BSD-derived kernels (which this code target), `m_split` does not allocate a new buffer of size `len`; instead, it splits an existing mbuf chain at the specified offset. If `len` is greater than the total length of the chain, `m_split` simply returns NULL. The code in `xdr_rpc_gss_unwrap_data` explicitly checks for this NULL return value: `if (!results) { m_freem(message); return (FALSE); }`. Since no allocation proportional to the attacker-supplied `len` occurs, and the failure case is handled correctly, this is not a memory exhaustion vulnerability. The use of `M_WAITOK` in `m_split` allows the kernel to sleep if it needs to allocate a small amount of management memory (a new mbuf header) to perform the split, but this is a constant-time/small-allocation operation regardless of the value of `len`.

CRUX: m_split splits an existing chain at an offset; if the offset exceeds the chain length, it returns NULL without allocating 'len' bytes of memory.
GREP: m_split

🔎 **Grep results:**

GREP `m_split`:
```
sys/netinet/tcp_stacks/tcp_bbr.h:720:	uint32_t rc_num_split_allocs;		/* num split map entries allocated */
sys/netinet/tcp_stacks/tcp_rack.h:434:	uint32_t rc_num_split_allocs;	/* num split map entries allocated */
sys/sys/mbuf.h:866:struct mbuf	*m_split(struct mbuf *, int, int);
sys/netinet/tcp_stacks/bbr.c:3300:		    bbr->r_ctl.rc_num_split_allocs >= V_tcp_map_split_limit) {
sys/netinet/tcp_stacks/bbr.c:3314:		bbr->r_ctl.rc_num_split_allocs++;
sys/netinet/tcp_stacks/bbr.c:3324:		bbr->r_ctl.rc_num_split_allocs--;
sys/netinet/tcp_stacks/rack.c:3303:		    rack->r_ctl.rc_num_split_allocs >= rack->r_ctl.rc_split_limit) {
sys/netinet/tcp_stacks/rack.c:3317:		rack->r_ctl.rc_num_split_allocs++;
sys/netinet/tcp_stacks/rack.c:3350:		rack->r_ctl.rc_num_split_allocs--;
sys/netinet/sctputil.c:7154:	sp = m_split(m, off, M_NOWAIT);
sys/netinet/sctp_input.c:2301:	m_sig = m_split(m, sig_offset, M_NOWAIT);
sys/fs/nfsclient/nfs_clrpcops.c:234:static struct mbuf *nfsm_split(struct mbuf *, uint64_t);
sys/fs/nfsclient/nfs_clrpcops.c:7108:					m2 = nfsm_split(mp, xfer);
sys/fs/nfsclient/nfs_clrpcops.c:9777: * Split an mbuf list.  For non-M_EXTPG mbufs, just use m_split().
sys/fs/nfsclient/nfs_clrpcops.c:9780:nfsm_split(struct mbuf *mp, uint64_t xfer)
sys/fs/nfsclient/nfs_clrpcops.c:9788:		m = m_split(mp, xfer, M_WAITOK);
sys/fs/nfsclient/nfs_clrpcops.c:9819:		panic("nfsm_split: erroneous ext_pgs mbuf");
sys/netpfil/ipfw/nat64/nat64_translate.c:594:			n = m_split(m, len, M_NOWAIT);
sys/netpfil/pf/pf.c:4064:	if ((n = m_split(m, off, M_NOWAIT)) == NULL)
sys/dev/iwm/if_iwm.c:5372:			 * Use m_copym instead of m_split, because that
sys/dev/nvmf/nvmf_tcp.c:1366:			n = m_split(m, space, M_WAITOK);
sys/dev/nvmf/nvmf_tcp.c:1843:			n = m_split(m, qp->max_tx_data, M_WAITOK);
sys/dev/iscsi/icl_soft.c:364:	*r = m_split(request->ip_ahs_mbuf, request->ip_ahs_len, M_WAITOK);
sys/dev/iscsi/icl_soft.c:511:		*r = m_split(m, len + padding, M_WAITOK);
sys/dev/cxgbe/nvmf/nvmf_che.c:3058:			n = m_split(m, qp->max_tx_data, M_WAITOK);
sys/dev/cxgbe/t4_netmap.c:107:static int nm_split_rss = 0;
sys/dev/cxgbe/t4_netmap.c:108:SYSCTL_INT(_hw_cxgbe, OID_AUTO, nm_split_rss, CTLFLAG_RWTUN,
sys/dev/cxgbe/t4_netmap.c:109:    &nm_split_rss, 0, "Split the netmap rx queues into two groups.");
sys/dev/cxgbe/t4_netmap.c:598:	MPASS(nm_split_rss != 0);
sys/dev/cxgbe/t4_netmap.c:685:	if (nm_split_rss == 0 || vi->nnmrxq == 1)
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability claim is based on a misunderstanding of `m_split`. In BSD-derived kernels, `m_split` does not allocate a new buffer of size `len`; it splits an existing mbuf chain at the specified offset. If the requested `len` exceeds the actual total length of the existing chain, `m_split` returns NULL. The code in `xdr_rpc_gss_unwrap_data` explicitly checks for this NULL return (`if (!results)`) and handles it by freeing the associated memory and returning FALSE. Therefore, providing a large `len` value does not cause memory exhaustion, as no massive allocation is attempted.

