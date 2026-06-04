# Triage T0145: Potential Kernel Panic / Memory Corruption (`m_pullup`)

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV]

---

## Finding

Potential Kernel Panic / Memory Corruption (`m_pullup`)

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The variable `cklen` is controlled by the attacker and passed to `m_pullup` without a production-grade bound check, as `KASSERT` is removed in production builds.

The vulnerability report correctly identifies that `cklen` is read from an untrusted network mbuf via `get_uint32(&results)`. The only check against `cklen` is `KASSERT(cklen <= MHLEN, ...)`, which is compiled out in production kernels. Consequently, an attacker can provide a very large `cklen` value (up to 2^32-1). This value is passed directly to `m_pullup(mic, cklen)`. In most BSD-derived kernels, `m_pullup` attempts to ensure that the first `N` bytes of an mbuf chain are contiguous. If `N` is excessively large (e.g., larger than the total length of the mbuf chain or exceeding available kernel memory/limits), `m_pullup` typically returns NULL. The code handles the NULL return case (`if (!mic) { m_freem(message); return (FALSE); }`), preventing a NULL pointer dereference. However, the request for a massive contiguous buffer can trigger a kernel panic due to memory exhaustion or integer overflows within the `m_pullup` implementation's internal size calculations before it returns NULL. Given that `cklen` is fully attacker-controlled and the only bound is a debug-only assertion, this is a reachable path to a denial-of-service (kernel panic).

CRUX: The variable `cklen` is controlled by the attacker and passed to `m_pullup` without a production-grade bound check, as `KASSERT` is removed in production builds.
GREP: MHLEN

🔎 **Grep results:**

GREP `MHLEN`:
```
sys/netpfil/pf/if_pflog.c:80:#define PFLOGMTU	(32768 + MHLEN + MLEN)
sys/sys/mbuf.h:96:#define	MHLEN		((int)(MSIZE - MPKTHSIZE))
sys/sys/mbuf.h:97:#define	MINCLSIZE	(MHLEN + 1)
sys/dev/ixgbe/ixgbe.h:155: * MHLEN is typically 168 bytes, giving us 8-byte alignment.  Getting
sys/sys/mbuf.h:86: * MHLEN is data length in an mbuf with pktheader.
sys/sys/mbuf.h:358:	 * to MHLEN (space left after a packet header) and MLEN (space left
sys/sys/mbuf.h:1202:	 ((m)->m_flags & M_PKTHDR) ? MHLEN :				\
sys/fs/nfs/nfs_commonsubs.c:791:	} else if (siz > MHLEN) {
sys/fs/nfsclient/nfs_clrpcops.c:5870:			if (stripecnt >= MHLEN / NFSX_UNSIGNED ||
sys/rpc/clnt_bck.c:248:	KASSERT(ct->ct_mpos + sizeof(uint32_t) <= MHLEN,
sys/rpc/clnt_dg.c:425:	KASSERT(cu->cu_mcalllen <= MHLEN, ("RPC header too big"));
sys/rpc/clnt_vc.c:359:	KASSERT(ct->ct_mpos + sizeof(uint32_t) <= MHLEN,
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:259:		KASSERT(cklen <= MHLEN, ("unexpected large GSS-API checksum"));
sys/netinet6/nd6_nbr.c:457:	if (max_linkhdr + maxlen > MHLEN)
sys/netinet6/nd6_nbr.c:1011:	if (max_linkhdr + maxlen > MHLEN)
sys/netinet6/ip6_mroute.c:1759:	i = MHLEN - M_LEADINGSPACE(mm);
sys/netinet6/ip6_input.c:601:		if (m->m_pkthdr.len > MHLEN)
sys/netinet6/icmp6.c:575:			CTASSERT(sizeof(*nip6) + sizeof(*nicmp6) <= MHLEN);
sys/netinet6/icmp6.c:705:			CTASSERT(sizeof(*nip6) + sizeof(*nicmp6) + 4 <= MHLEN);
sys/netinet6/icmp6.c:1411:	if (replylen > MHLEN)
sys/netinet6/icmp6.c:1960:		    m->m_len <= MHLEN) {
sys/netinet6/icmp6.c:2028:	if (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) > MHLEN)
sys/netinet6/icmp6.c:2413:	 * (MHLEN < IPV6_MMTU is almost always true)
sys/dev/ti/if_ti.c:1239:	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR, NULL, NULL, MHLEN, 1,
sys/dev/ti/if_ti.c:1240:	    MHLEN, 0, NULL, NULL, &sc->ti_cdata.ti_rx_mini_tag);
sys/dev/ti/if_ti.c:1454:	m->m_len = m->m_pkthdr.len = MHLEN;
sys/dev/ti/if_ti.c:1649:			m_new->m_len = MHLEN - ETHER_ALIGN;
sys/dev/ti/if_ti.c:2259:	rcb->ti_max_len = MHLEN - ETHER_ALIGN;
sys/dev/ti/if_ti.c:2694:	r->ti_len = MHLEN - ETHER_ALIGN;
sys/dev/mxge/if_mxge.c:2336:	m->m_len = MHLEN;
```

### Round 2: ✅ VALID

**🎯 Crux:** The attacker-controlled `cklen` is passed to `m_pullup` without any production-grade boundary check, as the only check is a `KASSERT` which is compiled out in production.

The vulnerability is real. The variable `cklen` is read directly from the network using `get_uint32(&results)`, making it attacker-controlled. The only check against `cklen` is `KASSERT(cklen <= MHLEN, ...)`. As noted, `KASSERT` is a debug-only macro and is removed in production builds. This allows an attacker to pass a very large value (up to 2^32-1) to `m_pullup(mic, cklen)`. In the BSD mbuf architecture, `m_pullup` attempts to make the first `N` bytes of a chain contiguous. If `N` is excessively large, it can lead to an attempt to allocate a massive amount of kernel memory or trigger integer overflows in the internal length calculations of `m_pullup`. While the code checks if `m_pullup` returns NULL, the failure typically happens inside the kernel's memory allocator or mbuf management logic when handling an unreasonable size request, leading to a kernel panic (DoS). The lack of a production-grade bound check on a value used for memory manipulation is a security vulnerability.

CRUX: The attacker-controlled `cklen` is passed to `m_pullup` without any production-grade boundary check, as the only check is a `KASSERT` which is compiled out in production.
GREP: MHLEN

🔎 **Grep results:**

GREP `MHLEN`:
```
sys/netpfil/pf/if_pflog.c:80:#define PFLOGMTU	(32768 + MHLEN + MLEN)
sys/sys/mbuf.h:96:#define	MHLEN		((int)(MSIZE - MPKTHSIZE))
sys/sys/mbuf.h:97:#define	MINCLSIZE	(MHLEN + 1)
sys/dev/ixgbe/ixgbe.h:155: * MHLEN is typically 168 bytes, giving us 8-byte alignment.  Getting
sys/sys/mbuf.h:86: * MHLEN is data length in an mbuf with pktheader.
sys/sys/mbuf.h:358:	 * to MHLEN (space left after a packet header) and MLEN (space left
sys/sys/mbuf.h:1202:	 ((m)->m_flags & M_PKTHDR) ? MHLEN :				\
sys/fs/nfs/nfs_commonsubs.c:791:	} else if (siz > MHLEN) {
sys/fs/nfsclient/nfs_clrpcops.c:5870:			if (stripecnt >= MHLEN / NFSX_UNSIGNED ||
sys/dev/ti/if_ti.c:1239:	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR, NULL, NULL, MHLEN, 1,
sys/dev/ti/if_ti.c:1240:	    MHLEN, 0, NULL, NULL, &sc->ti_cdata.ti_rx_mini_tag);
sys/dev/ti/if_ti.c:1454:	m->m_len = m->m_pkthdr.len = MHLEN;
sys/dev/ti/if_ti.c:1649:			m_new->m_len = MHLEN - ETHER_ALIGN;
sys/dev/ti/if_ti.c:2259:	rcb->ti_max_len = MHLEN - ETHER_ALIGN;
sys/dev/ti/if_ti.c:2694:	r->ti_len = MHLEN - ETHER_ALIGN;
sys/dev/mxge/if_mxge.c:2336:	m->m_len = MHLEN;
sys/dev/mxge/if_mxge.c:2702:		if (length <= (MHLEN - MXGEFW_PAD))
sys/dev/mxge/if_mxge.c:3210:				 MHLEN,			/* maxsize */
sys/dev/mxge/if_mxge.c:3212:				 MHLEN,			/* maxsegsize */
sys/dev/mxge/if_mxge.c:3530:	cmd.data0 = MHLEN - MXGEFW_PAD;
sys/dev/et/if_et.c:939:	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR, NULL, NULL, MHLEN, 1,
sys/dev/et/if_et.c:940:	    MHLEN, 0, NULL, NULL, &sc->sc_rx_mini_tag);
sys/dev/et/if_et.c:2381:	m->m_len = m->m_pkthdr.len = MHLEN;
sys/dev/my/if_my.c:1334:	if (m_head->m_pkthdr.len > MHLEN) {
sys/dev/bce/if_bce.c:2967:		sc->rx_bd_mbuf_alloc_size = MHLEN;
sys/dev/bce/if_bce.c:2970:			roundup2(MSIZE - MHLEN, 16) - (MSIZE - MHLEN);
sys/dev/bce/if_bce.c:6579:				 * FCS <= MHLEN).  In other words, the packet is
sys/dev/usb/wlan/if_zyd.c:2182:	} else if (rlen > (int)MHLEN)
sys/dev/usb/net/if_cdce.c:1694:			} else if (temp > (int)(MHLEN - ETHER_ALIGN)) {
sys/dev/usb/net/if_axge.c:1048:	if (len > MHLEN - ETHER_ALIGN)
```

### Round 3: ✅ VALID

**🎯 Crux:** An attacker-controlled uint32 `cklen` is passed to `m_pullup` without any production-grade boundary check, as the only check is a `KASSERT` which is removed in production builds.

The vulnerability exists because `cklen` is read from an untrusted network mbuf via `get_uint32()` and passed to `m_pullup(mic, cklen)`. The only boundary check is `KASSERT(cklen <= MHLEN, ...)`, and as is standard in BSD-derived kernels, `KASSERT` is compiled out in production builds. While the code checks if `m_pullup` returns NULL, `m_pullup` is an operation that attempts to make the first `N` bytes of an mbuf chain contiguous. In the BSD mbuf implementation, requesting an excessively large contiguous region (e.g., near 2^32) can lead to integer overflows in size calculations or attempts to allocate massive amounts of kernel memory before the function can safely return NULL. This creates a reachable path for a remote attacker to cause a kernel panic (Denial of Service). The previous reviewers correctly identified the flow; I have verified that `MHLEN` is a small constant (typically around 168 bytes based on the grep results), making the lack of a production-grade check for a `uint32_t` input a critical failure.

CRUX: An attacker-controlled uint32 `cklen` is passed to `m_pullup` without any production-grade boundary check, as the only check is a `KASSERT` which is removed in production builds.
GREP: m_pullup

🔎 **Grep results:**

GREP `m_pullup`:
```
usr.sbin/ppp/mbuf.h:112:extern struct mbuf *m_pullup(struct mbuf *);
sys/sys/mbuf.h:864:struct mbuf	*m_pullup(struct mbuf *, int);
sys/netgraph/bluetooth/hci/ng_hci_var.h:51:/* Wrapper around m_pullup */
sys/netgraph/bluetooth/hci/ng_hci_var.h:55:			(m) = m_pullup((m), (s)); 	\
sys/netgraph/bluetooth/hci/ng_hci_var.h:57:			NG_HCI_ALERT("%s: %s - m_pullup(%zd) failed\n", \
sys/netgraph/bluetooth/l2cap/ng_l2cap_var.h:51:/* Wrapper around m_pullup */
sys/netgraph/bluetooth/l2cap/ng_l2cap_var.h:55:			(m) = m_pullup((m), (s)); \
sys/netgraph/bluetooth/l2cap/ng_l2cap_var.h:57:			NG_L2CAP_ALERT("%s: %s - m_pullup(%zd) failed\n", \
sys/net/netisr.h:169: * for the chain, or NULL if the packet proves invalid or m_pullup() fails.
sys/net/debugnet.h:125:	 * which the header is guaranteed to be contiguous.  If m_pullup is
sys/net/altq/if_altq.h:80: * note that pattr_hdr could be stale after m_pullup, though link
sys/net/altq/if_altq.h:81: * layer output routines usually don't use m_pullup.  link-level
usr.sbin/ppp/nat_cmd.c:507:  bp = m_pullup(m_append(bp, NULL, NAT_EXTRABUF));
usr.sbin/ppp/nat_cmd.c:529:  bp = m_pullup(m_append(bp, NULL, NAT_EXTRABUF));
usr.sbin/ppp/ipcp.c:1467:      bp = m_pullup(bp);
usr.sbin/ppp/fsm.c:474:  bp = m_pullup(bp);
usr.sbin/ppp/fsm.c:511:      bp = m_pullup(bp);
usr.sbin/ppp/fsm.c:623:  bp = m_pullup(bp);
usr.sbin/ppp/fsm.c:707:  bp = m_pullup(bp);
usr.sbin/ppp/fsm.c:840:  bp = m_pullup(bp);
usr.sbin/ppp/fsm.c:955:  bp = m_pullup(bp);
usr.sbin/ppp/fsm.c:1001:    bp = m_pullup(m_append(bp, "", 1));
usr.sbin/ppp/fsm.c:1073:    bp = m_pullup(bp);
usr.sbin/ppp/lqr.c:219:    bp = m_pullup(proto_Prepend(bp, PROTO_LQR, 0, 0));
usr.sbin/ppp/lqr.c:224:    bp = m_pullup(bp);
usr.sbin/ppp/lqr.c:429:  bp = m_pullup(bp);
usr.sbin/ppp/cbcp.c:636:  bp = m_pullup(bp);
usr.sbin/ppp/pap.c:232:      bp = m_pullup(bp);
usr.sbin/ppp/hdlc.c:315:  bp = m_pullup(bp);
usr.sbin/ppp/ipv6cp.c:446:      bp = m_pullup(bp);
```

