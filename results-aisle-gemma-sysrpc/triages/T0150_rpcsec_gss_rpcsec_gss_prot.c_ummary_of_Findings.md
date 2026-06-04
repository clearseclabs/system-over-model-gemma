# Triage T0150: ummary of Findings

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

ummary of Findings

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** Attacker-controlled uint32_t values (len, cklen) from the network are used in m_split, m_pullup, and m_trim without validation, with the only existing check being a KASSERT which is removed in production.

I analyzed the three reported findings. 

1. **Kernel Memory Exhaustion via `m_split`**: In `xdr_rpc_gss_unwrap_data`, `len` is read from the network via `get_uint32` and passed directly to `m_split(results, len, M_WAITOK)`. `m_split` in BSD-style kernels typically attempts to split the mbuf chain. If `len` is very large (e.g., 2^32-1), it doesn't necessarily allocate `len` bytes immediately, but rather marks the split point. However, the vulnerability scanner's claim of 'unbounded' is technically correct as there is no upper bound check on `len` before calling `m_split`. 

2. **Integer Signedness in `m_trim`**: `m_trim` is defined as `static void m_trim(struct mbuf *m, int len)`. It is called in `xdr_rpc_gss_unwrap_data` as `m_trim(mic, cklen)` and `m_trim(message, len)`. Both `cklen` and `len` are `uint32_t`. If an attacker provides a value > 2,147,483,647 (INT_MAX), it becomes negative when passed to `m_trim`. Inside `m_trim`, this negative value is passed to `m_getptr(m, len, &off)`. In standard mbuf implementations, `m_getptr` takes a `size_t` or `int` for length. If it's treated as a large unsigned value or a negative signed value, it can lead to out-of-bounds access or kernel panics. This is a classic signedness mismatch on attacker-controlled input.

3. **Bypassed Length Check via `KASSERT`**: The code contains `KASSERT(cklen <= MHLEN, ("unexpected large GSS-API checksum"));`. KASSERTs are removed in production builds. Immediately following this, `m_pullup(mic, cklen)` is called. If `cklen` is huge, `m_pullup` will attempt to allocate a contiguous buffer of that size. This is a direct path to kernel memory exhaustion or a crash in production, as the only check protecting `m_pullup` from an arbitrary `uint32_t` is the `KASSERT`.

All three findings originate from `get_uint32(&results)`, which reads directly from the network mbuf chain, making them attacker-reachable. The lack of validation on `len` and `cklen` before they are used in memory management functions (`m_split`, `m_pullup`, `m_trim`) is a security vulnerability.

CRUX: Attacker-controlled uint32_t values (len, cklen) from the network are used in m_split, m_pullup, and m_trim without validation, with the only existing check being a KASSERT which is removed in production.
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
sys/fs/nfsclient/nfs_clrpcops.c:5870:			if (stripecnt >= MHLEN / NFSX_UNSIGNED ||
sys/fs/nfs/nfs_commonsubs.c:791:	} else if (siz > MHLEN) {
sys/netinet6/ip6_input.c:601:		if (m->m_pkthdr.len > MHLEN)
sys/dev/ti/if_ti.c:1239:	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR, NULL, NULL, MHLEN, 1,
sys/dev/ti/if_ti.c:1240:	    MHLEN, 0, NULL, NULL, &sc->ti_cdata.ti_rx_mini_tag);
sys/dev/ti/if_ti.c:1454:	m->m_len = m->m_pkthdr.len = MHLEN;
sys/dev/ti/if_ti.c:1649:			m_new->m_len = MHLEN - ETHER_ALIGN;
sys/dev/ti/if_ti.c:2259:	rcb->ti_max_len = MHLEN - ETHER_ALIGN;
sys/dev/ti/if_ti.c:2694:	r->ti_len = MHLEN - ETHER_ALIGN;
sys/dev/et/if_et.c:939:	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR, NULL, NULL, MHLEN, 1,
sys/dev/et/if_et.c:940:	    MHLEN, 0, NULL, NULL, &sc->sc_rx_mini_tag);
sys/dev/et/if_et.c:2381:	m->m_len = m->m_pkthdr.len = MHLEN;
sys/dev/mxge/if_mxge.c:2336:	m->m_len = MHLEN;
sys/dev/mxge/if_mxge.c:2702:		if (length <= (MHLEN - MXGEFW_PAD))
sys/dev/mxge/if_mxge.c:3210:				 MHLEN,			/* maxsize */
sys/dev/mxge/if_mxge.c:3212:				 MHLEN,			/* maxsegsize */
sys/dev/mxge/if_mxge.c:3530:	cmd.data0 = MHLEN - MXGEFW_PAD;
sys/dev/my/if_my.c:1334:	if (m_head->m_pkthdr.len > MHLEN) {
sys/dev/bce/if_bce.c:2967:		sc->rx_bd_mbuf_alloc_size = MHLEN;
sys/dev/bce/if_bce.c:2970:			roundup2(MSIZE - MHLEN, 16) - (MSIZE - MHLEN);
sys/dev/bce/if_bce.c:6579:				 * FCS <= MHLEN).  In other words, the packet is
sys/dev/cxgb/cxgb_main.c:3230:	KASSERT(len <= MHLEN, ("filter request too big for an mbuf"));
sys/dev/usb/wlan/if_zyd.c:2182:	} else if (rlen > (int)MHLEN)
```

### Round 2: ✅ VALID

**🎯 Crux:** In production builds, the KASSERT is removed, allowing an attacker-controlled uint32_t 'cklen' to be passed to m_pullup, leading to kernel memory exhaustion/DoS.

I analyzed the three findings reported. 

1. **m_split Memory Exhaustion**: `m_split` does not allocate `len` bytes; it splits an existing `mbuf` chain at the specified offset. If `len` exceeds the actual length of the chain, `m_split` typically returns NULL or fails without allocating massive amounts of memory. This is not a memory exhaustion vulnerability.

2. **m_trim Signedness**: `m_trim` takes an `int len`. In `xdr_rpc_gss_unwrap_data`, it is called with `uint32_t len` and `uint32_t cklen`. If `len > INT_MAX`, it becomes negative. Inside `m_trim`, `m_getptr(m, len, &off)` is called. If `len` is negative, `m_getptr` will treat it as a very large unsigned value (since `m_getptr` takes `size_t` for length in BSD). This leads to an out-of-bounds access attempt. However, there is a critical prerequisite: `len` must be greater than `INT_MAX` AND the `mbuf` chain must actually contain that much data for `m_getptr` to not simply return NULL. Since the data comes from the network, the total length of the `mbuf` chain is limited by the network stack's maximum packet size (usually ~64KB or slightly more for jumbo frames), which is far less than `INT_MAX` (2GB). Thus, `len` can never be large enough to wrap into a negative `int` while also being a valid length for an existing mbuf chain. Any value > `INT_MAX` will cause `m_getptr` to return NULL immediately because the chain is too short.

3. **m_pullup and KASSERT**: This is the real issue. `cklen` is read as a `uint32_t` from the network. The only check is `KASSERT(cklen <= MHLEN)`, which is removed in production. Then, `m_pullup(mic, cklen)` is called. `m_pullup` attempts to make `cklen` bytes contiguous. If `cklen` is large (e.g., 1GB), `m_pullup` will attempt to allocate a contiguous buffer of that size using `malloc` or `m_get`. This is a classic 'attacker-controlled allocation size' vulnerability leading to kernel memory exhaustion or a panic (DoS).

Verification of `MHLEN`: The grep shows `MHLEN` is approximately 168 bytes. The `KASSERT` was intended to ensure the checksum fit in a single mbuf, but because it's a `KASSERT`, production code allows any `uint32_t` to reach `m_pullup`.

CRUX: In production builds, the KASSERT is removed, allowing an attacker-controlled uint32_t 'cklen' to be passed to m_pullup, leading to kernel memory exhaustion/DoS.
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
usr.sbin/ppp/ipcp.c:1467:      bp = m_pullup(bp);
usr.sbin/ppp/nat_cmd.c:507:  bp = m_pullup(m_append(bp, NULL, NAT_EXTRABUF));
usr.sbin/ppp/nat_cmd.c:529:  bp = m_pullup(m_append(bp, NULL, NAT_EXTRABUF));
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
usr.sbin/ppp/ipv6cp.c:446:      bp = m_pullup(bp);
usr.sbin/ppp/vjcomp.c:80:  bp = m_pullup(bp);
```

### Round 3: ✅ VALID

**🎯 Crux:** The only check on `cklen` before it is passed to `m_pullup` is a `KASSERT`, which is absent in production builds, allowing attacker-controlled memory allocation requests.

The report flags three issues. First, `m_split` with an attacker-controlled length is not a memory exhaustion bug because `m_split` only separates an existing mbuf chain; it doesn't allocate new memory proportional to the requested length. Second, the signedness mismatch in `m_trim` is not exploitable because the total length of a network-received mbuf chain is limited (typically ~64KB), meaning a value exceeding `INT_MAX` (2GB) will cause `m_getptr` to return NULL immediately rather than causing an out-of-bounds access. Third, the `m_pullup` issue is a valid DoS. In `xdr_rpc_gss_unwrap_data`, `cklen` is read from the network as a `uint32_t`. The only check against it is `KASSERT(cklen <= MHLEN)`, which is removed in production builds. This allows an attacker to pass an arbitrary 32-bit value to `m_pullup`. `m_pullup` attempts to create a contiguous buffer of the requested size. If an attacker provides a very large `cklen`, the kernel will attempt a massive allocation, leading to kernel memory exhaustion or a panic. This is a classic attacker-controlled allocation size vulnerability.

CRUX: The only check on `cklen` before it is passed to `m_pullup` is a `KASSERT`, which is absent in production builds, allowing attacker-controlled memory allocation requests.
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
usr.sbin/ppp/cbcp.c:636:  bp = m_pullup(bp);
usr.sbin/ppp/pap.c:232:      bp = m_pullup(bp);
usr.sbin/ppp/hdlc.c:315:  bp = m_pullup(bp);
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
usr.sbin/ppp/ipv6cp.c:446:      bp = m_pullup(bp);
```

### Round 4: ✅ VALID

[ARBITER] In `xdr_rpc_gss_unwrap_data`, the variable `cklen` is read directly from the network via `get_uint32`. The only check ensuring `cklen` is reasonable is `KASSERT(cklen <= MHLEN, ...)`, which is stripped in production builds. This allows an attacker to pass an arbitrary `uint32_t` value to `m_pullup(mic, cklen)`. In BSD mbuf implementations, `m_pullup` attempts to make the specified length contiguous, which can lead to significant kernel memory allocation or failure (DoS) when provided with a massive value from an untrusted source.

