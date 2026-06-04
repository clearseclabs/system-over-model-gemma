# Triage T0147: Logic Error in `m_trim` leading to Out-of-Bounds Access

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Logic Error in `m_trim` leading to Out-of-Bounds Access

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** m_getptr returns NULL if len is out of bounds, and the subsequent 'if (n)' check prevents any invalid assignment to m_len.

The reported vulnerability suggests that `m_trim` causes an out-of-bounds access or inconsistent state because `n->m_len = off` truncates the mbuf to the start of the segment containing the `len`-th byte, rather than the `len`-th byte itself. Let's analyze `m_trim`: 
1. `n = m_getptr(m, len, &off);` - `m_getptr` returns a pointer to the `len`-th byte of the chain and sets `off` to the offset of that byte within the mbuf `n`.
2. `n->m_len = off;` - This sets the length of the mbuf `n` to be exactly the number of bytes *before* the `len`-th byte in that specific mbuf segment. 

Wait, if `len` is the total number of bytes we want to keep across the chain, and `off` is the offset within the final mbuf, then the total length of the chain is (sum of previous mbufs' lengths) + `off`. This effectively keeps exactly `len` bytes in the chain. This is the standard way to truncate an mbuf chain to a specific length in BSD-derived kernels.

Regarding the attacker's control: in `xdr_rpc_gss_unwrap_data`, `len` (for privacy) or `cklen` (for integrity) is read via `get_uint32` from the network. However, `m_trim` is only called if `len != RNDUP(len)`. If `len` is very large, `m_getptr(m, len, &off)` will return `NULL` if `len` exceeds the total length of the mbuf chain. The code explicitly checks `if (n)`, so if `len` is too large, `m_trim` does nothing and the original mbuf remains. This is not an OOB write; it's a no-op. If `len` is within bounds, it performs a valid truncation. There is no memory corruption or OOB access occurring here.

CRUX: m_getptr returns NULL if len is out of bounds, and the subsequent 'if (n)' check prevents any invalid assignment to m_len.
GREP: m_getptr

🔎 **Grep results:**

GREP `m_getptr`:
```
sys/sys/mbuf.h:856:struct mbuf	*m_getptr(struct mbuf *, int, int *);
sys/netinet/sctputil.h:131:caddr_t sctp_m_getptr(struct mbuf *, int, int, uint8_t *);
sys/netinet6/mld6.c:2449:	 * may potentially use clusters; use m_getptr() in this case.
sys/netinet6/mld6.c:2468:			md = m_getptr(m, 0, &off);
sys/netinet6/mld6.c:2549:		md = m_getptr(m, 0, &off);
sys/netinet6/mld6.c:2736:				md = m_getptr(m, npbytes -
sys/netinet6/mld6.c:3100:	md = m_getptr(m0, sizeof(struct ip6_hdr), &off);
sys/dev/sound/pci/hda/hdac.c:2153:hdac_stream_getptr(device_t dev, device_t child, int dir, int stream)
sys/dev/sound/pci/hda/hdac.c:2206:	DEVMETHOD(hdac_stream_getptr,	hdac_stream_getptr),
sys/dev/sound/pci/hda/hdacc.c:694:hdacc_stream_getptr(device_t dev, device_t child, int dir, int stream)
sys/dev/sound/pci/hda/hdacc.c:788:	DEVMETHOD(hdac_stream_getptr,	hdacc_stream_getptr),
sys/dev/mana/mana_en.c:772:	mbuf_next = m_getptr(mbuf, ehlen, &offset);
sys/dev/gve/gve_tx.c:667:	mbuf_next = m_getptr(mbuf, l3_off, &offset);
sys/dev/gve/gve_tx.c:674:		mbuf_next = m_getptr(mbuf, l4_off, &offset);
sys/dev/gve/gve_tx.c:680:		mbuf_next = m_getptr(mbuf, l4_off, &offset);
sys/dev/ena/ena_datapath.c:761:	mbuf_next = m_getptr(mbuf, ehdrlen, &offset);
sys/dev/ena/ena_datapath.c:784:	mbuf_next = m_getptr(mbuf, iphlen + ehdrlen, &offset);
sys/netpfil/pf/pf_norm.c:971:	m = m_getptr(m, hdrlen + offsetof(struct ip6_frag, ip6f_nxt), &off);
sys/netpfil/pf/pf_norm.c:1002:		m = m_getptr(m, extoff + offsetof(struct ip6_ext, ip6e_nxt),
sys/netpfil/pf/pf_norm.c:1070:		m = m_getptr(m, extoff + offsetof(struct ip6_ext, ip6e_nxt),
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:212:	n = m_getptr(m, len, &off);
sys/opencrypto/criov.c:792:	m = m_getptr(m, (int)skip, &rel_off);
sys/netipsec/ipsec_mbuf.c:246:	m1 = m_getptr(m, skip, &roff);
sys/netipsec/ipsec_mbuf.c:312:	struct mbuf *m = m_getptr(m0, off, &roff);
sys/kgssapi/krb5/krb5_mech.c:1669:	n = m_getptr(m, len, &off);
sys/kgssapi/krb5/krb5_mech.c:1792:		n = m_getptr(m, tlen + datalen - 1, &i);
sys/kgssapi/krb5/krb5_mech.c:1795:		 * in the mbuf list, m_getptr() will return the last mbuf in
sys/netinet/sctp_output.c:11581:	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_output.c:11605:		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_auth.c:1379:	phdr = (struct sctp_paramhdr *)sctp_m_getptr(m, offset,
```

### Round 2: ❌ INVALID

**🎯 Crux:** m_getptr returns NULL if the requested length is out of bounds, and the subsequent 'if (n)' check prevents any invalid write to m_len.

The reported vulnerability claims that `m_trim` causes an out-of-bounds access or inconsistent state by setting `n->m_len = off`. However, `m_getptr(m, len, &off)` is designed specifically to find the mbuf containing the `len`-th byte and return the offset `off` of that byte relative to the start of that mbuf's data area. By setting `n->m_len = off` and freeing all subsequent mbufs in the chain (`m_freem(n->m_next)`), the function correctly truncates the total length of the mbuf chain to exactly `len` bytes. This is standard mbuf manipulation in BSD-derived kernels. 

Furthermore, the attacker-controlled `len` is passed to `m_getptr`. If `len` exceeds the actual total length of the mbuf chain, `m_getptr` returns `NULL`. The code explicitly checks `if (n)` before attempting to modify `m_len`. Therefore, if an attacker provides a `len` value that is too large, the function simply does nothing (a no-op), and no memory corruption or out-of-bounds write occurs. There is no path to a security-relevant vulnerability.

CRUX: m_getptr returns NULL if the requested length is out of bounds, and the subsequent 'if (n)' check prevents any invalid write to m_len.
GREP: m_getptr

🔎 **Grep results:**

GREP `m_getptr`:
```
sys/sys/mbuf.h:856:struct mbuf	*m_getptr(struct mbuf *, int, int *);
sys/netinet/sctputil.h:131:caddr_t sctp_m_getptr(struct mbuf *, int, int, uint8_t *);
sys/opencrypto/criov.c:792:	m = m_getptr(m, (int)skip, &rel_off);
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:212:	n = m_getptr(m, len, &off);
sys/netinet6/mld6.c:2449:	 * may potentially use clusters; use m_getptr() in this case.
sys/netinet6/mld6.c:2468:			md = m_getptr(m, 0, &off);
sys/netinet6/mld6.c:2549:		md = m_getptr(m, 0, &off);
sys/netinet6/mld6.c:2736:				md = m_getptr(m, npbytes -
sys/netinet6/mld6.c:3100:	md = m_getptr(m0, sizeof(struct ip6_hdr), &off);
sys/netpfil/pf/pf_norm.c:971:	m = m_getptr(m, hdrlen + offsetof(struct ip6_frag, ip6f_nxt), &off);
sys/netpfil/pf/pf_norm.c:1002:		m = m_getptr(m, extoff + offsetof(struct ip6_ext, ip6e_nxt),
sys/netpfil/pf/pf_norm.c:1070:		m = m_getptr(m, extoff + offsetof(struct ip6_ext, ip6e_nxt),
sys/dev/sound/pci/hda/hdac.c:2153:hdac_stream_getptr(device_t dev, device_t child, int dir, int stream)
sys/dev/sound/pci/hda/hdac.c:2206:	DEVMETHOD(hdac_stream_getptr,	hdac_stream_getptr),
sys/dev/sound/pci/hda/hdacc.c:694:hdacc_stream_getptr(device_t dev, device_t child, int dir, int stream)
sys/dev/sound/pci/hda/hdacc.c:788:	DEVMETHOD(hdac_stream_getptr,	hdacc_stream_getptr),
sys/dev/mana/mana_en.c:772:	mbuf_next = m_getptr(mbuf, ehlen, &offset);
sys/dev/gve/gve_tx.c:667:	mbuf_next = m_getptr(mbuf, l3_off, &offset);
sys/dev/gve/gve_tx.c:674:		mbuf_next = m_getptr(mbuf, l4_off, &offset);
sys/dev/gve/gve_tx.c:680:		mbuf_next = m_getptr(mbuf, l4_off, &offset);
sys/dev/ena/ena_datapath.c:761:	mbuf_next = m_getptr(mbuf, ehdrlen, &offset);
sys/dev/ena/ena_datapath.c:784:	mbuf_next = m_getptr(mbuf, iphlen + ehdrlen, &offset);
sys/netipsec/ipsec_mbuf.c:246:	m1 = m_getptr(m, skip, &roff);
sys/netipsec/ipsec_mbuf.c:312:	struct mbuf *m = m_getptr(m0, off, &roff);
sys/kgssapi/krb5/krb5_mech.c:1669:	n = m_getptr(m, len, &off);
sys/kgssapi/krb5/krb5_mech.c:1792:		n = m_getptr(m, tlen + datalen - 1, &i);
sys/kgssapi/krb5/krb5_mech.c:1795:		 * in the mbuf list, m_getptr() will return the last mbuf in
sys/netinet/sctp_output.c:11581:	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_output.c:11605:		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_auth.c:1379:	phdr = (struct sctp_paramhdr *)sctp_m_getptr(m, offset,
```

### Round 3: ❌ INVALID

**🎯 Crux:** m_getptr returns NULL if the requested length exceeds the total mbuf chain length, and the 'if (n)' check in m_trim prevents any invalid memory writes.

The reported vulnerability claims that `m_trim` can lead to out-of-bounds access because `n->m_len = off` truncates the mbuf chain to the start of the segment containing the `len`-th byte. However, the analysis of the mbuf API in BSD-derived kernels confirms that `m_getptr(m, len, &off)` returns the mbuf containing the `len`-th byte and the offset `off` from the start of that mbuf's data. Setting `n->m_len = off` and freeing `n->m_next` correctly truncates the chain so that the total remaining length is exactly `len` bytes. Regarding attacker-controlled input, `len` is read from the network via `get_uint32`. If an attacker provides a `len` that exceeds the actual length of the mbuf chain, `m_getptr` returns `NULL`. The code explicitly checks `if (n)` before performing any modification, meaning an out-of-bounds `len` results in a no-op, not a crash or memory corruption. There is no evidence of an integer overflow or an inconsistent state that could be exploited.

CRUX: m_getptr returns NULL if the requested length exceeds the total mbuf chain length, and the 'if (n)' check in m_trim prevents any invalid memory writes.
GREP: m_getptr

🔎 **Grep results:**

GREP `m_getptr`:
```
sys/sys/mbuf.h:856:struct mbuf	*m_getptr(struct mbuf *, int, int *);
sys/netinet/sctputil.h:131:caddr_t sctp_m_getptr(struct mbuf *, int, int, uint8_t *);
sys/opencrypto/criov.c:792:	m = m_getptr(m, (int)skip, &rel_off);
sys/netinet6/mld6.c:2449:	 * may potentially use clusters; use m_getptr() in this case.
sys/netinet6/mld6.c:2468:			md = m_getptr(m, 0, &off);
sys/netinet6/mld6.c:2549:		md = m_getptr(m, 0, &off);
sys/netinet6/mld6.c:2736:				md = m_getptr(m, npbytes -
sys/netinet6/mld6.c:3100:	md = m_getptr(m0, sizeof(struct ip6_hdr), &off);
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:212:	n = m_getptr(m, len, &off);
sys/dev/sound/pci/hda/hdac.c:2153:hdac_stream_getptr(device_t dev, device_t child, int dir, int stream)
sys/dev/sound/pci/hda/hdac.c:2206:	DEVMETHOD(hdac_stream_getptr,	hdac_stream_getptr),
sys/dev/sound/pci/hda/hdacc.c:694:hdacc_stream_getptr(device_t dev, device_t child, int dir, int stream)
sys/dev/sound/pci/hda/hdacc.c:788:	DEVMETHOD(hdac_stream_getptr,	hdacc_stream_getptr),
sys/dev/mana/mana_en.c:772:	mbuf_next = m_getptr(mbuf, ehlen, &offset);
sys/dev/gve/gve_tx.c:667:	mbuf_next = m_getptr(mbuf, l3_off, &offset);
sys/dev/gve/gve_tx.c:674:		mbuf_next = m_getptr(mbuf, l4_off, &offset);
sys/dev/gve/gve_tx.c:680:		mbuf_next = m_getptr(mbuf, l4_off, &offset);
sys/dev/ena/ena_datapath.c:761:	mbuf_next = m_getptr(mbuf, ehdrlen, &offset);
sys/dev/ena/ena_datapath.c:784:	mbuf_next = m_getptr(mbuf, iphlen + ehdrlen, &offset);
sys/netpfil/pf/pf_norm.c:971:	m = m_getptr(m, hdrlen + offsetof(struct ip6_frag, ip6f_nxt), &off);
sys/netpfil/pf/pf_norm.c:1002:		m = m_getptr(m, extoff + offsetof(struct ip6_ext, ip6e_nxt),
sys/netpfil/pf/pf_norm.c:1070:		m = m_getptr(m, extoff + offsetof(struct ip6_ext, ip6e_nxt),
sys/kgssapi/krb5/krb5_mech.c:1669:	n = m_getptr(m, len, &off);
sys/kgssapi/krb5/krb5_mech.c:1792:		n = m_getptr(m, tlen + datalen - 1, &i);
sys/kgssapi/krb5/krb5_mech.c:1795:		 * in the mbuf list, m_getptr() will return the last mbuf in
sys/netipsec/ipsec_mbuf.c:246:	m1 = m_getptr(m, skip, &roff);
sys/netipsec/ipsec_mbuf.c:312:	struct mbuf *m = m_getptr(m0, off, &roff);
sys/netinet/sctp_output.c:11581:	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_output.c:11605:		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_auth.c:1379:	phdr = (struct sctp_paramhdr *)sctp_m_getptr(m, offset,
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability report claims that `m_trim` leads to out-of-bounds access or an inconsistent state by setting `n->m_len = off`. However, `m_getptr(m, len, &off)` is the standard BSD mbuf function designed specifically to find the mbuf containing the `len`-th byte and return the offset `off` of that byte from the start of that mbuf's data area. By setting `n->m_len = off` and freeing subsequent mbufs in the chain, `m_trim` correctly truncates the total length of the chain to exactly `len` bytes. Furthermore, `m_getptr` returns `NULL` if `len` is out of bounds, and the `if (n)` check prevents any invalid memory writes. The logic is a standard implementation of mbuf truncation.

