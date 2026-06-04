# Triage T0172: Potential zero-length message via unchecked padding trim

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI→I]

---

## Finding

Potential zero-length message via unchecked padding trim

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** `m_trim` can be invoked with a length of `0` supplied by an attacker, but the consequence is only a graceful failure of the RPC unwrapping routine; it cannot lead to memory corruption or code execution.

The code path in `xdr_rpc_gss_unwrap_data()` for the privacy service reads an unsigned 32‑bit length field (`len`) supplied by the client. It then calls `m_trim(message,len)` where `message` points to the plaintext from the GSS‑API unwrap. `m_trim()` uses `m_getptr()` to locate the requested offset; if the requested length exceeds the actual mbuf length, `m_getptr()` returns NULL and no truncation occurs. If the length is zero, `m_trim()` turns the first mbuf into a zero‑length mbuf and frees the rest, resulting in a decrypted payload of size zero. Immediately after trimming, the code calls `get_uint32(&message)` to read the sequence number. Because the mbuf has length zero, `get_uint32()` pulls up a missing chunk, fails, sets `*mp = NULL` and returns 0. The wrapper then returns `FALSE` and the RPC call fails. No memory write occurs beyond the bounds of the allocated mbuf chain, and no code path accepts a zero‑length message as valid data. Therefore the attacker cannot crash the kernel or achieve arbitrary code execution by manipulating the length field. The observed “zero‑length message” condition simply triggers an error and is handled safely.

No defensive boundary checks are required beyond the forwarding `m_trim()` logic because `m_trim()` itself is safe against oversized lengths. The `KASSERT(cklen <= MHLEN)` guard in the integrity path likewise protects the microblock used for the MIC calculation, and `MHLEN` is a fixed, compile‑time constant.

Hence the reported bug pattern exists only as a non‑security code quality issue and is not attacker‑reachable to cause harm. The vulnerability report is therefore *INVALID*.


CRUX: `m_trim` can be invoked with a length of `0` supplied by an attacker, but the consequence is only a graceful failure of the RPC unwrapping routine; it cannot lead to memory corruption or code execution.
GREP: m_trim\(.*\)

🔎 **Grep results:**

GREP `m_trim(.*)`:
```
sys/fs/nfs/nfs_var.h:790:void nfsm_trimtrailing(struct nfsrv_descript *, struct mbuf *, char *, int,
sys/ufs/ufs/ufsmount.h:112:	uint64_t um_trim_inflight;		/* (i) outstanding trim count */
sys/ufs/ufs/ufsmount.h:113:	uint64_t um_trim_inflight_blks;		/* (i) outstanding trim blks */
sys/ufs/ufs/ufsmount.h:114:	uint64_t um_trim_total;			/* (i) total trim count */
sys/ufs/ufs/ufsmount.h:115:	uint64_t um_trim_total_blks;		/* (i) total trim block count */
sys/ufs/ufs/ufsmount.h:116:	struct	taskqueue *um_trim_tq;		/* (c) trim request queue */
sys/ufs/ufs/ufsmount.h:117:	struct	trimlist_hashhead *um_trimhash;	/* (i) trimlist hash table */
sys/ufs/ufs/ufsmount.h:118:	u_long	um_trimlisthashsize;		/* (i) trim hash table size-1 */
sys/dev/bhnd/nvram/bhnd_nvram_private.h:260:size_t				 bhnd_nvram_trim_field(const char **inp,
sys/dev/bhnd/nvram/bhnd_nvram_private.h:263:const char			*bhnd_nvram_trim_path_name(const char *name);
usr.sbin/bhyve/pci_ahci.c:818:ahci_handle_dsm_trim(struct ahci_port *p, int slot, uint8_t *cfis)
usr.sbin/bhyve/pci_ahci.c:1803:			ahci_handle_dsm_trim(p, slot, cfis);
usr.sbin/bhyve/pci_ahci.c:1813:			ahci_handle_dsm_trim(p, slot, cfis);
sys/fs/nfsserver/nfs_nfsdsocket.c:1365:			nfsm_trimtrailing(nd, mb, bpos, bextpg, bextpgsiz);
sys/fs/nfsserver/nfs_nfsdport.c:3085:			nfsm_trimtrailing(nd, mb0, bpos0, bextpg0, bextpgsiz0);
sys/fs/nfsserver/nfs_nfsdport.c:3089:			nfsm_trimtrailing(nd, mb1, bpos1, bextpg1, bextpgsiz1);
sys/fs/nfsserver/nfs_nfsdport.c:7348:nfsm_trimtrailing(struct nfsrv_descript *nd, struct mbuf *mb, char *bpos,
sys/fs/nfsserver/nfs_nfsdport.c:7360:		    ("nfsm_trimtrailing: bextpg out of range"));
sys/fs/nfsserver/nfs_nfsdport.c:7363:		    ("nfsm_trimtrailing: bextpgsiz bad!"));
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:205:m_trim(struct mbuf *m, int len)
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:269:			m_trim(mic, cklen);
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:291:			m_trim(message, len);
sys/kgssapi/krb5/krb5_mech.c:1662:m_trim(struct mbuf *m, int len)
sys/kgssapi/krb5/krb5_mech.c:1847:		m_trim(m, datalen - 8 - padlen);
sys/kgssapi/krb5/krb5_mech.c:2001:			m_trim(m, plen);
sys/contrib/dev/rtw89/rtw8852bt_rfk.c:3328:static s8 _tssi_get_ofdm_trim_de(struct rtw89_dev *rtwdev, enum rtw89_phy_idx phy,
sys/contrib/dev/rtw89/rtw8852bt_rfk.c:3381:		trim_de = _tssi_get_ofdm_trim_de(rtwdev, phy, i, chan);
sys/contrib/dev/rtw89/rtw8852bt_rfk.c:3398:		trim_de = _tssi_get_ofdm_trim_de(rtwdev, phy, i, chan);
sys/contrib/dev/rtw89/rtw8851b.c:679:	static const u32 thm_trim_addr[RF_PATH_NUM_8851B] = {0x5DF};
sys/contrib/dev/rtw89/rtw8851b.c:684:		info->thermal_trim[i] = phycap_map[thm_trim_addr[i] - addr];
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** `m_trim()` protects against oversized `len` by checking the result of `m_getptr()`; if `len` exceeds the actual buffer length it performs no truncation, so no buffer underrun or crash can be induced.

The attack premise claims that an attacker-controlled length field can cause `m_trim()` in `xdr_rpc_gss_unwrap_data()` to truncate the buffer to zero, bypass downstream checks or crash the unwinder. \n
1. **Source of `len`** – The value is read via `get_uint32(&results)` from the network packet; thus it is fully attacker‑controlled.  \n
2. **Behavior of `m_trim()`** – It calls `m_getptr(m, len, &off)`.  In the FreeBSD mbuf implementation, `m_getptr()` traverses the mbuf chain to the requested offset and returns `NULL` if the offset is beyond the chain’s total length.  The code then checks `if (n) { ... }` before manipulating the mbuf.  Therefore, if `len` exceeds the actual size of `message`, `m_getptr()` returns `NULL` and `m_trim()` performs **no modification** – it does not free the mbuf nor set it to zero length.  Consequently the claim that a large `len` will truncate the buffer to zero is incorrect.  \n
3. **Zero‑length case** – If an attacker supplies `len == 0`, `m_trim()` will set the first mbuf’s `m_len` to zero and free any following mbufs.  This produces an empty ciphertext, and the subsequent call to `gss_unwrap_mbuf()` will fail with a normal error code.  The function then returns `FALSE`; control returns to the RPC server, which treats the request as failed – no crash or code execution occurs.  \n\n4. **No missing bounds check** – The only potentially dangerous area is the `len != RNDUP(len)` branch, but the `m_trim()` guard against over‑read already handles out‑of‑range values.  No unchecked arithmetic or out‑of‑bounds write exists.  \n\n5. **Result** – The reported bug pattern exists only as a code‑quality observation.  The attacker cannot leverage it to crash the kernel, corrupt data, or bypass authentication.  Hence the vulnerability is **INVALID**.

CRUX: `m_trim()` protects against oversized `len` by checking the result of `m_getptr()`; if `len` exceeds the actual buffer length it performs no truncation, so no buffer underrun or crash can be induced.
GREP: m_getptr(

🔎 **Grep results:**

GREP `m_getptr(`:
```
sys/sys/mbuf.h:856:struct mbuf	*m_getptr(struct mbuf *, int, int *);
sys/netinet/sctputil.h:131:caddr_t sctp_m_getptr(struct mbuf *, int, int, uint8_t *);
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:212:	n = m_getptr(m, len, &off);
sys/netinet/sctp_output.c:11581:	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_output.c:11605:		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/opencrypto/criov.c:794:	m = m_getptr(m, (int)skip, &rel_off);
sys/netinet/sctp_auth.c:1379:	phdr = (struct sctp_paramhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_auth.c:1447:		phdr = (struct sctp_paramhdr *)sctp_m_getptr(m, offset, sizeof(struct sctp_paramhdr),
sys/netinet/igmp.c:1229:	 * m_getptr() to walk the chain.
sys/netinet/igmp.c:2872:	 * may potentially use clusters; use m_getptr() in this case.
sys/netinet/igmp.c:2888:			md = m_getptr(m, 0, &off);
sys/netinet/igmp.c:2972:		md = m_getptr(m, 0, &off);
sys/netinet/igmp.c:3162:				md = m_getptr(m, npbytes -
sys/netinet/sctp_indata.c:1702:		chunk = (struct sctp_idata_chunk *)sctp_m_getptr(*m, offset,
sys/netinet/sctp_indata.c:1719:		chunk = (struct sctp_data_chunk *)sctp_m_getptr(*m, offset,
sys/netinet/sctp_indata.c:2699:	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, *offset,
sys/netinet/sctp_indata.c:2888:		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, *offset,
sys/netinet/sctp_indata.c:3190:		frag = (struct sctp_gap_ack_block *)sctp_m_getptr(m, *offset,
sys/netinet/sctp_indata.c:4474:			dupdata = (uint32_t *)sctp_m_getptr(m, offset_dup + i * sizeof(uint32_t),
sys/netinet/sctp_indata.c:5609:				stseq_m = (struct sctp_strseq_mid *)sctp_m_getptr(m, offset,
sys/netinet/sctp_indata.c:5625:				stseq = (struct sctp_strseq *)sctp_m_getptr(m, offset,
sys/netinet/sctputil.c:3036:sctp_m_getptr(struct mbuf *m, int off, int len, uint8_t *in_ptr)
sys/netinet/sctputil.c:3082:	return ((struct sctp_paramhdr *)sctp_m_getptr(m, offset, pull_limit,
sys/netinet/sctputil.c:4562:	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctputil.c:4595:		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctputil.c:4620:	ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset, sizeof(*ch),
sys/netinet/sctputil.c:4636:			init_chk = (struct sctp_init_chunk *)sctp_m_getptr(m,
sys/netinet/sctputil.c:4644:		ch = (struct sctp_chunkhdr *)sctp_m_getptr(m, offset,
sys/netinet/sctp_input.c:1404:	    sctp_m_getptr(m, init_offset, sizeof(struct sctp_init_chunk),
sys/netinet/sctp_input.c:1421:	    sctp_m_getptr(m, initack_offset, sizeof(struct sctp_init_ack_chunk),
```

### Round 4: ❌ INVALID

[ARBITER] FreeBSD’s `m_trim()` only truncates when the supplied length is within the actual mbuf length. When an attacker sends a length larger than the data, `m_getptr()` returns NULL and `m_trim()` does nothing, so no memory corruption or crash occurs. If the length is set to 0, `m_trim()` turns the first mbuf into a zero‑length mbuf; subsequent parsing of the message fails gracefully and the RPC will return FALSE. Therefore the described scenario cannot produce a security effect.

