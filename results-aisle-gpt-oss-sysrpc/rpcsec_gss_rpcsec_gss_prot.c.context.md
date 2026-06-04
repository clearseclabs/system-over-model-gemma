# Context: rpcsec_gss/rpcsec_gss_prot.c

**Context Briefing – `rpcsec_gss/rpcsec_gss_prot.c` (~250 words)**  

1. **What it does and placement**  
   `rpcsec_gss_prot.c` implements the XDR encoding/decoding of GSS‑API credentials and the wrap/unwrap logic that protects RPC arguments. It lives in the RPCSEC_GSS kernel module (FreeBSD’s RPC security layer) and is invoked by the RPC server when an RPCSEC_GSS call arrives.  

2. **Path of untrusted input**  
   Input originates from the network: client‑side RPC calls are received in the kernel, the raw payload is stored in an `mbuf` chain (`args`/`results`) that is later decoded by `xdr_rpc_gss_cred`, `xdr_rpc_gss_init_res`, `xdr_rpc_gss_wrap_data` and `xdr_rpc_gss_unwrap_data`.  

3. **Attacker‑controlled variables**  
   * `p->gc_handle` (gss_buffer_desc) and `p->gc_token` – arbitrary byte sequences supplied by the client.  
   * `p->gc_proc`, `p->gc_svc`, `p->gc_seq` – integer fields that control the wrap/unwrap flow.  
   * `args`/`results` mbuf chains – carry the RPC arguments, the client may control their size/content.  
   * `seq` – sequence number inserted by the caller (may be manipulated).  

4. **Fixed‑size buffers / constants**  
   * `MAX_GSS_SIZE = 10240` (GSS buffer ceiling).  
   * `zpad[4]` – 4‑byte padding array.  
   * `MHLEN` – maximum data per mbuf (GREP: `MHLEN`).  
   * `RNDUP(len)` rounds up to the next multiple of 4 (GREP: `#define RNDUP`).  

5. **Dangerous data flows**  
   * Attacker data in `args` → `gss_get_mic_mbuf` → `mic` (size ≈ len(args)).  
   * Attacker data in `args` → `gss_wrap_mbuf` → new `args` (size grows).  
   * All these flows are prefixed/terminated with 4‑byte length headers (`put_uint32`).  

6. **NULL derefs**  
   * `get_uint32` may set `*mp = NULL` on `m_pullup` failure; callers check for `NULL`.  
   * `m_trim` guards against `m == NULL`.  

7. **Tagged unions**  
   No union fields accessed without a corresponding type tag.  

8. **API vs static**  
   * Public: `xdr_rpc_gss_wrap_data`, `xdr_rpc_gss_unwrap_data`.  
   * Static helpers: `get_uint32`, `put_uint32`, `m_trim`. All static helpers are called only from the two public functions.  

9. **Likely bug classes**  
   * Buffer‑overflow or assertion (`KASSERT(cklen <= MHLEN)`) when a client supplies an oversized checksum → denial of service.  
   * Mis‑padding if `RNDUP` miscalculated or if length fields are forged.  
   * Integer under/overflow in length handling (e.g., `len = m_length(args, NULL)` could overflow the 32‑bit counter).  
   * Inadequate checks after `m_pullup` could lead to a use‑after‑free in rare edge cases.  
   * Overall, classes around unchecked length fields, improper buffer sizing, and potential kernel panics are the most relevant.

*GREP: `MHLEN`  
GREP: `#define RNDUP`*

[GREP RESULTS from codebase]:
GREP `MHLEN`).`:
```
(no matches in repo)
```

GREP `#define RNDUP`). (simplified to: define)`:
```
libexec/fingerd/fingerd.c:63:#define	ENTRIES	50
libexec/fingerd/fingerd.c:202:#define MSG ": cannot execute\n"
libexec/fingerd/pathnames.h:32:#define	_PATH_FINGER	"/usr/bin/finger"
share/examples/scsi_target/scsi_target.h:32:#define _SCSI_TARGET_H
share/examples/scsi_target/scsi_target.h:38:#define MAX_INITIATORS		8
share/examples/scsi_target/scsi_target.h:39:#define	SECTOR_SIZE		512
share/examples/scsi_target/scsi_target.h:40:#define MAX_EVENTS		(MAX_INITIATORS + 5)
share/examples/scsi_target/scsi_target.h:44:#define SID_Addr16	0x0100
share/examples/scsi_target/scsi_target.h:49:#define targ_descr	periph_priv.entries[1].ptr
share/examples/scsi_target/scsi_target.h:128:#define	OFF_FMT	"%ju"
share/examples/scsi_target/scsi_target.h:130:#define	OFF_FMT "%llu"
libexec/rpc.rusersd/rusers_proc.c:52:#define _PATH_DEV "/dev"
libexec/talkd/talkd.c:64:#define TIMEOUT 30
libexec/talkd/talkd.c:65:#define MAXIDLE 120
share/examples/scsi_target/scsi_cmds.c:53:#define	REPORT_LUNS	0xa0
share/examples/scsi_target/scsi_cmds.c:60:#define ILLEGAL_CDB	  0xFF
libexec/talkd/announce.c:74:#define max(a,b) ( (a) > (b) ? (a) : (b) )
libexec/talkd/announce.c:75:#define N_LINES 5
libexec/talkd/announce.c:76:#define N_CHARS 256
share/examples/scsi_target/scsi_target.c:57:#define MAX_XFER	MAXPHYS
share/examples/scsi_target/scsi_target.c:59:#define MAX_CTIOS	64
share/examples/scsi_target/scsi_target.c:61:#define MAX_SECTOR	32768
bin/setfacl/setfacl.c:46:#define	OP_MERGE_ACL		0x00	/* merge acl's (-mM) */
bin/setfacl/setfacl.c:47:#define	OP_REMOVE_DEF		0x01	/* remove default acl's (-k) */
bin/setfacl/setfacl.c:48:#define	OP_REMOVE_EXT		0x02	/* remove extended acl's (-b) */
bin/setfacl/setfacl.c:49:#define	OP_REMOVE_ACL		0x03	/* remove acl's (-xX) */
bin/setfacl/setfacl.c:50:#define	OP_REMOVE_BY_NUMBER	0x04	/* remove acl's (-xX) by acl entry number */
bin/setfacl/setfacl.c:51:#define	OP_ADD_ACL		0x05	/* add acls entries at a given position */
libexec/talkd/print.c:45:#define	NTYPES	(sizeof (types) / sizeof (types[0]))
libexec/talkd/print.c:49:#define	NANSWERS	(sizeof (answers) / sizeof (answers[0]))
```

GREP `MHLEN`:
```
sys/sys/mbuf.h:96:#define	MHLEN		((int)(MSIZE - MPKTHSIZE))
sys/sys/mbuf.h:97:#define	MINCLSIZE	(MHLEN + 1)
sys/netpfil/pf/if_pflog.c:80:#define PFLOGMTU	(32768 + MHLEN + MLEN)
sys/sys/mbuf.h:86: * MHLEN is data length in an mbuf with pktheader.
sys/sys/mbuf.h:358:	 * to MHLEN (space left after a packet header) and MLEN (space left
sys/sys/mbuf.h:1202:	 ((m)->m_flags & M_PKTHDR) ? MHLEN :				\
sys/dev/ixgbe/ixgbe.h:155: * MHLEN is typically 168 bytes, giving us 8-byte alignment.  Getting
sys/fs/nfsclient/nfs_clrpcops.c:5869:			if (stripecnt >= MHLEN / NFSX_UNSIGNED ||
sys/fs/nfs/nfs_commonsubs.c:773:	} else if (siz > MHLEN) {
sys/net/iflib.c:2849:	    ri->iri_frags[0].irf_len <= MIN(IFLIB_RX_COPY_THRESH, MHLEN)) {
sys/netinet/tcp_stacks/rack.c:18429:	if (MHLEN < hdrlen + max_linkhdr)
sys/netinet/tcp_stacks/rack.c:18478:	    (len <= MHLEN - hdrlen - max_linkhdr)) {
sys/netinet/tcp_stacks/rack.c:19006:	if (MHLEN < hdrlen + max_linkhdr)
sys/netinet/tcp_stacks/rack.c:19055:	    (len <= MHLEN - hdrlen - max_linkhdr)) {
sys/netinet/tcp_stacks/rack.c:21328:		if (max_linkhdr + hdrlen > MHLEN)
sys/netinet/tcp_stacks/rack.c:21386:		if (MHLEN < hdrlen + max_linkhdr)
sys/netinet/tcp_stacks/rack.c:21408:		if (len <= MHLEN - hdrlen - max_linkhdr && !hw_tls) {
sys/netinet/tcp_stacks/rack.c:21507:		if (isipv6 && (MHLEN < hdrlen + max_linkhdr) &&
sys/netinet/tcp_stacks/rack.c:21508:		    MHLEN >= hdrlen) {
sys/netinet/tcp_stacks/bbr.c:13026:	if (max_linkhdr + hdrlen > MHLEN)
sys/netinet/tcp_stacks/bbr.c:13069:		if (MHLEN < hdrlen + max_linkhdr)
sys/netinet/tcp_stacks/bbr.c:13134:		if (len <= MHLEN - hdrlen - max_linkhdr && !hw_tls) {
sys/netinet/tcp_stacks/bbr.c:13234:		if (isipv6 && (MHLEN < hdrlen + max_linkhdr) &&
sys/netinet/tcp_stacks/bbr.c:13235:		    MHLEN >= hdrlen) {
sys/net/rtsock.c:1752:	if (len > MHLEN)
sys/netinet6/nd6_nbr.c:453:	if (max_linkhdr + maxlen > MHLEN)
sys/netinet6/nd6_nbr.c:1007:	if (max_linkhdr + maxlen > MHLEN)
sys/netinet/sctp_output.c:6519:		    (sizeofcpy <= (int)((((SCTP_BASE_SYSCTL(sctp_mbuf_threshold_count) - 1) * MLEN) + MHLEN)))) {
sys/netinet6/ip6_input.c:602:		if (m->m_pkthdr.len > MHLEN)
sys/netinet6/ip6_mroute.c:1648:	i = MHLEN - M_LEADINGSPACE(mm);
```