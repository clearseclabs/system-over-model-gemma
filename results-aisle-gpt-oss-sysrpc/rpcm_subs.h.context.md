# Context: rpcm_subs.h

**Context Briefing – `rpcm_subs.h` (≈250 words)**  

`rpcm_subs.h` contains a small set of helper macros that are used by the RPC‑M protocol stack to serialize (`rpcm_build`) and parse (`rpcm_dissect`) network‑bound messages that live in a chain of `struct mbuf`s. The macros are defined in the RPC module of the *NetBSD/OpenBSD* kernel (see header comments – the file was copied from `nfsm_subs.h`). They are invoked from the public RPC request/response handlers (e.g., `xdr_rpcs`, `xdr_rpcm`).  

Untrusted data arrive from the network driver and are carved out into the `md` mbuf chain. The chain is passed to the macros via the parameter `md`. The macros access two global temporaries, `bpos` and `dpos`, as well as the pointer to the current mbuf (`mb` and `md`). Attacker‑controlled data thus enter through `md` → `dpos` → `a` in `rpcm_dissect`, and through `bpos` in `rpcm_build`.  

**Buffer constants**:  
```
GREP: "#define MLEN"
GREP: "#define M_TRAILINGSPACE(mb)"
```
Typical values in the NetBSD/ OpenBSD kernel are `MLEN=1500` and `M_TRAILINGSPACE(mb)` returns the free space after `mb->m_len`. The macro `rpcm_build` additionally uses `M_WAITOK` and `MT_DATA` for `m_get`, a standard kernel allocation macro.  

**Dangerous data flows**:  
1. **Source**: Network packet → `md` mbuf chain.  
   **Destination**: `mb->m_data` (via `mtod`) inside `rpcm_build`.  
   **Function**: `m_get`/`rpcm_build`.  
   **Buffer size**: `MLEN` (sender‑side limit).  
2. **Source**: Network packet → `md` mbuf chain → `dpos` → `cp2`.  
   **Destination**: User variable `a` (typed via cast in the macro).  
   **Function**: `rpcm_disct`.  
   **Buffer size**: `s` (length of the field being read).  

**NULL‑pointer hazards**: `cp2` is assigned from `rpcm_disct`; the macro assumes `rpcm_disct` does not return `NULL` for a malformed request. Also, after `rpcm_adv`, `dpos` can be advanced beyond the chain length if `rpc_adv` fails silently, potentially causing later dereferences of `md->m_next`.  

**Tagged unions**: `rpcm_disct` may return pointers that point into a union of variable‑length fields. The macro does not explicitly check the type tag before reading into `a`.  

**API vs helpers**: `rpcm_build`, `rpcm_dissect`, `rpcm_adv` are *static* macros used only within this translation unit. The underlying helper functions (`rpcm_disct`, `rpcm_adv`, `rpc_adv`, `m_get`) are part of the publicly exposed RPC subsystem and are always called with the sanity checks mandated by the kernel, though the macros themselves do not perform those checks.  

**Likely bug classes**:  
* **Buffer overrun** – using `s` directly on a fixed‑size buffer without enforcing `s <= MLEN`.  
* **Mis‑aligned copy** – calling `mtod` or `bpos` increments without rounding to 4‑byte boundaries (`rpcm_rndup`).  
* **NULL‑dereference** – passing an invalid `md` or `cnt` to `rpcm_disct` and assuming the result (`cp2`) is valid.  
* **Union misuse** – reading from the wrong variant of an XDR‑discriminated union.  

---  

**GREPS for constants (provide actual numeric values)**  
```
GREP: "#define MLEN"
GREP: "#define M_TRAILINGSPACE(mb)"
```

[GREP RESULTS from codebase]:
GREP `#define MLEN`:
```
sys/contrib/libsodium/test/default/aead_chacha20poly1305.c:9:#define MLEN 10U
sys/contrib/libsodium/test/default/aead_chacha20poly1305.c:184:#define MLEN 114U
sys/contrib/libsodium/test/default/aead_xchacha20poly1305.c:9:#define MLEN 114U
```

GREP `#define M_TRAILINGSPACE(mb) (simplified to: M_TRAILINGSPACE)`:
```
sys/sys/mbuf.h:1264:#define	M_TRAILINGSPACE(m) (M_WRITABLE(m) ? M_TRAILINGROOM(m) : 0)
contrib/smbfs/include/netsmb/smb_lib.h:143:#define M_TRAILINGSPACE(m) ((m)->m_maxlen - (m)->m_len)
sys/fs/nfs/nfsm_subs.h:64:	    siz > M_TRAILINGSPACE(nd->nd_mb)) {
sys/sys/mbuf.h:1260: * NB: In previous versions, M_TRAILINGSPACE() would only check M_WRITABLE()
sys/rpc/rpcm_subs.h:81:		{ if ((s) > M_TRAILINGSPACE(mb)) { \
sys/xdr/xdr_mbuf.c:220:		sz = M_TRAILINGSPACE(m) + (m->m_len - xdrs->x_handy);
sys/xdr/xdr_mbuf.c:230:		if (xdrs->x_handy == m->m_len && M_TRAILINGSPACE(m) == 0) {
sys/xdr/xdr_mbuf.c:290:		available = M_TRAILINGSPACE(m) + (m->m_len - xdrs->x_handy);
sys/fs/nfsclient/nfs_clcomsubs.c:84:				mlen = M_TRAILINGSPACE(mp);
sys/fs/nfsclient/nfs_clcomsubs.c:98:					mlen = M_TRAILINGSPACE(mp);
sys/fs/nfsclient/nfs_clcomsubs.c:131:		    M_TRAILINGSPACE(mp)) {
sys/fs/nfsclient/nfs_clcomsubs.c:202:				mlen = M_TRAILINGSPACE(mp);
sys/fs/nfsclient/nfs_clcomsubs.c:216:					mlen = M_TRAILINGSPACE(mp);
sys/fs/nfsclient/nfs_clcomsubs.c:251:		    rem <= M_TRAILINGSPACE(mp),
sys/fs/nfs/nfs_commonsubs.c:883:		left = M_TRAILINGSPACE(m2);
sys/fs/nfs/nfs_commonsubs.c:908:				left = M_TRAILINGSPACE(m1);
sys/fs/nfsserver/nfs_nfsdport.c:941:		siz = min(M_TRAILINGSPACE(m), left);
sys/fs/nfsserver/nfs_nfsdport.c:957:		siz = min(M_TRAILINGSPACE(m), left);
sys/cam/ctl/ctl_ha.c:699:		copylen = min(M_TRAILINGSPACE(mb), len - off);
sys/cam/ctl/ctl_ha.c:710:		copylen = min(M_TRAILINGSPACE(mb), len2 - off);
contrib/smbfs/lib/smb/rq.c:101:		cplen = M_TRAILINGSPACE(m);
contrib/smbfs/lib/smb/mbuf.c:177:		len -= M_TRAILINGSPACE(mp);
contrib/smbfs/lib/smb/mbuf.c:210:	if (M_TRAILINGSPACE(m) < (int)size) {
contrib/smbfs/lib/smb/mbuf.c:294:		cplen = M_TRAILINGSPACE(m);
sys/netinet/sctp_output.c:1960:	if (M_TRAILINGSPACE(m) >= plen) {
sys/netinet/sctp_output.c:5185:					if (M_TRAILINGSPACE(op_err_last) < (int)sizeof(struct sctp_paramhdr)) {
sys/netinet/sctp_output.c:6559:				len = (int)M_TRAILINGSPACE(*endofchain);
sys/netinet/sctp_output.c:6562:				len = (int)M_TRAILINGSPACE(*endofchain);
sys/netinet/sctp_output.c:6880:	cancpy = (int)M_TRAILINGSPACE(ret);
sys/netinet/sctp_output.c:6901:			cancpy = (int)M_TRAILINGSPACE(at);
```

GREP `#define MLEN`:
```
sys/contrib/libsodium/test/default/aead_chacha20poly1305.c:9:#define MLEN 10U
sys/contrib/libsodium/test/default/aead_chacha20poly1305.c:184:#define MLEN 114U
sys/contrib/libsodium/test/default/aead_xchacha20poly1305.c:9:#define MLEN 114U
```