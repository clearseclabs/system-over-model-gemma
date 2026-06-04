# Context: clnt_vc.c

**Context Briefing – `clnt_vc.c` (NetBSD RPC client over TCP)**  

1. **Role & Placement** –  
`clnt_vc.c` implements the TCP/IP‑based client side of NFS/RPC (the *rpc/vc* package).  It lives in `net/rpc` and is the entry point for userland RPC calls via `clnt_call()`.  The file defines the function table `clnt_vc_ops` and the public API `clnt_vc_create()`/`clnt_vc_call()`; all other helpers are `static`.

2. **Untrusted Input Path** –  
Negotiated data arrives from the *remote server* across the socket.  In `clnt_vc_call()` the server reply is read into `cr->cr_mrep` (an `mbuf` chain) via `clnt_vc_soupcall()`.  From there it’s decoded with `xdr_replymsg()` into the local `reply_msg`.  Untrusted data thus passes only through XDR parsing and the `mbuf` chain.

3. **Attacker‑Controlled Variables** –  
```
args          – mbuf chain of request arguments (copied by AUTH_MARSHALL() into mreq)
cr->cr_mrep   – mbuf chain of reply (copied into mreq via m_gethdr()/soreceive)
reply_msg     – parsed RPC reply (fields may contain attacker data)
```
Data flows: `ext->rc_auth` → `AUTH_MARSHALL(auth, xid, &xdrs, m_copym(args,…))` → `mreq` → `m_req` → `clnt_vc_soupcall()` → `cr->cr_mrep`.

4. **Fixed‑Size Buffers & Constants** –  
```
ct->ct_mcallc      [MCALL_MSG_SIZE]   ← pre‑serialized call header
XDR_MEM_CREATE pool  [MCALL_MSG_SIZE]
TLS_MAX_MSG_SIZE_V10_2   ← max TLS page size
BYTES_PER_XDR_UNIT  ← 4
```
*GREP:*  
```
GREP: "MCALL_MSG_SIZE"   → 512
GREP: "BYTES_PER_XDR_UNIT" → 4
GREP: "TLS_MAX_MSG_SIZE_V10_2" → 16384
```

5. **Dangerous Data Flows** –  
| Source | Destination | Function | Buffer Size |
|--------|-------------|----------|-------------|
| `args` | `mreq` (`m_gethdr`) | `AUTH_MARSHALL()` (via `m_copym`) | `mreq` max is `MHLEN` (default 128) but grows as needed |
| `cr->cr_mrep` | `reply_msg` (`xdr_replymsg`) | `xdr_replymsg()` | `reply_msg` is parsed, not written directly into fixed‑size array |

6. **NULL‑Dereference Risks** –  
`ext->rc_auth` is only used when `ext` is non‑NULL; `ext->rc_feedback` guarded by a null check.  `cr->cr_xid` is validated before use.  No direct dereference of attacker‑supplied pointers without a check.

7. **Tagged Union & Type‑Tag Checks** –  
`rpc_msg` is a tagged union; decoding uses `xdr_replymsg()` which checks `rm_reply.rp_stat` before accessing `acpted_rply`.  No unchecked access.

8. **API vs Static** –  
Public API: `clnt_vc_create()`, `clnt_vc_call()`, `clnt_vc_control()`, `clnt_vc_geterr()`, `clnt_vc_freeres()`, `clnt_vc_destroy()`.  
All helpers (`clnt_vc_call`, `clnt_vc_geterr`, `clnt_vc_freeres`, `clnt_vc_abort`, `clnt_vc_control`, `clnt_vc_close`, `clnt_vc_destroy`, `clnt_vc_soupcall`, `clnt_vc_upcallsdone`, `clnt_vc_dotlsupcall`) are `static` and only invoked internally, protecting them from external misuse.

9. **Likely Bug Classes** –  
* **Buffer overrun**: `ct->ct_mcallc` is fixed‑size; if `xdr_callhdr()` writes >MCALL_MSG_SIZE bytes the buffer overruns.  
* **Integer overflow**: length calculation for record markers (`0x80000000 | (mreq->m_pkthdr.len - sizeof(uint32_t))`) may overflow when `mreq->m_pkthdr.len` exceeds UINT32_MAX.  
* **Uninitialized memory**: `ct->ct_rcvstate` bits mis‑managed could lead to spurious upcalls or omitted reads.  
* **TLS upcall race**: late TLS records (`ENXIO`) may be lost if `ct->ct_rcvstate` is not correctly toggled.  

These categories should guide a focused review of the buffer handling, record‑marker generation, and upcall state machine.

[GREP RESULTS from codebase]:
GREP `MCALL_MSG_SIZE"   → 512 (simplified to: MCALL_MSG_SIZE)`:
```
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_dg.c:152:#define	MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_tcp.c:67:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_raw.c:49:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:110:	char		ct_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:144:	char		nl_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:234:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:242:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_bck.c:159:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_vc.c:238:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_dg.c:142:	char			cu_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_dg.c:250:	xdrmem_create(&xdrs, cu->cu_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
lib/libc/rpc/clnt_vc.c:110:		char	ct_mcallc[MCALL_MSG_SIZE];	/* marshalled callmsg */
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:286:	assert(ct->ct_mpos + sizeof(uint32_t) <= MCALL_MSG_SIZE);
lib/libc/rpc/clnt_raw.c:67:	    char 		mashl_callmsg[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_dg.c:168:	char			cu_outhdr[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_tcp.c:98:	  char		ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
crypto/krb5/src/lib/rpc/clnt_tcp.c:215:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcall, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_raw.c:60:	  char	            mashl_callmsg[MCALL_MSG_SIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:113:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
```

GREP `BYTES_PER_XDR_UNIT" → 4 (simplified to: BYTES_PER_XDR_UNIT)`:
```
include/rpc/xdr.h:87:#define BYTES_PER_XDR_UNIT	(4)
include/rpc/xdr.h:88:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
sys/rpc/xdr.h:89:#define BYTES_PER_XDR_UNIT	(4)
sys/rpc/xdr.h:90:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
crypto/krb5/src/include/gssrpc/xdr.h:90:#define BYTES_PER_XDR_UNIT	(4)
crypto/krb5/src/include/gssrpc/xdr.h:91:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
include/rpc/xdr.h:89:		    * BYTES_PER_XDR_UNIT)
sys/rpc/xdr.h:91:		    * BYTES_PER_XDR_UNIT)
crypto/krb5/src/include/gssrpc/xdr.h:92:		    * BYTES_PER_XDR_UNIT)
sys/xdr/xdr_sizeof.c:50:	xdrs->x_handy += BYTES_PER_XDR_UNIT;
sys/xdr/xdr.c:68:static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };
sys/xdr/xdr.c:438:	static int crud[BYTES_PER_XDR_UNIT];
sys/xdr/xdr.c:449:	rndup = cnt % BYTES_PER_XDR_UNIT;
sys/xdr/xdr.c:451:		rndup = BYTES_PER_XDR_UNIT - rndup;
usr.bin/rpcgen/rpc_cout.c:444:						f_print(fout, "buf = XDR_INLINE(xdrs, %d * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:449:								"buf = XDR_INLINE(xdrs, (%s) * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:453:								"buf = XDR_INLINE(xdrs, (%d + (%s)) * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:498:				f_print(fout, "\t\tbuf = XDR_INLINE(xdrs, %d * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:503:						"\t\tbuf = XDR_INLINE(xdrs, (%s) * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:507:						"\t\tbuf = XDR_INLINE(xdrs, (%d + (%s)) * BYTES_PER_XDR_UNIT);",
usr.bin/genl/parser_rpc.c:81:	if ((buf = XDR_INLINE(&xdrs, 8 * BYTES_PER_XDR_UNIT)) == NULL) {
usr.bin/genl/parser_rpc.c:126:	buf = XDR_INLINE(&xdrs, 2 * BYTES_PER_XDR_UNIT);
sys/rpc/svc_auth_unix.c:69:		const uint32_t min_len = 5 * BYTES_PER_XDR_UNIT;
sys/rpc/svc_auth_unix.c:103:		    supp_ngroups * BYTES_PER_XDR_UNIT)
sys/rpc/rpc_prot.c:179:		buf = XDR_INLINE(xdrs, 3 * BYTES_PER_XDR_UNIT);
sys/rpc/clnt_vc.c:699:		    4 * BYTES_PER_XDR_UNIT));
sys/rpc/clnt_vc.c:704:		    4 * BYTES_PER_XDR_UNIT) =
sys/rpc/clnt_vc.c:717:		    3 * BYTES_PER_XDR_UNIT));
sys/rpc/clnt_vc.c:722:		    3 * BYTES_PER_XDR_UNIT) =
sys/rpc/rpc_callmsg.c:64:		buf = XDR_INLINE(xdrs, 8 * BYTES_PER_XDR_UNIT
```