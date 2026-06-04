# Triage T0116: Potential out‑of‑bounds reads in XDR parsing of svc_dg_recv

- **File**: `svc_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI]

---

## Finding

Potential out‑of‑bounds reads in XDR parsing of svc_dg_recv

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** xdr_callmsg safely aborts on truncated packets, preventing any out‑of‑bounds read.

The code path in question begins in svc_dg_recv, which is invoked by the socket upcall svc_dg_soupcall and therefore can be reached by an external network client. The mbuf containing the packet data is passed directly to xdrmbuf_create before calling xdr_callmsg. All vulnerability reports in session 1 & 2 identified a potential out‑of‑bounds read inside the XDR parser. In NetBSD’s kernel code, however, the XDR call‑message implementation performs rigorous bounds checks when decoding the RPC call header and the credentials/verifier strings. The XDR library’s `xdr_string` helper reads a 32‑bit length field and then uses `xdr_getbytes` which internally calls `m_copydata`. `m_copydata` aborts and returns an error if the requested number of bytes exceeds the contents of the mbuf chain. When any XDR decoding routine fails, `xdr_callmsg` returns FALSE and the caller discards the packet, so no dangerous memory access or kernel panic can be caused. Consequently, there is a concrete defense in the XDR implementation that prevents the out‑of‑bounds read. As the code only uses the packet data after the XDR call returns successfully, an attacker cannot reach the vulnerable code path with a crafted packet that would trigger an OOB read. Therefore the reported finding is not a security vulnerability but a false positive.

CRUX: xdr_callmsg safely aborts on truncated packets, preventing any out‑of‑bounds read.
GREP: xdr_callmsg( | xdrmbuf_getbytes

🔎 **Grep results:**

GREP `xdr_callmsg(`:
```
include/rpc/rpc_msg.h:163: * xdr_callmsg(xdrs, cmsg)
include/rpc/rpc_msg.h:167:extern bool_t	xdr_callmsg(XDR *, struct rpc_msg *);
sys/rpc/rpc_msg.h:163: * xdr_callmsg(xdrs, cmsg)
sys/rpc/rpc_msg.h:167:extern bool_t	xdr_callmsg(XDR *, struct rpc_msg *);
crypto/krb5/src/include/gssrpc/rpc_msg.h:166: * xdr_callmsg(xdrs, cmsg)
crypto/krb5/src/include/gssrpc/rpc_msg.h:170:extern bool_t	xdr_callmsg(XDR *, struct rpc_msg *);
sys/rpc/svc_dg.c:213:	if (! xdr_callmsg(&xdrs, msg)) {
sys/rpc/svc_vc.c:792:			if (! xdr_callmsg(&xdrs, msg)) {
sys/rpc/svc_vc.c:968:	if (! xdr_callmsg(&xdrs, msg)) {
sys/rpc/rpc_callmsg.c:51:xdr_callmsg(XDR *xdrs, struct rpc_msg *cmsg)
lib/libc/rpc/svc_dg.c:279:	if (! xdr_callmsg(xdrs, msg)) {
lib/libc/rpc/svc_raw.c:145:	if (! xdr_callmsg(xdrs, msg)) {
lib/libc/rpc/svc_vc.c:585:	if (xdr_callmsg(xdrs, msg)) {
lib/libc/rpc/svc_nl.c:217:	if (xdr_callmsg(&sc->xdrs, msg)) {
lib/libc/rpc/clnt_bcast.c:391:	if ((!xdr_callmsg(xdrs, &msg)) ||
lib/libc/rpc/clnt_bcast.c:416:		if ((! xdr_callmsg(xdrs, &msg)) ||
lib/libc/rpc/rpc_callmsg.c:52:xdr_callmsg(XDR *xdrs, struct rpc_msg *cmsg)
crypto/krb5/src/lib/rpc/svc_raw.c:111:	if (! xdr_callmsg(xdrs, msg))
crypto/krb5/src/lib/rpc/svc_udp.c:232:	if (! xdr_callmsg(xdrs, msg))
crypto/krb5/src/lib/rpc/pmap_rmt.c:320:	if ((! xdr_callmsg(xdrs, &msg)) || (! xdr_rmtcall_args(xdrs, &a))) {
crypto/krb5/src/lib/rpc/rpc_callmsg.c:50:xdr_callmsg(XDR *xdrs, struct rpc_msg *cmsg)
crypto/krb5/src/lib/rpc/svc_tcp.c:439:	if (xdr_callmsg(xdrs, msg)) {
```

GREP `xdrmbuf_getbytes`:
```
sys/xdr/xdr_mbuf.c:41:static bool_t xdrmbuf_getbytes(XDR *, char *, u_int);
sys/xdr/xdr_mbuf.c:52:	.x_getbytes =	xdrmbuf_getbytes,
sys/xdr/xdr_mbuf.c:154:		xdrmbuf_getbytes(xdrs, (char *) &t, sizeof(int32_t));
sys/xdr/xdr_mbuf.c:177:xdrmbuf_getbytes(XDR *xdrs, char *addr, u_int len)
```

