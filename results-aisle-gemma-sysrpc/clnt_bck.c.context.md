# Context: clnt_bck.c

This briefing covers `clnt_bck.c`, which implements the NFSv4.1 session backchannel for callback RPCs.

**1. Role & Location**
This code provides a client-side RPC implementation that leverages an existing TCP connection (created by the client to the server) to send callback requests. It sits within the kernel RPC layer.

**2. Untrusted Input Path**
Untrusted input enters via the network. The server sends RPC replies which are received by the TCP stack, passed to the RPC service layer, and eventually delivered to `clnt_bck_svccall` as an `mbuf` chain (`mrep`).

**3. Attacker-Controlled Data**
*   **`mrep` (mbuf chain):** Carries the raw network response. 
*   **`xid` (uint32_t):** The transaction ID used to match replies to requests.
*   **Flow:** `clnt_bck_svccall` $\rightarrow$ `cr->cr_mrep` $\rightarrow$ `xdrmbuf_create` $\rightarrow$ `xdr_replymsg` $\rightarrow$ `reply_msg`.

**4. Fixed-Size Buffers & Constants**
*   `ct->ct_mcallc` (inside `struct ct_data`): Used with `MCALL_MSG_SIZE`.
    *   GREP: `MCALL_MSG_SIZE` value.
*   `mreq` initial header space: `sizeof(uint32_t)` (4 bytes).
*   `TLS_MAX_MSG_SIZE_V10_2`: Used for KERN_TLS message fragmentation.
    *   GREP: `TLS_MAX_MSG_SIZE_V10_2` value.

**5. Dangerous Data Flows**
*   **Source:** `mrep` (network) $\rightarrow$ **Destination:** `reply_msg` (stack) via `xdr_replymsg` in `clnt_bck_call`.
*   **Source:** `mrep` (network) $\rightarrow$ **Destination:** `results` (heap) via `xdrmbuf_getall` in `clnt_bck_call`.

**6. Potential NULL Dereferences**
*   `ext->rc_auth` or `ext->rc_err` if `ext` is provided but partially initialized.
*   `xprt->xp_socket` in `sosend` if the transport is malformed.

**7. Tagged Unions/Variants**
*   `struct rpc_msg reply_msg` is a union of `rm_call` and `rm_reply`. The code accesses `reply_msg.rm_reply` and `reply_msg.acpted_rply` after `xdr_replymsg` returns `ok`, implying the XDR layer performs the type validation.

**8. API vs. Helpers**
*   **Public API:** `clnt_bck_create`, `clnt_bck_call`, `clnt_bck_svccall`.
*   **Static Helpers:** `clnt_bck_geterr`, `clnt_bck_freeres`, `clnt_bck_abort`, `clnt_bck_control`, `clnt_bck_close`, `clnt_bck_destroy`. These are called via the `clnt_ops` function pointer table.

**9. Likely Bug Classes**
*   **Memory Corruption:** Buffer overflows during XDR decoding of `mrep`.
*   **Race Conditions:** State transitions between `ct_closing` and `ct_closed` involving `msleep`/`wakeup`.
*   **Resource Exhaustion:** `mbuf` leaks if `xdr_replymsg` fails or if `ct_pending` grows unboundedly.

[GREP RESULTS from codebase]:
GREP `MCALL_MSG_SIZE` value. (simplified to: MCALL_MSG_SIZE)`:
```
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_dg.c:152:#define	MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
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
lib/libc/rpc/clnt_raw.c:67:	    char 		mashl_callmsg[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_dg.c:168:	char			cu_outhdr[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:110:		char	ct_mcallc[MCALL_MSG_SIZE];	/* marshalled callmsg */
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:286:	assert(ct->ct_mpos + sizeof(uint32_t) <= MCALL_MSG_SIZE);
crypto/krb5/src/lib/rpc/clnt_tcp.c:98:	  char		ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
crypto/krb5/src/lib/rpc/clnt_tcp.c:215:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcall, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_raw.c:60:	  char	            mashl_callmsg[MCALL_MSG_SIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:113:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
```

GREP `TLS_MAX_MSG_SIZE_V10_2` value. (simplified to: TLS_MAX_MSG_SIZE_V10_2)`:
```
sys/opencrypto/ktls.h:31:#define	MAX_TLS_PAGES	(1 + btoc(TLS_MAX_MSG_SIZE_V10_2))
sys/sys/ktls.h:46:#define	TLS_MAX_MSG_SIZE_V10_2	16384
sys/rpc/clnt_bck.c:305:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/svc_vc.c:1026:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/svc_vc.c:1109:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/clnt_vc.c:421:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/kern/uipc_ktls.c:722:	tls->params.max_frame_len = min(TLS_MAX_MSG_SIZE_V10_2, ktls_maxlen);
sys/kern/uipc_ktls.c:2535:		    tls->params.tls_hlen + TLS_MAX_MSG_SIZE_V10_2 +
tests/sys/kern/ktls_test.c:1188:	outbuf_cap = tls_header_len(en) + TLS_MAX_MSG_SIZE_V10_2 +
tests/sys/kern/ktls_test.c:1335:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1505:	outbuf_cap = tls_header_len(en) + TLS_MAX_MSG_SIZE_V10_2 +
tests/sys/kern/ktls_test.c:1537:				if (todo > TLS_MAX_MSG_SIZE_V10_2 - padding)
tests/sys/kern/ktls_test.c:1538:					todo = TLS_MAX_MSG_SIZE_V10_2 - padding;
tests/sys/kern/ktls_test.c:1623:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1712:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1753:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1795:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1837:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:2383:	    TLS_MAX_MSG_SIZE_V10_2 * 2)
```