# Context: clnt_vc.c

This briefing covers `clnt_vc.c`, which implements the client-side RPC-over-TCP (virtual circuit) transport layer.

### 1. Function & Location
This code manages the lifecycle of an RPC TCP connection, including connection establishment, synchronous call handling (`clnt_vc_call`), and asynchronous record reception via socket upcalls (`clnt_vc_soupcall`). It sits between the high-level RPC API and the kernel socket layer.

### 2. Untrusted Input
Untrusted data enters via the network through `soreceive()` called within `clnt_vc_soupcall`. This data is processed as a stream of RPC records.

### 3. Attacker-Controlled Data
*   **`header`**: A `uint32_t` read from the socket; determines the length of the following record.
*   **`ct->ct_raw` / `ct->ct_record`**: Mbuf chains containing raw bytes from the network.
*   **`xid_plus_direction`**: The first 8 bytes of a decoded record (XID and message direction).
*   **`reply_msg`**: Decoded via `xdr_replymsg` from `ct->ct_record`.

### 4. Fixed-Size Buffers & Constants
*   **`MCALL_MSG_SIZE`**: Used in `xdrmem_create`. (GREP: `MCALL_MSG_SIZE`)
*   **`TLS_MAX_MSG_SIZE_V10_2`**: Used in `clnt_vc_call` for TLS pagination. (GREP: `TLS_MAX_MSG_SIZE_V10_2`)
*   **`uio.uio_resid = 1000000000`**: Constant used for maximum read size in `clnt_vc_soupcall`.

### 5. Dangerous Data Flows
*   **`header` $\to$ `ct->ct_record_resid`**: In `clnt_vc_soupcall`, the network-provided `header` (masked by `0x7fffffff`) defines how many bytes are accumulated into `ct->ct_record` before processing.
*   **Network $\to$ `xid_plus_direction`**: Raw bytes from `ct->ct_record` are copied via `m_copydata` into a local 8-byte array.

### 6. NULL Dereferences
*   **`cl->cl_private`**: Cast to `struct ct_data *` in almost every function without a NULL check.
*   **`ct->ct_socket`**: Dereferenced in `clnt_vc_close` and `clnt_vc_destroy` (though checked in some paths).

### 7. Tagged Unions / Variants
*   **`reply_msg`**: This is a tagged union (`rm_direction`). It is passed to `xdr_replymsg`, which internally validates the tag before accessing members like `acpted_rply`.

### 8. API vs. Helpers
*   **Public API**: `clnt_vc_create` (exports the `CLIENT` handle).
*   **Static Helpers**: `clnt_vc_call`, `clnt_vc_soupcall`, `clnt_vc_dotlsupcall`. These are called via the `clnt_ops` struct or as socket upcalls/kthreads.

### 9. Likely Bug Classes
*   **Integer Overflows/Underflows**: Calculation of `ct->ct_record_resid` and `rawlen` during mbuf splitting/adjustment.
*   **Resource Exhaustion**: Attacker sending a large `header` value to force the kernel to allocate large mbuf chains in `ct->ct_record`.
*   **Race Conditions**: Complex locking between `ct->ct_lock` and `SOCK_RECVBUF_LOCK`.

[GREP RESULTS from codebase]:
GREP `MCALL_MSG_SIZE`) (simplified to: MCALL_MSG_SIZE)`:
```
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
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
lib/libc/rpc/clnt_raw.c:67:	    char 		mashl_callmsg[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_vc.c:110:		char	ct_mcallc[MCALL_MSG_SIZE];	/* marshalled callmsg */
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:286:	assert(ct->ct_mpos + sizeof(uint32_t) <= MCALL_MSG_SIZE);
lib/libc/rpc/clnt_dg.c:168:	char			cu_outhdr[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_tcp.c:98:	  char		ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
crypto/krb5/src/lib/rpc/clnt_tcp.c:215:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcall, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_raw.c:60:	  char	            mashl_callmsg[MCALL_MSG_SIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:113:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
```

GREP `TLS_MAX_MSG_SIZE_V10_2`) (simplified to: TLS_MAX_MSG_SIZE_V10_2)`:
```
sys/opencrypto/ktls.h:31:#define	MAX_TLS_PAGES	(1 + btoc(TLS_MAX_MSG_SIZE_V10_2))
sys/sys/ktls.h:46:#define	TLS_MAX_MSG_SIZE_V10_2	16384
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
sys/rpc/clnt_bck.c:305:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/svc_vc.c:1026:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/svc_vc.c:1109:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/clnt_vc.c:421:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/kern/uipc_ktls.c:722:	tls->params.max_frame_len = min(TLS_MAX_MSG_SIZE_V10_2, ktls_maxlen);
sys/kern/uipc_ktls.c:2535:		    tls->params.tls_hlen + TLS_MAX_MSG_SIZE_V10_2 +
```