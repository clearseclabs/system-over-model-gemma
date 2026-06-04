# Context: clnt_dg.c

This security briefing covers `clnt_dg.c`, which implements the connectionless (datagram) client-side RPC transport.

### 1. Role and Location
This file is part of the RPC client library. it handles the creation of client handles, sending RPC requests via UDP/datagram sockets, and managing asynchronous replies via socket upcalls.

### 2. Untrusted Input Path
Untrusted data enters via the network. The `clnt_dg_soupcall` function is the primary entry point, triggered by the socket layer when data arrives. This data is stored in `mbuf` chains and matched against pending requests.

### 3. Attacker-Controlled Data
*   **`m` (mbuf):** In `clnt_dg_soupcall`, the `mbuf` contains the raw network packet.
*   **`xid`:** Extracted from the first 4 bytes of `m` via `m_copydata`.
*   **`cr->cr_mrep`:** The `mbuf` is attached to a `cu_request` and later passed to `xdr_replymsg` in `clnt_dg_call` for decoding.
*   **`info`:** In `clnt_dg_control`, the `void *info` parameter is provided by the caller (potentially user-space via a wrapper).

### 4. Fixed-Size Buffers and Constants
*   **`cr->cr_verf`**: `char[MAX_AUTH_BYTES]`. GREP: `MAX_AUTH_BYTES` is typically 1024 in RPC headers.
*   **`cu->cu_mcallc`**: `char[MCALL_MSG_SIZE]` where `MCALL_MSG_SIZE = 24`.
*   **`CWNDSCALE`**: `256`.
*   **`MAXCWND`**: `(32 * 256) = 8192`.

### 5. Dangerous Data Flows
*   **Network $\rightarrow$ `cr->cr_mrep` $\rightarrow$ `xdr_replymsg`**: Attacker-controlled network data is decoded by XDR. If the XDR decoder for the specific RPC procedure is flawed, this is the primary attack vector.
*   **`info` $\rightarrow$ `cu->cu_raddr`**: In `clnt_dg_control` (`CLSET_SVC_ADDR`), `memcpy` uses `addr->sa_len`. If `sa_len` is not validated against `sizeof(struct sockaddr_storage)`, this could cause an overflow.

### 6. NULL Dereferences
*   **`info`**: Checked at the start of `clnt_dg_control` for most cases, but specific `CLSET` cases assume the cast (e.g., `(struct timeval *)info`) is valid.
*   **`cl->cl_private`**: Cast to `struct cu_data *` without checking if it is NULL.

### 7. Tagged Unions/Variants
*   **`reply_msg`**: This is an `rpc_msg` union. In `clnt_dg_call`, the code checks `reply_msg.rm_reply.rp_stat == MSG_ACCEPTED` before accessing `acpted_rply` members, providing basic type-tag validation.

### 8. API vs Helpers
*   **Public API**: `clnt_dg_create`, `clnt_dg_soupcall`.
*   **Static Helpers**: `clnt_dg_call`, `clnt_dg_control`, `clnt_dg_close`, etc. These are called via the `clnt_ops` function pointer table.

### 9. Likely Bug Classes
*   **Integer Overflows/Underflows**: Especially in congestion window calculations (`cu->cu_cwnd`).
*   **Memory Corruption**: Via `memcpy` in `clnt_dg_control` using unchecked `sa_len`.
*   **Race Conditions**: Complex locking involving `cs_lock` and `SOCK_RECVBUF_LOCK`.
*   **XDR Decoding Flaws**: Remote memory corruption during `xdr_replymsg` processing of untrusted `mbufs`.

[GREP RESULTS from codebase]:
GREP `MAX_AUTH_BYTES` is typically 1024 in RPC headers. (simplified to: MAX_AUTH_BYTES)`:
```
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/svc.h:228:	char		rq_credarea[3*MAX_AUTH_BYTES];
sys/rpc/krpc.h:58:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
include/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/svc_dg.h:46:	char		su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
crypto/krb5/src/include/gssrpc/auth.h:89:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/rpc_prot.c:80:			&ap->oa_length, MAX_AUTH_BYTES));
sys/rpc/svc.c:933:	msg.rm_call.cb_verf.oa_base = &r->rq_credarea[MAX_AUTH_BYTES];
sys/rpc/svc.c:934:	r->rq_clntcred = &r->rq_credarea[2*MAX_AUTH_BYTES];
sys/rpc/rpc_callmsg.c:58:		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:61:		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:119:				if (oa->oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:155:				if (oa->oa_length > MAX_AUTH_BYTES) {
sys/rpc/auth_unix.c:92:	char			au_marshed[MAX_AUTH_BYTES];
sys/rpc/auth_unix.c:127:	char mymem[MAX_AUTH_BYTES];
sys/rpc/auth_unix.c:197:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/auth_unix.c:365:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1249:	KASSERT(mic.length <= MAX_AUTH_BYTES,
sys/rpc/clnt_dg.c:103:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
sys/rpc/rpcsec_gss/rpcsec_gss.c:518:	char			 credbuf[MAX_AUTH_BYTES];
lib/librpcsec_gss/rpcsec_gss.c:568:	char			 credbuf[MAX_AUTH_BYTES];
lib/librpcsec_gss/rpcsec_gss.c:569:	char			 tmpheader[MAX_AUTH_BYTES];
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
```