# Context: krpc.h

This is a context briefing for `krpc.h`, which defines the kernel-side RPC (Remote Procedure Call) structures and state management.

### 1. Role and Location
This header resides in the kernel RPC layer. It defines the state management for RPC clients (`rc_data`), connection tracking (`ct_data`), and request tracking (`ct_request`). It acts as the glue between the network transport (`mbuf` chains) and the RPC call logic.

### 2. Untrusted Input Path
Untrusted data enters via the network (socket $\to$ `mbuf` chains). Data flows from the network driver into `struct mbuf *ct_raw` and `struct mbuf *mpending` in `struct cf_conn`, where it is subsequently parsed into RPC records.

### 3. Attacker-Controlled Data
*   **`struct mbuf *ct_raw` / `*ct_record`**: Contains raw network packets.
*   **`ct_request.cr_verf`**: Carries the verification token from a reply.
*   **`ct_data.ct_xid`**: The transaction ID used to match replies to requests.
*   **`cf_conn.resid`**: The remaining bytes to be read for a fragment, derived from the RPC record header.

### 4. Fixed-Size Buffers
*   `ct_request.cr_verf[MAX_AUTH_BYTES]`: GREP: `MAX_AUTH_BYTES`
*   `ct_data.ct_mcallc[MCALL_MSG_SIZE]`: `MCALL_MSG_SIZE` = 24 bytes.

### 5. Dangerous Data Flows
*   **Network $\to$ `cr_verf`**: Data from an incoming `mbuf` reply is copied into the fixed-size `cr_verf` buffer in `struct ct_request`.
*   **Network $\to$ `ct_mcallc`**: While primarily used for marshaling, any logic copying network data back into this 24-byte buffer is a risk.

### 6. Potential NULL Dereferences
*   `rc_data.rc_ucred`: User credentials pointer.
*   `ct_data.ct_socket`: Socket pointer; may be NULL if the connection is closed/failed.
*   `ct_data.ct_record`: Mbuf chain for the current record.

### 7. Tagged Unions/Variants
No explicit tagged unions are present in this header, but `ct_rcvstate` (bitmask) acts as a state machine controlling how `ct_raw` and `ct_record` are processed.

### 8. API Visibility
*   **Public (Kernel API):** `clnt_bck_call`, `rpcnl_init`, `clnt_bck_svccall`.
*   **Helpers:** `_rpc_copym_into_ext_pgs` (Internal utility for mbuf/page movement).

### 9. Likely Bug Classes
*   **Buffer Overflows:** Specifically in `cr_verf` during RPC reply parsing.
*   **Race Conditions:** `ct_lock` and `rc_lock` protect these structures; improper locking during asynchronous `mbuf` processing could lead to UAF.
*   **Integer Overflows:** In `cf_conn.resid` and `ct_data.ct_record_resid` during fragment reassembly.

[GREP RESULTS from codebase]:
GREP `MAX_AUTH_BYTES`:
```
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/krpc.h:58:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
sys/rpc/svc.h:228:	char		rq_credarea[3*MAX_AUTH_BYTES];
include/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/svc_dg.h:46:	char		su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
crypto/krb5/src/include/gssrpc/auth.h:89:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
lib/librpcsec_gss/rpcsec_gss.c:568:	char			 credbuf[MAX_AUTH_BYTES];
lib/librpcsec_gss/rpcsec_gss.c:569:	char			 tmpheader[MAX_AUTH_BYTES];
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/svc_vc.c:95:	char verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_callmsg.c:62:		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:65:		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:123:				if (oa->oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/rpc_callmsg.c:159:				if (oa->oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/auth_unix.c:79:	char			au_marshed[MAX_AUTH_BYTES];
lib/libc/rpc/auth_unix.c:92:	char mymem[MAX_AUTH_BYTES];
lib/libc/rpc/auth_unix.c:136:	xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE);
lib/libc/rpc/auth_unix.c:339:	xdrmem_create(xdrs, au->au_marshed, MAX_AUTH_BYTES, XDR_ENCODE);
sys/rpc/svc.c:933:	msg.rm_call.cb_verf.oa_base = &r->rq_credarea[MAX_AUTH_BYTES];
sys/rpc/svc.c:934:	r->rq_clntcred = &r->rq_credarea[2*MAX_AUTH_BYTES];
sys/rpc/rpc_prot.c:80:			&ap->oa_length, MAX_AUTH_BYTES));
sys/rpc/rpc_callmsg.c:58:		if (cmsg->rm_call.cb_cred.oa_length > MAX_AUTH_BYTES) {
sys/rpc/rpc_callmsg.c:61:		if (cmsg->rm_call.cb_verf.oa_length > MAX_AUTH_BYTES) {
```