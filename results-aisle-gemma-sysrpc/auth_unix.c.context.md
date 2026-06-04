# Context: auth_unix.c

This security briefing covers `auth_unix.c`, which implements UNIX-style authentication for RPC.

**1. Functionality & Location**
This file implements the `AUTH_UNIX` flavor of RPC authentication. It manages the creation, validation, marshalling, and caching of UNIX credentials (`uid`, `gid`, `rgid`) to be sent over the network. It sits within the RPC authentication layer.

**2. Untrusted Input Path**
Untrusted data enters via the network as RPC packets. The `authunix_validate` function is the primary entry point for external data, receiving a `struct opaque_auth *verf` which is decoded from the network stream using XDR.

**3. Attacker-Controlled Data**
*   **`verf` (in `authunix_validate`)**: Carries the credentials/verifier sent by the client.
*   **Flow**: Network $\rightarrow$ `authunix_validate(verf)` $\rightarrow$ `xdrmem_create` $\rightarrow$ `xdr_opaque_auth` $\rightarrow$ `au->au_shcred`.

**4. Fixed-Size Buffers**
*   `au->au_marshed[MAX_AUTH_BYTES]`: `MAX_AUTH_BYTES` is not defined in this snippet. 
GREP: `grep -r "MAX_AUTH_BYTES" .`
*   `mymem[MAX_AUTH_BYTES]` (stack in `authunix_create`).

**5. Dangerous Data Flows**
*   **Source**: `verf->oa_base` (attacker controlled).
*   **Destination**: `au->au_shcred` (via `xdr_opaque_auth`).
*   **Function**: `authunix_validate`.
*   **Note**: The data is processed by the XDR engine; buffer overflows depend on the XDR implementation's bounds checking.

**6. Potential NULL Dereferences**
*   `authunix_validate`: Checks `if (!verf)`, but `verf->oa_base` is passed to `xdrmem_create` without a NULL check.

**7. Tagged Unions/Variants**
The code uses `oa_flavor` as a type tag. In `authunix_validate`, it explicitly checks `if (verf->oa_flavor == AUTH_SHORT)` before treating the payload as a short-hand credential.

**8. API Visibility**
*   **Public**: `authunix_create`.
*   **Static Helpers**: `authunix_nextverf`, `authunix_marshal`, `authunix_validate`, `authunix_refresh`, `authunix_destroy`, `marshal_new_auth`. These are called via the `authunix_ops` function table or internally.

**9. Likely Bug Classes**
*   **Memory Leaks**: Complex `mem_free` logic in `authunix_destroy` and `authunix_validate`.
*   **Integer Overflows**: `oa_length` usage in `mem_alloc` and `memcpy`.
*   **Race Conditions**: While `auth_unix_lock` is used, the interaction between `sx_try_upgrade` and the LRU list may be subtle.

[GREP RESULTS from codebase]:
GREP `grep -r "MAX_AUTH_BYTES" . (simplified to: MAX_AUTH_BYTES)`:
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
lib/librpcsec_gss/rpcsec_gss.c:568:	char			 credbuf[MAX_AUTH_BYTES];
lib/librpcsec_gss/rpcsec_gss.c:569:	char			 tmpheader[MAX_AUTH_BYTES];
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
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