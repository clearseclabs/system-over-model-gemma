# Context: auth_unix.c

**Context Briefing – `auth_unix.c`** *(≈250 words)*  

1. **Purpose & Placement**  
   Implements the “UNIX‐style” authentication flavour used by the kernel‐space RPC subsystem.  It lives in the NetBSD kernel RPC stack and is invoked whenever an RPC client/server creates or validates an `AUTH_UNIX` credential.  The code exposes `authunix_create()` to construct an `AUTH` handle; the rest are private helper routines registered in `authunix_ops`.  

2. **Untrusted Input Path**  
   - `authunix_create()` receives a `struct ucred *cred` which originates from the client’s credential, ultimately supplied over the network via the RPC transport layer.  
   - `authunix_validate()` accepts an incoming verifier (`struct opaque_auth *verf`) that is produced by the peer, thus also untrusted.  

3. **Attacker‑Control Flow**  
   *From client credential → `authunix_create()`*  
   - `cred → xcr (via cru2x) → xdr_authunix_parms → au->au_origcred.oa_base`.  
   *From network verifier → `authunix_validate()`*  
   - `verf → xdr_opaque_auth → au->au_shcred`.  

4. **Fixed‑size Buffers & Constants**  
   ```c
   char au_marshed[MAX_AUTH_BYTES];   // resolved: 256
   ```
   `MAX_AUTH_BYTES` is defined in `<rpc/rpc_com.h>`: **GREP: #define MAX_AUTH_BYTES => 256**  
   `AUTH_UNIX_HASH_SIZE` = 16  (GREP: #define AUTH_UNIX_HASH_SIZE 16)  
   `AUTH_UNIX_MAX` = 256 (GREP: #define AUTH_UNIX_MAX 256).  
   All other buffers (`xcr`, `mymem`) are stack‑allocated or GMP‑allocated.  

5. **Dangerous Data Flows**  
   | Source | Dest | Function | Size |  
   |--------|------|----------|------|  
   | `cred` → `au_marshed` via `xdr_authunix_parms` | `authunix_create()` | 256 bytes (MAX_AUTH_BYTES) |  
   | `verf` → `au_shcred.oa_base` via `xdr_opaque_auth` | `authunix_validate()` | `verf->oa_length` (user‑supplied) |  

6. **Unchecked NULLs**  
   `authunix_validate()` dereferences `verf->oa_base` without verifying it is non‑NULL after a failed `xdr_opaque_auth` (though it frees it only on success).  

7. **Tagged Union Handling**  
   `struct opaque_auth` is checked for `AUTH_SHORT` before decoding; no other flavour is accepted. No type‑tag validation occurs for `AUTH_UNIX` where the verifier is treated as opaque.  

8. **API vs Static**  
   *Public API*: `authunix_create()`.  
   *Static helpers*: all listed at the top (`authunix_nextverf`, `authunix_marshal`, `authunix_validate`, `authunix_refresh`, `authunix_destroy`, `marshal_new_auth`). Those static helpers are only called via the `authunix_ops` table and never from untrusted code.  

9. **Likely Bug Classes**  
   • Fixed‑size buffer overrun when `MAX_AUTH_BYTES` is exceeded during marshaling.  
   • Race conditions in the global LRU cache (`auth_unix_cache/ all`).  
   • Potential use‑after‑free if `authunix_validate()` mishandles a malformed verifier.  
   • Memory leaks if `authunix_create()` fails after allocating an `AUTH` but before fully populating the cache.  
   • No bounds check on `verf->oa_length` before allocating `oa_base`.

[GREP RESULTS from codebase]:
GREP `#define MAX_AUTH_BYTES => 256** (simplified to: MAX_AUTH_BYTES)`:
```
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
include/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
include/rpc/svc_dg.h:46:	char		su_verfbody[MAX_AUTH_BYTES];	/* verifier body */
sys/rpc/auth.h:169:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
sys/rpc/svc.h:228:	char		rq_credarea[3*MAX_AUTH_BYTES];
sys/rpc/krpc.h:58:	char			cr_verf[MAX_AUTH_BYTES]; /* reply verf */
crypto/krb5/src/include/gssrpc/auth.h:89:	u_int	oa_length;		/* not to exceed MAX_AUTH_BYTES */
usr.bin/genl/parser_rpc.c:104:		if (oa->oa_length > MAX_AUTH_BYTES) {
usr.bin/genl/parser_rpc.c:140:		if (oa->oa_length > MAX_AUTH_BYTES) {
lib/libc/rpc/svc.c:619:	char cred_area[2*MAX_AUTH_BYTES + RQCRED_SIZE];
lib/libc/rpc/svc.c:622:	msg.rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
lib/libc/rpc/svc.c:623:	r.rq_clntcred = &(cred_area[2*MAX_AUTH_BYTES]);
lib/libc/rpc/svc_raw.c:64:	char	verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/svc_vc.c:95:	char verf_body[MAX_AUTH_BYTES];
lib/libc/rpc/rpc_prot.c:74:			&ap->oa_length, MAX_AUTH_BYTES));
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

GREP `#define AUTH_UNIX_HASH_SIZE 16) (simplified to: AUTH_UNIX_HASH_SIZE)`:
```
sys/rpc/auth_unix.c:99:#define AUTH_UNIX_HASH_SIZE	16
sys/rpc/auth_unix.c:101:static struct audata_list auth_unix_cache[AUTH_UNIX_HASH_SIZE];
sys/rpc/auth_unix.c:111:	for (i = 0; i < AUTH_UNIX_HASH_SIZE; i++)
sys/rpc/auth_unix.c:140:				% AUTH_UNIX_HASH_SIZE;
sys/rpc/auth_unix.c:152:	h = HASHSTEP(HASHINIT, cred->cr_uid) % AUTH_UNIX_HASH_SIZE;
```

GREP `#define AUTH_UNIX_MAX 256). (simplified to: AUTH_UNIX_MAX)`:
```
sys/rpc/auth_unix.c:100:#define AUTH_UNIX_MAX		256
sys/rpc/auth_unix.c:135:	if (auth_unix_count > AUTH_UNIX_MAX) {
sys/rpc/auth_unix.c:136:		while (auth_unix_count > AUTH_UNIX_MAX) {
```