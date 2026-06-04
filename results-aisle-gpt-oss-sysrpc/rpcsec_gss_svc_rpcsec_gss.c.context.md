# Context: rpcsec_gss/svc_rpcsec_gss.c

**Context Brief – `svc_rpcsec_gss.c`**  
1. **Purpose & Placement** – This file implements the Remote Procedure Call (RPC) server‑side GSS‑API authentication (RPCSEC_GSS).  It defines the `svc_rpc_gss` public API, the auth ops (`svc_rpc_gss_wrap/unwrap/release`) and manages client state (creation, lookup, expiration, callback).  It sits in the RPC subsystem as a kobj `svc_auth` module.  

2. **Untrusted Input Path** – All attacker data originates from the network in the RPC payload.  The `svc_req` struct contains `rq_cred.oa_base/length` which are deserialized by `xdr_rpc_gss_cred` into the `rpc_gss_cred gc`.  Fields of `gc` (proc, svc, seq, handle, version) are subsequently used throughout the code.  

3. **Attack‑Controlled Variables**  
   * `gc.gc_version` – UUID of GSS version.  
   * `gc.gc_proc` – RPCSEC_GSS control proc (INIT/CONTINUE_INIT/DATA/DESTROY).  
   * `gc.gc_svc` – Requested service (NONE, INTEGRITY, PRIVACY).  
   * `gc.gc_seq` – Sequence number of the RPC call.  
   * `gc.gc_handle` – Client ID (ci_id, ci_hostid, ci_boottime).  
   * `gc.gc_svc` etc. → `client->cl_rawcred.service`.  
   * `recv_tok` → GSS token passed to `gss_accept_sec_context`.  

4. **Fixed‑Size Buffers / Constants**  
   * `cl_seqmask[SVC_RPC_GSS_SEQWINDOW/32]` → 4 *`int`* (`SVC_RPC_GSS_SEQWINDOW == 128`).  
   * `SVC_RPC_GSS_SEQWINDOW` = 128 – GREP: `#define SVC_RPC_GSS_SEQWINDOW 128`.  
   * `MAX_AUTH_BYTES` – bounds on MIC length (defined in `rpcsec_gss.h`: GREP `#define MAX_AUTH_BYTES`).  
   * `MAXSEQ` (sequence wrap) – GREP `#define MAXSEQ`.  

5. **Dangerous Data Flows**  
   * `recv_tok` (attacker‑provoked GSS token) → `gss_accept_sec_context` receives an opaque buffer whose length is taken directly from the cleared `gss_buffer_desc`.  No size limit is enforced before copying, potentially overreading on the GSS side.  
   * `gc.gc_svc` → `client->cl_rawcred.service` (direct assignment).  
   * `export_name.length` → `client->cl_rawcred.client_principal` allocation; then `memcpy(..., export_name.value, export_name.length)` – source length comes from the token, allocator does not constrain endianness; attacker could trigger large arrays.  

6. **NULL Derefs from Malformed Input** – `svc_rpc_gss_find_client` may return NULL if hostid/boottime mismatch.  Subsequent code uses `client->cl_ctx`, `client->cl_cname`, etc., only after a NULL check, but some branches (e.g., in `svc_rpc_gss_accept_sec_context`) dereference `client->cl_sname` without confirming non‑NULL after the lock lock.  

7. **Tagged Unions / Variants** – The `rpc_gss_cred` struct is an opaque GSS token; no type tag is validated before it is fed to `xdr_rpc_gss_cred`.  The `rpc_gss_callback` callback structure is also untagged; the code only matches program/version but not the actual callback type.  

8. **API vs Static Helpers** – `svc_rpc_gss` is the public auth handler.  `svc_rpc_gss_wrap/unwrap/release` are exposed through `svc_auth_gss_ops`.  All helper functions (`svc_rpc_gss_init`, `svc_rpc_gss_find_client`, `svc_rpc_gss_create_client`, `svc_rpc_gss_destroy_client`, etc.) are declared static and only invoked within this file, and are guarded by `svc_rpc_gss_lock` or per‑client locks where appropriate.  

9. **Likely Bug Classes** –  
   * **Buffer overflows / unchecked copy lengths** (GSS token, export name).  
   * **Replay/sequence window leaks** – improper mask updates if seq > MAXSEQ.  
   * **Integer overflows** in `client->cl_expiration` calculations (cred_lifetime, time_uptime).  
   * **NULL deref risks** when client structures are unlinked concurrently.  
   * **Callback injection** – callbacks are stored in a global list without strict validation, creating a path for arbitrary function returns if a malformed callback is injected.  

*(End of brief.)*

[GREP RESULTS from codebase]:
GREP `#define SVC_RPC_GSS_SEQWINDOW 128`. (simplified to: SVC_RPC_GSS_SEQWINDOW)`:
```
lib/librpcsec_gss/svc_rpcsec_gss.c:113:#define SVC_RPC_GSS_SEQWINDOW	128
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:125:#define SVC_RPC_GSS_SEQWINDOW	128
lib/librpcsec_gss/svc_rpcsec_gss.c:136:	uint32_t		cl_seqmask[SVC_RPC_GSS_SEQWINDOW/32]; /* bitmask of seqnums */
lib/librpcsec_gss/svc_rpcsec_gss.c:675:	gr->gr_win = SVC_RPC_GSS_SEQWINDOW;
lib/librpcsec_gss/svc_rpcsec_gss.c:900:		if (offset >= SVC_RPC_GSS_SEQWINDOW)
lib/librpcsec_gss/svc_rpcsec_gss.c:929:			for (i = (SVC_RPC_GSS_SEQWINDOW / 32) - 1;
lib/librpcsec_gss/svc_rpcsec_gss.c:938:			for (i = 0; i < SVC_RPC_GSS_SEQWINDOW / 32; i++) {
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:156:	uint32_t		cl_seqmask[SVC_RPC_GSS_SEQWINDOW/32]; /* bitmask of seqnums */
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1080:	gr->gr_win = SVC_RPC_GSS_SEQWINDOW;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1328:		if (offset >= SVC_RPC_GSS_SEQWINDOW) {
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1363:			for (i = (SVC_RPC_GSS_SEQWINDOW / 32) - 1;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1371:		for (i = 0; i < SVC_RPC_GSS_SEQWINDOW / 32; i++) {
```

GREP `#define MAX_AUTH_BYTES`:
```
include/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
crypto/krb5/src/include/gssrpc/auth.h:49:#define MAX_AUTH_BYTES	400
sys/rpc/auth.h:50:#define MAX_AUTH_BYTES	400
```

GREP `#define MAXSEQ`:
```
lib/librpcsec_gss/rpcsec_gss_int.h:72:#define MAXSEQ		0x80000000
sys/rpc/rpcsec_gss/rpcsec_gss_int.h:74:#define MAXSEQ		0x80000000
crypto/krb5/src/include/gssrpc/auth_gss.h:118:#define MAXSEQ		0x80000000
```