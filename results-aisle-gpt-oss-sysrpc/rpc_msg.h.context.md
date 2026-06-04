# Context: rpc_msg.h

**Context Briefing – `rpc_msg.h` (≈250 words)**  

1. **Purpose & Location**  
   `rpc_msg.h` declares the canonical XDR‑serialisable representation of an RPC message used by the Sun RPC (ONC‑RPC) client/server stack in NetBSD. It lives in *lib/rpc* (the RPC library) and is the API surface for serialising/deserialising messages on the wire (e.g. via `xdr_callmsg`, `xdr_replymsg`, etc.).  

2. **How Untrusted Input Reaches This Code**  
   Every message received over the network is read into a buffer by the transport layer (e.g. TCP/UDP) and then deserialised with `xdr_callmsg` or `xdr_replymsg`.  The caller supplies the raw network data; XDR unmarshals it into the `struct rpc_msg` defined here. Thus the entire struct is constructed from attacker‑controlled network traffic.  

3. **Attacker‑Controlled Variables**  
   * `rm_xid` – transaction ID, 32‑bit value.  
   * `rm_direction` – either CALL or REPLY.  
   * `rm_call` (call_body): `cb_prog`, `cb_vers`, `cb_proc`.  
   * `rm_call.cb_cred`, `rb_verf` – opaque auth credentials.  
   * `rm_reply` (reply_body): `rp_stat`, `rp_acpt.ar_stat`, `rp_acpt.ar_results.where`, etc.  
   The data flow: network buffer → `xdr_callmsg`/`xdr_replymsg` → `struct rpc_msg` → subsequent RPC processing.  

4. **Fixed‑size Buffers / Constants**  
   * `RPC_MSG_VERSION` = 2 (`GREP: #define RPC_MSG_VERSION`)  
   * `RPC_SERVICE_PORT` = 2048 (`GREP: #define RPC_SERVICE_PORT`)  
   The struct fields are all word‑sized or pointers; no static array buffers appear in this header.

5. **Dangerous Data Flows**  
   * Attacker → `rm_call.cb_cred` → `xdr_callmsg` → credential length field → potential buffer copy in the auth module.  
   * Attacker → `rm_reply.ar_results.where` pointer → dereferenced by client code.  

6. **Potential NULL Dereferences**  
   * `cb_cred.auth_payload` or `cb_verf.auth_payload` may be NULL if the client sends an empty credential blob.  
   * `ar_results.where` can be NULL in normal RPC flows; code must guard before use.  

7. **Tagged Unions**  
   * `ru` in `rpc_msg` uses `rm_direction` as the type tag; callers are expected to check that tag before accessing `RM_cmb` vs `RM_rmb`.  No defensive checks are in this header; the responsibility lies in the XDR routines.

8. **API vs Static Helpers**  
   All listed functions (`xdr_*`, `_seterr_reply`) are `extern` public APIs.  There are no static helper functions defined in this header.

9. **Likely Bug Classes**  
   * **Bounds‑overflow / uncontrolled buffer copy** during credential or procedure deserialization.  
   * **NULL‑pointer dereference** when processing optional fields (`where`, verbs).  
   * **Missing type‑tag validation** before union access in higher‑layer code.  

---  

**GREP FINDINGS**  
```
GREP: #define RPC_MSG_VERSION
#  define RPC_MSG_VERSION        ((uint32_t) 2)
GREP: #define RPC_SERVICE_PORT
#  define RPC_SERVICE_PORT       ((u_short) 2048)
```
These constants are the only fixed‑size values in this header.

[GREP RESULTS from codebase]:
GREP `#define RPC_MSG_VERSION`) (simplified to: RPC_MSG_VERSION)`:
```
include/rpc/rpc_msg.h:43:#define RPC_MSG_VERSION		((u_int32_t) 2)
sys/rpc/rpc_msg.h:43:#define RPC_MSG_VERSION		((uint32_t) 2)
contrib/tcpdump/rpc_msg.h:41:#define SUNRPC_MSG_VERSION	((uint32_t) 2)
crypto/krb5/src/include/gssrpc/rpc_msg.h:46:#define RPC_MSG_VERSION		((uint32_t) 2)
usr.sbin/rpcbind/rpcb_svc_com.c:789:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/rpc_prot.c:210:	cmsg->rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/clnt_vc.c:269:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/clnt_raw.c:112:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/clnt_bcast.c:376:	msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
lib/libc/rpc/rpc_callmsg.c:79:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
lib/libc/rpc/rpc_callmsg.c:113:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
lib/libc/rpc/rpc_callmsg.c:192:	    (cmsg->rm_call.cb_rpcvers == RPC_MSG_VERSION) &&
sys/rpc/clnt_nl.c:216:			.cb_rpcvers = RPC_MSG_VERSION,
sys/rpc/clnt_bck.c:152:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
sys/rpc/rpc_prot.c:229:	cmsg->rm_call.cb_rpcvers = RPC_MSG_VERSION;
sys/rpc/clnt_vc.c:231:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
sys/rpc/rpc_callmsg.c:75:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
sys/rpc/rpc_callmsg.c:109:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
sys/rpc/rpc_callmsg.c:188:	    (cmsg->rm_call.cb_rpcvers == RPC_MSG_VERSION) &&
contrib/tcpdump/print-sunrpc.c:200:	if (x != SUNRPC_MSG_VERSION)
crypto/krb5/src/lib/rpc/clnt_tcp.c:208:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/rpc_prot.c:165:	cmsg->rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/clnt_raw.c:110:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/pmap_rmt.c:305:	msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
crypto/krb5/src/lib/rpc/rpc_callmsg.c:74:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
crypto/krb5/src/lib/rpc/rpc_callmsg.c:110:			if (cmsg->rm_call.cb_rpcvers != RPC_MSG_VERSION) {
crypto/krb5/src/lib/rpc/rpc_callmsg.c:187:	    (cmsg->rm_call.cb_rpcvers == RPC_MSG_VERSION) &&
crypto/krb5/src/lib/rpc/clnt_udp.c:171:	call_msg.rm_call.cb_rpcvers = RPC_MSG_VERSION;
```

GREP `#define RPC_SERVICE_PORT`) (simplified to: RPC_SERVICE_PORT)`:
```
include/rpc/rpc_msg.h:44:#define RPC_SERVICE_PORT	((u_short) 2048)
sys/rpc/rpc_msg.h:44:#define RPC_SERVICE_PORT	((u_short) 2048)
crypto/krb5/src/include/gssrpc/rpc_msg.h:47:#define RPC_SERVICE_PORT	((u_short) 2048)
```

GREP `#define RPC_MSG_VERSION`:
```
crypto/krb5/src/include/gssrpc/rpc_msg.h:46:#define RPC_MSG_VERSION		((uint32_t) 2)
include/rpc/rpc_msg.h:43:#define RPC_MSG_VERSION		((u_int32_t) 2)
sys/rpc/rpc_msg.h:43:#define RPC_MSG_VERSION		((uint32_t) 2)
```