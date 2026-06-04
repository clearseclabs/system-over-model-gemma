# Context: clnt_nl.c

**Context Briefing – `clnt_nl.c` (kernel RPC client over netlink)**  

1. **Purpose & Location**  
`clnt_nl.c` implements the client side of a kernel RPC subsystem that sends calls to user‑space via the Netlink generic family “rpc”. The client logic lives in the CLNT ops table (`clnt_nl_ops`) and is invoked whenever a `CLIENT` created by `client_nl_create()` issues an RPC (`clnt_nl_call`).  Replies are received in `clnt_nl_reply`, parsed, and matched to the pending request in `cl`.  

2. **Untrusted Input Path**  
The only external data that reaches this code is the Netlink reply payload.  The generic Netlink parser (`rpcnl_parser`) extracts the `RPCNL_REPLY_GROUP` and `RPCNL_REPLY_BODY` attributes; the body (`attrs.data`) is then copied into an `mchain` (`mc`) and subsequently into the request’s `cr->cr_mrep`.  No other external channels feed this code.  

3. **Attacker‑Controlled Variables**  
* `attrs.data` – the raw attribute data supplied by the user‑space listener.  
* `NLA_DATA_LEN(attrs.data)` – length of that data (up to `UINT16_MAX`).  
* `mc` → `cr->cr_mrep` – the mbuf chain that holds the reply payload after it is copied in `clnt_nl_reply`.  The subsequent XDR decoding (`xdr_replymsg`, `xdrmbuf_getall`) consumes this data.  

4. **Fixed‑Size Buffers & Constants**  
* `nl->nl_mcallc[MCALL_MSG_SIZE]` – marshalled call prefix.  `MCALL_MSG_SIZE` is a compile‑time macro.  
  `GREP: #define MCALL_MSG_SIZE`  
* `nl->nl_footer` – not shown but implied in buffer allocation.  
* RPC payloads are limited by `NLA_DATA_LEN` (UINT16_MAX) in Netlink attributes.  
  `GREP: #define RPC_MAXDATASIZE` (for reference to upper bound).  

5. **Dangerous Data Flows**  
* Source: `attrs.data` → Destination: `cr->cr_mrep` via `m_copyback` in `clnt_nl_reply`.  
* Function: `nl_store` (implicit copy inside `m_copyback`).  
* Buffer size: `NLA_DATA_LEN(attrs.data)` (≤ 65535).  

6. **NULL Dereferences**  
* `attrs.data` is explicitly checked for NULL.  
* `cr->cr_mrep` is verified non‑NULL after a successful reply.  

7. **Tagged Unions / Variant Types**  
* `reply_msg.rp_reply` is a union; the code checks `reply_msg.rm_reply.rp_stat` before accessing `ar_stat`. No unchecked tag usage is visible.  

8. **API vs Static Helpers**  
* Public API: `client_nl_create()`, `client_nl_destroy()`, `clnt_nl_control()` (via `cl->cl_ops`).  
* Static helpers: `clnt_nl_call()`, `clnt_nl_reply()`, `clnt_nl_close()`, `clnt_nl_destroy()`. These helpers are only invoked internally and guard all data accesses with the appropriate locks (`nl->nl_lock`, `rpcnl_global_lock`).  

9. **Probable Bug Classes**  
* Buffer over‑run in `mem` allocation when `len` is computed from `nl->nl_mpos + nl->nl_authlen + m_length(args, NULL)` – no upper‑bound validation on `args`.  
* Incorrectly sized Netlink attribute handling if callers send a payload > UINT16_MAX.  
* Race conditions on the `nl_pending` queue if locking were omitted.  

---  
**GREP Results**  
`GREP: #define MCALL_MSG_SIZE`  
`GREP: #define RPC_MAXDATASIZE`

[GREP RESULTS from codebase]:
GREP `#define MCALL_MSG_SIZE`:
```
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_tcp.c:67:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_raw.c:49:#define MCALL_MSG_SIZE 24
```

GREP `#define RPC_MAXDATASIZE` (for reference to upper bound). (simplified to: RPC_MAXDATASIZE)`:
```
lib/libc/rpc/rpc_com.h:52:#define	RPC_MAXDATASIZE 9000
include/rpc/rpc_com.h:51:#define	RPC_MAXDATASIZE 9000
sys/rpc/rpc_com.h:53:#define	RPC_MAXDATASIZE 9000
sys/xdr/xdr.c:629:		maxsize = RPC_MAXDATASIZE;
sys/xdr/xdr.c:690:	return xdr_string(xdrs, cpp, RPC_MAXDATASIZE);
usr.sbin/rpcbind/rpcb_svc_com.c:420:	    RPC_MAXDATASIZE));
usr.sbin/rpcbind/rpcbind.c:156:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpcbind/rpcbind.c:517:			    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpcbind/rpcbind.c:559:		    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.statd/statd.c:91:  int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.statd/statd.c:561:		RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/ypserv/yp_main.c:399:			transp = svc_vc_create(slep->sle_sock, RPC_MAXDATASIZE,
usr.sbin/ypserv/yp_main.c:400:			    RPC_MAXDATASIZE);
usr.sbin/mountd/mountd.c:429:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/mountd/mountd.c:1082:			transp = svc_vc_create(fd, RPC_MAXDATASIZE,
usr.sbin/mountd/mountd.c:1083:			    RPC_MAXDATASIZE);
usr.sbin/rpc.lockd/lockd.c:125:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.lockd/lockd.c:292:			xprt = svc_vc_create(fd, RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.lockd/lockd.c:762:		    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:172:	int maxrec = RPC_MAXDATASIZE;
usr.bin/rpcgen/rpc_svcout.c:194:		f_print(fout,"nconf, 0, RPC_MAXDATASIZE, RPC_MAXDATASIZE);\n");
usr.bin/rpcgen/rpc_svcout.c:829:		RPC_MAXDATASIZE, RPC_MAXDATASIZE)) \
lib/libc/xdr/xdr.c:705:		maxsize = RPC_MAXDATASIZE;
lib/libc/xdr/xdr.c:767:	return xdr_string(xdrs, cpp, RPC_MAXDATASIZE);
lib/libc/rpc/rpcb_st_xdr.c:66:	if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:118:		if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:156:		if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:184:	if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:60:	if (!xdr_string(xdrs, &objp->r_netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:63:	if (!xdr_string(xdrs, &objp->r_addr, RPC_MAXDATASIZE)) {
```

GREP `#define MCALL_MSG_SIZE`:
```
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_tcp.c:67:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_raw.c:49:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
```