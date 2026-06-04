# Context: clnt.h

**Context Brief – clnt.h (client‑side RPC interface)**  

1. *Functionality & Placement* – `clnt.h` declares the public API for creating and using a client‐side RPC handle (`CLIENT`).  It contains the opaque client type, a table of operation callbacks (`cl_ops`), convenience macros (`CLNT_CALL`, `CLNT_DESTROY`, etc.), and helper functions such as `clnt_dg_create`, `clnt_vc_create`, and `client_nl_create`.  The header sits in the lib/rpc sub‑tree and is included by user programs that issue local‑host or network RPC calls.  

2. *Untrusted Input* – Data can enter this code from the application layer (e.g., values supplied to `clnt_dg_create` or `client_nl_create`), but the code itself is not directly reading network traffic; it serialises data and sends it out via sockets implemented in the underlying transport code.  Therefore the only “untrusted” data is supplied by the caller (program counters, argument buffers, network addresses).  

3. *Data‑flow* –  
   * `svcaddr` (type `struct sockaddr *`) – originates from the caller and propagates unchanged to the transport layer via `clnt_dg_create`.  
   * `program` (`rpcprog_t`) and `version` (`rpcvers_t`) – passed to `clnt_dg_create` and later into `cl_call` via the `CLIENT` handle.  
   * `sendsz`, `recvsz` (`size_t`) – directly set in the `CLIENT`’s callee‐specific struct by `clnt_dg_create`.  

4. *Fixed‑size buffers / constants* – The only explicit size constant in this file is:  

   ```
   #define RPCSMALLMSGSIZE 400   /* a more reasonable packet size */
   ```  

   (GREP: `#define RPCSMALLMSGSIZE 400`)  

   No fixed‑length array declarations appear here.  

5. *Dangerous flows* – None in this header; any copying to fixed‑size buffers is performed inside the transport module, not shown here.  

6. *Possible NULL derefs* – The macro `CLNT_ABSENT(ext)` (implicit in `clnt_call_private` when `ext` is NULL) could lead to a NULL `rc_auth` being passed to authenticators without a prior check in this file.  

7. *Tagged unions* – `rpc_err` contains a union `ru` with no explicit tag field; the caller must remember the semantics of `re_status`. No type‑tag validation occurs here.  

8. *API vs helper* – All functions declared `extern` (`clnt_dg_create`, `client_nl_create`, ... ) are public API.  No `static` helpers are defined in this header.  

9. *Likely bugs* –  
   * Mis‑use of `CLNT_CALL` macros without initializing `struct rpc_callextra` can result in NULL pointers being passed to low‑level helpers.  
   * Incorrect `sendsz/recvsz` values can cause buffer overflows in the transport implementation.  
   * The lack of runtime size checks around `rpc_err` fields makes it easy to misinterpret error data.  

**GREP results** –  

```
GREP: #define RPCSMALLMSGSIZE 400
GREP: #define RPCB_MULTICAST_ADDR "ff02::202"
```

[GREP RESULTS from codebase]:
GREP `#define RPCSMALLMSGSIZE 400`) (simplified to: RPCSMALLMSGSIZE)`:
```
include/rpc/clnt.h:138:#define RPCSMALLMSGSIZE 400	/* a more reasonable packet size */
sys/rpc/clnt.h:163:#define RPCSMALLMSGSIZE 400	/* a more reasonable packet size */
crypto/krb5/src/include/gssrpc/clnt.h:342:#define RPCSMALLMSGSIZE	400	/* a more reasonable packet size */
lib/libc/rpc/pmap_getport.c:76:	    PMAPVERS, timeout, &sock, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
usr.sbin/ypbind/ypbind.c:794:		YPPROG, YPVERS, interval, &rpcsock, RPCSMALLMSGSIZE,
usr.sbin/ypbind/ypbind.c:795:		RPCSMALLMSGSIZE)) == (CLIENT *)NULL) {
usr.sbin/ypbind/yp_ping.c:117:	    PMAPVERS, timeout, &sock, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
crypto/krb5/src/lib/rpc/pmap_getport.c:76:	    PMAPVERS, timeout, &sock, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
crypto/krb5/src/lib/rpc/pmap_clnt.c:76:	    timeout, &sock, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
crypto/krb5/src/lib/rpc/pmap_clnt.c:157:	    timeout, &sock, RPCSMALLMSGSIZE, RPCSMALLMSGSIZE);
```

GREP `#define RPCSMALLMSGSIZE 400`:
```
sys/rpc/clnt.h:163:#define RPCSMALLMSGSIZE 400	/* a more reasonable packet size */
include/rpc/clnt.h:138:#define RPCSMALLMSGSIZE 400	/* a more reasonable packet size */
```

GREP `#define RPCB_MULTICAST_ADDR "ff02::202`:
```
include/rpc/clnt.h:47:#define RPCB_MULTICAST_ADDR "ff02::202"
sys/rpc/clnt.h:51:#define RPCB_MULTICAST_ADDR "ff02::202"
```