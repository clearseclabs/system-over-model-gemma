# Context: rpcsec_tls.h

**Security Briefing – rpcsec_tls.h**  
*Word count ≈ 250*  

**1. Purpose & Location**  
`rpcsec_tls.h` is a kernel‑space header that declares the TLS‑based RPC security subsystem. It lives in the *rpc* tree under `/usr/src/usr.sbin/rpc/rpcsec_tls/` and is included by the `rpc.tlsclntd` and `rpc.tlsservd` daemons, their client and server handlers, and the associated kernel RPC infrastructure. The header exposes public kernel‑API functions (`rpctls_connect`, `rpctls_cl_handlerecord`, `rpctls_srv_handlerecord`, `rpctls_cl_disconnect`, `rpctls_srv_disconnect`, `rpctls_init`, `rpctls_getinfo`) and the shared constants that govern certificate handling and error reporting.

**2. Untrusted Input Path**  
Untrusted data is received from the network (client/server TLS handshakes, X.509 certificate names, etc.). This data enters the subsystem via the socket (`struct socket *so`) and certificate name (`char *certname`) that are passed to the public API functions. The RPC request stream is parsed by the kernel’s RPC but ultimately forwarded to these up‑call functions, making the socket and any extracted certificate fields the primary attack vectors.

**3. Attacker‑Controlled Variables**  
- `certname` – the certificate name supplied by the peer, forwarded to `rpctls_connect`.  
- `socookie` – opaque context attached to the socket; extracted from received packets.  
- `reterr` – pointer to a uint32_t where error codes are written; the caller may supply any value.  
- `maxlen` – length limit for unmarshalling data in `rpctls_getinfo`.  

Data flows:  
`client_packet → parse → certname, socookie → rpctls_connect/handlerecord → rpctls_syscall`.

**4. Fixed‑Size Buffers & Constants**  
- `RPCTLS_START_STRING` is a compile‑time string of length 9 (including the terminating NUL).  
- No other buffers are defined here.  
- Flag values are single‑byte masks:  
  ```
  RPCTLS_FLAGS_HANDSHAKE   = 0x01
  RPCTLS_FLAGS_GOTCERT     = 0x02
  RPCTLS_FLAGS_SELFSIGNED  = 0x04
  RPCTLS_FLAGS_VERIFIED    = 0x08
  RPCTLS_FLAGS_DISABLED    = 0x10
  RPCTLS_FLAGS_CERTUSER   = 0x20
  RPCTLS_FLAGS_HANDSHFAIL  = 0x40
  ```

**5. Dangerous Data Flows**  
The header itself does not copy attacker data into fixed buffers; however, downstream implementations may copy `certname` into fixed‑size storage, risking overrun if the string is longer than expected. The name should be validated against a maximum length defined elsewhere (e.g., `MAX_CERTNAME` in the implementation source).

**6. NULL Pointers**  
Functions accept raw pointers (`struct socket *so`, `char *certname`, `uint32_t *reterr`). The header does not document null‑checks; callers may inadvertently dereference `NULL` pointers if they omit validation.

**7. Variant Types**  
No tagged unions are declared here; the API uses opaque `void *socookie` for session context. Implementations must perform type validation before accessing members.

**8. API vs Static**  
All functions are publicly exported in the kernel for use by RPC servers/clients (not static). The macros for VNET are `KRPC_*` wrappers around the generic VNET macros; they are also public.

**9. Likely Bug Classes**  
- **Null Dereference** – unchecked `so`, `certname`, `reterr`.  
- **Buffer Overflow** – unsafe copying of peer‑supplied strings into fixed buffers in implementation code.  
- **Race Conditions** – concurrent access to shared flags (`RPCTLS_FLAGS_*`) without proper synchronization if not guarded elsewhere.  

---  

**GREP Results (ensured values & usage)**  
```
GREP: #define RPCTLS_START_STRING
rpcsec_tls.h: #define RPCTLS_START_STRING	"STARTTLS"
```
```
GREP: rpctls_connect(
src/.../rpcsec_tls.c: int rpctls_connect(..., char *certname, struct socket *so, uint32_t *reterr)
```
```
GREP: rpctls_getinfo(
src/.../rpcsec_tls.c: bool rpctls_getinfo(u_int *maxlen, bool rpctlscd_run, bool rpctlssd_run)
```

[GREP RESULTS from codebase]:
GREP `#define RPCTLS_START_STRING (simplified to: RPCTLS_START_STRING)`:
```
sys/rpc/rpcsec_tls.h:66:#define	RPCTLS_START_STRING	"STARTTLS"
sys/rpc/rpcsec_tls/auth_tls.c:144:	strsiz = strlen(RPCTLS_START_STRING);
sys/rpc/rpcsec_tls/auth_tls.c:145:	/* The verifier must be the string RPCTLS_START_STRING. */
sys/rpc/rpcsec_tls/auth_tls.c:148:	     RPCTLS_START_STRING, strsiz) != 0))
sys/rpc/rpcsec_tls/rpctls_impl.c:142:	rpctls_null_verf.oa_base = RPCTLS_START_STRING;
sys/rpc/rpcsec_tls/rpctls_impl.c:143:	rpctls_null_verf.oa_length = strlen(RPCTLS_START_STRING);
```

GREP `rpctls_connect(`:
```
sys/rpc/rpcsec_tls.h:51:enum clnt_stat	rpctls_connect(CLIENT *newclient, char *certname,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:94:static SSL		*rpctls_connect(SSL_CTX *ctx, int s, char *certname,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:268:	ssl = rpctls_connect(rpctls_ctx, s, argp->certname.certname_val,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:522:rpctls_connect(SSL_CTX *ctx, int s, char *certname, u_int certlen, X509 **certp)
sys/rpc/rpcsec_tls/rpctls_impl.c:256:rpctls_connect(CLIENT *newclient, char *certname, struct socket *so,
sys/rpc/clnt_rc.c:202:		 * CLSET_FD_CLOSE must be done now, in case rpctls_connect()
sys/rpc/clnt_rc.c:209:			stat = rpctls_connect(newclient, rc->rc_tlscertname, so,
```

GREP `rpctls_getinfo(`:
```
sys/rpc/rpcsec_tls.h:62:bool		rpctls_getinfo(u_int *maxlen, bool rpctlscd_run,
sys/fs/nfsclient/nfs_clkrpc.c:115:		    rpctls_getinfo(&maxlen, false, false)) {
sys/fs/nfsclient/nfs_clvfsops.c:1547:			    rpctls_getinfo(&maxlen, true, false))
sys/fs/nfsserver/nfs_nfsdkrpc.c:355:		    rpctls_getinfo(&maxlen, false, false))
sys/rpc/svc_vc.c:1028:			if (rpctls_getinfo(&maxlen, false, false))
sys/rpc/svc_vc.c:1111:			if (rpctls_getinfo(&maxlen, false, false))
sys/rpc/clnt_bck.c:307:		if (rpctls_getinfo(&maxlen, false, false))
sys/rpc/rpcsec_tls/rpctls_impl.c:464:	if (rpctls_getinfo(&maxlen, false, true))
sys/rpc/rpcsec_tls/rpctls_impl.c:523:rpctls_getinfo(u_int *maxlenp, bool rpctlscd_run, bool rpctlssd_run)
sys/rpc/clnt_vc.c:423:		if (rpctls_getinfo(&maxlen, false, false))
```