# Triage T0012: Function Pointer Indirection (`AUTH` handle)

- **File**: `auth.h`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Function Pointer Indirection (`AUTH` handle)

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The `AUTH` handle and its `ah_ops` pointer are internally managed by the RPC library and initialized by trusted constructors; they are not derived from or controllable by untrusted network input.

The vulnerability report identifies a potential Null Pointer Dereference (or ACE) in the `AUTH` structure because the macros `AUTH_NEXTVERF`, `AUTH_MARSHALL`, etc., dereference `ah_ops` without a NULL check. However, in the context of the RPC authentication framework, the `AUTH` handle is an internal object created by specific constructor functions (e.g., `authunix_create`, `authnone_create`, `authdes_create`). These constructors are responsible for allocating the `AUTH` structure and assigning a valid, static `auth_ops` table associated with that specific authentication flavor. An attacker cannot directly provide or manipulate the `AUTH` structure or its `ah_ops` pointer via network input; they only provide the `opaque_auth` credentials, which are then processed by the methods *defined* in the `ah_ops` table. Since the `AUTH` handle is an internally managed object and the function pointers are sourced from static operation tables, the lack of a NULL check in the macro is a code quality issue (assuming internal constructors are correct) rather than a security vulnerability reachable by an external attacker.

CRUX: The `AUTH` handle and its `ah_ops` pointer are internally managed by the RPC library and initialized by trusted constructors; they are not derived from or controllable by untrusted network input.
GREP: authunix_create|authnone_create|authdes_create

🔎 **Grep results:**

GREP `authunix_create`:
```
sys/rpc/auth.h:267:#define authsys_create(c,i1,i2,i3,ip) authunix_create((c),(i1),(i2),(i3),(ip))
sys/rpc/auth.h:268:#define authsys_create_default() authunix_create_default()
include/rpc/auth.h:270:#define authsys_create(c,i1,i2,i3,ip) authunix_create((c),(i1),(i2),(i3),(ip))
include/rpc/auth.h:271:#define authsys_create_default() authunix_create_default()
crypto/krb5/src/include/gssrpc/rename.h:63:#define authunix_create		gssrpc_authunix_create
crypto/krb5/src/include/gssrpc/rename.h:64:#define authunix_create_default	gssrpc_authunix_create_default
sys/rpc/auth.h:231: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
sys/rpc/auth.h:241:extern AUTH *authunix_create(struct ucred *);
sys/rpc/auth.h:243:extern AUTH *authunix_create(char *, u_int, u_int, int, u_int *);
sys/rpc/auth.h:244:extern AUTH *authunix_create_default(void);	/* takes no parameters */
include/rpc/auth.h:240: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
include/rpc/auth.h:248:extern AUTH *authunix_create(char *, u_int, u_int, int, u_int *);
include/rpc/auth.h:249:extern AUTH *authunix_create_default(void);	/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:182: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
crypto/krb5/src/include/gssrpc/auth.h:189:extern AUTH *authunix_create(char *machname, int uid, int gid, int len,
crypto/krb5/src/include/gssrpc/auth.h:191:extern AUTH *authunix_create_default(void);	/* takes no parameters */
sys/fs/nfsclient/nfs_clrpcops.c:9899:	ext.rc_auth = authunix_create(cr);
sys/fs/nfs/nfs_commonkrpc.c:621:		return (authunix_create(cred));
sys/nlm/nlm_advlock.c:256:	auth = authunix_create(cred);
sys/nlm/nlm_prot_impl.c:1592:	nlm_auth = authunix_create(curthread->td_ucred);
sys/rpc/auth_unix.c:123:authunix_create(struct ucred *cred)
sys/rpc/auth_unix.c:200:		panic("authunix_create: failed to encode creds");
lib/libypclnt/ypclnt_passwd.c:187:	clnt->cl_auth = authunix_create_default();
lib/libypclnt/ypclnt_passwd.c:268:	clnt->cl_auth = authunix_create_default();
lib/libc/rpc/clnt_bcast.c:252:	AUTH 		*sys_auth = authunix_create_default();
lib/libc/rpc/auth_unix.c:89:authunix_create(char *machname, u_int uid, u_int gid, int len, u_int *aup_gids)
lib/libc/rpc/auth_unix.c:105:		warnx("authunix_create: out of memory");
lib/libc/rpc/auth_unix.c:106:		goto cleanup_authunix_create;
lib/libc/rpc/auth_unix.c:112:		warnx("authunix_create: out of memory");
lib/libc/rpc/auth_unix.c:113:		goto cleanup_authunix_create;
```

GREP `authnone_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:65:#define authnone_create		gssrpc_authnone_create
sys/rpc/auth.h:246:extern AUTH *authnone_create(void);		/* takes no parameters */
include/rpc/auth.h:250:extern AUTH *authnone_create(void);		/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:192:extern AUTH *authnone_create(void);		/* takes no parameters */
usr.sbin/rpcbind/rpcb_svc_com.c:825:		auth = authnone_create();
usr.sbin/rpcbind/rpcb_svc_com.c:834:			auth = authnone_create();
sys/fs/nfs/nfs_commonkrpc.c:836:		auth = authnone_create();
sys/rpc/auth_none.c:100:authnone_create(void)
sys/rpc/clnt_rc.c:119:	cl->cl_auth = authnone_create();
sys/rpc/clnt_nl.c:227:		.cl_auth = authnone_create(),
sys/rpc/clnt_vc.c:259:	cl->cl_auth = authnone_create();
sys/rpc/clnt_bck.c:170:	cl->cl_auth = authnone_create();
sys/rpc/clnt_dg.c:311:	cl->cl_auth = authnone_create();
lib/libc/rpc/auth_none.c:74:authnone_create(void)
lib/libc/rpc/clnt_raw.c:131:	client->cl_auth = authnone_create();
lib/libc/rpc/clnt_vc.c:294:	cl->cl_auth = authnone_create();
lib/libc/rpc/clnt_dg.c:285:	cl->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/auth_none.c:77:authnone_create(void)
crypto/krb5/src/lib/rpc/clnt_raw.c:129:	client->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_tcp.c:233:	h->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_udp.c:204:	cl->cl_auth = authnone_create();
```

GREP `authdes_create`:
```
sys/rpc/auth.h:258:extern AUTH *authdes_create (char *, u_int, struct sockaddr *, des_block *);
include/rpc/auth.h:261:extern AUTH *authdes_create (char *, u_int, struct sockaddr *, des_block *);
lib/librpcsvc/yp_update.c:102:	if ((clnt->cl_auth = (AUTH *)authdes_create(netname, WINDOW, NULL,
lib/libc/rpc/rpc_soc.c:371:authdes_create(char *servername, u_int window, struct sockaddr *syncaddr,
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `AUTH` handle is internally allocated and initialized by trusted constructors; it is not derived from or controllable by untrusted network input.

The vulnerability report flags a missing NULL check on the `ah_ops` pointer within the `AUTH` structure, which is accessed via macros like `AUTH_NEXTVERF`. I have analyzed the data flow and the nature of the `AUTH` object. The `AUTH` structure is an internal handle used by the RPC client library. It is allocated and initialized by specific constructor functions (e.g., `authunix_create`, `authnone_create`, `authdes_create`). These constructors allocate the `AUTH` structure on the heap and assign a pointer to a static, constant `auth_ops` table specific to the authentication flavor (e.g., `auth_ops_none`, `auth_ops_unix`). 

Crucially, an external attacker does not provide the `AUTH` handle; they provide `opaque_auth` credentials (the data), which are then passed as arguments to the functions pointed to by `ah_ops`. There is no mechanism in the RPC protocol for a remote attacker to inject a pointer or a corrupted `AUTH` structure into the client-side memory where these macros are executed. The only way `ah_ops` could be NULL is if a constructor failed to initialize it or if there was a separate memory corruption vulnerability (which would be the root cause, not this missing check). Therefore, this is a code quality issue regarding internal API safety, not a reachable security vulnerability.

CRUX: The `AUTH` handle is internally allocated and initialized by trusted constructors; it is not derived from or controllable by untrusted network input.
GREP: authunix_create|authnone_create|authdes_create

🔎 **Grep results:**

GREP `authunix_create`:
```
sys/rpc/auth.h:267:#define authsys_create(c,i1,i2,i3,ip) authunix_create((c),(i1),(i2),(i3),(ip))
sys/rpc/auth.h:268:#define authsys_create_default() authunix_create_default()
include/rpc/auth.h:270:#define authsys_create(c,i1,i2,i3,ip) authunix_create((c),(i1),(i2),(i3),(ip))
include/rpc/auth.h:271:#define authsys_create_default() authunix_create_default()
crypto/krb5/src/include/gssrpc/rename.h:63:#define authunix_create		gssrpc_authunix_create
crypto/krb5/src/include/gssrpc/rename.h:64:#define authunix_create_default	gssrpc_authunix_create_default
sys/rpc/auth.h:231: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
sys/rpc/auth.h:241:extern AUTH *authunix_create(struct ucred *);
sys/rpc/auth.h:243:extern AUTH *authunix_create(char *, u_int, u_int, int, u_int *);
sys/rpc/auth.h:244:extern AUTH *authunix_create_default(void);	/* takes no parameters */
include/rpc/auth.h:240: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
include/rpc/auth.h:248:extern AUTH *authunix_create(char *, u_int, u_int, int, u_int *);
include/rpc/auth.h:249:extern AUTH *authunix_create_default(void);	/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:182: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
crypto/krb5/src/include/gssrpc/auth.h:189:extern AUTH *authunix_create(char *machname, int uid, int gid, int len,
crypto/krb5/src/include/gssrpc/auth.h:191:extern AUTH *authunix_create_default(void);	/* takes no parameters */
sys/fs/nfs/nfs_commonkrpc.c:621:		return (authunix_create(cred));
sys/fs/nfsclient/nfs_clrpcops.c:9899:	ext.rc_auth = authunix_create(cr);
sys/rpc/auth_unix.c:123:authunix_create(struct ucred *cred)
sys/rpc/auth_unix.c:200:		panic("authunix_create: failed to encode creds");
sys/nlm/nlm_advlock.c:256:	auth = authunix_create(cred);
sys/nlm/nlm_prot_impl.c:1592:	nlm_auth = authunix_create(curthread->td_ucred);
lib/libypclnt/ypclnt_passwd.c:187:	clnt->cl_auth = authunix_create_default();
lib/libypclnt/ypclnt_passwd.c:268:	clnt->cl_auth = authunix_create_default();
usr.sbin/ypbind/yp_ping.c:259:	clnt->cl_auth = authunix_create_default();
lib/libc/rpc/clnt_bcast.c:252:	AUTH 		*sys_auth = authunix_create_default();
lib/libc/rpc/auth_unix.c:89:authunix_create(char *machname, u_int uid, u_int gid, int len, u_int *aup_gids)
lib/libc/rpc/auth_unix.c:105:		warnx("authunix_create: out of memory");
lib/libc/rpc/auth_unix.c:106:		goto cleanup_authunix_create;
lib/libc/rpc/auth_unix.c:112:		warnx("authunix_create: out of memory");
```

GREP `authnone_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:65:#define authnone_create		gssrpc_authnone_create
sys/rpc/auth.h:246:extern AUTH *authnone_create(void);		/* takes no parameters */
include/rpc/auth.h:250:extern AUTH *authnone_create(void);		/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:192:extern AUTH *authnone_create(void);		/* takes no parameters */
sys/fs/nfs/nfs_commonkrpc.c:836:		auth = authnone_create();
sys/rpc/auth_none.c:100:authnone_create(void)
sys/rpc/clnt_bck.c:170:	cl->cl_auth = authnone_create();
sys/rpc/clnt_nl.c:227:		.cl_auth = authnone_create(),
sys/rpc/clnt_rc.c:119:	cl->cl_auth = authnone_create();
sys/rpc/clnt_vc.c:259:	cl->cl_auth = authnone_create();
sys/rpc/clnt_dg.c:311:	cl->cl_auth = authnone_create();
lib/libc/rpc/auth_none.c:74:authnone_create(void)
lib/libc/rpc/clnt_raw.c:131:	client->cl_auth = authnone_create();
lib/libc/rpc/clnt_dg.c:285:	cl->cl_auth = authnone_create();
lib/libc/rpc/clnt_vc.c:294:	cl->cl_auth = authnone_create();
usr.sbin/rpcbind/rpcb_svc_com.c:825:		auth = authnone_create();
usr.sbin/rpcbind/rpcb_svc_com.c:834:			auth = authnone_create();
crypto/krb5/src/lib/rpc/auth_none.c:77:authnone_create(void)
crypto/krb5/src/lib/rpc/clnt_tcp.c:233:	h->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_raw.c:129:	client->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_udp.c:204:	cl->cl_auth = authnone_create();
```

GREP `authdes_create`:
```
include/rpc/auth.h:261:extern AUTH *authdes_create (char *, u_int, struct sockaddr *, des_block *);
sys/rpc/auth.h:258:extern AUTH *authdes_create (char *, u_int, struct sockaddr *, des_block *);
lib/librpcsvc/yp_update.c:102:	if ((clnt->cl_auth = (AUTH *)authdes_create(netname, WINDOW, NULL,
lib/libc/rpc/rpc_soc.c:371:authdes_create(char *servername, u_int window, struct sockaddr *syncaddr,
```

### Round 3: ❌ INVALID

**🎯 Crux:** The `AUTH` handle and its `ah_ops` pointer are internally managed and initialized by trusted constructors, not derived from untrusted network input.

The vulnerability report identifies a missing NULL check for `ah_ops` when using macros like `AUTH_NEXTVERF`. However, the `AUTH` structure (the handle) is an internal object created by trusted constructor functions (e.g., `authunix_create`, `authnone_create`). These constructors allocate the `AUTH` structure and assign a pointer to a static, constant `auth_ops` table. An external attacker cannot provide or modify this `AUTH` handle via network input; they provide `opaque_auth` credentials, which are passed as arguments to the functions already defined in the `ah_ops` table. For `ah_ops` to be NULL, there would need to be a failure in the internal constructor or a pre-existing memory corruption vulnerability. This makes the missing check a code quality issue for internal API robustness, not a security vulnerability reachable by an external attacker.

CRUX: The `AUTH` handle and its `ah_ops` pointer are internally managed and initialized by trusted constructors, not derived from untrusted network input.
GREP: authunix_create|authnone_create|authdes_create

🔎 **Grep results:**

GREP `authunix_create`:
```
sys/rpc/auth.h:267:#define authsys_create(c,i1,i2,i3,ip) authunix_create((c),(i1),(i2),(i3),(ip))
sys/rpc/auth.h:268:#define authsys_create_default() authunix_create_default()
crypto/krb5/src/include/gssrpc/rename.h:63:#define authunix_create		gssrpc_authunix_create
crypto/krb5/src/include/gssrpc/rename.h:64:#define authunix_create_default	gssrpc_authunix_create_default
include/rpc/auth.h:270:#define authsys_create(c,i1,i2,i3,ip) authunix_create((c),(i1),(i2),(i3),(ip))
include/rpc/auth.h:271:#define authsys_create_default() authunix_create_default()
sys/rpc/auth.h:231: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
sys/rpc/auth.h:241:extern AUTH *authunix_create(struct ucred *);
sys/rpc/auth.h:243:extern AUTH *authunix_create(char *, u_int, u_int, int, u_int *);
sys/rpc/auth.h:244:extern AUTH *authunix_create_default(void);	/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:182: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
crypto/krb5/src/include/gssrpc/auth.h:189:extern AUTH *authunix_create(char *machname, int uid, int gid, int len,
crypto/krb5/src/include/gssrpc/auth.h:191:extern AUTH *authunix_create_default(void);	/* takes no parameters */
include/rpc/auth.h:240: * AUTH *authunix_create(machname, uid, gid, len, aup_gids)
include/rpc/auth.h:248:extern AUTH *authunix_create(char *, u_int, u_int, int, u_int *);
include/rpc/auth.h:249:extern AUTH *authunix_create_default(void);	/* takes no parameters */
usr.sbin/ypbind/yp_ping.c:259:	clnt->cl_auth = authunix_create_default();
usr.sbin/rpc.lockd/kern.c:254:        cl->cl_auth = authunix_create(hostname,
usr.sbin/rpc.umntall/rpc.umntall.c:182:	clp->cl_auth = authunix_create_default();
usr.sbin/rpcbind/rpcb_svc_com.c:830:		auth = authunix_create(au->aup_machname,
usr.sbin/ypset/ypset.c:94:	client->cl_auth = authunix_create_default();
sys/fs/nfsclient/nfs_clrpcops.c:9899:	ext.rc_auth = authunix_create(cr);
sys/fs/nfs/nfs_commonkrpc.c:621:		return (authunix_create(cred));
sys/rpc/auth_unix.c:123:authunix_create(struct ucred *cred)
sys/rpc/auth_unix.c:200:		panic("authunix_create: failed to encode creds");
sys/nlm/nlm_advlock.c:256:	auth = authunix_create(cred);
sys/nlm/nlm_prot_impl.c:1592:	nlm_auth = authunix_create(curthread->td_ucred);
lib/libypclnt/ypclnt_passwd.c:187:	clnt->cl_auth = authunix_create_default();
lib/libypclnt/ypclnt_passwd.c:268:	clnt->cl_auth = authunix_create_default();
lib/libc/rpc/clnt_bcast.c:252:	AUTH 		*sys_auth = authunix_create_default();
```

GREP `authnone_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:65:#define authnone_create		gssrpc_authnone_create
sys/rpc/auth.h:246:extern AUTH *authnone_create(void);		/* takes no parameters */
include/rpc/auth.h:250:extern AUTH *authnone_create(void);		/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:192:extern AUTH *authnone_create(void);		/* takes no parameters */
usr.sbin/rpcbind/rpcb_svc_com.c:825:		auth = authnone_create();
usr.sbin/rpcbind/rpcb_svc_com.c:834:			auth = authnone_create();
sys/fs/nfs/nfs_commonkrpc.c:836:		auth = authnone_create();
sys/rpc/auth_none.c:100:authnone_create(void)
sys/rpc/clnt_nl.c:227:		.cl_auth = authnone_create(),
sys/rpc/clnt_bck.c:170:	cl->cl_auth = authnone_create();
sys/rpc/clnt_rc.c:119:	cl->cl_auth = authnone_create();
sys/rpc/clnt_dg.c:311:	cl->cl_auth = authnone_create();
sys/rpc/clnt_vc.c:259:	cl->cl_auth = authnone_create();
lib/libc/rpc/auth_none.c:74:authnone_create(void)
lib/libc/rpc/clnt_raw.c:131:	client->cl_auth = authnone_create();
lib/libc/rpc/clnt_dg.c:285:	cl->cl_auth = authnone_create();
lib/libc/rpc/clnt_vc.c:294:	cl->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/auth_none.c:77:authnone_create(void)
crypto/krb5/src/lib/rpc/clnt_tcp.c:233:	h->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_raw.c:129:	client->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_udp.c:204:	cl->cl_auth = authnone_create();
```

GREP `authdes_create`:
```
include/rpc/auth.h:261:extern AUTH *authdes_create (char *, u_int, struct sockaddr *, des_block *);
sys/rpc/auth.h:258:extern AUTH *authdes_create (char *, u_int, struct sockaddr *, des_block *);
lib/librpcsvc/yp_update.c:102:	if ((clnt->cl_auth = (AUTH *)authdes_create(netname, WINDOW, NULL,
lib/libc/rpc/rpc_soc.c:371:authdes_create(char *servername, u_int window, struct sockaddr *syncaddr,
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability claims a risk of Null Pointer Dereference or ACE due to missing NULL checks on the `ah_ops` pointer in the `AUTH` structure. However, the `AUTH` structure is an internal object managed by the RPC library. It is initialized via trusted constructor functions (e.g., `authunix_create`, `authnone_create`), which allocate the structure and assign it a pointer to a static, constant operations table. There is no evidence that these internal handles are derived from or controllable by untrusted network input. An attacker providing network credentials affects the `opaque_auth` data, not the internal `AUTH` handle's function pointer table. Therefore, the risk of an attacker controlling `ah_ops` to achieve ACE or triggering a NULL dereference via external input is not supported by the code.

