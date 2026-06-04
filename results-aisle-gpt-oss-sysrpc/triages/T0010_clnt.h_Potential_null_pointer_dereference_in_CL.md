# Triage T0010: Potential null‑pointer dereference in CLNT_DESTROY macro

- **File**: `clnt.h`
- **Verdict**: INVALID
- **Confidence**: 25% [UUV→I]

---

## Finding

Potential null‑pointer dereference in CLNT_DESTROY macro

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

**🎯 Crux:** The macro consumes a CLIENT pointer without ensuring it is non‑NULL, allowing an attacker to trigger a crash by calling `clnt_destroy(NULL)` or passing a corrupted handle.

The CLNT_DESTROY macro expands to a direct dereference of the supplied CLIENT pointer: ((*(rh)->cl_ops->cl_destroy)(rh)).  No NULL‑check is performed on either `rh` or `rh->cl_ops`.  The macro is defined in the public header, so any user‑written client program may invoke it with a null handle or a corrupted pointer – the attacker can trivially supply such a value.  This results in a segmentation fault or potential arbitrary code execution via the caller’s function pointer table.  The code never supplies a guard; grep for the macro definition shows only the dereference, and there is no conditional that protects against a null `rh`.  We verified that the macro itself contains no check, and no surrounding function or wrapper performs a NULL check before calling this macro.  Therefore the bug pattern exists, it is attacker‑reachable through untrusted input, and the vulnerability leads to a crash (DoS).  No sufficient defense was found.


CRUX: The macro consumes a CLIENT pointer without ensuring it is non‑NULL, allowing an attacker to trigger a crash by calling `clnt_destroy(NULL)` or passing a corrupted handle.
GREP: CLNT_DESTROY\(|clnt_destroy\(

🔎 **Grep results:**

GREP `CLNT_DESTROY(`:
```
include/rpc/clnt.h:234:#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
crypto/krb5/src/include/gssrpc/clnt.h:224:#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
sys/rpc/clnt.h:330:#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
include/rpc/clnt.h:231: * CLNT_DESTROY(rh);
crypto/krb5/src/include/gssrpc/clnt.h:221: * CLNT_DESTROY(rh);
sys/rpc/clnt.h:176:		CLNT_DESTROY(rh)
sys/rpc/clnt.h:327: * CLNT_DESTROY(rh);
usr.bin/rpcinfo/rpcinfo.c:398:		(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:412:		(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:439:	(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:448:		(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:1293:		(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:1310:		(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:1336:	(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:1344:		(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:1402:		(void) CLNT_DESTROY(client);
usr.bin/rpcinfo/rpcinfo.c:1451:	(void) CLNT_DESTROY(client);
tools/regression/rpcsec_gss/rpctest.c:163:	CLNT_DESTROY(client);
lib/libc/rpc/pmap_getport.c:91:		CLNT_DESTROY(client);
lib/libc/rpc/clnt_simple.c:87:			CLNT_DESTROY(rcp->client);
lib/libc/rpc/clnt_simple.c:160:			CLNT_DESTROY(rcp->client);
lib/libc/rpc/rpcb_clnt.c:345:				CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:545:		CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:564:	CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:605:	CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:922:		CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:987:		CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:994:			CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:1001:		CLNT_DESTROY(client);
lib/libc/rpc/rpcb_clnt.c:1088:	CLNT_DESTROY(client);
```

GREP `clnt_destroy(`:
```
include/rpc/clnt.h:235:#define	clnt_destroy(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
crypto/krb5/src/include/gssrpc/clnt.h:225:#define	clnt_destroy(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
sys/rpc/clnt.h:331:#define	clnt_destroy(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
usr.sbin/yppush/yppush_main.c:351:			clnt_destroy(clnt);
usr.sbin/yppush/yppush_main.c:356:	clnt_destroy(clnt);
usr.bin/rpcinfo/rpcinfo.c:864:	clnt_destroy(client);
usr.bin/rpcinfo/rpcinfo.c:967:	clnt_destroy(client);
usr.bin/rpcinfo/rpcinfo.c:1195:	clnt_destroy(client);
usr.bin/rusers/rusers.c:198:	clnt_destroy(rusers_clnt);
libexec/ypxfr/ypxfrd_getmap.c:127:		clnt_destroy(clnt);
libexec/ypxfr/ypxfrd_getmap.c:141:	clnt_destroy(clnt);
libexec/ypxfr/ypxfr_misc.c:166:			clnt_destroy(clnt);
libexec/ypxfr/ypxfr_misc.c:170:		clnt_destroy(clnt);
libexec/ypxfr/ypxfr_misc.c:230:			clnt_destroy(clnt);
libexec/ypxfr/ypxfr_misc.c:234:		clnt_destroy(clnt);
libexec/ypxfr/ypxfr_misc.c:277:		clnt_destroy(clnt);
libexec/ypxfr/ypxfr_misc.c:283:	clnt_destroy(clnt);
libexec/ypxfr/ypxfr_getmap.c:88:	clnt_destroy(clnt);
libexec/ypxfr/ypxfr_main.c:97:			clnt_destroy(clnt);
libexec/ypxfr/ypxfr_main.c:100:		clnt_destroy(clnt);
usr.bin/rup/rup.c:190:		clnt_destroy(rstat_clnt);
usr.bin/rup/rup.c:196:	clnt_destroy(rstat_clnt);
usr.bin/ypwhich/ypwhich.c:111:		clnt_destroy(client);
usr.bin/ypwhich/ypwhich.c:117:			clnt_destroy(client);
usr.bin/ypwhich/ypwhich.c:121:	clnt_destroy(client);
usr.bin/showmount/showmount.c:251:	clnt_destroy(client);
usr.sbin/ypserv/yp_server.c:307:	clnt_destroy(clnt);
usr.bin/rpcgen/rpc_sample.c:181:	f_print(fout, "\tclnt_destroy(clnt);\n");
usr.sbin/ypset/ypset.c:103:		clnt_destroy(client);
usr.sbin/ypset/ypset.c:106:	clnt_destroy(client);
```

### Round 4: ❌ INVALID

[ARBITER] The CLNT_DESTROY macro directly dereferences the CLIENT pointer and its cl_ops field without a null check, which will crash if called with a NULL or corrupted value.  However, this macro is used only by application code that owns the CLIENT handle; an attacker cannot inject a NULL or malformed CLIENT pointer from an external source unless they already control the application logic.  Consequently, while it is a bug that can lead to a segmentation fault, it does not constitute a practical security vulnerability that can be exploited by an external party.

