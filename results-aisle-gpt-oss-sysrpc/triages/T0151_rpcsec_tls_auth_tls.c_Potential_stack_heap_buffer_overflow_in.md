# Triage T0151: Potential stack/heap buffer overflow in auth initialization

- **File**: `rpcsec_tls/auth_tls.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI→I]

---

## Finding

Potential stack/heap buffer overflow in auth initialization

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** ap->mclient always contains the two zero‑length auths that require 16 bytes, which fits MAX_MARSHAL_SIZE=20, so no overflow can occur and the bug is unreachable.

The buffer `mclient` is 20 bytes long (MAX_MARSHAL_SIZE). In `authtls_init` the code writes two opaque_auth structures with zero length. Each encoded auth consists of a 4‑byte flavor, a 4‑byte length, and no data bytes, for a total of 8 bytes per auth. Thus the two auths occupy exactly 16 bytes, safely under 20. The only place `mclient` and `mcnt` are written is `authtls_init`, which is executed once at boot by the `SYSINIT` macro. There are no functions that supply an external argument to influence the contents or size of this buffer, and no other code path re‑needs to marshal variable data into it. Therefore the alleged “overflow” cannot be triggered by an attacker or even via the public API; the buffer is always written with a constant payload that comfortably fits. No defensive check is required, because the invariant holds by design. The scan’s claim is based on a generic “put bytes > buffer” pattern, but the concrete data flow shows the bug pattern does not exist in an attacker‑reachable path.

Conclusion: the finding is a false positive.

"UNCONFIRMED DEFENSE" NOTE: No defensive guard is present, but the buffer’s size is sufficient for the expected payload. The vulnerability is not real.

We provide a grep pattern to verify the size calculation and constants.


CRUX: ap->mclient always contains the two zero‑length auths that require 16 bytes, which fits MAX_MARSHAL_SIZE=20, so no overflow can occur and the bug is unreachable.
GREP: MAX_MARSHAL_SIZE\|xdr_opaque_auth\|ap->mclient\|authtls_init

🔎 **Grep results:**

GREP `MAX_MARSHAL_SIZE\`:
```
(no matches in repo)
```

GREP `xdr_opaque_auth\`:
```
(no matches in repo)
```

GREP `ap->mclient\ (simplified to: ap->mclient)`:
```
sys/rpc/auth_none.c:91:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
sys/rpc/auth_none.c:115:	if (!XDR_PUTBYTES(xdrs, ap->mclient, ap->mcnt))
sys/rpc/rpcsec_tls/auth_tls.c:100:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
sys/rpc/rpcsec_tls/auth_tls.c:124:	if (!XDR_PUTBYTES(xdrs, ap->mclient, ap->mcnt))
```

GREP `authtls_init`:
```
sys/rpc/rpcsec_tls/auth_tls.c:89:authtls_init(void *dummy)
sys/rpc/rpcsec_tls/auth_tls.c:106:SYSINIT(authtls_init, SI_SUB_KMEM, SI_ORDER_ANY, authtls_init, NULL);
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** ap->mclient always contains exactly 16 bytes of data (two zero‑length opaque_auths), safely under MAX_MARSHAL_SIZE=20; no attacker can influence this, so no real overflow possible.

The only buffer that could overflow is the static array `mclient[20]`. It is filled once at system start by `authtls_init`. Inside that function two opaque_auth structures of length 0 are XDR‑encoded into `mclient`. Each encoded authentication consumes exactly 8 bytes: 4‑byte flavor and 4‑byte length. 8 × 2 = 16 bytes, which is < MAX_MARSHAL_SIZE (20). Hence `mcnt` is set to 16. In `authtls_marshal`, the same 16 bytes are copied to the caller’s XDR stream via `XDR_PUTBYTES`. The function returns FALSE if the stream has insufficient room, but it never actually writes past the end of `mclient`. No external input can change the size of the data written to `mclient` or the value of `mcnt`; the only caller is the `SYSINIT(...)` macro, which runs during boot, not under untrusted control. Therefore the purported overflow is unreachable by an attacker and the bug pattern does not exist in an attacker‑reachable path.

CRUX: ap->mclient always contains exactly 16 bytes of data (two zero‑length opaque_auths), safely under MAX_MARSHAL_SIZE=20; no attacker can influence this, so no real overflow possible.
GREP: MAX_MARSHAL_SIZE|xdr_opaque_auth|authtls_init|SYSINIT

🔎 **Grep results:**

GREP `MAX_MARSHAL_SIZE`:
```
sys/rpc/auth_none.c:54:#define MAX_MARSHAL_SIZE 20
sys/rpc/rpcsec_tls/auth_tls.c:58:#define MAX_MARSHAL_SIZE 20
lib/libc/rpc/auth_none.c:51:#define MAX_MARSHAL_SIZE 20
sys/rpc/auth_none.c:77:	char	mclient[MAX_MARSHAL_SIZE];
sys/rpc/auth_none.c:91:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
sys/rpc/rpcsec_tls/auth_tls.c:81:	char	mclient[MAX_MARSHAL_SIZE];
sys/rpc/rpcsec_tls/auth_tls.c:100:	xdrmem_create(&xdrs, ap->mclient, MAX_MARSHAL_SIZE, XDR_ENCODE);
lib/libc/rpc/auth_none.c:69:	char	marshalled_client[MAX_MARSHAL_SIZE];
lib/libc/rpc/auth_none.c:94:		    (u_int)MAX_MARSHAL_SIZE, XDR_ENCODE);
```

GREP `xdr_opaque_auth`:
```
crypto/krb5/src/include/gssrpc/rename.h:66:#define xdr_opaque_auth		gssrpc_xdr_opaque_auth
include/rpc/auth.h:267:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
sys/rpc/auth.h:264:extern bool_t xdr_opaque_auth		(XDR *, struct opaque_auth *);
crypto/krb5/src/include/gssrpc/auth.h:193:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:63:extern bool_t xdr_opaque_auth(XDR *, struct opaque_auth *);
lib/libc/rpc/auth_none.c:95:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_cred);
lib/libc/rpc/auth_none.c:96:		(void)xdr_opaque_auth(xdrs, &ap->no_client.ah_verf);
lib/libc/rpc/rpc_prot.c:66:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
lib/libc/rpc/rpc_prot.c:107:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
lib/libc/rpc/clnt_vc.c:438:			(void)xdr_opaque_auth(xdrs,
lib/libc/rpc/clnt_raw.c:221:			(void)xdr_opaque_auth(xdrs, &(msg.acpted_rply.ar_verf));
lib/libc/rpc/rpc_callmsg.c:196:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
lib/libc/rpc/rpc_callmsg.c:197:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
lib/libc/rpc/clnt_dg.c:574:				(void) xdr_opaque_auth(xdrs,
lib/libc/rpc/auth_unix.c:247:		if (xdr_opaque_auth(&xdrs, &au->au_shcred)) {
lib/libc/rpc/auth_unix.c:251:			(void)xdr_opaque_auth(&xdrs, &au->au_shcred);
lib/libc/rpc/auth_unix.c:340:	if ((! xdr_opaque_auth(xdrs, &(auth->ah_cred))) ||
lib/libc/rpc/auth_unix.c:341:	    (! xdr_opaque_auth(xdrs, &(auth->ah_verf))))
sys/rpc/auth_none.c:92:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/auth_none.c:93:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/rpc_prot.c:72:xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
sys/rpc/rpc_prot.c:100:	if (! xdr_opaque_auth(xdrs, &(ar->ar_verf)))
sys/rpc/rpcsec_tls/auth_tls.c:101:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_cred);
sys/rpc/rpcsec_tls/auth_tls.c:102:	xdr_opaque_auth(&xdrs, &ap->no_client.ah_verf);
sys/rpc/rpc_callmsg.c:192:	    xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_cred)) )
sys/rpc/rpc_callmsg.c:193:		return (xdr_opaque_auth(xdrs, &(cmsg->rm_call.cb_verf)));
sys/rpc/rpcsec_gss/rpcsec_gss.c:543:	xdr_opaque_auth(xdrs, &creds);
sys/rpc/rpcsec_gss/rpcsec_gss.c:547:		if (!xdr_opaque_auth(xdrs, &_null_auth)) {
sys/rpc/rpcsec_gss/rpcsec_gss.c:591:		xdr_stat = xdr_opaque_auth(xdrs, &verf);
sys/rpc/auth_unix.c:277:		if (xdr_opaque_auth(&txdrs, &au->au_shcred)) {
```

GREP `authtls_init`:
```
sys/rpc/rpcsec_tls/auth_tls.c:89:authtls_init(void *dummy)
sys/rpc/rpcsec_tls/auth_tls.c:106:SYSINIT(authtls_init, SI_SUB_KMEM, SI_ORDER_ANY, authtls_init, NULL);
```

GREP `SYSINIT`:
```
stand/kshim/bsd_kernel.h:98:#define	SYSINIT(uniq, subs, order, _func, _data)	\
stand/kshim/sysinit.h:27:#define	_SYSINIT_H_
stand/kshim/sysinit.h:41:#define	SYSINIT_ENTRY(uniq, keyword, msb, lsb, g_type, g_name, debug)	\
sys/sys/mutex.h:522:#define	MTX_SYSINIT(name, mtx, desc, opts)				\
sys/sys/kernel.h:254:#define	C_SYSINIT(uniquifier, subsystem, order, func, ident)	\
sys/sys/kernel.h:269:#define	C_SYSINIT(uniquifier, subsystem, order, func, ident)	\
sys/sys/kernel.h:280:#define	SYSINIT(uniquifier, subsystem, order, func, ident)	\
sys/sys/sx.h:135:#define	SX_SYSINIT_FLAGS(name, sxa, desc, flags)			\
sys/sys/sx.h:146:#define	SX_SYSINIT(name, sxa, desc)	SX_SYSINIT_FLAGS(name, sxa, desc, 0)
sys/sys/rwlock.h:253:#define	RW_SYSINIT_FLAGS(name, rw, desc, flags)				\
sys/sys/rwlock.h:264:#define	RW_SYSINIT(name, rw, desc)	RW_SYSINIT_FLAGS(name, rw, desc, 0)
sys/sys/lock.h:211:#define	LOCK_DELAY_SYSINIT(func) \
sys/sys/lock.h:214:#define	LOCK_DELAY_SYSINIT_DEFAULT(lc) \
sys/sys/counter.h:70:#define	COUNTER_U64_SYSINIT(c)					\
sys/sys/rmlock.h:107:#define	RM_SYSINIT_FLAGS(name, rm, desc, flags)				\
sys/sys/rmlock.h:118:#define	RM_SYSINIT(name, rm, desc)	RM_SYSINIT_FLAGS(name, rm, desc, 0)
sys/net/vnet.c:203:#define	VNET_SYSINIT_WLOCK()	sx_xlock(&vnet_sysinit_sxlock);
sys/net/vnet.c:204:#define	VNET_SYSINIT_WUNLOCK()	sx_xunlock(&vnet_sysinit_sxlock);
sys/net/vnet.c:205:#define	VNET_SYSINIT_RLOCK()	sx_slock(&vnet_sysinit_sxlock);
sys/net/vnet.c:206:#define	VNET_SYSINIT_RUNLOCK()	sx_sunlock(&vnet_sysinit_sxlock);
sys/net/vnet.h:112:#define	VNET_PCPUSTAT_SYSINIT(name)	\
sys/net/vnet.h:339:#define	VNET_SYSINIT(ident, subsystem, order, func, arg)		\
sys/net/vnet.h:449:#define	VNET_SYSINIT(ident, subsystem, order, func, arg)		\
stand/kshim/bsd_kernel.h:95:SYSINIT(bsd_##name##_##busname##_driver_mod, SI_SUB_DRIVERS,		\
stand/kshim/bsd_kernel.h:103:SYSINIT_ENTRY(uniq##_entry, "sysinit", (subs),		\
stand/kshim/bsd_kernel.h:105:    UNIQ_NAME_STR(sysinit_##uniq), "SYSINIT")
stand/kshim/bsd_kernel.h:112:SYSINIT_ENTRY(uniq##_entry, "sysuninit", (subs),	\
stand/kshim/bsd_kernel.h:286:/* SYSINIT API */
stand/kshim/sysinit.h:26:#ifndef _SYSINIT_H_
stand/kshim/sysinit.h:56:#endif				/* _SYSINIT_H_ */
```

### Round 4: ❌ INVALID

[ARBITER] The static buffer `mclient` is 20 bytes (`MAX_MARSHAL_SIZE`). In `authtls_init` two zero‑length `opaque_auth` objects are serialized: each occupies 8 bytes (flavor + length, no data). Total 16 bytes < 20, so `ap->mcnt` is set to 16. `authtls_marshal` then copies exactly `mcnt` bytes with `XDR_PUTBYTES`; if the destination XDR has insufficient space it simply returns FALSE, not overrunning memory. No external input can change `mcnt` or exceed the 20‑byte buffer, so the described stack/heap overflow cannot occur. Hence the claim is a false positive. 

