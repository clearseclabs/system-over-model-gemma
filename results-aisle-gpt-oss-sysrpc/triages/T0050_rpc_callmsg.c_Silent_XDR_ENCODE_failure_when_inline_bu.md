# Triage T0050: Silent XDR_ENCODE failure when inline buffer unavailable

- **File**: `rpc_callmsg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUU→I]

---

## Finding

Silent XDR_ENCODE failure when inline buffer unavailable

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** xdr_callmsg correctly falls back to generic encoding/decoding when XDR_INLINE returns NULL; the control flow does not silently skip encoding/decoding or expose unchecked memory accesses.

The function "xdr_callmsg" handles both encode and decode modes. When "XDR_INLINE" fails during the encode section it merely skips the inline write and later falls into the generic "xdr_*" fallback path that correctly encodes the data based on the current operation. The code after the encode block is not jumped to the decode block because the operation remains "XDR_ENCODE". The fallback path is fully operation‑aware (the same "xdr_*" functions will encode or decode according to the value of "xdrs->x_op"). 

During decode, a NULL result from "XDR_INLINE" likewise triggers the fallback path, which handles binary data safely. No unchecked pointer derefs, buffer overflows, or other data‑corrupting actions can be triggered via untrusted input. The only checks on lengths use the constant "MAX_AUTH_BYTES", which is safely verified before any memory allocation or memcpy.

Therefore the reported silent failure is a misinterpretation of the control flow; it does not constitute a security vulnerability.

Crucial control‑flow facts verified:
1. The encode case ends with a return on success; otherwise it proceeds past the if block.
2. The next if checks for "x_op == XDR_DECODE", which will not be true if we are still encoding.
3. The final block unconditionally executes the generic "xdr_*" helpers, which respect the operation mode.
4. All length checks guard against overruns.

Hence the bug pattern is not exploitable and is not security‑relevant.


CRUX: xdr_callmsg correctly falls back to generic encoding/decoding when XDR_INLINE returns NULL; the control flow does not silently skip encoding/decoding or expose unchecked memory accesses.
GREP: MAX_AUTH_BYTES\|BYTES_PER_XDR_UNIT\|RNDUP

🔎 **Grep results:**

GREP `MAX_AUTH_BYTES\`:
```
(no matches in repo)
```

GREP `BYTES_PER_XDR_UNIT\`:
```
(no matches in repo)
```

GREP `RNDUP`:
```
kerberos5/include/config.h:856:#define HAVE_STRNDUP 1
include/rpc/xdr.h:88:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
sys/fs/nfs/nfsm_subs.h:152:#define	NFSM_RNDUP(a)	(((a)+3)&(~0x3))
lib/libpam/modules/pam_krb5/config.h:244:#define HAVE_STRNDUP 1
lib/libmagic/config.h:196:#define HAVE_STRNDUP 1
sys/rpc/xdr.h:90:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
contrib/openbsm/config/config.h:167:#define HAVE_STRNDUP 1
contrib/openbsm/bin/auditdistd/strndup.h:31:#define	_STRNDUP_H_
contrib/mandoc/config.h:39:#define HAVE_STRNDUP 1
crypto/krb5/src/include/gssrpc/xdr.h:91:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
contrib/llvm-project/compiler-rt/lib/sanitizer_common/sanitizer_platform_interceptors.h:161:#define SANITIZER_INTERCEPT_STRNDUP SI_POSIX
contrib/llvm-project/compiler-rt/lib/sanitizer_common/sanitizer_platform_interceptors.h:162:#define SANITIZER_INTERCEPT___STRNDUP SI_GLIBC
crypto/openssh/config.h:1333:#define HAVE_STRNDUP 1
contrib/llvm-project/compiler-rt/lib/hwasan/hwasan_platform_interceptors.h:75:#define SANITIZER_INTERCEPT_STRNDUP 0
contrib/llvm-project/compiler-rt/lib/hwasan/hwasan_platform_interceptors.h:78:#define SANITIZER_INTERCEPT___STRNDUP 0
kerberos5/include/config.h:1374:/* #undef NEED_STRNDUP_PROTO */
sys/fs/nfs/nfsproto.h:281:				 NFSX_HYPER + NFSM_RNDUP(NFSX_V4PNFSFH))
sys/fs/nfs/nfsproto.h:283:    ((m) * (NFSX_V4DEVICEID + NFSX_STATEID + NFSM_RNDUP(NFSX_V4PNFSFH) +	\
contrib/openbsm/bin/auditdistd/strndup.h:30:#ifndef	_STRNDUP_H_
contrib/openbsm/bin/auditdistd/strndup.h:53:#endif	/* !_STRNDUP_H_ */
contrib/pam-krb5/portable/system.h:145:#if !HAVE_STRNDUP
crypto/openssh/config.h:83:/* #undef BROKEN_STRNDUP */
crypto/openssh/openbsd-compat/openbsd-compat.h:129:#ifndef HAVE_STRNDUP
contrib/llvm-project/compiler-rt/lib/hwasan/hwasan_platform_interceptors.h:74:#undef SANITIZER_INTERCEPT_STRNDUP
contrib/llvm-project/compiler-rt/lib/hwasan/hwasan_platform_interceptors.h:77:#undef SANITIZER_INTERCEPT___STRNDUP
sys/xdr/xdr_mem.c:284:		len = RNDUP((int)(*l));
usr.bin/genl/parser_rpc.c:113:		buf = XDR_INLINE(&xdrs, RNDUP(oa->oa_length));
usr.bin/genl/parser_rpc.c:149:		buf = XDR_INLINE(&xdrs, RNDUP(oa->oa_length));
sys/fs/nfsclient/nfs_clcomsubs.c:69:	rem = NFSM_RNDUP(siz) - siz;
sys/fs/nfsclient/nfs_clcomsubs.c:191:	rem = NFSM_RNDUP(siz) - siz;
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The control flow in `xdr_callmsg` is operation‑aware. The first `if (xdrs->x_op == XDR_ENCODE)` block encodes normally using `XDR_INLINE()` when it succeeds, otherwise it skips only that inline path and falls through to the final generic encoding sequence that calls `xdr_uint32_t`, `xdr_enum`, `xdr_opaque_auth`, etc. This fallback correctly performs an XDR encode, so the function never silently returns FALSE for an encode request. There is no observable buffer overflow or silent error path that could be abused. The claim that it “falls through to the decode logic” is incorrect because the decode part is guarded by `xdrs->x_op == XDR_DECODE`, which is false during encoding. Therefore the reported issue is not a real vulnerability. 

