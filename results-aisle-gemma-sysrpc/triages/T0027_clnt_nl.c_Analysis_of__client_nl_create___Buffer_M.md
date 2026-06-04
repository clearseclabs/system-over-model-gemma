# Triage T0027: Analysis of `client_nl_create` (Buffer Management)

- **File**: `clnt_nl.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Analysis of `client_nl_create` (Buffer Management)

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** client_nl_create is an internal initialization function using fixed auth (authnone) and deterministic inputs; it is not reachable by untrusted user input.

The vulnerability report claims that `client_nl_create` might overflow the `nl->nl_mcallc` buffer (size `MCALL_MSG_SIZE`) when calling `xdr_putint32` and `AUTH_MARSHALL`. 

1. **Bug Pattern:** `xdrmem_create` is used to initialize an XDR stream pointing to `nl->nl_mcallc` with a limit of `MCALL_MSG_SIZE`. If the encoded data exceeds this limit, the XDR library's behavior determines if an overflow occurs. In standard XDR implementations (like those used in FreeBSD/SUN RPC), `xdrmem_create` tracks the buffer boundary, and `xdr_put*` functions check for available space, returning `FALSE` (or 0) on failure rather than writing past the end of the buffer.

2. **Reachability:** `client_nl_create` is called to initialize an RPC client. The arguments `program` and `version` are typically hardcoded constants in the kernel's RPC client calls (e.g., for NFS). The `cl->cl_auth` is initialized to `authnone_create()`. This function is NOT triggered by untrusted input; it is part of the kernel's internal setup to create a client for communicating with userland.

3. **Analysis of the 'Overflow':** The code uses `MPASS(rv)` after `xdr_putint32` and `AUTH_MARSHALL`. `MPASS` is a FreeBSD kernel assertion that panics the system if the condition is false. If the buffer were too small, `rv` would be false, and the kernel would panic. A kernel panic is a Denial of Service, but it is not a heap overflow (which would allow memory corruption/execution). More importantly, since `client_nl_create` is called during internal kernel initialization and uses fixed authentication (`authnone`), the data written to the buffer is deterministic and not attacker-controlled.

4. **Verdict:** The 'overflow' is actually a bounded write that would lead to a panic via `MPASS` if the limit were exceeded, but since the input is internal/static, it's not reachable by an attacker. Even if it were, it's a crash (DoS) at best, but the inputs to this specific function are not untrusted.

CRUX: client_nl_create is an internal initialization function using fixed auth (authnone) and deterministic inputs; it is not reachable by untrusted user input.
GREP: MCALL_MSG_SIZE

🔎 **Grep results:**

GREP `MCALL_MSG_SIZE`:
```
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_dg.c:152:#define	MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_tcp.c:67:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_raw.c:49:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:110:	char		ct_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:144:	char		nl_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:234:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:242:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_bck.c:159:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_vc.c:238:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_dg.c:142:	char			cu_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_dg.c:250:	xdrmem_create(&xdrs, cu->cu_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
lib/libc/rpc/clnt_raw.c:67:	    char 		mashl_callmsg[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_vc.c:110:		char	ct_mcallc[MCALL_MSG_SIZE];	/* marshalled callmsg */
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:286:	assert(ct->ct_mpos + sizeof(uint32_t) <= MCALL_MSG_SIZE);
lib/libc/rpc/clnt_dg.c:168:	char			cu_outhdr[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_tcp.c:98:	  char		ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
crypto/krb5/src/lib/rpc/clnt_tcp.c:215:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcall, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_raw.c:60:	  char	            mashl_callmsg[MCALL_MSG_SIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:113:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
```

### Round 2: ❌ INVALID

**🎯 Crux:** xdrmem_create implements bounds checking that prevents overflows; any exceedance of the 24-byte buffer would trigger an MPASS panic, not memory corruption, and the function is not reachable via untrusted input.

The report suggests that `client_nl_create` can cause a buffer overflow in `nl->nl_mcallc` (size 24 bytes). However, the code uses `xdrmem_create` to initialize the XDR stream. In the FreeBSD/SUN RPC implementation, `xdrmem_create` explicitly takes the buffer size as an argument and the subsequent `xdr_put*` functions perform bounds checking against this size. If the data to be written exceeds the buffer, the XDR functions return `FALSE` rather than overflowing the buffer. The code uses `MPASS(rv)` after these calls; `MPASS` is a kernel assertion that will trigger a panic if `rv` is false. While a panic is a Denial of Service, it is not a buffer overflow. Furthermore, `client_nl_create` is an internal kernel initialization function. The inputs (`program`, `version`) and the authentication (`authnone_create()`) are deterministic and internal, not provided by an external attacker. Therefore, there is no path for an attacker to trigger this condition, and the 'overflow' is actually a safe (though potentially crashing) bounds-checked write.

CRUX: xdrmem_create implements bounds checking that prevents overflows; any exceedance of the 24-byte buffer would trigger an MPASS panic, not memory corruption, and the function is not reachable via untrusted input.
GREP: MCALL_MSG_SIZE

🔎 **Grep results:**

GREP `MCALL_MSG_SIZE`:
```
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_dg.c:152:#define	MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_tcp.c:67:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_raw.c:49:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:110:	char		ct_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
lib/libc/rpc/clnt_raw.c:67:	    char 		mashl_callmsg[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_vc.c:110:		char	ct_mcallc[MCALL_MSG_SIZE];	/* marshalled callmsg */
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:286:	assert(ct->ct_mpos + sizeof(uint32_t) <= MCALL_MSG_SIZE);
lib/libc/rpc/clnt_dg.c:168:	char			cu_outhdr[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_tcp.c:98:	  char		ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
crypto/krb5/src/lib/rpc/clnt_tcp.c:215:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcall, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_raw.c:60:	  char	            mashl_callmsg[MCALL_MSG_SIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:113:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_bck.c:159:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_nl.c:144:	char		nl_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:234:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:242:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_vc.c:238:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_dg.c:142:	char			cu_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_dg.c:250:	xdrmem_create(&xdrs, cu->cu_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
```

### Round 3: ❌ INVALID

**🎯 Crux:** xdrmem_create enforces the 24-byte limit, causing an MPASS panic (not an overflow) if exceeded, and the function is only called with internal, deterministic data.

The reported vulnerability describes a potential buffer overflow in `client_nl_create` within the `nl->nl_mcallc` buffer (size `MCALL_MSG_SIZE` = 24 bytes). However, the code utilizes `xdrmem_create`, which initializes an XDR stream with an explicit buffer limit. In the RPC XDR implementation, `xdr_put*` functions check the current position against the buffer limit and return `FALSE` (0) if the write would exceed the boundary. The code specifically uses `MPASS(rv)` after every `xdr_put` and `AUTH_MARSHALL` call. `MPASS` is a FreeBSD kernel assertion; if the buffer were exceeded, the kernel would panic (DoS), not suffer a memory corruption overflow. Furthermore, `client_nl_create` is an internal initialization function. The inputs `program` and `version` are kernel-provided constants, and `cl->cl_auth` is hardcoded to `authnone_create()`. There is no path for an external attacker to provide untrusted input to `client_nl_create` to trigger this condition. Since the buffer is bounded by the XDR library and the inputs are internal and deterministic, this is not a security vulnerability.

CRUX: xdrmem_create enforces the 24-byte limit, causing an MPASS panic (not an overflow) if exceeded, and the function is only called with internal, deterministic data.
GREP: MCALL_MSG_SIZE

🔎 **Grep results:**

GREP `MCALL_MSG_SIZE`:
```
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_dg.c:152:#define	MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_tcp.c:67:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_raw.c:49:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:110:	char		ct_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:144:	char		nl_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:234:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:242:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_vc.c:238:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_bck.c:159:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_dg.c:142:	char			cu_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_dg.c:250:	xdrmem_create(&xdrs, cu->cu_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
lib/libc/rpc/clnt_raw.c:67:	    char 		mashl_callmsg[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_vc.c:110:		char	ct_mcallc[MCALL_MSG_SIZE];	/* marshalled callmsg */
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:286:	assert(ct->ct_mpos + sizeof(uint32_t) <= MCALL_MSG_SIZE);
lib/libc/rpc/clnt_dg.c:168:	char			cu_outhdr[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_tcp.c:98:	  char		ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
crypto/krb5/src/lib/rpc/clnt_tcp.c:215:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcall, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_raw.c:60:	  char	            mashl_callmsg[MCALL_MSG_SIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:113:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability report claims a buffer overflow in `nl->nl_mcallc` (24 bytes). However, the code uses `xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE)`, which initializes the XDR stream with a strict limit of 24 bytes. In this implementation, `xdr_put*` and `AUTH_MARSHALL` perform bounds checking against this limit and return FALSE if the buffer is exceeded. The code then uses `MPASS(rv)`, which causes a kernel panic (fail-fast) if the limit is exceeded, rather than allowing a buffer overflow. Additionally, `client_nl_create` uses deterministic, internal data (authnone), making it unreachable by untrusted user input.

