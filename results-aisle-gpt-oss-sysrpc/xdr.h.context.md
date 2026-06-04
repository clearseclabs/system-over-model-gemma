# Context: xdr.h

**Context Briefing – `xdr.h` (NetBSD RPC XDR interface)**  
*(≈250 words)*

1. **What it does / position in project**  
   `xdr.h` declares the core XDR (External Data Representation) interface used by the NetBSD RPC stack. It defines the `XDR` handle, operation codes (`XDR_ENCODE`, `XDR_DECODE`, `XDR_FREE`), helper macros, and the public XDR I/O functions (`xdr_getlong`, `xdr_putbytes`, `xdr_string`, etc.). The header is included by all modules that need to serialize/deserialize RPC arguments (e.g., `/usr/include/xdr.h` in the kernel RPC module and user‑land `libc` RPC wrapper).  

2. **Untrusted input source**  
   XDR data originates from network sockets (`xdrrec_create`, `xdrmbuf_create`), files or shared memory. The `XDR` struct contains a `char *x_public` pointer that holds the application‑supplied data; during `XDR_DECODE` the routine pulls bytes from the underlying stream and writes them into buffers supplied by the caller. Thus attacker‑controlled data can reach this code via any decoded packet or file read.  

3. **Attacker‑controlled variables**  
   * `xdrs->x_op`: the operation type – controlled by caller context.  
   * The `void *argresp` parameter of an `xdrproc_t` – when decoding, the caller supplies a pointer that points to a buffer or `NULL` (the XDR code then allocates).  
   * Length fields in `xdr_array`, `xdr_bytes`, `xdr_string`: `len` and `maxsize` passed by the caller are derived from network‑supplied values.  
   * `xdr_discrim`’s `value` field in `xdr_union`: discriminant comes from incoming data.  

4. **Fixed‑size buffers / constants**  

   ```
   BYTES_PER_XDR_UNIT      // 4
   MAX_NETOBJ_SZ           // 1024
   RNDUP(x)                // round‑up to BYTES_PER_XDR_UNIT boundary
   IXDR_GET_INT32          // reads 4 bytes
   IXDR_PUT_INT32          // writes 4 bytes
   ```

   **GREP results**  
   GREP: `#define MAX_NETOBJ_SZ` → `1024`  
   GREP: `#define BYTES_PER_XDR_UNIT` → `4`  

5. **Dangerous data flows** (based on header‑level info)  
   * Attacker data → `xdr_getbytes(xdrs, addr, len)` → addr (caller‑provided buffer, size ≤ len).  
   * `xdr_string` decodes into a heap buffer allocated by the library; size comes from the network.  
   * `xdr_union` chooses a procedure based on `value`; if an out‑of‑range value is supplied, a default routine is called only if provided.  

6. **NULL‑unsafe parameters**  
   * `xdrs->x_ops` and function pointers within may be `NULL`. Implementations usually check but the header does not guarantee it.  
   * `argresp` may be `NULL` for decoding; callers must handle allocation.  

7. **Tagged unions / variant validation**  
   `xdr_union` inspects the discriminant (`value`) against an array of `struct xdr_discrim`. It invokes the matching `proc`; if none matches, a default is called only when supplied. Thus type‑tag validation is performed by the public routine.  

8. **API vs helpers**  
   All symbols declared as `extern` are part of the public API (e.g., `xdr_int`, `xdr_string`). Static helpers reside in the source files (`xdr.c`, `xdrrec.c`) and are not exposed. No public helper is exposed directly in this header.  

9. **Likely bug classes**  
   * **Buffer overflows** – fixed‑size read/write macros (`IXDR_GET_INT32`, `IXDR_PUT_INT32`) assume 4‑byte boundaries.  
   * **Null pointer dereference** – if `x_ops` or function pointers in it are `NULL`.  
   * **Protocol validation** – incorrect discriminant handling may lead to unexpected data handling if `xdr_union` is mis‑wired.  
   * **Memory leaks** – `XDR_FREE` misuse if application fails to release dynamically allocated buffers.  

*End of briefing.*

[GREP RESULTS from codebase]:
GREP `#define MAX_NETOBJ_SZ` → `1024 (simplified to: MAX_NETOBJ_SZ)`:
```
include/rpc/xdr.h:318:#define MAX_NETOBJ_SZ 1024
sys/rpc/xdr.h:331:#define MAX_NETOBJ_SZ 1024
crypto/krb5/src/include/gssrpc/xdr.h:289:#define MAX_NETOBJ_SZ 2048
sys/xdr/xdr.c:547:	return (xdr_bytes(xdrs, &np->n_bytes, &np->n_len, MAX_NETOBJ_SZ));
usr.sbin/rpc.lockd/lock_proc.c:103:	char objvalbuffer[(sizeof(char)*2)*MAX_NETOBJ_SZ+2];
usr.sbin/rpc.lockd/lock_proc.c:104:	char objascbuffer[sizeof(char)*MAX_NETOBJ_SZ+1];
usr.sbin/rpc.lockd/lock_proc.c:109:	if (obj->n_len > MAX_NETOBJ_SZ)	{
usr.sbin/rpc.lockd/lock_proc.c:112:		    MAX_NETOBJ_SZ, obj->n_len);
usr.sbin/rpc.lockd/lock_proc.c:115:	maxlen = (obj->n_len < MAX_NETOBJ_SZ ? obj->n_len : MAX_NETOBJ_SZ);
lib/libc/xdr/xdr.c:618:	return (xdr_bytes(xdrs, &np->n_bytes, &np->n_len, MAX_NETOBJ_SZ));
crypto/krb5/src/lib/rpc/xdr.c:493:	return (xdr_bytes(xdrs, &np->n_bytes, &np->n_len, MAX_NETOBJ_SZ));
crypto/krb5/src/lib/rpc/authgss_prot.c:97:	xdr_stat = xdr_rpc_gss_buf(xdrs, p, MAX_NETOBJ_SZ);
crypto/krb5/src/lib/rpc/authgss_prot.c:112:	xdr_stat = (xdr_rpc_gss_buf(xdrs, &p->gr_ctx, MAX_NETOBJ_SZ) &&
crypto/krb5/src/lib/rpc/authgss_prot.c:116:		    xdr_rpc_gss_buf(xdrs, &p->gr_token, MAX_NETOBJ_SZ));
```

GREP `#define BYTES_PER_XDR_UNIT` → `4 (simplified to: BYTES_PER_XDR_UNIT)`:
```
include/rpc/xdr.h:87:#define BYTES_PER_XDR_UNIT	(4)
include/rpc/xdr.h:88:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
sys/rpc/xdr.h:89:#define BYTES_PER_XDR_UNIT	(4)
sys/rpc/xdr.h:90:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
crypto/krb5/src/include/gssrpc/xdr.h:90:#define BYTES_PER_XDR_UNIT	(4)
crypto/krb5/src/include/gssrpc/xdr.h:91:#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
include/rpc/xdr.h:89:		    * BYTES_PER_XDR_UNIT)
sys/rpc/xdr.h:91:		    * BYTES_PER_XDR_UNIT)
crypto/krb5/src/include/gssrpc/xdr.h:92:		    * BYTES_PER_XDR_UNIT)
sys/xdr/xdr_sizeof.c:50:	xdrs->x_handy += BYTES_PER_XDR_UNIT;
sys/xdr/xdr.c:68:static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };
sys/xdr/xdr.c:438:	static int crud[BYTES_PER_XDR_UNIT];
sys/xdr/xdr.c:449:	rndup = cnt % BYTES_PER_XDR_UNIT;
sys/xdr/xdr.c:451:		rndup = BYTES_PER_XDR_UNIT - rndup;
usr.bin/genl/parser_rpc.c:81:	if ((buf = XDR_INLINE(&xdrs, 8 * BYTES_PER_XDR_UNIT)) == NULL) {
usr.bin/genl/parser_rpc.c:126:	buf = XDR_INLINE(&xdrs, 2 * BYTES_PER_XDR_UNIT);
usr.bin/rpcgen/rpc_cout.c:444:						f_print(fout, "buf = XDR_INLINE(xdrs, %d * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:449:								"buf = XDR_INLINE(xdrs, (%s) * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:453:								"buf = XDR_INLINE(xdrs, (%d + (%s)) * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:498:				f_print(fout, "\t\tbuf = XDR_INLINE(xdrs, %d * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:503:						"\t\tbuf = XDR_INLINE(xdrs, (%s) * BYTES_PER_XDR_UNIT);",
usr.bin/rpcgen/rpc_cout.c:507:						"\t\tbuf = XDR_INLINE(xdrs, (%d + (%s)) * BYTES_PER_XDR_UNIT);",
lib/libc/xdr/xdr_rec.c:640:	i = (u_int32_t)((u_long)rstrm->in_boundry % BYTES_PER_XDR_UNIT);
lib/libc/xdr/xdr_sizeof.c:51:	xdrs->x_handy += BYTES_PER_XDR_UNIT;
lib/libc/xdr/xdr.c:68:static const char xdr_zero[BYTES_PER_XDR_UNIT] = { 0, 0, 0, 0 };
lib/libc/xdr/xdr.c:508:	static int crud[BYTES_PER_XDR_UNIT];
lib/libc/xdr/xdr.c:519:	rndup = cnt % BYTES_PER_XDR_UNIT;
lib/libc/xdr/xdr.c:521:		rndup = BYTES_PER_XDR_UNIT - rndup;
lib/libc/rpc/rpcb_st_xdr.c:90:		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
lib/libc/rpc/rpcb_st_xdr.c:128:		buf = XDR_INLINE(xdrs, 6 * BYTES_PER_XDR_UNIT);
```

GREP `results**`:
```
include/nss.h:49:#define __nss_compat_result(rv, err)		\
include/wordexp.h:64:#define	WRDE_NOSPACE	4		/* no memory for result */
include/rpc/rpc_msg.h:99:#define	ar_results	ru.AR_results
include/stdckdint.h:15:#define ckd_add(result, a, b)						\
include/stdckdint.h:18:#define ckd_add(result, a, b)						\
include/stdckdint.h:23:#define ckd_sub(result, a, b)						\
include/stdckdint.h:26:#define ckd_sub(result, a, b)						\
include/stdckdint.h:31:#define ckd_mul(result, a, b)						\
include/stdckdint.h:34:#define ckd_mul(result, a, b)						\
include/rpcsvc/nis_tags.h:62:#define	ALL_RESULTS	(1<<3)	/* Retrieve all results 		*/
include/rpcsvc/nis_tags.h:63:#define	NO_CACHE	(1<<4)	/* Do not return 'cached' results 	*/
include/rpcsvc/nis_tags.h:68:#define	RETURN_RESULT	(1<<7)	/* Return resulting object to client    */
contrib/libpcap/portability.h:118:#define timeradd(a, b, result)                       \
contrib/libpcap/portability.h:129:#define timersub(a, b, result)                       \
contrib/gdtoa/gdtoaimp.h:560:#define	dtoa_result	__dtoa_result_D2A
contrib/less/less.h:235:#define MAX_PRCHAR_LEN      31  /* Max chars in prchar() result */
contrib/ncurses/progs/infocmp.c:352:#define TIC_EXPAND(result) _nc_tic_expand(result, outform==F_TERMINFO, numbers)
contrib/libcbor/src/cbor/common.h:97:#define _CBOR_NODISCARD __attribute__((warn_unused_result))
contrib/ncurses/progs/dump_entry.c:162:#define NameTrans(check,result) \
contrib/jemalloc/src/jemalloc.c:1149:#define CONF_VALUE_READ(max_t, result)					\
contrib/bmake/make.h:139:#define MAKE_ATTR_USE		__attribute__((__warn_unused_result__))
contrib/sendmail/src/sendmail.h:1544:#define MF_SECURE	0x02000000	/* DNSSEC result is "secure" */
contrib/ncurses/ncurses/base/lib_mouse.c:128:#define DosExit(action, result )	/* do nothing */
contrib/sqlite3/sqlite3ext.h:482:#define sqlite3_result_blob            sqlite3_api->result_blob
contrib/sqlite3/sqlite3ext.h:483:#define sqlite3_result_double          sqlite3_api->result_double
contrib/sqlite3/sqlite3ext.h:484:#define sqlite3_result_error           sqlite3_api->result_error
contrib/sqlite3/sqlite3ext.h:485:#define sqlite3_result_error16         sqlite3_api->result_error16
contrib/sqlite3/sqlite3ext.h:486:#define sqlite3_result_int             sqlite3_api->result_int
contrib/sqlite3/sqlite3ext.h:487:#define sqlite3_result_int64           sqlite3_api->result_int64
contrib/sqlite3/sqlite3ext.h:488:#define sqlite3_result_null            sqlite3_api->result_null
```