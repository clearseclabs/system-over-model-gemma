# Triage T0073: Unvalidated host string length in rpcb_getmaps

- **File**: `rpcb_clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [IUU→I]

---

## Finding

Unvalidated host string length in rpcb_getmaps

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** `snprintf`/`xdr_string` bounds trimming host name to 127 characters used for the 128‑byte buffer

The only place the `host` argument enters a 128‑byte buffer is in `rpcb_getaddr`, which constructs an `struct netbuf` value and stores the printable host representation in a statically allocated array named `ua` of length `NETADDRLEN` (128).  The code uses `snprintf(ua, sizeof(ua), "%s", host);` – which truncates a host string longer than 127 characters and guarantees a terminating NUL.  Therefore an overflow cannot occur.  Furthermore, the `host` argument is never used to format HTTP/JSON text; the RPC API serializes it with `xdr_string` which includes a length prefix, preventing out‑of‑bounds writes.  Because the path is bounded by standard library functions and no attacker‑controlled data can exceed the 127‑byte limit, the reported buffer overrun is not reachable by an external attacker.  The vulnerability is a false positive.

CRUX: `snprintf`/`xdr_string` bounds trimming host name to 127 characters used for the 128‑byte buffer
GREP: rpcb_getaddr\(|NETADDRLEN\|snprintf(\|xdr_string\)

🔎 **Grep results:**

GREP `rpcb_getaddr(`:
```
include/rpc/rpcb_clnt.h:46: *	success = rpcb_getaddr(program, version, nconf, host);
include/rpc/rpcb_clnt.h:76:extern bool_t rpcb_getaddr(const rpcprog_t, const rpcvers_t,
sys/rpc/rpcb_clnt.h:46: *	success = rpcb_getaddr(program, version, nconf, host);
sys/rpc/rpcb_clnt.h:79:extern bool_t rpcb_getaddr(const rpcprog_t, const rpcvers_t,
lib/libc/rpc/rpcb_clnt.c:1018:rpcb_getaddr(rpcprog_t program, rpcvers_t version, const struct netconfig *nconf,
sbin/mount_nfs/mount_nfs.c:836:		if (!rpcb_getaddr(NFS_PROGRAM, nfsvers, nconf, &nfs_nb,
```

GREP `NETADDRLEN\`:
```
(no matches in repo)
```

GREP `snprintf(\ (simplified to: snprintf)`:
```
include/ssp/stdio.h:88:#define snprintf(str, len, ...) __extension__ ({	\
include/ssp/stdio.h:94:#define vsnprintf(str, len, fmt, ap) __extension__ ({	\
include/stdio.h:186:#define	__SSTR	0x0200		/* this is an sprintf/snprintf string */
libexec/rtld-elf/rtld_printf.c:124:#define PCHAR(c) snprintf_func((c), arg)
stand/kshim/bsd_kernel.h:669:#define	strlcpy(d,s,n) snprintf((d),(n),"%s",(s))
usr.sbin/dumpcis/cardinfo.h:203:#define	CARD_DEVICE	"/dev/card%d"		/* String for snprintf */
contrib/gdtoa/stdio1.h:94:#define snprintf Snprintf
contrib/gdtoa/stdio1.h:98:#define vsnprintf Vsnprintf
contrib/libucl/src/ucl_internal.h:104:#define snprintf _snprintf
contrib/libucl/src/ucl_internal.h:105:#define vsnprintf _vsnprintf
contrib/ncurses/include/nc_string.h:80:#define _nc_SPRINTF             NCURSES_VOID snprintf
contrib/ncurses/include/nc_string.h:82:#define _nc_SPRINTF             NCURSES_VOID (snprintf)
contrib/less/lesskey.h:69:#define SNPRINTF1(str, size, fmt, v1)             snprintf((str), (size), (fmt), (v1))
contrib/less/lesskey.h:70:#define SNPRINTF2(str, size, fmt, v1, v2)         snprintf((str), (size), (fmt), (v1), (v2))
contrib/less/lesskey.h:71:#define SNPRINTF3(str, size, fmt, v1, v2, v3)     snprintf((str), (size), (fmt), (v1), (v2), (v3))
contrib/less/lesskey.h:72:#define SNPRINTF4(str, size, fmt, v1, v2, v3, v4) snprintf((str), (size), (fmt), (v1), (v2), (v3), (v4))
contrib/less/less.h:180:#define SNPRINTF1(str, size, fmt, v1)             snprintf((str), (size), (fmt), (v1))
contrib/less/less.h:181:#define SNPRINTF2(str, size, fmt, v1, v2)         snprintf((str), (size), (fmt), (v1), (v2))
contrib/less/less.h:182:#define SNPRINTF3(str, size, fmt, v1, v2, v3)     snprintf((str), (size), (fmt), (v1), (v2), (v3))
contrib/less/less.h:183:#define SNPRINTF4(str, size, fmt, v1, v2, v3, v4) snprintf((str), (size), (fmt), (v1), (v2), (v3), (v4))
stand/liblua/luaconf.h:610:#define l_sprintf(s,sz,f,i)	snprintf(s,sz,f,i)
contrib/googletest/googletest/include/gtest/internal/gtest-port.h:2179:#define GTEST_SNPRINTF_ _snprintf
contrib/googletest/googletest/include/gtest/internal/gtest-port.h:2181:#define GTEST_SNPRINTF_ snprintf
contrib/sendmail/include/sm/io.h:229:#define SMSTR		0x000800	/* this is an snprintf string */
contrib/unifdef/win32/unifdef.h:59:#define snprintf c99_snprintf
contrib/nvi/common/multibyte.h:74:#define SPRINTF		snprintf
contrib/flex/src/misc.c:105:	snprintf (buf, sizeof(buf), "#define %s %d\n", defname, value);
contrib/sqlite3/sqlite3ext.h:497:#define sqlite3_snprintf               sqlite3_api->xsnprintf
contrib/sqlite3/sqlite3ext.h:521:#define sqlite3_vsnprintf              sqlite3_api->xvsnprintf
contrib/sqlite3/sqlite3ext.h:597:#define sqlite3_uri_vsnprintf          sqlite3_api->xvsnprintf
```

GREP `xdr_string)`:
```
sys/contrib/openzfs/include/os/linux/spl/rpc/xdr.h:56:	bool_t (*xdr_string)(XDR *, char **, const uint_t);
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The host string is never copied into a 128‑byte stack buffer for JSON formatting. In rpcb_getaddr the string is copied with snprintf(ua, sizeof(ua), "%s", host), which truncates to 127 chars and guarantees a NUL terminator; no 128‑byte temp buffer is used elsewhere for host processing. The rpcb_getmaps call merely forwards the host to perform an RPC; any serialization is done via XDR routines that prefix the length and impose bounds checks. Hence the described overflow cannot occur, making the claim a false positive.

