# Context: rpcsec_tls/rpctlscd.x

**Context Briefing – `rpcsec_tls/rpctlscd.x` (≈250 words)**  

1. **What the file does & where it sits**  
   `rpctl_tls/rpctlscd.x` is an XDR (External Data Representation) source defining the client‑side RPC program that mediates TLS‑secured RPC calls in FreeBSD’s rpcsec_tls subsystem.  It is compiled by `rpcgen` into C stubs (`rpctlscd.h`, `rpctlscd.c`) and installed under the RPC infrastructure.  The program number is `0x40677374`, version `2`, and the RPC service (`RPCTLSCD`) exposes three operations: `CONNECT`, `HANDLERECORD`, and `DISCONNECT`.

2. **Untrusted input path**  
   All arguments arrive over the network via the underlying RPC transport (UDP/TCP).  The client invokes `RPCTLSCD_CONNECT`, `RPCTLSCD_HANDLERECORD`, etc., passing data that originates from a potentially malicious remote endpoint.

3. **Attacker‑controlled variables**  
   * `socookie` – a 64‑bit opaque token supplied **by the caller**.  
   * `certname` – a variable‑length string (`char certname<>;`) carrying the server’s certificate name, also supplied by the caller.  
   Data flows from the network layer → XDR deserialization → these fields → the generated C function signatures (`rpctlscd_connect`, `rpctlscd_handlerecord`, `rpctlscd_disconnect`).  No sanitization occurs in the XDR file itself; validation must happen in the generated code or the RPC server implementation.

4. **Fixed‑size buffers/size constants**  
   The XDR file contains **no** statically sized buffers or numeric constants.  The only numeric literal is the program number `0x40677374`.  GREP confirms no other constants:  
   ```
   GREP: "^#define"  (no matches)
   GREP: "uint8_t" (no matches)
   ```

5. **Dangerous data flows**  
   * `certname` → variable‑length XDR string field.  The eventual C representation depends on `rpcgen`’s `char *` allocation; if the server incorrectly assumes a maximum size, a buffer overflow can arise.  The size bound is **not** defined in this file.  `socookie` is 64 bits; overflow is unlikely but misuse (e.g., interpreting it as a pointer) can be dangerous.

6. **NULL‑pointer derefs**  
   None are specified in the XDR file.  The server‑side stubs must guard against `NULL` in `certname`, which XDR can legitimately encode as an empty string.

7. **Tagged unions / variant types**  
   None present in this XDR file.

8. **API vs. helpers**  
   - *Public API*: the RPC program `RPCTLSCD` and its operations (`RPCTLSCD_CONNECT`, `RPCTLSCD_HANDLERECORD`, `RPCTLSCD_DISCONNECT`).  
   - *Static helpers*: none in the XDR definition; helper code resides in the generated C file.

9. **Likely bug classes given this structure**  
   * **Untrusted input handling** – improper validation of variable‑length `certname`.  
   * **Buffer overflows / length misuse** – when the server or client copies or bounds `certname` based on incorrect assumptions.  
   * **Parameter semantics** – potential misuse of `socookie` if treated as a pointer or offset.

*End of briefing.*

[GREP RESULTS from codebase]:
GREP `^#define"  (no matches) (simplified to: define)`:
```
stand/arm64/libarm64/cache.c:39:#define	CACHE_FLAG_DIC_OFF	(1<<0)
stand/arm64/libarm64/cache.c:40:#define	CACHE_FLAG_IDC_OFF	(1<<1)
stand/arm64/libarm64/cache.h:29:#define	_CACHE_H_
include/ndbm.h:36:#define	_NDBM_H_
include/ndbm.h:41:#define DBM_RDONLY	O_RDONLY
include/ndbm.h:44:#define DBM_INSERT      0
include/ndbm.h:45:#define DBM_REPLACE     1
include/ndbm.h:51:#define	DBM_SUFFIX	".db"
include/ndbm.h:59:#define	dbm_pagfno(a)	DBM_PAGFNO_NOT_AVAILABLE
gnu/lib/libdialog/dlg_config.h:6:#define CURSES_WACS_ARRAY _nc_wacs
gnu/lib/libdialog/dlg_config.h:7:#define CURSES_WACS_SYMBOLS 1
gnu/lib/libdialog/dlg_config.h:8:#define DIALOG_PATCHDATE 20210117
gnu/lib/libdialog/dlg_config.h:9:#define DIALOG_VERSION "1.3"
gnu/lib/libdialog/dlg_config.h:11:#define GCC_NORETURN __attribute__((noreturn))
gnu/lib/libdialog/dlg_config.h:13:#define GCC_PRINTF 1
gnu/lib/libdialog/dlg_config.h:15:#define GCC_PRINTFLIKE(fmt,var) __attribute__((format(printf,fmt,var)))
gnu/lib/libdialog/dlg_config.h:17:#define GCC_SCANF 1
gnu/lib/libdialog/dlg_config.h:19:#define GCC_SCANFLIKE(fmt,var) __attribute__((format(scanf,fmt,var)))
gnu/lib/libdialog/dlg_config.h:22:#define GCC_UNUSED __attribute__((unused))
gnu/lib/libdialog/dlg_config.h:24:#define HAVE_ALLOCA 1
gnu/lib/libdialog/dlg_config.h:25:#define HAVE_BTOWC 1
gnu/lib/libdialog/dlg_config.h:26:#define HAVE_COLOR 1
gnu/lib/libdialog/dlg_config.h:27:#define HAVE_DIRENT_H 1
gnu/lib/libdialog/dlg_config.h:28:#define HAVE_DLG_FORMBOX 1
gnu/lib/libdialog/dlg_config.h:29:#define HAVE_DLG_GAUGE 1
gnu/lib/libdialog/dlg_config.h:30:#define HAVE_DLG_MIXEDFORM 1
gnu/lib/libdialog/dlg_config.h:31:#define HAVE_DLG_TAILBOX 1
gnu/lib/libdialog/dlg_config.h:32:#define HAVE_DLG_TRACE 1
gnu/lib/libdialog/dlg_config.h:33:#define HAVE_FEOF_UNLOCKED 1
gnu/lib/libdialog/dlg_config.h:34:#define HAVE_FLUSHINP 1
```

GREP `uint8_t" (no matches) (simplified to: uint8_t)`:
```
sys/net/pfvar.h:2086:#define	PF_STATELIM_ID_MAX	255 /* fits in pf_state uint8_t */
sys/net/pfvar.h:2092:#define	PF_SOURCELIM_ID_MAX	255 /* fits in pf_state uint8_t */
sys/arm64/include/_inttypes.h:77:#define	PRIo8		"o"	/* uint8_t */
sys/arm64/include/_inttypes.h:92:#define	PRIu8		"u"	/* uint8_t */
sys/arm64/include/_inttypes.h:107:#define	PRIx8		"x"	/* uint8_t */
sys/arm64/include/_inttypes.h:122:#define	PRIX8		"X"	/* uint8_t */
sys/arm64/include/_inttypes.h:171:#define	SCNo8		"hho"	/* uint8_t */
sys/arm64/include/_inttypes.h:186:#define	SCNu8		"hhu"	/* uint8_t */
sys/arm64/include/_inttypes.h:201:#define	SCNx8		"hhx"	/* uint8_t */
sys/fs/tarfs/tarfs_vfsops.c:97:#define	USTAR_MAGIC		(uint8_t []){ 'u', 's', 't', 'a', 'r', 0 }
sys/fs/tarfs/tarfs_vfsops.c:98:#define	USTAR_VERSION		(uint8_t []){ '0', '0' }
sys/fs/tarfs/tarfs_vfsops.c:99:#define	GNUTAR_MAGIC		(uint8_t []){ 'u', 's', 't', 'a', 'r', ' ' }
sys/fs/tarfs/tarfs_vfsops.c:100:#define	GNUTAR_VERSION		(uint8_t []){ ' ', '\x0' }
sys/fs/tarfs/tarfs_io.c:98:#define XZ_MAGIC		(uint8_t[]){ 0xfd, 0x37, 0x7a, 0x58, 0x5a }
sys/fs/tarfs/tarfs_io.c:99:#define ZLIB_MAGIC		(uint8_t[]){ 0x1f, 0x8b, 0x08 }
sys/fs/tarfs/tarfs_io.c:100:#define ZSTD_MAGIC		(uint8_t[]){ 0x28, 0xb5, 0x2f, 0xfd }
sys/amd64/include/cpufunc.h:48:#define readb(va)	(*(volatile uint8_t *) (va))
sys/amd64/include/cpufunc.h:53:#define writeb(va, d)	(*(volatile uint8_t *) (va) = (d))
sys/kern/subr_stats.c:200:#define	BLOB_OFFSET(sb, off) ((void *)(((uint8_t *)(sb)) + (off)))
sys/powerpc/include/_inttypes.h:83:#define	PRIo8		"o"		/* uint8_t */
sys/powerpc/include/_inttypes.h:98:#define	PRIu8		"u"		/* uint8_t */
sys/powerpc/include/_inttypes.h:113:#define	PRIx8		"x"		/* uint8_t */
sys/powerpc/include/_inttypes.h:128:#define	PRIX8		"X"		/* uint8_t */
sys/powerpc/include/_inttypes.h:177:#define	SCNo8		"hho"		/* uint8_t */
sys/powerpc/include/_inttypes.h:192:#define	SCNu8		"hhu"		/* uint8_t */
sys/powerpc/include/_inttypes.h:207:#define	SCNx8		"hhx"		/* uint8_t */
sys/i386/include/cpufunc.h:43:#define readb(va)	(*(volatile uint8_t *) (va))
sys/i386/include/cpufunc.h:47:#define writeb(va, d)	(*(volatile uint8_t *) (va) = (d))
usr.bin/sdiotool/linux_compat.h:36:#define u8 uint8_t
sys/dev/rtwn/if_rtwn_ridx.h:64:#define RTWN_RIDX_UNKNOWN	(uint8_t)-1
```