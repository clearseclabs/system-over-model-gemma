# Context: types.h

**Context Briefing – NetBSD RPC `types.h` (≈250 words)**  

1. **Purpose & Placement**  
`types.h` supplies the fundamental data types, constants, and helper macros used throughout the NetBSD RPC subsystem. It lives in the `rpc` library source tree (`src/rpc/types.h`) and is included by both user‑level RPC clients and server components. The file defines integer‑based logical types (`bool_t`, `enum_t`), RPC identifiers (`rpcprog_t`, `rpcvers_t`, `rpcproc_t`, `rpcprot_t`, `rpcport_t`), and a flag (`rpc_inline_t`). It also declares the `struct netbuf`, `struct t_bind`, and internal `struct __rpc_sockinfo`.  

2. **Untrusted Input Path**  
The header itself does not process external data. However, types it defines are used by functions that parse network packets or configuration files (e.g., `rpcbind`, `sunrpc`). Untrusted data (network payload, `/etc/rpc`, `netconfig` entries) reaches those parsers, which then populate instances of the defined structs.  

3. **Attacker‑Controlled Variables**  
The only fields that can be set from external input are the members of `struct netbuf` (`maxlen`, `len`, `buf`) and `struct t_bind` (`addr`, `qlen`). Data is ultimately sourced from network buffers or configuration strings and stored in these fields before being processed by RPC routines.  

4. **Fixed‑Size Buffers & Constants**  
No fixed‑size arrays are declared in this file. The only constants are:  

- `__dontcare__` = **-1**  
- `FALSE` = **0**  
- `TRUE` = **1**  

No macro or #define gives a buffer size.  

5. **Dangerous Data Flows**  
Not applicable – no buffers to overflow.  

6. **Potential NULL Derefs**  
Not present; this header contains no functions that dereference pointers.  

7. **Tagged Unions**  
No unions or variant types.  

8. **API vs Helpers**  
`types.h` contains only type definitions, no functions. All functions that use these types are defined in other RPC source files and are part of the public RPC API (`rpcbind`, `sunrpc`).  

9. **Likely Bug Classes**  
Given its role, typical issues arise in the *consumers* of these types: mis‑assumed field widths, incorrect use of `struct netbuf` lengths, and unsafe dereference of the `buf` pointer. Buffer overreads/under‑reads and improper NULL checks in code that constructs or consumes these structs are the most common classes of bugs associated with this module.  

**GREP results (numeric values)**  
```
GREP: __dontcare__
__dontcare__  -1

GREP: FALSE
FALSE  0

GREP: TRUE
TRUE  1
```
---

[GREP RESULTS from codebase]:
GREP `__dontcare__`:
```
krb5/include/gssrpc/types.h:107:#define __dontcare__	-1
sys/rpc/types.h:52:#define __dontcare__	-1
sys/rpc/rpc_prot.c:163:	{ __dontcare__, NULL_xdrproc_t } };
lib/libc/rpc/rpc_prot.c:166:	{ __dontcare__, NULL_xdrproc_t } };
crypto/krb5/src/lib/rpc/rpc_prot.c:137:	{ __dontcare__, NULL_xdrproc_t } };
```

GREP `FALSE`:
```
sys/xdr/xdr.c:60:#define XDR_FALSE	((long) 0)
include/rpcsvc/yp_prot.h:177:#define YP_FALSE 	((long)0)	/* general purpose failure code */
stand/ficl/aarch64/sysdep.h:73:#define FALSE 0
stand/ficl/riscv/sysdep.h:73:#define FALSE 0
stand/ficl/arm/sysdep.h:73:#define FALSE 0
stand/ficl/ficl.h:252:#define FICL_FALSE (0)
stand/ficl/ficl.h:253:#define FICL_BOOL(x) ((x) ? FICL_TRUE : FICL_FALSE)
stand/ficl/amd64/sysdep.h:74:#define FALSE 0
stand/ficl/i386/sysdep.h:72:#define FALSE 0
stand/ficl/powerpc/sysdep.h:73:#define FALSE 0
libexec/bootpd/bootpgw/bootpgw.c:75:#define FALSE 0
libexec/bootpd/bootpd.h:36:#define FALSE	0
libexec/bootpd/hash.c:43:#define FALSE		0
usr.bin/fortune/fortune/fortune.c:53:#define	FALSE	false
lib/libdpv/dpv.h:36:#define FALSE 0
sys/fs/udf/osta.c:289:#define	FALSE	0
sys/fs/nfsclient/nfs_clvnops.c:104:#define	FALSE	0
sys/fs/nfs/nfsproto.h:202:#define	NFSERR_SEQFALSERETRY	10076
sys/fs/nfsserver/nfs_nfsdcache.c:245:#define	FALSE	0
usr.bin/m4/mdef.h:126:#define FALSE           0
crypto/openssl/crypto/ec/curve448/curve448utils.h:68:#define C448_FALSE 0
sys/contrib/ncsw/Peripherals/QM/qm.h:147:#define DEFAULT_dequeueDcaMode                  FALSE
sys/contrib/ncsw/Peripherals/QM/qm.h:151:#define DEFAULT_dequeueSpecifiedWq              FALSE
sys/contrib/ncsw/Peripherals/QM/qm.h:157:#define DEFAULT_pullMode                        FALSE
sys/contrib/ncsw/Peripherals/FM/MACSEC/fm_macsec_master.h:131:#define DEFAULT_invalidTagsFrameTreatment               FALSE
sys/contrib/ncsw/Peripherals/FM/MACSEC/fm_macsec_master.h:132:#define DEFAULT_encryptWithNoChangedTextFrameTreatment  FALSE
sys/contrib/ncsw/Peripherals/FM/MACSEC/fm_macsec_master.h:134:#define DEFAULT_changedTextWithNoEncryptFrameTreatment  FALSE
sys/contrib/ncsw/Peripherals/FM/MACSEC/fm_macsec_master.h:135:#define DEFAULT_onlyScbIsSetFrameTreatment              FALSE
sys/contrib/ncsw/Peripherals/FM/MACSEC/fm_macsec_master.h:136:#define DEFAULT_keysUnreadable                          FALSE
sys/contrib/ncsw/Peripherals/FM/MACSEC/fm_macsec_master.h:138:#define DEFAULT_sc0ReservedForPTP                       FALSE
```

GREP `TRUE`:
```
usr.sbin/cron/cron/macros.h:27:#define TRUE		1
cddl/contrib/opensolaris/tools/ctf/cvt/ctftools.h:75:#define	TRUE	1
share/doc/psd/20.ipctut/strchkread.c:34:#define TRUE 1
share/doc/psd/20.ipctut/streamread.c:33:#define TRUE 1
libexec/bootpd/bootpgw/bootpgw.c:74:#define TRUE 1
libexec/bootpd/bootpd.h:33:#define TRUE	1
sys/xdr/xdr.c:61:#define XDR_TRUE	((long) 1)
libexec/bootpd/hash.c:42:#define TRUE		1
stand/ficl/aarch64/sysdep.h:70:#define TRUE 1
stand/ficl/riscv/sysdep.h:70:#define TRUE 1
stand/ficl/arm/sysdep.h:70:#define TRUE 1
stand/ficl/powerpc/sysdep.h:70:#define TRUE 1
stand/ficl/ficl.h:251:#define FICL_TRUE  (~(FICL_UNS)0)
stand/ficl/ficl.h:253:#define FICL_BOOL(x) ((x) ? FICL_TRUE : FICL_FALSE)
stand/ficl/amd64/sysdep.h:71:#define TRUE 1
stand/ficl/i386/sysdep.h:69:#define TRUE 1
usr.bin/fortune/fortune/fortune.c:52:#define	TRUE	true
lib/clang/include/llvm/Config/config.h:27:#define HAVE_BACKTRACE TRUE
lib/clang/include/llvm/Config/config.h:114:#define HAVE_LIBEDIT TRUE
lib/libc/xdr/xdr.c:63:#define XDR_TRUE	((long) 1)
usr.bin/mt/mt.c:99:#define TRUE 1
sys/arm64/include/float.h:60:#define	FLT_TRUE_MIN	1.40129846E-45F	/* b**(emin-p) */
sys/arm64/include/float.h:75:#define	DBL_TRUE_MIN	4.9406564584124654E-324
sys/arm64/include/float.h:90:#define	LDBL_TRUE_MIN	6.475175119438025110924438958227646552E-4966L
usr.bin/m4/mdef.h:125:#define TRUE            1
usr.bin/gprof/gprof.h:53:#define	TRUE	1
usr.sbin/ntp/config.h:152:#define CLOCK_TRUETIME 1
lib/libdpv/dpv.h:33:#define TRUE 1
sys/fs/udf/osta.c:288:#define	TRUE	1
usr.bin/rpcgen/rpc_main.c:66:#define	EXTEND	1		/* alias for TRUE */
```