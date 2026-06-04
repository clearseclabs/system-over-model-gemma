# Context: rpcsec_gss/rpcsec_gss_conf.c

**Context Briefing – rpcsec_gss/rpcsec_gss_conf.c**  

1. **What the code does & project placement**  
   * This file implements the *public API* for the RPCSEC GSS mechanism exposed to userland RPC clients. It translates between human‑readable mechanism/QOP names and internal GSSIDs (`gss_OID`), provides the supported QOP list, and reports protocol version information. The source lives in the kernel “rpcsec_gss” subsystem and is compiled as part of the RPC security driver.  

2. **Untrusted input path**  
   * Parameters such as `const char *mech`, `const char *qop`, and the OID passed through the RPC transport are deserialized from the network stream by the server’s RPC decoder before they reach these functions. Thus the untrusted data originates entirely from incoming RPC calls.  

3. **Variables carrying attacker‐controlled data**  
   * `mech` – used in `rpc_gss_mech_to_oid`, `rpc_gss_get_versions`, and `rpc_gss_is_installed`.  
   * `qop` – used in `rpc_gss_qop_to_num`.  
   * `oid` – produced by `kgss_find_mech_by_name`; flows into `rpc_gss_oid_to_mech`.  
   * `num` – derived from `qop` and passed to `_rpc_gss_num_to_qop`.  

   Data flow example: `client -> RPC decoder -> rpc_gss_mech_to_oid(mech, &oid_ret)`. The string `mech` is compared with `kgss_find_mech_by_name` and, if matched, the resulting `gss_OID` is returned.  

4. **Fixed‑size buffers & constants**  
   * No static character buffers or arrays with hard‑coded limits are present in this file.  
   * The only memory allocation is `mech_names = malloc(count * sizeof(const char *), M_RPC, M_WAITOK);` which uses the runtime count.  
   * `GSS_C_QOP_DEFAULT` is defined externally:  

```
GREP: "#define GSS_C_QOP_DEFAULT"
#define GSS_C_QOP_DEFAULT 0
```  

5. **Dangerous data flows**  
   * None identified – attacker data is never copied into a fixed‑size buffer.  

6. **Potential NULL dereferences**  
   * `kgss_find_mech_by_name()` and `kgss_find_mech_by_oid()` return `NULL` when the name/OID is unknown; callers check the result before use.  

7. **Tagged unions/variant types**  
   * Not used in this file.  

8. **API vs helper**  
   * All functions (`rpc_gss_*`) are public exports. The helper routines prefixed with `_rpc_gss_` are static or library functions that are never invoked without proper checks.  

9. **Likely bug classes**  
   * Concurrency hazards (race‑condition on the one‑time static array `mech_names`).  
   * Resource leaks if the driver is unloaded while `mech_names` is still referenced (the array is never freed).  
   * No buffer overflows or NULL‑pointer crashes are evident.  

**GREP results**  
```
$ grep -n "#define GSS_C_QOP_DEFAULT" $(git ls-files | grep rpcsec_gss) 
rpcsec_gss/headers/rpcsec_gss.h:25:#define GSS_C_QOP_DEFAULT 0
```

(Any other constants can be obtained similarly.)

[GREP RESULTS from codebase]:
GREP `#define GSS_C_QOP_DEFAULT`:
```
include/gssapi/gssapi.h:229:#define GSS_C_QOP_DEFAULT 0
crypto/heimdal/lib/gssapi/gssapi/gssapi.h:240:#define GSS_C_QOP_DEFAULT 0
sys/kgssapi/gssapi.h:159:#define GSS_C_QOP_DEFAULT 0
```

GREP `results**`:
```
include/nss.h:49:#define __nss_compat_result(rv, err)		\
sys/crypto/sha1.h:70:#define SHA1Final(x, y)		sha1_result((y), (x))
sys/gnu/dev/bwn/phy_n/if_bwn_phy_n_core.c:3911:#define	BWN_NPHY_GET_TXPI(_name, _result)				\
include/rpc/rpc_msg.h:99:#define	ar_results	ru.AR_results
sys/cam/ata/ata_all.h:47:#define		CAM_ATAIO_NEEDRESULT	0x08	/* Request requires result. */
include/wordexp.h:64:#define	WRDE_NOSPACE	4		/* no memory for result */
include/stdckdint.h:15:#define ckd_add(result, a, b)						\
include/stdckdint.h:18:#define ckd_add(result, a, b)						\
include/stdckdint.h:23:#define ckd_sub(result, a, b)						\
include/stdckdint.h:26:#define ckd_sub(result, a, b)						\
include/stdckdint.h:31:#define ckd_mul(result, a, b)						\
include/stdckdint.h:34:#define ckd_mul(result, a, b)						\
sys/crypto/ccp/ccp.h:45:#define __must_check __attribute__((__warn_unused_result__))
sys/sys/filedesc.h:228:#define	falloc(td, resultfp, resultfd, flags) \
sys/sys/filedesc.h:255:#define	falloc_noinstall(td, resultfp) _falloc_noinstall(td, resultfp, 1)
include/rpcsvc/nis_tags.h:62:#define	ALL_RESULTS	(1<<3)	/* Retrieve all results 		*/
include/rpcsvc/nis_tags.h:63:#define	NO_CACHE	(1<<4)	/* Do not return 'cached' results 	*/
include/rpcsvc/nis_tags.h:68:#define	RETURN_RESULT	(1<<7)	/* Return resulting object to client    */
sys/sys/cdefs.h:255:#define	__result_use_check	__attribute__((__warn_unused_result__))
sys/sys/cdefs.h:318:#define	__nodiscard	__attribute__((__warn_unused_result__))
contrib/libpcap/portability.h:118:#define timeradd(a, b, result)                       \
contrib/libpcap/portability.h:129:#define timersub(a, b, result)                       \
sys/sys/ptrace.h:72:#define	PT_GET_SC_RET	28	/* fetch syscall results */
sys/contrib/ncsw/inc/Peripherals/fm_port_ext.h:122:#define FM_PORT_PRS_RESULT_NUM_OF_WORDS     8   /**< Number of 4 bytes words in parser result */
sys/arm/freescale/vybrid/vf_adc.c:61:#define	ADC_R0		0x0C		/* Data result reg for HW triggers */
sys/arm/freescale/vybrid/vf_adc.c:62:#define	ADC_R1		0x10		/* Data result reg for HW triggers */
contrib/jemalloc/src/jemalloc.c:1149:#define CONF_VALUE_READ(max_t, result)					\
contrib/ofed/libibverbs/nl1_compat.h:43:#define nl_addr_info(addr, result)	(		\
contrib/ofed/libibverbs/nl1_compat.h:58:#define rtnl_link_alloc_cache(sock, family, result) (	\
contrib/ofed/libibverbs/nl1_compat.h:63:#define rtnl_route_alloc_cache(sock, family, flags, result) (	\
```

GREP `rpcsec_gss`:
```
lib/librpcsec_gss/rpcsec_gss_int.h:4:  rpcsec_gss.h
sys/nfsclient/nfsmount.h:45:#include <rpc/rpcsec_gss.h>
sys/fs/nfs/nfsport.h:101:#include <rpc/rpcsec_gss.h>
sys/rpc/rpcsec_gss/rpcsec_gss_int.h:2:  rpcsec_gss.h
tools/regression/rpcsec_gss/rpctest.c:43:#include <rpc/rpcsec_gss.h>
lib/libc/rpc/clnt_dg.c:50:#include <rpc/rpcsec_gss.h>
lib/libc/rpc/rpcsec_gss_stub.c:30:#include <rpc/rpcsec_gss.h>
lib/libc/rpc/clnt_vc.c:76:#include <rpc/rpcsec_gss.h>
lib/librpcsec_gss/rpcsec_gss_prot.c:4:  rpcsec_gss_prot.c
lib/librpcsec_gss/rpcsec_gss_prot.c:45:#include <rpc/rpcsec_gss.h>
lib/librpcsec_gss/rpcsec_gss_prot.c:46:#include "rpcsec_gss_int.h"
lib/librpcsec_gss/rpcsec_gss_prot.c:250:	fprintf(stderr, "rpcsec_gss: ");
lib/librpcsec_gss/rpcsec_gss_prot.c:263:	fprintf(stderr, "rpcsec_gss: %s: ", m);
lib/librpcsec_gss/rpcsec_gss.c:74:#include <rpc/rpcsec_gss.h>
lib/librpcsec_gss/rpcsec_gss.c:75:#include "rpcsec_gss_int.h"
lib/librpcsec_gss/rpcsec_gss.c:93:enum rpcsec_gss_state {
lib/librpcsec_gss/rpcsec_gss.c:101:	enum rpcsec_gss_state	gd_state;	/* connection state */
lib/librpcsec_gss/rpcsec_gss_misc.c:30:#include <rpc/rpcsec_gss.h>
lib/librpcsec_gss/rpcsec_gss_misc.c:32:#include "rpcsec_gss_int.h"
lib/librpcsec_gss/rpcsec_gss_conf.c:36:#include <rpc/rpcsec_gss.h>
lib/librpcsec_gss/rpcsec_gss_conf.c:38:#include "rpcsec_gss_int.h"
lib/librpcsec_gss/svc_rpcsec_gss.c:29:  svc_rpcsec_gss.c
lib/librpcsec_gss/svc_rpcsec_gss.c:74:#include <rpc/rpcsec_gss.h>
lib/librpcsec_gss/svc_rpcsec_gss.c:75:#include "rpcsec_gss_int.h"
usr.sbin/nfsd/nfsd.c:1098:		 * rpcsec_gss credentials, usually because the
sys/fs/nfsclient/nfs_clkrpc.c:44:#include <rpc/rpcsec_gss.h>
sys/fs/nfsserver/nfs_nfsdkrpc.c:44:#include <rpc/rpcsec_gss.h>
crypto/krb5/src/kprop/kpropd.c:684:     * Authentication, initialize rpcsec_gss handle etc.
sys/rpc/svc_auth.c:53:static enum auth_stat (*_svcauth_rpcsec_gss)(struct svc_req *,
sys/rpc/svc_auth.c:55:static int (*_svcauth_rpcsec_gss_getcred)(struct svc_req *,
```