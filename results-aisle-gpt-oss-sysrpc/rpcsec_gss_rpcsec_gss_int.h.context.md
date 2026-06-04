# Context: rpcsec_gss/rpcsec_gss_int.h

**Context Briefing – rpcsec_gss_int.h**

1. **Purpose & Location**  
   *`rpcsec_gss_int.h`* is part of the RPC‑SECURITY GSSAPI module, defining the data structures and XDR‑serialisable interfaces that marshal authentication data across the network. It lives in the `rpcsec_gss/` source tree and is included by all RPC‑GSS client/server code that needs to construct or parse GSS‑API credentials and tokens.

2. **Untrusted Input Path**  
   Untrusted data arrives over the wire via XDR‑encoded RPC calls (e.g., `CALL RPCSEC_GSS_INIT`). The XDR routines `xdr_rpc_gss_cred` and `xdr_rpc_gss_init_res` decode incoming byte streams into the `rpc_gss_cred` and `rpc_gss_init_res` structs, respectively.

3. **Attacker‑Controlled Variables**  
   * `gc_version` (u_int) – protocol version.  
   * `gc_proc` (rpc_gss_proc_t) – control procedure.  
   * `gc_seq` (u_int) – sequence number (max 0x80000000).  
   * `gc_svc` (rpc_gss_service_t) – service type.  
   * `gc_handle` (gss_buffer_desc) – opaque handle to a server‑side context.  
   * `gr_handle`, `gr_token` – similar token buffers in the init response.  
   The data originates in the network packet payload, is fed to `xdr_*` functions, and ends up stored directly in these fields.

4. **Fixed‑Size Buffers & Constants**  
   * `MAXSEQ` – maximum sequence number (`0x80000000`).  
   * `RPCSEC_GSS_VERSION` – protocol version (`1`).  
   (No array buffers are declared in this header; `gss_buffer_desc` is a variable‑length buffer.)

   GREP: `#define RPCSEC_GSS_VERSION 1` → resolved value = **1**  
   GREP: `#define MAXSEQ 0x80000000` → resolved value = **2147483648**  

5. **Dangerous Data Flows**  
   * `gc_handle.value` → written into a `gss_buffer_desc` whose `value` field may be arbitrarily long; the XDR routine must enforce length limits (not visible here).  
   * `gc_seq` → used as a sequence counter; if unchecked, an attacker could send `0x80000000` to trigger integer wrap‑around.

6. **Potential NULL Derefs**  
   The `gss_buffer_desc.value` pointer may be `NULL` for zero‑length buffers. XDR code that blindly dereferences it could crash.

7. **Tagged Union Safety**  
   No tagged unions are exposed in this header; all fields are plain structs.

8. **API vs Helpers**  
   All declared functions (`xdr_*`, `_rpc_gss_num_to_qop`, `_rpc_gss_set_error`, `rpc_gss_log_*`) are part of the public API. No static helper functions are defined here, so there is no risk of unsafe internal calls.

9. **Likely Bug Classes**  
   * Buffer over‑runs from unchecked token lengths in `gc_handle`/`gr_token`.  
   * Integer over‑flow or wrap‑around with `gc_seq` ≥ `MAXSEQ`.  
   * Null‑pointer dereference when `gss_buffer_desc.value` is `NULL`.  
   * Improper validation of `rpc_gss_proc_t` values (e.g., out‑of‑range `gc_proc`).  

*End of briefing.*

[GREP RESULTS from codebase]:
GREP `#define RPCSEC_GSS_VERSION 1` → resolved value = **1** (simplified to: RPCSEC_GSS_VERSION)`:
```
crypto/krb5/src/include/gssrpc/auth_gss.h:65:#define RPCSEC_GSS_VERSION	1
lib/librpcsec_gss/rpcsec_gss_int.h:51:#define RPCSEC_GSS_VERSION	1
sys/rpc/rpcsec_gss/rpcsec_gss_int.h:53:#define RPCSEC_GSS_VERSION	1
crypto/krb5/src/lib/rpc/svc_auth_gss.c:449:	if (gc->gc_v != RPCSEC_GSS_VERSION)
crypto/krb5/src/lib/rpc/auth_gss.c:199:	gd->gc.gc_v = RPCSEC_GSS_VERSION;
lib/librpcsec_gss/rpcsec_gss.c:205:	gd->gd_cred.gc_version = RPCSEC_GSS_VERSION;
lib/librpcsec_gss/svc_rpcsec_gss.c:700:		client->cl_rawcred.version = RPCSEC_GSS_VERSION;
lib/librpcsec_gss/svc_rpcsec_gss.c:992:	if (gc.gc_version != RPCSEC_GSS_VERSION) {
sys/rpc/rpcsec_gss/rpcsec_gss.c:426:	gd->gd_cred.gc_version = RPCSEC_GSS_VERSION;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1108:		client->cl_rawcred.version = RPCSEC_GSS_VERSION;
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1432:	if (gc.gc_version != RPCSEC_GSS_VERSION) {
```

GREP `#define MAXSEQ 0x80000000` → resolved value = **2147483648** (simplified to: x80000000)`:
```
include/_ctype.h:64:#define	_CTYPE_SW2	0x80000000L		/* 2 width character */
include/db.h:88:#define	DB_TXN		0x80000000	/* Do transactions. */
include/resolv.h:253:#define RES_NO_NIBBLE2	0x80000000	/*%< disable alternate nibble lookup */
stand/efi/include/amd64/pe.h:275:#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.
stand/efi/include/amd64/pe.h:578:#define IMAGE_ORDINAL_FLAG 0x80000000
stand/efi/include/i386/pe.h:275:#define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.
stand/efi/include/i386/pe.h:578:#define IMAGE_ORDINAL_FLAG 0x80000000
contrib/sendmail/src/sendmail.h:447:#define QRCPTOK		0x80000000	/* recipient() processed address */
contrib/bearssl/src/inner.h:968:#define MUL31(x, y)   ((uint64_t)((x) | (uint32_t)0x80000000) \
contrib/bearssl/src/inner.h:1007:#define MUL15(x, y)   (((uint32_t)(x) | (uint32_t)0x80000000) \
sys/arm64/arm64/gic_v3_acpi.c:49:#define	GICV3_PRIV_VGIC		0x80000000
sys/arm64/arm64/gic_v3_acpi.c:50:#define	GICV3_PRIV_FLAGS	0x80000000
stand/kboot/include/arch/powerpc64/termios_arch.h:145:#define HOST_NOFLSH  0x80000000
sys/arm64/linux/linux.h:158:#define	LINUX_SA_ONESHOT	0x80000000	/* SA_RESETHAND */
contrib/file/src/cdf.h:264:#define CDF_PROPERTY_LOCALE_ID			0x80000000
sys/arm64/include/vmm.h:100:#define	VM_INTINFO_VALID	0x80000000
sys/arm64/include/vmm.h:107:#define VM_GUEST_BASE_IPA	0x80000000UL	/* Guest kernel start ipa */
sys/arm64/include/cpu_feat.h:77:#define	CPU_FEAT_USER_DISABLED	0x80000000
sys/arm64/include/hypervisor.h:135:#define	CPTR_TCPAC		0x80000000
sys/arm64/include/armreg.h:2748:#define	PSR_N		0x80000000UL
sys/arm64/include/pcb.h:69:#define	PCB_FP_NOSAVE	0x80000000
sbin/routed/defs.h:127:#define MIN_PreferenceLevel		0x80000000
sys/arm64/apple/apple_aic.c:77:#define	 AIC_IPI_SELF		0x80000000
sbin/ifconfig/ifieee80211.c:671:#define	_CHAN_HT	0x80000000
contrib/llvm-project/openmp/runtime/src/kmp_os.h:218:#define KMP_INT_MIN ((kmp_int32)0x80000000)
sys/fs/msdosfs/msdosfsmount.h:281:#define	MSDOSFSMNT_RONLY	0x80000000	/* mounted read-only	*/
contrib/llvm-project/openmp/runtime/src/thirdparty/ittnotify/ittnotify.h:4139:#define __itt_section_write 0x80000000
contrib/tcsh/sh.err.c:52:#define ERR_INTERRUPT	0x80000000
sys/fs/tmpfs/tmpfs.h:128:#define	TMPFS_DIRCOOKIE_DUPHEAD		((off_t)0x80000000U)
contrib/gdtoa/gdtoaimp.h:342:#define Sign_bit 0x80000000
```