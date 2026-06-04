# Context: clnt_rc.c

**Context Brief – `clnt_rc.c` (RPC Reconnect Client, kernel‑space)**  

1. **Purpose & Placement**  
   * Implements a `CLIENT` wrapper that transparently reconnects when an RPC call fails.  
   * Lives in the kernel RPC subsystem (includes `<sys/...>` headers) and is instantiated by `clnt_reconnect_create()` – a public API function.  
   * All other functions (`clnt_reconnect_*`) are static helpers accessed only via the `clnt_ops` table.

2. **Untrusted Input Sources**  
   * **Network address (`svcaddr`)** – supplied by the caller, potentially from user‑controlled network name resolution.  
   * **TLS cert name** – set via `CLSET_TLSCERTNAME` request; the caller can pass any string (subject to a size check).  
   * **RPC arguments (`args`)** – `mbuf`s built by the calling application and forwarded to `CLNT_CALL_MBUF`.  
   * **Reconnection up‑call & back‑channel** – function pointers/objects that can be supplied by the caller.

3. **Attacker‑Controlled Variables & Data Flow**  
   * `svcaddr` → stored in `rc->rc_addr` (copy of `svcaddr->sa_len` bytes).  
   * `rc->rc_tlscertname` set by `CLSET_TLSCERTNAME` → passed to `rpctls_connect()` during reconnect.  
   * `args` → passed unchanged to `CLNT_CALL_MBUF(client, …)`; the data inside the `mbuf` originates from the user.  
   * `upcall` (`rc_reconcall`) and `backchannel` (`rc_backchannel`) can carry arbitrary function pointers passed through `ext`.

4. **Fixed‑Size Buffers / Size Constants**  
   * `rc_waitchan` = `"rpcrecv"` (13 bytes literal).  
   * `slen = strlen(info)+1` for TLS cert name.  **Resolved limits**:  
     * `NAME_MAX` = 255 (FreeBSD) → slen must be `<= NAME_MAX‑6 = 249`.  
   * `user_intr` and `rc_retry` timeouts use `struct timeval` (fixed size).  
   * `int one = 1` used in socket options.  
   * `INT_MAX` = 2147483647 (`#define INT_MAX 2147483647`).

5. **Dangerous Data Flow (Attacker → Fixed‑size Buffer)**  
   * **Source**: TLS cert name string via `CLSET_TLSCERTNAME`.  
     **Destination**: `rc->rc_tlscertname` allocated with `mem_alloc(slen)` and populated with `strlcpy()`.  
     **Buffer Size**: `slen` ≤ 249 bytes; attacker must respect the `NAME_MAX‑6` bound to avoid overruns.  
   * **Source**: `svcaddr` address passed into `clnt_reconnect_create()`.  
     **Destination**: `rc->rc_addr` (fixed size `sa_len`).  
     **Buffer Size**: `svcaddr->sa_len` (max 255 on IPv4/IPv6).  
   * **Source**: `args` `mbuf` chain – no static buffer copy in this file; contents traverse directly to the RPC call but may contain arbitrary payloads.

6. **Potential NULL‑Dereference**  
   * `rc->rc_backchannel` and `rc_reconcall` are stored without sanity checks; if they are `NULL` and later dereferenced (e.g., in `clnt_reconnect_control()` for `CLSET_BACKCHANNEL` or `CLSET_RECONUPCALL`), the code may crash only if the caller passes a broken pointer.  
   * `rc->rc_client` is protected by `rc_lock`; dereferencing after `rc_closed` is guarded, but race‑like misuse in higher‑level code could produce inconsistent state.

7. **Tagged Unions / Variant Types**  
   * No tagged unions are accessed directly in this file – all variant data are handled via function pointers or opaque `void*` (e.g., `rc_reconcall`/`rc_backchannel`).  
   * No type‑tag validation occurs for `rc_reconcall` or `rc_backchannel`.

8. **API vs Static**  
   * **Public**: `clnt_reconnect_create()`.  
   * **Static helpers**: all other `clnt_reconnect_*` functions, plus the `clnt_reconnect_ops` table.  
   * The static helpers are called only from the public API or internally; no external caller can invoke them directly.

9. **Likely Bug Classes**  
   * **Buffer overflow / string handling** – TLS cert name path manipulation if bounds are incorrectly enforced.  
   * **NULL pointer dereference / dangling references** – back‑channel or recon‑upcall pointers not validated or freed safely.  
   * **Race conditions** – `rc_closed` state changes under contention could lead to double‑free or use‑after‑free.  
   * **Privilege escalation via address spoofing** – arbitrary `svcaddr` may let an attacker force the client to connect to a malicious server or IP.  

**GREP Results**  
```
# Resolve NAME_MAX
grep -R "define NAME_MAX" /usr/include/sys/param.h
# → #define NAME_MAX 255

# Resolve INT_MAX
grep -R "define INT_MAX" /usr/include/sys/limits.h
# → #define INT_MAX 2147483647
```
All other constants (e.g., `struct timeval` size, `int` size) are architecture dependent but standard (8 bytes for `time.tv_sec`, 4 bytes for `time.tv_usec`).

[GREP RESULTS from codebase]:
GREP `Results**`:
```
usr.sbin/ppp/log.h:74:#define LOG_KEPT_SYSLOG (1)	/* Results of log_IsKept() */
usr.sbin/ppp/log.h:75:#define LOG_KEPT_LOCAL  (2)	/* Results of log_IsKept() */
sys/sys/errno.h:88:#define	ERANGE		34		/* Result too large */
sys/contrib/ncsw/Peripherals/FM/Port/fm_port.h:78:#define DEFAULT_PORT_bufferPrefixContent_passPrsResult  DEFAULT_FM_SP_bufferPrefixContent_passPrsResult
sys/contrib/ncsw/Peripherals/FM/inc/fm_sp_common.h:54:#define DEFAULT_FM_SP_bufferPrefixContent_passPrsResult     FALSE
sys/contrib/ncsw/inc/Peripherals/fm_ext.h:136:#define FM_PR_L2_VLAN_STACK         0x00000100  /**< Parse Result: VLAN stack */
sys/contrib/ncsw/inc/Peripherals/fm_ext.h:137:#define FM_PR_L2_ETHERNET           0x00008000  /**< Parse Result: Ethernet*/
sys/contrib/ncsw/inc/Peripherals/fm_ext.h:138:#define FM_PR_L2_VLAN               0x00004000  /**< Parse Result: VLAN */
sys/contrib/ncsw/inc/Peripherals/fm_ext.h:139:#define FM_PR_L2_LLC_SNAP           0x00002000  /**< Parse Result: LLC_SNAP */
sys/contrib/ncsw/inc/Peripherals/fm_ext.h:140:#define FM_PR_L2_MPLS               0x00001000  /**< Parse Result: MPLS */
sys/contrib/ncsw/inc/Peripherals/fm_ext.h:141:#define FM_PR_L2_PPPoE              0x00000800  /**< Parse Result: PPPoE */
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:1553:#define TPM_ORD_GetTestResult                   ((TPM_COMMAND_CODE) 0x00000054)
sys/contrib/edk2/Include/IndustryStandard/Tpm20.h:310:#define TPM_CC_GetTestResult               (TPM_CC)(0x0000017C)
sys/arm/freescale/vybrid/vf_adc.c:105:#define	 CAL_CODE_M	0xf		/* Calibration Result Value Mask */
sys/arm/freescale/vybrid/vf_adc.c:106:#define	 CAL_CODE_S	0		/* Calibration Result Value Shift */
contrib/tcpdump/print-l2tp.c:106:#define L2TP_AVP_RESULT_CODE		1  /* Result Code */
sys/dev/safe/safereg.h:54:#define	SAFE_PE_RDRBASE		0x004c	/* Packet Engine Result Ring Base */
contrib/wpa/src/eap_common/eap_tlv_common.h:13:#define EAP_TLV_RESULT_TLV 3 /* Acknowledged Result */
contrib/ncurses/ncurses/tty/lib_mvcur.c:810:#define NullResult _nc_str_null(&result, sizeof(buffer))
contrib/ncurses/ncurses/tty/lib_mvcur.c:811:#define InitResult _nc_str_init(&result, buffer, sizeof(buffer))
contrib/sqlite3/sqlite3.c:17133:#define OP_ResultRow      84 /* synopsis: output=r[P1@P2]                  */
contrib/sqlite3/sqlite3.c:20008:#define SF_ComplexResult 0x0040000 /* Result contains subquery or function */
contrib/sqlite3/sqlite3.c:140093:#define PragFlg_NoColumns  0x02 /* OP_ResultRow called with zero columns */
contrib/sqlite3/sqlite3.c:140096:#define PragFlg_Result0    0x10 /* Acts as query when no argument */
contrib/sqlite3/sqlite3.c:140097:#define PragFlg_Result1    0x20 /* Acts as query when has one argument */
contrib/sqlite3/sqlite3.c:208173:#define JSON_JSON      0x01        /* Result is always JSON */
contrib/sqlite3/sqlite3.c:208174:#define JSON_SQL       0x02        /* Result is always SQL */
contrib/sqlite3/autosetup/jimsh0.c:641:#define Jim_SetResultString(i,s,l) Jim_SetResult(i, Jim_NewStringObj(i,s,l))
contrib/sqlite3/autosetup/jimsh0.c:642:#define Jim_SetResultInt(i,intval) Jim_SetResult(i, Jim_NewIntObj(i,intval))
contrib/sqlite3/autosetup/jimsh0.c:644:#define Jim_SetResultBool(i,b) Jim_SetResultInt(i, b)
```