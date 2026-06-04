# Context: svc_vc.c

**Context Brief – `svc_vc.c` (NetBSD RPC VC implementation)**  

1. **Role & Placement**  
   `svc_vc.c` contains the server‑side logic for connection‑oriented RPC over TCP.  It implements three transport “flavors”:  
   * Rendezvous listener (`svc_vc_create`) – accepts inbound TCP connections and spawns a per‑connection `svc_vc_ops`.  
   * Active stream transport (`svc_vc_create_conn`) – for established sockets, managing TLS state and per‑stream context (`struct cf_conn`).  
   * Back‑channel API (`svc_vc_create_backchannel`).  
   The file is compiled into the kernel RPC subsystem and is the entry point for incoming RPC records.

2. **Untrusted Input Path**  
   All payloads originate from a network socket (`xprt->xp_socket`).  The socket receives arbitrary data from the client and passes it to `soreceive()`.  `soreceive()` delivers the data as an `mbuf` chain (`m`), which is appended to the per‑connection `cd->mpending`.  From there, `svc_vc_recv()` parses a record header and reads a complete RPC call into `cd->mreq` via a series of mbuf routines – no user‑controlled data ever lands in a fixed‑size kernel buffer in this file.

3. **Attacker‑controlled Variables**  
   * `xprt->xp_socket` – the socket descriptor wired to client traffic.  
   * `m` (returned by `soreceive()`) – raw bytes from the network.  
   * `cd->mpending` / `cd->mreq` – mbuf chains containing those bytes.  
   These are accessible only through `svc_vc_recv()` and `svc_vc_process_pending()`.

4. **Fixed‑Size Buffers & Constants**  
   * `struct sockaddr_storage ss = { .ss_len = sizeof(ss) };` – 128 bytes on NetBSD.  
   * `xpr->xp_ltaddr` and `xp_rtaddr` – same size.  
   * `SERV *` – none in this file.  
   * `M_PREPEND(mrep, sizeof(uint32_t), M_WAITOK);` – a 4‑byte marker prepended to reply chains.  
   * **TLS constants (resolved via grep)**  
     - `TLS_MAX_MSG_SIZE_V10_2`  
       GREP: `#define TLS_MAX_MSG_SIZE_V10_2`
     - `TRE_X` etc.  

5. **Dangerous Data Flows**  
   * Source: `m` (network).  Destination: `cd->mpending` (mbuf chain).  No bounded buffer (uses mbufs).  
   * Source: `m` to `cd->mreq` after full record parsed.  Again mbuf‐based.  
   * Source: TLs alert record from `cmsg` to `m` (TLS path).  

6. **Potential NULL Derefs**  
   * `xprt->xp_p2` may be NULL (e.g., back‑channel).  
   * `cd->mreq`, `cd->mpending` are NULL until data arrives.  
   * `xprt->xp_socket` can be NULL for back‑channel transports – code checks it before use.  

7. **Tagged Unions**  
   * `struct rpc_msg` is parsed via XDR; no explicit tag validation in this file – the XDR functions perform the check.  

8. **API vs Helper**  
   * **Public API** – `svc_vc_create`, `svc_vc_create_conn`, `svc_vc_create_backchannel`, `svc_vc_reply`, `svc_vc_backchannel_reply`.  
   * **Static helpers** – all other `svc_vc_*` functions; they are invoked only by the public API or registered callbacks (e.g., `svc_vc_recv`, `svc_vc_soupcall`).  

9. **Likely Bug Classes**  
   * **Data‑race / Concurrency** – race between `svc_vc_recv()` and `svc_vc_soupcall()` on shared structures (`cd`, `mpending`).  
   * **Defensive programming** – dereferencing potentially NULL `xprt->xp_socket` when TLS handshake state flags are set.  
   * **TLS alert handling** – misuse of `soreceive()` return codes (ENXIO) could lead to missed alert processing.  

**GREP Results** (to be appended by the system)  
```
GREP: #define TLS_MAX_MSG_SIZE_V10_2
```

[GREP RESULTS from codebase]:
GREP `#define TLS_MAX_MSG_SIZE_V10_2 (simplified to: TLS_MAX_MSG_SIZE_V10_2)`:
```
sys/sys/ktls.h:46:#define	TLS_MAX_MSG_SIZE_V10_2	16384
sys/opencrypto/ktls.h:31:#define	MAX_TLS_PAGES	(1 + btoc(TLS_MAX_MSG_SIZE_V10_2))
tests/sys/kern/ktls_test.c:1188:	outbuf_cap = tls_header_len(en) + TLS_MAX_MSG_SIZE_V10_2 +
tests/sys/kern/ktls_test.c:1335:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1505:	outbuf_cap = tls_header_len(en) + TLS_MAX_MSG_SIZE_V10_2 +
tests/sys/kern/ktls_test.c:1537:				if (todo > TLS_MAX_MSG_SIZE_V10_2 - padding)
tests/sys/kern/ktls_test.c:1538:					todo = TLS_MAX_MSG_SIZE_V10_2 - padding;
tests/sys/kern/ktls_test.c:1623:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1712:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1753:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1795:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1837:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:2383:	    TLS_MAX_MSG_SIZE_V10_2 * 2)
sys/kern/uipc_ktls.c:722:	tls->params.max_frame_len = min(TLS_MAX_MSG_SIZE_V10_2, ktls_maxlen);
sys/kern/uipc_ktls.c:2566:		    tls->params.tls_hlen + TLS_MAX_MSG_SIZE_V10_2 +
sys/rpc/svc_vc.c:1026:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/svc_vc.c:1109:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/clnt_bck.c:305:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/clnt_vc.c:421:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
```

GREP `#define TLS_MAX_MSG_SIZE_V10_2 (simplified to: TLS_MAX_MSG_SIZE_V10_2)`:
```
sys/opencrypto/ktls.h:31:#define	MAX_TLS_PAGES	(1 + btoc(TLS_MAX_MSG_SIZE_V10_2))
sys/sys/ktls.h:46:#define	TLS_MAX_MSG_SIZE_V10_2	16384
tests/sys/kern/ktls_test.c:1188:	outbuf_cap = tls_header_len(en) + TLS_MAX_MSG_SIZE_V10_2 +
tests/sys/kern/ktls_test.c:1335:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1505:	outbuf_cap = tls_header_len(en) + TLS_MAX_MSG_SIZE_V10_2 +
tests/sys/kern/ktls_test.c:1537:				if (todo > TLS_MAX_MSG_SIZE_V10_2 - padding)
tests/sys/kern/ktls_test.c:1538:					todo = TLS_MAX_MSG_SIZE_V10_2 - padding;
tests/sys/kern/ktls_test.c:1623:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1712:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1753:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1795:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:1837:	ATF_REQUIRE(len <= TLS_MAX_MSG_SIZE_V10_2);
tests/sys/kern/ktls_test.c:2383:	    TLS_MAX_MSG_SIZE_V10_2 * 2)
sys/rpc/svc_vc.c:1026:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/svc_vc.c:1109:			maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/clnt_bck.c:305:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/rpc/clnt_vc.c:421:		maxextsiz = TLS_MAX_MSG_SIZE_V10_2;
sys/kern/uipc_ktls.c:722:	tls->params.max_frame_len = min(TLS_MAX_MSG_SIZE_V10_2, ktls_maxlen);
sys/kern/uipc_ktls.c:2566:		    tls->params.tls_hlen + TLS_MAX_MSG_SIZE_V10_2 +
```

GREP `Results**`:
```
contrib/ncurses/ncurses/tty/lib_mvcur.c:810:#define NullResult _nc_str_null(&result, sizeof(buffer))
contrib/ncurses/ncurses/tty/lib_mvcur.c:811:#define InitResult _nc_str_init(&result, buffer, sizeof(buffer))
usr.sbin/ppp/log.h:74:#define LOG_KEPT_SYSLOG (1)	/* Results of log_IsKept() */
usr.sbin/ppp/log.h:75:#define LOG_KEPT_LOCAL  (2)	/* Results of log_IsKept() */
contrib/tcpdump/print-l2tp.c:106:#define L2TP_AVP_RESULT_CODE		1  /* Result Code */
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
contrib/sqlite3/autosetup/jimsh0.c:645:#define Jim_SetEmptyResult(i) Jim_SetResult(i, (i)->emptyObj)
contrib/sqlite3/autosetup/jimsh0.c:646:#define Jim_GetResult(i) ((i)->result)
contrib/sqlite3/autosetup/jimsh0.c:649:#define Jim_SetResult(i,o) do {     \
contrib/wpa/src/eap_common/eap_tlv_common.h:13:#define EAP_TLV_RESULT_TLV 3 /* Acknowledged Result */
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
```