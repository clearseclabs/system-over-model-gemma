# Context: clnt_nl.c

### Security Briefing: `clnt_nl.c`

**1. Role and Location**
This code implements a Kernel RPC client that communicates over Netlink. It allows the kernel to act as an RPC client while a userland application acts as the server. It sits within the RPC subsystem and integrates with the Generic Netlink framework.

**2. Untrusted Input Path**
Untrusted input originates from userland via **Netlink sockets**. Specifically, the kernel receives Netlink messages that are processed by the Generic Netlink dispatcher, which routes them to the `clnt_nl_reply` callback.

**3. Attacker-Controlled Data Flow**
*   **Entry Point:** `clnt_nl_reply(struct nlmsghdr *hdr, struct nl_pstate *npt)`
*   **Controlled Variables:**
    *   `hdr`: The Netlink message header (controls `nlmsg_seq` used for XID matching).
    *   `attrs`: Populated by `nl_parse_nlmsg` via `rpcnl_parser`.
    *   `attrs.group`: (uint32_t) Used to look up the `nl_data` structure in `rpcnl_clients` (RB-tree).
    *   `attrs.data`: (struct nlattr *) Pointer to the RPC payload.
    *   `NLA_DATA(attrs.data)`: The raw XDR-encoded bytes passed into the kernel.

**4. Fixed-Size Buffers and Constants**
*   `nl_data->nl_mcallc[MCALL_MSG_SIZE]`: Marshalled call message buffer. 
    *   GREP: `MCALL_MSG_SIZE` is defined in `rpc/clnt_nl.h`. (Assuming standard value, but requires GREP for numeric verification).
*   `len` (local to `clnt_nl_call`): Can be `RPC_MAXDATASIZE` (9000 bytes).

**5. Dangerous Data Flows**
*   **Source:** `NLA_DATA(attrs.data)` $\rightarrow$ **Destination:** `mchain mc` $\rightarrow$ **Function:** `m_copyback` in `clnt_nl_reply`.
*   **Source:** `cr->cr_mrep` (sourced from Netlink) $\rightarrow$ **Destination:** `XDR` decoder $\rightarrow$ **Function:** `xdr_replymsg` in `clnt_nl_call`. Buffer size is determined by the Netlink attribute length.

**6. NULL Dereferences**
*   `cl->cl_private` is dereferenced in almost all `clnt_nl_*` functions; depends on `client_nl_create` success.
*   `attrs.data` is checked for NULL in `clnt_nl_reply` before use.
*   `cr` can be NULL after `TAILQ_FOREACH` in `clnt_nl_reply` (explicitly checked).

**7. Tagged Unions/Variants**
The code uses `XDR` for decoding. The `reply_msg` (struct `rpc_msg`) is a union. The code checks `reply_msg.rm_reply.rp_stat == MSG_ACCEPTED` before accessing `acpted_rply` members, providing basic type-tag validation.

**8. API and Scope**
*   **Public API:** `rpcnl_init()`, `client_nl_create()`.
*   **Static Helpers:** `clnt_nl_call`, `clnt_nl_reply`, `clnt_nl_close`, `clnt_nl_destroy`, `clnt_nl_control`. These are managed via the `clnt_ops` structure or the `genl_cmd` table.

**9. Likely Bug Classes**
*   **Integer Overflows:** In `NLA_DATA_LEN` calculations during `m_copyback`.
*   **XDR Decoder Vulnerabilities:** Out-of-bounds reads/writes during `xdr_replymsg` processing of user-supplied payloads.
*   **Race Conditions:** Complex locking between `rpcnl_global_lock` (rwlock) and `nl->nl_lock` (mutex) during request/reply matching.

[GREP RESULTS from codebase]:
GREP `MCALL_MSG_SIZE`:
```
sys/rpc/krpc.h:38:#define MCALL_MSG_SIZE 24
sys/rpc/clnt_dg.c:108:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_vc.c:81:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_raw.c:56:#define MCALL_MSG_SIZE 24
lib/libc/rpc/clnt_dg.c:152:#define	MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_raw.c:49:#define MCALL_MSG_SIZE 24
crypto/krb5/src/lib/rpc/clnt_tcp.c:67:#define MCALL_MSG_SIZE 24
sys/rpc/krpc.h:110:	char		ct_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:144:	char		nl_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_nl.c:234:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_nl.c:242:	xdrmem_create(&xdrs, nl->nl_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_bck.c:159:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
sys/rpc/clnt_dg.c:142:	char			cu_mcallc[MCALL_MSG_SIZE]; /* marshalled callmsg */
sys/rpc/clnt_dg.c:250:	xdrmem_create(&xdrs, cu->cu_mcallc, MCALL_MSG_SIZE, XDR_ENCODE);
sys/rpc/clnt_vc.c:238:	xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:110:		char	ct_mcallc[MCALL_MSG_SIZE];	/* marshalled callmsg */
lib/libc/rpc/clnt_vc.c:276:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcallc, MCALL_MSG_SIZE,
lib/libc/rpc/clnt_vc.c:286:	assert(ct->ct_mpos + sizeof(uint32_t) <= MCALL_MSG_SIZE);
lib/libc/rpc/clnt_raw.c:67:	    char 		mashl_callmsg[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_raw.c:116:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE); 
lib/libc/rpc/clnt_dg.c:168:	char			cu_outhdr[MCALL_MSG_SIZE];
lib/libc/rpc/clnt_dg.c:259:	xdrmem_create(&(cu->cu_outxdrs), cu->cu_outhdr, MCALL_MSG_SIZE,
crypto/krb5/src/lib/rpc/clnt_raw.c:60:	  char	            mashl_callmsg[MCALL_MSG_SIZE];
crypto/krb5/src/lib/rpc/clnt_raw.c:113:	xdrmem_create(xdrs, clp->u.mashl_callmsg, MCALL_MSG_SIZE, XDR_ENCODE);
crypto/krb5/src/lib/rpc/clnt_tcp.c:98:	  char		ct_mcall[MCALL_MSG_SIZE];	/* marshalled callmsg */
crypto/krb5/src/lib/rpc/clnt_tcp.c:215:	xdrmem_create(&(ct->ct_xdrs), ct->ct_u.ct_mcall, MCALL_MSG_SIZE,
```

GREP `numeric`:
```
lib/libtacplus/taclib_private.h:189:#define is_num(ch) /* numerical */					\
lib/libtacplus/taclib_private.h:191:#define is_alnum(ch) /* alphanumerical */				\
lib/libc/stdio/vfwscanf.c:59:#define	BUF		513	/* Maximum length of numeric string. */
lib/libc/stdio/vfscanf.c:61:#define	BUF		513	/* Maximum length of numeric string. */
lib/libc/locale/lnumeric.c:41:#define LCNUMERIC_SIZE (sizeof(struct lc_numeric_T) / sizeof(char *))
contrib/sendmail/libsm/vfscanf.c:31:#define BUF		513	/* Maximum length of numeric string. */
usr.sbin/bhyve/amd64/vga.h:53:#define	ATC_MC_GA			0x01	/* Graphics/alphanumeric */
usr.sbin/bhyve/amd64/vga.h:100:#define	GC_MISC_GM			0x01	/* Graphics/alphanumeric */
contrib/nvi/vi/vi.h:51:#define	VM_CUTREQ	0x00000002	/* Always cut into numeric buffers. */
contrib/openbsm/bsm/libbsm.h:109:#define	AU_OFLAG_RAW		0x0001	/* Raw, numeric form. */
contrib/sqlite3/sqlite3ext.h:514:#define sqlite3_value_numeric_type     sqlite3_api->value_numeric_type
contrib/wpa/src/fst/fst_ctrl_defs.h:57:#define FST_CSG_PNAME_LLT        "llt"        /* pval = numeric llt value */
contrib/sqlite3/sqlite3.c:138885:#define sqlite3_value_numeric_type     sqlite3_api->value_numeric_type
contrib/libarchive/tar/bsdtar.h:107:#define	OPTFLAG_NUMERIC_OWNER	(0x00000200)	/* --numeric-owner */
usr.sbin/bsnmpd/tools/libbsnmptools/bsnmptools.h:186:#define	NUMERIC_BIT	0x00000004	/* bit 2 for numeric oids */
usr.sbin/syslogd/syslogd.c:240:#define a_addr u.numeric.addr
usr.sbin/syslogd/syslogd.c:241:#define a_mask u.numeric.mask
usr.sbin/ypldap/ber.h:34:#define be_numeric	be_union.bv_numeric
contrib/ncurses/progs/dump_entry.h:66:#define CMP_NUMBER	1	/* comparison on numerics */
contrib/ncurses/form/fty_num.c:56:#define thisARG numericARG
contrib/elftoolchain/libdwarf/dwarf.h:546:#define DW_ATE_numeric_string	 	0xb
sys/dev/qlnx/qlnxe/reg_addr.h:72125:  #define MCP_REG_NVM_RECONFIG_RECONFIG_STRAP_VALUE                                                          (0xf<<4) // Used by software to numerically encode how the FLSH has been reconfigured. On reset, this register is set to the same value as ORIG_STRAP_VALUE. These bits have no hardware functionality.
sys/dev/vt/hw/vga/vt_vga_reg.h:72:#define		VGA_AC_MC_GA		0x01	/* Graphics/alphanumeric */
sys/netpfil/ipfilter/netinet/ip_ftp_pxy.c:42:#define	FTPXY_JUNK_CONT	3	/* Saerching for next numeric */
sys/sys/stats.h:558:#define	DRBKT(lb, ub) { stats_ctor_vsd_numeric(lb), stats_ctor_vsd_numeric(ub) }
sys/sys/stats.h:561:#define	HBKTS(...) ((struct voistatdata_numeric [][2]){__VA_ARGS__})
sys/teken/teken.c:55:#define	TS_FIRSTDIGIT	0x0001	/* First numeric digit in escape sequence. */
sys/kern/subr_scanf.c:44:#define	BUF		32 	/* Maximum length of numeric string. */
usr.bin/localedef/bootstrap/lmonetary.h:37:#define	lc_numeric_T	localedef_bootstrap_lc_numeric_T
usr.bin/localedef/bootstrap/namespace.h:42:#define	xlocale_numeric	localedef_bootstrap_xlocale_numeric
```