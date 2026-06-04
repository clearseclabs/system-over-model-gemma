# Context: rpcb_prot.h

**Context Briefing – rpcb_prot.h (rpcbind protocol definitions)**  

1. *Location & Purpose*  
   rpcb_prot.h is a machine‑generated header (via rpcgen) that declares the RPC interface used by rpcbind (protocol v3 and v4). It lives in the userspace rpcbind program and exposes the data structures (e.g., `rpcb`, `rpcb_rmtcallargs`, `rpcb_rmtcallres`) and the public API entry points (`rpcbproc_*`) that the RPC server implements.

2. *Untrusted Input Path*  
   The data originates from network‑bound RPC calls (e.g., over the unix socket `/var/run/rpcbind.sock`). Clients marshal arguments via XDR and the rpcbind service unmarshals them into the structs declared herein. Thus the payload is network input.

3. *Attacker‑Controlled Variables*  
   * `RPCB.r_netid`, `r_addr`, `r_owner` – plain `char *` supplied by the caller.  
   * In `rpcb_rmtcallargs` the `args` field (`args_len`, `args_val`) carries opaque client data.  
   * Argument lengths (`arglen`) and result lengths (`resultslen`) are also supplied by the client.

4. *Fixed‑size Buffers & Constants*  
   The header does not define any array buffers; all strings are pointers. However the following constants are embedded:  

   ```
   GREP: "#define RPCBSTAT_HIGHPROC" -> 13
   GREP: "#define RPCBVERS_STAT"      -> 3
   GREP: "#define RPCBVERS_4_STAT"    -> 2
   GREP: "#define RPCBVERS_3_STAT"    -> 1
   GREP: "#define RPCBVERS_2_STAT"    -> 0
   GREP: "#define _PATH_RPCBINDSOCK" -> "/var/run/rpcbind.sock"
   GREP: "#define RPCBPROG"           -> 100000
   GREP: "#define RPCBVERS"           -> 3
   GREP: "#define RPCBVERS4"          -> 4
   ```

5. *Dangerous Data Flows*  
   * `rpcbproc_set_*` receives a pointer to `RPCB` whose `r_netid`, `r_addr`, `r_owner` strings are copied into the server’s internal data structures (size derived from the supplied lengths).  
   * `rpcbproc_callit_*` reads `r_args_len` into `rpckb_rmtcallargs.args.args_len` and copies the bytes at `args_val` into an internal buffer of that length. The buffer size is exactly the client‑supplied length, i.e., attacker‑controlled.

6. *NULL‑Dereference Risks*  
   The generated `*_svc` functions dereference the received `RPCB *` and the `rpcb_rmtcallargs` struct without checking that any `char *` fields are non‑NULL before using them (e.g., in `xdr_rpcb()` or when allocating strings).

7. *Variant Type Validation*  
   The protocol uses simple structs; there are no tagged unions. All struct fields are read directly; no type‑tag checks are necessary.

8. *Public Front‑End vs. Helpers*  
   All `rpcbproc_*` functions are public RPC entry points. There are no static helper functions in this header, so all calls are external to the rpcbind binary.

9. *Typical Vulnerability Classes*  
   * **Buffer overrun via string length mismatch** – the XDR unmarshalling relies on the supplied lengths to allocate buffers; malformed lengths can lead to overruns.  
   * **Unvalidated NULL pointers** – dereferencing client‑supplied `char *` fields without null checks may cause crashes or escalation.  
   * **Information disclosure** – the `RPCB` structure includes owner and network IDs that, if maliciously crafted, could expose internal naming or configuration data.  

This overview should help the researcher understand the data flow, where user input is accepted, and the static constraints that could influence any future vulnerability analysis.

[GREP RESULTS from codebase]:
GREP `#define RPCBSTAT_HIGHPROC" -> 13 (simplified to: RPCBSTAT_HIGHPROC)`:
```
sys/rpc/rpcb_prot.h:278:#define	RPCBSTAT_HIGHPROC 13
sys/rpc/rpcb_prot.h:428:#define RPCBSTAT_HIGHPROC 13
sys/rpc/rpcb_prot.h:310:typedef int rpcbs_proc[RPCBSTAT_HIGHPROC];
sys/rpc/rpcb_prot.h:460:typedef int rpcbs_proc[RPCBSTAT_HIGHPROC];
lib/libc/rpc/rpcb_st_xdr.c:198:	if (!xdr_vector(xdrs, (char *)(void *)objp, RPCBSTAT_HIGHPROC,
```

GREP `#define RPCBVERS_STAT"      -> 3 (simplified to: RPCBVERS_STAT)`:
```
sys/rpc/rpcb_prot.h:279:#define	RPCBVERS_STAT 3
sys/rpc/rpcb_prot.h:429:#define RPCBVERS_STAT 3
sys/rpc/rpcb_prot.h:330:typedef rpcb_stat rpcb_stat_byvers[RPCBVERS_STAT];
sys/rpc/rpcb_prot.h:480:typedef rpcb_stat rpcb_stat_byvers[RPCBVERS_STAT];
usr.sbin/rpcbind/rpcb_stat.c:88:	if ((rtype >= RPCBVERS_STAT) || (success == FALSE))
usr.sbin/rpcbind/rpcb_stat.c:96:	if ((rtype >= RPCBVERS_STAT) || (success == FALSE))
usr.sbin/rpcbind/rpcb_stat.c:108:	if (rtype >= RPCBVERS_STAT)
usr.sbin/rpcbind/rpcb_stat.c:152:	if (rtype >= RPCBVERS_STAT)
lib/libc/rpc/rpcb_st_xdr.c:254:	if (!xdr_vector(xdrs, (char *)(void *)objp, RPCBVERS_STAT,
```

GREP `#define RPCBVERS_4_STAT"    -> 2 (simplified to: RPCBVERS_4_STAT)`:
```
sys/rpc/rpcb_prot.h:280:#define	RPCBVERS_4_STAT 2
sys/rpc/rpcb_prot.h:430:#define RPCBVERS_4_STAT 2
usr.bin/rpcinfo/rpcinfo.c:1138:					inf[RPCBVERS_4_STAT].setinfo);
usr.bin/rpcinfo/rpcinfo.c:1142:					inf[RPCBVERS_4_STAT].unsetinfo);
usr.bin/rpcinfo/rpcinfo.c:1146:				for (pa = inf[RPCBVERS_4_STAT].addrinfo; pa;
usr.bin/rpcinfo/rpcinfo.c:1153:				for (pr = inf[RPCBVERS_4_STAT].rmtinfo; pr;
usr.bin/rpcinfo/rpcinfo.c:1167:			    sprintf(cp, "%d", inf[RPCBVERS_4_STAT].info[i]);
usr.bin/rpcinfo/rpcinfo.c:1169:			    sprintf(cp, "%d", inf[RPCBVERS_4_STAT].info[i] +
usr.bin/rpcinfo/rpcinfo.c:1170:			    inf[RPCBVERS_4_STAT].info[RPCBPROC_GETADDRLIST]);
usr.bin/rpcinfo/rpcinfo.c:1183:	if (inf[RPCBVERS_4_STAT].info[RPCBPROC_CALLIT] ||
usr.bin/rpcinfo/rpcinfo.c:1184:			    inf[RPCBVERS_4_STAT].info[RPCBPROC_INDIRECT]) {
usr.bin/rpcinfo/rpcinfo.c:1187:		print_rmtcallstat(RPCBVERS_4_STAT, &inf[RPCBVERS_4_STAT]);
usr.bin/rpcinfo/rpcinfo.c:1190:	if (inf[RPCBVERS_4_STAT].info[RPCBPROC_GETADDR]) {
usr.bin/rpcinfo/rpcinfo.c:1193:		print_getaddrstat(RPCBVERS_4_STAT, &inf[RPCBVERS_4_STAT]);
usr.bin/rpcinfo/rpcinfo.c:1619:	if (rtype == RPCBVERS_4_STAT)
usr.bin/rpcinfo/rpcinfo.c:1632:		if (rtype == RPCBVERS_4_STAT)
usr.sbin/rpcbind/rpcb_svc_4.c:81:	rpcbs_procinfo(RPCBVERS_4_STAT, rqstp->rq_proc);
```