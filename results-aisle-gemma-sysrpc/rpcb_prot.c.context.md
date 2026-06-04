# Context: rpcb_prot.c

This briefing covers `rpcb_prot.c`, which implements XDR (External Data Representation) serialization and deserialization routines for the RPC binder (portmapper) version 3.

**1. Project Role:** This file provides the "glue" code to convert network-byte-order data into C structures (`portmap`, `RPCB`, `rpcblist`, `rpcb_entry`) used by the RPC binder service.

**2. Input Path:** Untrusted input arrives via the **network** $\rightarrow$ RPC transport layer $\rightarrow$ `XDR` stream $\rightarrow$ these functions.

**3. Attacker-Controlled Data:** 
Data flows from the `XDR *xdrs` stream into the following structure fields:
*   `struct portmap`: `pm_prog`, `pm_vers`, `pm_prot`, `pm_port`.
*   `RPCB`: `r_prog`, `r_vers`, `r_netid`, `r_addr`, `r_owner`.
*   `rpcb_entry`: `r_maddr`, `r_nc_netid`, `r_nc_semantics`, `r_nc_protofmly`, `r_nc_proto`.

**4. Fixed-Size Buffers & Constants:**
The code relies on `RPC_MAXDATASIZE` for string limits.
GREP: `RPC_MAXDATASIZE`
(Assuming standard RPC headers: `RPC_MAXDATASIZE` is typically **1024** bytes).

**5. Dangerous Data Flows:**
*   `XDR stream` $\rightarrow$ `xdr_string()` $\rightarrow$ `objp->r_netid` (Size: 1024)
*   `XDR stream` $\rightarrow$ `xdr_string()` $\rightarrow$ `objp->r_addr` (Size: 1024)
*   `XDR stream` $\rightarrow$ `xdr_string()` $\rightarrow$ `objp->r_owner` (Size: 1024)
*   `XDR stream` $\rightarrow$ `xdr_string()` $\rightarrow$ `objp->r_maddr` (Size: 1024)
*   `XDR stream` $\rightarrow$ `xdr_string()` $\rightarrow$ `objp->r_nc_netid` (Size: 1024)
*   `XDR stream` $\rightarrow$ `xdr_string()` $\rightarrow$ `objp->r_nc_protofmly` (Size: 1024)
*   `XDR stream` $\rightarrow$ `xdr_string()` $\rightarrow$ `objp->r_nc_proto` (Size: 1024)

**6. NULL Dereferences:** 
`xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` dereference `*rp` to check `more_elements` and access `next` pointers. If the initial `rp` passed to the function is NULL, a crash occurs.

**7. Tagged Unions:** None present in this file.

**8. API Scope:** 
*   **Public:** `xdr_portmap`, `xdr_rpcb`, `xdr_rpcblist_ptr`, `xdr_rpcb_entry`, `xdr_rpcb_entry_list_ptr`.
*   **Static:** None.

**9. Likely Bug Classes:** 
*   **Integer Overflows/Underflows:** In list length processing.
*   **Memory Exhaustion:** Through deeply nested or extremely long `rpcblist` / `rpcb_entry_list` (Denial of Service).
*   **Heap Corruption:** If `xdr_string` or `xdr_reference` handles memory allocation/bounds incorrectly.

[GREP RESULTS from codebase]:
GREP `RPC_MAXDATASIZE`:
```
include/rpc/rpc_com.h:51:#define	RPC_MAXDATASIZE 9000
lib/libc/rpc/rpc_com.h:52:#define	RPC_MAXDATASIZE 9000
sys/rpc/rpc_com.h:53:#define	RPC_MAXDATASIZE 9000
usr.sbin/ypserv/yp_main.c:399:			transp = svc_vc_create(slep->sle_sock, RPC_MAXDATASIZE,
usr.sbin/ypserv/yp_main.c:400:			    RPC_MAXDATASIZE);
usr.sbin/mountd/mountd.c:429:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/mountd/mountd.c:1082:			transp = svc_vc_create(fd, RPC_MAXDATASIZE,
usr.sbin/mountd/mountd.c:1083:			    RPC_MAXDATASIZE);
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:172:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.lockd/lockd.c:125:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.lockd/lockd.c:292:			xprt = svc_vc_create(fd, RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.lockd/lockd.c:762:		    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.statd/statd.c:91:  int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.statd/statd.c:561:		RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpcbind/rpcbind.c:156:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpcbind/rpcbind.c:517:			    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpcbind/rpcbind.c:559:		    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpcbind/rpcb_svc_com.c:420:	    RPC_MAXDATASIZE));
lib/libc/rpc/rpcb_st_xdr.c:66:	if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:118:		if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:156:		if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_st_xdr.c:184:	if (!xdr_string(xdrs, &objp->netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:60:	if (!xdr_string(xdrs, &objp->r_netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:63:	if (!xdr_string(xdrs, &objp->r_addr, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:66:	if (!xdr_string(xdrs, &objp->r_owner, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:160:	if (!xdr_string(xdrs, &objp->r_maddr, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:163:	if (!xdr_string(xdrs, &objp->r_nc_netid, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:169:	if (!xdr_string(xdrs, &objp->r_nc_protofmly, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:172:	if (!xdr_string(xdrs, &objp->r_nc_proto, RPC_MAXDATASIZE)) {
lib/libc/rpc/rpcb_prot.c:287:	if (!xdr_string(xdrs, &objp->addr, RPC_MAXDATASIZE)) {
```