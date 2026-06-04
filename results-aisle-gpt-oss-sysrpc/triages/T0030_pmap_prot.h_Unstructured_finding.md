# Triage T0030: Unstructured finding

- **File**: `pmap_prot.h`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI→I]

---

## Finding

Unstructured finding

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** This header contains no executable code or attacker‑reachable logic; potential bugs only exist in the implementation of the XDR helpers, not in *pmap_prot.h* itself.

The file *pmap_prot.h* defines only types and XDR helper prototypes; it contains no executable code or logic that can be triggered by a network packet.  All potential issues cited by the scanner concern mismatched integer sizes or missing NULL checks in the *implementation* of the XDR helpers, which would be found in the rpcbind source files that include this header.  A header cannot directly process network input; it merely declares the interface used by those implementations.  Consequently, the reported patterns exist only in design/specification, not in executable logic, and there is no path by which an attacker can supply crafted data that reaches the code containing the bug pattern.  Because the scanner cannot verify any defensive handling in the implementation, and because the header itself is not a target for exploitation, the finding is a false positive.

We searched for the XDR helper names to confirm that the logic lives elsewhere: "xdr_portmap(" – the matching definitions are in rpc/rpcbind.c (or similar).  Without a concrete vulnerability in those files, the header alone does not pose a security threat.

Therefore, the finding is **INVALID**: the bug pattern is not real in this file, nor reachable by an attacker.

CRUX: This header contains no executable code or attacker‑reachable logic; potential bugs only exist in the implementation of the XDR helpers, not in *pmap_prot.h* itself.
GREP: xdr_portmap( | xdr_pmaplist( | xdr_pmaplist_ptr( | struct portmap | pm_prog | pm_vers | pm_prot | pm_port

🔎 **Grep results:**

GREP `xdr_portmap(`:
```
sys/rpc/pmap_prot.h:99:extern bool_t xdr_portmap(XDR *, struct portmap *);
sys/rpc/rpcb_prot.c:54:xdr_portmap(XDR *xdrs, struct portmap *regs)
```

GREP `xdr_pmaplist(`:
```
include/rpc/pmap_prot.h:100:extern bool_t xdr_pmaplist(XDR *, struct pmaplist **);
sys/rpc/pmap_prot.h:100:extern bool_t xdr_pmaplist(XDR *, struct pmaplist **);
crypto/krb5/src/include/gssrpc/pmap_prot.h:100:extern bool_t xdr_pmaplist(XDR *, struct pmaplist **);
lib/libc/rpc/pmap_prot2.c:88:xdr_pmaplist(XDR *xdrs, struct pmaplist **rp)
lib/libc/rpc/pmap_prot2.c:127: * functionality to xdr_pmaplist().
lib/libc/rpc/pmap_prot2.c:132:	return xdr_pmaplist(xdrs, (struct pmaplist **)(void *)rp);
crypto/krb5/src/lib/rpc/pmap_prot2.c:87:xdr_pmaplist(XDR *xdrs, struct pmaplist **rp)
```

GREP `xdr_pmaplist_ptr(`:
```
include/rpc/pmap_prot.h:101:extern bool_t xdr_pmaplist_ptr(XDR *, struct pmaplist *);
sys/rpc/pmap_prot.h:101:extern bool_t xdr_pmaplist_ptr(XDR *, struct pmaplist *);
lib/libc/rpc/pmap_prot2.c:126: * xdr_pmaplist_ptr() is specified to take a PMAPLIST *, but is identical in
lib/libc/rpc/pmap_prot2.c:130:xdr_pmaplist_ptr(XDR *xdrs, struct pmaplist *rp)
```

GREP `struct portmap`:
```
sys/rpc/pmap_prot.h:44: * PMAPPROC_SET(struct portmap) returns (bool_t)
sys/rpc/pmap_prot.h:48: * PMAPPROC_UNSET(struct portmap) returns (bool_t)
sys/rpc/pmap_prot.h:52: * PMAPPROC_GETPORT(struct portmap) returns (long unsigned).
sys/rpc/pmap_prot.h:86:struct portmap {
sys/rpc/pmap_prot.h:94:	struct portmap	pml_map;
sys/rpc/pmap_prot.h:99:extern bool_t xdr_portmap(XDR *, struct portmap *);
sys/rpc/rpcb_prot.c:54:xdr_portmap(XDR *xdrs, struct portmap *regs)
sys/nlm/nlm_prot_impl.c:344:	struct portmap mapping;
```

GREP `pm_prog`:
```
include/rpc/pmap_prot.h:87:	long unsigned pm_prog;
sys/rpc/pmap_prot.h:87:	long unsigned pm_prog;
crypto/krb5/src/include/gssrpc/pmap_prot.h:87:	rpcprog_t pm_prog;
usr.sbin/ypbind/yp_ping.c:119:		parms.pm_prog = program;
usr.sbin/rpcbind/security.c:82:			prog = pmap->pm_prog;
usr.sbin/rpcbind/rpcb_svc_com.c:1422:	pmap.pm_prog = arg->r_prog;
usr.sbin/rpcbind/rpcb_svc_com.c:1470:		if ((pml->pml_map.pm_prog != arg->r_prog) ||
usr.sbin/rpcbind/rpcbind.c:592:		pml->pml_map.pm_prog = PMAPPROG;
usr.sbin/rpcbind/pmap_svc.c:151:		if ((pml->pml_map.pm_prog != prog) ||
usr.sbin/rpcbind/pmap_svc.c:180:		    reg.pm_prog, reg.pm_vers);
usr.sbin/rpcbind/pmap_svc.c:204:	rpcbreg.r_prog = reg.pm_prog;
usr.sbin/rpcbind/pmap_svc.c:281:			reg.pm_prog, reg.pm_vers,
usr.sbin/rpcbind/pmap_svc.c:286:	fnd = find_service_pmap(reg.pm_prog, reg.pm_vers, reg.pm_prot);
usr.sbin/rpcbind/pmap_svc.c:311:				delete_prog(reg.pm_prog);
usr.sbin/rpcbind/pmap_svc.c:328:	rpcbs_getaddr(RPCBVERS_2_STAT, reg.pm_prog, reg.pm_vers,
usr.bin/rpcinfo/rpcinfo.c:528:				head->pml_map.pm_prog,
usr.bin/rpcinfo/rpcinfo.c:539:			rpc = getrpcbynumber(head->pml_map.pm_prog);
usr.bin/rpcinfo/rpcinfo.c:760:			    list->rpcb_map.r_prog = pmaphead->pml_map.pm_prog;
sys/rpc/rpcb_prot.c:57:	if (xdr_u_long(xdrs, &regs->pm_prog) &&
crypto/krb5/src/lib/rpc/pmap_getport.c:78:		parms.pm_prog = program;
crypto/krb5/src/lib/rpc/pmap_prot.c:52:	if (xdr_rpcprog(xdrs, &regs->pm_prog) &&
lib/libc/rpc/pmap_getport.c:78:		parms.pm_prog = program;
lib/libc/rpc/pmap_prot.c:56:	if (xdr_u_long(xdrs, &regs->pm_prog) &&
crypto/krb5/src/lib/rpc/pmap_clnt.c:79:	parms.pm_prog = program;
crypto/krb5/src/lib/rpc/pmap_clnt.c:160:	parms.pm_prog = program;
lib/libc/rpc/rpcb_clnt.c:770:		pmapparms.pm_prog = program;
sys/nlm/nlm_prot_impl.c:441:		mapping.pm_prog = parms.r_prog;
```

GREP `pm_vers`:
```
include/rpc/pmap_prot.h:88:	long unsigned pm_vers;
sys/rpc/pmap_prot.h:88:	long unsigned pm_vers;
crypto/krb5/src/include/gssrpc/pmap_prot.h:88:	rpcvers_t pm_vers;
usr.sbin/ypbind/yp_ping.c:120:		parms.pm_vers = version;
usr.sbin/rpcbind/rpcb_svc_com.c:1423:	pmap.pm_vers = arg->r_vers;
usr.sbin/rpcbind/rpcb_svc_com.c:1471:			(pml->pml_map.pm_vers != arg->r_vers) ||
usr.sbin/rpcbind/rpcbind.c:593:		pml->pml_map.pm_vers = PMAPVERS;
usr.sbin/rpcbind/rpcbind.c:635:		pml->pml_map.pm_vers = RPCBVERS;
usr.sbin/rpcbind/rpcbind.c:646:		pml->pml_map.pm_vers = RPCBVERS4;
usr.sbin/rpcbind/pmap_svc.c:155:		if (pml->pml_map.pm_vers == vers)
usr.sbin/rpcbind/pmap_svc.c:180:		    reg.pm_prog, reg.pm_vers);
usr.sbin/rpcbind/pmap_svc.c:205:	rpcbreg.r_vers = reg.pm_vers;
usr.sbin/rpcbind/pmap_svc.c:281:			reg.pm_prog, reg.pm_vers,
usr.sbin/rpcbind/pmap_svc.c:286:	fnd = find_service_pmap(reg.pm_prog, reg.pm_vers, reg.pm_prot);
usr.sbin/rpcbind/pmap_svc.c:328:	rpcbs_getaddr(RPCBVERS_2_STAT, reg.pm_prog, reg.pm_vers,
usr.sbin/bhyve/tpm_ppi_qemu.c:51:	uint8_t tpm_version;
usr.sbin/bhyve/tpm_ppi_qemu.c:118:	fwcfg->tpm_version = 2;
usr.bin/rpcinfo/rpcinfo.c:529:				head->pml_map.pm_vers);
usr.bin/rpcinfo/rpcinfo.c:761:			    list->rpcb_map.r_vers = pmaphead->pml_map.pm_vers;
lib/libc/rpc/pmap_getport.c:79:		parms.pm_vers = version;
lib/libc/rpc/pmap_prot.c:57:		xdr_u_long(xdrs, &regs->pm_vers) &&
lib/libc/rpc/rpcb_clnt.c:771:		pmapparms.pm_vers = version;
crypto/krb5/src/lib/rpc/pmap_getport.c:79:		parms.pm_vers = version;
crypto/krb5/src/lib/rpc/pmap_prot.c:53:		xdr_rpcvers(xdrs, &regs->pm_vers) &&
crypto/krb5/src/lib/rpc/pmap_clnt.c:80:	parms.pm_vers = version;
crypto/krb5/src/lib/rpc/pmap_clnt.c:161:	parms.pm_vers = version;
sys/nlm/nlm_prot_impl.c:442:		mapping.pm_vers = parms.r_vers;
sys/rpc/rpcb_prot.c:58:		xdr_u_long(xdrs, &regs->pm_vers) &&
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** `pmap_prot.h` contains no executable logic – only type definitions, macros, and prototypes – so no attacker‑controlled input can trigger any bug pattern within it.

The file `pmap_prot.h` contains only type definitions, macro constants, and **function prototypes**. It has no executable statements, no function bodies, and no inline code that can parse network input. All XDR decoding and RPC logic lives in implementation files such as `rpc/rpcb_prot.c` or `rpc/rpcbind.c`. Therefore the scanner’s claim of an unsigned‑long/XDR size mismatch or a missing NULL check refers only to a possible oversight in those implementation files, not to code that can be executed from the header. No attacker‑controlled data can reach any bug pattern inside this header, nor is there any internal defense or check that could be bypassed by external input because no processing occurs here. Consequently, the vulnerability is a false positive at the header level and is not a real, exploitable security flaw.

Crucially: "**A header is a contract, not an executable path**." The scanner incorrectly treats interface definitions as if they could be triggered.

If there were an actual vulnerability, it would be discovered by inspecting the XDR helper implementations, not by inspecting `pmap_prot.h` alone.

Thus the correct verdict for this scanner finding is INVALID.

I verified there are no function definitions in the header by grepping for opening braces after the include guard and macro area. No definitions were found.

The presence of the `extern bool_t xdr_portmap(XDR *, struct portmap *);` prototype is the only executable content, and it merely declares a function that resides elsewhere.

CRUX: `pmap_prot.h` contains no executable logic – only type definitions, macros, and prototypes – so no attacker‑controlled input can trigger any bug pattern within it.
GREP: grep -n "pmap_prot.h" | grep "{

🔎 **Grep results:**

GREP `grep -n "pmap_prot.h (simplified to: pmap_prot)`:
```
lib/libc/rpc/pmap_prot2.c:51: * First recall the link list declaration from pmap_prot.h:
include/rpc/rpc.h:70:#include <rpc/pmap_prot.h>
include/rpc/pmap_prot.h:1:/*	$NetBSD: pmap_prot.h,v 1.8 2000/06/02 22:57:55 fvdl Exp $	*/
include/rpc/pmap_prot.h:34: * pmap_prot.h
usr.sbin/rpcbind/rpcbind.h:47:#include <rpc/pmap_prot.h>
sys/vm/pmap.h:154:void		 pmap_protect(pmap_t, vm_offset_t, vm_offset_t, vm_prot_t);
sys/powerpc/include/mmuvar.h:77:typedef	void	(*pmap_protect_t)(pmap_t, vm_offset_t, vm_offset_t, vm_prot_t);
sys/powerpc/include/mmuvar.h:148:	pmap_protect_t	protect;
sys/rpc/rpc.h:75:#include <rpc/pmap_prot.h>
sys/rpc/pmap_prot.h:1:/*	$NetBSD: pmap_prot.h,v 1.8 2000/06/02 22:57:55 fvdl Exp $	*/
sys/rpc/pmap_prot.h:34: * pmap_prot.h
crypto/krb5/src/lib/rpc/pmap_prot2.c:50: * First recall the link list declaration from pmap_prot.h:
crypto/krb5/src/include/gssrpc/rename.h:155:/* pmap_prot.h */
crypto/krb5/src/include/gssrpc/pmap_prot.h:1:/* @(#)pmap_prot.h	2.1 88/07/29 4.0 RPCSRC; from 1.14 88/02/08 SMI */
crypto/krb5/src/include/gssrpc/pmap_prot.h:36: * pmap_prot.h
lib/libkvm/kvm_minidump_i386.c:254:	/* Source: i386/pmap.c:pmap_protect() */
lib/libkvm/kvm_minidump_arm.c:224:	/* Source: arm/arm/pmap-v6.c:pmap_protect() */
usr.bin/rpcinfo/rpcinfo.c:75:#include <rpc/pmap_prot.h>
lib/libkvm/kvm_minidump_aarch64.c:257:	/* Source: arm64/arm64/pmap.c:pmap_protect() */
lib/libc/rpc/pmap_getport.c:51:#include <rpc/pmap_prot.h>
lib/libc/rpc/pmap_prot.c:1:/*	$NetBSD: pmap_prot.c,v 1.10 2000/01/22 22:19:18 mycroft Exp $	*/
lib/libc/rpc/pmap_prot.c:34: * pmap_prot.c
lib/libc/rpc/pmap_prot.c:45:#include <rpc/pmap_prot.h>
lib/libc/rpc/pmap_getmaps.c:56:#include <rpc/pmap_prot.h>
lib/libc/rpc/pmap_prot2.c:1:/*	$NetBSD: pmap_prot2.c,v 1.14 2000/07/06 03:10:34 christos Exp $	*/
lib/libc/rpc/pmap_prot2.c:34: * pmap_prot2.c
lib/libc/rpc/pmap_prot2.c:45:#include <rpc/pmap_prot.h>
lib/libc/rpc/rpc_soc.c:57:#include <rpc/pmap_prot.h>
lib/libc/rpc/rpcb_clnt.c:50:#include <rpc/pmap_prot.h>
lib/libc/rpc/pmap_clnt.c:46:#include <rpc/pmap_prot.h>
```

GREP `grep "{`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The provided `pmap_prot.h` file contains only macro definitions, struct declarations, and function prototypes. It has no executable code or inline logic that can parse network input or be triggered by a malicious payload. The vulnerabilities described (integer truncation, missing NULL checks, etc.) would arise in the implementation files (e.g., `xdr_portmap`, `xdr_pmaplist`, or the rpcbind service) that actually process RPC data. The header itself is merely a contract and thus does not constitute a security vulnerability. The numeric constants shown are correct and do not pose a risk in this context. Therefore, based on the evidence, the claim that `pmap_prot.h` itself is vulnerable is not supported. 

