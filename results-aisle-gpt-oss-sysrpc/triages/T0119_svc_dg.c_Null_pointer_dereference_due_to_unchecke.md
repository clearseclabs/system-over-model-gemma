# Triage T0119: Null pointer dereference due to unchecked memory allocation in svc_dg_reply

- **File**: `svc_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI→I]

---

## Finding

Null pointer dereference due to unchecked memory allocation in svc_dg_reply

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** m_gethdr with M_WAITOK never returns NULL, so the null‑dereference cannot be triggered by an attacker.

The code performs an unchecked dereference of a pointer returned by m_gethdr(M_WAITOK, MT_DATA). In NetBSD’s (and historically FreeBSD’s) kernel, m_gethdr is a macro that ultimately calls kmalloc/malloc with the M_WAITOK flag. The M_WAITOK flag tells the allocator to sleep until memory becomes available; it never returns NULL. If memory allocation cannot be satisfied, the kernel will handle it by either blocking or panicking, but no valid pointer is returned. Therefore, the pointer ‘mrep’ will never be NULL, and the subsequent xdrmbuf_create call cannot dereference a NULL pointer. There is no attacker‑controllable path that can make m_gethdr return NULL in this code path. Consequently, the reported null‑pointer dereference is not a reachable vulnerability. The bug pattern is present syntactically, but it is protected by the semantics of M_WAITOK, making the finding an INVALID defect.

(If a non‑kernel‑panic null return were possible, that would be a DoS, but that is not the case here.)

CRUX: m_gethdr with M_WAITOK never returns NULL, so the null‑dereference cannot be triggered by an attacker.
GREP: m_gethdr","M_WAITOK","MT_DATA

🔎 **Grep results:**

GREP `m_gethdr","M_WAITOK","MT_DATA (simplified to: m_gethdr)`:
```
sys/sys/mbuf.h:1133:#define	MGETHDR(m, how, type)	((m) = m_gethdr((how), (type)))
sys/sys/mbuf.h:1013:m_gethdr_raw(int how, short type)
sys/sys/mbuf.h:1026:m_gethdr(int how, short type)
sys/dev/netmap/netmap_kern.h:2406: * We allocate mbufs with m_gethdr(), since the mbuf header is needed
sys/dev/netmap/netmap_kern.h:2434:	m = m_gethdr(M_NOWAIT, MT_DATA);
sys/dev/cxgb/cxgb_offload.h:95:    m_gethdr_ofld(qset, ctrl, sizeof(*cpl), (void **)&cpl)
sys/dev/cxgb/cxgb_offload.h:97:m_gethdr_ofld(int qset, int ctrl, int cpllen, void **cpl)
sys/dev/cxgb/cxgb_offload.h:102:	m = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/ip6_mroute.c:1638:	mm = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/icmp6.c:576:			n = m_gethdr(M_NOWAIT, n0->m_type);
sys/netinet6/icmp6.c:706:			n = m_gethdr(M_NOWAIT, m->m_type);
sys/netinet6/icmp6.c:1414:		n = m_gethdr(M_NOWAIT, m->m_type);
sys/netinet6/nd6_nbr.c:456:		m = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/nd6_nbr.c:1010:		m = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/ip6_output.c:247:		m = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/ip6_output.c:3200:		mh = m_gethdr(M_NOWAIT, MT_DATA);
sys/rpc/svc_dg.c:234:	mrep = m_gethdr(M_WAITOK, MT_DATA);
sys/rpc/svc_vc.c:993:	mrep = m_gethdr(M_WAITOK, MT_DATA);
sys/rpc/svc_vc.c:1077:	mrep = m_gethdr(M_WAITOK, MT_DATA);
sys/rpc/clnt_bck.c:246:	mreq = m_gethdr(M_WAITOK, MT_DATA);
sys/rpc/clnt_vc.c:357:	mreq = m_gethdr(M_WAITOK, MT_DATA);
sys/netinet6/ip6_input.c:605:			n = m_gethdr(M_NOWAIT, MT_DATA);
sys/rpc/clnt_dg.c:424:	mreq = m_gethdr(M_WAITOK, MT_DATA);
sys/netinet6/mld6.c:1763:	mh = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/mld6.c:2420:			m = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/mld6.c:2545:			m = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/mld6.c:2701:					m = m_gethdr(M_NOWAIT, MT_DATA);
sys/netinet6/mld6.c:3158:	mh = m_gethdr(M_NOWAIT, MT_DATA);
sys/nfs/krpc_subr.c:276:	mhead = m_gethdr(M_WAITOK, MT_DATA);
sys/netgraph/ng_ksocket.c:1203:			mh = m_gethdr(M_NOWAIT, MT_DATA);
```

### Round 4: ❌ INVALID

[ARBITER] In NetBSD/FreeBSD the call `m_gethdr(M_WAITOK, MT_DATA)` desugars to `mrep = m_gethdr(M_WAITOK, MT_DATA);`.  The function `m_gethdr()` in the kernel allocates an `mbuf` via `malloc()` or an equivalent allocator, passing the `M_WAITOK` flag.  For kernel allocations, `malloc()` with `M_WAITOK` will **never** return `NULL`; it will sleep until memory is available and, if the kernel runs out of memory, it will panic rather than return a null pointer.  Therefore `mrep` can never be `NULL` when `M_WAITOK` is used, and the subsequent call to `xdrmbuf_create(&xdrs, mrep, ...)` cannot dereference a null pointer.  Since the kernel guarantees a non‑NULL result, the alleged null pointer dereference cannot be triggered by an attacker, and the claim is not a real vulnerability.  Thus the finding is **invalid**.

