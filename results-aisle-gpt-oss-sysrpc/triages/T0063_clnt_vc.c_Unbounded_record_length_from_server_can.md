# Triage T0063: Unbounded record length from server can cause memory exhaustion

- **File**: `clnt_vc.c`
- **Verdict**: INVALID
- **Confidence**: 50% [VUV→I]

---

## Finding

Unbounded record length from server can cause memory exhaustion

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The record length header is extracted from the network stream via ``ct_record_resid = header & 0x7fffffff;`` with no bounds check, allowing an attacker to set a huge value that causes unbounded memory allocation.

The code in ``clnt_vc_soupcall`` parses an XDR record marker sent by the remote RPC server. It extracts the 32‑bit integer header, masks off the top bit and stores the lower 31 bits in ``ct->ct_record_resid`` without performing any bounds check.

The record length value is derived directly from the network stream – i.e. from an attacker‑controlled payload – as shown by ``m_copydata(ct->ct_raw, 0, sizeof(uint32_t), (char *)&header);`` and ``ct->ct_record_resid = header & 0x7fffffff;``.  There is no defensive limit, sanitization, or size‑validation around this field.

Once ``ct->ct_record_resid`` is set, the function repeatedly moves data from ``ct_raw`` into ``ct_record`` until the residue reaches zero.  For a large value (e.g. 0x7FFFFFFF) this causes the receive buffer to inflate with a proportional amount of ``mbuf`` chain storage before a match can occur.  The kernel therefore allocates memory proportional to the attacker’s chosen value, potentially exhausting system memory or at least delaying request handling.

Because the vulnerable field is derived from untrusted input, the code path exposes a legitimate denial‑of‑service (DoS) vector.  No defensive code limits the size, and no other checks interfere with the flow.

Therefore the pattern is real, attacker‑reachable, and security‑relevant.


CRUX: The record length header is extracted from the network stream via ``ct_record_resid = header & 0x7fffffff;`` with no bounds check, allowing an attacker to set a huge value that causes unbounded memory allocation.

GREP: ct_record_resid = header &

🔎 **Grep results:**

GREP `ct_record_resid = header &`:
```
sys/rpc/clnt_vc.c:1070:			ct->ct_record_resid = header & 0x7fffffff;
```

### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

**🎯 Crux:** The record length extracted from the network stream is stored in ct_record_resid without any bounds check, allowing an attacker‑controlled large value to cause unbounded memory allocation during the receipt of the RPC reply.

The code in clnt_vc_soupcall extracts a 4‑byte record header from the socket using `m_copydata` and sets `ct->ct_record_resid` to the lower 31 bits of that header (`header & 0x7fffffff`).  This value is derived entirely from untrusted data; no sanity check or bounds limit is applied.  Subsequent processing moves data from the chain referenced by `ct_raw` into `ct_record` until `ct_record_resid` reaches zero, potentially allocating a proportionate number of mbufs (up to the amount of data actually sent).  An attacker can therefore send a header claiming a very large record length and then stream a large amount of data, causing the kernel to allocate a large number of mbufs for the client’s receive buffer and exhausting system memory, or at least delaying processing of further requests.  There is no defensive check in `clnt_vc_soupcall` that limits `ct_record_resid`, nor is there any limit applied to the size of the record elsewhere in the call handling.  The unbounded value is therefore attacker‑reachable and leads to a denial‑of‑service condition.  No countermeasure is present in this file to mitigate the large value – the code simply trusts the header.  Hence the pattern is real, reachable, and security‑relevant.

The crux of the vulnerability is that `ct_record_resid` can be set to an arbitrary 31‑bit value (up to 0x7FFFFFFF) coming from the server without any bounds check, allowing a malicious server to force the client to allocate an unbounded amount of memory.

The grep pattern used to confirm the absence of a defense target is:
- "RPC_MAX"

No definition of an upper bound on the record length appears in this file (and a search for common RPC record‑size constants such as RPC_MAXRECORD or RPC_MAXCALL did not reveal any limits), confirming that no bound is enforced.


CRUX: The record length extracted from the network stream is stored in ct_record_resid without any bounds check, allowing an attacker‑controlled large value to cause unbounded memory allocation during the receipt of the RPC reply.
GREP: RPC_MAX

🔎 **Grep results:**

GREP `RPC_MAX`:
```
include/rpc/rpc_com.h:51:#define	RPC_MAXDATASIZE 9000
include/rpc/rpc_com.h:52:#define	RPC_MAXADDRSIZE 1024
lib/libc/rpc/rpc_com.h:52:#define	RPC_MAXDATASIZE 9000
lib/libc/rpc/rpc_com.h:53:#define	RPC_MAXADDRSIZE 1024
lib/libc/rpc/clnt_dg.c:69:#define	RPC_MAX_BACKOFF		1 /* second */
lib/libc/rpc/clnt_dg.c:71:#define	RPC_MAX_BACKOFF		30 /* seconds */
sys/rpc/rpc_com.h:53:#define	RPC_MAXDATASIZE 9000
sys/rpc/rpc_com.h:54:#define	RPC_MAXADDRSIZE 1024
sys/rpc/clnt_dg.c:64:#define	RPC_MAX_BACKOFF		1 /* second */
sys/rpc/clnt_dg.c:66:#define	RPC_MAX_BACKOFF		30 /* seconds */
sys/dev/hwpmc/hwpmc_powerpc.h:47:#define	POWERPC_MAX_PMC_VALUE	0x7fffffffUL
usr.sbin/ypserv/yp_main.c:399:			transp = svc_vc_create(slep->sle_sock, RPC_MAXDATASIZE,
usr.sbin/ypserv/yp_main.c:400:			    RPC_MAXDATASIZE);
usr.sbin/mountd/mountd.c:429:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/mountd/mountd.c:1082:			transp = svc_vc_create(fd, RPC_MAXDATASIZE,
usr.sbin/mountd/mountd.c:1083:			    RPC_MAXDATASIZE);
usr.sbin/rpc.yppasswdd/yppasswdd_main.c:172:	int maxrec = RPC_MAXDATASIZE;
usr.bin/rpcgen/rpc_svcout.c:194:		f_print(fout,"nconf, 0, RPC_MAXDATASIZE, RPC_MAXDATASIZE);\n");
usr.bin/rpcgen/rpc_svcout.c:829:		RPC_MAXDATASIZE, RPC_MAXDATASIZE)) \
usr.sbin/rpc.lockd/lockd.c:125:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.lockd/lockd.c:292:			xprt = svc_vc_create(fd, RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.lockd/lockd.c:762:		    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpcbind/rpcb_svc_com.c:420:	    RPC_MAXDATASIZE));
usr.sbin/rpcbind/rpcbind.c:156:	int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpcbind/rpcbind.c:517:			    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpcbind/rpcbind.c:559:		    RPC_MAXDATASIZE, RPC_MAXDATASIZE);
usr.sbin/rpc.statd/statd.c:91:  int maxrec = RPC_MAXDATASIZE;
usr.sbin/rpc.statd/statd.c:561:		RPC_MAXDATASIZE, RPC_MAXDATASIZE);
lib/libc/xdr/xdr.c:705:		maxsize = RPC_MAXDATASIZE;
lib/libc/xdr/xdr.c:767:	return xdr_string(xdrs, cpp, RPC_MAXDATASIZE);
```

### Round 4: ❌ INVALID

[ARBITER] The code stores the record length from the server in ct->ct_record_resid without a sanity check. However, the kernel’s receive buffer limits the amount of data that can be queued. The client processes whatever data is available, moving it into ct_record and freeing the source mbufs. Consequently, the client cannot allocate more memory than the socket buffer allows. The large declared length does not lead to uncontrolled allocation or memory exhaustion beyond normal socket limits, so the reported issue is not a practical security vulnerability.

