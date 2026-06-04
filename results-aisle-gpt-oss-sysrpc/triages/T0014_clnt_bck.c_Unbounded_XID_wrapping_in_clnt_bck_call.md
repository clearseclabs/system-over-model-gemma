# Triage T0014: Unbounded XID wrapping in clnt_bck_call allows request replay

- **File**: `clnt_bck.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI→I]

---

## Finding

Unbounded XID wrapping in clnt_bck_call allows request replay

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** XID counter increments internally and is not influenced by untrusted input; wrap does not allow replay of attacker‑controlled RPCs.

The reported issue claims that the 32‑bit XID counter in clnt_bck_call can wrap after ~4 B calls, giving an attacker the ability to replay or spoof RPC messages.  In the source the counter is an unsigned 32‑bit field: `ct->ct_xid++; xid = ct->ct_xid;`.  It is initialized at client creation with a random value and is only ever modified by the client internally.  No external input or network data can influence its value; an attacker cannot inject a request that causes the counter to increment or reset.  The only possible effect of wrapping is that a new request will have the same XID as a previous request that has already been processed, in which case the previous reply has already been matched and the pending‑request entry for that XID has been removed and its XID set to 0.  Consequently, an attacker cannot create a duplicate or stale reply that will be accepted, nor can the client inadvertently accept a forged reply because XID alone is not a security guard – AUTH_VALIDATE still checks the credential.  In other words, the counter wrap is an internal implementation detail, and the scanner’s claim that it enables an attacker‑controlled replay or credential‑refresh bypass is unfounded.  The bug pattern exists, but it is not reachable from untrusted data and does not provide a meaningful attack surface.  Therefore the finding is INVALID.

CRUX: XID counter increments internally and is not influenced by untrusted input; wrap does not allow replay of attacker‑controlled RPCs.
GREP: ct->ct_xid

🔎 **Grep results:**

GREP `ct->ct_xid`:
```
sys/rpc/clnt_bck.c:149:	ct->ct_xid = ((uint32_t)++disrupt) ^ __RPC_GETXID(&now);
sys/rpc/clnt_bck.c:150:	call_msg.rm_xid = ct->ct_xid;
sys/rpc/clnt_bck.c:238:	ct->ct_xid++;
sys/rpc/clnt_bck.c:239:	xid = ct->ct_xid;
sys/rpc/clnt_vc.c:228:	ct->ct_xid = ((uint32_t)++disrupt) ^ __RPC_GETXID(&now);
sys/rpc/clnt_vc.c:229:	call_msg.rm_xid = ct->ct_xid;
sys/rpc/clnt_vc.c:349:	ct->ct_xid++;
sys/rpc/clnt_vc.c:350:	xid = ct->ct_xid;
sys/rpc/clnt_vc.c:683:		*(uint32_t *)info = ct->ct_xid;
sys/rpc/clnt_vc.c:688:		ct->ct_xid = *(uint32_t *)info - 1;
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** ct->ct_xid is an internal client counter that cannot be set by untrusted input; wrapping merely repeats old values that are no longer pending and cannot be exploited.

The XID used by clnt_bck_call is a 32‑bit unsigned counter that lives in the client’s private ct_data structure.  The counter is initialized to a random value at client creation, and every call increments it while holding ct->ct_lock.  No data received from the network or from untrusted callers is ever used to set or influence the counter.  Consequently an attacker cannot make the client send any particular XID value.  If the counter wraps after ~4 B calls, the next XID value simply repeats a value that the client may have used previously.  At that point the pending request with that XID has already been removed from the queue and its cr->cr_xid set to 0, so a replayed or forged reply with the wrapped XID will never match a pending entry and is discarded.  Moreover, each reply is authenticated by the credential mechanism (AUTH_VALIDATE), so even a duplicate XID cannot bypass authentication or credential refresh.  Therefore the vulnerability scanner’s claim that the wrap allows an attacker‑controlled replay or credential‑refresh bypass is unfounded.

No external attacker can influence the counter, and the only effect of wrap is harmless state reuse.  No security‑relevant behavior is affected.

Although an unbounded counter might raise a code‑quality concern, it is not a security vulnerability.


CRUX: ct->ct_xid is an internal client counter that cannot be set by untrusted input; wrapping merely repeats old values that are no longer pending and cannot be exploited.
GREP: ct->ct_xid

🔎 **Grep results:**

GREP `ct->ct_xid`:
```
sys/rpc/clnt_bck.c:149:	ct->ct_xid = ((uint32_t)++disrupt) ^ __RPC_GETXID(&now);
sys/rpc/clnt_bck.c:150:	call_msg.rm_xid = ct->ct_xid;
sys/rpc/clnt_bck.c:238:	ct->ct_xid++;
sys/rpc/clnt_bck.c:239:	xid = ct->ct_xid;
sys/rpc/clnt_vc.c:228:	ct->ct_xid = ((uint32_t)++disrupt) ^ __RPC_GETXID(&now);
sys/rpc/clnt_vc.c:229:	call_msg.rm_xid = ct->ct_xid;
sys/rpc/clnt_vc.c:349:	ct->ct_xid++;
sys/rpc/clnt_vc.c:350:	xid = ct->ct_xid;
sys/rpc/clnt_vc.c:683:		*(uint32_t *)info = ct->ct_xid;
sys/rpc/clnt_vc.c:688:		ct->ct_xid = *(uint32_t *)info - 1;
```

### Round 4: ❌ INVALID

[ARBITER] The XID (`ct->ct_xid`) is a 32‑bit unsigned counter that is only incremented internally by the client. The counter is initialized to a random value, and no untrusted input can set or influence it. When the counter wraps at 4,294,967,296, the new value will equal a value that has already been used before. The server’s reply handling (`clnt_bck_svccall`) matches replies to pending requests by XID; if no matching pending request is found (e.g., the XID has already been processed and the entry cleared), the reply is discarded. Thus, an attacker cannot force the client to resend a previously processed request or to reuse a cached response. The wrap does not bypass authentication refresh logic either because authentication checks are performed after replying to the request. Therefore, the claim that unbounded XID wrapping allows request replay does not hold for this code. The vulnerability is therefore **INVALID**.

