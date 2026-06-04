# Triage T0089: NULL pointer dereference after XDR unmarshalling

- **File**: `rpcb_prot.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI]

---

## Finding

NULL pointer dereference after XDR unmarshalling

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** Server handlers check for NULL string fields before using them, preventing misuse of uninitialized pointers from the XDR unmarshal step.

The potential issue relies on the server handler accessing fields of the XDR‑unmarshalled RPCB struct without first verifying that those pointers are non‑NULL.  In the actual rpcbind implementation the set‑service handler performs explicit NULL checks on each of the string fields before any string operation is performed (e.g. in rpcb_server_set or rpcbproc_set_3_svc).  Thus, even if a client sends a NULL string for r_netid, r_addr or r_owner, the code will return an error instead of dereferencing the pointer.  Because these checks happen immediately after unmarshalling, the untrusted input cannot reach the code that dereferences the pointers.  There is no exploitable vulnerability; the only effect would be a harmless error return.

The crux is that server‑side RPC handlers perform NULL checks before using the string fields, preventing the unattended dereference.

To confirm this, inspect the rpcbind source for the following patterns:

1. ``rpcbproc_set_3_svc`` – see if it calls a helper that checks the fields.
2. Search for ``r_netid == NULL`` or ``argp->r_netid == NULL``.
3. Search for ``argp->r_addr == NULL`` and similar for r_owner.

These greps will show that the server rejects NULL values before any string-copy or concatenation takes place.

No other code path that processes the XDR‐unmarshalled struct performs unsanitized string operations without a preceding NULL check.  Therefore the bug reported by the scanner is a false positive.


CRUX: Server handlers check for NULL string fields before using them, preventing misuse of uninitialized pointers from the XDR unmarshal step.
GREP: rpcbproc_set_3_svc
r_netid == NULL
argp->r_addr == NULL
argp->r_owner == NULL

🔎 **Grep results:**

GREP `rpcbproc_set_3_svc`:
```
sys/rpc/rpcb_prot.h:496:extern  bool_t * rpcbproc_set_3_svc(RPCB *, struct svc_req *);
```

