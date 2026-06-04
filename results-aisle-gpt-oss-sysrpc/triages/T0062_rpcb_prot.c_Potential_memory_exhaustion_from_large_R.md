# Triage T0062: Potential memory exhaustion from large RPC strings

- **File**: `rpcb_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Potential memory exhaustion from large RPC strings

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] In NetBSD (the source for the file) RPC_MAXDATASIZE is defined as 32767 (32 KB). The XDR routine `xdr_string` will allocate a buffer of size `len+1` bytes, where `len` is the length received in the RPC packet, but it will not allocate more than RPC_MAXDATASIZE. A single string of 32 KB consumes negligible memory, and the binder processes calls sequentially, freeing the buffer after each call. Therefore, even with a large number of requests it would require thousands of concurrent requests to exhaust system memory, which is not realistic. No evidence shows that RPC_MAXDATASIZE is set to a harmful value or that multiple strings are kept concurrently. Hence the claim of a memory‑exhaustion vulnerability is unfounded.

