# Triage T0060: Unvalidated pointer dereference in rpcb_set()

- **File**: `rpcb_clnt.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

Unvalidated pointer dereference in rpcb_set()

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The function `rpcb_set()` copies the caller‑supplied `netconfig` and `netbuf` structures by value, but then uses the original pointers in constructing the RPCB arguments: `parms.r_netid = nconf->nc_netid;`. There is no validation that the `nc_netid` pointer (or the pointer returned by `taddr2uaddr()`) is a readable kernel address. If a malicious caller passes a crafted `netconfig` structure containing an arbitrary pointer, the kernel will dereference that pointer while serializing the RPCB parameters (via the XDR routines). Since this dereference occurs in kernel context, an invalid or malicious value can cause the kernel to read or free unintended memory, leading to a crash or arbitrary code execution. The code clearly relates to kernel memory allocation (`M_RPC`, `free(parms.r_addr, M_RPC)`), indicating it runs in kernel mode. Thus the lack of pointer validation represents a real, exploitable security vulnerability. Hence the verdict is VALID.

