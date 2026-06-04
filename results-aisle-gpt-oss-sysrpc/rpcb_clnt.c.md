# Scan: rpcb_clnt.c

```json
[
  {
    "severity": "critical",
    "title": "Unvalidated pointer dereference in rpcb_set()",
    "function": "rpcb_set",
    "description": "The function copies the caller‑supplied *nconf* and *address* structures and then uses pointers from them (nconf->nc_netid and the address returned by taddr2uaddr()) without verifying that the memory is readable.  An attacker who can supply a crafted rpcb_set() call with a pointer that does not reference valid kernel memory can cause the kernel to read or free arbitrary memory, leading to a crash or arbitrary code execution."
  },
  {
    "severity": "high",
    "title": "Improper null‑pointer handling of rpcb_clnt global",
    "function": "local_rpcb / rpcb_set / rpcb_unset",
    "description": "rpcb_clnt is initialized once at system start.  The API functions rpcb_set() and rpcb_unset() assume rpcb_clnt is non‑NULL and pass it directly to CLNT_CALL without checking.  If for some reason local_rpcb() has not run (e.g., during early boot or if the init sequence fails), a call from user space could dereference a NULL rpcb_clnt pointer, causing a kernel panic."
  },
  {
    "severity": "medium",
    "title": "Race condition due to unsynchronized use of rpcb_clnt",
    "function": "rpcb_set / rpcb_unset",
    "description": "The global CLIENT *rpcb_clnt is accessed concurrently by multiple threads but there is no locking around CLNT_CALL.  If multiple threads perform CLNT_CALL simultaneously, they may corrupt the CLIENT structure or interfere with each other's calls, potentially leading to denial‑of‑service or inconsistent state.  This race in kernel code can be triggered by flooding RPC bind requests."
  }
]
```
