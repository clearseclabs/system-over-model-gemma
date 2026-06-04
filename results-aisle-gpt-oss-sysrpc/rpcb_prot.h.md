# Scan: rpcb_prot.h

```json
[
  {
    "severity": "critical",
    "title": "Unbounded XDR string unmarshalling of rpcb fields",
    "function": "xdr_rpcb",
    "description": "The `rpcb` structure contains `char *` members (`r_netid`, `r_addr`, `r_owner`) whose lengths are specified only by the incoming XDR stream.  If the XDR decoder uses `xdr_string` with a large or malformed size field, it will allocate a buffer proportional to that size without any hard‑coded upper bound.  An attacker can supply an excessively large length, which causes memory exhaustion or a heap overflow during allocation or string copying in the generated XDR code, potentially leading to denial‑of‑service or arbitrary code execution if the allocator misbehaves."
  },
  {
    "severity": "high",
    "title": "Integer overflow in XDR processing of args_len/results_len",
    "function": "xdr_rpcb_rmtcallargs / xdr_rpcb_rmtcallres",
    "description": "Both structures contain unsigned 32‑bit fields (`args_len` / `results_len`) used to allocate a temporary buffer that holds the opaque payload.  The generated XDR code performs an allocation of `length * sizeof(char)`; if the length field wraps around when multiplied (e.g., length > UINT32_MAX/sizeof(char)), the requested size becomes very small.  The subsequent copy of the XDR buffer into the allocated memory will then write beyond bounds, corrupting heap metadata and enabling memory corruption or privilege escalation."
  },
  {
    "severity": "high",
    "title": "NULL pointer dereference after XDR unmarshalling",
    "function": "xdr_rpcb / xdr_rpcb_rmtcallargs / xdr_rpcb_rmtcallres",
    "description": "The XDR routines allocate the `char *` fields only when the corresponding XDR string is non‑null.  However the unmarshalling code in *rpcbind* (e.g., `rpcbprog_3_svc`, `rpcbproc_callit_3_svc`) typically accesses these pointers without checking for NULL before performing operations such as string concatenation, comparison, or logging.  A client can send a NULL pointer for any string field, causing a NULL dereference and a server crash or potential exploitation through a fast‑break mechanism."
  },
  {
    "severity": "medium",
    "title": "Missing bounds check on `rpcbs_proc` array usage",
    "function": "xdr_rpcbs_proc / xdr_rpcb_stat_byvers",
    "description": "The array `rpcbs_proc info[RPCBSTAT_HIGHPROC]` is declared with a compile‑time constant (13).  Functions that populate this array (e.g., statistics update routines) may index it by routine numbers not validated against this size.  An attacker that can corrupt the `r_proc` field (via remote call or crafted XDR stream) could cause an out‑of‑bounds write in the array, corrupting adjacent memory and potentially leading to arbitrary code execution or information leakage."
  },
  {
    "severity": "medium",
    "title": "Unvalidated network address string in rpcb_getaddr/_versaddr",
    "function": "xdr_rpcb / rpcbproc_getaddr_*",
    "description": "The `rpcb_getaddr` RPC returns a `char **` pointing to the universal address string.  The server code typically copies or prints this address directly without validating its length or ensuring it is a properly terminated string.  A malformed/overlong string can overflow fixed‑size buffers on the client side, resulting in a client crash or memory corruption that an attacker could exploit during parsing."
  }
]
```