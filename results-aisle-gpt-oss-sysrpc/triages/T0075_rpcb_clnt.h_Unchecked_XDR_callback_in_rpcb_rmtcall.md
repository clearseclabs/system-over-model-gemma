# Triage T0075: Unchecked XDR callback in rpcb_rmtcall

- **File**: `rpcb_clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI→I]

---

## Finding

Unchecked XDR callback in rpcb_rmtcall

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** rpcb_rmtcall passes arbitrary xdrproc_t callbacks directly to clnt_call; no runtime validation, so a malicious local client can cause local corruption/DoS, but not a remote or system‑wide exploit.

The function rpcb_rmtcall simply forwards the caller‑supplied xdrproc_t callbacks to clnt_call without performing any validation. A malicious local client can point these callbacks to arbitrary code, causing the client process to crash or corrupt its own memory. The API contract assumes callers supply well‑formed XDR procedures, so the library does not provide any defensive checks. Because the attacker must run code in the client’s process space (i.e., it must be a malicious client program), this does not constitute a remote or cross‑process vulnerability – it is merely a misuse of the API that can lead to local denial‑of‑service. No defensive bounds checks or sanitization are enforced on the callbacks, and the bug only affects the caller’s own process, not the RPC subsystems or other users’ processes. Therefore the finding is not a security vulnerability but a code‑quality / contract issue and should be rated INVALID.

CRUX: rpcb_rmtcall passes arbitrary xdrproc_t callbacks directly to clnt_call; no runtime validation, so a malicious local client can cause local corruption/DoS, but not a remote or system‑wide exploit.
GREP: rpcb_rmtcall

🔎 **Grep results:**

GREP `rpcb_rmtcall`:
```
include/rpc/rpcb_clnt.h:48: *	clnt_stat = rpcb_rmtcall(nconf, host, program, version, procedure,
include/rpc/rpcb_clnt.h:69:extern enum clnt_stat rpcb_rmtcall(const struct netconfig *,
sys/rpc/rpcb_clnt.h:48: *	clnt_stat = rpcb_rmtcall(nconf, host, program, version, procedure,
sys/rpc/rpcb_clnt.h:72:extern enum clnt_stat rpcb_rmtcall(const struct netconfig *,
sys/rpc/rpcb_prot.h:75: * RPCBPROC_CALLIT(rpcb_rmtcallargs)
sys/rpc/rpcb_prot.h:76: * 	RETURNS (rpcb_rmtcallres);
sys/rpc/rpcb_prot.h:99: * RPCBPROC_BCAST(rpcb_rmtcallargs)
sys/rpc/rpcb_prot.h:100: * 	RETURNS (rpcb_rmtcallres);
sys/rpc/rpcb_prot.h:111: * RPCBPROC_INDIRECT(rpcb_rmtcallargs)
sys/rpc/rpcb_prot.h:112: * 	RETURNS (rpcb_rmtcallres);
sys/rpc/rpcb_prot.h:184:struct rpcb_rmtcallargs {
sys/rpc/rpcb_prot.h:193:typedef struct rpcb_rmtcallargs rpcb_rmtcallargs;
sys/rpc/rpcb_prot.h:196: * Client-side only representation of rpcb_rmtcallargs structure.
sys/rpc/rpcb_prot.h:198: * The routine that XDRs the rpcb_rmtcallargs structure must deal with the
sys/rpc/rpcb_prot.h:199: * opaque arguments in the "args" structure.  xdr_rpcb_rmtcallargs() needs to
sys/rpc/rpcb_prot.h:203: * different "XDR" structure on the client side, r_rpcb_rmtcallargs, which
sys/rpc/rpcb_prot.h:206:struct r_rpcb_rmtcallargs {
sys/rpc/rpcb_prot.h:222:struct rpcb_rmtcallres {
sys/rpc/rpcb_prot.h:229:typedef struct rpcb_rmtcallres rpcb_rmtcallres;
sys/rpc/rpcb_prot.h:232: * Client-side only representation of rpcb_rmtcallres structure.
sys/rpc/rpcb_prot.h:234:struct r_rpcb_rmtcallres {
sys/rpc/rpcb_prot.h:379:struct rpcb_rmtcallargs {
sys/rpc/rpcb_prot.h:387:typedef struct rpcb_rmtcallargs rpcb_rmtcallargs;
sys/rpc/rpcb_prot.h:392:struct rpcb_rmtcallres {
sys/rpc/rpcb_prot.h:398:typedef struct rpcb_rmtcallres rpcb_rmtcallres;
sys/rpc/rpcb_prot.h:507:extern  rpcb_rmtcallres * rpcbproc_callit_3(rpcb_rmtcallargs *, CLIENT *);
sys/rpc/rpcb_prot.h:508:extern  rpcb_rmtcallres * rpcbproc_callit_3_svc(rpcb_rmtcallargs *, struct svc_req *);
sys/rpc/rpcb_prot.h:531:extern  rpcb_rmtcallres * rpcbproc_bcast_4(rpcb_rmtcallargs *, CLIENT *);
sys/rpc/rpcb_prot.h:532:extern  rpcb_rmtcallres * rpcbproc_bcast_4_svc(rpcb_rmtcallargs *, struct svc_req *);
sys/rpc/rpcb_prot.h:543:extern  rpcb_rmtcallres * rpcbproc_indirect_4(rpcb_rmtcallargs *, CLIENT *);
```

### Round 4: ❌ INVALID

[ARBITER] `rpcb_rmtcall` is part of the RPC client library API and is only intended to be called by trusted client code. The function simply forwards the caller‑supplied XDR procedure pointers to `clnt_call`. If the caller supplies malformed callbacks, the call will fail or the client process may crash, but this is expected behaviour for a misuse of the API, not a security flaw exposed to an external attacker.

There is no unchecked or unchecked bounds checking that allows an untrusted remote party to control the callbacks or influence the deserialization of data from a remote server. The API contract requires that callers provide well‑formed XDR procedures; the library does not attempt to validate them beyond what the underlying `clnt_call` will do. Therefore the claim of a “high‑severity” unchecked XDR callback vulnerability is unfounded from the standpoint of remote or system‑wide exploitation; it is effectively a benign design choice.

Hence the finding should be considered invalid.

