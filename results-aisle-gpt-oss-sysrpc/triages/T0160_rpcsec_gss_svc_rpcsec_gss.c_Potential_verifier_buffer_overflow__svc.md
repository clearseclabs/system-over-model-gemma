# Triage T0160: Potential verifier buffer overflow (svc_rpc_gss_nextverf)

- **File**: `rpcsec_gss/svc_rpcsec_gss.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 33% [VUU]

---

## Finding

Potential verifier buffer overflow (svc_rpc_gss_nextverf)

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** svc_rpc_gss_nextverf() copies mic.length bytes into rqst->rq_verf.oa_base without verifying that rqst->rq_verf.oa_length >= mic.length; the verifier buffer may be smaller than the MIC, leading to a buffer overflow.

The code path for generating the reply verifier in RFCSEC_GSS re‑uses the same opaque_auth buffer that carried the request’s verifier. In svc_rpc_gss_nextverf() the server computes a GSS MIC, stores its length in mic.length, and copies it into rqst->rq_verf.oa_base via bcopy(mic.value, rqst->rq_verf.oa_base, mic.length).

The only bound present is a KASSERT that mic.length <= MAX_AUTH_BYTES (defined in rpcsec_gss.h as 400). No check is performed against the original length of rqst->rq_verf.oa_length. That length comes from the client’s request and can be arbitrarily small, so an attacker can send a request with a tiny verifier buffer (e.g., 20‑byte) and a GSS MIC of up to 400 bytes. The bcopy will then write beyond the allocated buffer, corrupting memory. The RPC stack does not impose a larger limit on the verifier buffer before this write; the verifier length is accepted as-is when parsing the incoming call.

The code does not contain a defense that ensures the reply buffer is large enough for the MIC. Therefore an untrusted attacker can trigger a buffer overflow.

Hence the vulnerability is real and attacker‑reachable.


CRUX: svc_rpc_gss_nextverf() copies mic.length bytes into rqst->rq_verf.oa_base without verifying that rqst->rq_verf.oa_length >= mic.length; the verifier buffer may be smaller than the MIC, leading to a buffer overflow.
GREP: svc_rpc_gss_nextverf

🔎 **Grep results:**

GREP `svc_rpc_gss_nextverf`:
```
lib/librpcsec_gss/svc_rpcsec_gss.c:796:svc_rpc_gss_nextverf(struct svc_rpc_gss_client *client,
lib/librpcsec_gss/svc_rpcsec_gss.c:803:	log_debug("in svc_rpc_gss_nextverf()");
lib/librpcsec_gss/svc_rpcsec_gss.c:1066:			if (!svc_rpc_gss_nextverf(client, rqst, gr.gr_win)) {
lib/librpcsec_gss/svc_rpcsec_gss.c:1104:		if (!svc_rpc_gss_nextverf(client, rqst, gc.gc_seq)) {
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1218:svc_rpc_gss_nextverf(struct svc_rpc_gss_client *client,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1226:	rpc_gss_log_debug("in svc_rpc_gss_nextverf()");
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1514:			if (!svc_rpc_gss_nextverf(client, rqst, gr.gr_win)) {
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1556:		if (!svc_rpc_gss_nextverf(client, rqst, gc.gc_seq)) {
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



