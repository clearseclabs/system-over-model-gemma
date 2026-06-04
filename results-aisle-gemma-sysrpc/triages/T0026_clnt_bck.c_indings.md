# Triage T0026: indings

- **File**: `clnt_bck.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

indings

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** XID spoofing is prevented by AUTH_VALIDATE; the request queue is bounded by call timeouts and memory limits.

I analyzed both findings. 

1. **XID Spoofing**: The report claims XIDs are predictable. In `clnt_bck_create`, the initial XID is `((uint32_t)++disrupt) ^ __RPC_GETXID(&now)`, where `disrupt` is initialized to the socket address. Subsequent calls in `clnt_bck_call` simply do `ct->ct_xid++`. While this is a linear counter and technically predictable, the crucial defense is the authentication layer. In `clnt_bck_call`, the response is processed via `AUTH_VALIDATE(auth, xid, &reply_msg.acpted_rply.ar_verf, &results)`. For the backchannel to be useful to an attacker, they would need to spoof a valid authenticated reply. Since the transport is explicitly stated to be for NFSv4.1 session backchannels (which use session-based security or TLS via `rpcsec_tls.h` as seen in the includes), simple XID prediction is insufficient to inject a payload that passes `AUTH_VALIDATE` without the session keys.

2. **Unbounded Request Queue**: The `ct_pending` queue is a `TAILQ` where `ct_request` structures are inserted in `clnt_bck_call` and removed after a response or timeout. The scanner claims there is no maximum size. While there is no explicit `if (queue_len > MAX)` check, the `ct_request` is allocated via `malloc(..., M_WAITOK)`. In a kernel environment, this will eventually fail or cause the system to swap/pressure if truly unbounded. However, the number of pending requests is naturally bounded by the number of active threads calling `clnt_bck_call` and the timeout `utimeout`. Since these are callback requests sent by the client to the server on a specific TCP connection, the 'attacker' would have to be the server. A malicious server can refuse to respond, but the requests will time out and be removed via `msleep` returning `EWOULDBLOCK` or the `timeout` expiring. This is a resource management concern, but given it's a kernel-side client handle for a specific connection, it's not a remote exploit primitive for an external attacker to crash the kernel arbitrarily without already having a connection established, and it's managed by standard kernel memory pressure and timeouts.

CRUX: XID spoofing is prevented by AUTH_VALIDATE; the request queue is bounded by call timeouts and memory limits.
GREP: AUTH_VALIDATE

🔎 **Grep results:**

GREP `AUTH_VALIDATE`:
```
sys/rpc/auth.h:212:#define AUTH_VALIDATE(auth, xid, verfp, resultsp) \
include/rpc/auth.h:214:#define AUTH_VALIDATE(auth, verfp)	\
crypto/krb5/src/include/gssrpc/auth.h:142:#define AUTH_VALIDATE(auth, verfp)	\
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:589:/// Part 2, section 5.11: TPM_CHANGEAUTH_VALIDATE
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:591:typedef struct tdTPM_CHANGEAUTH_VALIDATE {
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:594:} TPM_CHANGEAUTH_VALIDATE;
sys/rpc/clnt_nl.c:363:			if (__predict_true(AUTH_VALIDATE(auth, cr->cr_xid,
sys/rpc/clnt_bck.c:323:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_bck.c:429:			if (!AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_bck.c:475:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_dg.c:702:			if (! AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_dg.c:773:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_vc.c:438:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_vc.c:547:			if (!AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_vc.c:596:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/rpcsec_gss/rpcsec_gss.c:555:		 * the matching gss_verify_mic in AUTH_VALIDATE.
lib/libc/rpc/clnt_raw.c:206:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
lib/libc/rpc/clnt_raw.c:216:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
lib/libc/rpc/clnt_vc.c:418:		if (! AUTH_VALIDATE(cl->cl_auth,
lib/libc/rpc/clnt_dg.c:538:			if (! AUTH_VALIDATE(cl->cl_auth,
crypto/krb5/src/lib/rpc/clnt_tcp.c:331:		if (! AUTH_VALIDATE(h->cl_auth, &reply_msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_raw.c:202:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_raw.c:212:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_udp.c:368:			if (! AUTH_VALIDATE(cl->cl_auth,
```

### Round 2: ❌ INVALID

**🎯 Crux:** XID spoofing is mitigated by AUTH_VALIDATE, and the request queue is bounded by the client's own call rate and enforced timeouts.

I evaluated both findings. 

1. **XID Spoofing**: The report claims XIDs are predictable. Looking at `clnt_bck_create`, the initial XID uses a predictable seed (socket address and time). In `clnt_bck_call`, XIDs are incremented linearly (`ct->ct_xid++`). While predictable, an attacker cannot inject a meaningful reply because `clnt_bck_call` enforces `AUTH_VALIDATE(auth, xid, &reply_msg.acpted_rply.ar_verf, &results)` at line 429. For the attack to be valid, the attacker would need to forge a valid cryptographic authenticator for the given XID. Since this is used for NFSv4.1 backchannels (which require session security or TLS), the attacker lacks the keys to pass `AUTH_VALIDATE`. Predictability of XID is a known property of RPC, and the security is delegated to the authentication layer.

2. **Unbounded Request Queue**: The `ct_pending` queue is indeed a `TAILQ` without an explicit count limit. However, for a remote attacker (the server) to exhaust memory, they must trigger the allocation of `ct_request` structures. These allocations happen in `clnt_bck_call` when the *client* initiates a request. A malicious server cannot force the client to create requests; it can only refuse to respond to them. If the server refuses to respond, each request is removed from the queue when `msleep` returns due to the `timeout` expiring (line 368). The memory usage is thus bounded by `(Max Concurrent Requests) * (sizeof(ct_request))`. Since `clnt_bck_call` is typically called by a limited number of kernel threads, this does not provide a remote memory exhaustion primitive.

Both findings are invalid as they either lack a viable exploit path or are mitigated by existing architectural defenses (Authentication and Timeouts).

CRUX: XID spoofing is mitigated by AUTH_VALIDATE, and the request queue is bounded by the client's own call rate and enforced timeouts.
GREP: AUTH_VALIDATE

🔎 **Grep results:**

GREP `AUTH_VALIDATE`:
```
sys/rpc/auth.h:212:#define AUTH_VALIDATE(auth, xid, verfp, resultsp) \
include/rpc/auth.h:214:#define AUTH_VALIDATE(auth, verfp)	\
crypto/krb5/src/include/gssrpc/auth.h:142:#define AUTH_VALIDATE(auth, verfp)	\
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:589:/// Part 2, section 5.11: TPM_CHANGEAUTH_VALIDATE
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:591:typedef struct tdTPM_CHANGEAUTH_VALIDATE {
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:594:} TPM_CHANGEAUTH_VALIDATE;
lib/libc/rpc/clnt_raw.c:206:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
lib/libc/rpc/clnt_raw.c:216:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
lib/libc/rpc/clnt_vc.c:418:		if (! AUTH_VALIDATE(cl->cl_auth,
lib/libc/rpc/clnt_dg.c:538:			if (! AUTH_VALIDATE(cl->cl_auth,
sys/rpc/clnt_bck.c:323:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_bck.c:429:			if (!AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_bck.c:475:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_nl.c:363:			if (__predict_true(AUTH_VALIDATE(auth, cr->cr_xid,
sys/rpc/clnt_vc.c:438:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_vc.c:547:			if (!AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_vc.c:596:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/rpcsec_gss/rpcsec_gss.c:555:		 * the matching gss_verify_mic in AUTH_VALIDATE.
sys/rpc/clnt_dg.c:702:			if (! AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_dg.c:773:		AUTH_VALIDATE(auth, xid, NULL, NULL);
crypto/krb5/src/lib/rpc/clnt_tcp.c:331:		if (! AUTH_VALIDATE(h->cl_auth, &reply_msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_raw.c:202:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_raw.c:212:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_udp.c:368:			if (! AUTH_VALIDATE(cl->cl_auth,
```

### Round 3: ❌ INVALID

**🎯 Crux:** XID spoofing is prevented by AUTH_VALIDATE requiring a valid cryptographic verifier; the request queue is bounded by client-side call rates and enforced timeouts.

I evaluated both findings in `clnt_bck.c`. 

1. **XID Spoofing**: The report correctly identifies that XIDs are predictable (initialized with socket address and time, then incremented linearly). However, for an attacker to successfully inject a spoofed RPC reply, they must pass `AUTH_VALIDATE(auth, xid, &reply_msg.acpted_rply.ar_verf, &results)` at line 429. Since this code is specifically for NFSv4.1 session backchannels, it uses secure authentication (as evidenced by the inclusion of `rpc/rpcsec_tls.h`). A remote attacker cannot forge a valid cryptographic authenticator (verifier) for a predicted XID without the session keys. Thus, the predictability of the XID is not a security vulnerability in this context.

2. **Unbounded Request Queue**: The `ct_pending` queue is a `TAILQ` without an explicit size limit. However, entries are only added when the *client* (the kernel) initiates a request via `clnt_bck_call`. A remote attacker (the server) cannot force the client to allocate `ct_request` structures. If the server refuses to respond to legitimate requests, the memory is bounded by the number of concurrent calls the client is willing to make, and every request is guaranteed to be removed from the queue when the `timeout` expires (via `msleep` returning `EWOULDBLOCK` or timeout, line 368). This is a resource management characteristic, not a remote exploit primitive for memory exhaustion.

CRUX: XID spoofing is prevented by AUTH_VALIDATE requiring a valid cryptographic verifier; the request queue is bounded by client-side call rates and enforced timeouts.
GREP: AUTH_VALIDATE

🔎 **Grep results:**

GREP `AUTH_VALIDATE`:
```
sys/rpc/auth.h:212:#define AUTH_VALIDATE(auth, xid, verfp, resultsp) \
include/rpc/auth.h:214:#define AUTH_VALIDATE(auth, verfp)	\
crypto/krb5/src/include/gssrpc/auth.h:142:#define AUTH_VALIDATE(auth, verfp)	\
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:589:/// Part 2, section 5.11: TPM_CHANGEAUTH_VALIDATE
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:591:typedef struct tdTPM_CHANGEAUTH_VALIDATE {
sys/contrib/edk2/Include/IndustryStandard/Tpm12.h:594:} TPM_CHANGEAUTH_VALIDATE;
sys/rpc/clnt_bck.c:323:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_bck.c:429:			if (!AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_bck.c:475:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_nl.c:363:			if (__predict_true(AUTH_VALIDATE(auth, cr->cr_xid,
sys/rpc/clnt_vc.c:438:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/clnt_vc.c:547:			if (!AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_vc.c:596:		AUTH_VALIDATE(auth, xid, NULL, NULL);
sys/rpc/rpcsec_gss/rpcsec_gss.c:555:		 * the matching gss_verify_mic in AUTH_VALIDATE.
sys/rpc/clnt_dg.c:702:			if (! AUTH_VALIDATE(auth, xid,
sys/rpc/clnt_dg.c:773:		AUTH_VALIDATE(auth, xid, NULL, NULL);
lib/libc/rpc/clnt_raw.c:206:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
lib/libc/rpc/clnt_raw.c:216:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
lib/libc/rpc/clnt_vc.c:418:		if (! AUTH_VALIDATE(cl->cl_auth,
lib/libc/rpc/clnt_dg.c:538:			if (! AUTH_VALIDATE(cl->cl_auth,
crypto/krb5/src/lib/rpc/clnt_tcp.c:331:		if (! AUTH_VALIDATE(h->cl_auth, &reply_msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_raw.c:202:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_raw.c:212:		if (! AUTH_VALIDATE(h->cl_auth, &msg.acpted_rply.ar_verf)) {
crypto/krb5/src/lib/rpc/clnt_udp.c:368:			if (! AUTH_VALIDATE(cl->cl_auth,
```

### Round 4: ❌ INVALID

[ARBITER] The report claims XID spoofing is possible due to predictability. However, in `clnt_bck_call`, every response is subjected to `AUTH_VALIDATE(auth, xid, &reply_msg.acpted_rply.ar_verf, &results)`. For an attacker to inject a spoofed reply, they would need to forge a valid cryptographic verifier (credential) for the authentication flavor in use, not just predict the XID. Regarding the unbounded queue, while `ct_pending` has no explicit maximum size, it is bounded by the memory limits of the system and the timeouts associated with each request (`msleep` with `tvtohz(&timeout)`), which ensures requests are removed from the queue. There is no evidence of a practical security vulnerability.

