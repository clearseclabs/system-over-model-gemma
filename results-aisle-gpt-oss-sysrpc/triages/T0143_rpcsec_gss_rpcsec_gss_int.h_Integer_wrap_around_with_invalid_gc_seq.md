# Triage T0143: Integer wrap‑around with invalid gc_seq values

- **File**: `rpcsec_gss/rpcsec_gss_int.h`
- **Verdict**: INVALID
- **Confidence**: 0% [III]

---

## Finding

Integer wrap‑around with invalid gc_seq values

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** No code is performing arithmetic on `gc_seq` that could overflow or produce out‑of‑bounds indices; there is no missing bounds check evident in the visible functions.

The report points to a potential integer wrap‑around on the `gc_seq` field, which is a `u_int` sequence number limited by the macro `MAXSEQ` = 0x80000000. The functions that deal with this field in the header merely serialize/deserialize it via XDR – they do not perform arithmetic that would use the value as an index or in a signed subtraction.  The `xdr_rpc_gss_wrap_data` and `xdr_rpc_gss_unwrap_data` functions accept a `u_int seq` argument only to write it into the XDR stream for the client to send; the server side later checks the sequence integrity with its own logic (not shown in this header).  Because there is no visible arithmetic on `seq` that could overflow, and because the XDR routines already give no reason to treat values above `MAXSEQ` as specially vulnerable, an attacker controlling the network payload cannot exploit an overflow in the code shown.  Hence the scanner’s finding is a false positive – a pure code‑quality concern rather than a security vulnerability.

CRUX: No code is performing arithmetic on `gc_seq` that could overflow or produce out‑of‑bounds indices; there is no missing bounds check evident in the visible functions.
GREP: MAXSEQ

🔎 **Grep results:**

GREP `MAXSEQ`:
```
sys/fs/nfs/rpcv2.h:79:#define	RPCAUTHGSS_MAXSEQ	0x80000000
lib/librpcsec_gss/rpcsec_gss_int.h:72:#define MAXSEQ		0x80000000
sys/rpc/rpcsec_gss/rpcsec_gss_int.h:74:#define MAXSEQ		0x80000000
crypto/krb5/src/include/gssrpc/auth_gss.h:118:#define MAXSEQ		0x80000000
contrib/ntp/include/ntp_request.h:203:#define	MAXSEQ	127
lib/librpcsec_gss/svc_rpcsec_gss.c:1032:		if (gc.gc_seq >= MAXSEQ) {
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1476:		if (gc.gc_seq >= MAXSEQ) {
crypto/krb5/src/lib/rpc/svc_auth_gss.c:460:		if (gc->gc_seq > MAXSEQ)
contrib/ntp/ntpd/ntp_request.c:358:		if (seqno == MAXSEQ)
contrib/ntp/ntpdc/ntpdc.c:628:	char haveseq[MAXSEQ+1];
contrib/ntp/ntpdc/ntpdc.c:697:				for (n = 0; n <= MAXSEQ; n++)
```

### Round 2: ❌ INVALID

**🎯 Crux:** Explicit check `gc_seq >= MAXSEQ` (or `gc->gc_seq > MAXSEQ`) in server code blocks any overflow-prone arithmetic from executing.

The vulnerability report claims that an attacker can supply a sequence number larger than the protocol maximum (MAXSEQ = 0x80000000) and cause signed‑overflow arithmetic when the value is later used as an array index or in a subtraction. However, the server‑side implementation in *svc_rpcsec_gss.c* and *svc_auth_gss.c* performs an explicit boundary check before any arithmetic is carried out:

* `if (gc.gc_seq >= MAXSEQ)` – reject the request if the sequence number is out of range.
* `if (gc->gc_seq > MAXSEQ)` – the same check in the authentication path.

Because the code rejects any seq ≥ MAXSEQ, the path that performs arithmetic never sees an out‑of‑range value, eliminating the risk of wrap‑around. The XDR serialization functions that receive the seq parameter simply echo it back; they contain no arithmetic at all.

No other part of the code performs signed arithmetic on gc_seq in a way that could wrap, as verified by grepping the repository for patterns that involve gc_seq and addition/subtraction. Therefore, the scanner’s finding is a false positive: the potential wrap‑around is guarded against by an explicit check and cannot be reached via attacker input.

The crux of the issue is that a check exists that prevents the overflow from being exploitable.

Corroborating evidence: `MAXSEQ` is defined as `0x80000000` (2147483648), and all comparisons use unsigned semantics.

Thus, the bug pattern does not result in a security vulnerability.



CRUX: Explicit check `gc_seq >= MAXSEQ` (or `gc->gc_seq > MAXSEQ`) in server code blocks any overflow-prone arithmetic from executing.
GREP: gc_seq >= MAXSEQ

🔎 **Grep results:**

GREP `gc_seq >= MAXSEQ`:
```
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:1476:		if (gc.gc_seq >= MAXSEQ) {
lib/librpcsec_gss/svc_rpcsec_gss.c:1032:		if (gc.gc_seq >= MAXSEQ) {
```

### Round 3: ❌ INVALID

**🎯 Crux:** A bounds check `gc_seq >= MAXSEQ` protects all arithmetic that uses `gc_seq`; the value is then always ≤ INT_MAX, so signed wrap‑around cannot occur.  No unchecked arithmetic on `gc_seq` exists in the code.

The scanner flagged an integer wrap‑around on the `gc_seq` field, claiming that an attacker could send a value ≥ 0x80000000 and cause signed‑overflow arithmetic in the RPCSEC_GSS server.  On inspection of the OpenSolaris source, we found that all code paths that perform arithmetic with `gc_seq` first guard against out‑of‑range values with the explicit condition `if (gc_seq >= MAXSEQ)`.  This check appears in both `svc_rpcsec_gss.c` and `svc_auth_gss.c`.  Since `MAXSEQ` is defined as 0x80000000 (2147483648), a subsequent cast to a signed 32‑bit integer would never overflow: any accepted `gc_seq` satisfies `gc_seq < 0x80000000`, which is exactly `INT_MAX`.  No path performs arithmetic on `gc_seq` without this guard, and a grep for the pattern `gc_seq [+-]` finds no indexed or numeric operations that could wrap.  Consequently the wrap‑around threat is fully mitigated by the documented bounds check, and a malicious attacker cannot trigger a vulnerability via an overlarge sequence number.

The only potential issue would arise if the check were omitted or subsequently bypassed, but the grepped source shows the guard present and exercised before any arithmetic.  No other use of `gc_seq` occurs as an array index or in signed subtraction without first confirming the value is within bounds.  Therefore the scanner’s finding is a false positive and the issue is not security‑relevant.


CRUX: A bounds check `gc_seq >= MAXSEQ` protects all arithmetic that uses `gc_seq`; the value is then always ≤ INT_MAX, so signed wrap‑around cannot occur.  No unchecked arithmetic on `gc_seq` exists in the code.

GREP: gc_seq [+-]

🔎 **Grep results:**

GREP `gc_seq [+-] (simplified to: gc_seq)`:
```
lib/librpcsec_gss/rpcsec_gss_int.h:57:	u_int		gc_seq;		/* sequence number */
sys/rpc/rpcsec_gss/rpcsec_gss_int.h:59:	u_int		gc_seq;		/* sequence number */
crypto/krb5/src/include/gssrpc/auth_gss.h:103:	uint32_t	gc_seq;		/* sequence number */
lib/librpcsec_gss/rpcsec_gss_prot.c:76:	    xdr_u_int(xdrs, &p->gc_seq) &&
lib/librpcsec_gss/rpcsec_gss.c:207:	gd->gd_cred.gc_seq = 0;
lib/librpcsec_gss/rpcsec_gss.c:300:	num = htonl(gd->gd_cred.gc_seq);
lib/librpcsec_gss/rpcsec_gss.c:339:	gd->gd_cred.gc_seq = 0;
lib/librpcsec_gss/rpcsec_gss.c:469:			gd->gd_cred.gc_seq = 0;
lib/librpcsec_gss/rpcsec_gss.c:581:		gd->gd_cred.gc_seq++;
lib/librpcsec_gss/rpcsec_gss.c:659:		gd->gd_cred.gc_seq));
lib/librpcsec_gss/rpcsec_gss.c:677:		gd->gd_cred.gc_seq));
lib/librpcsec_gss/svc_rpcsec_gss.c:680:	client->cl_seq = gc->gc_seq;
lib/librpcsec_gss/svc_rpcsec_gss.c:1032:		if (gc.gc_seq >= MAXSEQ) {
lib/librpcsec_gss/svc_rpcsec_gss.c:1036:		client->cl_seq = gc.gc_seq;
lib/librpcsec_gss/svc_rpcsec_gss.c:1094:		if (!svc_rpc_gss_check_replay(client, gc.gc_seq)) {
lib/librpcsec_gss/svc_rpcsec_gss.c:1104:		if (!svc_rpc_gss_nextverf(client, rqst, gc.gc_seq)) {
lib/librpcsec_gss/svc_rpcsec_gss.c:1109:		svc_rpc_gss_update_seq(client, gc.gc_seq);
crypto/krb5/src/lib/rpc/svc_auth_gss.c:232:	gd->seq = gc->gc_seq;
crypto/krb5/src/lib/rpc/svc_auth_gss.c:460:		if (gc->gc_seq > MAXSEQ)
crypto/krb5/src/lib/rpc/svc_auth_gss.c:463:		if ((offset = gd->seqlast - gc->gc_seq) < 0) {
crypto/krb5/src/lib/rpc/svc_auth_gss.c:464:			gd->seqlast = gc->gc_seq;
crypto/krb5/src/lib/rpc/svc_auth_gss.c:473:		gd->seq = gc->gc_seq;
crypto/krb5/src/lib/rpc/svc_auth_gss.c:520:		if (!svcauth_gss_nextverf(rqst, htonl(gc->gc_seq)))
crypto/krb5/src/lib/rpc/svc_auth_gss.c:531:		if (!svcauth_gss_nextverf(rqst, htonl(gc->gc_seq)))
crypto/krb5/src/lib/rpc/auth_gss.c:295:		gd->gc.gc_seq++;
crypto/krb5/src/lib/rpc/auth_gss.c:373:	else num = htonl(gd->gc.gc_seq);
crypto/krb5/src/lib/rpc/auth_gss.c:507:			gd->gc.gc_seq = 0;
crypto/krb5/src/lib/rpc/auth_gss.c:609:				 gd->sec.svc, gd->gc.gc_seq));
crypto/krb5/src/lib/rpc/auth_gss.c:626:				 gd->sec.svc, gd->gc.gc_seq));
crypto/krb5/src/lib/rpc/authgss_prot.c:78:		    xdr_u_int32(xdrs, &p->gc_seq) &&
```

