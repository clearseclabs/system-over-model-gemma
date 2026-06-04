# Triage T0127: Unprotected NULL pointer dereference – rpc_gss_qop_to_num

- **File**: `rpcsec_gss/rpcsec_gss_conf.c`
- **Verdict**: INVALID
- **Confidence**: 25% [UVU→I]

---

## Finding

Unprotected NULL pointer dereference – rpc_gss_qop_to_num

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ✅ VALID

**🎯 Crux:** The function dereferences a NULL pointer when the XDR string decoder passes a NULL for a zero‑length QOP string; no upstream guard is present

The function rpc_gss_qop_to_num calls strcmp directly on its first argument. The only callers are the RPCSEC_GSS authentication handlers that receive strings deserialized from the RPC request. The XDR decoder used by the RPC layer sets the string pointer to NULL when the encoded length is zero (the standard XDR string‐decode routine assigns NULL to empty strings). Therefore an attacker can send an AUTH_GSS request containing a zero‑length QOP string, which results in qop being NULL when rpc_gss_qop_to_num is invoked, causing the kernel to dereference a null pointer and crash. No defensive check exists in the function, and no prior caller guarantees that qop is non‑NULL (the decoder does not verify string length >0). Consequently the null‑pointer dereference is attacker‑reachable and results in a critical kernel fault. This is a security‑relevant vulnerability. No implicit input validation, size limit or NULL guard is present; the only reference is the standard XDR routine which does not constrain the field to be non‑empty.

Crucially, this is not a benign code‑quality issue: the bug is exploitable by an external client and leads to denial of service by crashing the kernel.

The findings from prior reviewers did not confirm a defensive check or a guarantee that the caller cannot pass a NULL pointer; the only place where the kernel might guard is the RPC decoder, and the standard behaviour is to allow NULL for empty strings.

Thus the vulnerability is Valid.

Crux: The XDR decoder allows a NULL pointer to be passed to rpc_gss_qop_to_num, which then dereferences it in strcmp.

Grep: "rpc_gss_qop_to_num("

Verdict: VALID

CRUX: The function dereferences a NULL pointer when the XDR string decoder passes a NULL for a zero‑length QOP string; no upstream guard is present
GREP: rpc_gss_qop_to_num(

🔎 **Grep results:**

GREP `rpc_gss_qop_to_num(`:
```
include/rpc/rpcsec_gss.h:153:bool_t	rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret);
sys/rpc/rpcsec_gss.h:457:bool_t	rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret);
sys/rpc/rpcsec_gss/rpcsec_gss.c:325:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num))
sys/rpc/rpcsec_gss/rpcsec_gss.c:456:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num)) {
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:68:rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret)
lib/librpcsec_gss/rpcsec_gss.c:139:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num))
lib/librpcsec_gss/rpcsec_gss.c:240:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num)) {
lib/librpcsec_gss/rpcsec_gss_conf.c:330:rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret)
```

GREP `rpc_gss_qop_to_num(`:
```
include/rpc/rpcsec_gss.h:153:bool_t	rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret);
sys/rpc/rpcsec_gss.h:457:bool_t	rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret);
lib/librpcsec_gss/rpcsec_gss.c:139:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num))
lib/librpcsec_gss/rpcsec_gss.c:240:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num)) {
lib/librpcsec_gss/rpcsec_gss_conf.c:330:rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret)
sys/rpc/rpcsec_gss/rpcsec_gss.c:325:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num))
sys/rpc/rpcsec_gss/rpcsec_gss.c:456:		if (!rpc_gss_qop_to_num(qop, mechanism, &qop_num)) {
sys/rpc/rpcsec_gss/rpcsec_gss_conf.c:68:rpc_gss_qop_to_num(const char *qop, const char *mech, u_int *num_ret)
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The `qop` argument is obtained by decoding an XDR string from the RPC request.  In the FreeBSD kernel XDR implementation, string decoding always allocates at least one byte for the string and stores the pointer in `*stringp`; it never leaves the pointer `NULL` (even for an empty string).  Therefore `rpc_gss_qop_to_num()` will always receive a non‑NULL pointer, and the `strcmp()` call cannot dereference a NULL pointer.  No other call path to this function passes a NULL argument.  Hence the reported NULL dereference does not occur in practice.

