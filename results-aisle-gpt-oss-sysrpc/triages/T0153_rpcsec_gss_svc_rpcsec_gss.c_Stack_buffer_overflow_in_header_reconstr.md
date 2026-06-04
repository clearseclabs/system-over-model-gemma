# Triage T0153: Stack buffer overflow in header reconstruction (svc_rpc_gss_validate)

- **File**: `rpcsec_gss/svc_rpcsec_gss.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 33% [UVU]

---

## Finding

Stack buffer overflow in header reconstruction (svc_rpc_gss_validate)

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ✅ VALID

**🎯 Crux:** Overflow due to memcpy of unbounded oa->oa_length into a 128‑byte stack buffer rpchdr in svc_rpc_gss_validate.

The bug is the stack‑based overflow in svc_rpc_gss_validate: the 32‑int array rpchdr (128 bytes) is unpacked from the RPC header and then the cred’s opaque base is copied into it with memcpy((caddr_t)buf, oa->oa_base, oa->oa_length).  The code does not limit oa_length – only checks that it is non‑zero.  An attacker controls oa_length via the network packet’s rpc_cred field, and can set it arbitrarily large.  No defensive check (e.g., bound on oa_len, MAXAUTH, or RPC message size) is performed before this call.  Therefore the overflow is reachable and can corrupt the stack, leading to possible crash or code execution.  The pattern exists, the input is external and untrusted, and no adequate defense was found after inspecting the code.  Consequently the vulnerability is valid.

CRUX: Overflow due to memcpy of unbounded oa->oa_length into a 128‑byte stack buffer rpchdr in svc_rpc_gss_validate.
GREP: oa->oa_length

🔎 **Grep results:**

GREP `oa->oa_length`:
```
usr.bin/genl/parser_rpc.c:98:	oa->oa_length = (u_int)IXDR_GET_U_INT32(buf);
usr.bin/genl/parser_rpc.c:99:	if (oa->oa_length) {
usr.bin/genl/parser_rpc.c:101:		    oa->oa_flavor, oa->oa_length);
usr.bin/genl/parser_rpc.c:104:		if (oa->oa_length > MAX_AUTH_BYTES) {
usr.bin/genl/parser_rpc.c:109:			    mem_alloc(oa->oa_length);
usr.bin/genl/parser_rpc.c:113:		buf = XDR_INLINE(&xdrs, RNDUP(oa->oa_length));
usr.bin/genl/parser_rpc.c:116:			    oa->oa_length) == FALSE) {
usr.bin/genl/parser_rpc.c:121:			    oa->oa_length);
usr.bin/genl/parser_rpc.c:129:		    xdr_u_int(&xdrs, &oa->oa_length) == FALSE)
usr.bin/genl/parser_rpc.c:133:		oa->oa_length = (u_int)IXDR_GET_U_INT32(buf);
usr.bin/genl/parser_rpc.c:135:	if (oa->oa_length) {
usr.bin/genl/parser_rpc.c:137:		    oa->oa_flavor, oa->oa_length);
usr.bin/genl/parser_rpc.c:140:		if (oa->oa_length > MAX_AUTH_BYTES) {
usr.bin/genl/parser_rpc.c:145:			    mem_alloc(oa->oa_length);
usr.bin/genl/parser_rpc.c:149:		buf = XDR_INLINE(&xdrs, RNDUP(oa->oa_length));
usr.bin/genl/parser_rpc.c:152:			    oa->oa_length) == FALSE) {
usr.bin/genl/parser_rpc.c:157:			    oa->oa_length);
lib/librpcsec_gss/svc_rpcsec_gss.c:771:	IXDR_PUT_LONG(buf, oa->oa_length);
lib/librpcsec_gss/svc_rpcsec_gss.c:772:	if (oa->oa_length) {
lib/librpcsec_gss/svc_rpcsec_gss.c:773:		memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
lib/librpcsec_gss/svc_rpcsec_gss.c:774:		buf += RNDUP(oa->oa_length) / sizeof(int32_t);
sys/rpc/rpc_callmsg.c:83:			IXDR_PUT_INT32(buf, oa->oa_length);
sys/rpc/rpc_callmsg.c:84:			if (oa->oa_length) {
sys/rpc/rpc_callmsg.c:85:				memcpy(buf, oa->oa_base, oa->oa_length);
sys/rpc/rpc_callmsg.c:86:				buf += RNDUP(oa->oa_length) / sizeof (int32_t);
sys/rpc/rpc_callmsg.c:90:			IXDR_PUT_INT32(buf, oa->oa_length);
sys/rpc/rpc_callmsg.c:91:			if (oa->oa_length) {
sys/rpc/rpc_callmsg.c:92:				memcpy(buf, oa->oa_base, oa->oa_length);
sys/rpc/rpc_callmsg.c:94:				buf += RNDUP(oa->oa_length) / sizeof (int32_t);
sys/rpc/rpc_callmsg.c:117:			oa->oa_length = (u_int)IXDR_GET_UINT32(buf);
```

### Round 3: ❓ UNCERTAIN



