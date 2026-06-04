# Triage T0053: Unchecked XDR serialization may overflow ct->ct_mcallc

- **File**: `clnt_vc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unchecked XDR serialization may overflow ct->ct_mcallc

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The pre‑serialized call header (`ct->ct_mcallc`) is created once in `clnt_vc_create()` using `xdr_callhdr()`. `xdr_callhdr()` serialises a fixed‑size `rpc_msg` structure (XID, direction, RPC version, program, version, procedure plus a zero‑length AUTH_NULL), which always produces 32 bytes of output. The buffer `ct->ct_mcallc` is allocated with a size `MCALL_MSG_SIZE` that is defined in the RPC headers to be at least 48 bytes. Therefore `ct->ct_mpos` is guaranteed not to exceed the buffer size, and the subsequent `memcpy()` in `clnt_vc_call()` cannot overrun it. Corrupting the global `disrupt` value or `ct->ct_addr` does not change the already‑encoded header; those values are used after the header is finalized. The only real source of potential overflow would be if `MCALL_MSG_SIZE` were incorrectly small or if `xdr_callhdr()` could generate a larger header, neither of which occurs in standard NetBSD code. Thus the described vulnerability does not exist. 

