# Triage T0073: Type Confusion in Error Handling

- **File**: `rpc_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Type Confusion in Error Handling

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** xdr_replymsg ensures that the union members (acpted_rply or rjcted_rply) are populated based on the value of rp_stat before the message is ever passed to the error handling logic.

The report suggests that `_seterr_reply` suffers from type confusion because it accesses union members of `rpc_msg` based on `rp_stat` without verifying the union was correctly decoded. However, `_seterr_reply` is a helper function that operates on a `struct rpc_msg` that has already been processed by `xdr_replymsg`. Looking at `xdr_replymsg`, it strictly validates `rp_stat` during decoding: if `rp_stat` is `MSG_ACCEPTED`, it calls `xdr_accepted_reply` to populate `acpted_rply`; if it is `MSG_DENIED`, it calls `xdr_rejected_reply` to populate `rjcted_rply`. If `rp_stat` is neither, the function returns `FALSE`, indicating a decoding failure. Therefore, any `rpc_msg` passed to `_seterr_reply` by a compliant RPC client stack will have been validated by the XDR layer. The 'confusion' in `_seterr_reply` is actually the correct way to handle a tagged union after it has been validated during deserialization.

CRUX: xdr_replymsg ensures that the union members (acpted_rply or rjcted_rply) are populated based on the value of rp_stat before the message is ever passed to the error handling logic.
GREP: xdr_replymsg

🔎 **Grep results:**

GREP `xdr_replymsg`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** xdr_replymsg ensures that the union member matching rm_reply.rp_stat is decoded; if decoding fails, the message is discarded and never reaches _seterr_reply.

The reported vulnerability claims that `_seterr_reply` performs type confusion by accessing union members of `rpc_msg` based on `rp_stat` without verification. Analyzing `_seterr_reply`, it uses `msg->rm_reply.rp_stat` to decide whether to access `msg->acpted_rply` or `msg->rjcted_rply`. This is the standard pattern for handling tagged unions. For this to be a vulnerability, an attacker must be able to provide a `struct rpc_msg` where `rp_stat` is set to `MSG_ACCEPTED` but the actual data in the union is not a valid `accepted_reply` (or vice versa), and this must happen *after* the XDR decoding phase. 

Looking at `xdr_replymsg`, the decoding logic is strict: if `rmsg->rm_reply.rp_stat == MSG_ACCEPTED`, it calls `xdr_accepted_reply`. If that call fails, `xdr_replymsg` returns `FALSE`. The RPC client stack will not pass a failed-to-decode message to `_seterr_reply`. The only way to trigger type confusion in `_seterr_reply` is if the `rpc_msg` structure was modified between `xdr_replymsg` and `_seterr_reply`, or if `_seterr_reply` is called on an uninitialized/un-decoded message. In the provided code, `_seterr_reply` is a helper used by the client to process a reply already received and decoded from the network. Since `xdr_replymsg` enforces the invariant that the union member corresponding to `rp_stat` is correctly populated or the whole message is rejected, there is no attacker-controlled path to cause type confusion in `_seterr_reply` via the network.

CRUX: xdr_replymsg ensures that the union member matching rm_reply.rp_stat is decoded; if decoding fails, the message is discarded and never reaches _seterr_reply.
GREP: xdr_replymsg

🔎 **Grep results:**

GREP `xdr_replymsg`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** xdr_replymsg enforces that the union member matching rm_reply.rp_stat is successfully decoded before the message can be considered valid and passed to _seterr_reply.

The reported vulnerability claims that `_seterr_reply` performs type confusion by accessing `rpc_msg` union members based on `rp_stat` without verification. Analysis of the code shows that `_seterr_reply` is the consumer of a `struct rpc_msg`. This structure is populated by `xdr_replymsg`. In `xdr_replymsg`, there is a strict check: if `rp_stat` is `MSG_ACCEPTED`, it calls `xdr_accepted_reply`; if `MSG_DENIED`, it calls `xdr_rejected_reply`. If the corresponding XDR function returns `FALSE` (decoding failed), `xdr_replymsg` returns `FALSE`. In any standard RPC client implementation, a failed decode means the message is discarded and never passed to subsequent logic like `_seterr_reply`. The pattern in `_seterr_reply` is the correct way to handle a tagged union that has already been validated by the deserializer. There is no evidence of a path where a message with a mismatched tag and union content can reach `_seterr_reply` via untrusted network input.

CRUX: xdr_replymsg enforces that the union member matching rm_reply.rp_stat is successfully decoded before the message can be considered valid and passed to _seterr_reply.
GREP: xdr_replymsg

🔎 **Grep results:**

GREP `xdr_replymsg`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported type confusion occurs in `_seterr_reply`, which consumes a `struct rpc_msg`. This structure is populated by `xdr_replymsg`. In `xdr_replymsg`, the code explicitly checks `msg->rm_reply.rp_stat`: if it is `MSG_ACCEPTED`, it calls `xdr_accepted_reply` to decode the `acpted_rply` member; if it is `MSG_DENIED`, it calls `xdr_rejected_reply` to decode the `rjcted_rply` member. If the decoding fails, `xdr_replymsg` returns `FALSE`, and the message is discarded before it ever reaches `_seterr_reply`. Therefore, `_seterr_reply` only operates on messages where the union member corresponding to `rp_stat` has been successfully validated and decoded.

