# Triage T0070: Potential Arbitrary Code Execution via Function Pointer Dereference

- **File**: `rpc_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Potential Arbitrary Code Execution via Function Pointer Dereference

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The function pointer `ar->ar_results.proc` is not decoded from the XDR stream; it is pre-set by the internal RPC client state to determine how to decode the results.

The vulnerability report claims that `ar->ar_results.proc` is a function pointer that can be hijacked by untrusted XDR data. Looking at `xdr_accepted_reply`, the code does indeed dereference `ar->ar_results.proc` if `ar->ar_stat == SUCCESS`. However, we must determine if `ar->ar_results.proc` is ever populated from the `xdrs` stream (the untrusted input). 

Tracing the data flow in `xdr_accepted_reply`:
1. `xdr_opaque_auth(xdrs, &(ar->ar_verf))` is called.
2. `xdr_enum(xdrs, (enum_t *) par_stat)` is called to populate `ar->ar_stat` from the stream.
3. If `ar->ar_stat == SUCCESS`, the code checks `if (ar->ar_results.proc != (xdrproc_t) xdr_void)`. 
4. If it is not `xdr_void`, it calls `(*(ar->ar_results.proc))(xdrs, ar->ar_results.where)`.

Crucially, there is NO call to any XDR decoding function (like `xdr_uint32_t` or `xdr_bytes`) that writes to `ar->ar_results.proc` or `ar->ar_results.where`. The `ar` structure is passed into `xdr_accepted_reply` from `xdr_replymsg` via `&rmsg->acpted_rply`. The `rpc_msg` structure is typically allocated on the stack or heap by the RPC client. In the RPC protocol, when a client receives a 'SUCCESS' reply, the client already knows which procedure it called; the `proc` pointer is set by the client-side dispatcher *before* the reply is decoded so that the XDR decoder knows which function to use to deserialize the results specific to that procedure. 

The attacker controls the stream (`xdrs`), but the function pointer `ar->ar_results.proc` is a piece of internal state managed by the client's RPC runtime to handle the response. Since the pointer is not read from the network, the attacker cannot hijack the control flow.

CRUX: The function pointer `ar->ar_results.proc` is not decoded from the XDR stream; it is pre-set by the internal RPC client state to determine how to decode the results.
GREP: xdr_accepted_reply

🔎 **Grep results:**

GREP `xdr_accepted_reply`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The function pointer `ar->ar_results.proc` is not decoded from the XDR stream (untrusted input); it is pre-populated by the internal client state.

The vulnerability report claims that an attacker can hijack control flow via `ar->ar_results.proc` in `xdr_accepted_reply`. I have analyzed the code in `rpc_prot.c`. In `xdr_accepted_reply`, the function pointer `ar->ar_results.proc` is indeed dereferenced and called if `ar->ar_stat == SUCCESS`. However, for this to be a vulnerability, the pointer itself must be controllable by the attacker. Looking at the data flow in `xdr_accepted_reply`: the code decodes `ar->ar_verf` and `ar->ar_stat` from the `xdrs` stream, but it NEVER decodes `ar->ar_results.proc` or `ar->ar_results.where` from the stream. These fields must be populated by the caller (the RPC client) before calling the XDR decoding routine. In the RPC protocol, the client knows which procedure it called and sets the appropriate decoding function in the `rpc_msg` structure to handle the returning result. Since the function pointer is internal state and not read from the untrusted network stream, an external attacker cannot overwrite it to redirect execution.

CRUX: The function pointer `ar->ar_results.proc` is not decoded from the XDR stream (untrusted input); it is pre-populated by the internal client state.
GREP: xdr_accepted_reply

🔎 **Grep results:**

GREP `xdr_accepted_reply`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The function pointer `ar->ar_results.proc` is not read from the XDR stream; it is an internal state variable set by the RPC client to determine which procedure-specific decoder to use.

The vulnerability scanner flags the dereference of `ar->ar_results.proc` in `xdr_accepted_reply` as a potential arbitrary code execution. To be valid, an attacker must be able to control the value of this function pointer. In `xdr_accepted_reply`, the function decodes `ar->ar_verf` and `ar->ar_stat` from the `xdrs` stream. If `ar->ar_stat` is `SUCCESS`, it calls the function pointer `ar->ar_results.proc`. However, there is no code in `xdr_accepted_reply` or its caller `xdr_replymsg` that decodes the `proc` pointer or the `where` pointer from the network stream. These fields are part of the `accepted_reply` structure, which is embedded in `rpc_msg`. In the RPC protocol, the client sets the `proc` pointer (the decoding routine for the specific RPC call) based on the request it previously sent *before* calling the decoder on the response. Since the pointer is internal state and not sourced from the untrusted XDR stream, the attacker cannot hijack it.

CRUX: The function pointer `ar->ar_results.proc` is not read from the XDR stream; it is an internal state variable set by the RPC client to determine which procedure-specific decoder to use.
GREP: xdr_accepted_reply

🔎 **Grep results:**

GREP `xdr_accepted_reply`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability claim is that an attacker can control the function pointer `ar->ar_results.proc` via XDR input. However, analyzing `xdr_accepted_reply`, the only fields decoded from the `xdrs` stream are `ar->ar_verf` (via `xdr_opaque_auth`) and `ar->ar_stat` (via `xdr_enum`). The function pointer `ar->ar_results.proc` is never read from the input stream; it is a member of the `accepted_reply` structure that must be pre-populated by the RPC client's internal state to determine the appropriate decoder for the expected result. Since the pointer is not derived from untrusted input, it cannot be hijacked by an attacker.

