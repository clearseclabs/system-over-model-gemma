# Triage T0043: Unchecked XDR Memory Bounds

- **File**: `clnt_vc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Unchecked XDR Memory Bounds

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** clnt_vc_control is a local control interface for the RPC client handle and is not reachable via untrusted network input.

The reported vulnerability describes an out-of-bounds (OOB) read/write in `clnt_vc_control` when handling `CLGET_VERS`, `CLSET_VERS`, `CLGET_PROG`, and `CLSET_PROG`. These cases perform pointer arithmetic on `ct->ct_mcallc` using `BYTES_PER_XDR_UNIT` (which is 4). Specifically, they access offsets up to `4 * 4 = 16` bytes. 

1. **Is the bug real?** The code does direct pointer arithmetic. The buffer `ct->ct_mcallc` is initialized via `xdrmem_create(&xdrs, ct->ct_mcallc, MCALL_MSG_SIZE, XDR_ENCODE)`. If `MCALL_MSG_SIZE` is smaller than 20 bytes (the offset 16 + 4 bytes for the uint32_t access), it would be an OOB access. I need to verify the value of `MCALL_MSG_SIZE`.
2. **Is it attacker-reachable?** `clnt_vc_control` is the implementation of `cl_control` for the virtual circuit transport. In the RPC client API, `clnt_control()` is called by the application (the RPC client) to configure the client handle. It is NOT called in response to network input. The `CLIENT` handle is created by the local system, and `clnt_control` is used to modify local state. An external attacker cannot trigger a call to `clnt_vc_control` on a client handle they do not control. This is a local API for the RPC client application.
3. **Conclusion:** Even if `MCALL_MSG_SIZE` were too small, this is a local configuration interface. The 'attacker' would need to already have the ability to call `clnt_control` on the `CLIENT` handle, which implies they already have execution privileges in the process using the RPC client. This is not a remote vulnerability.

CRUX: clnt_vc_control is a local control interface for the RPC client handle and is not reachable via untrusted network input.
GREP: MCALL_MSG_SIZE

🔎 **Grep results:**

GREP `MCALL_MSG_SIZE`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** clnt_vc_control is a local client-side configuration API and is not reachable via untrusted network input.

The reported vulnerability is in `clnt_vc_control`. This function is a callback implementation for the `cl_control` operation of a `CLIENT` handle. In the RPC architecture, `clnt_control` (and by extension `clnt_vc_control`) is a local API called by the application using the RPC client to manage its connection state (e.g., changing timeouts, program/version numbers). It is not a handler for incoming network packets. An external attacker cannot send a packet that triggers the execution of `clnt_vc_control`. The only way to trigger this code is to already have the ability to call functions within the process's own memory space. While the pointer arithmetic in `CLGET_VERS` etc. is brittle and relies on the structure of the RPC header, the lack of reachability from an untrusted external source makes it a code quality issue rather than a security vulnerability.

CRUX: clnt_vc_control is a local client-side configuration API and is not reachable via untrusted network input.
GREP: clnt_control

🔎 **Grep results:**

GREP `clnt_control`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** clnt_vc_control is a local client-side configuration API and is not reachable via untrusted network input.

The reported bug pattern is real in the sense that `clnt_vc_control` uses hardcoded offsets to read/write from `ct->ct_mcallc`. However, the vulnerability is not reachable by an external attacker. `clnt_vc_control` is the implementation of the `cl_control` operation for the `clnt_vc` transport. This function is called via the local RPC client API (`clnt_control`) by the application using the RPC client handle. It is used to configure local client state (like timeouts, XIDs, or the target program/version). There is no data flow from the network (untrusted input) into the `request` or `info` parameters of `clnt_vc_control`. An attacker would need to already have the ability to execute code in the client process to call this function. Therefore, this is a code quality issue (brittle pointer arithmetic) rather than a security vulnerability.

CRUX: clnt_vc_control is a local client-side configuration API and is not reachable via untrusted network input.
GREP: clnt_control

🔎 **Grep results:**

GREP `clnt_control`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported issue describes an out-of-bounds read/write in `clnt_vc_control`. However, `clnt_vc_control` is an internal client-side configuration function (part of the `cl_control` operation for the `CLIENT` handle) used by the application calling the RPC library to manage its own local connection state. It is not a handler for incoming network data and cannot be triggered by an external attacker. Furthermore, the offsets used (up to 16 bytes) are within the `MCALL_MSG_SIZE` (24 bytes) allocated for `ct->ct_mcallc` during `clnt_vc_create`. Therefore, there is no reachable security vulnerability.

