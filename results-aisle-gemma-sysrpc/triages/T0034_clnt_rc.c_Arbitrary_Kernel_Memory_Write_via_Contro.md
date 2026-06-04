# Triage T0034: Arbitrary Kernel Memory Write via Control Interface

- **File**: `clnt_rc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Arbitrary Kernel Memory Write via Control Interface

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The `info` pointer is provided by internal kernel callers, not by untrusted user-space input.

The reported vulnerability describes an arbitrary kernel memory write in `clnt_reconnect_control` because the `info` pointer is used as a destination for writes (e.g., in `CLGET_TIMEOUT`, `CLGET_VERS`). While it is true that `info` is dereferenced and written to, `clnt_reconnect_control` is an internal kernel API used to configure RPC client handles. In the provided code, the `CLIENT` handle is created via `clnt_reconnect_create`, which allocates memory from the kernel heap (`mem_alloc`). There is no evidence in the provided code or security context that an untrusted user-space attacker can pass an arbitrary pointer as the `info` argument to `clnt_reconnect_control`. The function is used by other kernel components to manage the lifecycle and configuration of RPC clients. Since the `info` pointer originates from trusted kernel callers, this is not a security vulnerability.

CRUX: The `info` pointer is provided by internal kernel callers, not by untrusted user-space input.
GREP: clnt_reconnect_control

🔎 **Grep results:**

GREP `clnt_reconnect_control`:
```
sys/rpc/clnt_rc.c:57:static bool_t clnt_reconnect_control(CLIENT *, u_int, void *);
sys/rpc/clnt_rc.c:68:	.cl_control =	clnt_reconnect_control
sys/rpc/clnt_rc.c:422:clnt_reconnect_control(CLIENT *cl, u_int request, void *info)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `info` pointer is passed by internal kernel callers to the `cl_control` operation; there is no path for an external attacker to control this pointer.

The reported vulnerability is a 'Write-What-Where' pattern: if an attacker controls the `info` pointer in `clnt_reconnect_control`, they can write kernel data to an arbitrary address (e.g., via `CLGET_VERS` writing a 4-byte version number to `info`). However, `clnt_reconnect_control` is a function pointer assigned to the `cl_control` field of a `CLIENT` structure. In the kernel RPC implementation, `CLIENT` structures are internal kernel objects created via `clnt_reconnect_create`. The `cl_control` operation is intended to be called by other kernel modules or the RPC subsystem to configure the client. There is no mechanism in the provided code or the general architecture of kernel RPC for a user-space process to pass an arbitrary pointer directly into this internal control interface. The `info` pointer is provided by the kernel caller, not by an untrusted network packet or a direct system call argument that bypasses validation. Therefore, it is not attacker-reachable.

CRUX: The `info` pointer is passed by internal kernel callers to the `cl_control` operation; there is no path for an external attacker to control this pointer.
GREP: clnt_reconnect_control

🔎 **Grep results:**

GREP `clnt_reconnect_control`:
```
sys/rpc/clnt_rc.c:57:static bool_t clnt_reconnect_control(CLIENT *, u_int, void *);
sys/rpc/clnt_rc.c:68:	.cl_control =	clnt_reconnect_control
sys/rpc/clnt_rc.c:422:clnt_reconnect_control(CLIENT *cl, u_int request, void *info)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The `info` pointer is passed by internal kernel callers to the `cl_control` operation; there is no path for an external attacker to control this pointer.

The reported vulnerability identifies a 'Write-What-Where' pattern in `clnt_reconnect_control` where the `info` pointer is used as a destination for writes during 'GET' operations (e.g., `CLGET_VERS`). However, for this to be a security vulnerability, an attacker must be able to control the `info` pointer. In this codebase, `clnt_reconnect_control` is a static function assigned to the `cl_control` callback of a `CLIENT` handle created via `clnt_reconnect_create`. This `CLIENT` handle is an internal kernel object. The `cl_control` interface is used by the kernel to configure these handles. There is no evidence of a system call or network-facing interface that allows a user-space attacker to specify the `info` pointer passed to this function. The data flow for `info` originates from internal kernel callers who provide the memory buffer they wish to be populated. Since the attacker cannot control the destination address (`info`), the 'arbitrary write' is not reachable by an untrusted actor.

CRUX: The `info` pointer is passed by internal kernel callers to the `cl_control` operation; there is no path for an external attacker to control this pointer.
GREP: clnt_reconnect_control

🔎 **Grep results:**

GREP `clnt_reconnect_control`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The function `clnt_reconnect_control` does perform unchecked writes to the `info` pointer. However, it is a static internal kernel function assigned as a callback (`cl_control`) for a `CLIENT` handle created via `clnt_reconnect_create`. These handles and their associated control operations are used internally by the kernel to manage RPC connections. There is no evidence of any system call or user-space interface that allows an external attacker to provide a controlled `info` pointer to this function. Without a path from untrusted input to the function arguments, this is not a security vulnerability.

