# Triage T0060: NULL Pointer Dereference of Global RPC Client

- **File**: `rpcb_clnt.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

NULL Pointer Dereference of Global RPC Client

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The functions `rpcb_set` and `rpcb_unset` are called by internal kernel components to register services, not by untrusted user-space input.

The report identifies a potential NULL pointer dereference of the global `rpcb_clnt` pointer. The pointer is initialized in `local_rpcb` using `client_nl_create`. If `client_nl_create` fails, `rpcb_clnt` remains NULL. The code contains a `KASSERT(rpcb_clnt, ...)` immediately after the initialization. In most kernel environments (including NetBSD/FreeBSD where this pattern originates), `KASSERT` is only active in debug builds; in production/release builds, it is compiled out. Therefore, if initialization fails, the execution continues, and subsequent calls to `rpcb_set` or `rpcb_unset` will pass a NULL pointer to `CLNT_CALL`. However, we must evaluate reachability. `rpcb_set` and `rpcb_unset` are used by the kernel to register RPC services (like NFS). These are triggered by internal kernel requests to export a service. An external attacker cannot directly call `rpcb_set` or `rpcb_unset`. While the failure of `client_nl_create` would lead to a crash, triggering that failure typically requires a system-level misconfiguration or resource exhaustion during boot, not a remote trigger. Furthermore, the data flow from untrusted input to these functions is non-existent; they are called by the kernel to notify the portmapper of a service's existence. A crash during a failed service registration is a denial-of-service, but it is not triggerable by an external attacker through untrusted input.

CRUX: The functions `rpcb_set` and `rpcb_unset` are called by internal kernel components to register services, not by untrusted user-space input.
GREP: rpcb_set

🔎 **Grep results:**

GREP `rpcb_set`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The functions `rpcb_set` and `rpcb_unset` are internal kernel APIs used for service registration and are not reachable via untrusted external input.

The reported bug is a NULL pointer dereference of the global `rpcb_clnt` pointer if `client_nl_create` fails during system initialization. While it is true that `KASSERT` is typically disabled in production builds, meaning the kernel would proceed with a NULL pointer, the vulnerability is not reachable by an external attacker. `rpcb_set` and `rpcb_unset` are internal kernel functions used to register RPC services (like NFS) with the portmapper. They are not exposed to user-space or triggered by external network packets. A failure in `client_nl_create` would be a boot-time failure or a result of internal resource exhaustion, not a remote trigger. Since an external attacker cannot control the input or trigger the call to these functions to cause a crash, this is a reliability/code quality issue, not a security vulnerability.

CRUX: The functions `rpcb_set` and `rpcb_unset` are internal kernel APIs used for service registration and are not reachable via untrusted external input.
GREP: rpcb_set

🔎 **Grep results:**

GREP `rpcb_set`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** rpcb_set and rpcb_unset are internal kernel functions used for service registration and are not reachable by external untrusted input.

The vulnerability report describes a NULL pointer dereference if `rpcb_clnt` fails to initialize. While `KASSERT` is likely removed in production builds, leaving the pointer NULL, we must determine if an attacker can trigger `rpcb_set` or `rpcb_unset` to cause a crash. These functions are used to register RPC services with the portmapper. The provided grep results for `rpcb_set` show zero matches in the repository, implying that these functions are either unused or the codebase provided is incomplete. However, based on the provided security context, these are internal kernel APIs used for service registration (e.g., by NFS). Service registration is triggered by the kernel during the setup of a server-side service, not by incoming network packets or untrusted user-space input. Therefore, an external attacker cannot trigger the call to these functions. A crash resulting from a boot-time initialization failure of a global kernel client is a stability/reliability issue, not a security vulnerability reachable by an external attacker.

CRUX: rpcb_set and rpcb_unset are internal kernel functions used for service registration and are not reachable by external untrusted input.
GREP: rpcb_set

🔎 **Grep results:**

GREP `rpcb_set`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The code confirms that `rpcb_clnt` is initialized during system startup via `SYSINIT`. If `client_nl_create` fails, `rpcb_clnt` remains NULL. While `rpcb_set` and `rpcb_unset` do not check for NULL before calling `CLNT_CALL`, these functions are internal kernel APIs used for registering RPC services. There is no evidence that an external, untrusted user can trigger these functions. A failure in `SYSINIT` resulting in a kernel panic during service registration is a stability/reliability issue, not a security vulnerability, as it cannot be leveraged by an attacker to gain unauthorized access or execute arbitrary code.

