# Triage T0035: Environment variable injection via NETPATH

- **File**: `netconfig.h`
- **Verdict**: VALID
- **Confidence**: 75% [VVI→V]

---

## Finding

Environment variable injection via NETPATH

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The existence of `setnetpath` and `getnetpath` confirms the API supports loading configuration from the `NETPATH` environment variable, which is a classic injection vector in privileged programs.

The vulnerability report claims that the `NETPATH` environment variable can be used to force the application to parse a malicious configuration file. In the provided header `netconfig.h`, there are explicit functions `setnetpath` and `getnetpath` specifically designed to handle network configuration paths provided via the environment. In a privileged context (e.g., a setuid binary), if the application calls `setnetpath` or `getnetpath` without clearing the environment or validating the paths, an attacker can point the configuration lookup to a file they control. This allows the attacker to inject arbitrary network device paths or protocol mappings into the application's logic, which can lead to redirection of network traffic or other privilege escalation vectors depending on how the resulting `struct netconfig` is used.

CRUX: The existence of `setnetpath` and `getnetpath` confirms the API supports loading configuration from the `NETPATH` environment variable, which is a classic injection vector in privileged programs.
GREP: setnetpath

🔎 **Grep results:**

GREP `setnetpath`:
```
include/netconfig.h:117:void *setnetpath(void);
sys/rpc/netconfig.h:88:void *setnetpath(void);
lib/libc/rpc/rpc_generic.c:295:		if (!(handle->nhandle = setnetpath()))
lib/libc/rpc/getnetpath.c:70: * A call to setnetpath() establishes a NETPATH "session".  setnetpath()
lib/libc/rpc/getnetpath.c:74: * to setnetpath()).
lib/libc/rpc/getnetpath.c:75: * If setnetpath() is unable to establish a session (due to lack of memory
lib/libc/rpc/getnetpath.c:81:setnetpath(void)
lib/libc/rpc/getnetpath.c:129: * NULL and sets errno in case of an error (e.g., setnetpath was not called
lib/libc/rpc/getnetpath.c:192: * (e.g. if setnetpath() was not called previously.
lib/libc/rpc/getnetconfig.c:143: * (Handles are used to allow for nested calls to setnetpath()).
```

### Round 2: ✅ VALID

**🎯 Crux:** The RPC library calls `setnetpath()`, which reads the `NETPATH` environment variable to locate configuration files without any evident sanitization or restriction to trusted paths, allowing an attacker to influence the networking configuration of a privileged process.

The vulnerability report identifies a classic environment variable injection pattern where `NETPATH` is used to determine which configuration files are parsed. The grep results confirm that `setnetpath()` is called within `lib/libc/rpc/rpc_generic.c`. In the context of RPC (Remote Procedure Call) libraries, these functions are often used by system daemons or setuid utilities. If a privileged process calls `setnetpath()`, it will read the `NETPATH` environment variable to locate configuration files. An attacker who can control the environment variables of a privileged process (e.g., via a setuid binary) can point `NETPATH` to a file they control. By providing a malicious netconfig file, the attacker can manipulate the `nc_device` or `nc_lookups` fields, potentially redirecting network traffic to a malicious device or forcing the loading of a malicious shared library (via `nc_lookups`). This is a standard security flaw in privileged applications that trust environment variables.

CRUX: The RPC library calls `setnetpath()`, which reads the `NETPATH` environment variable to locate configuration files without any evident sanitization or restriction to trusted paths, allowing an attacker to influence the networking configuration of a privileged process.
GREP: setnetpath

🔎 **Grep results:**

GREP `setnetpath`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The grep for 'setnetpath' returned no matches in the repository, meaning the function is not called in the implementation code, rendering the injection path unreachable.

The vulnerability report claims that `NETPATH` can be used to inject malicious configuration files into a privileged context. The header `netconfig.h` defines `setnetpath()`, and previous reviewers claimed this function is used in `lib/libc/rpc/rpc_generic.c`. However, the provided GREP results for `setnetpath` returned '(no matches in repo)'. If the function `setnetpath` is not actually implemented or called within the codebase being analyzed, the bug pattern cannot be real in the current context. Even if the header defines the prototype, the lack of implementation or calls to it in the actual source code means there is no reachable code path for an attacker to trigger this injection. Furthermore, the report specifies 'Environment variable injection', but for this to be a security vulnerability, it must occur in a privileged context (like a setuid binary). There is no evidence provided that the RPC library is used in a setuid binary that fails to sanitize its environment.

CRUX: The grep for 'setnetpath' returned no matches in the repository, meaning the function is not called in the implementation code, rendering the injection path unreachable.
GREP: setnetpath

🔎 **Grep results:**

GREP `setnetpath`:
```
(no matches in repo)
```

### Round 4: ✅ VALID

[ARBITER] The evidence from Round 1 provides explicit grep matches proving that `setnetpath` is defined in `netconfig.h`, implemented in `getnetpath.c`, and called in `rpc_generic.c`. The Round 3 'no matches' result is contradictory to the provided evidence in Round 1 and the actual content of `netconfig.h`. The function `setnetpath` is designed to establish a session based on the `NETPATH` environment variable; if called in a privileged context (common for RPC libraries), it allows an attacker to redirect configuration parsing to a malicious file.

