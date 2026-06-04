# Triage T0103: Null Pointer Dereference in `svc_tp_create`

- **File**: `svc_generic.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Null Pointer Dereference in `svc_tp_create`

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** svc_tp_create is a privileged initialization function; its inputs are not reachable by an untrusted external attacker.

The bug pattern is real: `svc_tp_create` calls `uaddr2taddr(nconf, uaddr)` and immediately dereferences the result with `bind.addr = *taddr` without checking if `taddr` is NULL. However, we must determine if an external attacker can trigger this. The function `svc_tp_create` is a server-side initialization routine used to create and register an RPC service. In a kernel-based RPC implementation (as indicated by `M_RPC`, `curthread`, and `solisten`), this function is called during the setup of a system service. The parameters `prognum`, `versnum`, and `uaddr` are typically hardcoded in the service driver or read from a privileged system configuration file at boot/load time. An unprivileged external attacker cannot call `svc_tp_create` directly nor can they typically influence the `uaddr` string passed to it. Since this is a setup-time failure that would require administrative privileges to trigger (by misconfiguring the service), it is a code quality issue/reliability bug rather than a security vulnerability.

CRUX: svc_tp_create is a privileged initialization function; its inputs are not reachable by an untrusted external attacker.
GREP: svc_tp_create

🔎 **Grep results:**

GREP `svc_tp_create`:
```
include/rpc/svc.h:393:extern SVCXPRT *svc_tp_create(void (*)(struct svc_req *, SVCXPRT *),
sys/rpc/svc.h:582:extern SVCXPRT *svc_tp_create(SVCPOOL *, void (*)(struct svc_req *, SVCXPRT *),
lib/libc/rpc/svc_generic.c:114:			xprt = svc_tp_create(dispatch, prognum, versnum, nconf);
lib/libc/rpc/svc_generic.c:150:svc_tp_create(void (*dispatch)(struct svc_req *, SVCXPRT *),
lib/libc/rpc/svc_generic.c:157:	"svc_tp_create: invalid netconfig structure for prog %u vers %u",
lib/libc/rpc/svc_generic.c:169:		"svc_tp_create: Could not register prog %u vers %u on %s",
sys/rpc/svc_generic.c:73:svc_tp_create(
sys/rpc/svc_generic.c:88:	"svc_tp_create: invalid netconfig structure for prog %u vers %u\n",
sys/rpc/svc_generic.c:110:		"svc_tp_create: Could not register prog %u vers %u on %s\n",
sys/nlm/nlm_prot_impl.c:1488:				xprts[j] = svc_tp_create(pool, dispatchers[i],
```

### Round 2: ❌ INVALID

**🎯 Crux:** svc_tp_create is a kernel-level initialization function whose inputs are not controllable by an external attacker.

The bug pattern is real: `svc_tp_create` dereferences the return value of `uaddr2taddr` without a NULL check. However, to determine if this is a security vulnerability, we must examine the reachability. `svc_tp_create` is used to initialize RPC services. The grep results show it is called in `sys/rpc/svc_generic.c` and `sys/nlm/nlm_prot_impl.c`. These are kernel-side (indicated by `M_RPC` and `curthread` in the source) initialization routines for system services (like NFS/NLM). The `uaddr` parameter in these contexts is either NULL (defaulting to anonymous bind) or derived from kernel-level network configuration. There is no path for an unprivileged external attacker to provide a string to `uaddr` to trigger this crash. This is a reliability issue in the system's startup/configuration logic, not a security vulnerability.

CRUX: svc_tp_create is a kernel-level initialization function whose inputs are not controllable by an external attacker.
GREP: svc_tp_create

🔎 **Grep results:**

GREP `svc_tp_create`:
```
include/rpc/svc.h:393:extern SVCXPRT *svc_tp_create(void (*)(struct svc_req *, SVCXPRT *),
sys/rpc/svc.h:582:extern SVCXPRT *svc_tp_create(SVCPOOL *, void (*)(struct svc_req *, SVCXPRT *),
lib/libc/rpc/svc_generic.c:114:			xprt = svc_tp_create(dispatch, prognum, versnum, nconf);
lib/libc/rpc/svc_generic.c:150:svc_tp_create(void (*dispatch)(struct svc_req *, SVCXPRT *),
lib/libc/rpc/svc_generic.c:157:	"svc_tp_create: invalid netconfig structure for prog %u vers %u",
lib/libc/rpc/svc_generic.c:169:		"svc_tp_create: Could not register prog %u vers %u on %s",
sys/rpc/svc_generic.c:73:svc_tp_create(
sys/rpc/svc_generic.c:88:	"svc_tp_create: invalid netconfig structure for prog %u vers %u\n",
sys/rpc/svc_generic.c:110:		"svc_tp_create: Could not register prog %u vers %u on %s\n",
sys/nlm/nlm_prot_impl.c:1488:				xprts[j] = svc_tp_create(pool, dispatchers[i],
```

### Round 3: ❌ INVALID

**🎯 Crux:** svc_tp_create is a kernel-level initialization function whose inputs are not reachable by an unprivileged external attacker.

The bug pattern is real: `svc_tp_create` calls `uaddr2taddr(nconf, uaddr)` and immediately dereferences the result (`bind.addr = *taddr`) without checking for NULL. However, the security relevance depends on whether `uaddr` can be controlled by an untrusted attacker. The provided code uses kernel-specific types and functions (`M_RPC`, `curthread`, `solisten`), and the grep results show it is called in `sys/rpc/svc_generic.c` and `sys/nlm/nlm_prot_impl.c`. These are kernel-space initialization routines for RPC services (like NLM). In this context, `uaddr` is typically a configuration string used during the boot or module-loading phase of the kernel. There is no evidence of a syscall, ioctl, or network-facing API that allows an unprivileged user to pass an arbitrary string to `svc_tp_create`. Because the trigger requires the ability to configure kernel-level RPC service bindings—a privileged operation—this is a reliability/code quality issue, not a security vulnerability.

CRUX: svc_tp_create is a kernel-level initialization function whose inputs are not reachable by an unprivileged external attacker.
GREP: svc_tp_create

🔎 **Grep results:**

GREP `svc_tp_create`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] While a Null Pointer Dereference exists in `svc_tp_create` (the result of `uaddr2taddr` is dereferenced without a NULL check), the function is used for server-side initialization of RPC services in kernel space. The inputs, such as `uaddr` and `nconf`, are provided by the system configuration or kernel setup routines, not by an untrusted external attacker. Since the vulnerability is not reachable by an unprivileged user, it is a bug but not a security vulnerability.

