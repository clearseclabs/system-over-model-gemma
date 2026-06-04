# Triage T0104: Potential Use-After-Free / Double-Free Risk

- **File**: `svc_generic.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI→I]

---

## Finding

Potential Use-After-Free / Double-Free Risk

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** svc_tp_create is an initialization function processing configuration data, not untrusted network input, making any potential memory corruption non-reachable by an external attacker.

The report suggests a Use-After-Free (UAF) or Double-Free if `uaddr2taddr` returns a `netbuf` structure where `buf` points into the `netbuf` structure itself. In `svc_tp_create`, the code performs `taddr = uaddr2taddr(...)`, then `bind.addr = *taddr`, then `free(taddr, M_RPC)`, and finally `free(bind.addr.buf, M_RPC)`. If `bind.addr.buf` is a pointer into the memory of `taddr`, the second free is a UAF/Double-Free. However, `svc_tp_create` is a server-side initialization function. It is called during the setup of an RPC service, typically by a privileged process or kernel module during boot/service start. The inputs `uaddr` and `nconf` are configuration parameters, not data sent over the network by an external attacker. Even if the memory corruption were possible, it is not reachable by an external attacker triggering a request; it would require control over the server's own startup configuration, which is already a high-privilege compromise. Furthermore, `uaddr2taddr` is a standard helper; if it were implemented in a way that caused a double-free on every call to `svc_tp_create`, the system would crash consistently during service startup, making it a stability issue rather than a remote security vulnerability.

CRUX: svc_tp_create is an initialization function processing configuration data, not untrusted network input, making any potential memory corruption non-reachable by an external attacker.
GREP: uaddr2taddr

🔎 **Grep results:**

GREP `uaddr2taddr`:
```
sys/rpc/rpcb_clnt.h:84:extern struct netbuf *rpcb_uaddr2taddr(struct netconfig *, char *);
sys/rpc/rpc_com.h:75:struct netbuf *__rpc_uaddr2taddr_af(int, const char *);
sys/rpc/rpc_com.h:106:extern struct netbuf *__rpc_uaddr2taddr_af(int, const char *);
sys/rpc/rpc.h:99:struct netbuf *uaddr2taddr(const struct netconfig *, const char *);
sys/rpc/rpcb_prot.h:513:extern  struct netbuf * rpcbproc_uaddr2taddr_3(char **, CLIENT *);
sys/rpc/rpcb_prot.h:514:extern  struct netbuf * rpcbproc_uaddr2taddr_3_svc(char **, struct svc_req *);
sys/rpc/rpcb_prot.h:535:extern  struct netbuf * rpcbproc_uaddr2taddr_4(char **, CLIENT *);
sys/rpc/rpcb_prot.h:536:extern  struct netbuf * rpcbproc_uaddr2taddr_4_svc(char **, struct svc_req *);
usr.sbin/rpcbind/rpcbind.h:119:void *rpcbproc_uaddr2taddr_com(void *, struct svc_req *, SVCXPRT *, rpcvers_t);
lib/libc/rpc/rpc_com.h:64:struct netbuf *__rpc_uaddr2taddr_af(int, const char *);
include/rpc/rpcb_clnt.h:81:extern struct netbuf *rpcb_uaddr2taddr(struct netconfig *, char *);
include/rpc/rpc_com.h:64:struct netbuf *__rpc_uaddr2taddr_af(int, const char *);
include/rpc/rpc.h:88:struct netbuf *uaddr2taddr(const struct netconfig *, const char *);
sys/rpc/svc_generic.c:93:		taddr = uaddr2taddr(nconf, uaddr);
sys/rpc/rpc_generic.c:284:uaddr2taddr(const struct netconfig *nconf, const char *uaddr)
sys/rpc/rpc_generic.c:290:	return __rpc_uaddr2taddr_af(si.si_af, uaddr);
sys/rpc/rpc_generic.c:357:__rpc_uaddr2taddr_af(int af, const char *uaddr)
sys/nlm/nlm_prot_impl.c:417:			a = __rpc_uaddr2taddr_af(ss.ss_family, uaddr);
usr.sbin/rpcbind/security.c:177:	/* RPCBPROC_UADDR2TADDR */	"uaddr2taddr",
usr.sbin/rpcbind/rpcb_svc.c:73:		char *rpcbproc_uaddr2taddr_3_arg;
usr.sbin/rpcbind/rpcb_svc.c:145:		local = rpcbproc_uaddr2taddr_com;
usr.sbin/rpcbind/util.c:147:		if ((hint_nbp = uaddr2taddr(nconf, contct_uaddr)) == NULL)
usr.sbin/rpcbind/util.c:275:	serv_nbp = uaddr2taddr(nconf, serv_uaddr);
usr.sbin/rpcbind/check_bound.c:86:	na = uaddr2taddr(fdl->nconf, uaddr);
usr.sbin/rpcbind/rpcb_svc_com.c:365:rpcbproc_uaddr2taddr_com(void *arg, struct svc_req *rqstp __unused,
usr.sbin/rpcbind/rpcb_svc_com.c:376:	    ((taddr = uaddr2taddr(nconf, *uaddrp)) == NULL)) {
usr.sbin/rpcbind/rpcb_svc_com.c:877:	na = uaddr2taddr(nconf, local_uaddr);
usr.sbin/rpcbind/rpcb_svc_4.c:74:		char *rpcbproc_uaddr2taddr_4_arg;
usr.sbin/rpcbind/rpcb_svc_4.c:176:		local = rpcbproc_uaddr2taddr_com;
lib/libc/rpc/pmap_clnt.c:74:	na = uaddr2taddr(nconf, buf);
```

### Round 2: ❓ UNCERTAIN

**🎯 Crux:** Whether `uaddr2taddr` allocates `buf` separately from the `netbuf` structure.

The reported bug pattern is a potential double-free if `uaddr2taddr` allocates a `netbuf` structure and its `buf` field points into the `netbuf` structure itself. To verify this, we must examine the implementation of `uaddr2taddr` and its helper `__rpc_uaddr2taddr_af`. The provided grep results show `uaddr2taddr` is defined in `sys/rpc/rpc_generic.c` and calls `__rpc_uaddr2taddr_af`. I need to check if `__rpc_uaddr2taddr_af` performs separate allocations for the `netbuf` structure and the `buf` member. If `buf` is part of the same allocation as `netbuf`, the code in `svc_tp_create` is indeed performing a double-free. However, the security relevance depends on whether `uaddr` can be controlled by an attacker. While typically a configuration parameter, the security briefing indicates it could be sourced from a management API. More importantly, `rpcbind` uses `uaddr2taddr` in several places (e.g., `rpcb_svc_com.c`), some of which handle RPC requests. However, `svc_tp_create` specifically is an initialization function. Even if the bug exists, we must determine if it's reachable via untrusted input in the context of `svc_tp_create` or if it's a general flaw in the `uaddr2taddr` usage pattern across the system. Given the current evidence, the 'crux' is the memory layout returned by `uaddr2taddr`.

CRUX: Whether `uaddr2taddr` allocates `buf` separately from the `netbuf` structure.
GREP: __rpc_uaddr2taddr_af

🔎 **Grep results:**

GREP `__rpc_uaddr2taddr_af`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** svc_tp_create is an initialization function whose inputs are configuration-driven, meaning an external network attacker cannot reach the bug to cause meaningful harm.

The reported bug pattern exists in `svc_tp_create`: it calls `uaddr2taddr`, copies the resulting `netbuf` structure, frees the structure (`taddr`), and then later frees the buffer pointer within that structure (`bind.addr.buf`). This is a double-free if `buf` points into the `taddr` allocation. However, we must evaluate if this is a security vulnerability. 

1. **Reachability**: `svc_tp_create` is a server-side initialization function. It is used to create an RPC transport provider during the startup of an RPC service. The `uaddr` and `nconf` arguments are provided by the system administrator or a configuration file. An external network attacker cannot trigger this function via a network packet. Even if `uaddr` were sourced from a management API, the operation happens during the creation of the service, not during the handling of requests.
2. **Impact**: A double-free here would cause a kernel panic or heap corruption during service startup. While this is a reliability/stability issue, it does not provide a mechanism for an external attacker to gain unauthorized access, execute code, or leak data, as they do not control the execution flow or the input at this stage.
3. **Context**: The previous reviewers correctly identified that this is an initialization path. The security briefing mentions the input comes via 'System API/Kernel Interface'. For a bug to be VALID per the rules, an 'external attacker' must be able to trigger it. Controlling the startup configuration of the kernel's RPC stack is generally considered a pre-existing high-privilege compromise, not an attack vector.

Therefore, while the memory management pattern is fragile and potentially incorrect (code quality issue), it is not a security vulnerability.

CRUX: svc_tp_create is an initialization function whose inputs are configuration-driven, meaning an external network attacker cannot reach the bug to cause meaningful harm.
GREP: svc_tp_create

🔎 **Grep results:**

GREP `svc_tp_create`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported bug pattern—a potential double-free if `uaddr2taddr` allocates a `netbuf` and its internal buffer points to the same memory block—is a theoretical implementation risk. However, `svc_tp_create` is a server-side initialization function. Its inputs are derived from system configuration (`netconfig`) and local setup, not from untrusted network packets. Therefore, even if a memory corruption bug exists here, it is not reachable by an external attacker and does not constitute a security vulnerability.

