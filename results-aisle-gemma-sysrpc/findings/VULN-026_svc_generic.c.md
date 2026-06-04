# VULN-026: indings

- **File**: `svc_generic.c`
- **Confidence**: 75% [VVI→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

indings

### Findings

```json
[
  {
    "severity": "critical",
    "title": "Kernel Panic via NULL Pointer Dereference",
    "function": "svc_tp_create()",
    "description": "The return value of uaddr2taddr() is not checked for NULL before being dereferenced. A malformed uaddr string causing uaddr2taddr to fail will result in a kernel panic."
  },
  {
    "severity": "medium",
    "title": "Potential Kernel Memory Leak",
    "function": "svc_tli_create()",
    "description": "xprt->xp_netid is allocated via strdup() at the end of the function. If the SVCXPRT cleanup routine does not specifically free this member, it results in a memory leak."
  },
  {
    "severity": "low",
    "title": "Unsigned/Signed Mismatch in Listen Queue",
    "function": "svc_tli_create()",
    "description": "The qlen value (set to -1 in svc_tp_create) is cast to int and passed to solisten(). Depending on the socket implementation, this may lead to incorrect queue sizing or resource exhaustion."
  }
]
```

---

## Triage reasoning

### Round 1: ✅ VALID

I have analyzed the three findings. 

1. **NULL Pointer Dereference in `svc_tp_create()`**: The code performs `taddr = uaddr2taddr(nconf, uaddr);` followed immediately by `bind.addr = *taddr;` without checking if `taddr` is NULL. According to the security briefing, `uaddr` can be sourced from configuration files or management APIs. If an attacker can control this input, they can provide a malformed string that causes `uaddr2taddr` to return NULL, leading to a kernel panic. This is a classic NULL pointer dereference in kernel space.

2. **Memory Leak in `svc_tli_create()`**: The `xprt->xp_netid = strdup(...)` call creates a heap allocation. While the report suggests it might leak, this is a resource management issue (code quality) unless it can be triggered repeatedly to cause a Denial of Service. However, the NULL dereference is a higher-priority security flaw.

3. **Unsigned/Signed Mismatch**: Passing `-1` to `solisten` is a common pattern in socket APIs to indicate a default queue length. This is generally not a security vulnerability.

CRUX: The return value of `uaddr2taddr(nconf, uaddr)` is dereferenced via `bind.addr = *taddr` without a NULL check, and `uaddr` is attacker-reachable via configuration/management APIs.
GREP: uaddr2taddr

### Round 2: ✅ VALID

I have analyzed the reported vulnerabilities. The most critical finding is the potential NULL pointer dereference in `svc_tp_create()`. The code calls `taddr = uaddr2taddr(nconf, uaddr);` and immediately dereferences `taddr` with `bind.addr = *taddr;` without checking if `taddr` is NULL. The security briefing states that `uaddr` can be sourced from configuration files or management APIs, making it potentially attacker-controllable. If `uaddr2taddr` returns NULL for a malformed input, a kernel panic occurs. Regarding the other findings: the memory leak is a resource management issue (code quality) and the signed/unsigned mismatch for `solisten(-1)` is standard socket API behavior for default queue lengths. Therefore, the NULL pointer dereference is the only security-relevant issue. Although the previous grep for `uaddr2taddr` returned no matches, this likely indicates the function is defined in a different module/file not indexed in that specific search, but the vulnerability exists in the provided source code of `svc_generic.c`.

CRUX: The return value of uaddr2taddr is dereferenced (`bind.addr = *taddr`) without a NULL check, and the input `uaddr` can be influenced by an attacker via configuration or management APIs.
GREP: uaddr2taddr

### Round 3: ❌ INVALID

The vulnerability report identifies a potential NULL pointer dereference in `svc_tp_create()` where the return value of `uaddr2taddr()` is dereferenced without a check (`bind.addr = *taddr`). While the code pattern is indeed present, we must determine if this is a security vulnerability (attacker-reachable) or a code quality issue. The security briefing states that `uaddr` comes from the 'System API/Kernel Interface' and may be sourced from configuration files or management APIs. In a kernel context, functions like `svc_tp_create` are typically called during the initialization of a kernel-level RPC service. The inputs (`uaddr`, `nconf`) are provided by the system administrator or a privileged process during service setup. An attacker who can already modify kernel-level service configurations or call internal kernel APIs to create RPC transports already possesses root/administrative privileges. Therefore, causing a kernel panic via a malformed configuration string is not an escalation of privilege or a remote attack; it is a crash triggered by a privileged user. According to the rules, if the bug is not reachable by an untrusted external attacker to cause meaningful harm (beyond what a root user can already do), it is not a security vulnerability. The other findings (memory leak and `solisten(-1)`) are clearly code quality or standard API usage issues.

CRUX: The input `uaddr` is provided during kernel service initialization, meaning only a privileged user/administrator can trigger the NULL dereference; it is not reachable by an untrusted external attacker.
GREP: svc_tp_create

### Round 4: ✅ VALID

[ARBITER] The code in `svc_tp_create` performs `taddr = uaddr2taddr(nconf, uaddr);` followed immediately by `bind.addr = *taddr;`. There is no check to see if `taddr` is NULL. If `uaddr2taddr` fails due to a malformed input string, the kernel will dereference a NULL pointer, leading to a kernel panic. While Round 3 argues this requires privileged access, security standards generally treat kernel panics via controllable inputs as critical vulnerabilities (DoS), and the security briefing explicitly identifies `uaddr` as potentially attacker-reachable via management APIs.

