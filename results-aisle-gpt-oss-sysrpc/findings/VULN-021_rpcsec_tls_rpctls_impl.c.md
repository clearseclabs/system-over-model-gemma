# VULN-021: ummary of High‑Risk Findings

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

ummary of High‑Risk Findings

### Summary of High‑Risk Findings

| Severity | Title | Function | Description |
|----------|-------|----------|-------------|
| **Critical** | Integer overflow + unchecked array copy in `rpctls_server` | `rpctls_server()` | The multiplier `*ngrps * sizeof(gid_t)` is unchecked; a malicious daemon that reports a huge `gid_len` can cause overflow and buffer overwrite when copying *gidp*.  This yields arbitrary kernel memory corruption. |
| **High** | OOB read in `rpctls_connect` due to unchecked `strlen` | `rpctls_connect()` | `certname` is dereferenced blindly; an attacker that calls this helper with a non‑paged or non‑NULL‑terminated string can crash the kernel. |
| **Medium** | Unchecked user cookie in `sys_rpctls_syscall` | `sys_rpctls_syscall()` | Any arbitrary 64‑bit value can be used as a socket cookie, causing lookup failures and possible double free race.  Primarily a DoS vector. |
| **Medium** | Optionally unchecked `res.gid.gid_len` array read in `rpctls_server` | `rpctls_server()` | Even without integer overflow, reading *ngrps* entries when less than that were returned can corrupt memory. |
| **Low** | Potential double‑free and race in `rpctls_rpc_failed` | `rpctls_rpc_failed()` | Locking mitigates but a race between `RB_REMOVE` and `soclose` may lead to double free. |

---

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code allocates memory based on the value returned by the user‑controlled upcall daemon: `*ngrps = res.gid.gid_len; *gids = mem_alloc(*ngrps * sizeof(gid_t));` The multiplication is performed with an `int` (`*ngrps`) and `sizeof(gid_t)` (4 bytes). If the daemon returns a large `gid_len`, the multiplication can wrap around the 32‑bit signed int, producing a small allocation size while the subsequent copy loop copies `*ngrps` entries, overrunning the buffer and corrupting kernel memory. The value `gid_len` originates from the user‑space rpctlssd service, so a malicious user can inject any value, making the vulnerability real and exploitable. Other listed issues are either low impact or rely on improper user input handling that does not lead to memory corruption. Hence the reported high‑risk findings are valid.

