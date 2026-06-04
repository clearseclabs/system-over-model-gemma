# VULN-021: Kernel Memory Exhaustion (DoS)

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Kernel Memory Exhaustion (DoS)

Lack of upper-bound validation on res.gid.gid_len allows a malicious or compromised userspace daemon to trigger massive kernel memory allocations via mem_alloc, leading to a Denial of Service.

---

## Triage reasoning

### Round 1: ✅ VALID

The function `rpctls_server` performs a kernel-side RPC call to a userspace daemon (`rpctlssd`) via `rpctlssd_connect_2`. The response `res` contains `res.gid.gid_len`, which is used directly as a multiplier for a kernel memory allocation: `mem_alloc(*ngrps * sizeof(gid_t))`. 

(1) The bug pattern (unbounded allocation based on external input) is real. 
(2) Reachability: An attacker can trigger this by sending an RPC NULL request with `AUTH_TLS`, which invokes `_svcauth_rpcsec_tls`, which in turn calls `rpctls_server`. While the allocation depends on the response from the `rpctlssd` daemon, the security context explicitly states that the daemon can be 'malicious or compromised'. In a security triage context, if the kernel relies on a userspace daemon for critical size parameters without validation, a compromise of that daemon (or an attacker who can spoof/influence the RPC response if the channel is not sufficiently secured) leads to kernel memory exhaustion. 
(3) No defense (such as a maximum limit on `ngrps`) is present in the provided code. The `rpctls_getinfo` function fetches a `maxlen`, but that is not used to bound `res.gid.gid_len` in `rpctls_server`.

CRUX: The variable `res.gid.gid_len` is provided by a userspace daemon and used directly in `mem_alloc` without any upper-bound validation in `rpctls_server`.
GREP: rpctlssd_connect_res

### Round 2: ✅ VALID

The function `rpctls_server` receives a response `res` from the `rpctlssd` userspace daemon via `rpctlssd_connect_2`. The field `res.gid.gid_len` is used as a size for a kernel memory allocation: `mem_alloc(*ngrps * sizeof(gid_t))`. There is no validation check on `res.gid.gid_len` before this allocation. The security context explicitly notes that the daemon can be 'malicious or compromised'. In the kernel's threat model, userspace daemons are untrusted. A compromised `rpctlssd` could send a very large `gid_len`, causing the kernel to allocate excessive memory, leading to a Denial of Service (Kernel Memory Exhaustion). While `rpctls_getinfo` retrieves a `maxlen` sysctl, this value is not used to bound the allocation in `rpctls_server`.

CRUX: The kernel allocates memory using `res.gid.gid_len` provided by a userspace daemon without any upper-bound validation.
GREP: res.gid.gid_len

### Round 3: ✅ VALID

The bug pattern is present: `rpctls_server` takes `res.gid.gid_len` from the response of an RPC call to the userspace daemon `rpctlssd` and uses it to calculate the size for a kernel memory allocation via `mem_alloc(*ngrps * sizeof(gid_t))`. The security context explicitly states that the userspace daemon can be compromised. In a kernel-security model, the kernel must not trust size parameters returned from userspace for memory allocations without verification. While `rpctls_getinfo` retrieves a `maxlen` from sysctl, the code in `rpctls_server` does not use this value to bound `res.gid.gid_len`. An attacker who compromises the `rpctlssd` daemon can provide an arbitrarily large `gid_len`, causing kernel memory exhaustion and a Denial of Service.

CRUX: The kernel performs a memory allocation based on `res.gid.gid_len` returned from a userspace daemon without any upper-bound validation.
GREP: res.gid.gid_len

### Round 4: ✅ VALID

[ARBITER] The function `rpctls_server` receives a response `res` from the `rpctlssd` userspace daemon via `rpctlssd_connect_2`. It takes the value of `res.gid.gid_len` and uses it as a multiplier for a kernel memory allocation: `mem_alloc(*ngrps * sizeof(gid_t))`, where `*ngrps = res.gid.gid_len`. There is no upper-bound validation on `res.gid.gid_len`. Since userspace daemons are untrusted in the kernel security model, a compromised or malicious daemon can provide an arbitrarily large value for `gid_len`, triggering massive kernel memory allocations and leading to a Denial of Service (DoS).

