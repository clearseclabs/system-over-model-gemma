# VULN-020: Kernel Heap Overflow in rpctls_server

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Confidence**: 100% [VVV]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Kernel Heap Overflow in rpctls_server

The function uses res.gid.gid_len from an RPC response to allocate memory for gids. An integer overflow in the multiplication (*ngrps * sizeof(gid_t)) can lead to a undersized buffer allocation, followed by a heap buffer overflow in the loop copying gid values.

---

## Triage reasoning

### Round 1: ✅ VALID

The vulnerability report identifies a potential integer overflow in `rpctls_server` when calculating the allocation size: `*ngrps * sizeof(gid_t)`, where `*ngrps` comes from `res.gid.gid_len` (returned by the `rpctlssd` userspace daemon). If `*ngrps` is large enough, the multiplication can overflow, leading to an undersized buffer allocation and a subsequent heap overflow in the loop `for (i = 0; i < *ngrps; i++) *gidp++ = *gidv++;`. 

Tracing the data flow: `_svcauth_rpcsec_tls` (triggered by an external network request) calls `rpctls_server`. `rpctls_server` calls `rpctlssd_connect_2`, which performs an RPC call to the `rpctlssd` daemon. The `res` structure contains data returned by this daemon. While the daemon is technically a local process, the kernel must treat its responses as untrusted if it is possible for an attacker to compromise the daemon or if the daemon itself forwards attacker-controlled data from the TLS handshake. More importantly, in a security analysis of a kernel, we must assume any value coming from userspace (even a helper daemon) is untrusted unless there is a hard check in the kernel. 

There are no checks on `res.gid.gid_len` (stored in `*ngrps`) before the multiplication or the allocation. A value of `ngrps` such as `(SIZE_MAX / sizeof(gid_t)) + 1` would cause an overflow. Given that `gid_t` is typically 4 or 8 bytes, this is easily reachable if the daemon is compromised or malicious. The kernel blindly trusts the length reported by the daemon and uses it to drive a loop that writes to the heap.

CRUX: The kernel performs `mem_alloc(*ngrps * sizeof(gid_t))` and a subsequent copy loop based on `*ngrps` without verifying that `*ngrps` is within reasonable bounds or checking for integer overflow, where `*ngrps` is provided by the userspace `rpctlssd` daemon.
GREP: sizeof(gid_t)

### Round 2: ✅ VALID

The vulnerability exists in `rpctls_server` where `res.gid.gid_len` (an integer from an RPC response) is used to calculate an allocation size: `mem_alloc(*ngrps * sizeof(gid_t))`. There is no check on `*ngrps` before this multiplication, making it susceptible to an integer overflow. If `*ngrps` is large enough, `mem_alloc` will allocate a small buffer, and the subsequent loop `for (i = 0; i < *ngrps; i++) *gidp++ = *gidv++;` will write `*ngrps` elements into that buffer, causing a heap overflow. The input originates from the `rpctlssd` daemon via the `rpctlssd_connect_2` RPC call. While the daemon is a local process, the kernel is acting as a client to this daemon; if the daemon is compromised or if it transmits data derived from the TLS handshake (which is triggered by an external network request to `_svcauth_rpcsec_tls`), the attacker can control these values. Even if the daemon is considered 'trusted', kernel-to-userspace boundaries require rigorous validation to prevent a compromised userspace process from escalating privileges in the kernel. There are no guards (like `MAX_GROUPS`) seen in the provided code or common in this path to prevent this.

CRUX: The kernel performs an unchecked multiplication `*ngrps * sizeof(gid_t)` using a value from a userspace RPC response, leading to a potential integer overflow and subsequent heap buffer overflow.
GREP: gid_t

### Round 3: ✅ VALID

The bug pattern is real: `rpctls_server` uses `res.gid.gid_len` (provided by the userspace `rpctlssd` daemon) to calculate an allocation size `*ngrps * sizeof(gid_t)` and then uses `*ngrps` as the loop limit for copying data into that buffer. If `*ngrps` is large enough to cause an integer overflow during the multiplication, `mem_alloc` will allocate a buffer smaller than required, leading to a kernel heap overflow. The input is attacker-reachable because `_svcauth_rpcsec_tls` is triggered by any external network request (NULL RPC with AUTH_TLS). While the value comes from the `rpctlssd` daemon, kernel security best practices mandate that data crossing the kernel-userspace boundary be treated as untrusted. A compromised or malicious daemon, or one that forwards data from a malicious TLS handshake, could trigger this. There are no bounds checks on `res.gid.gid_len` in the provided code.

CRUX: The kernel performs an unchecked multiplication `*ngrps * sizeof(gid_t)` using `*ngrps` from a userspace RPC response and subsequently uses the same potentially overflowing `*ngrps` as a loop limit for memory writes.
GREP: gid_t

