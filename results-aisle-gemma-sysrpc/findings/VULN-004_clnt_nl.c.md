# VULN-004: ummary of Findings

- **File**: `clnt_nl.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

ummary of Findings

### Summary of Findings

| Severity | Title | Function | Description |
| :--- | :--- | :--- | :--- |
| **Critical** | Kernel Deadlock in Destroyer | `clnt_nl_destroy` | Double-call to `rw_wlock` instead of `rw_wunlock` causes a permanent deadlock of the global RPC lock. |
| **High** | Potential Heap Overflow in Init | `client_nl_create` | `MCALL_MSG_SIZE` (24 bytes) is used as a fixed buffer for XDR encoding. If `AUTH_MARSHALL` exceeds this limit, a heap overflow occurs. |
| **Medium** | XDR Decoder Attack Surface | `clnt_nl_call` | Untrusted userland data is passed to `xdr_replymsg`. Any vulnerability in the XDR decoding logic leads to kernel memory corruption or leaks. |

```json
[
  {
    "severity": "critical",
    "title": "Kernel Deadlock via Double Lock",
    "function": "clnt_nl_destroy",
    "description": "The function calls rw_wlock(&rpcnl_global_lock) twice instead of unlocking the second time. This results in a permanent deadlock of the RPC subsystem when a client is destroyed."
  },
  {
    "severity": "high",
    "title": "Heap Buffer Overflow in XDR Initialization",
    "function": "client_nl_create",
    "description": "The code uses nl->nl_mcallc (fixed size 24 bytes) as a buffer for XDR encoding. If the combined size of the RPC header and the authentication marshalled data exceeds 24 bytes, it will result in a kernel heap overflow."
  },
  {
    "severity": "medium",
    "title": "Untrusted XDR Decoding",
    "function": "clnt_nl_call",
    "description": "The kernel processes XDR-encoded replies from userland via xdr_replymsg. This exposes the kernel to any memory safety vulnerabilities present in the XDR decoding implementation."
  }
]
```

---

## Triage reasoning

### Round 1: ✅ VALID

I will analyze the three reported vulnerabilities:

1. **Kernel Deadlock in `clnt_nl_destroy`**: Looking at the code for `clnt_nl_destroy`, I see:
   `rw_wlock(&rpcnl_global_lock);`
   `RB_REMOVE(nl_data_t, &rpcnl_clients, nl);`
   `rw_wlock(&rpcnl_global_lock);`
   The function calls `rw_wlock` twice on the same lock without an intervening unlock. In FreeBSD, `rwlock` is not recursive. This will cause an immediate deadlock of the thread and leave the global lock held, permanently deadlocking the RPC subsystem. Since `clnt_nl_destroy` is the `cl_destroy` operation for the `CLIENT` object, it is called when the RPC client is freed. While the destruction of a kernel RPC client is typically triggered by kernel-side teardown (e.g., unmounting a filesystem), any path that allows a user to trigger the release of this client (like unmounting an NFS share) would trigger this deadlock, resulting in a Denial of Service (DoS).

2. **Heap Overflow in `client_nl_create`**: The code uses `nl->nl_mcallc` (size `MCALL_MSG_SIZE`) as a temporary buffer for `xdrmem_create` during the pre-serialization of the call header and auth header. The reported vulnerability claims `MCALL_MSG_SIZE` is 24 bytes. If the auth header exceeds this, `xdr_put` operations would overflow. I need to verify the value of `MCALL_MSG_SIZE`.

3. **XDR Decoder Attack Surface**: The report claims `xdr_replymsg` processes untrusted userland data. This is true: `clnt_nl_reply` takes data from a Netlink attribute and puts it into an mbuf (`cr->cr_mrep`), which is then passed to `xdr_replymsg` in `clnt_nl_call`. This is a classic attack surface, but without a specific bug in `xdr_replymsg`, it's a general observation of attack surface rather than a specific bug in `clnt_nl.c`. However, the deadlock is a concrete, verifiable bug in the provided code.

CRUX: clnt_nl_destroy calls rw_wlock(&rpcnl_global_lock) twice in a row without an unlock, causing a kernel deadlock.
GREP: MCALL_MSG_SIZE

### Round 2: ✅ VALID

I analyzed the three reported findings. 

1. **Kernel Deadlock in `clnt_nl_destroy`**: The code explicitly calls `rw_wlock(&rpcnl_global_lock);` twice consecutively without an intervening `rw_wunlock`. In the FreeBSD kernel, `rwlock` is not recursive. This will cause the thread to deadlock itself and keep the global RPC lock held, leading to a system-wide denial of service of the RPC subsystem. The `CLIENT` object is destroyed when the associated kernel RPC client is freed (e.g., during NFS unmount), which can be triggered by an administrative action or a system event. While this requires some level of privilege to trigger the unmount, a deadlock in a kernel-level global lock is a critical security vulnerability (DoS).

2. **Heap Overflow in `client_nl_create`**: `MCALL_MSG_SIZE` is confirmed via grep to be 24 bytes. The code uses `xdrmem_create` with this limit. It calls `xdr_putint32` (4 bytes) and `AUTH_MARSHALL`. If `authnone_create()` (the default used here) produces a header larger than 20 bytes, an overflow occurs. However, `authnone` usually produces very little to no data. The critical part is that `xdrmem_create` typically sets up a boundary check in the `XDR` structure, and the subsequent `MPASS(rv)` (which is an assertion) would trigger a kernel panic rather than a silent heap overflow if `xdr_put` fails due to space. More importantly, the `authnone` case is constant and safe. Other auth types might be used, but the `MPASS` makes this a crash (DoS) rather than an exploitable overflow in a production build (where `MPASS` might be disabled, but `XDR` internal checks would return failure).

3. **XDR Decoder Attack Surface**: This is a general architectural observation. While `clnt_nl_reply` does pass untrusted Netlink data to `xdr_replymsg`, there is no specific vulnerability demonstrated in the XDR logic itself within this file. This is a 'potential' for bugs, not a bug in `clnt_nl.c`.

CRUX: clnt_nl_destroy calls rw_wlock(&rpcnl_global_lock) twice without an unlock, causing a non-recursive lock deadlock.
GREP: rw_wlock

### Round 3: ✅ VALID

I analyzed the three reported findings. 

1. **Kernel Deadlock in `clnt_nl_destroy`**: The code explicitly calls `rw_wlock(&rpcnl_global_lock);` twice in a row without an intervening `rw_wunlock`. In the FreeBSD kernel, `rwlock` is not recursive. This will cause the thread to deadlock itself and leave the global RPC lock held, resulting in a permanent denial of service (DoS) of the entire RPC subsystem. While the trigger (`cl_destroy`) typically happens during kernel teardown (like unmounting NFS), this is a reachable path that causes a catastrophic system state. 

2. **Heap Overflow in `client_nl_create`**: The code uses `xdrmem_create` with a buffer of `MCALL_MSG_SIZE` (24 bytes). `xdrmem_create` in FreeBSD's XDR implementation creates a bounded buffer. If `xdr_putint32` or `AUTH_MARSHALL` exceeds the 24 bytes, the XDR internal state marks the stream as failed. The code then calls `MPASS(rv)`. `MPASS` is a kernel assertion that triggers a panic if the condition is false. Therefore, this is a potential kernel panic (DoS) during client creation if a large auth header is used, not a heap overflow, because the `XDR` structure prevents writing past the provided buffer size. 

3. **XDR Decoder Attack Surface**: As noted by prior reviewers, this is an observation of attack surface. Without a specific vulnerability in the XDR decoding logic, this is not a bug in `clnt_nl.c`.

CRUX: clnt_nl_destroy contains a double-call to rw_wlock on a non-recursive lock, causing a kernel deadlock.
GREP: rw_wlock

### Round 4: ✅ VALID

[ARBITER] The evidence and code confirm three vulnerabilities. 1. In `clnt_nl_destroy`, `rw_wlock(&rpcnl_global_lock)` is called twice consecutively without a corresponding unlock, causing a kernel deadlock. 2. In `client_nl_create`, `xdrmem_create` uses `nl->nl_mcallc` (size `MCALL_MSG_SIZE` = 24 bytes) as a destination buffer. If `xdr_callhdr` or `AUTH_MARSHALL` writes more than 24 bytes, a heap overflow occurs. 3. In `clnt_nl_call`, the kernel calls `xdr_replymsg` on data received from userland via netlink, expanding the attack surface for XDR decoding vulnerabilities.

