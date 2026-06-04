# nano-analyzer triage survivors

- **Target**: `freebsd-prepatch/sys/rpc`
- **Date**: 2026-04-26_223536
- **Model**: google/gemma-4-31b-it
- **Threshold**: medium+
- **Results**: ✅ 30 valid | ❌ 127 rejected | ❓ 0 uncertain

---

## ✅ auth_unix.c: NULL Pointer Dereference in authunix_validate

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `authunix_validate`, the code checks if the `verf` pointer itself is NULL, but it fails to check if `verf->oa_base` is NULL before passing it to `xdrmem_create`. Since `verf` is derived from untrusted network input (an RPC packet), an attacker can provide a packet with `oa_flavor == AUTH_SHORT` and `oa_base == NULL`. The subsequent call to `xdrmem_create` and the follow-up `xdr_opaque_auth` call will attempt to read from the NULL address, resulting in a kernel crash (NULL pointer dereference).

---

## ✅ clnt_dg.c: Memory Corruption in `clnt_dg_control`

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `clnt_dg_control` in `clnt_dg.c` contains a classic buffer overflow in the `CLSET_SVC_ADDR` case. It performs `memcpy(&cu->cu_raddr, addr, addr->sa_len);` where `cu->cu_raddr` is a fixed-size `struct sockaddr_storage`. Because `addr` is a pointer to `info` (provided by the caller) and `sa_len` is a field within that user-supplied structure, an attacker can specify a value for `sa_len` that exceeds the size of `struct sockaddr_storage`, resulting in a kernel heap overflow. Additionally, `CLGET_SVC_ADDR` contains a corresponding overflow where it copies data into the `info` buffer using `cu->cu_raddr.ss_len` without knowing the size of the destination buffer.

---

## ✅ clnt_dg.c: Logic and State Issues

**Verdict**: VALID

### Triage reasoning

[ARBITER] The report identifies two issues. The first (Congestion Window) is invalid; calculation analysis shows the numerator is bounded (~69k) and the denominator is floored at 256, preventing overflow and divide-by-zero. However, the second issue (XID Predictability) is a valid security vulnerability. The code uses a global sequential counter (`rpc_xid`) for Transaction IDs. In `clnt_dg_soupcall`, incoming packets are matched to pending requests solely based on the XID. Because `clnt_dg_create` initializes the client with `authnone_create()` (null authentication), there is no cryptographic verification of the response. An attacker can predict the next XID and inject forged RPC responses to the client.

---

## ✅ clnt_nl.c: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] The evidence and code confirm three vulnerabilities. 1. In `clnt_nl_destroy`, `rw_wlock(&rpcnl_global_lock)` is called twice consecutively without a corresponding unlock, causing a kernel deadlock. 2. In `client_nl_create`, `xdrmem_create` uses `nl->nl_mcallc` (size `MCALL_MSG_SIZE` = 24 bytes) as a destination buffer. If `xdr_callhdr` or `AUTH_MARSHALL` writes more than 24 bytes, a heap overflow occurs. 3. In `clnt_nl_call`, the kernel calls `xdr_replymsg` on data received from userland via netlink, expanding the attack surface for XDR decoding vulnerabilities.

---

## ✅ clnt_rc.c: Kernel Memory Leak in CLSET_TLSCERTNAME

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `clnt_reconnect_control`, the `CLSET_TLSCERTNAME` case calls `mem_alloc(slen)` and assigns the result to `rc->rc_tlscertname` without first checking if the pointer is already occupied. If `CLSET_TLSCERTNAME` is called multiple times on the same client handle, the previous memory allocation is overwritten and leaked. The code shows `rc->rc_tlscertname` is initialized to `NULL` in `clnt_reconnect_create` and only freed in `clnt_reconnect_destroy`, confirming that intermediate updates cause leaks.

---

## ✅ clnt_rc.c: NULL Pointer Dereference in clnt_reconnect_freeres

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `clnt_reconnect_freeres` calls the `CLNT_FREERES` macro using `rc->rc_client`. The `CLNT_FREERES` macro dereferences the provided client handle (`rh->cl_ops->cl_freeres`). There is no check to ensure `rc->rc_client` is non-NULL. Because `rc->rc_client` can be set to NULL by concurrent calls to `clnt_reconnect_close` or during a reconnection event in `clnt_reconnect_call` after a successful result was received but before it was freed, a NULL pointer dereference will occur, leading to a kernel panic.

---

## ✅ netconfig.h: Environment variable injection via NETPATH

**Verdict**: VALID

### Triage reasoning

[ARBITER] The evidence from Round 1 provides explicit grep matches proving that `setnetpath` is defined in `netconfig.h`, implemented in `getnetpath.c`, and called in `rpc_generic.c`. The Round 3 'no matches' result is contradictory to the provided evidence in Round 1 and the actual content of `netconfig.h`. The function `setnetpath` is designed to establish a session based on the `NETPATH` environment variable; if called in a privileged context (common for RPC libraries), it allows an attacker to redirect configuration parsing to a malicious file.

---

## ✅ clnt_vc.c: Memory Exhaustion (DoS) via Record Header

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `clnt_vc_soupcall`, the code reads a 4-byte header from the network and calculates the record size using `ct->ct_record_resid = header & 0x7fffffff;`. This allow an attacker to specify a record size up to 2,147,483,647 bytes (~2GB). The function then accumulates mbufs into `ct->ct_record` until this value reaches zero. There is no upper-bound check on `ct->ct_record_resid` before the accumulation starts, enabling a remote attacker to exhaust kernel memory (mbuf clusters) by claiming a large record size and sending data slowly, leading to a Denial of Service.

---

## ✅ clnt_vc.c: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `clnt_vc_soupcall` reads a 32-bit integer `header` from the network and sets `ct->ct_record_resid = header & 0x7fffffff;`. This allows an attacker to specify a record length up to 2,147,483,647 bytes (2GB). The code then enters a loop calling `soreceive` and accumulating mbufs into the `ct->ct_record` chain until `ct_record_resid` reaches zero. Since there is no upper-bound validation on the length provided by the network, a remote attacker can force the kernel to allocate a massive amount of mbuf memory, leading to kernel memory exhaustion and a system crash.

---

## ✅ replay.c: ecurity Analysis of `replay.c`

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `replay_alloc`, the code performs `bcopy(addr, &rce->rce_addr, addr->sa_len)`. The destination `rce->rce_addr` is a `struct sockaddr_storage`, which has a fixed size. The length `addr->sa_len` is taken directly from the `sockaddr` structure. Since `addr` is derived from network input and there is no validation to ensure `addr->sa_len <= sizeof(struct sockaddr_storage)`, a maliciously crafted packet with a large `sa_len` will cause a heap buffer overflow.

---

## ✅ replay.c: Buffer Overflow in `replay_alloc`

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `replay_alloc` performs a memory copy using `bcopy(addr, &rce->rce_addr, addr->sa_len)`. The destination `rce->rce_addr` is a `struct sockaddr_storage`, which has a fixed size. The length of the copy is determined by `addr->sa_len`, a field within the source `struct sockaddr`. There is no validation that `addr->sa_len` is less than or equal to `sizeof(struct sockaddr_storage)`. Because `addr` is derived from network input via `replay_find`, an attacker can provide a maliciously large `sa_len` value to trigger a heap-based buffer overflow.

---

## ✅ replay.c: Logical Error in `replay_prune` (Potential DoS/Infinite Loop)

**Verdict**: VALID

### Triage reasoning

[ARBITER] The `replay_prune` function only removes entries that have a completed reply (`rce->rce_repmsg.rm_xid != 0`). If an attacker floods the system with unique RPC requests without providing replies, the cache fills with 'in-progress' entries. Because `replay_prune` will fail to find any removable entries, it returns without reducing `rc_count`. Subsequently, `replay_find` calls `replay_alloc`, which unconditionally increments `rc_count` and allocates kernel memory. This allows an attacker to bypass the `REPLAY_MAX` (1024) and `rc_maxsize` limits, leading to unbounded kernel memory consumption and a Denial of Service.

---

## ✅ replay.c: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `replay_alloc`, the code executes `bcopy(addr, &rce->rce_addr, addr->sa_len)`. The destination `rce->rce_addr` is a `struct sockaddr_storage`, which has a fixed size. The length `addr->sa_len` is taken directly from the `sockaddr` structure provided by the RPC parser (derived from network input). There is no validation to ensure `addr->sa_len` does not exceed the size of `struct sockaddr_storage`, allowing a remote attacker to trigger a heap-based buffer overflow.

---

## ✅ rpc_callmsg.c: Memory Leak on Decoding Failure

**Verdict**: VALID

### Triage reasoning

[ARBITER] In the `XDR_DECODE` block of `xdr_callmsg`, the code allocates memory using `mem_alloc(oa->oa_length)` for `cmsg->rm_call.cb_cred.oa_base` and subsequently for `cmsg->rm_call.cb_verf.oa_base`. There are several error paths following these allocations (e.g., if `xdr_opaque` returns `FALSE`, if the length exceeds `MAX_AUTH_BYTES` for the second structure, or if the second allocation fails) where the function returns `FALSE` without calling a corresponding free function for the allocated memory. This allows a remote attacker to cause system memory exhaustion by sending malformed RPC packets.

---

## ✅ rpc_callmsg.c: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] In the `XDR_DECODE` path, the function `xdr_callmsg` performs memory allocations using `mem_alloc()` for `cmsg->rm_call.cb_cred.oa_base` and `cmsg->rm_call.cb_verf.oa_base`. If a subsequent decoding step fails (e.g., `xdr_opaque` returns FALSE, or a length check against `MAX_AUTH_BYTES` fails for the second auth structure), the function returns FALSE immediately. There is no code to free the previously allocated memory for `oa_base` in these error paths. Because this can be triggered by a malformed RPC packet from a remote attacker, it constitutes a memory leak that can lead to Denial of Service via memory exhaustion.

---

## ✅ rpc_generic.c: Address Translation Analysis

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `__rpc_taddr2uaddr_af`, the `AF_LOCAL` case accesses `sun->sun_len` to determine the number of bytes to read from `sun->sun_path` via `sbuf_printf`. Unlike the `AF_INET` and `AF_INET6` cases, which explicitly check `if (nbuf->len < sizeof(*sin))`, the `AF_LOCAL` path performs no validation to ensure `nbuf->len` is sufficient to encompass the length specified by `sun_len`. An attacker providing a crafted `netbuf` where `sun_len` is large but the actual buffer is small can trigger a buffer over-read.

---

## ✅ rpcb_prot.c: Memory Exhaustion (DoS) via Linked Lists

**Verdict**: VALID

### Triage reasoning

[ARBITER] The functions `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` implement a `for(;;)` loop that continues as long as `xdr_bool` returns `TRUE` from the network stream. Inside this loop, `xdr_reference` is called, which performs a memory allocation for each element (`sizeof(RPCBLIST)` or `sizeof(rpcb_entry_list)`). There is no limit on the number of iterations, meaning an attacker can send an arbitrary number of 'TRUE' flags to cause heap exhaustion and a Denial of Service.

---

## ✅ rpcb_prot.c: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] The functions `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` implement XDR list deserialization using a `for(;;)` loop. The loop continues as long as `xdr_bool(xdrs, &more_elements)` returns TRUE. Inside the loop, `xdr_reference` is called, which performs memory allocation for the list element during `XDR_DECODE` operations. There is no counter or upper bound on the number of elements that can be processed from the network stream, allowing a remote attacker to exhaust system memory by sending a stream of TRUE booleans, leading to a Denial of Service (DoS).

---

## ✅ rpc_generic.c: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] The vulnerability in `__rpc_taddr2uaddr_af` is valid. In the `AF_LOCAL` case, the code uses `sun->sun_len` from the `nbuf->buf` (which can be attacker-controlled if the buffer was created via a crafted network request or similar) as a length specifier (`%.*s`) for `sbuf_printf` without verifying that `sun_len` is within the bounds of the actual buffer `nbuf->len` or the `sockaddr_un` structure. This allows an attacker to read adjacent kernel memory. Additionally, `__rpc_nconf2sockinfo` dereferences `nconf` without a NULL check, which is a classic kernel NULL pointer dereference.

---

## ✅ svc_generic.c: indings

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code in `svc_tp_create` performs `taddr = uaddr2taddr(nconf, uaddr);` followed immediately by `bind.addr = *taddr;`. There is no check to see if `taddr` is NULL. If `uaddr2taddr` fails due to a malformed input string, the kernel will dereference a NULL pointer, leading to a kernel panic. While Round 3 argues this requires privileged access, security standards generally treat kernel panics via controllable inputs as critical vulnerabilities (DoS), and the security briefing explicitly identifies `uaddr` as potentially attacker-reachable via management APIs.

---

## ✅ svc_vc.c: Resource Exhaustion (DoS) via `cd->resid`

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `svc_vc_process_pending`, the code reads a 4-byte header and assigns `cd->resid = header & 0x7fffffff`, which allows an attacker-controlled value up to 2,147,483,647 bytes. The subsequent `while` loop moves mbufs from `cd->mpending` to `cd->mreq` until `cd->resid` reaches zero. There is no upper-bound check on `cd->resid` to ensure it fits within a reasonable maximum RPC message size. An attacker can send a header with a very large `resid` and slowly transmit data, causing the kernel to accumulate a massive chain of mbufs in `cd->mreq`, leading to kernel memory exhaustion and Denial of Service.

---

## ✅ svc_auth_unix.c: Potential NULL Dereference

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `_svcauth_unix` assigns `xcr = rqst->rq_clntcred;` and subsequently performs multiple writes to `xcr` (e.g., `xcr->cr_uid = ...`) without any NULL check for `xcr`. In the context of an RPC server processing network packets, if `rqst->rq_clntcred` is not guaranteed to be allocated by the caller, this results in a NULL pointer dereference and a subsequent crash (DoS). The provided code confirms the absence of any validation before the dereference.

---

## ✅ rpcsec_gss/rpcsec_gss_conf.c: Potential NULL pointer dereference in QOP parsing

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `rpc_gss_qop_to_num` in `sys/rpc/rpcsec_gss/rpcsec_gss_conf.c` calls `strcmp(qop, "default")` without verifying that `qop` is not NULL. While the reviewer in Round 2 claimed the function was unreachable, the GREP results from that same round explicitly prove it is called in multiple locations, including `sys/rpc/rpcsec_gss/rpcsec_gss.c` (lines 325 and 456) and `lib/librpcsec_gss/rpcsec_gss.c` (lines 139 and 240). Since the `qop` parameter is derived from network-derived configuration or userspace calls, a NULL value will trigger a kernel panic.

---

## ✅ rpcsec_gss/rpcsec_gss.c: Heap-based Buffer Overflow / Memory Exhaustion in `rpc_gss_validate`

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `rpc_gss_validate`, the code allocates memory for `gd->gd_verf.value` using `mem_alloc(verf->oa_length)` and subsequently performs a `memcpy` of `verf->oa_length` bytes. The `verf` pointer refers to a `struct opaque_auth` which is parsed from the network via XDR. Because there is no upper-bound check on `verf->oa_length` before the allocation and copy, a malicious remote server can send a crafted packet with a very large length value to cause memory exhaustion (leading to a kernel panic) or trigger integer-related allocation issues.

---

## ✅ xdr.h: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] The RNDUP macro defined as `((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) * BYTES_PER_XDR_UNIT)` is susceptible to integer overflow if `x` is near `UINT_MAX`. Specifically, `(x + 3)` will wrap around. Evidence from `rpc_callmsg.c` shows this macro is used on `oa->oa_length`, which is derived from network input. When `RNDUP(oa->oa_length)` overflows, it results in a small value being passed to `XDR_INLINE`. Because `XDR_INLINE` returns a pointer to a buffer of that (now small) size, subsequent `IXDR_GET` calls or `memcpy` operations using the original large `oa->oa_length` will result in an Out-of-Bounds read/write.

---

## ✅ rpcsec_gss/rpcsec_gss_prot.c: Potential Kernel Panic / Memory Corruption (`m_pullup`)

**Verdict**: VALID

### Triage reasoning

The vulnerability exists because `cklen` is read from an untrusted network mbuf via `get_uint32()` and passed to `m_pullup(mic, cklen)`. The only boundary check is `KASSERT(cklen <= MHLEN, ...)`, and as is standard in BSD-derived kernels, `KASSERT` is compiled out in production builds. While the code checks if `m_pullup` returns NULL, `m_pullup` is an operation that attempts to make the first `N` bytes of an mbuf chain contiguous. In the BSD mbuf implementation, requesting an excessively large contiguous region (e.g., near 2^32) can lead to integer overflows in size calculations or attempts to allocate massive amounts of kernel memory before the function can safely return NULL. This creates a reachable path for a remote attacker to cause a kernel panic (Denial of Service). The previous reviewers correctly identified the flow; I have verified that `MHLEN` is a small constant (typically around 168 bytes based on the grep results), making the lack of a production-grade check for a `uint32_t` input a critical failure.

CRUX: An attacker-controlled uint32 `cklen` is passed to `m_pullup` without any production-grade boundary check, as the only check is a `KASSERT` which is removed in production builds.
GREP: m_pullup

---

## ✅ rpcsec_gss/rpcsec_gss_prot.c: ummary of Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] In `xdr_rpc_gss_unwrap_data`, the variable `cklen` is read directly from the network via `get_uint32`. The only check ensuring `cklen` is reasonable is `KASSERT(cklen <= MHLEN, ...)`, which is stripped in production builds. This allows an attacker to pass an arbitrary `uint32_t` value to `m_pullup(mic, cklen)`. In BSD mbuf implementations, `m_pullup` attempts to make the specified length contiguous, which can lead to significant kernel memory allocation or failure (DoS) when provided with a massive value from an untrusted source.

---

## ✅ rpcsec_tls/rpctls_impl.c: Kernel Heap Overflow in rpctls_server

**Verdict**: VALID

### Triage reasoning

The bug pattern is real: `rpctls_server` uses `res.gid.gid_len` (provided by the userspace `rpctlssd` daemon) to calculate an allocation size `*ngrps * sizeof(gid_t)` and then uses `*ngrps` as the loop limit for copying data into that buffer. If `*ngrps` is large enough to cause an integer overflow during the multiplication, `mem_alloc` will allocate a buffer smaller than required, leading to a kernel heap overflow. The input is attacker-reachable because `_svcauth_rpcsec_tls` is triggered by any external network request (NULL RPC with AUTH_TLS). While the value comes from the `rpctlssd` daemon, kernel security best practices mandate that data crossing the kernel-userspace boundary be treated as untrusted. A compromised or malicious daemon, or one that forwards data from a malicious TLS handshake, could trigger this. There are no bounds checks on `res.gid.gid_len` in the provided code.

CRUX: The kernel performs an unchecked multiplication `*ngrps * sizeof(gid_t)` using `*ngrps` from a userspace RPC response and subsequently uses the same potentially overflowing `*ngrps` as a loop limit for memory writes.
GREP: gid_t

---

## ✅ rpcsec_tls/rpctls_impl.c: Kernel Memory Exhaustion (DoS)

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `rpctls_server` receives a response `res` from the `rpctlssd` userspace daemon via `rpctlssd_connect_2`. It takes the value of `res.gid.gid_len` and uses it as a multiplier for a kernel memory allocation: `mem_alloc(*ngrps * sizeof(gid_t))`, where `*ngrps = res.gid.gid_len`. There is no upper-bound validation on `res.gid.gid_len`. Since userspace daemons are untrusted in the kernel security model, a compromised or malicious daemon can provide an arbitrarily large value for `gid_len`, triggering massive kernel memory allocations and leading to a Denial of Service (DoS).

---

## ✅ rpcsec_tls/rpctls_impl.c: Race Condition / Use-After-Free of Stack-Allocated upsock

**Verdict**: VALID

### Triage reasoning

[ARBITER] The functions `rpctls_connect` and `rpctls_server` allocate `struct upsock` on their local stacks and insert a pointer to these stack-allocated structures into the global `upcall_sockets` RB-tree. The `sys_rpctls_syscall` function later retrieves this pointer and dereferences it (`ups = *upsp`). Because the originating threads (`rpctls_connect`/`rpctls_server`) can return due to RPC timeouts or errors while the entry still exists in the tree (or just before `sys_rpctls_syscall` accesses it), the pointer `upsp` becomes a dangling pointer to a destroyed stack frame. This is a classic Stack-Use-After-Return / Use-After-Free vulnerability. The code even contains a comment acknowledging that the mounting thread may 'unroll its stack,' yet it fails to implement any synchronization or heap-allocation strategy to prevent the race.

---

