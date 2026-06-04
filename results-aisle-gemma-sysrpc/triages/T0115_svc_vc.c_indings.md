# Triage T0115: indings

- **File**: `svc_vc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

indings

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** svc_vc_process_pending moves existing mbufs rather than allocating new ones based on the attacker-controlled length.

I evaluated the three reported findings. 

1. **Kernel Memory Exhaustion**: In `svc_vc_process_pending()`, `cd->resid` is derived from the 31-bit `header` read from the network (`cd->resid = header & 0x7fffffff`). The loop `while (cd->mpending && cd->resid)` pulls mbufs from `cd->mpending` into `cd->mreq`. While the attacker can specify a large `resid`, they must actually *send* the data for it to occupy memory. The memory is already allocated by the socket layer as mbufs in the receive queue (`so_rcv`). `svc_vc_process_pending` simply moves these existing mbufs from one pointer (`cd->mpending`) to another (`cd->mreq`). It does not perform new allocations based on the `resid` value. Therefore, this is not a memory exhaustion vulnerability beyond the existing socket buffer limits (which are managed by the kernel's networking stack).

2. **Integer Underflow in `svc_vc_ack`**: The code performs `*ack -= sbused(&xprt->xp_socket->so_snd);`. Since `*ack` is a `uint32_t`, if `sbused` exceeds `xp_snt_cnt`, it will wrap around. However, `xp_snt_cnt` tracks the total bytes sent, and `sbused` tracks bytes currently in the send buffer. In a standard TCP implementation, `sbused` is a subset of the data that was intended to be sent. Even if it wraps, this value is used for an RPC ACK (likely for flow control or sequence tracking). Without evidence that this wrapped value triggers a memory corruption or privilege escalation, it is a logic/quality issue.

3. **NULL Pointer Dereference in `svc_vc_destroy`**: The function casts `xprt->xp_p1` to `struct cf_conn *cd` and later dereferences it (`if (cd->mreq)`). `xprt->xp_p1` is initialized to `NULL` in `svc_vc_create` (rendezvous) and to a allocated `cd` in `svc_vc_create_conn` and `svc_vc_create_backchannel`. The `svc_vc_ops` (which includes `svc_vc_destroy`) are only assigned in `svc_vc_create_conn` and `svc_vc_create_backchannel`, where `xp_p1` is guaranteed to be allocated. For the rendezvous transporter, `svc_vc_rendezvous_ops.xp_destroy` calls `svc_vc_rendezvous_destroy`, which does NOT call `svc_vc_destroy`. Thus, `svc_vc_destroy` is only called on transporters where `xp_p1` is non-NULL.

CRUX: svc_vc_process_pending moves existing mbufs rather than allocating new ones based on the attacker-controlled length.
GREP: sbused

🔎 **Grep results:**

GREP `sbused`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The memory exhaustion claim is false because the code moves existing mbufs rather than allocating new ones based on the length header; the NULL dereference is unreachable because the function is only mapped to transports where the pointer is initialized; the underflow is not security-relevant.

I analyzed the three reported findings. 

1. **Kernel Memory Exhaustion**: In `svc_vc_process_pending()`, the attacker-controlled `cd->resid` (up to 2GB) determines how many bytes are moved from `cd->mpending` to `cd->mreq`. However, `cd->mpending` is populated by `soreceive()`. The mbufs are already allocated by the TCP stack's receive buffers (`so_rcv`). `svc_vc_process_pending` merely re-links these existing mbufs. The memory exhaustion would occur at the socket layer, not because of the `resid` value itself. Thus, this is a false positive regarding `svc_vc_process_pending`.

2. **Integer Underflow in `svc_vc_ack`**: The calculation `*ack = atomic_load_acq_32(&xprt->xp_snt_cnt); *ack -= sbused(&xprt->xp_socket->so_snd);` can indeed underflow if `sbused` (current buffer usage) is greater than `xp_snt_cnt` (total bytes sent). However, this value is returned as an ACK to the caller. Without any evidence that this `uint32_t` is later used for memory allocation, array indexing, or critical logic that could be subverted, it is a logic error/code quality issue, not a security vulnerability.

3. **NULL Pointer Dereference in `svc_vc_destroy`**: `svc_vc_destroy` is part of `svc_vc_ops`. Looking at `svc_vc_create` (rendezvous) and `svc_vc_create_conn`, the rendezvous transporter uses `svc_vc_rendezvous_ops` (which uses `svc_vc_rendezvous_destroy`), while only connection-oriented transports (created via `svc_vc_create_conn` or `svc_vc_create_backchannel`) use `svc_vc_ops`. In both connection-oriented creation paths, `xprt->xp_p1` is explicitly assigned a `mem_alloc`'d `struct cf_conn`. Therefore, `cd` will not be NULL when `svc_vc_destroy` is called.

CRUX: The memory exhaustion claim is false because the code moves existing mbufs rather than allocating new ones based on the length header; the NULL dereference is unreachable because the function is only mapped to transports where the pointer is initialized; the underflow is not security-relevant.
GREP: sbused

🔎 **Grep results:**

GREP `sbused`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** svc_vc_process_pending re-links existing mbufs rather than allocating new ones based on the network-provided length; the NULL dereference is unreachable via the defined operation mappings; the integer underflow is not security-relevant.

I evaluated the three findings. 

1. **Kernel Memory Exhaustion**: The scanner claims that a large `resid` forces the kernel to accumulate an unbound number of mbufs. However, `svc_vc_process_pending` only moves mbufs from `cd->mpending` to `cd->mreq`. `cd->mpending` is populated by `soreceive`, meaning the mbufs are already allocated by the networking stack and governed by the socket's receive buffer limits (`so_rcv.sb_hiwat`). The code does not perform new allocations proportional to `resid`. This is a false positive.

2. **Integer Underflow in `svc_vc_ack`**: The expression `*ack -= sbused(...)` can underflow if the current socket send buffer usage exceeds the total sent count. However, this underflow results in a large `uint32_t` value being returned as an RPC ACK. There is no evidence in the provided code that this value is used as a length for memory allocation or an index into an array. It is a logic/code quality issue, not a security vulnerability.

3. **NULL Pointer Dereference in `svc_vc_destroy`**: The function `svc_vc_destroy` is mapped via `svc_vc_ops`. Only transports created by `svc_vc_create_conn` and `svc_vc_create_backchannel` use `svc_vc_ops`. Both of these functions allocate `struct cf_conn` and assign it to `xprt->xp_p1` before registration. The rendezvous transporter uses `svc_vc_rendezvous_ops` and calls `svc_vc_rendezvous_destroy` instead. Thus, `xprt->xp_p1` is guaranteed to be non-NULL when `svc_vc_destroy` is invoked. This is unreachable.

CRUX: svc_vc_process_pending re-links existing mbufs rather than allocating new ones based on the network-provided length; the NULL dereference is unreachable via the defined operation mappings; the integer underflow is not security-relevant.
GREP: sbused

🔎 **Grep results:**

GREP `sbused`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] 1. Kernel Memory Exhaustion: In `svc_vc_process_pending()`, `cd->resid` is used to move existing mbufs from `cd->mpending` (populated by `soreceive`) to `cd->mreq`. It does not perform new allocations based on the attacker-supplied length; memory is already constrained by the socket's receive buffer limits (`so_rcv`). 2. Integer Underflow: `svc_vc_ack()` performs `*ack -= sbused(...)`. While a wrap-around is theoretically possible if `sbused` exceeds `xp_snt_cnt`, this is a statistics/acknowledgment value and does not lead to memory corruption or privilege escalation. 3. NULL Pointer Dereference: `svc_vc_destroy()` casts `xprt->xp_p1` to `struct cf_conn *`. In all creation paths (`svc_vc_create_conn` and `svc_vc_create_backchannel`), `xp_p1` is initialized with a `mem_alloc` result before the transporter is registered and becomes eligible for destruction.

