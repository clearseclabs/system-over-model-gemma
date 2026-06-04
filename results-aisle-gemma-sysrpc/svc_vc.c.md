# Scan: svc_vc.c

### Security Analysis of `svc_vc.c`

The file `svc_vc.c` implements a TCP-based transporter for the kernel RPC (KRPC) framework. The primary attack surface is the network stream, where untrusted data is processed to extract RPC records.

#### 1. Resource Exhaustion (DoS) via `cd->resid`
In `svc_vc_process_pending`, the code reads a 4-byte header from the network to determine the record length:
```c
m_copydata(cd->mpending, 0, sizeof(header), (char *)&header);
header = ntohl(header);
cd->eor = (header & 0x80000000) != 0;
cd->resid = header & 0x7fffffff;
```
An attacker can send a record header with `resid` set to a very large value (up to $2^{31}-1$). The subsequent `while` loop continues to pull mbufs from `cd->mpending` into `cd->mreq` until `cd->resid` reaches zero. 

If the attacker sends a large `resid` but slows down the actual data transmission, the kernel will continue to accumulate mbufs in the `cd->mreq` chain. Because there is no upper bound check on `cd->resid` relative to a maximum allowable RPC message size, a single connection can pin a massive amount of kernel memory (mbufs), leading to a kernel panic or system-wide Denial of Service (DoS) through memory exhaustion.

#### 2. Potential Integer Underflow/Wrap in `svc_vc_ack`
The `svc_vc_ack` function calculates the acknowledgement sequence:
```c
*ack = atomic_load_acq_32(&xprt->xp_snt_cnt);
*ack -= sbused(&xprt->xp_socket->so_snd);
```
`xp_snt_cnt` is a `uint32_t` tracking total bytes sent. `sbused()` returns the number of bytes currently in the socket send buffer. If `sbused` returns a value larger than `xp_snt_cnt` (which could happen during race conditions or specific socket state transitions), `*ack` will wrap around to a very large positive value. While this might only cause logic errors in the RPC sequence tracking, it represents an unsafe arithmetic operation on untrusted/volatile socket states.

#### 3. Missing Validation in `svc_vc_backchannel_recv`
In `svc_vc_backchannel_recv`, the code retrieves a message from the backchannel:
```c
m = cd->mreq;
if (m == NULL) { ... }
cd->mreq = m->m_nextpkt;
```
The function assumes that `cd->mreq` contains a valid RPC message. However, the logic for populating `cd->mreq` in the backchannel path is less stringent than the main `svc_vc_recv` path. If the internal state of the backchannel is corrupted or manipulated, `xdr_callmsg` may be called on malformed data, potentially triggering vulnerabilities within the XDR decoding layer.

#### 4. Potential NULL Dereference in `svc_vc_destroy`
The `svc_vc_destroy` function performs the following:
```c
struct cf_conn *cd = (struct cf_conn *)xprt->xp_p1;
...
if (cd->mreq)
    m_freem(cd->mreq);
```
While `svc_vc_create_conn` initializes `xp_p1` to `cd`, other paths or future modifications to transporter creation might leave `xp_p1` as NULL. The function does not check if `cd` is NULL before dereferencing it to access `cd->mreq`.

---

### Findings

```json
[
  {
    "severity": "high",
    "title": "Kernel Memory Exhaustion via Large Record Length",
    "function": "svc_vc_process_pending()",
    "description": "The function reads a 31-bit record length (resid) directly from the network header. An attacker can specify a massive length, forcing the kernel to accumulate an unbound number of mbufs in the cd->mreq chain, leading to system-wide memory exhaustion and DoS."
  },
  {
    "severity": "medium",
    "title": "Integer Underflow in ACK Calculation",
    "function": "svc_vc_ack()",
    "description": "Subtracting the current socket send buffer usage (sbused) from the total sent count (xp_snt_cnt) without checking if the buffer usage exceeds the count can result in a 32-bit integer wrap-around."
  },
  {
    "severity": "medium",
    "title": "Potential NULL Pointer Dereference during Destruction",
    "function": "svc_vc_destroy()",
    "description": "The function casts xprt->xp_p1 to struct cf_conn * and dereferences it without verifying it is not NULL, which could lead to a kernel panic if the transporter was not fully initialized."
  }
]
```