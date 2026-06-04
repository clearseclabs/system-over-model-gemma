# VULN-016: Resource Exhaustion (DoS) via `cd->resid`

- **File**: `svc_vc.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Resource Exhaustion (DoS) via `cd->resid`

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

---

## Triage reasoning

### Round 1: ✅ VALID

The vulnerability report identifies a classic resource exhaustion pattern. In `svc_vc_process_pending`, the code reads a 4-byte header from the network and assigns `cd->resid = header & 0x7fffffff`. This allows an attacker to specify a record length up to 2,147,483,647 bytes. The subsequent `while` loop pulls mbufs from `cd->mpending` (which is populated by `soreceive` in `svc_vc_recv`) and appends them to `cd->mreq`. Crucially, there is no check to see if `cd->resid` exceeds a reasonable maximum RPC message size. Since `soreceive` is called in a loop in `svc_vc_recv` and appends data to `cd->mpending`, an attacker can send a large `resid` and then slowly stream data. The kernel will continue to allocate and chain mbufs in `cd->mreq` until the requested `resid` is met or the connection is closed. This can lead to kernel memory exhaustion (DoS). While there is a `uio.uio_resid = 1000000000` in `svc_vc_recv`, this only limits a single `soreceive` call; the overall record length `cd->resid` is not bounded.

CRUX: cd->resid is assigned an attacker-controlled value from the network header without any upper bound check, and the code proceeds to accumulate mbufs in cd->mreq until this length is reached.
GREP: MAX_RPC_MSG_SIZE

### Round 2: ✅ VALID

The vulnerability is real. In `svc_vc_process_pending`, the server reads a 4-byte header from the network and assigns `cd->resid = header & 0x7fffffff`. This allows an attacker to specify a record length of up to 2GB. The function then enters a `while` loop that moves mbufs from `cd->mpending` to `cd->mreq` as long as `cd->resid` is non-zero. While `svc_vc_recv` uses `uio.uio_resid = 1000000000` for individual `soreceive` calls, it does so within a `for(;;)` loop that continues to call `svc_vc_process_pending` and `soreceive`. Consequently, the kernel will accumulate mbufs in the `cd->mreq` chain until the 2GB limit is reached or the system runs out of memory. There is no check against a maximum RPC message size before starting this accumulation. This allows a remote attacker to exhaust kernel memory (mbufs) by sending a large header and then streaming data slowly, causing a system-wide Denial of Service.

CRUX: cd->resid is set to an attacker-controlled value (up to 2^31-1) from the network header, and the server accumulates mbufs in cd->mreq until this length is reached without any upper-bound validation.
GREP: MAX_RPC_MSG_SIZE

### Round 3: ✅ VALID

The vulnerability is real. In `svc_vc_process_pending`, the code extracts a record length from the network header and assigns it to `cd->resid` using `cd->resid = header & 0x7fffffff`. This allows an attacker to specify a record size up to 2,147,483,647 bytes (~2 GB). The logic then proceeds to pull mbufs from `cd->mpending` (populated by `soreceive` in `svc_vc_recv`) and append them to `cd->mreq` until `cd->resid` reaches zero. While `svc_vc_recv` uses a large constant `uio.uio_resid = 1000000000` for individual `soreceive` calls, this is merely a hint for the socket layer's read limit and does not bound the aggregate size of the RPC record. Because there is no upper bound check on `cd->resid` relative to a maximum allowable RPC message size, a remote attacker can force the kernel to allocate and chain mbufs for a massive record, leading to kernel memory exhaustion and system-wide Denial of Service. Previous greps for `MAX_RPC_MSG_SIZE` confirm that no such limit is defined or enforced in this context.

CRUX: cd->resid is assigned an attacker-controlled value from the network header (up to 2^31-1) without any upper-bound validation, leading to unbounded mbuf accumulation in cd->mreq.
GREP: MAX_RPC_MSG_SIZE

### Round 4: ✅ VALID

[ARBITER] In `svc_vc_process_pending`, the code reads a 4-byte header and assigns `cd->resid = header & 0x7fffffff`, which allows an attacker-controlled value up to 2,147,483,647 bytes. The subsequent `while` loop moves mbufs from `cd->mpending` to `cd->mreq` until `cd->resid` reaches zero. There is no upper-bound check on `cd->resid` to ensure it fits within a reasonable maximum RPC message size. An attacker can send a header with a very large `resid` and slowly transmit data, causing the kernel to accumulate a massive chain of mbufs in `cd->mreq`, leading to kernel memory exhaustion and Denial of Service.

