# VULN-007: Memory Exhaustion (DoS) via Record Header

- **File**: `clnt_vc.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Memory Exhaustion (DoS) via Record Header

#### 1. Memory Exhaustion (DoS) via Record Header
In `clnt_vc_soupcall`, the code reads a 4-byte header from the network to determine the size of the following RPC record:
```c
m_copydata(ct->ct_raw, 0, sizeof(uint32_t), (char *)&header);
header = ntohl(header);
ct->ct_record_resid = header & 0x7fffffff;
```
The value `ct->ct_record_resid` can be up to $2^{31}-1$ bytes (~2GB). The loop then continues to call `soreceive` and append mbufs to `ct->ct_record` until `ct->ct_record_resid` reaches zero. An attacker can send a header claiming a huge record size and then send a slow stream of data. This forces the kernel to allocate a massive chain of mbufs, potentially exhausting the system's memory (mbuf cluster exhaustion) and causing a kernel panic or system-wide Denial of Service.

---

## Triage reasoning

### Round 1: ✅ VALID

The vulnerability is real. In `clnt_vc_soupcall`, the code reads a 4-byte header from the network and uses it to set `ct->ct_record_resid = header & 0x7fffffff`. This allows an attacker to specify a record size up to 2,147,483,647 bytes. The code then enters a loop where it calls `soreceive` and appends the resulting mbuf chains to `ct->ct_record` until `ct->ct_record_resid` reaches zero. There is no check on the maximum allowable value of `ct->ct_record_resid` before starting the accumulation. An attacker can send a header claiming a ~2GB record and then send data slowly, forcing the kernel to allocate and maintain a massive chain of mbufs. This leads to mbuf cluster exhaustion, which is a critical resource in the kernel, resulting in a Denial of Service (system-wide memory exhaustion or kernel panic).

CRUX: The record length `ct->ct_record_resid` is derived directly from untrusted network input (up to 2GB) and used to drive mbuf accumulation without any upper-bound validation.
GREP: ct->ct_record_resid

### Round 2: ✅ VALID

The vulnerability report describes a classic memory exhaustion pattern in RPC-over-TCP. In `clnt_vc_soupcall`, the code reads a 4-byte header from the network: `m_copydata(ct->ct_raw, 0, sizeof(uint32_t), (char *)&header);`. It then calculates the remaining bytes for the record: `ct->ct_record_resid = header & 0x7fffffff;`. 

Crucially, there is no upper bound check on `ct->ct_record_resid` before it is used to control the accumulation of mbufs in `ct->ct_record`. An attacker can send a header with a value of `0x7FFFFFFF` (approx 2.1GB). The loop will then continue calling `soreceive` and appending mbufs to `ct->ct_record` until that amount of data is received. Because this occurs in kernel space using mbufs (which are typically limited and critical resources), an attacker can exhaust the mbuf pool, leading to a kernel panic or a system-wide Denial of Service. The `uio.uio_resid = 1000000000` constant only limits the size of a single `soreceive` call, not the total accumulated size of the record.

Since this code handles raw network data in the kernel without a reasonable size limit on the accumulated buffer, it is a valid security vulnerability.

CRUX: The variable `ct->ct_record_resid` is set from untrusted network input (up to 2GB) and controls mbuf accumulation in the kernel without an upper bound check.
GREP: ct->ct_record_resid

### Round 3: ✅ VALID

The vulnerability exists in `clnt_vc_soupcall`. The function reads a 4-byte header from the network and sets `ct->ct_record_resid = header & 0x7fffffff;`. This allows an attacker to specify a record size up to 2GB. The code then enters a loop that calls `soreceive()` and appends the resulting mbuf chains to `ct->ct_record` until `ct->ct_record_resid` reaches zero. There is no check on the maximum allowable value of `ct->ct_record_resid`. While `uio.uio_resid` is set to 1,000,000,000, this only limits a single `soreceive` call, not the cumulative size of the mbuf chain. In a kernel environment, allocating 2GB of mbufs is almost certain to exhaust the mbuf cluster pool, leading to a system-wide Denial of Service (DoS). The input comes directly from an untrusted network source via a socket.

CRUX: ct->ct_record_resid is set from untrusted network input (up to 2GB) and drives mbuf accumulation in the kernel without any upper bound validation.
GREP: ct->ct_record_resid

### Round 4: ✅ VALID

[ARBITER] In `clnt_vc_soupcall`, the code reads a 4-byte header from the network and calculates the record size using `ct->ct_record_resid = header & 0x7fffffff;`. This allow an attacker to specify a record size up to 2,147,483,647 bytes (~2GB). The function then accumulates mbufs into `ct->ct_record` until this value reaches zero. There is no upper-bound check on `ct->ct_record_resid` before the accumulation starts, enabling a remote attacker to exhaust kernel memory (mbuf clusters) by claiming a large record size and sending data slowly, leading to a Denial of Service.

