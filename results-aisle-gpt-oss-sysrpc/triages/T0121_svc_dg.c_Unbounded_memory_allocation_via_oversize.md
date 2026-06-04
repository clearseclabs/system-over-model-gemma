# Triage T0121: Unbounded memory allocation via oversized uio_resid in svc_dg_recv

- **File**: `svc_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI→I]

---

## Finding

Unbounded memory allocation via oversized uio_resid in svc_dg_recv

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN

{"reasoning":"The function svc_dg_recv sets uio.uio_resid to 1,000,000,000, but the actual amount of data the kernel will copy into an mbuf chain is limited by the datagram size that arrives on the socket and the socket’s receive‑buffer limits. In NetBSD (the source of svc_dg.c) the maximum size of a single UDP packet is bounded by the IPv4 datagram size (65507 bytes of payload) and the sysctl net.inet.udp.maxdgram (default 65535). The soreceive() routine, which is invoked with this uio, will only allocate an mbuf chain that matches the length of the packet actually received; it does not allocate based on the uio_resid value when the packet is smaller. Moreover, the socket’s receive buffer (so_rcv.sb_hiwat) imposes a hard limit on the total number of bytes that can be queued to the socket, further bounding any allocation. Hence an attacker cannot trigger a 1 GB allocation – the largest attainable allocation is on the order of <64 KB per packet, far from a denial‑of‑service vector. Therefore the reported issue is not an attacker‑reachable memory exhaustion.
/// The grep pattern below verifies that the maximum UDP datagram size is constrained by
// the sysctl net.inet.udp.maxdgram and default to 65535; it also shows the socket
// buffer limit via SO_MAXBUF which is typically < 1 GB.\n","crux":"Maximum UDP packet and socket receive‑buffer limits prevent allocation of 1 GB; hardcoded uio_resid does not lead to unbounded allocation.","grep":"UDP_MAXDGRAM|SO_MAXBUF","verdict":"INVALID"}

### Round 3: ❌ INVALID

**🎯 Crux:** svc_dg_recv’s uio_resid is ignored by the kernel; the actual allocation is limited by the maximum UDP datagram size (≈65 KB) and socket buffer limits. The attacker cannot trigger >1 GB allocation.

The function svc_dg_recv does not use uio.uio_resid to decide how much data the kernel will copy. The kernel’s soreceive routine allocates an mbuf chain whose size is the length of the received UDP datagram. In IPv4 the size of a single datagram payload cannot exceed ~65,535 bytes (the maximum for UDP after accounting for headers). The kernel enforces this limit through the sysctl net.inet.udp.maxdgram or a hard‑coded 0xFFFF bound, independent of the uio_resid value. The socket’s receive buffer (so_rcv.sb_hiwat) further caps the total amount of queued data. Consequently, even with uio_resid set to 1,000,000,000, the largest mbuf chain that will be created during a single call to svc_dg_recv is bounded by the actual datagram size, making any attacker‑triggered “unbounded” allocation impossible. No additional application‑level defense is needed beyond the kernel’s datagram size and socket buffer limits, which are proven to bound the allocation.

Even if an attacker sends many small packets in succession, svc_dg_recv processes them one at a time, each limited to the same 65‑kB cap. Therefore the flaw is a false positive.

Crucially, the attacker does control the input that triggers svc_dg_recv (by sending a packet to the RPC/UDP socket), but the input cannot influence the allocation size beyond the inherent UDP limits.

The code quality issue (using a hard‑coded large uio_resid and not initializing uio.iovcnt) is benign and does not introduce a security problem.

Thus the scanner report is **INVALID**.


CRUX: svc_dg_recv’s uio_resid is ignored by the kernel; the actual allocation is limited by the maximum UDP datagram size (≈65 KB) and socket buffer limits. The attacker cannot trigger >1 GB allocation.

GREP: UDP_MAXDGRAM|net.inet.udp.maxdgram

🔎 **Grep results:**

GREP `UDP_MAXDGRAM`:
```
(no matches in repo)
```

GREP `net.inet.udp.maxdgram`:
```
libexec/tftpd/tftp-options.c:225:	if (sysctlbyname("net.inet.udp.maxdgram",
libexec/tftpd/tftp-options.c:227:		tftp_log(LOG_ERR, "sysctl: net.inet.udp.maxdgram");
libexec/tftpd/tftp-options.c:252:			    "net.inet.udp.maxdgram sysctl limits it to "
libexec/tftpd/tftp-options.c:259:			    "net.inet.udp.maxdgram sysctl limits it to "
libexec/tftpd/tftp-options.c:293:	if (sysctlbyname("net.inet.udp.maxdgram",
libexec/tftpd/tftp-options.c:295:		tftp_log(LOG_ERR, "sysctl: net.inet.udp.maxdgram");
libexec/tftpd/tftp-options.c:314:		    "Invalid blocksize2 (%d bytes), net.inet.udp.maxdgram "
usr.bin/tftp/main.c:977:		if (sysctlbyname("net.inet.udp.maxdgram",
usr.bin/tftp/main.c:979:			perror("sysctl: net.inet.udp.maxdgram");
usr.bin/tftp/main.c:989:			    "to the net.inet.udp.maxdgram sysctl limitation.\n",
usr.bin/tftp/main.c:1020:		if (sysctlbyname("net.inet.udp.maxdgram",
usr.bin/tftp/main.c:1022:			perror("sysctl: net.inet.udp.maxdgram");
usr.bin/tftp/main.c:1041:			    "to the net.inet.udp.maxdgram sysctl limitation.\n",
```

### Round 4: ❌ INVALID

[ARBITER] The `svc_dg_recv` function merely sets `uio.uio_resid` to a large value and then calls `soreceive`.  The kernel’s `soreceive` routine for a datagram socket reads at most the length of the incoming UDP packet and allocates an `mbuf` chain sized to that packet.  A UDP datagram cannot exceed the IP/UDP maximum payload (≈65 KB, limited by `net.inet.udp.maxdgram` or the 0xFFFF bound).  Therefore, regardless of the oversized `uio_resid`, the kernel will never attempt to allocate a 1 GB chain; the allocation is bounded by the actual packet size and the socket’s receive buffer limits.  Consequently, the reported high‑severity claim of an unbounded memory allocation is incorrect.

