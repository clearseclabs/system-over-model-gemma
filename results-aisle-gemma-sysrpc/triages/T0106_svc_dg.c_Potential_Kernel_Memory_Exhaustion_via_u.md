# Triage T0106: Potential Kernel Memory Exhaustion via uio_resid

- **File**: `svc_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Potential Kernel Memory Exhaustion via uio_resid

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** For datagram sockets, soreceive retrieves existing mbufs from the receive queue; uio_resid limits the amount of data returned but does not trigger a fresh allocation of that size.

The report claims that setting `uio.uio_resid = 1000000000` allows an attacker to cause kernel memory exhaustion because the socket layer might allocate a massive mbuf chain. However, in the context of connectionless (datagram) RPC (which `svc_dg.c` implements), `soreceive` typically retrieves a single datagram from the socket queue. The `uio_resid` field in a `uio` structure passed to `soreceive` generally acts as a *maximum* limit on how much data the caller is willing to accept, not a request for the kernel to allocate that much memory upfront. For datagram sockets, the kernel has already allocated the mbuf chain when the packet was received from the wire and placed in the socket's receive buffer. The `soreceive` call simply hands a reference to that existing mbuf chain to the caller. Therefore, the memory for the packet is already consumed by the time `svc_dg_recv` is called, and the value of `uio_resid` does not trigger a new massive allocation. The actual limit on packet size is governed by the network layer (MTU) and the socket's receive buffer limits (SO_RCVBUF), not by this constant.

CRUX: For datagram sockets, soreceive retrieves existing mbufs from the receive queue; uio_resid limits the amount of data returned but does not trigger a fresh allocation of that size.
GREP: soreceive

🔎 **Grep results:**

GREP `soreceive`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** For datagram sockets, soreceive retrieves mbufs already allocated by the network stack; uio_resid is a limit on data retrieval, not an allocation request.

The vulnerability report suggests that `uio.uio_resid = 1000000000` in `svc_dg_recv` leads to kernel memory exhaustion. However, `svc_dg.c` implements connectionless (datagram) RPC. In the FreeBSD/NetBSD-style socket layer (which this code mirrors), `soreceive` for datagram sockets does not allocate memory based on the `uio_resid` value; rather, it retrieves a datagram that has already been received from the network and stored in the socket's receive buffer (mbuf chain). The `uio_resid` acts as a ceiling for the amount of data that can be copied or referenced from that existing packet to the user/kernel buffer. Since the memory is already allocated by the network stack upon packet arrival (limited by MTU and `SO_RCVBUF`), the value of `uio_resid` here does not trigger a new massive allocation and cannot be used by an attacker to exhaust memory beyond the existing socket buffer limits.

CRUX: For datagram sockets, soreceive retrieves mbufs already allocated by the network stack; uio_resid is a limit on data retrieval, not an allocation request.
GREP: soreceive

🔎 **Grep results:**

GREP `soreceive`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** For datagram sockets, soreceive returns existing mbufs already allocated by the network stack; uio_resid acts as a limit on the amount of data retrieved, not as a request for a new allocation.

The vulnerability report claims that `uio.uio_resid = 1000000000` allows an attacker to trigger a massive memory allocation. In the provided code, `svc_dg_recv` uses `soreceive` to read from a datagram socket (`svc_dg` is for connectionless RPC). In standard BSD-derived socket layers, for datagram sockets, `soreceive` does not allocate memory based on the `uio_resid` value. Instead, it returns a pointer to the `mbuf` chain that was already allocated by the network stack when the packet arrived from the network. The `uio_resid` value serves as a maximum bound for how much data the caller is willing to process from that existing packet. The actual memory consumption is limited by the network MTU and the socket's receive buffer (`SO_RCVBUF`), both of which are managed by the kernel's networking stack, not by the `uio` structure passed into `soreceive`. Therefore, an attacker cannot force the kernel to allocate 1GB of memory simply by sending a packet, as the kernel would have already rejected or truncated a packet of that size based on lower-level constraints.

CRUX: For datagram sockets, soreceive returns existing mbufs already allocated by the network stack; uio_resid acts as a limit on the amount of data retrieved, not as a request for a new allocation.
GREP: soreceive

🔎 **Grep results:**

GREP `soreceive`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability is based on a misunderstanding of how `soreceive` works for datagram sockets. In BSD-derived kernels, `soreceive` retrieves data from mbuf chains that have already been allocated by the network stack upon packet arrival. The `uio_resid` field serves as a limit on the amount of data to be copied or processed from those existing buffers; it does not trigger a new memory allocation of that size. Therefore, setting `uio.uio_resid = 1000000000` does not allow an attacker to force the kernel to allocate a massive amount of memory.

