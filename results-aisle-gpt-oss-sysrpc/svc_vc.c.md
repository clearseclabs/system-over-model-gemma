# Scan: svc_vc.c

```json
[
  {
    "severity": "critical",
    "title": "Freeing uninitialised mbuf pointers in svc_vc_destroy",
    "function": "svc_vc_destroy",
    "description": "When a connection is accepted with svc_vc_create_conn() the cf_conn structure is allocated but its fields `mreq` and `mpending` are never initialised. If the remote end closes the socket immediately before any data is sent, svc_vc_destroy() will be called with these garbage pointers and perform `m_freem(cd->mreq)` and `m_freem(cd->mpending)`. This results in a kernel panic due to freeing an invalid address, which can be triggered by an attacker that connects to the RPC port and then closes the socket before the server processes any request. The bug enables a denial‑of‑service (DoS) but also potentially allows a local privilege escalation if the kernel does not guard the free operation."
  },
  {
    "severity": "high",
    "title": "Potential sockaddr copy overflow in svc_vc_create_conn",
    "function": "svc_vc_create_conn",
    "description": "The code copies the peer address into a fixed‑size `struct sockaddr_storage` with `memcpy(&xprt->xp_rtaddr, raddr, raddr->sa_len)`. The source length `raddr->sa_len` is taken directly from the caller‐supplied `sockaddr` pointer without any bounds check. If an attacker can control a socket that advertises a peer address whose `sa_len` field is larger than 128 bytes (the size of `sockaddr_storage`), the memcpy will overflow the destination and corrupt adjacent kernel memory. This can lead to arbitrary memory corruption, potentially enabling code execution or privilege escalation."
  },
  {
    "severity": "medium",
    "title": "Incorrect record‑length calculation in svc_vc_reply / svc_vc_backchannel_reply",
    "function": ["svc_vc_reply","svc_vc_backchannel_reply"],
    "description": "The reply record length is computed as `htonl(0x80000000 | (len - sizeof(uint32_t)))` where `len` is the total length of the mbuf chain (`mrep->m_pkthdr.len`). If `len` exceeds `INT_MAX`, the subtraction and bitwise OR can wrap, producing a malformed record header. A crafted response with a very large payload could therefore cause the client to read an incorrect length, potentially leading to read overruns or corrupting its own state. While the kernel limits `len` to `TLS_MAX_MSG_SIZE_V10_2` in TLS mode, the unchecked path in non‑TLS mode may overflow when extremely large mbuf chains are constructed."
  },
  {
    "severity": "low",
    "title": "Missing error handling in svc_vc_create after solisten",
    "function": "svc_vc_create",
    "description": "The function calls `solisten(so, -1, curthread)` and completely ignores its return value. If `solisten` fails, the socket is left in an inconsistent state but the rest of the code proceeds as if it succeeded, potentially leading to resource leaks or undefined behaviour. This is unlikely to be directly exploitable but represents a safety‑critical flaw in kernel life‑cycle management."
  }
]
```