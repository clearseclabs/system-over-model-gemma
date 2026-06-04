# Scan: clnt_rc.c

```json
[
  {
    "severity": "critical",
    "title": "Unbounded memcpy of sockaddr into rc->rc_addr",
    "function": "clnt_reconnect_create",
    "description": "The function copies svcaddr->sa_len bytes into the struct field rc->rc_addr using memcpy without checking that the size of rc->rc_addr is large enough.  If the caller supplies an IPv6 address (or a spoofed address with sa_len > sizeof(struct sockaddr)), the memcpy will write beyond the bounds of rc->rc_addr, corrupting the rc structure on the heap and potentially overwriting kernel pointers.  This overflow can be exploited to execute arbitrary code or crash the kernel."
  },
  {
    "severity": "critical",
    "title": "Arbitrary kernel‑space function‑pointer execution via CLSET_RECONUPCALL",
    "function": "clnt_reconnect_control / clnt_reconnect_connect",
    "description": "The control operation CLSET_RECONUPCALL accepts a user‑controlled pointer to a struct rpc_reconupcall which contains a function pointer.  The code assigns rc->rc_reconcall = upcp->call without any validation.  In clnt_reconnect_connect it is later invoked as (*rc->rc_reconcall)(newclient, rc->rc_reconarg, rc->rc_ucred); while holding kernel privileges.  An attacker can supply a pointer to any kernel address or even a user‑land address, causing a crash or enabling arbitrary code execution in the kernel."
  },
  {
    "severity": "high",
    "title": "Unvalidated backchannel pointer in CLSET_BACKCHANNEL",
    "function": "clnt_reconnect_control",
    "description": "The CLSET_BACKCHANNEL request accepts a pointer of type SVCXPRT * from user space and assigns it to rc->rc_backchannel.  This pointer is later registered via xprt_register(), used in CLNT_CONTROL(..., CLSET_BACKCHANNEL, ...), and finally unregistered and released in clnt_reconnect_destroy() without validating that it points to a valid kernel object.  Arbitrary data written to rc->rc_backchannel can lead to memory corruption, use‑after‑free, or an assertion failure, resulting in a kernel panic or an unlockable race condition."
  },
  {
    "severity": "high",
    "title": "User‑controlled callback execution via rpc_callextra rc_feedback",
    "function": "clnt_reconnect_call",
    "description": "When a call fails with a non‑NULL rpc_callextra structure, clnt_reconnect_call invokes ext->rc_feedback(FEEDBACK_RECONNECT, …).  The callback pointer is supplied by user space and executed in kernel context.  This provides an arbitrary code‑execution vector that can be used to manipulate kernel state or privilege everything."
  },
  {
    "severity": "medium",
    "title": "Potential overruns when copying IPv6 addresses",
    "function": "clnt_reconnect_create",
    "description": "If svcaddr points to an IPv6 sockaddr, its sa_len can be up to 28 bytes while rc->rc_addr is likely a plain struct sockaddr of 16 bytes.  The memcpy in clnt_reconnect_create will overflow by up to 12 bytes, corrupting adjacent memory on the heap.  While not exploitable on its own, it weakens overall reliability and can be combined with other bugs."
  },
  {
    "severity": "medium",
    "title": "Use of potentially negative values for timeouts",
    "function": "clnt_reconnect_connect",
    "description": "The struct timeval rc->rc_timeout is copied directly into the socket options SO_SNDTIMEO.  An attacker can set the seconds or microseconds field to a negative value via CLSET_TIMEOUT.  Passing a negative timeout might cause the kernel to misbehave, return errors, or silently treat the timeout as zero, leading to potential denial‑of‑service or incorrect retry logic."
  }
]
```
