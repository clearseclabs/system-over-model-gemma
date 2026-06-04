# VULN-003: Unbounded memcpy of svcaddr during clnt_dg_create()

- **File**: `clnt_dg.c`
- **Confidence**: 50% [VUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Unbounded memcpy of svcaddr during clnt_dg_create()

The RPC client address supplied by the caller is copied into the kernel‑only field `cu->cu_raddr` via

    memcpy(&cu->cu_raddr, svcaddr, (size_t)svcaddr->sa_len);

`svcaddr->sa_len` originates from userland and is not bounded to the size of a `sockaddr_storage`.  An attacker can pass a very large value causing the memcpy to write past the 128‑byte buffer that `cu_raddr` occupies, corrupting arbitrary kernel memory (including the `cs` or `cl` structures) and providing a path to privilege escalation or denial‑of‑service.
  
  The same unchecked length is later stored in `cu->cu_rlen` and used for copy operations in `clnt_dg_control()` (see local copy of the socket address), further widening the impact.
  
  Fix: Validate `svcaddr->sa_len <= sizeof(cu->cu_raddr)` (or `sizeof(sockaddr_storage)`) before copying and reject the request otherwise.
  
  Threat model: An unprivileged user running an RPC client shim could construct a malicious `struct sockaddr` to overwrite kernel memory.
  
  Expected impact: Elevation of privilege or complete system compromise.
  

---

## Triage reasoning

### Round 1: ✅ VALID

The code in clnt_dg_create copies the caller‑supplied sockaddr into the kernel buffer cu->cu_raddr using memcpy(&cu->cu_raddr, svcaddr, (size_t)svcaddr->sa_len). The variable svcaddr->sa_len originates from user memory and is not bounded. The destination cu->cu_raddr is a struct sockaddr_storage, which in NetBSD is 128 bytes. There is no check that svcaddr->sa_len <= sizeof(cu->cu_raddr). Consequently an attacker can craft a struct sockaddr with an arbitrary (large) sa_len field and trigger this memcpy to overflow the buffer, corrupting kernel memory and potentially allowing privilege escalation. No defensive bound is present; the code proceeds directly to the memcpy. Thus the vulnerability pattern is real, attacker‑reachable and security‑relevant.

CRUX: Unchecked svcaddr->sa_len used as size for memcpy into fixed‑size sockaddr_storage (cu_raddr).
GREP: memcpy(&cu->cu_raddr, svcaddr

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code copies svcaddr into the kernel buffer cu->cu_raddr using memcpy, with the copy length taken directly from svcaddr->sa_len, which comes from user space and is not bounded. A sockaddr_storage in NetBSD is 128 bytes long; if svcaddr->sa_len >128 the memcpy overruns cu->cu_raddr, corrupting adjacent kernel data (such as cu_rlen or other structures). The kernel later uses cu->cu_rlen and cu->cu_raddr in more copies without bounds checking. Thus the unbounded memcpy provides a write‑to‑kernel memory vector, satisfying the threat model and making this a real critical vulnerability. No defensive checks or sanitization is present in the shown code, confirming the flaw is valid.

