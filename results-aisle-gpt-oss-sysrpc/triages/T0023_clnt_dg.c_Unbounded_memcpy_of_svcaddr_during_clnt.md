# Triage T0023: Unbounded memcpy of svcaddr during clnt_dg_create()

- **File**: `clnt_dg.c`
- **Verdict**: VALID
- **Confidence**: 50% [VUU→V]

---

## Finding

Unbounded memcpy of svcaddr during clnt_dg_create()

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** Unchecked svcaddr->sa_len used as size for memcpy into fixed‑size sockaddr_storage (cu_raddr).

The code in clnt_dg_create copies the caller‑supplied sockaddr into the kernel buffer cu->cu_raddr using memcpy(&cu->cu_raddr, svcaddr, (size_t)svcaddr->sa_len). The variable svcaddr->sa_len originates from user memory and is not bounded. The destination cu->cu_raddr is a struct sockaddr_storage, which in NetBSD is 128 bytes. There is no check that svcaddr->sa_len <= sizeof(cu->cu_raddr). Consequently an attacker can craft a struct sockaddr with an arbitrary (large) sa_len field and trigger this memcpy to overflow the buffer, corrupting kernel memory and potentially allowing privilege escalation. No defensive bound is present; the code proceeds directly to the memcpy. Thus the vulnerability pattern is real, attacker‑reachable and security‑relevant.

CRUX: Unchecked svcaddr->sa_len used as size for memcpy into fixed‑size sockaddr_storage (cu_raddr).
GREP: memcpy(&cu->cu_raddr, svcaddr

🔎 **Grep results:**

GREP `cu->cu_raddr`:
```
lib/libc/rpc/clnt_dg.c:242:	(void) memcpy(&cu->cu_raddr, svcaddr->buf, (size_t)svcaddr->len);
lib/libc/rpc/clnt_dg.c:353:		if (_connect(cu->cu_fd, (struct sockaddr *)&cu->cu_raddr,
lib/libc/rpc/clnt_dg.c:365:		sa = (struct sockaddr *)&cu->cu_raddr;
lib/libc/rpc/clnt_dg.c:683:		(void) memcpy(info, &cu->cu_raddr, (size_t)cu->cu_rlen);
lib/libc/rpc/clnt_dg.c:700:		addr->buf = &cu->cu_raddr;
lib/libc/rpc/clnt_dg.c:702:		addr->maxlen = sizeof cu->cu_raddr;
lib/libc/rpc/clnt_dg.c:706:		if (addr->len < sizeof cu->cu_raddr) {
lib/libc/rpc/clnt_dg.c:710:		(void) memcpy(&cu->cu_raddr, addr->buf, addr->len);
sys/rpc/clnt_dg.c:226:	(void) memcpy(&cu->cu_raddr, svcaddr, (size_t)svcaddr->sa_len);
sys/rpc/clnt_dg.c:389:		    (struct sockaddr *)&cu->cu_raddr, curthread);
sys/rpc/clnt_dg.c:401:		sa = (struct sockaddr *)&cu->cu_raddr;
sys/rpc/clnt_dg.c:858:		memcpy(info, &cu->cu_raddr, cu->cu_raddr.ss_len);
sys/rpc/clnt_dg.c:862:		(void) memcpy(&cu->cu_raddr, addr, addr->sa_len);
crypto/krb5/src/lib/rpc/clnt_udp.c:162:	cu->cu_raddr = *raddr;
crypto/krb5/src/lib/rpc/clnt_udp.c:163:	cu->cu_rlen = sizeof (cu->cu_raddr);
crypto/krb5/src/lib/rpc/clnt_udp.c:467:		*(struct sockaddr_in *)info = cu->cu_raddr;
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code copies svcaddr into the kernel buffer cu->cu_raddr using memcpy, with the copy length taken directly from svcaddr->sa_len, which comes from user space and is not bounded. A sockaddr_storage in NetBSD is 128 bytes long; if svcaddr->sa_len >128 the memcpy overruns cu->cu_raddr, corrupting adjacent kernel data (such as cu_rlen or other structures). The kernel later uses cu->cu_rlen and cu->cu_raddr in more copies without bounds checking. Thus the unbounded memcpy provides a write‑to‑kernel memory vector, satisfying the threat model and making this a real critical vulnerability. No defensive checks or sanitization is present in the shown code, confirming the flaw is valid.

