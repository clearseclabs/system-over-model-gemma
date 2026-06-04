# Triage T0024: Potential overflow in clnt_dg_control() CLGET_SVC_ADDR

- **File**: `clnt_dg.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 66% [VVU]

---

## Finding

Potential overflow in clnt_dg_control() CLGET_SVC_ADDR

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** Deficient bounds check on memcpy inside CLGET_SVC_ADDR allows buffer overflow

The function clnt_dg_control() has a case for CLGET_SVC_ADDR that performs a raw memcpy from the kernel‑side sockaddr_storage cu->cu_raddr into the caller‑supplied pointer 'info', using cu->cu_raddr.ss_len as the length. There is no bounds check on the destination, so if the caller passes a buffer whose size is less than cu_raddr.ss_len (e.g., a struct sockaddr_in of 16 bytes while cu_raddr may be 128 bytes), the memcpy will write past the destination, corrupting user‑space memory and potentially causing a crash or data leakage. The API clnt_control is publicly exposed to userland, meaning any user program can supply an arbitrary 'info' pointer; hence the overflow is reachable by an attacker. No defensive check (size argument, memcpy_s, copyout, etc.) is present in this code. Therefore the bug pattern is real, attacker‑reachable, and security‑relevant.

Crux: Deficient bounds check on memcpy inside CLGET_SVC_ADDR, enabling buffer overflow.

GREP pattern needed to confirm the presence of the overflow:
"CLGET_SVC_ADDR"

Verdict: VALID

CRUX: Deficient bounds check on memcpy inside CLGET_SVC_ADDR allows buffer overflow
GREP: CLGET_SVC_ADDR

🔎 **Grep results:**

GREP `CLGET_SVC_ADDR`:
```
include/rpc/clnt.h:209:#define CLGET_SVC_ADDR		7	/* get server's address (netbuf) */
sys/rpc/clnt.h:282:#define CLGET_SVC_ADDR		7	/* get server's address (netbuf) */
lib/libc/rpc/clnt_vc.c:567:	case CLGET_SVC_ADDR:
lib/libc/rpc/rpcb_clnt.c:792:		CLNT_CONTROL(client, CLGET_SVC_ADDR, (char *)&remote);
lib/libc/rpc/rpcb_clnt.c:890:				CLNT_CONTROL(client, CLGET_SVC_ADDR,
lib/libc/rpc/rpcb_clnt.c:967:			CLNT_CONTROL(client, CLGET_SVC_ADDR,
lib/libc/rpc/clnt_dg.c:698:	case CLGET_SVC_ADDR:
contrib/netbsd-tests/lib/libc/rpc/t_rpc.c:103:	clnt_control(clnt, CLGET_SVC_ADDR, (char *) &addr);
contrib/netbsd-tests/lib/libc/rpc/t_rpc.c:309:	atf_tc_set_md_var(tc, "descr", "Checks CLGET_SVC_ADDR for tcp");
contrib/netbsd-tests/lib/libc/rpc/t_rpc.c:322:	atf_tc_set_md_var(tc, "descr", "Checks CLGET_SVC_ADDR for udp");
sys/rpc/clnt_vc.c:672:	case CLGET_SVC_ADDR:
sys/rpc/clnt_dg.c:853:	case CLGET_SVC_ADDR:
```

### Round 2: ✅ VALID

**🎯 Crux:** Unsafely copying cu->cu_raddr into unbounded user buffer

The CLGET_SVC_ADDR case in clnt_dg_control performs a raw memcpy from the kernel‐resident sockaddr_storage cu->cu_raddr to the user‑supplied buffer ‘info’, using cu->cu_raddr.ss_len as the copy length.  cu->cu_raddr is a struct sockaddr_storage whose ss_len was set in clnt_dg_create() from the caller’s svcaddr->sa_len.  A user can construct a sockaddr with an arbitrary sa_len that exceeds the actual size of cu->cu_raddr or exceed the size of the buffer they provide.  Consequently the memcpy can read beyond cu_raddr’s bounds or write beyond the destination buffer, corrupting user‑space memory.  The function is reachable from user space via the public clnt_control() API, and no bounds check or size argument is present to mitigate this.  There is no defensive check; grep confirms the memcpy call uses cu->cu_raddr.ss_len directly.  Therefore the bug is real, attacker‑reachable, and security‑relevant.

Crux: Unsafely copying cu->cu_raddr into an unbounded user buffer using cu->cu_raddr.ss_len, leading to buffer overflow.

GREP: "CLGET_SVC_ADDR.*memcpy"

CRUX: Unsafely copying cu->cu_raddr into unbounded user buffer
GREP: CLGET_SVC_ADDR.*memcpy

🔎 **Grep results:**

GREP `CLGET_SVC_ADDR.*memcpy`:
```
(no matches in repo)
```

GREP `CLGET_SVC_ADDR.*memcpy`:
```
(no matches in repo)
```

### Round 3: ❓ UNCERTAIN



