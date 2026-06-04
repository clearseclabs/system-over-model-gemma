# Triage T0117: Potential logic error from improper success check on bindresvport

- **File**: `svc_generic.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UIU→I]

---

## Finding

Potential logic error from improper success check on bindresvport

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** The bindresvport return value is correctly interpreted as error (non‑zero) – no logic bug.

The code uses bindresvport correctly: the function returns 0 on success and a non‑zero error code on failure. The 'if (bindresvport…) { … }' block is executed only when bindresvport fails, in which case the code falls back to binding an anonymous port (or aborts in the bind‑address case). Therefore the conditional does not invert the success flag and there is no logic error that an attacker could exploit. No untrusted input reaches the bindresvport call except for the optional bind address supplied via svc_tp_create, which is validated by uaddr2taddr. The error handling path safely closes the socket and returns NULL. Hence the scanner report is a false positive and the bug pattern does not exist.


CRUX: The bindresvport return value is correctly interpreted as error (non‑zero) – no logic bug.

GREP: bindresvport

🔎 **Grep results:**

GREP `bindresvport`:
```
crypto/krb5/src/include/gssrpc/rename.h:168:#define bindresvport		gssrpc_bindresvport
crypto/krb5/src/include/gssrpc/rename.h:169:#define bindresvport_sa		gssrpc_bindresvport_sa
contrib/tnftp/tnftp.h:479:#define bindresvport	Rbindresvport
include/rpc/rpc.h:80:extern int bindresvport(int, struct sockaddr_in *);
include/rpc/rpc.h:91:extern int bindresvport_sa(int, struct sockaddr *);
sys/rpc/rpc_com.h:110:extern int bindresvport(struct socket *so, struct sockaddr *sa);
sys/rpc/rpc.h:90:extern int bindresvport(int, struct sockaddr_in *);
sys/rpc/rpc.h:102:extern int bindresvport_sa(int, struct sockaddr *);
crypto/krb5/src/include/gssrpc/rpc.h:69:extern int bindresvport(int, struct sockaddr_in *);
crypto/krb5/src/include/gssrpc/rpc.h:70:extern int bindresvport_sa(int, struct sockaddr *);
crypto/openssh/config.h:247:/* Define to 1 if you have the 'bindresvport_sa' function. */
crypto/openssh/openbsd-compat/openbsd-compat.h:69:int bindresvport_sa(int sd, struct sockaddr *sa);
usr.sbin/rpc.statd/statd.c:228:					    "bindresvport_sa: %m");
usr.sbin/rpc.statd/statd.c:481:		r = bindresvport_sa(fd, res->ai_addr);
usr.sbin/rpc.statd/statd.c:491:			syslog(LOG_ERR, "bindresvport_sa: %m");
usr.sbin/ypserv/yp_main.c:304:				if (bindresvport_sa(s, res->ai_addr) == -1) {
usr.sbin/rpc.lockd/lock_proc.c:275:	/* Get the FD of the client, for bindresvport. */ 
usr.sbin/rpc.lockd/lock_proc.c:278:	/* Regain root privileges, for bindresvport. */
usr.sbin/rpc.lockd/lock_proc.c:289:	bindresvport(clnt_fd, NULL);
usr.sbin/rpc.lockd/lockd.c:355:							 "bindresvport_sa: %m");
usr.sbin/rpc.lockd/lockd.c:680:			r = bindresvport_sa(fd, res->ai_addr);
usr.sbin/rpc.lockd/lockd.c:690:				syslog(LOG_ERR, "bindresvport_sa: %m");
usr.sbin/mountd/mountd.c:678:							    "bindresvport_sa:"
usr.sbin/mountd/mountd.c:996:		r = bindresvport_sa(fd, res->ai_addr);
usr.sbin/mountd/mountd.c:1006:			syslog(LOG_ERR, "bindresvport_sa: %m");
lib/libc/rpc/bindresvport.c:1:/*	$NetBSD: bindresvport.c,v 1.19 2000/07/06 03:03:59 christos Exp $	*/
lib/libc/rpc/bindresvport.c:33:/* from: $OpenBSD: bindresvport.c,v 1.7 1996/07/30 16:25:47 downsj Exp $ */
lib/libc/rpc/bindresvport.c:59:bindresvport(int sd, struct sockaddr_in *sin)
lib/libc/rpc/bindresvport.c:61:	return bindresvport_sa(sd, (struct sockaddr *)sin);
lib/libc/rpc/bindresvport.c:68:bindresvport_sa(int sd, struct sockaddr *sa)
```

### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] `bindresvport()` returns 0 on success and a non‑zero error code on failure. The code checks `if (bindresvport(...))` and treats a non‑zero return as failure, which is correct. It does not invert the logic, so there is no unbound socket being used. The observed behaviour matches normal semantics; therefore the claim of a logic error is unfounded.

