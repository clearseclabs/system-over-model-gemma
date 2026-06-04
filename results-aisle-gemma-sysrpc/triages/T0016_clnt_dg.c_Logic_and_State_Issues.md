# Triage T0016: Logic and State Issues

- **File**: `clnt_dg.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Logic and State Issues

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The XID is a sequential global counter, and clnt_dg_soupcall matches replies solely on XID. With authnone (the default), an attacker can inject forged RPC replies by predicting the XID.

I analyzed the two reported issues: 

1. **Congestion Window Overflow/Divide-by-Zero**: The calculation is `cu->cu_cwnd += (CWNDSCALE * CWNDSCALE + cu->cu_cwnd / 2) / cu->cu_cwnd;`. 
- CWNDSCALE is 256. `CWNDSCALE * CWNDSCALE` = 65536. 
- `cu->cu_cwnd` is initialized to `MAXCWND / 2` (4096). 
- In the retransmit block, `cu->cu_cwnd` is halved but floored at `CWNDSCALE` (256). 
- Therefore, `cu->cu_cwnd` is always >= 256. 
- Max value of numerator: `65536 + (8192 / 2) = 69632`, which fits easily in a 32-bit `int`. 
- Since `cu->cu_cwnd >= 256`, division by zero is impossible and overflow is impossible. This is INVALID.

2. **XID Predictability**: The `rpc_xid` is indeed a global counter incremented by `atomic_fetchadd_32`. This makes it sequential and predictable. In `clnt_dg_soupcall`, the code matches incoming packets to pending requests using only the XID: `if (cr->cr_xid == xid)`. 
- An attacker can observe a request, predict the XID of subsequent requests, and send a forged UDP packet with that XID. 
- If the attacker can successfully spoof the source IP/port of the RPC server, they can inject a forged reply. 
- While many RPC calls use `AUTH_VALIDATE`, `clnt_dg_create` initializes the client with `authnone_create()` (null authentication) by default. For calls using `authnone`, there is no cryptographic verification of the reply, meaning the XID is the only 'secret' preventing reply injection. 
- Forged replies can cause the client to process fake data or trigger errors in the application logic, which is a security-relevant issue (denial of service or data corruption/spoofing).

CRUX: The XID is a sequential global counter, and clnt_dg_soupcall matches replies solely on XID. With authnone (the default), an attacker can inject forged RPC replies by predicting the XID.
GREP: authnone_create

🔎 **Grep results:**

GREP `authnone_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:65:#define authnone_create		gssrpc_authnone_create
include/rpc/auth.h:250:extern AUTH *authnone_create(void);		/* takes no parameters */
sys/rpc/auth.h:246:extern AUTH *authnone_create(void);		/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:192:extern AUTH *authnone_create(void);		/* takes no parameters */
usr.sbin/rpcbind/rpcb_svc_com.c:825:		auth = authnone_create();
usr.sbin/rpcbind/rpcb_svc_com.c:834:			auth = authnone_create();
lib/libc/rpc/auth_none.c:74:authnone_create(void)
lib/libc/rpc/clnt_raw.c:131:	client->cl_auth = authnone_create();
lib/libc/rpc/clnt_vc.c:294:	cl->cl_auth = authnone_create();
lib/libc/rpc/clnt_dg.c:285:	cl->cl_auth = authnone_create();
sys/fs/nfs/nfs_commonkrpc.c:836:		auth = authnone_create();
sys/rpc/auth_none.c:100:authnone_create(void)
sys/rpc/clnt_nl.c:227:		.cl_auth = authnone_create(),
sys/rpc/clnt_bck.c:170:	cl->cl_auth = authnone_create();
sys/rpc/clnt_rc.c:119:	cl->cl_auth = authnone_create();
sys/rpc/clnt_vc.c:259:	cl->cl_auth = authnone_create();
sys/rpc/clnt_dg.c:311:	cl->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/auth_none.c:77:authnone_create(void)
crypto/krb5/src/lib/rpc/clnt_tcp.c:233:	h->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_raw.c:129:	client->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_udp.c:204:	cl->cl_auth = authnone_create();
```

### Round 2: ✅ VALID

**🎯 Crux:** XIDs are sequential and predictable, and clnt_dg_soupcall matches replies solely on XID. When using the default authnone, there is no mechanism to verify the authenticity of the reply, allowing for blind injection of forged RPC responses.

I evaluated the two reported issues. 

1. **Congestion Window**: The formula `cu->cu_cwnd += (CWNDSCALE * CWNDSCALE + cu->cu_cwnd / 2) / cu->cu_cwnd` is safe. `CWNDSCALE` is 256, so `CWNDSCALE * CWNDSCALE` is 65536. `cu->cu_cwnd` is initialized to `MAXCWND/2` (4096) and is floored at `CWNDSCALE` (256) during retransmission. The numerator maxes at ~69632 (well within 32-bit `int`), and the denominator is always at least 256. No overflow or divide-by-zero is possible.

2. **XID Predictability**: The `rpc_xid` is a global volatile `uint32_t` incremented by `atomic_fetchadd_32`. This is strictly sequential. `clnt_dg_soupcall` matches replies to pending requests using only the XID (`if (cr->cr_xid == xid)`). For RPC calls using `AUTH_NONE` (which is the default assigned in `clnt_dg_create`), there is no cryptographic verification of the reply. An attacker capable of spoofing the server's IP/port can predict the next XID and inject a forged reply packet. This allows the attacker to inject arbitrary data into the client's RPC response buffer, leading to potential application-level logic errors or crashes depending on how the `results` are processed by the specific RPC procedure. This is a classic RPC vulnerability when using unauthenticated transports.

CRUX: XIDs are sequential and predictable, and clnt_dg_soupcall matches replies solely on XID. When using the default authnone, there is no mechanism to verify the authenticity of the reply, allowing for blind injection of forged RPC responses.
GREP: authnone_create

🔎 **Grep results:**

GREP `authnone_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:65:#define authnone_create		gssrpc_authnone_create
sys/rpc/auth.h:246:extern AUTH *authnone_create(void);		/* takes no parameters */
include/rpc/auth.h:250:extern AUTH *authnone_create(void);		/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:192:extern AUTH *authnone_create(void);		/* takes no parameters */
usr.sbin/rpcbind/rpcb_svc_com.c:825:		auth = authnone_create();
usr.sbin/rpcbind/rpcb_svc_com.c:834:			auth = authnone_create();
sys/fs/nfs/nfs_commonkrpc.c:836:		auth = authnone_create();
sys/rpc/clnt_rc.c:119:	cl->cl_auth = authnone_create();
sys/rpc/auth_none.c:100:authnone_create(void)
sys/rpc/clnt_bck.c:170:	cl->cl_auth = authnone_create();
sys/rpc/clnt_nl.c:227:		.cl_auth = authnone_create(),
sys/rpc/clnt_vc.c:259:	cl->cl_auth = authnone_create();
sys/rpc/clnt_dg.c:311:	cl->cl_auth = authnone_create();
lib/libc/rpc/auth_none.c:74:authnone_create(void)
lib/libc/rpc/clnt_raw.c:131:	client->cl_auth = authnone_create();
lib/libc/rpc/clnt_vc.c:294:	cl->cl_auth = authnone_create();
lib/libc/rpc/clnt_dg.c:285:	cl->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/auth_none.c:77:authnone_create(void)
crypto/krb5/src/lib/rpc/clnt_tcp.c:233:	h->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_raw.c:129:	client->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_udp.c:204:	cl->cl_auth = authnone_create();
```

### Round 3: ✅ VALID

**🎯 Crux:** XIDs are sequential and predictable, and clnt_dg_soupcall matches replies solely on XID. When using the default authnone, there is no mechanism to verify the authenticity of the reply, allowing for blind injection of forged RPC responses.

I have evaluated the two reported issues. 

1. **Congestion Window**: The formula `cu->cu_cwnd += (CWNDSCALE * CWNDSCALE + cu->cu_cwnd / 2) / cu->cu_cwnd` is safe from both overflow and division-by-zero. `CWNDSCALE` is 256, so `CWNDSCALE * CWNDSCALE` is 65,536. The `cu->cu_cwnd` is initialized to `MAXCWND / 2` (4,096) and is explicitly floored at `CWNDSCALE` (256) during retransmission (`if (cu->cu_cwnd < CWNDSCALE) cu->cu_cwnd = CWNDSCALE;`). The numerator maxes at roughly 69,632, and the denominator is always at least 256. This is a non-issue.

2. **XID Predictability**: The XID is generated using `atomic_fetchadd_32(&rpc_xid, 1)`, meaning it is a strictly sequential global counter. In `clnt_dg_soupcall`, incoming packets are matched to pending requests solely by comparing this XID (`if (cr->cr_xid == xid)`). While the client allows for other authentication methods, `clnt_dg_create` initializes the client with `authnone_create()` by default. For requests using `authnone`, the `AUTH_VALIDATE` macro effectively performs no cryptographic check on the reply. Therefore, an attacker who can spoof the server's IP and port can predict the next XID and inject a forged RPC reply. This can lead to the client processing malicious data as a legitimate response, causing application-level logic errors or potential crashes (DoS). This is a legitimate security vulnerability in the context of unauthenticated RPC over UDP.

CRUX: XIDs are sequential and predictable, and clnt_dg_soupcall matches replies solely on XID. When using the default authnone, there is no mechanism to verify the authenticity of the reply, allowing for blind injection of forged RPC responses.
GREP: authnone_create

🔎 **Grep results:**

GREP `authnone_create`:
```
crypto/krb5/src/include/gssrpc/rename.h:65:#define authnone_create		gssrpc_authnone_create
include/rpc/auth.h:250:extern AUTH *authnone_create(void);		/* takes no parameters */
crypto/krb5/src/include/gssrpc/auth.h:192:extern AUTH *authnone_create(void);		/* takes no parameters */
sys/rpc/auth.h:246:extern AUTH *authnone_create(void);		/* takes no parameters */
usr.sbin/rpcbind/rpcb_svc_com.c:825:		auth = authnone_create();
usr.sbin/rpcbind/rpcb_svc_com.c:834:			auth = authnone_create();
crypto/krb5/src/lib/rpc/auth_none.c:77:authnone_create(void)
crypto/krb5/src/lib/rpc/clnt_raw.c:129:	client->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_tcp.c:233:	h->cl_auth = authnone_create();
crypto/krb5/src/lib/rpc/clnt_udp.c:204:	cl->cl_auth = authnone_create();
sys/fs/nfs/nfs_commonkrpc.c:836:		auth = authnone_create();
sys/rpc/auth_none.c:100:authnone_create(void)
sys/rpc/clnt_nl.c:227:		.cl_auth = authnone_create(),
sys/rpc/clnt_bck.c:170:	cl->cl_auth = authnone_create();
sys/rpc/clnt_rc.c:119:	cl->cl_auth = authnone_create();
sys/rpc/clnt_vc.c:259:	cl->cl_auth = authnone_create();
sys/rpc/clnt_dg.c:311:	cl->cl_auth = authnone_create();
lib/libc/rpc/auth_none.c:74:authnone_create(void)
lib/libc/rpc/clnt_raw.c:131:	client->cl_auth = authnone_create();
lib/libc/rpc/clnt_vc.c:294:	cl->cl_auth = authnone_create();
lib/libc/rpc/clnt_dg.c:285:	cl->cl_auth = authnone_create();
```

### Round 4: ✅ VALID

[ARBITER] The report identifies two issues. The first (Congestion Window) is invalid; calculation analysis shows the numerator is bounded (~69k) and the denominator is floored at 256, preventing overflow and divide-by-zero. However, the second issue (XID Predictability) is a valid security vulnerability. The code uses a global sequential counter (`rpc_xid`) for Transaction IDs. In `clnt_dg_soupcall`, incoming packets are matched to pending requests solely based on the XID. Because `clnt_dg_create` initializes the client with `authnone_create()` (null authentication), there is no cryptographic verification of the response. An attacker can predict the next XID and inject forged RPC responses to the client.

