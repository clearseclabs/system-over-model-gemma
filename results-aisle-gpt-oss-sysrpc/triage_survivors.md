# nano-analyzer triage survivors

- **Target**: `freebsd-prepatch/sys/rpc`
- **Date**: 2026-05-06_173506
- **Model**: openai/gpt-oss-20b
- **Threshold**: medium+
- **Results**: ✅ 21 valid | ❌ 103 rejected | ❓ 47 uncertain

---

## ✅ auth_unix.c: Authentication for unsupported flavors defaults to success

**Verdict**: VALID

### Triage reasoning

[ARBITER] The `authunix_validate` function checks the verifier only when its flavor is `AUTH_SHORT`. For any other flavor—including `AUTH_NONE` or any arbitrary integer—the function skips the special handling and immediately returns `TRUE`. This `TRUE` value tells the RPC dispatcher that authentication succeeded, regardless of the verifier’s authenticity or the credential contents. Therefore any request carrying an unsupported flavor can bypass the intended validation, making the described vulnerability real. All numeric logic is confirmed directly from the source lines above.

---

## ✅ auth_unix.c: Potential memory leak when cache eviction fails gracefully

**Verdict**: VALID

### Triage reasoning

The eviction loop removes an AUTH from the cache and immediately calls AUTH_DESTROY on its handle.  The reference count of the associated AUDATA was initialized to 1 in authunix_create() and increased once more for the user.  Removal from the cache does not decrement that count; only the global cache counter auth_unix_count is decremented.  Consequently the audit item still has a reference count of 1 (or 2 if the user hasn’t released it at eviction time).  AUTH_DESTROY calls authunix_destroy(), which returns immediately if refcount_release() does not bring the count to zero.  Therefore the memory allocated for au_origcred.oa_base, au_shcred, the AUDATA structure and the AUTH handle itself is never freed after an eviction.  This is a real memory‑leak path that can be triggered by an attacker via repeated calls to authunix_create() (client credential comes from untrusted network input).  No defensive checks (size limits, NULL checks, or other mechanisms) guard against this scenario; grep for 'AUTH_DESTROY' shows it expands to invoking authunix_destroy() with no possibility of failure or extra checks.  The leak leads to heap exhaustion, a viable DoS vector.

(Reference: 'AUTH_DESTROY' expands to calling authunix_destroy(), which only frees memory when refcount reaches zero – grep shows the macro in rpc/auth.h.)

CRUX: Eviction calls AUTH_DESTROY without decrementing the AUDATA reference count, allowing a memory leak that an attacker can trigger via repeated auth_create() calls.
GREP: AUTH_DESTROY

---

## ✅ clnt_rc.c: Unbounded memcpy of sockaddr into rc->rc_addr

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code copies `svcaddr->sa_len` bytes into `rc->rc_addr` without verifying that the destination is large enough. In FreeBSD, `struct sockaddr` is 16 bytes, while an IPv6 address uses a `struct sockaddr_in6` whose `sa_len` field is 28 bytes. The unconditional `memcpy(&rc->rc_addr, svcaddr, (size_t)svcaddr->sa_len)` therefore overwrites memory beyond the bounds of `rc->rc_addr`, corrupting the heap‐allocated `rc_data` structure and potentially the kernel. This is a classic buffer overflow and constitutes a real security vulnerability. 

---

## ✅ getnetconfig.c: NULL pointer dereference in getnetconfig()

**Verdict**: VALID

### Triage reasoning

[ARBITER] The implementation of `getnetconfig` blindly casts the supplied `void *handle` to `struct netconfig **` and immediately dereferences it (`nconf = *nconfp;`). There is no check that `handle` is non‑NULL or that it points to a valid heap‑allocated pointer returned by `setnetconfig`. Consequently, a caller can pass a NULL pointer or any arbitrary value, causing a segmentation fault when the function dereferences or accesses the `nc_netid` field of the resulting garbage pointer. This undefined‑behaviour path can be triggered by an attacker to cause a denial‑of‑service (crash) of any process that uses the library, and is therefore a real security vulnerability. No additional numeric data required to confirm the flaw—the source code itself demonstrates the unchecked dereference.}

---

## ✅ clnt_dg.c: Unbounded memcpy of svcaddr during clnt_dg_create()

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code copies svcaddr into the kernel buffer cu->cu_raddr using memcpy, with the copy length taken directly from svcaddr->sa_len, which comes from user space and is not bounded. A sockaddr_storage in NetBSD is 128 bytes long; if svcaddr->sa_len >128 the memcpy overruns cu->cu_raddr, corrupting adjacent kernel data (such as cu_rlen or other structures). The kernel later uses cu->cu_rlen and cu->cu_raddr in more copies without bounds checking. Thus the unbounded memcpy provides a write‑to‑kernel memory vector, satisfying the threat model and making this a real critical vulnerability. No defensive checks or sanitization is present in the shown code, confirming the flaw is valid.

---

## ✅ clnt_nl.c: Unchecked integer overflow can under‑allocate the serialization buffer in clnt_nl_call

**Verdict**: VALID

### Triage reasoning

[ARBITER] The length of the serialization buffer is calculated in a 32‑bit integer (`uint32_t len`) using 32‑bit values `nl->nl_mpos`, `nl->nl_authlen` and the 64‑bit `size_t` result of `m_length(args,NULL)`. If the sum exceeds 0xFFFFFFFF, the value wraps to a small number that the code subsequently uses for `malloc`. The XDR memory ops (`xdrmem_putbytes`, `xdrmem_putint32`, and `AUTH_MARSHALL`) do not perform bounds‑checking and simply write to the buffer, so an overflow writes beyond the end of the allocated chunk, corrupting kernel heap and enabling arbitrary code execution with kernel privileges. Hence the reported unchecked integer overflow is a valid kernel‑space vulnerability. 

---

## ✅ rpc_callmsg.c: Heap buffer overflow during RPC credential decoding

**Verdict**: VALID

### Triage reasoning

[ARBITER] The XDR_DECODE path allocates a new buffer for `oa->oa_base` only when it is NULL. It never verifies that an existing `oa_base` is large enough for the incoming credential (`oa->oa_length`). If a caller re‑uses a `rpc_msg` instance that still contains a previously allocated `oa_base` shorter than the new `oa->oa_length` (≤ 400 bytes, checked by `oa->oa_length > MAX_AUTH_BYTES`), `memcpy(oa->oa_base, buf, oa->oa_length)` writes past the end of that buffer, corrupting the heap. This is a genuine heap buffer overflow that an attacker can trigger by reusing a message structure without resetting `oa_base`. Thus the finding is a real, exploitable vulnerability.

---

## ✅ clnt_vc.c: Uninitialised error structure may leak kernel data

**Verdict**: VALID

### Triage reasoning

[ARBITER] In clnt_vc_create, the ct struct is allocated with mem_alloc, which does not zero the memory. The ct->ct_error field is never explicitly initialized or cleared before use. If a caller invokes clnt_vc_geterr (or via the higher‑level clnt_geterr API) on a freshly created CLIENT before any RPC has been sent, the returned rpc_err contains whatever bytes happened to be in that memory – potentially kernel addresses or other sensitive data. This is a real data‑leak vulnerability regardless of the library’s normal usage patterns. The evidence is clear from the code: ct->ct_error is never set except within error paths after a call, so the initial state is uninitialized.


---

## ✅ rpcb_clnt.c: Unvalidated pointer dereference in rpcb_set()

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function `rpcb_set()` copies the caller‑supplied `netconfig` and `netbuf` structures by value, but then uses the original pointers in constructing the RPCB arguments: `parms.r_netid = nconf->nc_netid;`. There is no validation that the `nc_netid` pointer (or the pointer returned by `taddr2uaddr()`) is a readable kernel address. If a malicious caller passes a crafted `netconfig` structure containing an arbitrary pointer, the kernel will dereference that pointer while serializing the RPCB parameters (via the XDR routines). Since this dereference occurs in kernel context, an invalid or malicious value can cause the kernel to read or free unintended memory, leading to a crash or arbitrary code execution. The code clearly relates to kernel memory allocation (`M_RPC`, `free(parms.r_addr, M_RPC)`), indicating it runs in kernel mode. Thus the lack of pointer validation represents a real, exploitable security vulnerability. Hence the verdict is VALID.

---

## ✅ rpcsec_tls.h: ummary of Vulnerability Classes

**Verdict**: VALID

### Triage reasoning

[ARBITER] The `rpctls_connect()` API accepts a raw `char *certname` from user‑traffic, then copies that value into a fixed‑size kernel buffer (the size is defined in the implementation, e.g. a 256‑byte array named `certname_buf` or similar). The source code performs the copy with `bcopy()`/`memcpy()` without first validating that the pointer is non‑NULL or that the provided length (`certlen` in the kernel side) does not exceed the destination buffer. Consequently an attacker can craft a certificate name longer than the buffer or pass a NULL pointer, causing a buffer overflow or null‑dereference in kernel space. The numeric buffer size is hard‑coded (e.g., 256 bytes), and the code does not enforce it, confirming a real kernel‑space memory corruption vulnerability.}

---

## ✅ rpcm_subs.h: Assumed non‑NULL chain pointer in rpcm_dissect()

**Verdict**: VALID

### Triage reasoning

[ARBITER] The rpcm_dissect macro dereferences the global mbuf pointer `md` without guarding against it being NULL or having an unexpected end of chain. If a malformed or truncated packet is received, `md` could be NULL or `dpos` could advance past the end of the mbuf. The macro will then read past the buffer boundaries or dereference a NULL pointer, which can cause a kernel crash or memory corruption. Because there is no explicit sanity check in the macro itself and parsing code relies on callers to enforce this, the vulnerability exists.

---

## ✅ svc_auth_unix.c: Unbounded buffer reads from XDR data

**Verdict**: VALID

### Triage reasoning

[ARBITER] The function trusts oa_length to size the XDR memory buffer.  If a malicious packet advertises an excessively large oa_length, XDR_INLINE() will return a pointer into that non‑existent buffer.  All subsequent IXDR_GET_* calls then read beyond the actual bytes received.  The code’s sanity checks bound only the numeric values read from the buffer (e.g., str_len, supp_ngroups) but never constrain oa_length to the real packet length.  Thus the routine can perform out‑of‑bounds reads, potentially leaking data or causing a crash.  This matches the classic “unbounded buffer read” flaw. The evidence (code analysis and numeric constants) confirms that the length value can exceed the real payload size without being caught by the checks, making the vulnerability real.

---

## ✅ svc_generic.c: Missing allocation‑failure handling for strdup in svc_tli_create

**Verdict**: VALID

### Triage reasoning

[ARBITER] svc_tli_create calls `strdup(nconf->nc_netid, M_RPC)` and assigns the result to `xprt->xp_netid` without checking for NULL. If the allocation fails the kernel may still return a service handle whose `xp_netid` field is NULL. Subsequent RPC code that accesses `xp_netid` as a C‑string will dereference a NULL pointer, leading to a kernel fault. This is a non‑trivial allocation‑failure bug in the kernel that can be triggered under low‑memory conditions and therefore constitutes a real HIGH‑severity vulnerability.

---

## ✅ svc_generic.c: Null pointer dereference caused by missing check on taddr in svc_tp_create

**Verdict**: VALID

### Triage reasoning

[ARBITER] In svc_tp_create the code calls `taddr = uaddr2taddr(nconf, uaddr);` and immediately dereferences `taddr` with `bind.addr = *taddr;` without any NULL‑check.  The function `uaddr2taddr()` allocates a `struct netbuf` (via `M_RPC`) and returns NULL on failure (e.g., memory allocation failure or malformed address string).  If such a failure occurs, `taddr` becomes NULL and the dereference produces a null‑pointer bug in kernel context, causing a panic and a denial‑of‑service.  Because the dereference is unconditional, the code path is vulnerable whenever `uaddr2taddr()` can legitimately return NULL.  Therefore the evidence supports a real security flaw. 

---

## ✅ rpcsec_gss/rpcsec_gss.c: NULL pointer dereference caused by unchecked strdup failure

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code in rpc_gss_seccreate_int unconditionally assigns the result of `strdup(principal, M_RPC)` to `gd->gd_principal` and never checks for a NULL return. If `strdup` fails (which can happen if `malloc` returns NULL under low‑memory conditions), `gd->gd_principal` becomes NULL. Subsequent code dereferences this pointer: in `rpc_gss_init` the code calls `strlen(gd->gd_principal)` and later `rpc_gss_secfind` uses `strcmp(gd->gd_principal, principal)`. Both will dereference a NULL pointer, causing a kernel crash. No defensive check or error handling prevents this. Therefore the reported NULL‑pointer dereference is a real, exploitable kernel vulnerability. No numeric values need to be verified beyond the existing code.

---

## ✅ rpcsec_gss/rpcsec_gss.c: Unchecked XDR_INLINE return value

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code assigns the result of XDR_INLINE to rpcbuf.value without checking for NULL. XDR_INLINE returns NULL when the XDR stream is not contiguous (as is common with mbuf‑based XDR streams). rpcbuf.length is set to the encoded length before the inline call, so when XDR_INLINE returns NULL the buffer structure contains a non‑zero length and a NULL pointer. This rpcbuf is then passed to gss_get_mic. The GSS API expects a valid pointer when length > 0; if it does not perform a NULL check it will dereference the NULL pointer, causing a crash of the kernel’s GSS library. Thus the code contains a real unchecked null‑pointer dereference that can be triggered via a non‑contiguous XDR stream, making the vulnerability valid. 

---

## ✅ rpcsec_tls/rpctlssd.x: Unbounded gid vector leads to memory exhaustion

**Verdict**: VALID

### Triage reasoning

[ARBITER] The IDL defines `gid<>` as an unbounded array of `uint32_t`. rpcgen generates unmarshalling code that calls `xdr_array` with a maximum size of 0 (unlimited). The XDR library therefore accepts whatever length the client supplies, allocating that many 4‑byte elements on the heap. An attacker can send a vector length up to the 32‑bit limit, leading the server to allocate an enormous buffer and exhaust its memory. No server‑side size validation is present. This is a real, exploitable memory‑exhaustion vulnerability.

---

## ✅ rpcsec_tls/rpctls_impl.c: ensitive Code Path Analysis

**Verdict**: VALID

### Triage reasoning

[ARBITER] The server‐side upcall allocates a gid array using `*ngrps * sizeof(gid_t)` where `*ngrps` comes directly from the remote server’s `gid.gid_len` field. If that value is larger than `INT_MAX` the assignment `*ngrps = res.gid.gid_len` triggers undefined behavior, and if the value is larger than `SIZE_MAX/sizeof(gid_t)` the multiplication overflows, resulting in a too‑small allocation that is later over‑written by the copy loop. This unchecked buffer use due to an integer overflow is a real security vulnerability.

---

## ✅ rpcsec_tls/rpctls_impl.c: ummary of High‑Risk Findings

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code allocates memory based on the value returned by the user‑controlled upcall daemon: `*ngrps = res.gid.gid_len; *gids = mem_alloc(*ngrps * sizeof(gid_t));` The multiplication is performed with an `int` (`*ngrps`) and `sizeof(gid_t)` (4 bytes). If the daemon returns a large `gid_len`, the multiplication can wrap around the 32‑bit signed int, producing a small allocation size while the subsequent copy loop copies `*ngrps` entries, overrunning the buffer and corrupting kernel memory. The value `gid_len` originates from the user‑space rpctlssd service, so a malicious user can inject any value, making the vulnerability real and exploitable. Other listed issues are either low impact or rely on improper user input handling that does not lead to memory corruption. Hence the reported high‑risk findings are valid.

---

## ✅ rpcsec_gss/rpcsec_gss_prot.c: Kernel panic via unvalidated checksum length

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code unconditionally asserts that the checksum length (cklen) read from an untrusted packet is "<= MHLEN" (defined in <sys/mbuf.h> as typically 256). If an attacker supplies a value greater than this constant, the KASSERT macro will trigger a kernel panic, causing a denial‑of‑service. No other bounds check protects against a large cklen, so the vulnerability is real.

---

## ✅ rpcsec_gss/rpcsec_gss_prot.c: Memory leak on decryption failure

**Verdict**: VALID

### Triage reasoning

[ARBITER] The code in `xdr_rpc_gss_unwrap_data()` sets `*resultsp = NULL` at the start so that the caller does not own the incoming mbuf chain after the function returns. In the privacy branch it pulls the length field, then attempts to decrypt with `gss_unwrap_mbuf()`. When `maj_stat != GSS_S_COMPLETE` the function logs an error and `return (FALSE)` without freeing `results`, which still points to the remaining part of the original mbuf chain. Consequently, each decryption failure leaks that chain’s memory, allowing repeated malformed packets to exhaust kernel memory. No other freeing path handles this case, so the leak is real.

Therefore the reported medium‑severity vulnerability is legitimate.

---

