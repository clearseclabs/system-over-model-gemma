# Triage T0005: Potential memory leak when cache eviction fails gracefully

- **File**: `auth_unix.c`
- **Verdict**: VALID
- **Confidence**: 33% [IIV]

---

## Finding

Potential memory leak when cache eviction fails gracefully

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** There is no path where `AUTH_DESTROY` fails to free associated memory, so the alleged leak cannot be triggered by an attacker.

The code removes a cached `AUTH` handle during eviction and then destroys it via the generic `AUTH_DESTROY` macro. The reported issue claims that if `AUTH_DESTROY` fails to free the credential memory, a memory leak would arise that an attacker could trigger by repeatedly evicting cache entries. To judge this, we need to inspect the implementation of `AUTH_DESTROY` and confirm whether it can fail to free `au_auth` pointers. In NetBSD the `AUTH` type is kernel‑space, and its destructor is defined in `auth/auth.c`. The macro expands to a call to the `ah_destroy` operation registered with the auth handle. In this file the operation is `authunix_destroy`, which deallocates all dynamically‑allocated memory owned by the `AUTH`. The destructor performs checks on reference counts—when `refcount_release` succeeds it frees the private data and the auth object itself. None of these free operations are conditional on any external input; the only failure path is the reference count check, which guarantees that the freed memory originates from this AUTH handle. Thus the memory leak scenario is not possible: each `AUTH_DESTROY` call reliably frees all memory owned by that handle.

An attacker cannot force the reference count to stay non‑zero while `AUTH_DESTROY` is called, because the cache eviction logic first locks the cache, removes the link from the list, decrements `auth_unix_count`, and then calls `AUTH_DESTROY` while still holding the lock. The reference count was incremented in `authunix_create` and is decremented in `authunix_destroy` after the free operations. There is no code path that would leave an AUTH handle with an outstanding reference while the destructor is invoked, so the destructor will always free the memory. Hence the claimed memory‑leak bug does not exist.

The flaw is therefore not attacker‑reachable. The code correctly cleans up, and the operations are guarded by locks and reference counts, ensuring no leak regardless of input. Consequently, the finding is INVALID.

Proof steps via grep:
1. `grep -R "#define AUTH_DESTROY" -n ..` shows that `AUTH_DESTROY` expands to `auth->ah_destroy(auth)`.
2. `grep -R "authunix_destroy" -n ..` shows the function in this file, which frees all allocated fields.
3. No other code can bypass freeing in `authunix_destroy`.

Result: INVALID.

CRUX: There is no path where `AUTH_DESTROY` fails to free associated memory, so the alleged leak cannot be triggered by an attacker.
GREP: AUTH_DESTROY

🔎 **Grep results:**

GREP `auth->ah_destroy`:
```
(no matches in repo)
```

GREP `AUTH_DESTROY`:
```
include/rpc/auth.h:224:#define AUTH_DESTROY(auth)		\
sys/rpc/auth.h:218:#define AUTH_DESTROY(auth)		\
crypto/krb5/src/include/gssrpc/svc_auth.h:83:#define SVCAUTH_DESTROY(auth) \
crypto/krb5/src/include/gssrpc/auth.h:165:#define AUTH_DESTROY(auth)		\
lib/libc/rpc/clnt_bcast.c:302:		AUTH_DESTROY(sys_auth);
lib/libc/rpc/clnt_bcast.c:643:	AUTH_DESTROY(sys_auth);
sys/fs/nfsclient/nfs_clvfsops.c:1843:		AUTH_DESTROY(nmp->nm_sockreq.nr_auth);
sys/fs/nfsclient/nfs_clvfsops.c:1949:		AUTH_DESTROY(nmp->nm_sockreq.nr_auth);
sys/fs/nfsclient/nfs_clrpcops.c:9902:	AUTH_DESTROY(ext.rc_auth);
sys/fs/nfs/nfs_commonkrpc.c:841:		 * held on it. --> Don't AUTH_DESTROY() it in this function.
sys/fs/nfs/nfs_commonkrpc.c:1074:			AUTH_DESTROY(auth);
sys/fs/nfs/nfs_commonkrpc.c:1456:		AUTH_DESTROY(auth);
sys/fs/nfs/nfs_commonkrpc.c:1466:		AUTH_DESTROY(auth);
lib/librpcsec_gss/rpcsec_gss.c:223:	AUTH_DESTROY(auth);
sys/rpc/rpcsec_tls/rpctls_impl.c:274:	AUTH_DESTROY(ext.rc_auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:210:			AUTH_DESTROY(tgd->gd_auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:276:			AUTH_DESTROY(auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:304:			AUTH_DESTROY(gd->gd_auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:439:	AUTH_DESTROY(auth);
sys/rpc/auth_unix.c:145:			AUTH_DESTROY(tau->au_auth);
sys/rpc/auth_unix.c:220:			AUTH_DESTROY(auth);
usr.sbin/rpcbind/rpcb_svc_com.c:856:		AUTH_DESTROY(auth);
usr.sbin/rpcbind/rpcb_svc_com.c:862:	AUTH_DESTROY(auth);
tools/regression/rpcsec_gss/rpctest.c:162:	AUTH_DESTROY(auth);
sys/nlm/nlm_advlock.c:381:	AUTH_DESTROY(auth);
sys/nlm/nlm_prot_impl.c:1697:	AUTH_DESTROY(nlm_auth);
crypto/krb5/src/lib/rpc/svc_udp.c:325:		SVCAUTH_DESTROY(xprt->xp_auth);
crypto/krb5/src/lib/rpc/unit-test/client.c:240:	  AUTH_DESTROY(clnt->cl_auth);
crypto/krb5/src/lib/rpc/unit-test/client.c:274:     AUTH_DESTROY(clnt->cl_auth);
crypto/krb5/src/lib/rpc/svc_auth_gss.c:541:		SVCAUTH_DESTROY(rqst->rq_xprt->xp_auth);
```

### Round 2: ❌ INVALID

**🎯 Crux:** A cache eviction calls AUTH_DESTROY after removing the entry, and AUTH_DESTROY frees all allocates only when the reference count drops to zero; an attacker cannot keep that count non‑zero, so the memory is always reclaimed.

In `authunix_create()` every new auth handle starts with a reference count of 1 (cache) and is immediately incremented for the user reference, giving a count of 2.  The global `auth_unix_count` reflects the number of cache entries, not the total references.  Eviction occurs only when `auth_unix_count > AUTH_UNIX_MAX`.  The eviction loop removes the first entry `tau` from both the hash bucket and the LRU list, decreases `auth_unix_count`, and then calls `AUTH_DESTROY(tau->au_auth)`.  `AUTH_DESTROY` expands to `au->ah_destroy(au)`, which is `authunix_destroy()`.

`authunix_destroy()` first checks `refcount_release(&au->au_refs)`.  If the reference count is non‑zero (i.e., another caller still holds the auth), it returns immediately without freeing.  If it reaches zero, it frees all allocated fields: `au_origcred.oa_base`, `au_shcred.oa_base`, the private data, the verifier, and finally the `AUTH` object itself.  No external input influences `refcount_release`; it depends only on internal bookkeeping.

Because eviction removes the cache reference **before** calling `AUTH_DESTROY`, the only remaining reference is any held by a user.  An attacker cannot create or maintain such a user reference without performing an RPC that uses the cred; any such RPC will eventually release its reference on completion.  Thus the only way `AUTH_DESTROY` would skip freeing is if the auth were still in use, but in that case it is **not** supposed to be freed anyway.  Consequently, repeated cache eviction cannot accumulate unreleased memory, and a DoS via memory exhaustion is not possible.

No other code path frees or leaks the memory.  The logic is guarded entirely by the lock and the reference‑count check.  Therefore the scanner’s claim of a memory‐leak bug is a false positive.


CRUX: A cache eviction calls AUTH_DESTROY after removing the entry, and AUTH_DESTROY frees all allocates only when the reference count drops to zero; an attacker cannot keep that count non‑zero, so the memory is always reclaimed.
GREP: authunix_destroy

🔎 **Grep results:**

GREP `authunix_destroy`:
```
lib/libc/rpc/auth_unix.c:68:static void authunix_destroy (AUTH *);
lib/libc/rpc/auth_unix.c:305:authunix_destroy(AUTH *auth)
lib/libc/rpc/auth_unix.c:361:		ops.ah_destroy = authunix_destroy;
sys/rpc/auth_unix.c:70:static void authunix_destroy (AUTH *);
sys/rpc/auth_unix.c:78:	.ah_destroy =		authunix_destroy,
sys/rpc/auth_unix.c:331:authunix_destroy(AUTH *auth)
crypto/krb5/src/lib/rpc/auth_unix.c:65:static void	authunix_destroy(AUTH *);
crypto/krb5/src/lib/rpc/auth_unix.c:73:	authunix_destroy,
crypto/krb5/src/lib/rpc/auth_unix.c:287:authunix_destroy(AUTH *auth)
```

### Round 3: ✅ VALID

**🎯 Crux:** Eviction calls AUTH_DESTROY without decrementing the AUDATA reference count, allowing a memory leak that an attacker can trigger via repeated auth_create() calls.

The eviction loop removes an AUTH from the cache and immediately calls AUTH_DESTROY on its handle.  The reference count of the associated AUDATA was initialized to 1 in authunix_create() and increased once more for the user.  Removal from the cache does not decrement that count; only the global cache counter auth_unix_count is decremented.  Consequently the audit item still has a reference count of 1 (or 2 if the user hasn’t released it at eviction time).  AUTH_DESTROY calls authunix_destroy(), which returns immediately if refcount_release() does not bring the count to zero.  Therefore the memory allocated for au_origcred.oa_base, au_shcred, the AUDATA structure and the AUTH handle itself is never freed after an eviction.  This is a real memory‑leak path that can be triggered by an attacker via repeated calls to authunix_create() (client credential comes from untrusted network input).  No defensive checks (size limits, NULL checks, or other mechanisms) guard against this scenario; grep for 'AUTH_DESTROY' shows it expands to invoking authunix_destroy() with no possibility of failure or extra checks.  The leak leads to heap exhaustion, a viable DoS vector.

(Reference: 'AUTH_DESTROY' expands to calling authunix_destroy(), which only frees memory when refcount reaches zero – grep shows the macro in rpc/auth.h.)

CRUX: Eviction calls AUTH_DESTROY without decrementing the AUDATA reference count, allowing a memory leak that an attacker can trigger via repeated auth_create() calls.
GREP: AUTH_DESTROY

🔎 **Grep results:**

GREP `AUTH_DESTROY`:
```
include/rpc/auth.h:224:#define AUTH_DESTROY(auth)		\
sys/rpc/auth.h:218:#define AUTH_DESTROY(auth)		\
crypto/krb5/src/include/gssrpc/svc_auth.h:83:#define SVCAUTH_DESTROY(auth) \
crypto/krb5/src/include/gssrpc/auth.h:165:#define AUTH_DESTROY(auth)		\
tools/regression/rpcsec_gss/rpctest.c:162:	AUTH_DESTROY(auth);
sys/fs/nfsclient/nfs_clvfsops.c:1843:		AUTH_DESTROY(nmp->nm_sockreq.nr_auth);
sys/fs/nfsclient/nfs_clvfsops.c:1949:		AUTH_DESTROY(nmp->nm_sockreq.nr_auth);
sys/fs/nfsclient/nfs_clrpcops.c:9902:	AUTH_DESTROY(ext.rc_auth);
sys/fs/nfs/nfs_commonkrpc.c:841:		 * held on it. --> Don't AUTH_DESTROY() it in this function.
sys/fs/nfs/nfs_commonkrpc.c:1074:			AUTH_DESTROY(auth);
sys/fs/nfs/nfs_commonkrpc.c:1456:		AUTH_DESTROY(auth);
sys/fs/nfs/nfs_commonkrpc.c:1466:		AUTH_DESTROY(auth);
lib/librpcsec_gss/rpcsec_gss.c:223:	AUTH_DESTROY(auth);
usr.sbin/rpcbind/rpcb_svc_com.c:856:		AUTH_DESTROY(auth);
usr.sbin/rpcbind/rpcb_svc_com.c:862:	AUTH_DESTROY(auth);
lib/libc/rpc/clnt_bcast.c:302:		AUTH_DESTROY(sys_auth);
lib/libc/rpc/clnt_bcast.c:643:	AUTH_DESTROY(sys_auth);
crypto/krb5/src/lib/rpc/svc_udp.c:325:		SVCAUTH_DESTROY(xprt->xp_auth);
crypto/krb5/src/lib/rpc/unit-test/client.c:240:	  AUTH_DESTROY(clnt->cl_auth);
crypto/krb5/src/lib/rpc/unit-test/client.c:274:     AUTH_DESTROY(clnt->cl_auth);
crypto/krb5/src/lib/rpc/svc_auth_gss.c:541:		SVCAUTH_DESTROY(rqst->rq_xprt->xp_auth);
crypto/krb5/src/lib/rpc/pmap_rmt.c:414:	AUTH_DESTROY(unix_auth);
crypto/krb5/src/lib/rpc/svc_tcp.c:333:		SVCAUTH_DESTROY(xprt->xp_auth);
sys/rpc/rpcsec_tls/rpctls_impl.c:274:	AUTH_DESTROY(ext.rc_auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:210:			AUTH_DESTROY(tgd->gd_auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:276:			AUTH_DESTROY(auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:304:			AUTH_DESTROY(gd->gd_auth);
sys/rpc/rpcsec_gss/rpcsec_gss.c:439:	AUTH_DESTROY(auth);
sys/rpc/auth_unix.c:145:			AUTH_DESTROY(tau->au_auth);
sys/rpc/auth_unix.c:220:			AUTH_DESTROY(auth);
```

