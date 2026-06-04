# Defect: double write-lock (self-deadlock) in `clnt_nl_destroy` — `sys/rpc/clnt_nl.c`

## Summary

`clnt_nl_destroy()` acquires the global rwlock `rpcnl_global_lock` with
`rw_wlock()` twice and never releases it. The second `rw_wlock()` is plainly a
typo for `rw_wunlock()`. On a non-recursive rwlock this re-acquire is a hard
error: an `INVARIANTS`/`WITNESS` kernel panics ("recursing on non-recursive
rw"), and a production kernel self-deadlocks the calling thread while leaving
the global lock held — which then wedges the entire netlink-RPC subsystem.

It is a **reliability/correctness defect, not a security vulnerability**
(reachable only via privileged teardown). See "Security assessment" below.

## Affected

- **File / function:** `sys/rpc/clnt_nl.c`, `clnt_nl_destroy()`
- **Introduced:** commit `fa1b961259bc` ("krpc: add kernel side client over
  netlink(4)", 2025-02-01) — present in the file from its first commit.
- **Status:** still present in `main` as of 2026-06 (verified against
  `raw.githubusercontent.com/freebsd/freebsd-src/main`). ~16 months unfixed.
- **Maintainer/author:** Gleb Smirnoff (`glebius@FreeBSD.org`).

## The defect

```c
static void
clnt_nl_destroy(CLIENT *cl)
{
	struct nl_data *nl = cl->cl_private;

	MPASS(TAILQ_EMPTY(&nl->nl_pending));

	genl_unregister_group(rpcnl_family_id, nl->nl_hdr.group);
	rw_wlock(&rpcnl_global_lock);          /* acquire */
	RB_REMOVE(nl_data_t, &rpcnl_clients, nl);
	rw_wlock(&rpcnl_global_lock);          /* BUG: should be rw_wunlock() */

	mtx_destroy(&nl->nl_lock);
	free(nl, M_RPC);
	free(cl, M_RPC);
}
```

`rpcnl_global_lock` is a plain `struct rwlock` initialized with `rw_init()` in
`rpcnl_init()` — non-recursive. Every other site pairs the lock correctly
(`client_nl_create`: `rw_wlock`/`rw_wunlock`; `clnt_nl_reply`:
`rw_rlock`/`rw_runlock`). Only `clnt_nl_destroy` is wrong.

## Impact

1. **`INVARIANTS`/`WITNESS` kernel:** immediate panic on the second
   `rw_wlock()` (recursing on a non-recursive rwlock).
2. **Production (`GENERIC`-style) kernel:** the calling thread blocks forever
   trying to re-acquire a write lock it already holds, **and the lock is never
   released**. Because `rpcnl_global_lock` guards the netlink-RPC client tree,
   every subsequent:
   - `clnt_nl_reply()` (`rw_rlock`, the path that delivers *every* netlink-RPC
     reply), and
   - `client_nl_create()` (`rw_wlock`, creating any new netlink-RPC client)

   blocks indefinitely. One destroy wedges the whole subsystem (kgssapi, NLM,
   NFS-over-TLS client/server).

## Reachability

`clnt_nl_destroy` is the `.cl_destroy` op, invoked when a netlink RPC client's
refcount reaches 0 (`CLNT_RELEASE`/`CLNT_DESTROY`). The netlink RPC clients are
created once as long-lived singletons:

- `rpcb_clnt.c` — `client_nl_create("rpcbind", …)`
- `rpcsec_tls/rpctls_impl.c` — `tlsclnt` and `tlsserv` handles
- kgssapi (kernel GSS) RPC client

They are not released during normal operation, so the path is effectively
dormant — it is reached on subsystem teardown / kernel module unload, or any
future code that releases one of these clients. That dormancy is almost
certainly why a self-deadlock has survived in `main` for over a year.

**Not** reachable remotely and **not** by an unprivileged local user: the
netlink command and multicast layers are `PRIV_NFS_DAEMON`-gated, and inbound
replies take the read-lock path (`clnt_nl_reply`), not destroy.

## Security assessment

**This is not a security vulnerability.** The only way to reach the bug is a
privileged teardown action (e.g. `kldunload` of the relevant krpc components by
root). An actor who can unload kernel modules can already panic or halt the
machine, so there is no privilege or trust boundary crossed: no remote vector,
no unprivileged local vector, no memory corruption, no privilege escalation —
just a latent panic/self-deadlock (a DoS) on an administrative path.

Classification: CWE-667 (improper locking) / a recursive-lock defect. It should
be filed as an ordinary bug (FreeBSD Bugzilla or a patch to the maintainer /
review), **not** reported to `secteam@FreeBSD.org` as a security issue.

## Suggested fix

```diff
 	rw_wlock(&rpcnl_global_lock);
 	RB_REMOVE(nl_data_t, &rpcnl_clients, nl);
-	rw_wlock(&rpcnl_global_lock);
+	rw_wunlock(&rpcnl_global_lock);
```

## How it was found

Surfaced by `google/gemma-4-31b-it` running AISLE's `nano-analyzer` pipeline
over FreeBSD `sys/rpc/` (Run 1 of the *system-over-model* reproduction). The
scanner flagged it as "Kernel Deadlock via Double Lock" with the correct crux
in all three triage rounds plus the arbiter. It was then verified by hand
against the pre-patch tree and current `main`.

Note: it is the *only* genuine defect among Run 1's 30 graduated "VALID"
findings — the other 29 are false positives, and the actual target bug
(CVE-2026-4747) was dropped at the scan stage. A real but low-value catch:
correct, but not the security bug the run was hunting.
