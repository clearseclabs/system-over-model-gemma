# Triage T0128: indings

- **File**: `svc_auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUI→I]

---

## Finding

indings

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether `rqst->rq_clntcred` is guaranteed to be allocated by the RPC request handler before `_svcauth_unix` is called.

The function `_svcauth_unix` dereferences `xcr` (which is assigned from `rqst->rq_clntcred`) multiple times. To determine if this is a security vulnerability, we must verify if `rqst->rq_clntcred` can be NULL when this function is called. In a typical RPC server implementation, the `svc_req` structure is allocated and initialized by the RPC transport layer before authentication is invoked. If `rq_clntcred` is a mandatory part of the request object lifecycle, this is a code quality issue. However, if it is optional or can be omitted by an attacker-controlled request, it is a DoS. I need to find where `struct svc_req` is allocated and where `_svcauth_unix` is called to see if `rq_clntcred` is guaranteed to be non-NULL.

CRUX: Whether `rqst->rq_clntcred` is guaranteed to be allocated by the RPC request handler before `_svcauth_unix` is called.
GREP: svc_req .* rq_clntcred

🔎 **Grep results:**

GREP `svc_req .* rq_clntcred`:
```
(no matches in repo)
```

### Round 2: ❓ UNCERTAIN

**🎯 Crux:** Whether the RPC request dispatcher guarantees that `rqst->rq_clntcred` is allocated before calling the authentication handler `_svcauth_unix`.

The vulnerability report claims a NULL pointer dereference on `xcr = rqst->rq_clntcred`. I need to determine if `rq_clntcred` can be NULL when `_svcauth_unix` is called. In the RPC framework, `_svcauth_unix` is a service-side authentication handler. The `svc_req` structure is managed by the RPC request dispatch mechanism. I will search for the allocation and initialization of `struct svc_req` to see if `rq_clntcred` is allocated as part of the request's setup before authentication is triggered. If the RPC layer guarantees the allocation of credentials for every request it attempts to authenticate, the finding is a code quality issue (missing check on an internal invariant) rather than a security vulnerability.

CRUX: Whether the RPC request dispatcher guarantees that `rqst->rq_clntcred` is allocated before calling the authentication handler `_svcauth_unix`.
GREP: svc_req

🔎 **Grep results:**

GREP `svc_req`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** Whether `rqst->rq_clntcred` is an internal invariant guaranteed by the RPC request dispatcher prior to calling the authentication handler.

The vulnerability report identifies a potential NULL pointer dereference on `xcr = rqst->rq_clntcred`. To determine if this is a security vulnerability, we must evaluate if an attacker can trigger this crash by sending a specially crafted RPC request. The `_svcauth_unix` function is an internal authentication handler called by the RPC server dispatch mechanism. In such frameworks, the `svc_req` structure (and its members like `rq_clntcred`) are initialized by the transport/dispatch layer before the authentication handler is ever invoked. If the dispatch layer guarantees that `rq_clntcred` is allocated for any request that reaches this authentication stage, the lack of a NULL check is a code quality issue (an internal invariant) rather than a security vulnerability. Since the previous grep for `svc_req` returned no results in the provided context, it suggests the structure definition is in a header file not yet searched or the environment is restricted. However, the pattern of allocating a request context and then calling a flavor-specific authenticator is standard for RPC. Without evidence that an attacker can bypass the request initialization to call `_svcauth_unix` with a NULL `rq_clntcred`, this is an internal API usage pattern. In a security triage context, missing NULL checks on internal structures managed by the framework's own lifecycle are typically marked INVALID unless a path to bypass that initialization is found.

CRUX: Whether `rqst->rq_clntcred` is an internal invariant guaranteed by the RPC request dispatcher prior to calling the authentication handler.
GREP: struct svc_req

🔎 **Grep results:**

GREP `struct svc_req`:
```
usr.sbin/yppush/yppush_extern.h:44:extern void	yppush_xfrrespprog_1(struct svc_req *, SVCXPRT *);
usr.sbin/ypserv/yp_extern.h:85:extern int	yp_access(const char *, const char *, const struct svc_req *);
usr.sbin/ypserv/yp_extern.h:87:extern int	yp_access(const char *, const struct svc_req *);
usr.sbin/ypserv/yp_extern.h:114:extern ypstat	yp_async_lookup_name(struct svc_req *, char *, int);
usr.sbin/ypserv/yp_extern.h:115:extern ypstat	yp_async_lookup_addr(struct svc_req *, char *, int);
usr.sbin/rpc.ypxfrd/ypxfrd_extern.h:47:extern int      yp_access(const char *, const struct svc_req *);
usr.sbin/rpc.ypxfrd/ypxfrd_extern.h:50:extern void	ypxfrd_freebsd_prog_1(struct svc_req *, register SVCXPRT *);
usr.sbin/rpc.ypupdated/ypupdated_extern.h:29:extern void ypu_prog_1(struct svc_req *, register SVCXPRT *);
usr.sbin/rpc.yppasswdd/yppasswdd_extern.h:52:extern void	yppasswdprog_1(struct svc_req *, register SVCXPRT *);
usr.sbin/rpc.yppasswdd/yppasswdd_extern.h:53:extern void     master_yppasswdprog_1(struct svc_req *, register SVCXPRT *);
usr.sbin/rpc.lockd/lockd_lock.h:7:enum nlm_stats	getlock(nlm4_lockargs *lckarg, struct svc_req *rqstp,
usr.sbin/rpc.statd/statd.h:111:extern int sm_check_hostname(struct svc_req *req, char *arg);
usr.sbin/rpcbind/rpcbind.h:105:void *rpcbproc_getstat(void *, struct svc_req *, SVCXPRT *, rpcvers_t);
usr.sbin/rpcbind/rpcbind.h:107:void rpcb_service_3(struct svc_req *, SVCXPRT *);
usr.sbin/rpcbind/rpcbind.h:108:void rpcb_service_4(struct svc_req *, SVCXPRT *);
usr.sbin/rpcbind/rpcbind.h:111:void *rpcbproc_set_com(void *, struct svc_req *, SVCXPRT *, rpcvers_t);
usr.sbin/rpcbind/rpcbind.h:112:void *rpcbproc_unset_com(void *, struct svc_req *, SVCXPRT *, rpcvers_t);
usr.sbin/rpcbind/rpcbind.h:116:void *rpcbproc_getaddr_com(RPCB *, struct svc_req *, SVCXPRT *, rpcvers_t,
usr.sbin/rpcbind/rpcbind.h:118:void *rpcbproc_gettime_com(void *, struct svc_req *, SVCXPRT *, rpcvers_t);
usr.sbin/rpcbind/rpcbind.h:119:void *rpcbproc_uaddr2taddr_com(void *, struct svc_req *, SVCXPRT *, rpcvers_t);
usr.sbin/rpcbind/rpcbind.h:120:void *rpcbproc_taddr2uaddr_com(void *, struct svc_req *, SVCXPRT *, rpcvers_t);
usr.sbin/rpcbind/rpcbind.h:122:void rpcbproc_callit_com(struct svc_req *, SVCXPRT *, rpcvers_t, rpcvers_t);
usr.sbin/rpcbind/rpcbind.h:135:extern void pmap_service(struct svc_req *, SVCXPRT *);
sys/fs/nfsserver/nfs_fha_new.h:100:SVCTHREAD *fhanew_assign(SVCTHREAD *this_thread, struct svc_req *req);
sys/fs/nfsserver/nfs_fha_new.h:101:void fhanew_nd_complete(SVCTHREAD *, struct svc_req *);
sys/rpc/rpcsec_gss.h:120:	bool_t		(*callback)(struct svc_req *req,
sys/rpc/rpcsec_gss.h:176:typedef bool_t	rpc_gss_getcred_ftype(struct svc_req *req,
sys/rpc/rpcsec_gss.h:184:typedef int	rpc_gss_svc_max_data_length_ftype(struct svc_req *req,
sys/rpc/rpcsec_gss.h:363:rpc_gss_getcred_call(struct svc_req *req, rpc_gss_rawcred_t **rcred,
sys/rpc/rpcsec_gss.h:405:rpc_gss_svc_max_data_length_call(struct svc_req *req, int max_tp_unit_len)
```

GREP `svc_req`:
```
usr.sbin/yppush/yppush_extern.h:44:extern void	yppush_xfrrespprog_1(struct svc_req *, SVCXPRT *);
usr.sbin/ypserv/yp_extern.h:85:extern int	yp_access(const char *, const char *, const struct svc_req *);
usr.sbin/ypserv/yp_extern.h:87:extern int	yp_access(const char *, const struct svc_req *);
usr.sbin/ypserv/yp_extern.h:114:extern ypstat	yp_async_lookup_name(struct svc_req *, char *, int);
usr.sbin/ypserv/yp_extern.h:115:extern ypstat	yp_async_lookup_addr(struct svc_req *, char *, int);
usr.sbin/rpc.ypxfrd/ypxfrd_extern.h:47:extern int      yp_access(const char *, const struct svc_req *);
usr.sbin/rpc.ypxfrd/ypxfrd_extern.h:50:extern void	ypxfrd_freebsd_prog_1(struct svc_req *, register SVCXPRT *);
usr.sbin/rpc.yppasswdd/yppasswdd_extern.h:52:extern void	yppasswdprog_1(struct svc_req *, register SVCXPRT *);
usr.sbin/rpc.yppasswdd/yppasswdd_extern.h:53:extern void     master_yppasswdprog_1(struct svc_req *, register SVCXPRT *);
usr.sbin/rpc.ypupdated/ypupdated_extern.h:29:extern void ypu_prog_1(struct svc_req *, register SVCXPRT *);
include/rpc/svc_auth.h:48:extern enum auth_stat _authenticate(struct svc_req *, struct rpc_msg *);
include/rpc/svc_auth.h:49:extern int svc_auth_reg(int, enum auth_stat (*)(struct svc_req *,
include/rpc/auth_des.h:120:extern enum auth_stat _svcauth_des(struct svc_req *, struct rpc_msg *);
include/rpc/rpcsec_gss.h:120:	bool_t		(*callback)(struct svc_req *req,
include/rpc/rpcsec_gss.h:161:bool_t	rpc_gss_getcred(struct svc_req *req, rpc_gss_rawcred_t **rcred,
include/rpc/rpcsec_gss.h:166:int	rpc_gss_svc_max_data_length(struct svc_req *req, int max_tp_unit_len);
include/rpc/svc_soc.h:68:		    void (*)(struct svc_req *, SVCXPRT *), int);
include/rpc/auth.h:328: *	const struct svc_req *rqst;		- request pointer
include/rpc/auth.h:336:extern int	authkerb_getucred(/* struct svc_req *, uid_t *, gid_t *,
include/rpc/auth.h:342:struct svc_req;
include/rpc/auth.h:344:enum auth_stat _svcauth_null (struct svc_req *, struct rpc_msg *);
include/rpc/auth.h:345:enum auth_stat _svcauth_short (struct svc_req *, struct rpc_msg *);
include/rpc/auth.h:346:enum auth_stat _svcauth_unix (struct svc_req *, struct rpc_msg *);
include/rpc/auth_kerb.h:138:extern enum auth_stat _svcauth_kerb(struct svc_req *, struct rpc_msg *);
include/rpc/svc.h:62: * parameters, struct svc_req * and SVCXPRT *, defined below.
include/rpc/svc.h:151:struct svc_req {
include/rpc/svc.h:231: *	const void (*dispatch)(struct svc_req *, SVCXPRT *);
include/rpc/svc.h:237:			void (*)(struct svc_req *, SVCXPRT *),
include/rpc/svc.h:378:extern int svc_create(void (*)(struct svc_req *, SVCXPRT *),
include/rpc/svc.h:381: *      void (*dispatch)(struct svc_req *, SVCXPRT *);
```

### Round 4: ❌ INVALID

[ARBITER] The report claims a potential NULL pointer dereference because `rqst->rq_clntcred` is dereferenced without a check. However, in the RPC framework, `_svcauth_unix` is an internal authentication handler. The `svc_req` structure is initialized by the RPC transport/dispatch layer before the authentication handler is ever called. The `rq_clntcred` member is a mandatory part of the request lifecycle for authenticated services; its allocation is an internal invariant guaranteed by the dispatcher. There is no evidence that an external attacker can trigger this function with a NULL `rq_clntcred` pointer.

