# Context: svc.c

This briefing covers `svc.c`, the server-side Remote Procedure Call (RPC) interface.

### 1. Function & Location
`svc.c` implements the RPC server core, managing transport handles (`SVCXPRT`), service registration (`svc_callout`), and a multi-threaded worker pool (`SVCPOOL`) to dispatch incoming RPC requests to registered handlers. It sits between the transport layer and the actual RPC service implementations.

### 2. Untrusted Input Entry
Untrusted data enters via the network through `SVC_RECV` (called inside `svc_getreq`), which populates a `struct rpc_msg` and an `mbuf` containing the RPC arguments.

### 3. Attacker-Controlled Data Flow
*   **`msg` (`struct rpc_msg`)**: Direct network input.
    *   `msg.rm_xid` $\rightarrow$ `rqstp->rq_xid`
    *   `msg.rm_call.cb_prog` $\rightarrow$ `rqstp->rq_prog`
    *   `msg.rm_call.cb_vers` $\rightarrow$ `rqstp->rq_vers`
    *   `msg.rm_call.cb_proc` $\rightarrow$ `rqstp->rq_proc`
*   **`args` (`struct mbuf *`)**: Network payload $\rightarrow$ `rqstp->rq_args` $\rightarrow$ passed to `xdr_results` or `xargs` for decoding.
*   **`r->rq_credarea`**: Network-supplied authentication data.

### 4. Fixed-Size Buffers & Constants
*   `rq_credarea` buffer within `struct svc_req`:
    *   Auth base: `&r->rq_credarea[0]`
    *   Verf base: `&r->rq_credarea[MAX_AUTH_BYTES]`
    *   Client cred: `&r->rq_credarea[2*MAX_AUTH_BYTES]`
    *   **GREP: MAX_AUTH_BYTES** (typically 1024 or similar in RPC headers).
*   `sp_groups[SVC_MAXGROUPS]`:
    *   **GREP: SVC_MAXGROUPS** (Used to bound loops in `svcpool_create` and `svcpool_cleanup`).

### 5. Dangerous Data Flows
*   **Network $\rightarrow$ `rq_credarea`**: In `svc_getreq`, `SVC_RECV` fills the `rpc_msg` which points into `r->rq_credarea`.
*   **Network $\rightarrow$ `mbuf`**: `SVC_RECV` provides `args` (mbuf), which is later processed by XDR decoders.

### 6. Potential NULL Dereferences
*   `rqstp->rq_addr`: While checked in some places, it is passed to `free(..., M_SONAME)`; if `free` does not handle NULL, this is a risk.
*   `xprt->xp_socket`: Dereferenced in `svc_getreq` for `so_setsockopt` after checking `xprt->xp_socket != NULL`.

### 7. Tagged Unions/Variants
*   `struct rpc_msg` uses `rm_direction` (CALL/REPLY) to determine which union member (`rm_call` or `rm_reply`) is active. In `svc_getreq`, it is assumed to be a CALL.

### 8. API Visibility
*   **Public API**: `svcpool_create`, `svcpool_destroy`, `xprt_register`, `svc_reg`, `svc_sendreply`, `svc_run`, `svc_getargs`.
*   **Static Helpers**: `svc_find`, `svc_executereq`, `svc_getreq`, `svc_run_internal`. These are called internally by the pool management logic.

### 9. Likely Bug Classes
*   **Integer Overflows**: Specifically in `rq_size` calculations (`sizeof(*r) + m_length(args, NULL)`).
*   **Race Conditions**: High complexity in `SVCPOOL`/`SVCGROUP` locking and thread state transitions (`SVCPOOL_THREADWANTED` $\rightarrow$ `SVCPOOL_THREADSTARTING`).
*   **Memory Corruption**: Potential for overflows in the `rq_credarea` if `SVC_RECV` does not strictly bound input to `2 * MAX_AUTH_BYTES`.

[GREP RESULTS from codebase]:
GREP `MAX_AUTH_BYTES** (typically 1024 or similar in RPC headers).`:
```
(no matches in repo)
```

GREP `svcpool_cleanup`:
```
(no matches in repo)
```