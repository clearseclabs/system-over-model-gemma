# Context: svc.h

This is a context briefing for `svc.h`, the server-side Remote Procedure Call (RPC) interface.

**1. Function & Location**
`svc.h` defines the core data structures and API for the RPC server framework. It sits at the boundary between the transport layer (TCP/UDP) and the registered service dispatchers. It manages service registration, transport handles (`SVCXPRT`), and request processing (`svc_req`).

**2. Untrusted Input Path**
Untrusted data enters via the network. The flow is: `Network` $\rightarrow$ `SVCXPRT` (via `xp_ops->xp_recv`) $\rightarrow$ `struct mbuf` $\rightarrow$ `struct svc_req` $\rightarrow$ `sc_dispatch` (Service Dispatcher).

**3. Attacker-Controlled Data**
Data arrives in `struct svc_req`:
* `rq_xid`, `rq_prog`, `rq_vers`, `rq_proc`: RPC headers used for routing.
* `rq_args`: XDR-encoded arguments (contained in `mbuf` chain).
* `rq_cred` / `rq_verf`: Authentication credentials from the wire.
* `rq_credarea`: Raw credential buffer.

**4. Fixed-Size Buffers & Constants**
* `rq_credarea[3 * MAX_AUTH_BYTES]`: Found in `struct svc_req`. 
GREP: `MAX_AUTH_BYTES`
* `sp_groups[SVC_MAXGROUPS]`: `SVC_MAXGROUPS` is explicitly `16`.

**5. Dangerous Data Flows**
* **Source:** Network/RPC Header $\rightarrow$ **Destination:** `rq_credarea` $\rightarrow$ **Function:** Likely internal authentication wrappers (e.g., `svc_ah_unwrap`) $\rightarrow$ **Size:** `3 * MAX_AUTH_BYTES`.

**6. Potential NULL Dereferences**
* `rq_addr`: Explicitly noted as "NULL if connected" in `struct svc_req`.
* `xp_ops` members: `SVC_ACK` checks if `xp_ack` is NULL, but other `xp_ops` calls (like `xp_recv` or `xp_reply`) assume the function pointer is populated.

**7. Tagged Unions/Variants**
The `SVCAUTH` structure uses a `svc_ah_ops` pointer and `svc_ah_private` void pointer. This is a manual implementation of a variant; the code relies on the `svc_ah_ops` table to determine how to handle `svc_ah_private`.

**8. API vs. Helpers**
* **Public API:** `svc_reg`, `svc_run`, `svc_sendreply`, `svc_getargs`, `svcpool_create`.
* **Static/Internal:** `__xprt_unregister_unlocked` (Internal helper).

**9. Likely Bug Classes**
* **Buffer Overflows:** Specifically in `rq_credarea` during credential parsing.
* **Integer Overflows:** In `rq_size` or `xp_snd_cnt` / `xp_snt_cnt` during mbuf manipulation.
* **Race Conditions:** High complexity in `SVCGROUP` and `SVCPOOL` locking (`sg_lock`, `sp_lock`) across worker threads.
* **Memory Leaks:** Failure to call `svc_freereq` or `SVCAUTH_RELEASE`.

[GREP RESULTS from codebase]:
GREP `MAX_AUTH_BYTES`:
```
(no matches in repo)
```