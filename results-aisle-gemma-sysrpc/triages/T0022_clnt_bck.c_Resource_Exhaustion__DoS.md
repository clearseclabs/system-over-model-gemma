# Triage T0022: Resource Exhaustion (DoS)

- **File**: `clnt_bck.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Resource Exhaustion (DoS)

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The `ct_pending` queue is populated by the client initiating RPC calls, not by the server sending unsolicited data; thus, an external attacker cannot cause the queue to grow unboundedly.

The report claims that the `ct_pending` queue is unbounded, potentially leading to kernel memory exhaustion. Let's trace the life cycle of a request in `clnt_bck_call`. A request (`struct ct_request`) is allocated on the heap and inserted into the `ct_pending` queue. The code then calls `msleep(cr, ...)` with a timeout derived from `utimeout` or `ct->ct_wait`. When `msleep` returns (either due to a reply from the server via `clnt_bck_svccall` or a timeout), `TAILQ_REMOVE(&ct->ct_pending, cr, cr_link)` is called, and the request is freed. Crucially, the queue only grows if requests are made faster than they time out or are replied to. In the context of the NFSv4.1 backchannel, this code is used by the kernel to send callbacks *to* the server. An external attacker (the server) cannot force the client to create these requests; the client initiates them based on internal kernel state (e.g., needing to send a callback). Therefore, the 'unbounded' nature of the queue is not attacker-reachable in a way that allows an external entity to exhaust memory. The attacker (server) can ignore requests, but that simply leads to the requests timing out and being freed by the client's own `msleep` logic.

CRUX: The `ct_pending` queue is populated by the client initiating RPC calls, not by the server sending unsolicited data; thus, an external attacker cannot cause the queue to grow unboundedly.
GREP: clnt_bck_call

🔎 **Grep results:**

GREP `clnt_bck_call`:
```
sys/rpc/krpc.h:41:enum clnt_stat clnt_bck_call(CLIENT *, struct rpc_callextra *, rpcproc_t,
sys/fs/nfs/nfs_commonkrpc.c:972:		stat = clnt_bck_call(nrp->nr_client, &ext, procnum,
sys/rpc/clnt_bck.c:182:clnt_bck_call(
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `ct_pending` queue is populated by the client (kernel) initiating calls, not by the server; the server cannot force the queue to grow, and all entries eventually time out via `msleep`.

The vulnerability report claims that the `ct_pending` queue is unbounded and can be exhausted by a server that ignores requests. However, looking at the data flow, the `ct_pending` queue is populated in `clnt_bck_call`. This function is called by the kernel (the client) when it needs to send a callback to the server. An external attacker (the server) cannot force the kernel to call `clnt_bck_call` with arbitrary frequency; the client controls the rate of outgoing requests. While it is true that the queue has no hard limit, each request is guarded by `msleep` with a timeout (`utimeout` or `ct->ct_wait`). Once the timeout expires, the request is removed from the queue and freed. Therefore, the only way to exhaust memory would be if the kernel itself initiated requests faster than the timeout period, which is a resource management issue of the internal kernel NFS client, not a vulnerability triggerable by an external attacker. The attacker's only action (ignoring requests) simply triggers the timeout mechanism, which cleans up the memory. This is not an attacker-reachable vulnerability.

CRUX: The `ct_pending` queue is populated by the client (kernel) initiating calls, not by the server; the server cannot force the queue to grow, and all entries eventually time out via `msleep`.
GREP: clnt_bck_call

🔎 **Grep results:**

GREP `clnt_bck_call`:
```
sys/rpc/krpc.h:41:enum clnt_stat clnt_bck_call(CLIENT *, struct rpc_callextra *, rpcproc_t,
sys/fs/nfs/nfs_commonkrpc.c:972:		stat = clnt_bck_call(nrp->nr_client, &ext, procnum,
sys/rpc/clnt_bck.c:182:clnt_bck_call(
```

### Round 3: ❌ INVALID

**🎯 Crux:** The `ct_pending` queue is populated by the local kernel initiating outgoing calls and is cleaned up by a mandatory `msleep` timeout; a remote server cannot force the creation of these requests.

The reported vulnerability claims that the `ct_pending` queue in `clnt_bck.c` is unbounded, allowing a server to cause kernel memory exhaustion by ignoring requests. To determine if this is a security vulnerability, we must assess if an external attacker can control the growth of this queue. 

1. **Who populates the queue?** The queue `ct->ct_pending` is populated in `clnt_bck_call` via `TAILQ_INSERT_TAIL`. 
2. **Who calls `clnt_bck_call`?** Based on the code and grep results, `clnt_bck_call` is called by the NFS client (the kernel) to send callback requests to the server (e.g., `sys/fs/nfs/nfs_commonkrpc.c:972`). 
3. **Can an attacker trigger it?** The 'attacker' in this scenario is the remote server. However, the server cannot force the client to initiate more RPC calls; it can only choose whether or not to respond to the calls the client has already sent. 
4. **Is there a cleanup mechanism?** Yes. Every request inserted into the queue in `clnt_bck_call` is followed by an `msleep` with a timeout (`tvtohz(&timeout)`). When `msleep` returns (due to a timeout or a response), the code explicitly calls `TAILQ_REMOVE(&ct->ct_pending, cr, cr_link)` and later `free(cr, M_RPC)`. 

Since the client (kernel) controls the rate of request generation and every request has a mandatory timeout that triggers cleanup, a malicious server cannot cause the queue to grow unboundedly. The server's only power is to make the client wait until the timeout, but the timeout itself is the defense that prevents memory exhaustion. This is an internal resource management characteristic, not an attacker-reachable vulnerability.

CRUX: The `ct_pending` queue is populated by the local kernel initiating outgoing calls and is cleaned up by a mandatory `msleep` timeout; a remote server cannot force the creation of these requests.
GREP: clnt_bck_call

🔎 **Grep results:**

GREP `clnt_bck_call`:
```
sys/rpc/krpc.h:41:enum clnt_stat clnt_bck_call(CLIENT *, struct rpc_callextra *, rpcproc_t,
sys/rpc/clnt_bck.c:182:clnt_bck_call(
sys/fs/nfs/nfs_commonkrpc.c:972:		stat = clnt_bck_call(nrp->nr_client, &ext, procnum,
```

### Round 4: ❌ INVALID

[ARBITER] The `ct_pending` queue is populated within `clnt_bck_call`, which is triggered by the local kernel (the RPC client) initiating an outgoing callback request to a server. A remote server cannot force the local kernel to initiate these calls. Furthermore, every entry in the queue is guaranteed to be removed either when a reply is received (`clnt_bck_svccall`) or when the `msleep` timeout expires. Because the client controls the rate of request generation and all requests have a mandatory timeout, a remote attacker cannot cause unbounded growth of the queue to exhaust kernel memory.

