# Scan: rpcsec_gss/rpcsec_gss.c

### Security Analysis of `rpcsec_gss/rpcsec_gss.c`

The provided code implements the client-side logic for RPCSEC_GSS. After a step-by-step analysis of data flow and memory management, several high-severity vulnerabilities were identified.

#### 1. Heap-based Buffer Overflow / Memory Exhaustion in `rpc_gss_validate`
In `rpc_gss_validate`, the function receives a `struct opaque_auth *verf` from the network (via the RPC layer).
```c
if (gd->gd_state == RPCSEC_GSS_CONTEXT) {
    // ...
    gd->gd_verf.value = mem_alloc(verf->oa_length);
    if (gd->gd_verf.value == NULL) {
        // ... error handling ...
    }
    memcpy(gd->gd_verf.value, verf->oa_base, verf->oa_length);
    gd->gd_verf.length = verf->oa_length;
    return (TRUE);
}
```
**Vulnerability:** `verf->oa_length` is an attacker-controlled value from the network packet.
- **Memory Exhaustion:** An attacker can send a packet with a massive `oa_length` to trigger a kernel panic or exhaust the heap.
- **Integer Overflow:** While `mem_alloc` likely takes a `size_t`, if `oa_length` is used in calculations elsewhere or if the allocator has internal size limits, it can lead to unexpected behavior.
- **Lack of Bounds Check:** There is no upper limit checked against `verf->oa_length` before calling `mem_alloc` and `memcpy`.

#### 2. Race Condition / Use-After-Free in `rpc_gss_secfind`
The `rpc_gss_secfind` function manages a global cache of security contexts using a shared lock `rpc_gss_lock`.
```c
if (rpc_gss_count > RPC_GSS_MAX) {
    while (rpc_gss_count > RPC_GSS_MAX) {
        sx_xlock(&rpc_gss_lock);
        tgd = TAILQ_FIRST(&rpc_gss_all);
        // ... remove from lists ...
        rpc_gss_count--;
        sx_xunlock(&rpc_gss_lock);
        AUTH_DESTROY(tgd->gd_auth);
    }
}
```
**Vulnerability:** The cache eviction logic is flawed.
- The code removes a `rpc_gss_data` object (`tgd`) from the cache and immediately calls `AUTH_DESTROY(tgd->gd_auth)`.
- However, `AUTH_DESTROY` only calls `rpc_gss_destroy`, which calls `refcount_release(&gd->gd_refs)`.
- If another thread is currently using that `AUTH` object (having acquired a reference in the `TAILQ_FOREACH` loop below), the object stays alive. But the logic for `rpc_gss_count` is decremented immediately. 
- More critically, if the `refcount` is 1, `rpc_gss_destroy` proceeds to free `gd` and `auth`. If another thread is concurrently executing the lookup loop and has a pointer to `gd` but hasn't called `refcount_acquire` yet, it will dereference a freed pointer.

#### 3. Potential Kernel Stack Overflow in `rpc_gss_marshal`
```c
char credbuf[MAX_AUTH_BYTES];
// ...
xdrmem_create(&tmpxdrs, credbuf, sizeof(credbuf), XDR_ENCODE);
if (!xdr_rpc_gss_cred(&tmpxdrs, &gsscred)) { ... }
```
**Vulnerability:** The code relies on `MAX_AUTH_BYTES` to be sufficient for the XDR encoding of `gsscred`. If the GSS-API implementation or a specific mechanism produces credentials that exceed this constant, `xdr_rpc_gss_cred` may overflow the stack buffer `credbuf` if the XDR implementation does not strictly enforce the buffer size passed to `xdrmem_create`. (Note: While `xdrmem_create` suggests size enforcement, many legacy XDR implementations have had boundary issues).

#### 4. Logic Error / Resource Leak in `rpc_gss_init`
In the GSS context establishment loop:
```c
if (recv_tokenp != GSS_C_NO_BUFFER) {
    xdr_free((xdrproc_t) xdr_gss_buffer_desc,
        (char *) &recv_token);
    recv_tokenp = GSS_C_NO_BUFFER;
}
```
**Vulnerability:** `recv_token` is a local `gss_buffer_desc` structure. The code calls `xdr_free` on the address of the local structure itself (`&recv_token`), rather than the buffer pointer contained within it (`recv_token.value`). This will likely lead to a kernel crash (Invalid Free) as the allocator attempts to free a stack address.

### Summary of Findings

```json
[
  {
    "severity": "critical",
    "title": "Kernel Heap Overflow/Exhaustion via Unchecked Network Length",
    "function": "rpc_gss_validate()",
    "description": "The function allocates memory for 'gd->gd_verf.value' using 'verf->oa_length' directly from untrusted network input without bounds checking. An attacker can cause memory exhaustion or trigger a kernel panic by providing an excessively large length."
  },
  {
    "severity": "critical",
    "title": "Invalid Free of Stack Memory",
    "function": "rpc_gss_init()",
    "description": "The code calls 'xdr_free' on the address of a local stack variable '&recv_token' instead of the buffer pointer 'recv_token.value'. This will result in an immediate kernel crash when the memory allocator attempts to free stack-allocated memory."
  },
  {
    "severity": "high",
    "title": "Race Condition in Cache Eviction leading to Use-After-Free",
    "function": "rpc_gss_secfind()",
    "description": "The LRU cache eviction logic removes entries from the global list and calls AUTH_DESTROY without ensuring that no other threads are currently traversing the list with a pointer to the object, leading to a potential Use-After-Free (UAF) scenario."
  }
]
```