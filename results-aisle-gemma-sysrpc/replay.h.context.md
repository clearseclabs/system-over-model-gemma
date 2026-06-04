# Context: replay.h

This briefing covers `replay.h`, which defines the interface for the RPC replay cache.

**1. Function & Location**
This code provides a mechanism to prevent RPC replay attacks by caching requests and their corresponding responses. It sits in the RPC layer of the network stack, acting as a middleware between the request receiver and the execution engine.

**2. Untrusted Input Path**
Untrusted data arrives via the **network**. An attacker sends a crafted RPC packet, which is parsed into `struct rpc_msg` and `struct sockaddr` before being passed to `replay_find`.

**3. Attacker-Controlled Data**
*   `struct rpc_msg *msg`: Contains the RPC header and payload (XID, procedure call).
*   `struct sockaddr *addr`: Contains the source network address.
*   **Flow:** Network $\rightarrow$ RPC Parser $\rightarrow$ `replay_find` $\rightarrow$ Cache Lookup/Storage.

**4. Fixed-Size Buffers & Constants**
No fixed-size buffers or numeric constants are defined in this header. Memory allocation for the cache is controlled by the `size_t` parameters in `replay_newcache` and `replay_setsize`.

**5. Dangerous Data Flows**
The primary risk is the flow from `struct rpc_msg` and `struct sockaddr` into the internal `struct replay_cache` storage.

**6. Potential NULL Dereferences**
`struct replay_cache *rc`, `struct rpc_msg *msg`, and `struct sockaddr *addr` are passed as pointers. If the caller fails to validate these before calling `replay_find` or `replay_setreply`, a NULL dereference will occur.

**7. Tagged Unions**
None present in the header.

**8. API Visibility**
*   **Public API:** All functions listed (`replay_newcache`, `replay_setsize`, `replay_freecache`, `replay_find`, `replay_setreply`) are public.
*   **Static Helpers:** None defined here; these would reside in the corresponding `.c` file.

**9. Likely Bug Classes**
*   **Memory Exhaustion:** Unbounded `size_t` values in `replay_newcache`.
*   **Use-After-Free:** `replay_freecache` requires the caller to ensure no entries are `RS_INPROGRESS`.
*   **Hash Collisions/DoS:** If the internal lookup uses a weak hash of `rpc_msg` or `sockaddr`.