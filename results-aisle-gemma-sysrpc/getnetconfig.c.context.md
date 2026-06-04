# Context: getnetconfig.c

### Security Context Briefing: `getnetconfig.c`

**1. Role & Location**
This code provides a kernel-space implementation of network configuration lookups (similar to `getnetconfig` in libc) for the RPC subsystem. It manages a static table of supported network protocols (`netconfigs`) and provides an iterator interface.

**2. Untrusted Input Path**
Untrusted input reaches this code via the `netid` parameter in `getnetconfigent()`. This is typically triggered by RPC requests specifying a particular network protocol.

**3. Attacker-Controlled Data**
*   **Variable:** `netid` (const char *)
*   **Flow:** External RPC Request $\rightarrow$ RPC Dispatcher $\rightarrow$ `getnetconfigent(netid)` $\rightarrow$ `strcmp(netid, nconf->nc_netid)`.

**4. Fixed-Size Buffers & Constants**
There are no fixed-size arrays or buffers defined within this file. It relies on a static array of `struct netconfig` containing pointers to string literals.

**5. Dangerous Data Flows**
None. There are no copies of `netid` into fixed-size buffers; it is only used for read-only comparison via `strcmp`.

**6. NULL Dereferences**
*   `getnetconfig(void *handle)`: Dereferences `handle` (cast to `struct netconfig **`) without checking if `handle` is NULL.
*   `endnetconfig(void *handle)`: Passes `handle` directly to `free()` without validation.

**7. Tagged Unions**
None present.

**8. API Visibility**
*   **Public API:** `setnetconfig`, `getnetconfig`, `getnetconfigent`, `freenetconfigent`, `endnetconfig`.
*   **Static Helpers:** None.

**9. Likely Bug Classes**
*   **Null Pointer Dereference:** Specifically regarding the `handle` passed to `getnetconfig` and `endnetconfig`.
*   **Type Confusion:** `void *handle` is cast to `struct netconfig **`. If a caller passes an incorrect pointer type, it will lead to an invalid memory access.