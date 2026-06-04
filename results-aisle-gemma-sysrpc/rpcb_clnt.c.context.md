# Context: rpcb_clnt.c

This briefing covers `rpcb_clnt.c`, which implements the client-side interface to the `rpcbind` service (portmapper) within the kernel.

### 1. Functionality and Location
This code provides the kernel-level client logic to register (`rpcb_set`) or remove (`rpcb_unset`) RPC service mappings. It sits in the RPC subsystem and interacts with the `rpcbind` daemon via the `CLNT_CALL` interface.

### 2. Untrusted Input Path
Input typically reaches these functions from other kernel components attempting to export RPC services (e.g., NFS). While the data originates from the kernel, the `netconfig` and `netbuf` structures can be influenced by system configuration or network interface settings.

### 3. Attacker-Controlled Data Flow
*   **Variables:** `program`, `version`, `nconf` (struct netconfig), and `address` (struct netbuf).
*   **Flow:** `rpcb_set(program, version, nconf, address)` $\rightarrow$ `taddr2uaddr(&nconfcopy, &addresscopy)` $\rightarrow$ `parms.r_addr` $\rightarrow$ `CLNT_CALL` $\rightarrow$ XDR serialization $\rightarrow$ Network.

### 4. Fixed-Size Buffers
*   `uidbuf[32]`: Found in commented-out (`#if 0`) blocks. Resolved size: **32 bytes**.
*   `nullstring[]`: Static constant. Resolved size: **2 bytes** (including null terminator).

### 5. Dangerous Data Flows
There are no active flows from attacker-controlled data into fixed-size buffers in the current enabled code. The `snprintf` into `uidbuf` is disabled.

### 6. Potential NULL Dereferences
*   `rpcb_clnt`: The global client handle is initialized via `SYSINIT`. If `client_nl_create` fails, the `KASSERT` triggers, but subsequent calls to `CLNT_CALL` would dereference a NULL `rpcb_clnt`.

### 7. Tagged Unions/Variants
No tagged unions are processed in this file. Data is handled via the `RPCB` structure and XDR.

### 8. API Visibility
*   **Public API:** `rpcb_set`, `rpcb_unset`.
*   **Static Helpers:** `local_rpcb` (Initialization helper called by `SYSINIT`).

### 9. Likely Bug Classes
*   **Resource Leaks:** Potential for `parms.r_addr` leak if `CLNT_CALL` fails or crashes.
*   **Race Conditions:** `rpcb_clnt` is a global static pointer accessed without locking in `rpcb_set/unset`.
*   **Null Pointer Dereference:** Reliance on `SYSINIT` success for the global `rpcb_clnt` handle.