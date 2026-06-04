# Context: rpcsec_tls/rpctls_impl.c

This briefing covers `rpcsec_tls/rpctls_impl.c`, which implements the kernel-side orchestration for RPC-over-TLS.

### 1. Function and Location
This file manages the transition of RPC sockets from the kernel to userspace TLS daemons (`rpctlscd` for clients, `rpctlssd` for servers) to perform TLS handshakes. It sits between the KRPC layer and the userspace TLS helpers.

### 2. Untrusted Input Path
Input reaches this code via:
*   **Network:** Incoming RPC requests (specifically NULL RPCs with `AUTH_TLS` flavor) trigger `_svcauth_rpcsec_tls`.
*   **Syscalls:** `sys_rpctls_syscall` is called by the userspace daemons to reclaim sockets.

### 3. Attacker-Controlled Data
*   **`uap->socookie`**: Passed from userspace to `sys_rpctls_syscall`. It is cast to `struct socket *` and used for RB-tree lookups.
*   **`certname`**: Passed to `rpctls_connect`. It is used to populate `arg.certname.certname_val`.
*   **`res` (RPC Responses)**: Data returned from `rpctlscd_connect_2` and `rpctlssd_connect_2` (e.g., `res.uid`, `res.gid.gid_len`, `res.flags`) is used to update `SVCXPRT` states.

### 4. Fixed-Size Buffers and Constants
No traditional fixed-size arrays are declared in this file. Memory is primarily allocated via `mem_alloc` based on sizes returned by the RPC response.

### 5. Dangerous Data Flows
*   **`res.gid.gid_len` $\rightarrow$ `mem_alloc`**: In `rpctls_server`, `*ngrps` (from `res.gid.gid_len`) is used to allocate memory for `gidp`. If `gid_len` is excessively large, it could lead to kernel memory exhaustion.
*   **`res.gid.gid_val` $\rightarrow$ `gidp`**: Data from the RPC response `gid_val` is copied into the allocated `gidp` buffer via a loop based on `*ngrps`.

### 6. NULL Dereferences
*   **`uap`**: In `sys_rpctls_syscall`, `uap` is dereferenced to access `socookie`.
*   **`newclient` / `so`**: In `rpctls_connect`, these are dereferenced without checks.

### 7. Tagged Unions
The `struct upsock` contains a union of `CLIENT *cl` and `SVCXPRT *xp`. Access is governed by the `bool server` flag. In `sys_rpctls_syscall`, the code checks `ups.server` before accessing `ups.xp`.

### 8. API Visibility
*   **Public API:** `rpctls_init`, `rpctls_connect`, `rpctls_cl_handlerecord`, `rpctls_srv_handlerecord`, `rpctls_cl_disconnect`, `rpctls_srv_disconnect`, `_svcauth_rpcsec_tls`, `rpctls_getinfo`.
*   **Static Helpers:** `rpctls_server`, `rpctls_rpc_failed`, `upsock_compare`. These are called internally; `rpctls_server` is called by `_svcauth_rpcsec_tls`.

### 9. Likely Bug Classes
*   **Integer Overflows/DoS:** Memory allocation in `rpctls_server` based on `res.gid.gid_len`.
*   **Race Conditions:** Potential window between `RB_REMOVE` and `soclose` in `sys_rpctls_syscall` or `rpctls_rpc_failed`.
*   **Type Confusion:** Mismanagement of the `upsock` union if `server` flag is corrupted.