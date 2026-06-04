# Context: svc_vc.c

### Security Context Briefing: `svc_vc.c`

**1. Role and Location**
This file implements the server-side Connection-Oriented (TCP) transporter for the kernel RPC (KRPC) framework. It manages the lifecycle of TCP connections, including a "rendezvous" listener (accepting connections) and the subsequent record-based stream handling for RPC requests and replies.

**2. Untrusted Input Entry**
Untrusted input arrives via the **network** (TCP stream). Data enters through the socket layer via `soreceive` (called in `svc_vc_recv`) and `soaccept` (called in `svc_vc_rendezvous_recv`).

**3. Attacker-Controlled Data Flow**
*   **`header`**: Read from the socket in `svc_vc_process_pending`. It defines the record length.
*   **`cd->resid`**: Derived from `header`. Controls how many bytes are pulled from `cd->mpending` into `cd->mreq`.
*   **`cd->eor`**: Derived from `header` (bit 31). Signals the end of a record.
*   **`cd->mreq`**: The actual RPC message payload extracted from the socket.
*   **`xid_plus_direction`**: The first 8 bytes of `cd->mreq`, used to identify XIDs and message direction (REPLY vs CALL).

**4. Fixed-Size Buffers & Constants**
*   `struct sockaddr_storage ss`: Used in `svc_vc_rendezvous_recv` (size depends on architecture, typically ~128 bytes).
*   `xid_plus_direction[2]`: Array of 2 `uint32_t` (8 bytes).
*   `tgr` (`struct tls_get_record`): Size depends on definition in `sys/ktls.h`.
*   `TLS_MAX_MSG_SIZE_V10_2`: Used in `svc_vc_reply` (GREP needed for numeric value).
*   `uio.uio_resid = 1000000000`: A large constant used as a maximum read limit.

**5. Dangerous Data Flows**
*   **Source**: `header` $\rightarrow$ **Destination**: `cd->resid` $\rightarrow$ **Function**: `svc_vc_process_pending`. An attacker-controlled length determines the amount of data shifted into `cd->mreq`.
*   **Source**: `cd->mreq` $\rightarrow$ **Destination**: `xid_plus_direction` $\rightarrow$ **Function**: `svc_vc_recv` via `m_copydata`.

**6. Potential NULL Dereferences**
*   `xprt->xp_socket` is dereferenced in several places (e.g., `svc_vc_destroy_common`).
*   `ct` (`struct ct_data *`) in `svc_vc_backchannel_recv` is checked for NULL, but `xprt->xp_p2` is cast directly to `ct`.

**7. Tagged Unions/Variants**
*   `struct rpc_msg` is used; the code relies on `xdr_callmsg` and `xdr_replymsg` to handle the internal union types of the RPC message.

**8. API Surface**
*   **Public API**: `svc_vc_create`, `svc_vc_create_conn`, `svc_vc_create_backchannel`, `svc_vc_accept`.
*   **Static Helpers**: All `svc_vc_*_recv`, `_reply`, `_stat`, and `_destroy` functions. These are called via the `xp_ops` function pointer table.

**9. Likely Bug Classes**
*   **Integer Overflows/Underflows**: Specifically in record length calculations (`cd->resid`) and mbuf offsets.
*   **Resource Exhaustion (DoS)**: An attacker sending a record header with a massive `resid` without sending the actual bytes, potentially pinning memory in `cd->mreq`.
*   **State Machine Errors**: Improper transitions between `XPRT_IDLE` and `XPRT_DIED` during error handling.