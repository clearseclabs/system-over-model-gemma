# Context: svc_auth.h

This is a header file (`svc_auth.h`) defining the interface for the server-side RPC authentication framework. It acts as the glue between the RPC request handling layer and the credential verification logic.

**1. Role & Location:** It sits in the RPC service layer, providing the API for registering authentication handlers and retrieving user credentials (`ucred`) for a given request.

**2. Input Path:** Untrusted input arrives via the network as RPC messages. These are parsed into `struct rpc_msg` and encapsulated within `struct svc_req`.

**3. Attacker-Controlled Data:** Data flows from the network $\to$ `struct rpc_msg` (specifically the authentication body) $\to$ `_authenticate()` and `svc_getcred()`. The `struct rpc_msg *` pointer carries the raw, untrusted request.

**4. Fixed-Size Buffers:** No buffers are defined in this header.

**5. Dangerous Data Flows:** None defined in this header; flows occur within the implementations of `_authenticate` and `svc_getcred`.

**6. NULL Dereferences:** `struct svc_req *` and `struct rpc_msg *` are the primary pointers. If the RPC layer fails to allocate these before calling the auth hooks, dereferences will occur.

**7. Tagged Unions:** Not present in this header.

**8. API Visibility:**
*   **Public API:** `_authenticate`, `svc_auth_reg`, and `svc_getcred` are all exported (extern).
*   **Static Helpers:** None present.

**9. Likely Bug Classes:** 
*   **Authentication Bypass:** Failures in `_authenticate` logic.
*   **Integer Overflows/Buffer Overflows:** During the parsing of the `rpc_msg` authentication blob.
*   **Use-After-Free/Memory Leaks:** Related to the `ucred` pointers returned by `svc_getcred` (which require manual `crfree`).