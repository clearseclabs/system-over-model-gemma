# Context: svc_auth.h

**Context Briefing – `svc_auth.h` (≈250 words)**  

1. **Purpose & Location**  
   * `svc_auth.h` is the header for the *service‑side* RPC authentication subsystem in the network‑layer RPC stack (historically part of Sun RPC and now NetBSD).  
   * It declares the public API for authenticating incoming RPC requests (`_authenticate`), registering authentication handlers (`svc_auth_reg`), and extracting Unix credentials from a request (`svc_getcred`).  
   * Implementations live in the `rpc` module (e.g., `svc_auth_unix.c`, `svc_auth_null.c`).  

2. **Untrusted Input Path**  
   * The `struct svc_req *req` argument represents an incoming RPC call received over the network (UDP/TCP).  The data in `svc_req` (e.g., caller credentials, authentication blob) originates from the wire and is thus attacker‑controlled.  

3. **Variables Carrying Attacker‑Controlled Data**  
   * `req` – full request data (caller’s credentials, authentication flavor).  
   * `msg` (from `struct rpc_msg *`) – optional fields like the authentication body passed in the request.  
   * `crp`, `flavorp` (in `svc_getcred`) receive data derived from `req` and may be overwritten by the caller’s supplied pointers.  

4. **Fixed‑Size Buffers / Constants**  
   * This header does not declare any buffers or numeric constants; the actual buffers are defined in the concrete implementations (e.g., `AUTH_MAXLEN` in `svc_auth_null.c`).  
   * Any size constants are retrieved via `grep` in the implementation files (e.g., `grep -n "AUTH_MAXLEN" *`).  

5. **Dangerous Data Flow**  
   * `req` → authentication blob inside `svc_req` → buffer in the specific auth implementation (`svc_auth_unix.c`).  
   * The implementation must copy the blob into a fixed‑size buffer (e.g., `char authbuf[AUTH_MAXLEN];`) using the length from `req->sreq_auth->au_len`.  If `au_len` exceeds `AUTH_MAXLEN`, overflow may occur.  

6. **Potential NULL Dereferences**  
   * If a malformed request omits `sreq_auth`, functions may receive a NULL pointer for the auth structure and call `->au_flavor` without a NULL check.  

7. **Tagged Union / Variant Types**  
   * `struct svc_req` contains `sreq_auth`, which is a `xdr_opaque *` but accessed via flavor tags (`au_flavor`). No explicit type‑tag validation in this header; implementations must check the auth flavor.  

8. **API vs Helpers**  
   * All functions (`_authenticate`, `svc_auth_reg`, `svc_getcred`) are exported (`extern`).  
   * There are no static helpers declared here; the implementations define private static callbacks (`svc_auth/*_auth`, etc.).  

9. **Likely Bug Classes**  
   * **Buffer over‑run** from copying user‑supplied auth data into fixed‑size buffers.  
   * **NULL‑pointer dereference** when parsing malformed `svc_req` structures.  
   * **Missing auth‑flavor validation** leading to processing unrecognized authentication types.  

*GREP:*  
```
grep -n "AUTH_MAXLEN" -R src/rpc/*.c
```