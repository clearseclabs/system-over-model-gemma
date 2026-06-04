# Context: auth_none.c

**Context Briefing – `auth_none.c` (≈250 words)**  

1. **Purpose & Location**  
`auth_none.c` implements the “null” authentication mechanism used by the NetBSD RPC client stack.  It is part of the kernel‑space RPC library (`/rpc/`, `/net/rpc/`), providing a singleton `AUTH` object (`authnone_create`) that sends empty credentials and verifiers to remote servers.  The file is loaded via a `SYSINIT()` hook so the global `authnone_private` structure is initialized once during boot.

2. **Untrusted Input Path**  
The global authenticator never accepts data from the network or external files.  The only RPC‑level data that flows into this module is the caller’s request arguments (`struct mbuf *args`) in `authnone_marshal`, but those arguments are forwarded unchanged via `xdr_putmbuf`; they are not written into the fixed buffer `mclient`.  Consequently, no untrusted input reaches `authnone_marshal`’s fixed‑size buffer.

3. **Data Flow & Fixed Buffers**  
* `mclient[20]` – a statically sized buffer that holds the XDR‑encoded “null auth” header.  
* `mcnt` – the size of `mclient` after encoding (`xdr_getpos`).  
The only data flow that touches `mclient` is during bootstrap (`authnone_init`) where it is filled with `_null_auth` via `xdrmem_create`/`xdr_opaque_auth`.  No attacker‑controlled values are ever written into it.

4. **Size Constants**  
```
GREP: "#define MAX_MARSHAL_SIZE"
#define MAX_MARSHAL_SIZE 20
```
Thus `mclient[20]` is fixed at 20 bytes.

5. **Dangerous Data Flows**  
None.  The fixed buffer is populated exclusively from the kernel’s `_null_auth` definition; there is no buffer write from external input.

6. **NULL Parameters**  
All functions receive a fixed `AUTH *` that originates from the single global instance; no dereference of potentially NULL pointers occurs.

7. **Variant Types**  
The file only deals with opaque_auth structs; no tagged unions or type‑tag validation is required.

8. **Public vs. Static**  
*Public API*: `authnone_create()` returns the `AUTH *` to clients.  
*Static helpers*: `authnone_marshal`, `authnone_verf`, `authnone_validate`, `authnone_refresh`, `authnone_destroy`.  They are only called through the `authnone_ops` table and are not exposed externally.

9. **Likely Bug Classes**  
* **Race Condition / Concurrency** – the singleton `authnone_private` is accessed by multiple threads; however, initialization occurs in `SYSINIT()`.  If the client library is used concurrently before init, a data‑race could occur.  
* **Buffer Over‑read (unlikely)** – if the XDR stream pos returned by `XDR_GETPOS()` changes unexpectedly, an overflow could be attempted, but the size is bounded by `MAX_MARSHAL_SIZE`.  

Overall, `auth_none.c` contains no apparent vulnerability paths from untrusted input to critical buffers.

[GREP RESULTS from codebase]:
GREP `#define MAX_MARSHAL_SIZE`:
```
lib/libc/rpc/auth_none.c:51:#define MAX_MARSHAL_SIZE 20
sys/rpc/auth_none.c:54:#define MAX_MARSHAL_SIZE 20
sys/rpc/rpcsec_tls/auth_tls.c:58:#define MAX_MARSHAL_SIZE 20
```