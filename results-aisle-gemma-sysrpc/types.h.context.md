# Context: types.h

This is a context briefing for `types.h`.

**1. Role and Location**
This is a header file containing type definitions and macros for the RPC (Remote Procedure Call) implementation. It serves as a foundational types layer, providing transport-independent abstractions and compatibility wrappers for NetBSD/FreeBSD/SunOS.

**2. Untrusted Input Path**
Data does not flow *through* this file (it contains no logic), but it defines the structures used to handle network data. Untrusted input arrives via the network, is parsed by the RPC transport layer, and is stored in the structures defined here.

**3. Attacker-Controlled Data**
*   `struct netbuf.len` and `struct netbuf.buf`: These carry network addresses and transport-specific options.
*   `struct t_bind.addr` and `struct t_bind.qlen`: Carry binding parameters from the network/API.
*   **Flow:** Network Packet $\rightarrow$ Transport Layer $\rightarrow$ `netbuf` $\rightarrow$ RPC Processing Logic.

**4. Fixed-Size Buffers**
There are no statically sized arrays (e.g., `char buf[N]`) in this file. All buffers (like `netbuf.buf`) are pointers to dynamically allocated memory via `mem_alloc`.

**5. Dangerous Data Flows**
*   **Source:** Network input $\rightarrow$ **Destination:** `netbuf.buf` via `mem_alloc`.
*   **Risk:** If `netbuf.len` is controlled by the attacker and used in subsequent `memcpy` or `read` operations without bounds checking against `maxlen`.

**6. Potential NULL Dereferences**
*   `struct netbuf.buf`: May be NULL if `mem_alloc` fails or if a malformed request specifies zero length.
*   `struct __rpc_sockinfo`: Internal structure; if passed as a pointer to helpers, it may be NULL.

**7. Tagged Unions**
None present in this file.

**8. API vs. Helpers**
This file defines types only. It defines `mem_alloc`/`mem_free` macros which wrap `malloc`/`free` (userland) or `MALLOC_DECLARE` (kernel).

**9. Likely Bug Classes**
*   **Integer Overflows:** Discrepancies between `maxlen` and `len` in `struct netbuf`.
*   **Heap Overflows:** Improper use of `netbuf.len` when copying data into the dynamic `buf`.
*   **Memory Leaks:** Failure to call `mem_free` on `netbuf` allocations.