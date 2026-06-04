# Context: rpcm_subs.h

This briefing covers `rpcm_subs.h`, which provides helper macros for serializing and deserializing RPC messages using `mbuf` structures.

**1. Role & Location**
This is a header file containing utility macros (`rpcm_build`, `rpcm_dissect`, `rpcm_adv`) used by the RPC layer to move data between memory buffers and `mbuf` chains. It sits in the transport/marshalling layer of the RPC implementation.

**2. Input Path**
Untrusted input reaches this code via the network. Data is received into `mbuf` chains, which are then processed by functions (likely in `rpcm_reqhead` or similar) that employ the `rpcm_dissect` and `rpcm_adv` macros.

**3. Attacker-Controlled Data**
The data resides in the `mbuf` chain (`md`). The pointer `dpos` (current dissection position) and the content of the buffers accessed via `mtod(md, caddr_t)` are attacker-controlled. Data flow: `Network` $\rightarrow$ `mbuf (md)` $\rightarrow$ `rpcm_dissect` $\rightarrow$ local variable `(a)`.

**4. Buffers & Constants**
*   **`MLEN`**: The maximum size of a single `mbuf` data area. 
    GREP: `grep -r "#define MLEN" .`
*   **`M_TRAILINGSPACE`**: A macro calculating available space in the current `mbuf`.

**5. Dangerous Data Flows**
*   **`rpcm_build`**: Data $\rightarrow$ `mb`. If `(s)` (size) is controlled by an attacker and exceeds `MLEN`, the code triggers a `panic`.
*   **`rpcm_dissect`**: `md` (network data) $\rightarrow$ `(a)` (local variable). If `(s)` is large, it calls `rpcm_disct` to handle fragmented `mbufs`.

**6. NULL Dereferences**
The macros rely on `mb`, `md`, and `dpos` being pre-initialized. If the `mbuf` chain `md` is NULL, `mtod(md, ...)` will dereference a NULL pointer.

**7. Tagged Unions**
Not present in this header, though the comments mention "xdr discriminating unions" are handled by the functions these macros support.

**8. API vs Helpers**
These are internal macros. They are not public APIs but are used by static and public RPC processing functions.

**9. Likely Bug Classes**
*   **Integer Overflows**: In size calculations (`(s) > M_TRAILINGSPACE`).
*   **Out-of-bounds Reads**: In `rpcm_dissect` if `(s)` is not properly validated against total packet length.
*   **DoS**: Via the `panic("build > MLEN")` path if an attacker can influence the build size `(s)`.

[GREP RESULTS from codebase]:
GREP `grep -r "#define MLEN" .`:
```
(no matches in repo)
```