# Scan: rpcm_subs.h

### Security Analysis of `rpcm_subs.h`

The file `rpcm_subs.h` contains internal macros used for the serialization (`rpcm_build`) and deserialization (`rpcm_dissect`, `rpcm_adv`) of RPC messages within `mbuf` chains. These macros operate on shared state variables (`mb`, `md`, `bpos`, `dpos`, `t1`, `error`) that are expected to be defined in the calling scope (specifically mentioned as `rpcm_reqhead`).

#### 1. `rpcm_build(a, c, s)`
This macro handles writing data into an `mbuf` chain.
- **Denial of Service (Panic):** The macro contains a hard `panic("build > MLEN")` if the size `(s)` exceeds `MLEN`. While `MLEN` is usually a large constant, if an attacker can influence the value of `s` during the construction of a response (e.g., by providing a very large length in a request that the server then echoes back in a response), they can trigger a kernel panic, leading to a complete system crash.
- **Integer Overflow:** The line `mb->m_len += (s);` performs addition without checking for overflow. If `s` is an unsigned integer and can be manipulated to wrap `m_len`, it could lead to memory corruption or incorrect buffer lengths being reported to the network stack.

#### 2. `rpcm_dissect(a, c, s)`
This macro extracts data from an `mbuf` chain.
- **Out-of-Bounds Read (Integer Underflow/Overflow):** 
    - `t1 = mtod(md, caddr_t) + md->m_len - dpos;`
    - This calculation determines the remaining space in the current `mbuf` segment. If `dpos` (the current dissection position) is ever advanced beyond the end of the current buffer (due to a bug in a calling function or malformed input), `t1` will underflow (since `t1` is likely a signed or unsigned integer used in comparisons).
    - If `t1` underflows to a very large positive value, the check `if (t1 >= (s))` will pass even if the buffer is exhausted, leading to an out-of-bounds read from the `mbuf` memory.
- **Implicit Trust in `s`:** The macro assumes the caller has validated that the total packet length is $\ge s$. If not, it relies on `rpcm_disct` or `rpc_adv` to catch the error. If those functions have flaws, an attacker can read memory beyond the allocated `mbuf` chain.

#### 3. `rpcm_adv(s)`
Similar to `rpcm_dissect`, this macro advances the dissection pointer.
- **Out-of-Bounds Pointer Arithmetic:** The calculation `t1 = mtod(md, caddr_t) + md->m_len - dpos;` is repeated here. The same risk of integer underflow exists. If `dpos` is pushed beyond the current buffer boundary, `t1` becomes massive, the `if (t1 >= (s))` check is bypassed, and `dpos` is incremented further into unmapped or unrelated kernel memory.

#### 4. General Architectural Concerns
- **State Dependency:** These macros rely on global/scope-level variables (`md`, `mb`, `dpos`, `bpos`). This pattern is highly prone to "state corruption" bugs. If any function in the call chain modifies `dpos` without updating the `mbuf` pointer (`md`), subsequent macro calls will perform invalid memory accesses.
- **Lack of NULL Checks:** There is no verification that `md` or `mb` are non-NULL. While the briefing suggests they are pre-initialized, a failure in the `m_get` or `m_getcl` calls preceding these macros would result in a NULL pointer dereference via `mtod`.

### Findings

```json
[
  {
    "severity": "high",
    "title": "Kernel Panic via Attacker-Controlled Build Size",
    "function": "rpcm_build",
    "description": "The macro triggers a kernel panic if the size parameter (s) exceeds MLEN. If an attacker can influence the size of data being serialized into a response, they can cause a remote Denial of Service."
  },
  {
    "severity": "high",
    "title": "Out-of-bounds Read via Pointer Underflow",
    "function": "rpcm_dissect / rpcm_adv",
    "description": "The calculation 'mtod(md, caddr_t) + md->m_len - dpos' can underflow if dpos is greater than the current buffer end. This causes the bounds check (t1 >= s) to pass erroneously, allowing dpos to be advanced into adjacent kernel memory."
  },
  {
    "severity": "medium",
    "title": "Integer Overflow in mbuf Length Update",
    "function": "rpcm_build",
    "description": "The expression 'mb->m_len += (s)' does not check for integer overflow. A large value of (s) could wrap the length field, potentially leading to memory corruption or bypassing later length checks."
  }
]
```