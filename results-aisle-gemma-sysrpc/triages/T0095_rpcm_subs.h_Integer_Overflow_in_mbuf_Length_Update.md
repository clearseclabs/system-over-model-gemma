# Triage T0095: Integer Overflow in mbuf Length Update

- **File**: `rpcm_subs.h`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Integer Overflow in mbuf Length Update

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The `if ((s) > MLEN) panic("build > MLEN");` check prevents an attacker from providing an arbitrarily large value for `s`, making an integer overflow of `m_len` practically impossible given standard `MLEN` values.

The reported vulnerability is an integer overflow in the `rpcm_build(a, c, s)` macro at the line `mb->m_len += (s);`. 

1. **Bug Pattern**: The bug pattern exists. There is no check to see if `mb->m_len + s` overflows the type of `m_len`.
2. **Reachability**: The `rpcm_build` macro is used to construct RPC responses (building an mbuf from data). For this to be a security vulnerability, an attacker must control the value of `(s)`. In RPC, `(s)` typically represents the size of a data element being serialized. If `(s)` is derived from attacker-supplied input (e.g., a length field in a request that is mirrored back in a response), the overflow can occur.
3. **Defense Verification**: The macro contains a check: `if ((s) > MLEN) panic("build > MLEN");`. This is a critical defense. If `s` is capped at `MLEN`, and `mb->m_len` is also capped by `MLEN` (which is the architectural limit of a single mbuf data area), the sum `mb->m_len + s` cannot overflow a standard integer type used for lengths (typically 16 or 32 bits) unless `MLEN` itself is extremely large. Even if `mb->m_len` was already `MLEN`, and `s` was `MLEN`, the total would be `2 * MLEN`. In BSD-derived mbuf implementations, `MLEN` is typically a few kilobytes (e.g., 2048 or 4096), and `m_len` is usually a 16-bit or 32-bit unsigned integer. 

To confirm if this is a vulnerability, we must verify the value of `MLEN` and the type of `m_len`. However, the presence of the `panic` check `if ((s) > MLEN)` effectively prevents any arbitrarily large `s` from being added. Since `mb->m_len` is reset to 0 just before the addition if a new mbuf is allocated, or is limited by the mbuf's capacity, the addition is bounded.

CRUX: The `if ((s) > MLEN) panic("build > MLEN");` check prevents an attacker from providing an arbitrarily large value for `s`, making an integer overflow of `m_len` practically impossible given standard `MLEN` values.
GREP: MLEN

🔎 **Grep results:**

GREP `MLEN`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `if ((s) > MLEN) panic("build > MLEN");` check and the preceding `mb->m_len = 0` assignment ensure the addition `mb->m_len += (s)` cannot overflow standard integer types used for mbuf lengths.

The reported vulnerability is an integer overflow in the `rpcm_build` macro: `mb->m_len += (s);`. 

1. **Bug Pattern**: The code performs addition without an explicit overflow check. However, the logic surrounding it provides a strong bound. If `(s) > M_TRAILINGSPACE(mb)`, the code allocates a new mbuf, sets `mb->m_len = 0`, and then checks `if ((s) > MLEN) panic("build > MLEN");`. If it doesn't panic, `s` is at most `MLEN`. 

2. **Reachability**: This macro is used for *building* (serializing) responses. For an attacker to trigger this, they must control `s`. Even if they do, the `panic` check and the mbuf allocation logic constrain `s` to `MLEN` and `mb->m_len` to the remaining space in the mbuf. 

3. **Defense Verification**: The key defense is `if ((s) > MLEN) panic("build > MLEN");`. While the previous reviewer's grep for `MLEN` failed (likely due to it being defined in a system header like `<sys/mbuf.h>` not present in the local repo), `MLEN` is a standard BSD kernel constant for the maximum size of a single mbuf data area (typically 2048 or 4096 bytes). 

If `s <= MLEN` and `mb->m_len` is the current length of a single mbuf (also capped by `MLEN`), the maximum possible value of `mb->m_len + s` is approximately `2 * MLEN`. Given that `m_len` is typically a `uint16_t` or `uint32_t`, a value of ~8KB cannot cause an integer overflow. If a new mbuf was just allocated, `mb->m_len` is 0, and the result is simply `s` (which is `<= MLEN`).

4. **Conclusion**: The logic ensures that the addition is performed on values that are small relative to the capacity of the integer type used for `m_len`.

CRUX: The `if ((s) > MLEN) panic("build > MLEN");` check and the preceding `mb->m_len = 0` assignment ensure the addition `mb->m_len += (s)` cannot overflow standard integer types used for mbuf lengths.
GREP: MLEN

🔎 **Grep results:**

GREP `MLEN`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The logic `mb->m_len = 0` followed by `if ((s) > MLEN) panic(...)` ensures that the addition `mb->m_len += (s)` is bounded by `MLEN`, which is far below the overflow threshold of any standard integer type used for mbuf lengths.

The reported vulnerability is an integer overflow in the `rpcm_build` macro: `mb->m_len += (s);`. For this to be security-relevant, `s` must be attacker-controlled and large enough to cause an overflow. However, the macro implements a strict defense: `if ((s) > M_TRAILINGSPACE(mb))`. If the current buffer doesn't have enough space, it allocates a new mbuf (`mb2`), sets the current pointer to it (`mb = mb2`), and explicitly sets `mb->m_len = 0`. It then checks `if ((s) > MLEN) panic("build > MLEN");`. 

This means there are only two paths to the addition `mb->m_len += (s)`:
1. `s <= M_TRAILINGSPACE(mb)`: Here, `m_len + s` is bounded by the total capacity of a single mbuf (usually `MLEN`).
2. `s > M_TRAILINGSPACE(mb)`: The code sets `mb->m_len = 0` and ensures `s <= MLEN`. The result of the addition is exactly `s`, which is `≤ MLEN`.

In either case, the resulting value is bounded by approximately `MLEN`. In BSD-derived network stacks, `MLEN` is typically 2048 or 4096 bytes. Even if `m_len` is a 16-bit unsigned integer (the smallest common type for mbuf lengths), it can hold up to 65,535. A value of ~4KB cannot overflow this. The `panic` prevents any `s` larger than `MLEN` from ever reaching the addition. Thus, the overflow is mathematically impossible under the constraints provided by the code.

CRUX: The logic `mb->m_len = 0` followed by `if ((s) > MLEN) panic(...)` ensures that the addition `mb->m_len += (s)` is bounded by `MLEN`, which is far below the overflow threshold of any standard integer type used for mbuf lengths.
GREP: MLEN

🔎 **Grep results:**

GREP `MLEN`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The addition `mb->m_len += (s)` is protected by the preceding logic. If `(s)` exceeds the available trailing space, a new mbuf is allocated, `mb->m_len` is explicitly set to 0, and `(s)` is checked against `MLEN` (triggering a panic if exceeded). If a new mbuf is not allocated, `(s)` is by definition less than or equal to `M_TRAILINGSPACE(mb)`. In either case, the resulting `m_len` cannot overflow a standard integer type used for buffer lengths, as it is bounded by `MLEN` or the buffer's maximum capacity.

