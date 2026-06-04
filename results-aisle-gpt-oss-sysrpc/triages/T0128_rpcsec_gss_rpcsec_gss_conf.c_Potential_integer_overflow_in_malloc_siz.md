# Triage T0128: Potential integer overflow in malloc size computation

- **File**: `rpcsec_gss/rpcsec_gss_conf.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Potential integer overflow in malloc size computation

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN

{"reasoning":"The reported overflow occurs in `rpc_gss_get_mechanisms` when allocating an array of pointers to mechanism names:\n\n```\ncount = 0;\nLIST_FOREACH(km, &kgss_mechs, km_link) count++;\ncount++;\nmech_names = malloc(count * sizeof(const char *), M_RPC, M_WAITOK);\n```\n\n`count` is set solely by iterating over the kernel list `kgss_mechs`. This list contains the GSS mechanisms that are compiled and registered with the RPCSEC_GSS subsystem during kernel module load. It is not possible for user‑space or an external RPC client to add entries to this list – only kernel code that registers mechanisms can do so, and the number of built‑in mechanisms is a small, compile‑time constant (typically 1–5). Therefore the value of `count` is bounded by a known, low constant and cannot be influenced by attacker input.\n\nMoreover, the multiplication is performed as a 64‑bit `size_t` on all supported architectures. Even on 32‑bit architectures, the maximum theoretical product (`INT_MAX * sizeof(char *) ≈ 17 GB`) exceeds `SIZE_MAX` only if the list itself were astronomically large, which it cannot be. The actual list is tiny, so the product is well within bounds and will never trigger an overflow.\n\nBecause the count is both bounded and attacker‑unreachable, the potential overflow is a non‑security bug and does not lead to a crash, code execution, or data corruption in any realistic scenario.\n\nNo additional runtime defense is required, and the code behaves correctly given its intended usage. Hence the scanner’s finding is a false positive.\n\nThe key fact is that `kgss_mechs` is a static, kernel‑only list whose size is fixed at compile time, making the `count` unforgeable and the multiplication safe.\n\n\"crc\"Verifying this requires inspecting the definition of `kgss_mechs` and any registration functions, e.g.: using the grep pattern \"kgss_mechs\" will locate its declaration and confirm it is a static list initialized at module load.\n\nPotential Overflow Check: Even if `sizeof(char *)` is 8 and `count == INT_MAX`, the product is `INT_MAX * 8 ≈ 17 GB`, which is < 2^64‑1, so no wraparound occurs on 64‑bit or on 32‑bit `size_t` when `count` is tiny.\n\nThus the vulnerability is not valid.\n","crux":"`kgss_mechs` is a static, kernel‑only list of registered GSS mechanisms; `count` is derived from it and cannot be set by an attacker, so the multiplication is safe and the bug is not exploitable.","grep":"kgss_mechs","verdict":"INVALID"}

### Round 4: ❌ INVALID

[ARBITER] The overflow can only occur if `count` exceeds the maximum number of GSS mechanisms that can be registered in the kernel. In practice that list is limited to a handful of entries (a handful of modules), far below INT_MAX. Even on a 32‑bit system the overflow would require on the order of 1 billion entries, which is impossible to achieve from user space. Moreover, the list is manipulated only by privileged kernel code, not by external users. Consequently, the integer overflow is a theoretical corner case with no realistic attack surface, so it does not constitute a practical security vulnerability.

