# Triage T0168: ummary of High‑Risk Findings

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

ummary of High‑Risk Findings

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code allocates memory based on the value returned by the user‑controlled upcall daemon: `*ngrps = res.gid.gid_len; *gids = mem_alloc(*ngrps * sizeof(gid_t));` The multiplication is performed with an `int` (`*ngrps`) and `sizeof(gid_t)` (4 bytes). If the daemon returns a large `gid_len`, the multiplication can wrap around the 32‑bit signed int, producing a small allocation size while the subsequent copy loop copies `*ngrps` entries, overrunning the buffer and corrupting kernel memory. The value `gid_len` originates from the user‑space rpctlssd service, so a malicious user can inject any value, making the vulnerability real and exploitable. Other listed issues are either low impact or rely on improper user input handling that does not lead to memory corruption. Hence the reported high‑risk findings are valid.

