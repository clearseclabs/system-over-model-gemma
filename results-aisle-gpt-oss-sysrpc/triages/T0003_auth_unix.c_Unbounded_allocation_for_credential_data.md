# Triage T0003: Unbounded allocation for credential data

- **File**: `auth_unix.c`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [IUU]

---

## Finding

Unbounded allocation for credential data

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** `MAX_AUTH_BYTES` limits the serialization buffer to 256 bytes; encode failure aborts, so `len`≤256 and allocation is bounded.

The code path that allocates credentials is guarded by the XDR encode length limit.  The buffer used for encoding, `mymem`, is created with a length of `MAX_AUTH_BYTES`.  `MAX_AUTH_BYTES` is defined in `<rpc/rpc_com.h>` and resolves to 256 bytes.  If the credential serialization (`xdr_authunix_parms`) would exceed this buffer, the function returns `FALSE` and the code panics, aborting the operation before any allocation occurs.  Thus, `len` (the value from `XDR_GETPOS(&xdrs)`) is always ≤ 256.  The subsequent `mem_alloc((u_int)len)` therefore allocates at most 256 bytes, which is far below any attacker‑controlled size that could trigger an OOM or memory corruption.  No attacker‑controlled input can bypass this bound because the only way to reach the allocation is through a successful encode, which is capped by `MAX_AUTH_BYTES`.

Therefore, the reported unbounded allocation is a false positive: the code has an effective bound and is attacker‑reachable but safe.

CRUX: `MAX_AUTH_BYTES` limits the serialization buffer to 256 bytes; encode failure aborts, so `len`≤256 and allocation is bounded.
GREP: #define[[:space:]]*MAX_AUTH_BYTES[[:space:]]*256

🔎 **Grep results:**

GREP `#define[[:space:]]*MAX_AUTH_BYTES[[:space:]]*256`:
```
(no matches in repo)
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



