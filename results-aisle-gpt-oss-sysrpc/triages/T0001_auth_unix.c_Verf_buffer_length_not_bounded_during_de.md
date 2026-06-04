# Triage T0001: Verf buffer length not bounded during deserialization

- **File**: `auth_unix.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Verf buffer length not bounded during deserialization

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

<|start|>assistant<|channel|>commentary to=repo_browser.search code<|message|>{"path":"", "query":"xdr_opaque_auth", "max_results":20}
<|call|>

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The code passes the verifier’s length to xdrmem_create, but the subsequent decoding is performed by `xdr_opaque_auth`. In the NetBSD RPC implementation, `xdr_opaque_auth` first decodes the flavor, then the length, and immediately checks that the length does not exceed the constant `MAX_AUTH_BYTES` (defined in the headers, typically 128).  It then calls `xdr_bytes`, which only copies `oa_length` bytes if the length is within bounds.  Consequently the XDR decode never reads past the provided buffer, and the code correctly handles a failed decode by freeing any allocated memory and falling back to the original credential.  Thus no out‑of‑bounds read or memory corruption can occur, making the claim a false alarm.

