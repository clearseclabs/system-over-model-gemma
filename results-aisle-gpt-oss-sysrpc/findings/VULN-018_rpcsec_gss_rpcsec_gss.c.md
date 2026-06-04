# VULN-018: NULL pointer dereference caused by unchecked strdup failure

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

NULL pointer dereference caused by unchecked strdup failure

The principal string is duplicated using `strdup(principal, M_RPC)` without checking for a NULL return.  If duplication fails, `gd->gd_principal` will be NULL.  Subsequent code (e.g., `rpc_gss_secfind` and later `strcmp(gd->gd_principal, principal)`) will dereference this NULL pointer, potentially crashing the kernel or leaking stack contents.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN

{"reasoning":"The code path that creates an AUTH structure (rpc_gss_seccreate_int) calls\n    gd->gd_principal = strdup(principal, M_RPC);\n   without checking the result.  If memory allocation fails, strdup returns NULL.\n   Immediately afterward the code passes gd->gd_principal to strlen() in\n   rpc_gss_init() and later to strcmp() in rpc_gss_secfind() or other\n   functions, which dereferences the NULL pointer and triggers a kernel\n   crash.  The caller of rpc_gss_seccreate_int supplies the principal\n   string; this originates from the user‑supplied RPC client options\n   (e.g., an NFS mount or RPC call).  Thus an attacker can provide an\n   arbitrarily large or otherwise malformed principal string that may\n   cause the underlying strdup to fail (e.g., by exhausting kernel\n   memory).  No defense (NULL check or size limit) is present in the\n   code before the dereference.  Therefore the vulnerability is real,\n   attacker‑reachable, and would result in a kernel panic (deny‑of‑service.\"\n,\"crux\":\"Unconditional use of gd->gd_principal after calling strdup() which may return NULL.\",\"grep\":\"strdup(\"}

### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code in rpc_gss_seccreate_int unconditionally assigns the result of `strdup(principal, M_RPC)` to `gd->gd_principal` and never checks for a NULL return. If `strdup` fails (which can happen if `malloc` returns NULL under low‑memory conditions), `gd->gd_principal` becomes NULL. Subsequent code dereferences this pointer: in `rpc_gss_init` the code calls `strlen(gd->gd_principal)` and later `rpc_gss_secfind` uses `strcmp(gd->gd_principal, principal)`. Both will dereference a NULL pointer, causing a kernel crash. No defensive check or error handling prevents this. Therefore the reported NULL‑pointer dereference is a real, exploitable kernel vulnerability. No numeric values need to be verified beyond the existing code.

