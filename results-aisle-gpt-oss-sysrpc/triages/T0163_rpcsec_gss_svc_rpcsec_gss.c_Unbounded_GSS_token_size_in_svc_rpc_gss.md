# Triage T0163: Unbounded GSS token size in svc_rpc_gss_accept_sec_context

- **File**: `rpcsec_gss/svc_rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unbounded GSS token size in svc_rpc_gss_accept_sec_context

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The GSS token is received as part of the RPC authentication header, which is limited by the RPC transport size limits. The kernel‐side XDR routines read the token length and allocate memory accordingly, but the overall RPC message size is bounded (typically by the maximum RPC message size imposed by the kernel’s mbuf limits). Therefore, while the code does not explicitly cap the GSS token length, an attacker cannot supply an arbitrarily large token beyond these transport limits, preventing the kind of memory exhaustion or out‑of‑bounds reads implied by the report. Consequently the finding is not a real vulnerability.

