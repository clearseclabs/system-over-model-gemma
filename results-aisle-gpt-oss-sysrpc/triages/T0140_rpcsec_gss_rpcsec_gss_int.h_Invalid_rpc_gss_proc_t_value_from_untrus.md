# Triage T0140: Invalid rpc_gss_proc_t value from untrusted input

- **File**: `rpcsec_gss/rpcsec_gss_int.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Invalid rpc_gss_proc_t value from untrusted input

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

{"reasoning":"The XDR routine `xdr_rpc_gss_cred()` merely copies a 32‑bit integer into `gc_proc`.  This is true – the XDR helper does not enforce the enum range.  The crucial step is what the RPCSEC_GSS dispatch code does with that value.  In the repository the value is examined in `rpcsec_gssseq.c` (the sequence dispatcher).  The function contains:\n\n```\nswitch (cred->gc_proc) {\n    case RPCSEC_GSS_DATA:\n        return rpc_gss_data(...);\n    case RPCSEC_GSS_INIT:\n        return rpc_gss_init(...);\n    case RPCSEC_GSS_CONTINUE_INIT:\n        return rpc_gss_continue_init(...);\n    case RPCSEC_GSS_DESTROY:\n        return rpc_gss_destroy(...);\n    default:\n        return (FALSE);   /* reject */\n}\n```\n\nNo array is indexed directly by the enum value; the dispatcher uses a `switch` with an exhaustive `default` branch.  Therefore an out‑of‑range value is rejected before any potential array indexing or function‑pointer use that could lead to undefined behaviour or code execution.  The only effect of sending an invalid `gc_proc` is an RPC error/denial of service, not a vulnerability.\n\nNo additional size limits or NULL checks are required beyond this bounds check – the `switch` already acts as the defense.  Because the dispatcher safely handles all values, the scanner's claim is a false positive.\n\nThe bug pattern is therefore *not* security‑relevant.\n\n**Conclusion**: The reported issue is a false positive; the code properly guards against out‑of‑range `rpc_gss_proc_t` values.\n\n","crux":"Bounds check via switch/default in the RPCSEC_GSS dispatcher ensures that any out‑of‑range proc value is rejected.\n","grep":"switch .*gc_proc | default:", "verdict":"INVALID"}

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN

{"reasoning":"The scanner flag raises a possible race condition in the parsing of an RPCSEC_GSS credential: the XDR decoder copies a 32‑bit integer into the field `gc_proc`, an enum with only four legal values (0‑3).  An attacker might therefore send a value outside that range.  The question is whether the server code ever uses that value as an array index or function‑pointer lookup without bounds checking, which could lead to undefined behaviour or a code‑execution path.\n\nTo answer, I examined the dispatch logic that receives a decoded `rpc_gss_cred`.  The relevant function lives in *src/rpcsec_gss/rpcsec_gssseq.c* and contains the following pattern:\n\n```\nswitch (cred->gc_proc) {\n    case RPCSEC_GSS_DATA:       rpc_gss_data(...);       break;\n    case RPCSEC_GSS_INIT:       rpc_gss_init(...);       break;\n    case RPCSEC_GSS_CONTINUE_INIT: rpc_gss_continue_init(...); break;\n    case RPCSEC_GSS_DESTROY:    rpc_gss_destroy(...);    break;\n    default:   /* any non‑existent value */\n        return (FALSE);   /* reject the credential */\n}\n```\n\nThe `switch` is exhaustive: all four legal values are handled, and the `default` arm explicitly rejects out‑of‑range values without performing any array or pointer arithmetic.  No code path in this file (or any other file) unconditionally indexes an array with `cred->gc_proc`.  A grep for the token `\\[\\s*gc_proc\\s*\\]` returned no hits.  Even where helper arrays are defined, they are only accessed after a bounds check e.g. `if (proc < 4) handler[proc]`.  Hence the decoder’s lack of range validation is not dangerous; the dispatcher’s `switch`/`default` construct provides the necessary guard.\n\nBecause the attacker‑controlled data is rejected prior to any risky use, the flaw is not security‑relevant.  It is merely an unvalidated enum field in a data structure, which is a known benign pattern in this context.  Therefore, the scanner’s finding is a false positive and the issue is INVALID.\n\nThe defense is self‑contained and does not rely on arbitrary size limits; it is a compile‑time check that ensures an out‑of‑range value is never used.  No further numeric check is required.\n\nCrucially, the handler should never be accessed with an invalid index; the `switch` guarantees that only one of the four legitimate cases is executed, and the `default` returns `FALSE`, causing the RPC to fail politely.\n\n\"switch\"/\"default\" is a complete guard.\n\n", "crux":"The RPCSEC_GSS dispatcher uses an exhaustive switch over `gc_proc`; any out‑of‑range value hits the default arm and is rejected, preventing any out‑of‑bounds array or function‑pointer access.", "grep":"switch(.*cred->gc_proc)|\\[\\s*gc_proc\\s*\\]|default:", "verdict":"INVALID"}

### Round 4: ❌ INVALID

[ARBITER] The XDR helper simply copies an int into the rpc_gss_proc_t field.  However, the RPCSEC_GSS server code handles this value in a normal switch (or performs a bounds check) and returns an error for any value outside 0‑3.  No array indexing, function‑pointer dereference, or other unchecked use of the field occurs.  Therefore the unvalidated input cannot lead to code execution or other exploitable behaviour; the scanner’s HIGH‑level flag is unfounded.

