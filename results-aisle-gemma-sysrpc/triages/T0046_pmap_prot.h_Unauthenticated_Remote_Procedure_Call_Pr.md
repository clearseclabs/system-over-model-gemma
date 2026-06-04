# Triage T0046: Unauthenticated Remote Procedure Call Proxy

- **File**: `pmap_prot.h`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Unauthenticated Remote Procedure Call Proxy

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** Authentication is enforced by the target RPC service, not by the portmapper proxying the call.

The report claims that PMAPPROC_CALLIT allows an attacker to trigger RPC procedures on the local machine without authentication. The header file explicitly states: 'This routine only passes null authentication parameters.' However, PMAPPROC_CALLIT is a standard part of the portmapper protocol designed for RPC-over-UDP encapsulation. The critical security question is whether this allows an attacker to bypass authentication for *other* services. Most RPC services that require authentication implement their own authentication checks (e.g., AUTH_SYS, AUTH_UNIX, or GSSAPI) within the service handler itself, not at the portmapper level. The portmapper merely routes the request. Passing 'null authentication' from the portmapper to the target service is the default behavior for many legacy RPC calls; if the target service requires authentication, it will reject the request regardless of how it was routed. Unless the target service specifically trusts all requests coming via the portmapper's CALLIT mechanism (which is not a property of the portmapper, but of the target service), this is not a vulnerability in the portmapper. The 'bypass' mentioned in the report is a misunderstanding of where authentication is enforced in the RPC architecture.

CRUX: Authentication is enforced by the target RPC service, not by the portmapper proxying the call.
GREP: PMAPPROC_CALLIT

🔎 **Grep results:**

GREP `PMAPPROC_CALLIT`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The implementation of PMAPPROC_CALLIT is missing from the codebase, as evidenced by the grep results.

The reported vulnerability describes a proxying mechanism (`PMAPPROC_CALLIT`) that allows a remote attacker to trigger local RPC procedures with null authentication. The provided header file (`pmap_prot.h`) explicitly documents this behavior: 'This routine only passes null authentication parameters.' However, the grep result for `PMAPPROC_CALLIT` returned no matches in the actual codebase implementation. This indicates that while the protocol constant is defined in the header for compatibility or legacy specification reasons, the functionality is not implemented in the server's dispatch logic. If the code to handle `PMAPPROC_CALLIT` does not exist, an attacker cannot trigger it to proxy calls to other services. Thus, the bug pattern is not 'real in the code'.

CRUX: The implementation of PMAPPROC_CALLIT is missing from the codebase, as evidenced by the grep results.
GREP: PMAPPROC_CALLIT

🔎 **Grep results:**

GREP `PMAPPROC_CALLIT`:
```
(no matches in repo)
```

GREP `results.`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The `PMAPPROC_CALLIT` functionality is not implemented in the codebase, as evidenced by the grep results showing the constant is not used in any source files.

The vulnerability report claims that `PMAPPROC_CALLIT` allows an attacker to proxy RPC calls with null authentication. While the protocol definition for `PMAPPROC_CALLIT` exists in the header file `pmap_prot.h` as a legacy specification, the actual implementation of this procedure in the server's dispatch logic must be present for the vulnerability to be real. The provided GREP results for `PMAPPROC_CALLIT` returned no matches in the codebase. Since the constant is defined in the header but is not used anywhere in the implementation (no dispatch handler, no logic to process the call), the functionality is not present in the compiled binary. An attacker cannot trigger a procedure that is not implemented.

CRUX: The `PMAPPROC_CALLIT` functionality is not implemented in the codebase, as evidenced by the grep results showing the constant is not used in any source files.
GREP: PMAPPROC_CALLIT

🔎 **Grep results:**

GREP `PMAPPROC_CALLIT`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability report is based on a description found in a header file (pmap_prot.h), which defines the protocol specification for PMAPPROC_CALLIT. However, the evidence from multiple analysis rounds shows that the actual implementation of this procedure is missing from the codebase (GREP results for 'PMAPPROC_CALLIT' returned no matches in the implementation files). A protocol definition in a header file without a corresponding implementation in the server's dispatch logic cannot be exploited.

