# VULN-001: Authentication for unsupported flavors defaults to success

- **File**: `auth_unix.c`
- **Confidence**: 50% [UUV→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Authentication for unsupported flavors defaults to success

If the verifier’s flavor is not `AUTH_SHORT` (`verf->oa_flavor != AUTH_SHORT`), the function simply returns `TRUE` without inspecting the verifier.  Because this `TRUE` is used by the RPC subsystem to indicate successful authentication, an attacker can send a verifier with an arbitrary, unsupported flavor and bypass authentication entirely.  This effectively turns the authentication mechanism into a no‑op for any attacker who can craft a remote RPC request.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN

{"reasoning":"The vulnerability report targets the function `authunix_validate`.  Inspecting that function shows that it only performs additional validation when the incoming verifier’s flavor is `AUTH_SHORT`.  For every other flavor, or when the verifier pointer is NULL, the function immediately returns TRUE without performing any checks:\n\n```c\nif (!verf) return (TRUE);\n\nif (verf->oa_flavor == AUTH_SHORT) {\n    … // special handling\n}\n\nreturn (TRUE);   /* <-- unconditional success */\n```\nThis code is invoked by the RPC subsystem whenever a request is authenticated using the `AUTH_UNIX` flavor.  The verifier field is part of the RPC message header and originates entirely from the client, thus it is an attacker‑controlled input.  Because the function returns success unconditionally for any unsupported verifier flavor, an attacker can craft a request that supplies an arbitrary verifier (e.g., with flavor `AUTH_NONE` or a non‑existent numeric value).  The RPC layer will accept the request as authenticated, effectively bypassing authentication for that call.  No defensive check or size/bound validation is present inside `authunix_validate` or in the surrounding RPC path to prevent this; the server never rejects the request based on the verifier’s flavor.  Verification of constants and other code paths confirms there is no alternative validation of the verifier’s flavor.  Hence the bug pattern is real, the attacker can reach it through untrusted input, and there is no mitigation to prevent the bypass.\n\nTherefore the finding is a true security vulnerability.\n","crux":"`authunix_validate` returns TRUE for any verifier flavor other than `AUTH_SHORT`, allowing attackers to bypass authentication by providing an arbitrary verifier.\n","grep":"authunix_validate","verdict":"VALID"}

### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

The code for `authunix_validate` returns TRUE unconditionally except when the verifier flavor is `AUTH_SHORT`.  The verifier is supplied by the client over the network, so it is attacker‑controlled.  No other check of the verifier flavor exists in this function or elsewhere in the file.  Consequently, a client can send a verifier with any unsupported flavor (e.g., a random integer or `AUTH_NONE`) and the function will still signal successful authentication.  The RPC dispatcher relies on the return value of the `ah_validate` function; a return value of TRUE indicates authentication success, after which the requested RPC method is executed.  Because the attacker can cause the RPC layer to accept any verifier, they can gain authenticated access to the service without performing the intended authentication checks.  No defensive check (such as rejecting unsupported flavors) is present in the code base, and therefore the bug pattern is real, attacker‑reachable, and security‑relevant.


CRUX: `authunix_validate` ignores any verifier flavor other than `AUTH_SHORT` and always returns TRUE, allowing an attacker to supply an arbitrary, unsupported verifier and bypass authentication checks.
GREP: authunix_validate

### Round 4: ✅ VALID

[ARBITER] The `authunix_validate` function checks the verifier only when its flavor is `AUTH_SHORT`. For any other flavor—including `AUTH_NONE` or any arbitrary integer—the function skips the special handling and immediately returns `TRUE`. This `TRUE` value tells the RPC dispatcher that authentication succeeded, regardless of the verifier’s authenticity or the credential contents. Therefore any request carrying an unsupported flavor can bypass the intended validation, making the described vulnerability real. All numeric logic is confirmed directly from the source lines above.

