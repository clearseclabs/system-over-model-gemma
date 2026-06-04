# Scan: authunix_prot.c

```json
[
  {
    "severity": "medium",
    "title": "Dereference of possible NULL cred pointer",
    "function": "xdr_authunix_parms",
    "description": "The function assumes that the `cred` pointer passed by the caller is valid. All accesses to `cred->cr_uid`, `cred->cr_gid`, `cred->cr_ngroups`, and `cred->cr_sgroups[]` occur without checking that `cred` is non‑NULL. If an attacker can control the pointer value (e.g., by poisoning memory or through another vulnerability that allows the struct to be replaced with a NULL pointer), this will result in a crash that may be exploited for denial‑of‑service or potentially information disclosure.\n\nMitigation: Add an explicit check `if (!cred) return FALSE;` before dereferencing the pointer."
  },
  {
    "severity": "low",
    "title": "Potential array bounds confusion during group processing",
    "function": "xdr_authunix_parms",
    "description": "When decoding supplementary groups, the code iterates up to `supp_ngroups` and writes to `cred->cr_sgroups[i]` only if `i < XU_NGROUPS - 1`; otherwise it discards the value into a local `junk`. While the loop is bounded by the check `supp_ngroups > AUTH_SYS_MAX_GROUPS` (which returns FALSE if violated), the logic relies on `XU_NGROUPS` and `AUTH_SYS_MAX_GROUPS` having matching values. If future changes adjust one constant but not the other, the bounds check may fail and write past the end of the `cr_sgroups` array, causing a buffer overflow. This is an implementation‑time risk rather than an exploitable runtime issue in the current code.\n\nMitigation: Add a compile‑time consistency assertion or compute indices using `MIN(i, XU_NGROUPS-2)` to guarantee that array accesses never exceed bounds."
  },
  {
    "severity": "low",
    "title": "Unvalidated length of host name during decode",
    "function": "xdr_authunix_parms",
    "description": "The length of the host name field (`namelen`) is read from the XDR stream and only validated against `AUTH_SYS_MAX_HOSTNAME`. If an attacker sends a value larger than this constant, the function returns FALSE. However, if later code in the RPC stack interprets a `FALSE` as an error and continues with an incomplete or malformed packet, this may lead to unexpected behavior or further resource exhaustion. The current guard is sufficient for preventing buffer overflows in this function, but relying on the downstream behavior could be risky.\n\nMitigation: Ensure that any return value of FALSE results in immediate termination of the RPC call and proper cleanup."
  }
]
```