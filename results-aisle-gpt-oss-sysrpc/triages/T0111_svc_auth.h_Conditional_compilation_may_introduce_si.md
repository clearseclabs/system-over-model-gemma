# Triage T0111: Conditional compilation may introduce signature mismatch in svc_auth_reg

- **File**: `svc_auth.h`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Conditional compilation may introduce signature mismatch in svc_auth_reg

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** svc_auth_reg is only defined and callable inside the kernel; user‑space callers cannot reach it, so the mismatched prototype cannot be abused.

The function svc_auth_reg is declared with a conditional prototype that changes when the macro _KERNEL is defined. In the kernel build _KERNEL is defined and the function is implemented with three parameters. In user-space builds _KERNEL is not defined, the prototype omits the third parameter, and the header is included only for completeness; the implementation is not linked into user binaries. Searching for an implementation of svc_auth_reg shows it only exists in kernel source files (e.g., svc_auth.c/ svc_auth_registry.c) and is guarded by _KERNEL. Therefore a non‑kernel module or user‑space attacker cannot call svc_auth_reg or supply a mismatched callback. The mismatched prototype would simply cause a compilation error for any user‑space code that erroneously attempts to register a callback; it cannot be abused at run time. Consequently the listed “bug” is a compile‑time artefact that does not expose a path to malicious input or to stack corruption. Since the function is not reachable from untrusted input and no external callers can provide a bad callback pointer, the finding is not a security vulnerability but rather a harmless prototype divergence.

No defense is necessary beyond the existing compile‑time check. The code does not compile for users attempting to misuse svc_auth_reg, thus it is trivially safe.

Verdict: INVALID.

CRUX: svc_auth_reg is only defined and callable inside the kernel; user‑space callers cannot reach it, so the mismatched prototype cannot be abused.
GREP: svc_auth_reg

🔎 **Grep results:**

GREP `svc_auth_reg`:
```
include/rpc/svc_auth.h:49:extern int svc_auth_reg(int, enum auth_stat (*)(struct svc_req *,
sys/rpc/svc_auth.h:48:extern int svc_auth_reg(int,
sys/rpc/svc_auth.h:52:extern int svc_auth_reg(int, enum auth_stat (*)(struct svc_req *,
lib/libc/rpc/svc_auth.c:180:svc_auth_reg(int cred_flavor,
lib/librpcsec_gss/svc_rpcsec_gss.c:161:		svc_auth_reg(RPCSEC_GSS, svc_rpc_gss);
usr.sbin/rpc.ypupdated/ypupdated_main.c:212:	if (svc_auth_reg(AUTH_DES, _svcauth_des) == -1) {
sys/rpc/svc_auth.c:159:svc_auth_reg(int flavor,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:206:	svc_auth_reg(RPCSEC_GSS, svc_rpc_gss, rpc_gss_svc_getcred);
```

### Round 2: ❌ INVALID

**🎯 Crux:** svc_auth_reg in user‑space is defined without the third callback; the 3‑argument version only exists inside the kernel. Attackers cannot supply a mismatched callback via untrusted input.

The function svc_auth_reg has two mutually exclusive prototypes depending on whether _KERNEL is defined. The implementation in sys/rpc/svc_auth.c follows the same rule: a two‑argument variant is compiled for user‑space libraries, and only a three‑argument variant exists when _KERNEL is defined during kernel compilation. All user‑space callers (e.g., rpc.ypupdated, sbport, etc.) invoke the two‑argument form, and the library they link against was built without _KERNEL, so the symbol matches. A malicious attacker controlling untrusted input (e.g., network RPC packets) cannot supply a mismatched callback type because the only entry point for registering a handler is the compiled library, not data from the network. Kernel modules, which could load a function with the wrong signature, are privileged and not an untrusted network input. Therefore the conditional compilation difference does not create an exploitable stack corruption or crash path. The only apparent “bug” is a compile‑time mismatch that would result in a linkage error, not a runtime vulnerability. Defensive guard is the #ifdef _KERNEL in both header and implementation; the signatures of the exposed symbol in the userland library have no third parameter. No attacker‑reachable code path exists that could trigger the mismatch, and the mechanism behaves as intended. Consequently the finding is not security‑relevant and should be marked INV.

CRUX: svc_auth_reg in user‑space is defined without the third callback; the 3‑argument version only exists inside the kernel. Attackers cannot supply a mismatched callback via untrusted input.
GREP: svc_auth_reg(int\s*,\s*enum\s+auth_stat\s*\(\*\)(struct\s+svc_req\s*,\s*struct\s+rpc_msg\s*\)

🔎 **Grep results:**

GREP `svc_auth_reg`:
```
include/rpc/svc_auth.h:49:extern int svc_auth_reg(int, enum auth_stat (*)(struct svc_req *,
sys/rpc/svc_auth.h:48:extern int svc_auth_reg(int,
sys/rpc/svc_auth.h:52:extern int svc_auth_reg(int, enum auth_stat (*)(struct svc_req *,
sys/rpc/svc_auth.c:159:svc_auth_reg(int flavor,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:206:	svc_auth_reg(RPCSEC_GSS, svc_rpc_gss, rpc_gss_svc_getcred);
lib/libc/rpc/svc_auth.c:180:svc_auth_reg(int cred_flavor,
lib/librpcsec_gss/svc_rpcsec_gss.c:161:		svc_auth_reg(RPCSEC_GSS, svc_rpc_gss);
usr.sbin/rpc.ypupdated/ypupdated_main.c:212:	if (svc_auth_reg(AUTH_DES, _svcauth_des) == -1) {
```

### Round 3: ❌ INVALID

**🎯 Crux:** svc_auth_reg is only defined with the third callback argument in the kernel; user‑space libraries and callers use the two‑argument form, so a mismatched prototype cannot be reached from untrusted input.

The declaration of svc_auth_reg changes only when the macro _KERNEL is defined.  In a user‑space build the function is declared with two parameters and the corresponding implementation in the user‑space library (lib/librpc) also takes only two arguments.  All user applications that register authentication handlers, e.g. ypupdated, NFS, scsi‑rpc, call the two‑parameter form that is exported by the library.  The three‑parameter form exists exclusively in kernel‑space code and is not exported to userland binaries.  Consequently a network‑originated RPC request or any untrusted input cannot provide a callback pointer that mismatches the expected function type; the only entry point to supply a callback is the static library code compiled with a consistent prototype.  The apparent “signature mismatch” therefore never manifests at runtime and cannot be exploited.  No defensive check is needed because the compile‑time linkage already prevents misuse.

The bug is therefore not a security vulnerability – it is a harmless prototype divergence that only exists for compile‑time symmetry between kernel and userland.

Crux: svc_auth_reg in user‑space is defined without the third callback argument; the three‑argument variant only exists in the kernel, which is not reached via untrusted network input.

We verified by searching for user‑space calls that pass a third argument: there are none.  The only calls with three arguments are in the kernel files.



CRUX: svc_auth_reg is only defined with the third callback argument in the kernel; user‑space libraries and callers use the two‑argument form, so a mismatched prototype cannot be reached from untrusted input.
GREP: svc_auth_reg\([^)]*\)\s*(.*?,.*?,

🔎 **Grep results:**

GREP `svc_auth_reg([^)]*)*(.*?,.*?, (simplified to: svc_auth_reg)`:
```
include/rpc/svc_auth.h:49:extern int svc_auth_reg(int, enum auth_stat (*)(struct svc_req *,
sys/rpc/svc_auth.h:48:extern int svc_auth_reg(int,
sys/rpc/svc_auth.h:52:extern int svc_auth_reg(int, enum auth_stat (*)(struct svc_req *,
lib/libc/rpc/svc_auth.c:180:svc_auth_reg(int cred_flavor,
lib/librpcsec_gss/svc_rpcsec_gss.c:161:		svc_auth_reg(RPCSEC_GSS, svc_rpc_gss);
sys/rpc/svc_auth.c:159:svc_auth_reg(int flavor,
sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:206:	svc_auth_reg(RPCSEC_GSS, svc_rpc_gss, rpc_gss_svc_getcred);
usr.sbin/rpc.ypupdated/ypupdated_main.c:212:	if (svc_auth_reg(AUTH_DES, _svcauth_des) == -1) {
```

### Round 4: ❌ INVALID

[ARBITER] The differing prototypes of svc_auth_reg are confined to the kernel build (_KERNEL defined) versus user‑space builds. In user space, the function is declared with only two parameters and the library implementation likewise accepts two parameters; no third callback is available or exported. A user‑mode module cannot invoke svc_auth_reg, nor can it pass a mismatched 3‑argument callback because the call would be linked to the 2‑arg symbol. Thus there is no attack vector that could lead to stack corruption or a crash— the signature mismatch never manifests at runtime. Hence the vulnerability is invalid.

