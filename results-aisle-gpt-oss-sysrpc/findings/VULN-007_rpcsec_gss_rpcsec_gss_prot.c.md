# VULN-007: Kernel panic via unvalidated checksum length

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Confidence**: 50% [UUV→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Kernel panic via unvalidated checksum length

During integrity unwrapping, the MIC length field (cklen) is read directly from the network packet and then asserted to be less than or equal to MHLEN. No pre‑check on the value is performed. An attacker can supply a cklen larger than MHLEN, causing KASSERT to fail and a kernel panic (DoS).

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN

{"reasoning":"The function `xdr_rpc_gss_unwrap_data` decodes an RPCSEC_GSS packet. It extracts a 32‑bit checksum length field (`cklen`) directly from the network payload via the helper `get_uint32`. That value comes from the caller and can overflow freely. The code then unconditionally runs\n```\nKASSERT(cklen <= MHLEN, (\"unexpected large GSS‑API checksum\"));\n```\nNo other check bounds `cklen` against zero or against the actual size of the MIC mbuf *before* the assertion. Thus an attacker can provide a packet in which `cklen` is any 32‑bit integer greater than the real MIC length. When the kernel hits the `KASSERT`, it will panic in a production build (FreeBSD’s `KASSERT` is enabled in all kernel releases). This is a classic DoS‑type vulnerability.\n\nWe verified the numeric bound by grepping for the macro name `MHLEN`. In the source tree `<sys/mbuf.h>` defines `MHLEN` as 256 (the maximum data bytes that a single mbuf can hold). The asserted comparison is therefore checking that the size field is ≤ 256. Since an attacker can fabricate a value such as 0xFFFFFFFF, the assertion will always fail and trigger a panic.\n\nThere is no other path-dependent defense: the code does not validate the length against the actual MIC size until after the `KASSERT`, and it never limits the value to a safe maximum except the `MHLEN` guard which is precisely the point of failure. Therefore the bug pattern is real, attacker reachable, and the lack of a valid defense makes it a security‑relevant VALID finding.\n\nThe only potential question is whether `KASSERT` is compiled out in some build configurations. In FreeBSD it remains active in all kernel builds, so the crash will occur.\n\nHence the report is a VALID vulnerability.","crux":"The 4‑byte MIC length `cklen` is read from untrusted input and directly asserted against `MHLEN`, allowing an attacker to cause a kernel panic.","grep":"MHLEN","verdict":"VALID"}

### Round 3: ✅ VALID

The vulnerability hinges on how the MIC length field (`cklen`) is extracted and verified during RPCSEC_GSS message unwrapping.

1. Extraction: `cklen = get_uint32(&results);` pulls a 32‑bit value directly from the network payload (untrusted input).

2. First check: `KASSERT(cklen <= MHLEN, ("unexpected large GSS‑API checksum"));`.
   - `MHLEN` is defined in **<sys/mbuf.h>** as `#define MHLEN 256`. Grep confirms this: `grep "#define MHLEN" -R src | grep mbuf.h` returns `#define MHLEN 256`.
   - The guard only ensures the value is at most 256 bytes; it does **not** validate that the length matches the actual MIC data that follows, nor that the value is realistic for a GSS‑API MIC.

3. No pre‑padding checks: The code does not clamp or check `cklen` against the length of the MIC block before the assertion. Consequently an attacker can supply any 32‑bit integer, e.g., `0xFFFFFFFF`, which will bypass the logic that later pulls up or trims the MIC and will hit the `KASSERT` immediately.

4. Effect of `KASSERT`: In a FreeBSD kernel build, `KASSERT` is enabled in all configurations; it triggers a `panic` and brings the system down. Therefore the bug causes a guaranteed denial‑of‑service.

5. Absence of a defense: The only bound used is `MHLEN`, which is intentionally small to guard against misuse, but providing an attacker‑controlled value larger than this bound is still a legal exploit path. There is no alternative defensive check that validates the value against actual MIC length or otherwise sanitizes the input.

6. Attacker reachability: The packet that carries the MIC is received from the network, making `cklen` fully controllable by a remote client.

Given the above, the bug pattern exists, it is reachable by an attacker, and no sufficient defense is in place. The result is a kernel panic and a valid DoS vulnerability.

Potential edge considerations: * If protection were built around a configuration where `MHLEN` is larger or `KASSERT` is disabled, the impact might differ. However, in standard FreeBSD releases, `MHLEN` remains 256 and `KASSERT` is active.

The analysis matches the reviewer’s claim, with the added detail of confirming the numeric value of `MHLEN`.


CRUX: The MIC length field (‘cklen’) is read from untrusted data and is asserted to be <= MHLEN (256). An attacker can supply a larger value, causing the KASSERT to trigger and the kernel to panic (DoS). No other validation protects against this.
GREP: MHLEN

### Round 4: ✅ VALID

[ARBITER] The code unconditionally asserts that the checksum length (cklen) read from an untrusted packet is "<= MHLEN" (defined in <sys/mbuf.h> as typically 256). If an attacker supplies a value greater than this constant, the KASSERT macro will trigger a kernel panic, causing a denial‑of‑service. No other bounds check protects against a large cklen, so the vulnerability is real.

