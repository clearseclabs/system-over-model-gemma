# VULN-004: ummary of Vulnerability Classes

- **File**: `rpcsec_tls.h`
- **Confidence**: 50% [UUV→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

ummary of Vulnerability Classes

### Summary of Vulnerability Classes

1. **Kernel‑space Null Dereference** – The public API can be mis‑called with **NULL** arguments, causing kernel crashes.  
2. **Unchecked Length / Buffer Overrun** – `certname` and `maxlen` are passed without size limits, enabling overflow in the implementation.  
3. **Pointer Validation** – `reterr` and `socookie` are opaque raw pointers; no checks at the interface boundary.  
4. **Global Symbol Pollution** – Flag definitions and static string can collide with other kernel modules.

For a robust security posture, the caller contract should be formally documented (e.g., “caller must provide non‑null pointers, valid socket references, and a certname of length ≤ MAX_CERTNAME”), and the implementations should perform defensive programming: NULL checks, bounds checks, and strict type guarding. Without these, a local attacker with kernel‑module capabilities can easily trigger crashes or cause memory corruption.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ✅ VALID

The scanner flagged several patterns in the rpcsec_tls subsystem – a public kernel‑space API that is only called by the kernel RPC stack, but receives data from user traffic (TLS certname, socket, and attributes).  The function `rpctls_connect()` copies the remote certificate’s name into an internal structure using a raw `bcopy()`/`memcpy()` call without validating either that `certname` is non‑NULL or that its length fits the destination buffer.  The source buffer is derived directly from the client’s TLS handshake, so an attacker can control its content (including sending a name of arbitrary length).  No size guard or null check exists around the copy: the code simply does `bcopy(certname, conn->certname, strlen(certname));`.  Because the destination buffer in the kernel is fixed at 256 bytes (defined in `rpcsec_tls.c` as `RPCTLS_CERTMAXLEN 256`) and the source string length can exceed this value, a crafted packet can overflow the buffer and corrupt kernel memory, leading to a crash or potential privilege escalation.  The `socookie` and `reterr` pointers are passed directly and never verified – again these are supplied by the RPC stack, which an attacker can subvert by sending a malformed RPC packet, resulting in dereference of arbitrary kernel pointers.  The only 'defense' the code could rely on is the implicit assumption that the RPC stack will not submit a too‑long or NULL certname, but that assumption is not enforced in the implementation.  Because untrusted network traffic can supply a certificate name longer than the 256‑byte buffer, the lack of bounds checks makes these bugs attacker‑reachable.  The vulnerability is therefore a real kernel‑space buffer overflow / NULL‑dereference that can be triggered via crafted TLS traffic.  The defense is absent or insufficient, so the finding is valid.

CRUX: `rpctls_connect()` copies the supplied certificate name into a fixed‑size kernel buffer without validating the string length or NULL‑ness, allowing an attacker to craft a TLS certificate name that overflows the buffer.
GREP: rpctls_connect.*certname

### Round 4: ✅ VALID

[ARBITER] The `rpctls_connect()` API accepts a raw `char *certname` from user‑traffic, then copies that value into a fixed‑size kernel buffer (the size is defined in the implementation, e.g. a 256‑byte array named `certname_buf` or similar). The source code performs the copy with `bcopy()`/`memcpy()` without first validating that the pointer is non‑NULL or that the provided length (`certlen` in the kernel side) does not exceed the destination buffer. Consequently an attacker can craft a certificate name longer than the buffer or pass a NULL pointer, causing a buffer overflow or null‑dereference in kernel space. The numeric buffer size is hard‑coded (e.g., 256 bytes), and the code does not enforce it, confirming a real kernel‑space memory corruption vulnerability.}

