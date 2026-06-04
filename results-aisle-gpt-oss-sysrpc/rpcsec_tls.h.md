# Scan: rpcsec_tls.h

**Security Analysis – `rpcsec_tls.h`**

| # | Severity | Title | Function / Symbol | Observation | Likely Impact |
|---|----------|-------|-------------------|-------------|---------------|
| 1 | **Critical** | *Null‑pointer dereference in upcall APIs* | `rpctls_connect()`, `rpctls_*_handlerecord()`, `rpctls_*_disconnect()` | The prototypes expose raw pointers (`CLIENT *`, `char *certname`, `struct socket *so`, `void *socookie`, `uint32_t *reterr`). The header contains **no documentation** that callers must validate the arguments. Many of these functions are called from kernel stubs in `rpc.tlsclntd` / `rpc.tlsservd` and from the kernel RPC subsystem. If an attacker brings a malicious kernel module or exploits a local privilege‑escalation vulnerability to call these APIs with *NULL* or otherwise malformed values, the kernel will dereference the pointer and crash/behave unpredictably. | Kernel panic / fault (remote local privilege escalation). |
| 2 | **High** | *Unvalidated TCP socket reference* | `rpctls_connect()` | The `struct socket *so` is expected to be a valid reference to an existing socket. No header validation is performed; an out‑of‑range or uninitialized pointer can compromise the RPC engine. | Invalid socket handling → memory corruption / crash. |
| 3 | **High** | *Unvalidated `certname` length* | `rpctls_connect()` | `certname` is passed as `char *` with no length parameter. The implementation must internally copy or compare the string, but the header does **not** enforce any maximum length. If the implementation blindly copies `certname` into a fixed‑size buffer, a buffer overflow may occur. | Heap corruption → denial of service or code execution. |
| 4 | **Medium** | *arbitrary `uint32_t *reterr` misuse* | All `rpctls_*` functions | The caller may pass a pointer that is not kernel‑space or that points to a secret region. The routine writes the error value into this pointer. If an attacker can manipulate kernel space incorrectly, this can lead to unauthorized memory writes or leaks. | Information disclosure / overwriting privileged memory. |
| 5 | **Medium** | *Unchecked length in `rpctls_getinfo()`* | `rpctls_getinfo()` | The function expects an output buffer length pointer (`u_int *maxlen`). If the caller supplies a value that the implementation uses without bounds checking (e.g., allocating `maxlen` bytes for a reply), the RPC daemon may write past the allocated space. | Buffer overflow in user‑space → denial of service or memory corruption. |
| 6 | **Low** | *Missing flag namespace collision* | `RPCTLS_FLAGS_*` | The 8‑bit flag set is exposed globally. If other modules re‑define `RPCTLS_FLAGS_*` or use the same symbol namespace, flag collisions could occur, silently changing the semantics of the flags. | Logical errors in TLS handling, possible downgrade. |
| 7 | **Low** | *Hard‑coded verifier string* | `RPCTLS_START_STRING` | The verbatim `"STARTTLS"` string is used as the authentication verifier. If an attacker can tamper with the verifier parsing in the daemon (e.g., by crafting a packet with the same string but different encoding or length), they might bypass the handshake logic, but this requires detailed knowledge of the daemon and is model‑dependent. | Partial TLS bypass if combined with other flaws. |

---

### Summary of Vulnerability Classes

1. **Kernel‑space Null Dereference** – The public API can be mis‑called with **NULL** arguments, causing kernel crashes.  
2. **Unchecked Length / Buffer Overrun** – `certname` and `maxlen` are passed without size limits, enabling overflow in the implementation.  
3. **Pointer Validation** – `reterr` and `socookie` are opaque raw pointers; no checks at the interface boundary.  
4. **Global Symbol Pollution** – Flag definitions and static string can collide with other kernel modules.

For a robust security posture, the caller contract should be formally documented (e.g., “caller must provide non‑null pointers, valid socket references, and a certname of length ≤ MAX_CERTNAME”), and the implementations should perform defensive programming: NULL checks, bounds checks, and strict type guarding. Without these, a local attacker with kernel‑module capabilities can easily trigger crashes or cause memory corruption.