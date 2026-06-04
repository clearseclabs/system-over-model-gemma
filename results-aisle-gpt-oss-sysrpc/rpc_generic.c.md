# Scan: rpc_generic.c

```json
[
  {
    "severity": "critical",
    "title": "Unchecked sun_path copy with no NUL‑termination",
    "function": "__rpc_uaddr2taddr_af",
    "description": "For AF_LOCAL addresses the code copies the user‑supplied path into `sun->sun_path` with `strncpy(sun->sun_path, addrstr, sizeof(sun->sun_path) - 1)`.  If the input path is longer than the destination (108 bytes for `sun_path`), the destination will not be NUL‑terminated.  `SUN_LEN(sun)` then calls `strlen(sun->sun_path)` on unaligned data, reading past the end of the `sockaddr_un` structure and potentially overreading kernel memory.  The bounded `m->len` is not checked before `SUN_LEN`, so an attacker can supply a very long string to cause a kernel memory read and, combined with carefully crafted payloads, can create arbitrary data corruption, leading to privilege escalation or denial‑of‑service.  This flaw also grows `ret->buf` size incorrectly, causing heap corruption or additional reads from uninitialized memory."
  },
  {
    "severity": "high",
    "title": "Negative or oversized sun_len in AF_LOCAL conversion",
    "function": "__rpc_taddr2uaddr_af",
    "description": "When the address family is `AF_LOCAL`, the function interprets `sun->sun_len` directly with no validation.  If the source `netbuf` is fabricated with a length smaller than the offset of `sun_path`, `sun->sun_len - offsetof(struct sockaddr_un, sun_path)` becomes negative.  That negative length is passed to `sbuf_printf` via the `%.*s` format specifier, leading to a format‑string length underflow and undefined behaviour, potentially causing a kernel crash or data leak.  An attacker controlling an RPC request can thus trigger a panic or readable memory leakage."
  },
  {
    "severity": "medium",
    "title": "Incorrect maximum size usage in __rpc_get_t_size",
    "function": "__rpc_get_t_size",
    "description": "The function clamps the requested size to `sb_max_adj`.  If `sb_max_adj` is set to a negative value via sysctl by a privileged user, the cast to `u_int` turns it into an overflowed positive number, allowing an attacker with elevation to request enormous allocation sizes that could exhaust kernel memory.  While not an immediate code‑execution flaw, it is a potential denial‑of‑service vector that merits careful bounds checking."
  },
  {
    "severity": "medium",
    "title": "Possible OOM via excessively large SUN_LEN",
    "function": "__rpc_taddr2uaddr_af",
    "description": "Even if the path is NUL‑terminated, `SUN_LEN(sun)` uses `strlen` on the path.  An attacker can send a very long socket path (up to the kernel’s `MAXPATHLEN`) to force `SUN_LEN` to return a very large value.  `sbuf_printf` will allocate a buffer of that size, potentially exhausting kernel memory and causing a denial‑of‑service before any other checks occur."
  },
  {
    "severity": "medium",
    "title": "KASSERT triggered by malformed mbuf chains in _rpc_copym_into_ext_pgs",
    "function": "_rpc_copym_into_ext_pgs",
    "description": "The routine assumes that the first mbuf is non‑ext_pgs and that any subsequent mbufs are either non‑ext_pgs followed by ext_pgs.  A crafted RPC payload could supply a mbuf chain that violates these assumptions.  The `KASSERT` on the first mbuf flags will panic the kernel, giving an attacker a dependable denial‑of‑service vector when the kernel is processing remote calls."
  },
  {
    "severity": "low",
    "title": "Potential misuse of unvalidated `mfree` in BINDRESVPORT",
    "function": "bindresvport",
    "description": "The function calls `sosetopt` to set the port range without checking that the socket is of the expected type.  If an attacker supplies a socket with maliciously crafted options or an incorrect family, the call may fail silently or perform unintended actions.  This is a secondary risk primarily for integrity, not for arbitrary code execution."
  }
]
```