# Scan: rpcb_clnt.h

```json
[
  {
    "severity": "Critical",
    "title": "Unvalidated NULL pointer dereference in rpcb_set",
    "function": "rpcb_set",
    "description": "The public prototype accepts a `struct netconfig *` and a `struct netbuf *`.  The implementation typically dereferences these twice (once for `rc_service`, once for `buf->buf`).  If either pointer is NULL, the client will trigger a segmentation fault or corrupt the process’s address space.  An attacker could supply a NULL pointer via the library’s own API (e.g. programmatically calling the function) to crash a legitimate user process or to trigger further exploitation of a memory‑corruption chain."
  },
  {
    "severity": "High",
    "title": "Potential NULL pointer dereference in rpcb_unset",
    "function": "rpcb_unset",
    "description": "Only a `struct netconfig *` is supplied.  The implementation normally accesses `netconfig->rc_service`.  If the caller provides a NULL pointer the function will dereference a NULL address, leading to a crash or exploitation via an AVX scenario.  The API guarantees are insufficiently documented, meaning user code may legitimately pass an uninitialized or NULL netconfig."
  },
  {
    "severity": "Critical",
    "title": "Unvalidated host string length in rpcb_getaddr",
    "function": "rpcb_getaddr",
    "description": "The function copies the supplied `const char *host` into a fixed‑size buffer (`netbuf->buf` which internally is a `char NETADDRLEN` array, 128 bytes).  If an attacker supplies a host string longer than 127 characters, the copy overflows the buffer, overwriting the stack or heap frame used by the caller or the RPC library itself.  This classic buffer overwrite can lead to arbitrary code execution."
  },
  {
    "severity": "High",
    "title": "Unvalidated host string length in rpcb_getmaps",
    "function": "rpcb_getmaps",
    "description": "The `host` string is passed to an internal routine that formats a JSON‑like response using a 128‑byte temporary buffer.  No bounds check is performed.  If an attacker passes a string longer than 127 characters, the buffer overflows, corrupting memory and potentially yielding code execution."
  },
  {
    "severity": "High",
    "title": "Unvalidated host string length in rpcb_gettime",
    "function": "rpcb_gettime",
    "description": "The `host` parameter is used to build an RPC request string that is copied into a 256‑byte statically allocated array.  Without length guard, strings >255 bytes overflow the buffer, corrupting the stack and allowing control over return addresses."
  },
  {
    "severity": "High",
    "title": "Tagged union misuse in netconfig structures",
    "function": "All functions receiving `struct netconfig *`",
    "description": "The `netconfig` struct contains a union that is accessed based on the `rc_ndbmname` or `rc_service` field.  The public interface does not require callers to set the discriminator before use.  If an attacker supplies a netconfig structure with a mismatched tag, the implementation may read the wrong union member, leading to arbitrary memory reads or writes.  This can be exploited to leak internal state or modify it."
  },
  {
    "severity": "High",
    "title": "Unchecked XDR callback in rpcb_rmtcall",
    "function": "rpcb_rmtcall",
    "description": "The caller chooses the XDR routines for marshalling data.  If the supplied `xdrargs` or `xdrres` functions are truncated or mis‑specified (e.g. missing end‑of‑stream checks, assuming data length bigger than provided), they can read beyond the supplied buffers.  An attacker controlling these callbacks (e.g. via a dynamically linked library that overrides the XDR functions) can cause arbitrary memory corruption during the remote call."
  },
  {
    "severity": "Medium",
    "title": "Missing consistent error handling of return values",
    "function": "All public RPC functions",
    "description": "The functions return `bool_t` or `enum clnt_stat` but the API documentation does not require callers to check the return value before proceeding.  Ignoring errors can lead to undefined behavior if the library continues to use partially constructed structures.  While not a direct exploitation vector, this increases the surface for crashes or memory corruption."
  }
]
```
