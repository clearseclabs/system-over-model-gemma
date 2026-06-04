# Scan: rpc.h

```json
[
    {
        "severity": "critical",
        "title": "Potential NULL pointer dereference in get_myaddress()",
        "function": "int get_myaddress(struct sockaddr_in *)",
        "description": "The prototype accepts a plain pointer without any const qualifier.  If an attacker passes a NULL pointer, the implementation is free to dereference it (e.g. memcpy, inet_ntoa) as it assumes a valid address structure.  This can cause a null‑pointer crash or a denial‑of‑service when the RPC library is used in privileged code."
    },
    {
        "severity": "critical",
        "title": "Potential buffer overflow in registerrpc() callback",
        "function": "int registerrpc(int, int, int, char *(*)(char [UDPMSGSIZE]), xdrproc_t, xdrproc_t)",
        "description": "The user supplied callback is declared to accept a fixed‐size array of UDPMSGSIZE (default 8800) bytes and return a pointer to a string.  The library gives the callback a pointer to that array and expects it to be written to safely, but the prototype does not express size limits (the array decays to a pointer).  If the callback writes more than 8800 bytes, it will overwrite adjacent data on the stack or heap, leading to corruption or execution of injected code."
    },
    {
        "severity": "high",
        "title": "Unverified return values from callrpc() user callbacks",
        "function": "int callrpc(const char *, int, int, int, xdrproc_t, void *, xdrproc_t , void *)",
        "description": "callrpc uses two XDR routines for request/response serialization.  If either routine fails and returns a non‑zero status, the library will still continue processing and may dereference the returned data structures.  An attacker sending malformed XDR payloads could trigger a failure in the xdrproc_t functions, causing an unchecked status value to propagate and potentially expose sensitive data or crash the process."
    },
    {
        "severity": "medium",
        "title": "Integer overflow in __rpc_get_t_size()",
        "function": "u_int __rpc_get_t_size(int, int, int)",
        "description": "The function calculates message sizes from three integer arguments, which are potentially derived from client‑supplied parameters such as protocol version or object ID.  If these inputs are maliciously large, the computed size could wrap around or overflow and produce a very small value.  Subsequent memory allocation with that size could then allocate a buffer that is far smaller than needed, resulting in a write‑past‑end during serialization or deserialization."
    },
    {
        "severity": "medium",
        "title": "Lack of bounds checking in network address conversion utilities",
        "function": "char *taddr2uaddr(const struct netconfig *, const struct netbuf *);",
        "function2": "struct netbuf *uaddr2taddr(const struct netconfig *, const char *);",
        "description": "These utilities translate between transport and user addresses.  They accept raw buffers (e.g., the char * in uaddr2taddr) but the prototype does not enforce a maximum length.  If an attacker feeds an overly long string, the conversion may read beyond the supplied buffer, potentially leaking kernel memory or causing a crash in user space."
    }
]
```