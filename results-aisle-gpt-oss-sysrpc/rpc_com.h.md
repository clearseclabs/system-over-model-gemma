# Scan: rpc_com.h

```json
[
    {
        "severity": "HIGH",
        "title": "Potential null pointer dereference in __RPC_GETXID macro",
        "function": "Macro __RPC_GETXID",
        "description": "The macro dereferences the `tv_sec` and `tv_usec` fields of a struct `timeval *now` without checking that `now` is non‑NULL. A malicious caller could pass a NULL pointer, causing a crash or denial‑of‑service. While the macro only returns a uint32_t value, the crash could allow local privilege escalation or service interruption on systems where RPC is enabled."
    },
    {
        "severity": "MEDIUM",
        "title": "Unbounded string length calculation in SUN_LEN macro",
        "function": "Macro SUN_LEN",
        "description": "SUN_LEN(su) uses `strlen((su)->sun_path)` directly without validating that `su` is a valid pointer or that `sun_path` is null‑terminated within bounds. If an attacker provides a malformed sockaddr_un where `sun_path` is too long or not terminated, the macro may compute a size larger than the buffer allocated for the socket name, leading to a potential buffer overflow when the size is used elsewhere in the program."
    },
    {
        "severity": "MEDIUM",
        "title": "Unvalidated size value returned by __rpc_get_a_size",
        "function": "__rpc_get_a_size",
        "description": "The function returns an unsigned int that callers presumably use as an allocation size. Since the size is derived from external input, an attacker could cause it to be very large, resulting in integer overflow or out‑of‑memory conditions. There is no evidence in this header that the return value is checked against `RPC_MAXDATASIZE` or any other bounds before allocation."
    },
    {
        "severity": "LOW",
        "title": "Potential misuse of be‑presented function prototypes with unvalidated pointers",
        "function": [
            "__rpc_taddr2uaddr_af",
            "__rpc_uaddr2taddr_af",
            "__rpc_fixup_addr",
            "__rpc_sockinfo2netid",
            "__rpc_seman2socktype",
            "__rpc_socktype2seman",
            "xdr_authunix_parms",
            "__xdrrec_getrec",
            "__svc_clean_idle"
        ],
        "description": "All of the above functions accept raw pointers (e.g., `struct netbuf *`, `XDR *`, `fd_set *`) but the header does not specify any guarantees that the input pointers are valid or that the functions perform bounds or NULL checks. If an attacker can influence the arguments (for instance by forging a netbuf or XDR stream), these functions could dereference invalid pointers or read under‑initialized memory, leading to crashes or subtle data corruption."
    }
]
```