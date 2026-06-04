# Scan: clnt_nl.c

```json
[
  {
    "severity": "Critical",
    "title": "Unchecked integer overflow can under‑allocate the serialization buffer in clnt_nl_call",
    "function": "clnt_nl_call",
    "description": "The size of the buffer used for serializing the RPC request is calculated as\n\n    len = nl->nl_mpos + nl->nl_authlen + m_length(args, NULL);\n\n`nl->nl_mpos` and `nl->nl_authlen` are `uint32_t`, and `m_length()` returns a `size_t` (≥32 bits).  If `m_length(args)` is large enough to make the addition wrap around the 32‑bit range, `len` will be a small value.  The code then `malloc`s `len` bytes and proceeds to XDR‑encode the arguments into that buffer.  Since the real number of bytes that will be written can be far larger than the allocated space, an attacker who can inject a large `args` chain into a kernel RPC request can cause an out‑of‑bounds write in kernel memory.  This leads to heap corruption and arbitrary code execution with kernel privileges.  The bug is not mitigated by any bounds check or error handling after `malloc`."
  },
  {
    "severity": "High",
    "title": "Incorrect lock release in clnt_nl_destroy leads to deadlock",
    "function": "clnt_nl_destroy",
    "description": "After removing the `nl_data` instance from the global red‑black tree (`RB_REMOVE`), the function mistakenly performs a second `rw_wlock(&rpcnl_global_lock)` instead of unlocking it.  The global write lock therefore remains held after the function returns, blocking any other thread that attempts to create or destroy an RPC client, or to receive a reply.  This can be trivially triggered by a privileged user running `client_nl_destroy()` while a reply is being processed, resulting in a denial‑of‑service."
  },
  {
    "severity": "Medium",
    "title": "Potential misuse of user‑controlled nlmsg attributes in clnt_nl_reply",
    "function": "clnt_nl_reply",
    "description": "The function accepts the contents of the `RPCNL_REPLY_BODY` attribute without any semantic validation – it simply copies the raw data into the reply `mbuf`.  While generic netlink guarantees that a single attribute cannot exceed 64 KiB, an attacker can still send a payload that is larger than the expected RPC message size (`RPC_MAXDATASIZE` = 9000).  The subsequent XDR decoding (`xdr_replymsg`, `xdrmbuf_getall`) will read past the end of the supplied data.  Although the XDR routines validate the message length, a malformed payload can cause XDR to return an error and set `stat = RPC_CANTDECODERES`.  If the caller disregards this error and proceeds with authentication or other operations, it could lead to subtle bugs or information leakage.  This reflects a lack of strict validation on the size and format of the reply payload."
  }
]
```