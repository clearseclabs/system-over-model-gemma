# Scan: rpcsec_gss/rpcsec_gss_int.h

```json
[
  {
    "severity": "critical",
    "title": "Unbounded gss_buffer_desc handling in XDR\"",
    "function": "xdr_rpc_gss_cred, xdr_rpc_gss_init_res",
    "description": "The XDR routines deserialize the `gc_handle` and `gr_token` fields of `rpc_gss_cred` and `rpc_gss_init_res` directly into `gss_buffer_desc` structures whose `length` member is an arbitrary `int`.  No protocol‑level limit is imposed.  An attacker can send an oversized buffer value, forcing the XDR decoder to allocate a huge `gss_buffer_desc` on the heap or stack which may lead to out‑of‑memory crashes or memory exhaustion (DoS).  Because the decoded buffers are often later used in cryptographic or network operations, the large size can also provoke integer overflow or index‑out‑of‑bounds errors in downstream code."
  },
  {
    "severity": "high",
    "title": "Integer wrap‑around with invalid gc_seq values",
    "function": "xdr_rpc_gss_wrap_data, xdr_rpc_gss_unwrap_data",
    "description": "Both functions accept a `u_int seq` parameter used as a per‑message sequence counter.  The protocol defines `MAXSEQ` as `0x80000000`.  If an attacker supplies a sequence number larger than `MAXSEQ` (e.g., `0xFFFFFFFF`), arithmetic performed on `seq` (e.g., modulo or subtraction with signed intermediates) can wrap, producing a negative or small index.  This may bypass sequence integrity checks, lead to out‑of‑bounds array accesses, or allow replay/duplicate message exploitation."
  },
  {
    "severity": "high",
    "title": "Invalid rpc_gss_proc_t value from untrusted input",
    "function": "dispatcher code that switches on `gc_proc`",
    "description": "The `rpc_gss_proc_t` enum has four defined values (0‑3).  The XDR decoder does not enforce this range – it merely copies the raw 32‑bit integer.  Application code that switches on `gc_proc` (for RPCSEC_GSS handling) may index into an array of handlers or fall through to a default case that executes additional code without proper validation.  An out‑of‑range index can result in use of uninitialized function pointers, arbitrary code execution, or a crash."
  },
  {
    "severity": "medium",
    "title": "NULL pointer dereference of gss_buffer_desc.value for zero‑length buffers",
    "function": "any code that assumes `gss_buffer_desc.value` is non‑NULL",
    "description": "When a `gss_buffer_desc` is serialised by the XDR layer, the `value` pointer may legitimately be `NULL` if `length == 0`.  Subsequent code that accesses `value` without a `NULL` check (e.g., for printing or further cryptographic use) will crash with a segmentation fault, providing a trivial denial‑of‑service vector."
  },
  {
    "severity": "medium",
    "title": "Unvalidated numeric QOP conversion in `_rpc_gss_num_to_qop`",
    "function": "_rpc_gss_num_to_qop",
    "description": "This helper translates a numeric QOP value to a string.  It accepts an unsigned integer `num` but performs no bounds checking against the predefined QOP enumerations.  An attacker providing an out‑of‑range value could cause the function to return `NULL` or an undefined string pointer, which may be dereferenced later, triggering crashes or data leakage."
  },
  {
    "severity": "medium",
    "title": "Potential format‑string vulnerability in `rpc_gss_log_debug`",
    "function": "rpc_gss_log_debug",
    "description": "The function forwards its variadic arguments to `printf(...)` without any formatting safeguards.  If an attacker can supply a user‑controlled `fmt` string, they could execute arbitrary format specifiers, read memory contents, or cause stack corruption.  The risk is limited to logs that are written only on privileged servers but still constitutes a classic format‑string bug."
  },
  {
    "severity": "low",
    "title": "Missing bounds checks on `rpc_gss_service_t` values",
    "function": "any code that interprets `gc_svc` or its counterpart in `rpc_gss_init_res`",
    "description": "The header defines a `rpc_gss_service_t` type elsewhere but does not constrain its values.  If an untrusted packet contains an out‑of‑range service identifier and later code uses this enum value as an array index or switch case without validation, it may lead to memory corruption or unintended code paths."
  }
]
```