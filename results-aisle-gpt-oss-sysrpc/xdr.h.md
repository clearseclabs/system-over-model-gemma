# Scan: xdr.h

```json
[
  {
    "severity": "high",
    "title": "Potential NULL dereference of XDR operations vector",
    "function": "XDR_GETLONG / XDR_PUTLONG / XDR_GETBYTES / XDR_PUTBYTES / XDR_GETPOS / XDR_SETPOS / XDR_INLINE / XDR_DESTROY / XDR_CONTROL",
    "description": "All XDR operation macros directly dereference the `x_ops` pointer of the `XDR` structure (e.g., `(*(xdrs)->x_ops->x_getlong)(xdrs, longp)`).  If an `XDR` instance is created with `x_ops == NULL` or with any of its function pointers uninitialised, the call triggers a NULL‑pointer dereference that results in a crash.  An attacker who can dictate the construction of an `XDR` handle (e.g., via a vulnerable wrapper or uninitialised memory) could cause a denial‑of‑service or potentially trigger arbitrary code execution if the function pointer is corrupted to point to attacker supplied code."
  },
  {
    "severity": "medium",
    "title": "Integer overflow risk in RNDUP macro",
    "function": "RNDUP",
    "description": "The macro rounds up to the nearest multiple of 4: `(((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) * BYTES_PER_XDR_UNIT`.  If `x` is close to the maximum value representable by an unsigned int, the temporary addition can overflow, producing an incorrectly small quotient and later an under‑allocation.  Subsequent operations that rely on the rounded value (e.g., buffer size allocations) could therefore allocate fewer bytes than required, leading to out‑of‑bounds writes."
  },
  {
    "severity": "medium",
    "title": "Unchecked return of XDR_INLINE",
    "function": "XDR_INLINE / xdr_inline",
    "description": "The macro invokes `x_ops->x_inline` to obtain a fast pointer to the current stream buffer.  The contract requires callers to check whether the returned pointer is `NULL`, but the macro itself offers no safeguard, and many higher‑level routines (e.g., in XDR implementations) assume a non‑NULL return.  If the underlying stream cannot provide the requested bytes (e.g., at the end of a record), the macro returns `NULL` and subsequent dereferencing by the caller will cause a crash or memory corruption, allowing a remote attacker to cause a denial‑of‑service."
  },
  {
    "severity": "medium",
    "title": "Missing bounds checks for XDR string/array allocations",
    "function": "xdr_string, xdr_bytes, xdr_array, xdr_netobj",
    "description": "These functions accept a maximum length in caller‑supplied arguments (e.g., `maxsize` in `xdr_bytes` or the implicit `MAX_NETOBJ_SZ` in `xdr_netobj`).  The header does not enforce any limits on those values, nor does it validate that the supplied length fits within the receiver's buffer.  Malicious input that supplies an excessively large length can cause the library to allocate more memory than intended or write past the end of available buffers when the `x_getbytes` operation pulls in data, potentially leading to heap corruption or a denial‑of‑service."
  },
  {
    "severity": "medium",
    "title": "Lack of type‑tag verification for union handling",
    "function": "xdr_union",
    "description": "The public `xdr_union` routine takes an `enum_t *` discriminant and an array of `xdr_discrim`.  If the discriminant value is not present in the array and no default routine is supplied, `xdr_union` returns `FALSE`.  However, the caller may ignore this failure status, assuming the operation succeeded, and proceed to use an uninitialised or partially initialised value.  An attacker controlling the discriminant (e.g., via crafted RPC data) could therefore bypass validation and obtain a use‑of‑uninitialised‑memory vulnerability."
  }
]
```