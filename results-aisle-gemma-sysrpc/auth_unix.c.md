# Scan: auth_unix.c

### Security Analysis of `auth_unix.c`

The `auth_unix.c` file implements UNIX-style authentication for RPC. The primary security boundary is `authunix_validate`, which processes credentials received over the network.

#### 1. Buffer Overflows and Memory Safety
**Analysis of `authunix_create`**:
- The function uses a stack-allocated buffer `char mymem[MAX_AUTH_BYTES]`.
- It calls `xdrmem_create(&xdrs, mymem, MAX_AUTH_BYTES, XDR_ENCODE)` and then `xdr_authunix_parms`.
- If `xdr_authunix_parms` exceeds `MAX_AUTH_BYTES`, it would cause a stack overflow. While `MAX_AUTH_BYTES` (400) is generally sufficient for UNIX credentials (UID, GID, RGID, and a timestamp), this is a hard-coded limit.

**Analysis of `marshal_new_auth`**:
- This function encodes the current credentials into `au->au_marshed`, which is a fixed-size array of `MAX_AUTH_BYTES`.
- It calls `xdr_opaque_auth` twice. If the combination of `ah_cred` and `ah_verf` exceeds 400 bytes, `au->au_marshed` will be overflowed. Since `ah_cred` is derived from `au->au_origcred` (which was created via `xdr_authunix_parms`), it is likely within limits, but `ah_verf` could potentially be manipulated.

#### 2. Untrusted Input Flow (`authunix_validate`)
The `authunix_validate` function is the primary entry point for attacker-controlled data (`struct opaque_auth *verf`).

- **The Vulnerability**: The code checks `if (verf->oa_flavor == AUTH_SHORT)`. If true, it proceeds to call `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE)`.
- **XDR Memory Handling**: `xdrmem_create` initializes an XDR stream using `verf->oa_base` as the source and `verf->oa_length` as the boundary.
- **The Flaw**: `xdr_opaque_auth(&txdrs, &au->au_shcred)` is called to decode the shorthand credential. If the XDR implementation of `xdr_opaque_auth` does not strictly validate the length of the data being read against the remaining buffer size provided by `verf->oa_length`, or if it trusts the length encoded *inside* the XDR stream, a heap overflow or out-of-bounds read could occur.
- **NULL Pointer**: While `verf` is checked for NULL, `verf->oa_base` is not. If a packet is crafted where `oa_flavor == AUTH_SHORT` but `oa_base` is NULL, `xdrmem_create` (and subsequently the XDR engine) will dereference a NULL pointer.

#### 3. Integer and Type Issues
- **`mem_alloc` usage**: In `authunix_create`, `au->au_origcred.oa_base = mem_alloc((u_int) len)`. Since `len` is derived from `XDR_GETPOS`, it is unlikely to be negative, but if `len` were 0, `mem_alloc(0)` behavior depends on the kernel implementation (potentially returning a valid pointer or NULL).
- **Refcount Race**: The use of `sx_try_upgrade` in `authunix_create` is used to maintain the LRU list. If the upgrade fails, the code simply unlocks and returns the auth handle. This is a correct use of the lock to avoid deadlocks.

#### 4. Memory Leaks and Life Cycle
- In `authunix_validate`, `au->au_shcred.oa_base` is freed before being overwritten. However, if `xdr_opaque_auth` fails, the code sets `au->au_shcred.oa_base = NULL`. This seems robust.
- `authunix_destroy` properly releases the refcount and frees the associated memory for `origcred` and `shcred`.

### Summary of Findings

1.  **NULL Pointer Dereference**: In `authunix_validate`, `verf->oa_base` is passed to `xdrmem_create` without verification. An attacker providing a packet with `oa_flavor = AUTH_SHORT` and `oa_base = NULL` can trigger a kernel panic.
2.  **Potential Heap Overflow/OOB Read**: The logic in `authunix_validate` relies entirely on the XDR engine to respect `verf->oa_length`. If the XDR decoder reads more than `oa_length` bytes based on a length field embedded within the `oa_base` payload, it will result in an out-of-bounds read or heap corruption.
3.  **Fixed-Size Buffer Risk**: `marshal_new_auth` writes to `au->au_marshed[MAX_AUTH_BYTES]` without a final check that the XDR position did not exceed the array boundary. While the `printf` warns of a "Fatal marshalling problem," the overflow has already occurred by the time the check is performed.

```json
[
  {
    "severity": "high",
    "title": "NULL Pointer Dereference in authunix_validate",
    "function": "authunix_validate",
    "description": "The function checks if the 'verf' pointer is NULL, but does not check if 'verf->oa_base' is NULL before passing it to 'xdrmem_create'. A malformed RPC packet with AUTH_SHORT flavor and a NULL base pointer will cause a kernel crash."
  },
  {
    "severity": "medium",
    "title": "Potential Buffer Overflow in marshal_new_auth",
    "function": "marshal_new_auth",
    "description": "The function uses a fixed-size buffer 'au->au_marshed' (MAX_AUTH_BYTES). It calls 'xdr_opaque_auth' twice to encode credentials. If the resulting encoded data exceeds 400 bytes, a stack/heap overflow occurs. The overflow check is performed after the XDR operations have already written to the buffer."
  },
  {
    "severity": "medium",
    "title": "XDR Boundary Trust Issue",
    "function": "authunix_validate",
    "description": "The function trusts 'verf->oa_length' to bound the XDR decoding process. If the XDR engine's 'xdr_opaque_auth' implementation relies on internal length fields from the untrusted 'verf->oa_base' rather than the stream boundary, it can lead to out-of-bounds memory access."
  }
]
```