# VULN-001: NULL Pointer Dereference in authunix_validate

- **File**: `auth_unix.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

NULL Pointer Dereference in authunix_validate

The function checks if the 'verf' pointer is NULL, but does not check if 'verf->oa_base' is NULL before passing it to 'xdrmem_create'. A malformed RPC packet with AUTH_SHORT flavor and a NULL base pointer will cause a kernel crash.

---

## Triage reasoning

### Round 1: ✅ VALID

The function `authunix_validate` is called when an RPC request arrives. It receives a `struct opaque_auth *verf`, which is decoded from the network. If the attacker sets the `oa_flavor` to `AUTH_SHORT`, the code proceeds to call `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE)`. There is no check to ensure `verf->oa_base` is not NULL. If `verf->oa_base` is NULL, `xdrmem_create` (which typically initializes an XDR handle to read from a buffer) will likely dereference this pointer when the subsequent `xdr_opaque_auth` call attempts to read data from the stream, leading to a kernel crash (Panic). Since `verf` is constructed from network-provided XDR data, an attacker can specifically craft a packet where the base pointer for the opaque auth structure is null (or the XDR decoding of the opaque auth structure results in a NULL base).

CRUX: authunix_validate passes verf->oa_base to xdrmem_create without checking if it is NULL, and verf is derived from untrusted network input.
GREP: xdrmem_create

### Round 2: ✅ VALID

The `authunix_validate` function is called during RPC request processing. It receives a `struct opaque_auth *verf` which is derived from the network. If the attacker provides a packet with `oa_flavor == AUTH_SHORT` and `oa_base == NULL`, the code calls `xdrmem_create(&txdrs, verf->oa_base, verf->oa_length, XDR_DECODE)`. Looking at the implementation of `xdrmem_create` (referenced in `lib/libc/xdr/xdr_mem.c`), it initializes an XDR handle to read from the provided memory address. While `xdrmem_create` itself might only assign the pointer, the subsequent call to `xdr_opaque_auth(&txdrs, &au->au_shcred)` will attempt to read data from that pointer. If `oa_base` is NULL, this results in a NULL pointer dereference and a kernel crash. The check `if (!verf)` only ensures the structure containing the metadata is present, not that the payload buffer `oa_base` is present. Since `verf` is constructed from untrusted network input via XDR, an attacker can trigger this path.

CRUX: authunix_validate passes verf->oa_base to xdrmem_create without verifying it is non-NULL, and verf is attacker-controlled network input.
GREP: xdr_opaque_auth

### Round 3: ✅ VALID

The bug pattern is real: `authunix_validate` passes `verf->oa_base` to `xdrmem_create` and then calls `xdr_opaque_auth` without checking if `oa_base` is NULL. In RPC, the `opaque_auth` structure is decoded from the network. If an attacker provides a payload where `oa_flavor` is `AUTH_SHORT` but the data buffer `oa_base` is NULL (which happens if the XDR decoder processes a zero-length opaque object or a specifically crafted malformed packet), the subsequent read operation in `xdr_opaque_auth` will dereference the NULL pointer. Since `authunix_validate` is part of the kernel RPC authentication layer, this will trigger a kernel panic (DoS). The `if (!verf)` check is insufficient because it only checks the container, not the internal data pointer. There are no intervening defenses that prevent a NULL `oa_base` from reaching `xdrmem_create` when `oa_flavor == AUTH_SHORT`.

CRUX: authunix_validate lacks a NULL check for verf->oa_base before using it as a source buffer for xdr_opaque_auth, and this pointer is derived from untrusted network input.
GREP: xdrmem_create

### Round 4: ✅ VALID

[ARBITER] In `authunix_validate`, the code checks if the `verf` pointer itself is NULL, but it fails to check if `verf->oa_base` is NULL before passing it to `xdrmem_create`. Since `verf` is derived from untrusted network input (an RPC packet), an attacker can provide a packet with `oa_flavor == AUTH_SHORT` and `oa_base == NULL`. The subsequent call to `xdrmem_create` and the follow-up `xdr_opaque_auth` call will attempt to read from the NULL address, resulting in a kernel crash (NULL pointer dereference).

