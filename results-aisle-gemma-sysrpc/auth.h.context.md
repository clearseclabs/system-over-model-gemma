# Context: auth.h

This briefing covers `auth.h`, the header defining the RPC authentication interface.

### 1. Function & Location
This code defines the structures and API for RPC authentication (client and server side). It sits at the core of the RPC layer, providing a common interface (`AUTH` handle) for various security flavors (Unix, DES, Kerberos, TLS, GSS).

### 2. Untrusted Input Path
Untrusted data reaches this code via the network. RPC requests contain authentication credentials (`opaque_auth`) and verifiers, which are deserialized using XDR (External Data Representation) and passed to the `ah_validate` or `_svcauth_*` functions.

### 3. Attacker-Controlled Data
*   **`struct opaque_auth`**: `oa_flavor` (integer), `oa_base` (pointer to data), and `oa_length` (size).
*   **`des_block`**: `c[8]` (raw key/block data).
*   **Trace**: Network $\rightarrow$ `xdr_opaque_auth()` $\rightarrow$ `struct opaque_auth` $\rightarrow$ `ah_validate()` / `_svcauth_*` functions.

### 4. Fixed-Size Buffers & Constants
*   `MAX_AUTH_BYTES`: 400 (Maximum length for `oa_length` in `opaque_auth`).
*   `MAXNETNAMELEN`: 255.
*   `AUTH_SYS_MAX_HOSTNAME`: 255.
*   `AUTH_SYS_MAX_GROUPS`: 16.
*   `des_block.c`: 8 bytes.

### 5. Dangerous Data Flows
*   **Source**: `struct opaque_auth` $\rightarrow$ **Destination**: Internal buffers in `ah_validate` or `_svcauth_*` $\rightarrow$ **Numeric Size**: 400 (`MAX_AUTH_BYTES`).
*   **Source**: `char *machname` (via `authunix_create`) $\rightarrow$ **Destination**: Internal buffers $\rightarrow$ **Numeric Size**: 255 (`AUTH_SYS_MAX_HOSTNAME`).

### 6. NULL Pointer Risks
*   `ah_ops` in `struct __auth`: If an `AUTH` handle is improperly initialized, the macros `AUTH_NEXTVERF`, `AUTH_MARSHALL`, etc., will dereference a NULL `ah_ops` pointer.
*   `oa_base` in `struct opaque_auth`: May be NULL if `oa_length` is 0; functions consuming `oa_base` must check this.

### 7. Tagged Unions/Variants
*   `struct opaque_auth`: Uses `oa_flavor` as a type tag to determine how to interpret `oa_base`.
*   `union des_block`: Provides access to 8 bytes as either a `struct` of two `uint32_t` or a `char[8]`.

### 8. API Scope
*   **Public API**: `authunix_create`, `authdes_create`, `xdr_opaque_auth`, `_svcauth_*` family.
*   **Static/Internal**: The `auth_ops` function pointers are used internally by the RPC engine.

### 9. Likely Bug Classes
*   **Integer Overflows/Underflows**: In `oa_length` calculations.
*   **Buffer Overflows**: When copying `oa_base` or `netname` into fixed-size buffers (255/400 bytes).
*   **Type Confusion**: Incorrect `oa_flavor` handling leading to misinterpretation of `oa_base`.
*   **Null Pointer Dereference**: Via the `ah_ops` function table.