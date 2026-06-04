# Scan: auth.h

This is a security analysis of `auth.h`. Since this is a header file, the analysis focuses on the architectural design, data structure definitions, and the API contracts that implementations must follow. The vulnerabilities identified here are "structural" and "contractual," meaning they define how the corresponding `.c` implementations are likely to fail.

### Architectural Analysis

The file defines the interface for RPC authentication. The primary risk surface is the `struct opaque_auth`, which is designed to hold credentials (`ah_cred`) and verifiers (`ah_verf`) received from the network via XDR.

#### 1. The `opaque_auth` Design (The Primary Attack Vector)
The `struct opaque_auth` is a tagged union pattern:
```c
struct opaque_auth {
	enum_t	oa_flavor;
	caddr_t	oa_base;
	u_int	oa_length;
};
```
The `oa_flavor` determines how the `oa_base` buffer is cast and interpreted. 
*   **Risk**: If the implementation of `ah_validate` or `_svcauth_*` functions does not strictly validate that `oa_length` is sufficient for the expected structure associated with `oa_flavor`, a **buffer over-read** occurs.
*   **Risk**: While `MAX_AUTH_BYTES` (400) is defined, this is a constant. If the XDR decoder (`xdr_opaque_auth`) does not enforce this limit during deserialization, an attacker can cause an **Integer Overflow** or **Heap Overflow** in the allocation of `oa_base`.

#### 2. Function Pointer Indirection (`AUTH` handle)
The `AUTH` structure uses a table of function pointers (`ah_ops`):
```c
const struct auth_ops {
    void (*ah_nextverf) (struct __auth *);
    int  (*ah_marshal) (struct __auth *, uint32_t, XDR *, struct mbuf *);
    // ...
} *ah_ops;
```
The macros `AUTH_NEXTVERF`, `AUTH_MARSHALL`, etc., perform direct dereferences:
`((*((auth)->ah_ops->ah_nextverf))(auth))`
*   **Risk**: There is no safety check to ensure `ah_ops` is not NULL. If an `AUTH` handle is partially initialized or corrupted in memory, this leads to an immediate **Null Pointer Dereference** or, if `ah_ops` is controlled by an attacker, **Arbitrary Code Execution (ACE)**.

#### 3. `des_block` Union
```c
union des_block {
	struct {
		uint32_t high;
		uint32_t low;
	} key;
	char c[8];
};
```
*   **Risk**: This union allows treating 8 bytes of raw data as two 32-bit integers. While not inherently a bug, if the `key` struct is used on architectures with different endianness than the network byte order without calling `ntohl()`, the authentication will fail or, worse, lead to predictable key material.

#### 4. Input Constraints and Fixed Buffers
The header defines several limits:
*   `MAXNETNAMELEN` (255)
*   `AUTH_SYS_MAX_HOSTNAME` (255)
*   `AUTH_SYS_MAX_GROUPS` (16)

These constants imply that the corresponding `.c` files likely use fixed-size stack buffers.
*   **Risk**: If `authunix_create` or `netname2user` takes a `len` parameter from a network packet and uses these constants for buffer allocation but forgets to validate the input length against them, a **Stack Buffer Overflow** is highly probable.

### Summary of Findings

| Severity | Title | Function/Structure | Description |
| :--- | :--- | :--- | :--- |
| **High** | Potential Buffer Over-read via `oa_flavor` | `struct opaque_auth` | The reliance on `oa_flavor` to interpret `oa_base` without an enforced length check in the API contract can lead to out-of-bounds reads if `oa_length` is smaller than the structure associated with the flavor. |
| **High** | Unsafe Function Pointer Dereference | `AUTH_NEXTVERF` etc. | The macros dereference `ah_ops` without verifying it is non-NULL, leading to crashes or potential ACE if the `AUTH` handle is corrupted. |
| **Medium** | Insecure Memory Contract | `xdr_opaque_auth` | The header defines `MAX_AUTH_BYTES` but the API does not explicitly force the XDR decoder to reject packets exceeding this, risking heap exhaustion or overflows in implementations. |
| **Medium** | Fixed-size Buffer Risk | `authunix_create` | The definition of `AUTH_SYS_MAX_HOSTNAME` and `MAXNETNAMELEN` suggests the use of fixed buffers; if not strictly validated against untrusted input, these are primary sites for stack overflows. |

```json
[
  {
    "severity": "high",
    "title": "Potential Buffer Over-read via Flavor Type Confusion",
    "function": "struct opaque_auth",
    "description": "The structure uses oa_flavor to determine the type of oa_base. If implementation functions (like ah_validate) trust the flavor without verifying that oa_length is sufficient for that specific flavor's data structure, an attacker can trigger an out-of-bounds read."
  },
  {
    "severity": "high",
    "title": "Null Pointer Dereference in AUTH Macros",
    "function": "AUTH_NEXTVERF, AUTH_MARSHALL, AUTH_VALIDATE",
    "description": "The API macros dereference the ah_ops function table pointer without checking for NULL. If an AUTH handle is not fully initialized, this results in a crash or potential control-flow hijack."
  },
  {
    "severity": "medium",
    "title": "Fixed-size Buffer Overflow Risk in Unix Auth",
    "function": "authunix_create",
    "description": "The presence of AUTH_SYS_MAX_HOSTNAME and MAXNETNAMELEN indicates the use of fixed-length buffers. If these are used in memcpy/strcpy operations without validating the input length from the network, a stack overflow is possible."
  }
]
```