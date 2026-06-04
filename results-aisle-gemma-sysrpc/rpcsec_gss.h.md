# Scan: rpcsec_gss.h

This is a header file (`rpcsec_gss.h`) that defines an interface. Because it consists almost entirely of type definitions and function prototypes, there is no executable logic (implementation) to analyze for traditional bugs like buffer overflows or logic errors. 

However, from a security researcher's perspective, the **API design** reveals several high-risk patterns that the corresponding implementation (likely in `kgssapi` or the RPC layer) must handle correctly to avoid vulnerabilities.

### Security Analysis

#### 1. Buffer Overflow Risks in `rpc_gss_options_ret_t`
The structure `rpc_gss_options_ret_t` contains a fixed-size buffer:
```c
char actual_mechanism[MAX_GSS_MECH]; // MAX_GSS_MECH is 64
```
The function `rpc_gss_seccreate` takes a `mechanism` string (attacker-controlled via RPC request) and returns `options_ret`. If the implementation uses `strcpy` or `memcpy` to populate `actual_mechanism` based on the input `mechanism` or the GSS-API's returned mechanism name without verifying it is $< 64$ bytes, a **stack or heap overflow** will occur depending on where `rpc_gss_options_ret_t` is allocated.

#### 2. Integer Overflows in `rpc_gss_principal_t`
The principal type uses a flexible array member pattern (though defined as `name[1]` for legacy C compatibility):
```c
typedef struct {
    int len;
    char name[1];
} *rpc_gss_principal_t;
```
The field `len` is a signed `int`. If an implementation uses `len` to calculate allocation sizes (e.g., `malloc(principal->len + 1)`), a negative value or a very large value could lead to:
- **Integer Underflow/Wrap**: Resulting in a small allocation followed by a large `memcpy` (Heap Overflow).
- **Negative Size**: Passing a negative value to a size-expecting function, which often casts to `size_t` (unsigned), creating a massive allocation request that may fail or wrap.

#### 3. NULL Pointer Dereferences in `rpc_gss_rawcred_t`
The `rpc_gss_rawcred_t` structure contains several pointers:
```c
const char *mechanism;
const char *qop;
rpc_gss_principal_t client_principal;
const char *svc_principal;
```
Since these are populated from network-driven RPC requests, a malformed packet could result in any of these pointers being `NULL`. Any function consuming this structure (such as `rpc_gss_set_defaults`) must explicitly check for `NULL` before dereferencing these strings.

#### 4. Memory Management of `rpc_gss_ucred_t`
The Unix credentials structure includes a pointer to a list:
```c
typedef struct {
    uid_t uid;
    gid_t gid;
    short gidlen;
    gid_t *gidlist;
} rpc_gss_ucred_t;
```
If `gidlen` is used to iterate over `gidlist` without validating that `gidlist` is not `NULL` or that the allocation matches `gidlen`, an **out-of-bounds read** or **NULL pointer dereference** is possible.

#### 5. Function Pointer Table (`rpc_gss_entries`)
The header implements a "plugin" architecture where function pointers are filled at runtime. The `_call` helpers (e.g., `rpc_gss_secfind_call`) correctly check if the pointer is `NULL` before calling:
```c
if (rpc_gss_entries.rpc_gss_secfind != NULL)
    ret = (*rpc_gss_entries.rpc_gss_secfind)(...);
```
This pattern is safe. However, if any internal kernel code bypasses these `_call` wrappers and accesses `rpc_gss_entries` directly, it will trigger a kernel panic if the GSS module is not loaded.

### Findings Summary

```json
[
  {
    "severity": "high",
    "title": "Potential Buffer Overflow in actual_mechanism",
    "function": "rpc_gss_seccreate",
    "description": "The rpc_gss_options_ret_t structure defines a fixed-size buffer 'actual_mechanism' of 64 bytes. If the implementation copies the mechanism name from the network request or GSS-API return without strict bounds checking, it may lead to a buffer overflow."
  },
  {
    "severity": "high",
    "title": "Integer Overflow/Signedness Issue in rpc_gss_principal_t",
    "function": "rpc_gss_get_principal_name",
    "description": "The rpc_gss_principal_t structure uses a signed integer 'len' to track the name length. Use of this signed value in memory allocation or bounds checking can lead to integer overflows or heap corruption if negative values are provided."
  },
  {
    "severity": "medium",
    "title": "Potential NULL Pointer Dereference in raw credentials",
    "function": "rpc_gss_getcred",
    "description": "The rpc_gss_rawcred_t structure contains multiple pointers (mechanism, qop, client_principal) derived from untrusted RPC headers. Lack of NULL checks in functions consuming this structure could lead to crashes."
  }
]
```