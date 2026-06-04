# Scan: authunix_prot.c

### Security Analysis: `authunix_prot.c`

The function `xdr_authunix_parms` handles the serialization and deserialization of UNIX authentication credentials. In the context of an RPC request (where `xdrs->x_op != XDR_ENCODE`), the input is entirely controlled by the network attacker.

#### 1. Input Vector Analysis
The attacker controls the following values via the `XDR` stream:
- `time` (uint32_t)
- `namelen` (uint32_t)
- `cred->cr_uid` (uint32_t)
- `cred->cr_gid` (uint32_t)
- `supp_ngroups` (uint32_t)
- The sequence of group IDs following `supp_ngroups`.

#### 2. Vulnerability Trace

**A. Integer Overflow in `cr_ngroups` Calculation**
At the end of the function, during decoding, the code calculates the number of groups to store:
```c
if (xdrs->x_op != XDR_ENCODE)
    cred->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
```
- `supp_ngroups` is a `uint32_t` decoded from the network.
- The code checks `if (supp_ngroups > AUTH_SYS_MAX_GROUPS) return (FALSE);` earlier.
- Since `AUTH_SYS_MAX_GROUPS` is a small constant (usually 16), `supp_ngroups + 1` will not overflow a 32-bit integer. This specific operation is safe.

**B. Buffer Boundary Analysis (`cr_sgroups`)**
The loop iterates based on the attacker-controlled `supp_ngroups`:
```c
for (i = 0; i < supp_ngroups; ++i)
    if (!xdr_uint32_t(xdrs, i < XU_NGROUPS - 1 ?
        &cred->cr_sgroups[i] : &junk))
        return (FALSE);
```
- **Boundary:** The condition `i < XU_NGROUPS - 1` determines whether the value is written to the `cred->cr_sgroups` array or a local `junk` variable.
- **Array Size:** According to the grep results, `struct xucred` defines `cr_sgroups[XU_NGROUPS - 1]`.
- **Index Trace:** 
    - If `i` is `0` to `XU_NGROUPS - 2`, it writes to `&cred->cr_sgroups[i]`. This is within bounds.
    - If `i` is `XU_NGROUPS - 1` or greater, it writes to `&junk`.
- **Conclusion:** The loop correctly prevents an out-of-bounds write to the `xucred` structure.

**C. Potential NULL Dereference**
The function signature is:
`bool_t xdr_authunix_parms(XDR *xdrs, uint32_t *time, struct xucred *cred)`
- The code immediately dereferences `xdrs->x_op`.
- The code dereferences `cred->cr_uid`, `cred->cr_gid`, etc.
- If the RPC framework calls this function with a `NULL` `cred` pointer or `NULL` `xdrs` pointer, the kernel will panic. While usually the caller's responsibility, in the context of an external-facing RPC interface, this is a potential crash vector if the framework doesn't guarantee allocation.

**D. Hostname Handling**
```c
if (namelen > AUTH_SYS_MAX_HOSTNAME)
    return (FALSE);
xdr_setpos(xdrs, xdr_getpos(xdrs) + RNDUP(namelen));
```
- On decode, the code validates `namelen` against `AUTH_SYS_MAX_HOSTNAME` (255).
- It then uses `xdr_setpos` to skip the hostname.
- If `xdr_getpos` or `RNDUP(namelen)` can cause an integer wrap around the XDR stream's internal buffer boundaries, it could lead to an out-of-bounds read in subsequent `xdr_uint32_t` calls. However, `namelen` is capped at 255, making a wrap-around unlikely unless the stream position is already near `UINT32_MAX`.

#### 3. Summary of Findings
The code is surprisingly robust regarding the most common XDR pitfalls (buffer overflows). The loop logic specifically accounts for the difference between the RFC's group limits and the internal `xucred` structure's limits.

The primary risks are architectural:
1. **Lack of NULL validation** on the `cred` and `xdrs` pointers.
2. **Trust in `xdr_setpos`**: The logic assumes the XDR stream contains at least `namelen` bytes. If the stream is shorter than `namelen`, `xdr_setpos` may move the pointer beyond the actual data buffer, leading to an OOB read when `xdr_uint32_t` is called for `cr_uid`.

```json
[
  {
    "severity": "medium",
    "title": "Potential Out-of-Bounds Read via xdr_setpos",
    "function": "xdr_authunix_parms",
    "description": "During decoding, the function uses xdr_setpos to skip the hostname based on a network-provided 'namelen' (up to 255 bytes). If the actual data remaining in the XDR buffer is less than 'namelen', the stream position is advanced beyond the buffer boundary, causing subsequent calls to xdr_uint32_t to perform out-of-bounds reads."
  },
  {
    "severity": "low",
    "title": "Unvalidated Pointer Dereferences",
    "function": "xdr_authunix_parms",
    "description": "The function dereferences the 'xdrs' and 'cred' pointers without verifying they are non-NULL. If the calling RPC framework passes a NULL pointer due to an internal allocation failure, the system will crash."
  }
]
```