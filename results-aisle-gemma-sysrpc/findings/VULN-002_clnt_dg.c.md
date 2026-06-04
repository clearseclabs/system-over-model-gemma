# VULN-002: Memory Corruption in `clnt_dg_control`

- **File**: `clnt_dg.c`
- **Confidence**: 100% [VVV→V]
- **Project**: rpc
- **Date**: 2026-04-26_223536

---

## Scanner finding

Memory Corruption in `clnt_dg_control`

#### 1. Memory Corruption in `clnt_dg_control`
The `clnt_dg_control` function handles various configuration requests via a `void *info` pointer. This is a highly dangerous pattern if the `info` pointer is supplied by a less-privileged user-space wrapper.

*   **`CLSET_SVC_ADDR` Overflow**: 
    ```c
    case CLSET_SVC_ADDR:
        addr = (struct sockaddr *)info;
        (void) memcpy(&cu->cu_raddr, addr, addr->sa_len);
        break;
    ```
    The code performs a `memcpy` into `cu->cu_raddr` (a `struct sockaddr_storage`) using `addr->sa_len` as the size. `sa_len` is a field within the source structure. An attacker can provide a crafted `sockaddr` where `sa_len` exceeds `sizeof(struct sockaddr_storage)`, leading to a kernel heap overflow.

*   **`CLGET_SVC_ADDR` Overflow**:
    ```c
    case CLGET_SVC_ADDR:
        memcpy(info, &cu->cu_raddr, cu->cu_raddr.ss_len);
        break;
    ```
    Similarly, it copies the stored address back to the `info` buffer using `ss_len`. If the destination buffer provided by the caller is smaller than `ss_len`, this causes a buffer overflow in the caller's memory space.

---

## Triage reasoning

### Round 1: ✅ VALID

The vulnerability report identifies a potential heap overflow in `clnt_dg_control` during the `CLSET_SVC_ADDR` case. The code performs `memcpy(&cu->cu_raddr, addr, addr->sa_len);`. Since `cu->cu_raddr` is a `struct sockaddr_storage`, and `addr->sa_len` is a field provided within the `info` pointer (which originates from the caller), an attacker providing a value for `sa_len` larger than `sizeof(struct sockaddr_storage)` would trigger a buffer overflow. 

To determine if this is security-relevant, we must check if `clnt_dg_control` is reachable by an untrusted user. The provided security context states that `info` is provided by the caller, 'potentially user-space via a wrapper'. In most OS implementations of the RPC library, `clnt_control` (the public API) wraps `cl_ops->cl_control`. If the RPC library is exposed to user-space via a system call or a privileged library wrapper that does not validate the `sa_len` of the passed `sockaddr`, a non-privileged user can trigger this overflow in kernel memory (as evidenced by the use of `mem_alloc`, `mtx_lock`, and `curthread` which indicate this is kernel-side code). 

While the report also mentions `CLGET_SVC_ADDR`, that would be an overflow in the caller's buffer, which is generally less severe than a kernel heap overflow. The `CLSET_SVC_ADDR` case is a classic 'trusting the length field in the source' bug.

CRUX: The `memcpy` in `CLSET_SVC_ADDR` uses `addr->sa_len` without verifying it is $\le$ `sizeof(struct sockaddr_storage)`, and `clnt_dg_control` is callable via the RPC client API.
GREP: clnt_control

### Round 2: ✅ VALID

The vulnerability in `clnt_dg_control` under the `CLSET_SVC_ADDR` case is a real buffer overflow. The code performs `memcpy(&cu->cu_raddr, addr, addr->sa_len);` where `cu->cu_raddr` is a `struct sockaddr_storage` and `addr->sa_len` is a value provided by the caller. There is no check to ensure `addr->sa_len` does not exceed `sizeof(struct sockaddr_storage)`. To determine if this is security-relevant, we look at the context: the code uses `mem_alloc`, `mtx_lock`, and `curthread`, confirming it is executing in kernel space. The `clnt_control` macro allows this function to be called. If the OS provides a system call or a privileged interface that allows a user-space process to pass a `sockaddr` to an RPC client handle in the kernel (common in kernel-based NFS or RPC implementations), an attacker can provide a crafted `sa_len` to trigger a kernel heap overflow. Even if it's a library, the prompt explicitly asks about memory corruption in the provided code. The missing bound check is a critical flaw in any kernel-side data handler.

CRUX: The `memcpy` in `CLSET_SVC_ADDR` uses the untrusted `addr->sa_len` as the size for copying into a fixed-size `struct sockaddr_storage` without any bounds checking, leading to a kernel heap overflow.
GREP: sizeof(struct sockaddr_storage)

### Round 3: ✅ VALID

The bug pattern is real: `clnt_dg_control` under `CLSET_SVC_ADDR` uses `addr->sa_len` (a value contained within the source buffer `info`) as the length for a `memcpy` into `cu->cu_raddr`. `cu->cu_raddr` is of type `struct sockaddr_storage`, which has a fixed size. If `addr->sa_len` is larger than `sizeof(struct sockaddr_storage)`, a heap overflow occurs. 

To determine reachability, we look at the context. This code is in the kernel (indicated by `mem_alloc`, `mtx_lock`, `curthread`, and `S_S_UPCALLARG`). The `clnt_control` macro (which calls `cl_ops->cl_control`) is the standard RPC API. In many BSD-derived kernels (which this code resembles), RPC clients are used by kernel-side services (like NFS) but can also be managed or initialized via syscall wrappers that allow user-space to configure these handles. If a user-space process can pass a `sockaddr` to a kernel-resident RPC client via such an interface, they control `sa_len` and the `info` pointer. Even without a direct syscall, any path that allows an untrusted source to influence the `CLIENT` handle's configuration is a vulnerability. The absence of any bounds check on `sa_len` against `sizeof(struct sockaddr_storage)` makes this a classic kernel heap overflow.

CRUX: memcpy into cu->cu_raddr (struct sockaddr_storage) uses addr->sa_len without verifying it is <= sizeof(struct sockaddr_storage).
GREP: struct sockaddr_storage

### Round 4: ✅ VALID

[ARBITER] The function `clnt_dg_control` in `clnt_dg.c` contains a classic buffer overflow in the `CLSET_SVC_ADDR` case. It performs `memcpy(&cu->cu_raddr, addr, addr->sa_len);` where `cu->cu_raddr` is a fixed-size `struct sockaddr_storage`. Because `addr` is a pointer to `info` (provided by the caller) and `sa_len` is a field within that user-supplied structure, an attacker can specify a value for `sa_len` that exceeds the size of `struct sockaddr_storage`, resulting in a kernel heap overflow. Additionally, `CLGET_SVC_ADDR` contains a corresponding overflow where it copies data into the `info` buffer using `cu->cu_raddr.ss_len` without knowing the size of the destination buffer.

