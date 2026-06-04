# Triage T0156: Race Condition / Use-After-Free of Stack-Allocated upsock

- **File**: `rpcsec_tls/rpctls_impl.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Race Condition / Use-After-Free of Stack-Allocated upsock

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The code inserts a pointer to a stack-allocated `struct upsock` into a global RB-tree, which is later dereferenced in a different thread/context (`sys_rpctls_syscall`), creating a Use-After-Free if the original thread returns.

The bug pattern is real: `rpctls_connect` and `rpctls_server` both allocate a `struct upsock` on their respective stacks and insert a pointer to this stack-allocated structure into the global `upcall_sockets` RB-tree. The `sys_rpctls_syscall` function then retrieves this pointer from the tree and dereferences it (`ups = *upsp`). There is a clear race window: if the thread that called `rpctls_connect` or `rpctls_server` returns (e.g., due to a timeout in `rpctlscd_connect_2` or `rpctlssd_connect_2`), its stack frame is destroyed. If `sys_rpctls_syscall` is called after this return but before the entry is removed (or while it is being removed), it will perform a Use-After-Free (UAF) on the stack memory. While `sys_rpctls_syscall` has a `priv_check(td, PRIV_NFS_DAEMON)`, this check only ensures the caller is the daemon. The vulnerability is triggered by the interaction between the kernel thread (mounting thread) and the daemon. An external attacker can trigger the 'mounting thread' side by initiating a TLS handshake (via a NULL RPC), and potentially influence the timing or trigger timeouts to force the stack to unwind while the daemon is still processing or about to call the syscall. This is a classic kernel UAF.

CRUX: The code inserts a pointer to a stack-allocated `struct upsock` into a global RB-tree, which is later dereferenced in a different thread/context (`sys_rpctls_syscall`), creating a Use-After-Free if the original thread returns.
GREP: sys_rpctls_syscall

🔎 **Grep results:**

GREP `sys_rpctls_syscall`:
```
sys/sys/sysproto.h:2318:int	sys_rpctls_syscall(struct thread *, struct rpctls_syscall_args *);
lib/libsys/_libsys.h:451:typedef int (__sys_rpctls_syscall_t)(uint64_t);
lib/libsys/_libsys.h:861:int __sys_rpctls_syscall(uint64_t socookie);
sys/rpc/rpcsec_tls/rpctls_impl.c:152:sys_rpctls_syscall(struct thread *td, struct rpctls_syscall_args *uap)
```

### Round 2: ✅ VALID

**🎯 Crux:** Stack-allocated `struct upsock` is stored in a global RB-tree and dereferenced in `sys_rpctls_syscall` after the original stack frame may have been destroyed.

The vulnerability is a textbook Use-After-Free (UAF) / Stack-Use-After-Return. In `rpctls_connect` and `rpctls_server`, a `struct upsock` is allocated on the stack and a pointer to it is inserted into the global `upcall_sockets` RB-tree. The `sys_rpctls_syscall` function retrieves this pointer from the tree and dereferences it (`ups = *upsp`). The critical race window occurs because the functions that inserted the pointer (`rpctls_connect`/`rpctls_server`) can return and destroy their stack frames before the daemon calls `sys_rpctls_syscall`. Specifically, if `rpctlscd_connect_2` or `rpctlssd_connect_2` fails or times out, the function calls `rpctls_rpc_failed` and returns. Although `rpctls_rpc_failed` attempts to remove the entry, there is a window where `sys_rpctls_syscall` could have already found the pointer and be about to dereference it, or the daemon might call the syscall just as the timeout occurs. More importantly, the design fundamentally relies on the daemon calling the syscall while the original thread is still blocked in the RPC call. An attacker can trigger the 'mounting thread' path by initiating a TLS handshake via a NULL RPC. While `sys_rpctls_syscall` requires `PRIV_NFS_DAEMON`, the attacker controls the timing of the network requests that cause the kernel thread to enter this state and potentially time out, thus triggering the UAF. The `priv_check` does not protect against this because the victim is the kernel thread's stack, and the trigger is the network-facing RPC mechanism.

CRUX: Stack-allocated `struct upsock` is stored in a global RB-tree and dereferenced in `sys_rpctls_syscall` after the original stack frame may have been destroyed.
GREP: sys_rpctls_syscall

🔎 **Grep results:**

GREP `sys_rpctls_syscall`:
```
lib/libsys/_libsys.h:451:typedef int (__sys_rpctls_syscall_t)(uint64_t);
lib/libsys/_libsys.h:861:int __sys_rpctls_syscall(uint64_t socookie);
sys/sys/sysproto.h:2318:int	sys_rpctls_syscall(struct thread *, struct rpctls_syscall_args *);
sys/rpc/rpcsec_tls/rpctls_impl.c:152:sys_rpctls_syscall(struct thread *td, struct rpctls_syscall_args *uap)
```

### Round 3: ✅ VALID

**🎯 Crux:** A pointer to a stack-allocated `struct upsock` is stored in a global RB-tree and dereferenced in `sys_rpctls_syscall` without any mechanism to guarantee the originating thread's stack frame still exists.

The bug pattern is a classic Stack-Use-After-Return. In `rpctls_connect` and `rpctls_server`, a `struct upsock` is allocated on the stack, and a pointer to it is inserted into the global `upcall_sockets` RB-tree. `sys_rpctls_syscall` retrieves this pointer and dereferences it (`ups = *upsp`). The code explicitly acknowledges this danger in a comment: 'The upsp points to stack of NFS mounting thread... The mounting thread may timeout the RPC and unroll its stack.' 

Despite the comment, the code does not implement a synchronization mechanism (like a semaphore or completion variable) to ensure the mounting thread is still alive when `sys_rpctls_syscall` is called. The `mtx_lock(&rpctls_lock)` only protects the RB-tree structure itself, not the lifetime of the object pointed to by the tree entries. If `rpctlscd_connect_2` or `rpctlssd_connect_2` returns (due to timeout or error), the `upsock` stack frame is destroyed. If the userspace daemon calls `sys_rpctls_syscall` after this return, the kernel will dereference a pointer to a defunct stack frame.

An external attacker can trigger this by initiating a TLS handshake (via a NULL RPC with AUTH_TLS), which calls `_svcauth_rpcsec_tls` -> `rpctls_server`. By manipulating network timing or causing the daemon to delay its response, the attacker can force the kernel thread to timeout and return, while the daemon subsequently calls the syscall, triggering the UAF. While `sys_rpctls_syscall` requires `PRIV_NFS_DAEMON`, this is a check on the *caller* (the daemon), not the *victim* (the kernel stack). The daemon is a trusted part of the system, but the vulnerability is triggered by the external RPC request that puts the kernel into this state.

CRUX: A pointer to a stack-allocated `struct upsock` is stored in a global RB-tree and dereferenced in `sys_rpctls_syscall` without any mechanism to guarantee the originating thread's stack frame still exists.
GREP: sys_rpctls_syscall

🔎 **Grep results:**

GREP `sys_rpctls_syscall`:
```
sys/sys/sysproto.h:2318:int	sys_rpctls_syscall(struct thread *, struct rpctls_syscall_args *);
lib/libsys/_libsys.h:451:typedef int (__sys_rpctls_syscall_t)(uint64_t);
lib/libsys/_libsys.h:861:int __sys_rpctls_syscall(uint64_t socookie);
sys/rpc/rpcsec_tls/rpctls_impl.c:152:sys_rpctls_syscall(struct thread *td, struct rpctls_syscall_args *uap)
```

### Round 4: ✅ VALID

[ARBITER] The functions `rpctls_connect` and `rpctls_server` allocate `struct upsock` on their local stacks and insert a pointer to these stack-allocated structures into the global `upcall_sockets` RB-tree. The `sys_rpctls_syscall` function later retrieves this pointer and dereferences it (`ups = *upsp`). Because the originating threads (`rpctls_connect`/`rpctls_server`) can return due to RPC timeouts or errors while the entry still exists in the tree (or just before `sys_rpctls_syscall` accesses it), the pointer `upsp` becomes a dangling pointer to a destroyed stack frame. This is a classic Stack-Use-After-Return / Use-After-Free vulnerability. The code even contains a comment acknowledging that the mounting thread may 'unroll its stack,' yet it fails to implement any synchronization or heap-allocation strategy to prevent the race.

