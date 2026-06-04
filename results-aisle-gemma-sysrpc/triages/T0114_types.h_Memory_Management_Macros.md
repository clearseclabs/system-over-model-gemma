# Triage T0114: Memory Management Macros

- **File**: `types.h`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Memory Management Macros

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The `bsize` parameter in the `mem_free` macro is ignored, but the underlying `free` implementations (user and kernel) do not require the size for correct memory deallocation.

The scanner is pointing out a discrepancy between the macro signature of `mem_free(ptr, bsize)` and its implementation, which ignores the `bsize` argument. In both the user-land implementation (`free(ptr)`) and the kernel implementation (`free(ptr, M_RPC)`), the size of the allocated block is managed internally by the allocator (the standard `free` in user-land and the NetBSD kernel `free` which tracks size via the `M_RPC` type). Passing an extra argument to a macro that is then ignored by the expanding function call is a code style/quality issue, not a security vulnerability. There is no memory corruption, double-free, or leak caused by the fact that the size is not passed to the underlying `free` function, as these allocators do not require the size for deallocation.

CRUX: The `bsize` parameter in the `mem_free` macro is ignored, but the underlying `free` implementations (user and kernel) do not require the size for correct memory deallocation.
GREP: mem_free

🔎 **Grep results:**

GREP `mem_free`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `bsize` parameter in the `mem_free` macro is ignored, but the underlying allocators (standard libc and NetBSD kernel) do not require the size to safely deallocate memory.

The reported issue is a discrepancy in the `mem_free(ptr, bsize)` macro definition where the `bsize` parameter is ignored by the underlying `free(ptr)` (user-land) or `free(ptr, M_RPC)` (kernel) calls. This is a common pattern in abstraction layers where a consistent interface is maintained across different backends, even if some backends don't require all provided arguments. In both standard C `free()` and the NetBSD kernel `free()`, the size of the memory block is tracked by the allocator metadata, not provided by the caller. Therefore, ignoring the size argument does not lead to memory corruption, leaks, or any other security-relevant behavior. This is a code quality/API design issue, not a security vulnerability.

CRUX: The `bsize` parameter in the `mem_free` macro is ignored, but the underlying allocators (standard libc and NetBSD kernel) do not require the size to safely deallocate memory.
GREP: mem_free

🔎 **Grep results:**

GREP `mem_free`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The underlying memory allocators (libc and NetBSD kernel) do not require the size of the block to perform a safe deallocation, making the unused macro parameter security-irrelevant.

The reported issue is that the `mem_free(ptr, bsize)` macro accepts a size argument that is not used by the underlying `free` calls in either user-land (`free(ptr)`) or kernel-land (`free(ptr, M_RPC)`). In both environments, the allocator tracks the size of the allocation internally; the caller is not required to provide the size to successfully and safely free the memory. Therefore, providing a size argument to the macro that is then ignored by the expansion does not cause memory corruption, leaks, or any other security-relevant failure. This is a purely cosmetic API discrepancy (a code quality issue).

CRUX: The underlying memory allocators (libc and NetBSD kernel) do not require the size of the block to perform a safe deallocation, making the unused macro parameter security-irrelevant.
GREP: mem_free

🔎 **Grep results:**

GREP `mem_free`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported issue is a cosmetic discrepancy in the macro definition. The `mem_free` macro accepts a `bsize` argument but does not use it, passing only the pointer to the underlying `free()` (user-land) or `free(ptr, M_RPC)` (kernel-land) functions. Since both of these allocator implementations track the size of the allocated block internally, the unused `bsize` parameter does not result in memory corruption, leaks, or any other security vulnerability.

