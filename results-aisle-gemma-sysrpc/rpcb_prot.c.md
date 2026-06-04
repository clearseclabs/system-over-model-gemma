# Scan: rpcb_prot.c

### Security Analysis of `rpcb_prot.c`

The analyzed file `rpcb_prot.c` provides XDR (External Data Representation) serialization and deserialization routines for the RPC binder. The primary attack surface consists of functions that process data received from the network (`XDR_DECODE` operation).

#### 1. Memory Exhaustion (DoS) via Linked Lists
The functions `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` implement deserialization for linked lists. 
*   **Mechanism:** These functions use a `for(;;)` loop that continues as long as the XDR stream provides a `TRUE` value for `more_elements` (via `xdr_bool`).
*   **Vulnerability:** There is no upper bound on the number of elements an attacker can specify in the network stream. For every `TRUE` boolean, `xdr_reference` is called, which typically allocates memory for a new list node (`RPCBLIST` or `rpcb_entry_list`) and then calls the element's XDR routine.
*   **Impact:** An attacker can send a crafted XDR stream containing thousands of "TRUE" flags, forcing the server to allocate massive amounts of memory, leading to heap exhaustion and a Denial of Service (DoS).

#### 2. Potential NULL Pointer Dereferences
Both list-processing functions (`xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr`) begin with:
`more_elements = (bool_t)(*rp != NULL);`
*   **Risk:** If the caller passes a NULL pointer for `rp` itself (rather than `*rp` being NULL), the program will crash immediately upon dereferencing `*rp`. While this depends on the caller's implementation, these are public API functions.

#### 3. String Handling and Buffer Overflows
The code repeatedly calls `xdr_string(xdrs, &objp->..., RPC_MAXDATASIZE)`.
*   **Analysis:** The security of these calls depends entirely on the implementation of `xdr_string`. If `xdr_string` correctly respects the `RPC_MAXDATASIZE` limit and ensures null-termination within that bound, this is safe. However, if `xdr_string` allocates memory based on the length provided in the XDR stream *before* checking it against the limit, or if it fails to null-terminate, it could lead to heap overflows or read-out-of-bounds.
*   **Context:** Given `RPC_MAXDATASIZE` is 9000 (per grep results), an attacker can force the allocation of 9KB strings for multiple fields in a single `RPCB` object (netid, addr, owner), compounding the memory exhaustion issue identified in point 1.

#### 4. Logic Analysis of `XDR_FREE` path
The logic for `freeing` in `xdr_rpcblist_ptr` is complex:
```c
if (freeing && *rp)
    next = (*rp)->rpcb_next;
...
if (freeing && *rp) {
    next_copy = next;
    rp = &next_copy;
}
```
While this is intended to avoid "use-after-free" during the recursive cleanup of the list, the manual manipulation of the pointer `rp` to point to a local stack variable (`&next_copy`) is fragile. If the logic in `xdr_reference` (which is called with `rp`) does not handle the pointer update exactly as expected for the `XDR_FREE` operation, it could lead to memory leaks or double-frees.

### Summary of Findings

| Severity | Title | Function | Description |
| :--- | :--- | :--- | :--- |
| **High** | Unbounded Memory Allocation (DoS) | `xdr_rpcblist_ptr`, `xdr_rpcb_entry_list_ptr` | No limit on the number of list elements processed from the network stream, allowing an attacker to exhaust system memory. |
| **Medium** | Potential NULL Pointer Dereference | `xdr_rpcblist_ptr`, `xdr_rpcb_entry_list_ptr` | The functions dereference the `rp` pointer immediately without verifying if the pointer to the list head is itself NULL. |
| **Low** | Resource Exhaustion via Large Strings | `xdr_rpcb`, `xdr_rpcb_entry` | Multiple strings per object can be up to 9000 bytes each, facilitating rapid memory consumption. |

```json
[
  {
    "severity": "high",
    "title": "Unbounded Memory Allocation in XDR List Deserialization",
    "function": "xdr_rpcblist_ptr(), xdr_rpcb_entry_list_ptr()",
    "description": "The functions process linked lists from the XDR stream using a loop that continues as long as the stream indicates more elements. Because there is no maximum limit on the number of elements, a remote attacker can send a specially crafted stream to force excessive memory allocations, leading to a Denial of Service (DoS)."
  },
  {
    "severity": "medium",
    "title": "NULL Pointer Dereference in List Pointer Access",
    "function": "xdr_rpcblist_ptr(), xdr_rpcb_entry_list_ptr()",
    "description": "The functions dereference the input pointer 'rp' (via '*rp') at the start of the loop without checking if 'rp' itself is NULL. If called with a NULL argument, this will cause a kernel panic or application crash."
  }
]
```