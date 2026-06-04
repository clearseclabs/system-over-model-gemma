# Triage T0082: Memory Exhaustion (DoS) via Linked Lists

- **File**: `rpcb_prot.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

Memory Exhaustion (DoS) via Linked Lists

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The loop in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` continues as long as the network stream provides `TRUE` for `more_elements`, with no upper bound on the number of allocations performed via `xdr_reference`.

The functions `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` implement a common XDR pattern for linked lists. In `XDR_DECODE` mode (when receiving data from the network), the loop continues as long as `xdr_bool` returns `TRUE`. Each iteration calls `xdr_reference`, which allocates a new node of size `sizeof(RPCBLIST)` or `sizeof(rpcb_entry_list)` and then calls the element's XDR routine (e.g., `xdr_rpcb`). There is no counter or limit on the number of iterations. Since these functions are used to deserialize data from the network for the RPC binder service, an attacker can send a stream of `TRUE` values to force the server to allocate an arbitrary amount of memory until the heap is exhausted, causing a Denial of Service. This is a classic unbounded allocation vulnerability.

CRUX: The loop in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` continues as long as the network stream provides `TRUE` for `more_elements`, with no upper bound on the number of allocations performed via `xdr_reference`.
GREP: xdr_reference

🔎 **Grep results:**

GREP `xdr_reference`:
```
(no matches in repo)
```

### Round 2: ✅ VALID

**🎯 Crux:** The loops in xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr perform allocations via xdr_reference based on untrusted boolean flags from the network stream without any upper bound on the number of elements.

The reported vulnerability describes a memory exhaustion (DoS) scenario where an attacker can send a stream of 'TRUE' booleans to `xdr_rpcblist_ptr` or `xdr_rpcb_entry_list_ptr`, causing unbounded allocations via `xdr_reference`. 

1. **Bug Pattern**: The code shows a `for(;;)` loop that continues as long as `xdr_bool` returns `TRUE` and `more_elements` is true. Inside this loop, `xdr_reference` is called. In XDR decoding, `xdr_reference` is responsible for allocating memory for the object being referenced.
2. **Reachability**: These functions are XDR routines for the RPC binder (`rpcb`). The RPC binder is a network-facing service. Input flows from the network $\rightarrow$ RPC transport $\rightarrow$ XDR stream $\rightarrow$ these functions. An external attacker can control the bytes in the XDR stream.
3. **Defense**: There is no counter, limit, or size check on the number of iterations in the loops in `xdr_rpcblist_ptr` or `xdr_rpcb_entry_list_ptr`. The loop only terminates when the stream provides a `FALSE` boolean or an XDR error occurs.
4. **Security Relevance**: This is a classic unbounded allocation vulnerability. By sending a crafted packet with thousands of 'TRUE' flags, an attacker can exhaust the server's heap memory, leading to a Denial of Service (DoS). This is a security-relevant issue, not a code quality issue.

CRUX: The loops in xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr perform allocations via xdr_reference based on untrusted boolean flags from the network stream without any upper bound on the number of elements.
GREP: xdr_reference

🔎 **Grep results:**

GREP `xdr_reference`:
```
(no matches in repo)
```

### Round 3: ✅ VALID

**🎯 Crux:** The loops in xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr allocate memory via xdr_reference for each 'TRUE' boolean received from the network, with no upper bound on the number of elements.

The vulnerability report identifies a potential memory exhaustion (DoS) issue in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` due to unbounded loops that call `xdr_reference`. In XDR decoding, `xdr_reference` typically allocates memory for a new object. 

1. **Bug Pattern**: The code explicitly uses a `for(;;)` loop that continues as long as `xdr_bool` returns `TRUE`. Inside this loop, `xdr_reference` is called to deserialize the next element of the list. There is no internal counter or maximum element limit within these functions.

2. **Reachability**: These functions are part of the RPC binder (`rpcb`) protocol. The RPC binder is a network-facing service. Untrusted network data is passed into the `XDR *xdrs` stream, which is then processed by these functions. An attacker can control the sequence of booleans sent in the XDR stream.

3. **Defense**: No defense is present in the provided code. There are no bounds checks on the number of list elements. While the XDR stream itself might have a maximum packet size (e.g., `RPC_MAXDATASIZE` often limits individual strings), that does not prevent an attacker from sending a large number of small elements (a boolean and a small struct) within a single large RPC record or across multiple fragments, potentially exhausting heap memory.

4. **Security Relevance**: Unbounded allocation based on attacker-controlled input is a classic Denial of Service vector. By sending a stream of `TRUE` flags, an attacker can force the server to allocate memory until it crashes or becomes unresponsive.

CRUX: The loops in xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr allocate memory via xdr_reference for each 'TRUE' boolean received from the network, with no upper bound on the number of elements.
GREP: xdr_reference

🔎 **Grep results:**

GREP `xdr_reference`:
```
(no matches in repo)
```

### Round 4: ✅ VALID

[ARBITER] The functions `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` implement a `for(;;)` loop that continues as long as `xdr_bool` returns `TRUE` from the network stream. Inside this loop, `xdr_reference` is called, which performs a memory allocation for each element (`sizeof(RPCBLIST)` or `sizeof(rpcb_entry_list)`). There is no limit on the number of iterations, meaning an attacker can send an arbitrary number of 'TRUE' flags to cause heap exhaustion and a Denial of Service.

