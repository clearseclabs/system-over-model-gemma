# Triage T0086: ummary of Findings

- **File**: `rpcb_prot.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

ummary of Findings

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** The loop in xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr continues as long as the XDR stream provides TRUE for more_elements, with no upper limit on the number of elements allocated via xdr_reference.

The reported vulnerability describes an unbounded memory allocation in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr`. In XDR, lists are encoded as a sequence of booleans. If the boolean is TRUE, an element follows. The provided code uses a `for(;;)` loop that continues as long as `more_elements` is TRUE. Inside the loop, `xdr_reference` is called, which typically allocates memory for the element (via the `XDR_DECODE` operation). Because there is no counter or limit on the number of elements processed from the network stream, a remote attacker can send a stream of TRUE booleans and corresponding elements to exhaust system memory. The 'Medium' finding (NULL pointer dereference) is likely a code quality issue or internal API misuse, as `rp` is typically a pointer to a pointer provided by the XDR framework, but the 'High' finding is a classic XDR resource exhaustion pattern. The strings are bounded by `RPC_MAXDATASIZE`, but the number of elements in the list is not.

CRUX: The loop in xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr continues as long as the XDR stream provides TRUE for more_elements, with no upper limit on the number of elements allocated via xdr_reference.
GREP: xdr_reference

🔎 **Grep results:**

GREP `xdr_reference`:
```
(no matches in repo)
```

### Round 2: ✅ VALID

**🎯 Crux:** xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr use a while(TRUE) loop based on network input (xdr_bool) to call xdr_reference (which allocates memory) without any limit on the number of elements.

The report identifies a potential DoS via unbounded memory allocation in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr`. In these functions, the `for(;;)` loop depends on `xdr_bool` returning `more_elements = TRUE`. If the operation is `XDR_DECODE`, `xdr_reference` is called. In XDR implementations, `xdr_reference` typically allocates memory for the object being deserialized. Since there is no counter limiting the number of iterations, a remote attacker can send a stream of 'TRUE' booleans to force the system to allocate an arbitrary number of `RPCBLIST` or `rpcb_entry_list` structures, leading to memory exhaustion (DoS). The NULL pointer dereference reported is likely an internal API contract issue (the caller provides the address of a pointer), but the unbounded list allocation is a classic XDR vulnerability. The lack of a loop counter or a maximum element limit makes this reachable and impactful.

CRUX: xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr use a while(TRUE) loop based on network input (xdr_bool) to call xdr_reference (which allocates memory) without any limit on the number of elements.
GREP: xdr_reference

🔎 **Grep results:**

GREP `xdr_reference`:
```
(no matches in repo)
```

### Round 3: ✅ VALID

**🎯 Crux:** xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr loop indefinitely based on network-supplied booleans, calling xdr_reference to allocate memory for each element without any upper bound on the number of elements.

The vulnerability report identifies an unbounded memory allocation in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr`. Looking at the code, both functions use a `for(;;)` loop that continues as long as `xdr_bool` returns `TRUE` (indicating `more_elements`). Inside this loop, `xdr_reference` is called. In the context of `XDR_DECODE` (which is the operation used when receiving data from the network), `xdr_reference` is responsible for allocating memory for the object being deserialized (either `RPCBLIST` or `rpcb_entry_list`) and then calling the provided XDR procedure (`xdr_rpcb` or `xdr_rpcb_entry`) to fill it. There is no counter, limit, or check on the number of iterations the loop can perform. Since the `XDR *xdrs` stream comes from an untrusted network source, an attacker can send a continuous stream of 'TRUE' booleans to force the system to allocate memory until it is exhausted, resulting in a Denial of Service (DoS). The reported NULL pointer dereference is likely an internal API contract issue (where `rp` is the address of a pointer), but the memory exhaustion is a clear, reachable security vulnerability. The strings are bounded by `RPC_MAXDATASIZE`, but the number of structures is not.

CRUX: xdr_rpcblist_ptr and xdr_rpcb_entry_list_ptr loop indefinitely based on network-supplied booleans, calling xdr_reference to allocate memory for each element without any upper bound on the number of elements.
GREP: xdr_reference

🔎 **Grep results:**

GREP `xdr_reference`:
```
(no matches in repo)
```

### Round 4: ✅ VALID

[ARBITER] The functions `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` implement XDR list deserialization using a `for(;;)` loop. The loop continues as long as `xdr_bool(xdrs, &more_elements)` returns TRUE. Inside the loop, `xdr_reference` is called, which performs memory allocation for the list element during `XDR_DECODE` operations. There is no counter or upper bound on the number of elements that can be processed from the network stream, allowing a remote attacker to exhaust system memory by sending a stream of TRUE booleans, leading to a Denial of Service (DoS).

