# Triage T0079: ecurity Analysis of `rpcb_prot.c`

- **File**: `rpcb_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

ecurity Analysis of `rpcb_prot.c`

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The pointer `rp` is an address of a pointer variable provided by the caller; network input controls the content of the memory at `*rp`, not the value of `rp` itself.

The report suggests a potential NULL dereference in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` if the initial `rp` argument is NULL. However, the `rp` argument is a pointer to a pointer (`rpcblist_ptr *rp`). In C, when these XDR functions are called, the caller passes the address of a pointer variable (e.g., `&my_list`). The expression `*rp` then dereferences that address to access the pointer variable itself. For `rp` to be NULL, the caller would have to pass a literal `NULL` as the argument. In the context of XDR routines, the `XDR` framework and the generated/hand-written wrappers pass the address of a local or heap-allocated pointer. A NULL `rp` would be a programmer error in the caller, not a result of untrusted network input. The network input controls the value *pointed to* by `*rp` (via `xdr_bool` and `xdr_reference`), but not the address of the pointer variable `rp` itself. Therefore, this is not an attacker-reachable vulnerability.

CRUX: The pointer `rp` is an address of a pointer variable provided by the caller; network input controls the content of the memory at `*rp`, not the value of `rp` itself.
GREP: xdr_rpcblist_ptr

🔎 **Grep results:**

GREP `xdr_rpcblist_ptr`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The argument `rp` is a pointer to a pointer provided by the internal caller; untrusted network input controls the values decoded *via* `rp`, not the value of `rp` itself.

The reported vulnerability focuses on a potential NULL dereference of the `rp` argument in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr`. These functions are XDR deserialization routines. In C, XDR routines that handle pointers or lists typically take the address of a pointer (e.g., `Type **ptr`) so they can allocate memory and update the caller's pointer. For the bug to be security-relevant, an attacker must be able to force `rp` itself to be NULL. However, `rp` is provided by the internal caller (the RPC service logic), not read from the network stream. The network input controls the *data* that is decoded into the memory pointed to by `rp` (specifically, the `more_elements` boolean and the subsequent object data), but it cannot change the address of the pointer variable passed as an argument. A NULL `rp` would be a developer error in the internal codebase, not an attacker-controlled input. Therefore, it is not a security vulnerability.

CRUX: The argument `rp` is a pointer to a pointer provided by the internal caller; untrusted network input controls the values decoded *via* `rp`, not the value of `rp` itself.
GREP: xdr_rpcblist_ptr

🔎 **Grep results:**

GREP `xdr_rpcblist_ptr`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The pointer `rp` is an address provided by the internal caller, not a value derived from network input; therefore, an attacker cannot force it to be NULL.

The reported vulnerability claims a NULL dereference in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr` if the argument `rp` is NULL. As noted by previous reviewers, `rp` is a pointer to a pointer (`rpcblist_ptr *rp`). In the XDR framework, this argument is provided by the internal caller as the address of a local or heap-allocated pointer variable (e.g., `&list_ptr`). The data coming from the network stream controls the values *stored* at that address (through `xdr_bool` and `xdr_reference`), but the network input cannot control the value of the `rp` pointer itself. For `rp` to be NULL, the internal caller would have to pass `NULL` explicitly, which is a developer error (code quality issue) and not an attacker-triggered event. Since the attacker cannot influence the value of `rp`, they cannot trigger a NULL dereference at `*rp`.

CRUX: The pointer `rp` is an address provided by the internal caller, not a value derived from network input; therefore, an attacker cannot force it to be NULL.
GREP: xdr_rpcblist_ptr

🔎 **Grep results:**

GREP `xdr_rpcblist_ptr`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability claims a NULL dereference of the `rp` argument in `xdr_rpcblist_ptr` and `xdr_rpcb_entry_list_ptr`. However, `rp` is a pointer to a pointer provided by the internal caller (e.g., the address of a local pointer variable). The network input controls the data being decoded and stored *at* the address `rp`, but it cannot control the value of the `rp` pointer itself. For `rp` to be NULL, the internal C code calling these functions would have to explicitly pass NULL, which is not a result of external attacker input. Therefore, this is not a security vulnerability.

