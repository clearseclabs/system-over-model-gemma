# Triage T0044: Potential Memory Exhaustion via Unbounded Linked List

- **File**: `pmap_prot.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UII→I]

---

## Finding

Potential Memory Exhaustion via Unbounded Linked List

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Does the implementation of xdr_pmaplist enforce a limit on the number of elements it allocates when deserializing a pmaplist from the network?

The reported vulnerability concerns memory exhaustion via an unbounded linked list during XDR deserialization of `struct pmaplist`. In the provided header `pmap_prot.h`, `xdr_pmaplist` is declared as the function responsible for deserializing this structure. In RPC XDR implementations, linked lists are typically deserialized by reading an element and then recursively or iteratively calling the deserializer for the next element until a NULL terminator is reached. If `xdr_pmaplist` does not implement a maximum count or a size limit on the number of elements it will allocate from the network stream, a remote attacker can send a specially crafted XDR stream that causes the server to allocate an arbitrary number of `struct pmaplist` nodes, leading to heap exhaustion (DoS). I need to examine the implementation of `xdr_pmaplist` to see if it enforces any bounds on the number of elements.

CRUX: Does the implementation of xdr_pmaplist enforce a limit on the number of elements it allocates when deserializing a pmaplist from the network?
GREP: xdr_pmaplist

🔎 **Grep results:**

GREP `xdr_pmaplist`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `pmaplist` structure is returned by the server (PMAPPROC_DUMP) to the client; the server does not deserialize `pmaplist` from network input, making server-side memory exhaustion via this path impossible.

The reported vulnerability claims that `xdr_pmaplist` can be used by a remote attacker to cause memory exhaustion via an unbounded linked list. However, the provided security context and the protocol definition in `pmap_prot.h` show that `PMAPPROC_DUMP` is the procedure that RETURNS a `struct pmaplist *`. In RPC, the server returns the result of `PMAPPROC_DUMP` to the client. Deserialization (`xdr_pmaplist`) would occur on the *client* side when receiving the list from the server, not on the server side. While a malicious server could crash a client, the vulnerability report describes a remote attacker causing DoS, which typically implies attacking the server. The server-side implementation of `PMAPPROC_DUMP` would *serialize* the list, not deserialize it. There is no evidence in the provided header that the server ever deserializes a `pmaplist` from an untrusted network source; it only sends them. Therefore, the bug pattern as applied to the server is not reachable.

CRUX: The `pmaplist` structure is returned by the server (PMAPPROC_DUMP) to the client; the server does not deserialize `pmaplist` from network input, making server-side memory exhaustion via this path impossible.
GREP: PMAPPROC_DUMP

🔎 **Grep results:**

GREP `PMAPPROC_DUMP`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The pmaplist structure is defined as a return value for PMAPPROC_DUMP; the server serializes it for the client and does not deserialize it from network input.

The vulnerability report claims that deserializing a `pmaplist` from the network can lead to memory exhaustion. To determine if this is valid, we must identify if the server ever calls `xdr_pmaplist` on untrusted input. Looking at the protocol definition in `pmap_prot.h`, `PMAPPROC_DUMP` is the only procedure associated with `pmaplist`, and it is explicitly defined as returning a `struct pmaplist *`. In RPC, if a procedure 'RETURNS' a type, the server serializes it and the client deserializes it. For an attacker to trigger memory exhaustion on the server, the server would need to 'take' a `pmaplist` as an argument. Reviewing the procedures: `PMAPPROC_SET`, `PMAPPROC_UNSET`, and `PMAPPROC_GETPORT` take a `struct portmap` (a fixed-size structure), and `PMAPPROC_CALLIT` takes integers and a string. None of the server-side procedures accept a `pmaplist` as input. Therefore, the server does not deserialize `pmaplist` structures from the network, making the reported memory exhaustion attack unreachable on the server.

CRUX: The pmaplist structure is defined as a return value for PMAPPROC_DUMP; the server serializes it for the client and does not deserialize it from network input.
GREP: xdr_pmaplist

🔎 **Grep results:**

GREP `xdr_pmaplist`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The evidence demonstrates that `struct pmaplist` is used exclusively as a return value for the `PMAPPROC_DUMP` procedure. In the RPC architecture, the server serializes the return value and the client deserializes it. For a remote attacker to cause memory exhaustion on the server, the server would need to deserialize a `pmaplist` sent by the client. Since no such procedure exists in the protocol definition (`pmap_prot.h`), the server never calls `xdr_pmaplist` on untrusted network input.

