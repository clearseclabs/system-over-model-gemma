# Context: pmap_prot.h

This is a context briefing for `pmap_prot.h`, which defines the protocol for the RPC portmapper (pmap) service.

**1. Role & Location**
This is a header file defining the interface and data structures for the local binder service (`pmap`). It sits within the RPC subsystem, providing the constants and structures used by both the server (which manages the port registry) and clients.

**2. Untrusted Input Path**
Untrusted input reaches this code via the network (UDP/TCP port 111). Remote clients send RPC requests that are deserialized using XDR (External Data Representation) into the structures defined here.

**3. Attacker-Controlled Data**
Data enters via `xdr_portmap` and `xdr_pmaplist`.
*   `struct portmap`: All fields (`pm_prog`, `pm_vers`, `pm_prot`, `pm_port`) are attacker-controlled.
*   `struct pmaplist`: The `pml_map` fields and the linked-list structure are controlled via the XDR stream.

**4. Fixed-Size Buffers & Constants**
There are no fixed-size arrays/buffers defined in this header.
*   `PMAPPORT`: 111
*   `PMAPPROG`: 100000
*   `PMAPVERS`: 2

**5. Dangerous Data Flows**
Attacker-controlled `struct portmap` values $\rightarrow$ used as keys or values in the internal port registry lookup table (implementation handled in `.c` files).

**6. NULL Dereferences**
`struct pmaplist *pml_next` is a pointer. If the XDR deserialization logic fails to properly terminate or validate the list, the service may dereference a null or malformed pointer during list traversal.

**7. Tagged Unions**
None present in this header.

**8. API Scope**
*   **Public API:** `xdr_portmap`, `xdr_pmaplist`, and `xdr_pmaplist_ptr` are exported for use by the RPC XDR engine.

**9. Likely Bug Classes**
*   **Integer Overflows/Underflows:** Manipulation of `pm_port` or `pm_prog` values.
*   **Memory Exhaustion:** The `pmaplist` is a linked list; a malformed XDR stream could trigger an allocation loop (DoS).
*   **Logic Errors:** Improper validation of `PMAPPROC_` constants leading to unexpected function execution.