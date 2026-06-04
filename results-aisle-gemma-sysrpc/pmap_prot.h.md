# Scan: pmap_prot.h

### Security Analysis of `pmap_prot.h`

This file is a protocol definition header. It contains constants, data structures, and function prototypes used for the RPC portmapper (`pmap`) service. Because it is a header file, it contains no executable logic; however, the definitions here dictate how the XDR (External Data Representation) engine deserializes untrusted network data into memory, which creates the attack surface for the implementation files (`.c`).

#### 1. Data Structure Analysis

**`struct portmap`**
*   **Fields:** `pm_prog`, `pm_vers`, `pm_prot`, `pm_port` (all `long unsigned`).
*   **Risk:** These are all attacker-controlled via XDR. The `pm_port` field is particularly sensitive. If the implementation uses this value as an index into a table or passes it directly to socket system calls without validating that it falls within the valid port range (1-65535), it could lead to logic errors or resource exhaustion.

**`struct pmaplist`**
*   **Fields:** `pml_map` (embedded struct), `pml_next` (pointer to next element).
*   **Risk:** This is a linked-list structure. In XDR, linked lists are typically encoded as a sequence of elements terminated by a null pointer.
*   **Memory Exhaustion (DoS):** An attacker can craft an XDR stream that specifies an extremely large number of `pmaplist` elements. If the XDR deserializer (`xdr_pmaplist`) allocates memory for each element without a maximum limit or quota, the service will suffer from heap exhaustion (OutOfMemory), leading to a Denial of Service.
*   **Pointer Integrity:** While the XDR engine handles the allocation, any failure in the `xdr_pmaplist` logic that fails to properly null-terminate the `pml_next` pointer could lead to a NULL dereference or a use-after-free during the `DUMP` operation traversal.

#### 2. API and Function Prototypes

**`xdr_portmap`, `xdr_pmaplist`, `xdr_pmaplist_ptr`**
*   These functions are the gateways for untrusted data. The security of the entire `pmap` service depends on the implementation of these functions.
*   `xdr_pmaplist` specifically takes a `struct pmaplist **`, implying it dynamically allocates a list. As noted above, the lack of a specified bound in the protocol definition suggests the implementation must enforce its own limits to prevent DoS.

#### 3. Logic and Protocol Analysis

**`PMAPPROC_CALLIT`**
*   The comments explicitly state: *"This routine only passes null authentication parameters."*
*   **Security Risk:** This indicates a lack of authentication for the `CALLIT` procedure. An attacker can use this to trigger procedures on the local machine via the portmapper, effectively using the portmapper as a proxy to interact with other RPC services that might have assumed they were only receiving local requests.

#### 4. Summary of Findings

The vulnerabilities in this file are "architectural"—they are risks inherent in the data structures that the implementation must mitigate.

1.  **Resource Exhaustion:** The recursive nature of `struct pmaplist` allows an attacker to force arbitrary memory allocations via the `DUMP` or list-receiving XDR routines.
2.  **Lack of Authentication:** `PMAPPROC_CALLIT` is defined to bypass authentication, providing a vector for unauthorized local service interaction.
3.  **Integer Range Validation:** The use of `long unsigned` for ports and programs requires strict validation in the implementation to prevent integer-related logic bugs.

```json
[
  {
    "severity": "high",
    "title": "Potential Memory Exhaustion via Unbounded Linked List",
    "function": "xdr_pmaplist()",
    "description": "The pmaplist structure is a linked list. If the XDR deserialization implementation does not enforce a maximum number of elements when parsing a pmaplist from the network, a remote attacker can cause heap exhaustion and Denial of Service (DoS)."
  },
  {
    "severity": "medium",
    "title": "Unauthenticated Remote Procedure Call Proxy",
    "function": "PMAPPROC_CALLIT",
    "description": "The PMAPPROC_CALLIT procedure is designed to pass null authentication parameters. This allows a remote attacker to trigger RPC procedures on the local machine without authentication, bypassing potential security controls of the target service."
  }
]
```