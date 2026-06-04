# Scan: rpcb_prot.h

This is a generated header file (`rpcb_prot.h`) produced by `rpcgen`. In the context of an RPC service, the header defines the "contract" (data structures and function signatures) that the XDR (External Data Representation) engine uses to deserialize network packets into C structures.

Because this is a header file, there is no executable logic (no function bodies) to analyze for traditional bugs like buffer overflows or logic errors. However, the **definitions** within this header dictate the attack surface for the corresponding `.c` implementation files.

### Security Analysis

#### 1. Memory Management and XDR Deserialization
The structures defined here are heavily reliant on pointers to dynamically allocated memory (XDR strings and opaque blobs):
*   **`struct rpcb`**: Contains `char *r_netid`, `char *r_addr`, and `char *r_owner`.
*   **`struct rpcb_rmtcallargs`**: Contains `char *args_val` (or `args_ptr`) and `u_int args_len`.
*   **`struct rpcb_entry`**: Contains multiple `char *` fields.

**Risk**: The security of the service depends entirely on the implementation of the `xdr_*` functions (e.g., `xdr_rpcb`). If the XDR engine does not strictly limit the length of strings or the size of the `args_val` blob provided by the network, the server is vulnerable to **Heap Overflow** or **Denial of Service (Memory Exhaustion)**.

#### 2. Opaque Blob Handling (`rpcb_rmtcallargs`)
The `rpcb_rmtcallargs` structure is particularly dangerous:
```c
struct rpcb_rmtcallargs {
    rpcprog_t prog;
    rpcvers_t vers;
    rpcproc_t proc;
    struct {
        u_int args_len;
        char *args_val;
    } args;
};
```
This structure is used by `RPCBPROC_CALLIT`, `RPCBPROC_BCAST`, and `RPCBPROC_INDIRECT`. It allows an attacker to specify a target program, version, and procedure, and then provide an arbitrary blob of data.
*   **Risk**: This creates a "proxy" mechanism. If the service logic doesn't strictly validate the `prog/vers/proc` triple before forwarding the `args_val` to another service, it can be used to bypass firewalls or trigger vulnerabilities in internal RPC services that are not directly exposed to the network.

#### 3. Integer Type Mismatches
There is a discrepancy between the `_KERNEL` and non-`_KERNEL` definitions of `rpcb_rmtcallargs` and `rpcb_rmtcallres`.
*   In `_KERNEL` sections, `args_len` and `results_len` are `u_int`.
*   In non-`_KERNEL` sections, they are `uint32_t`.

**Risk**: While likely consistent on most platforms, any mismatch in integer width between the XDR decoding layer and the processing layer could lead to **Integer Truncation** or **Signedness bugs**, potentially resulting in undersized buffer allocations followed by oversized `memcpy` operations.

#### 4. Potential for NULL Dereferences
The XDR protocol allows strings to be NULL. In `struct rpcb`, `r_netid`, `r_addr`, and `r_owner` can all be NULL if the network input is malformed.
*   **Risk**: Any function implementing the logic for `rpcbproc_set_3` or `rpcbproc_getaddr_4` must explicitly check these pointers before use.

### Summary of Findings

Since this is a header file, the "findings" are architectural risks that must be mitigated in the implementation.

```json
[
  {
    "severity": "medium",
    "title": "Architectural Risk: Unbounded XDR String Allocation",
    "function": "xdr_rpcb / xdr_rpcb_entry",
    "description": "The protocol defines multiple string pointers (r_netid, r_addr, r_owner). If the corresponding XDR implementation does not enforce maximum length limits on these strings, an attacker can cause excessive memory consumption leading to DoS."
  },
  {
    "severity": "high",
    "title": "Architectural Risk: Remote Procedure Proxying",
    "function": "rpcbproc_callit / rpcbproc_indirect",
    "description": "The rpcb_rmtcallargs structure allows an attacker to specify an arbitrary target program and provide an opaque data blob. This can be used to pivot attacks to internal RPC services if the implementation does not strictly validate the target program/version/procedure."
  },
  {
    "severity": "low",
    "title": "Potential NULL Pointer Dereference",
    "function": "Various rpcbproc_* functions",
    "description": "XDR-decoded strings in struct rpcb and rpcb_entry can be NULL. Implementation must ensure all pointers are validated before dereferencing."
  }
]
```