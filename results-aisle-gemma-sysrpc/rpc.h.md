# Scan: rpc.h

### Security Analysis

The provided file, `rpc.h`, is a master header file. As per the security context provided, it contains no executable logic, only macro definitions, type inclusions, and function prototypes. Therefore, there are no traditional "bugs" (like buffer overflows or null pointer dereferences) within this specific file.

However, from a security researcher's perspective, this header defines the **attack surface** and **contract** for the entire RPC subsystem. I have analyzed the declarations to identify potential systemic risks that could be exploited in the accompanying implementation files.

#### 1. The `UDPMSGSIZE` Constraint
The header defines `#define UDPMSGSIZE 8800`. 
This value is used as a fixed-size array parameter in the `registerrpc` callback:
`char *(*)(char [UDPMSGSIZE])`

**Security Risk:** This establishes a rigid boundary for network packets. If the implementation of the server-side dispatcher (likely in `svc.c`) fails to strictly enforce that incoming UDP packets are $\le 8800$ bytes before passing them to the registered callback, a stack or heap overflow will occur in the callback function. An attacker can trigger this by sending a jumbo UDP frame.

#### 2. `callrpc` and Untrusted Data
The prototype `extern int callrpc(..., xdrproc_t, void *, xdrproc_t, void *);` handles the serialization and deserialization of data via `xdrproc_t` functions.

**Security Risk:** The vulnerability surface here is shifted to the `xdrproc_t` (XDR procedure) implementations. If a client calls an RPC service and the server's XDR decoder does not validate lengths or tags (as mentioned in the security context regarding tagged unions), this function will facilitate the delivery of malicious payloads into the application's internal memory.

#### 3. Address Conversion Functions
The functions `taddr2uaddr` and `uaddr2taddr` handle conversions between `netconfig`/`netbuf` structures and string representations.

**Security Risk:** Since these functions handle network addresses, they are prime targets for:
* **Buffer Overflows:** If the destination string buffer for `taddr2uaddr` is not sized correctly based on the input address type (e.g., IPv4 vs IPv6).
* **NULL Dereferences:** If the `netconfig` or `netbuf` pointers are passed as NULL from a failed lookup.

#### 4. Internal API Visibility
The header explicitly lists several `__rpc_` prefixed functions as "internal library and rpcbind use only." 

**Security Risk:** While marked internal, these are exported symbols in the resulting binary. If an attacker can achieve partial code execution or use a gadget-based attack (ROP), these internal functions (which likely bypass high-level validation) provide a secondary attack surface to manipulate socket info and file descriptors.

### Findings

Since this is a header file, no actionable code-level vulnerabilities exist within the source provided. However, based on the interface definitions, the following architectural risks are identified:

```json
[
  {
    "severity": "high",
    "title": "Potential Buffer Overflow in registerrpc Callback",
    "function": "registerrpc()",
    "description": "The API defines a fixed-size buffer of UDPMSGSIZE (8800). If the transport layer does not strictly enforce this limit before invoking the callback, any incoming packet larger than 8800 bytes will cause a buffer overflow in the handler."
  },
  {
    "severity": "medium",
    "title": "Risk of Type Confusion in XDR Deserialization",
    "function": "callrpc()",
    "description": "The interface relies on xdrproc_t functions for data handling. If the implementations of these XDR procedures do not validate type tags for unions or length fields for arrays, it will lead to memory corruption or out-of-bounds reads/writes."
  }
]
```