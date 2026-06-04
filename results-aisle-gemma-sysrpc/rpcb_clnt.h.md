# Scan: rpcb_clnt.h

This analysis examines `rpcb_clnt.h`, the header file defining the client-side interface for the RPC Portmapper.

### Architectural Analysis
As a header file, `rpcb_clnt.h` does not contain executable logic, but it defines the **attack surface** for the RPC client library. The security of the system depends on how the corresponding `.c` implementation handles the parameters defined here, particularly when dealing with data returned from a remote network server.

The primary risk vector is the **Remote Portmapper $\rightarrow$ Local Client** data flow. An attacker controlling a malicious portmapper server can craft XDR (External Data Representation) responses designed to trigger vulnerabilities in the functions declared in this header.

### Function-by-Function Analysis

#### 1. `rpcb_getmaps(const struct netconfig *, const char *)`
*   **Untrusted Input:** The `char *` (host) is used to connect to a remote server. The return value `rpcblist *` is populated by data sent from that remote server.
*   **Potential Vulnerabilities:** 
    *   **Integer Overflow/Heap Overflow:** The `rpcblist` structure likely contains a list of mappings. If the remote server claims to send a very large number of mappings, the implementation may suffer from an integer overflow when calculating the memory allocation size for the list.
    *   **Memory Leak:** If the client fails to properly free the `rpcblist` on error or after use, a malicious server could cause a Denial of Service (DoS) via memory exhaustion.

#### 2. `rpcb_rmtcall(...)`
*   **Untrusted Input:** This is a generic wrapper for remote calls. The `const caddr_t resp` parameter is the buffer where the remote server's response is written.
*   **Potential Vulnerabilities:**
    *   **Buffer Overflow:** The header does not specify how the size of `resp` is communicated to the function. If the implementation assumes a fixed size or relies on the remote server to specify the response length without validation, a heap or stack overflow is possible.
    *   **XDR Decoding Errors:** Since this function uses `xdrproc_t` for decoding, any vulnerability in the XDR decoding engine (e.g., handling of deeply nested arrays or oversized strings) can be triggered here.

#### 3. `rpcb_getaddr(...)`
*   **Untrusted Input:** Takes a `struct netbuf *` as an output parameter.
*   **Potential Vulnerabilities:**
    *   **Buffer Overrun:** `struct netbuf` is used to store network addresses. If the remote server returns an address format that is larger than the expected `netbuf` structure or the internal buffer it points to, it could lead to memory corruption.

#### 4. `rpcb_uaddr2taddr(struct netconfig *, char *)` and `rpcb_taddr2uaddr(...)`
*   **Untrusted Input:** The `char *` (uaddr) in `rpcb_uaddr2taddr` is likely a string representation of a network address.
*   **Potential Vulnerabilities:**
    *   **Format String/Injection:** If the `char *` is passed to logging functions (like `printf`) or system calls without sanitization.
    *   **NULL Dereference:** If these functions are called with the result of a failed `rpcb_getaddr` call without checking for NULL.

### Summary of Risks

| Function | Risk Class | Trigger | Impact |
| :--- | :--- | :--- | :--- |
| `rpcb_getmaps` | Heap Overflow | Malformed `rpcblist` count from server | RCE / Crash |
| `rpcb_rmtcall` | Buffer Overflow | Oversized XDR response from server | RCE / Crash |
| `rpcb_getaddr` | Memory Corruption | Non-standard address length from server | RCE / Crash |
| `rpcb_uaddr2taddr`| NULL Deref | Passing NULL `char *` input | DoS |

### Findings

Since this is a header file, the "bugs" are theoretical risks inherent in the API design that must be mitigated in the implementation.

```json
[
  {
    "severity": "high",
    "title": "Potential Heap Overflow in rpcblist allocation",
    "function": "rpcb_getmaps",
    "description": "The function returns an rpcblist pointer populated by a remote server. If the implementation fails to validate the number of entries returned by the server before allocating memory, an integer overflow could lead to a heap-based buffer overflow."
  },
  {
    "severity": "high",
    "title": "Unbounded Response Buffer in rpcb_rmtcall",
    "function": "rpcb_rmtcall",
    "description": "The resp parameter is a buffer for remote server data. Without an explicit length parameter passed to the function to bound the XDR decoding process, a malicious server can trigger a buffer overflow by sending more data than the allocated size of resp."
  },
  {
    "severity": "medium",
    "title": "Potential NULL Pointer Dereference in Address Conversion",
    "function": "rpcb_uaddr2taddr",
    "description": "The function accepts a char * input. If the calling application passes a NULL pointer (e.g., a failed result from a previous network call) and the implementation does not validate this input, it will result in a denial-of-service crash."
  }
]
```