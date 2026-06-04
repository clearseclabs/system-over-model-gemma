# Scan: rpcb_prot.c

**Security Analysis**

The file implements XDR serialization routines for RPC binder structures. In zero‑day analysis, the focus is on how data read from the network is decoded and how the code handles pointers, memory allocation, and bounds. The code is largely safe because the XDR library performs most low‑level checks. However, there are a few critical gaps that can be triggered by malformed input:

1. **Unconditional Dereference of Pointer Arguments (`rp`)**  
   *Functions*: `xdr_rpcblist_ptr`, `xdr_rpcb_entry_list_ptr`  
   *Issue*: The functions assume that the caller passes a valid pointer to a pointer. Immediately after entry, they compute `more_elements = (bool_t)(*rp != NULL);`. If `rp` itself is `NULL` (which can happen if the caller passes a corrupted pointer, or an attacker forces this via prior memory corruption), the code dereferences a NULL pointer and crashes. This can be used to crash the RPC binder process, yielding a DoS. The function does **not** perform a NULL check on `rp` before dereferencing it.  
   *Severity*: **High** – a crash / DoS can be triggered from malformed RPC payloads that corrupt internal bookkeeping pointers.

2. **Unbounded String Allocation (Potential Memory Exhaustion)**  
   *Functions*: `xdr_rpcb`, `xdr_rpcb_entry`  
   *Issue*: Although `xdr_string` enforces a maximum length of `RPC_MAXDATASIZE` (valid in the NetBSD implementation), the value of `RPC_MAXDATASIZE` must be correctly defined. An attacker could send a string whose declared length is close to this limit. The XDR routine will allocate that amount of memory. If `RPC_MAXDATASIZE` is large enough, repeated requests could exhaust memory, causing the process to swap or OOM kill. This is a **resource exhaustion** issue rather than a classic buffer overflow.  
   *Severity*: **Medium** – mitigated by proper configuration of `RPC_MAXDATASIZE`.

3. **Lack of Return‑Value Checks after `xdr_reference` (Potential Mis‑state)**  
   *Functions*: `xdr_rpcblist_ptr`, `xdr_rpcb_entry_list_ptr`  
   *Issue*: While the code checks the return value of `xdr_reference`, it does not handle the situation where the reference points to a non‑existent (NULL) object in decode mode. If the XDR stream incorrectly indicates that a pointer is present but contains an invalid address, `xdr_reference` will attempt to free or deserialize that memory, potentially leading to undefined behaviour. This is a subtle issue that could be abused if the attacker can influence pointer values via earlier memory corruption.  
   *Severity*: **Low to Medium** – depends on the attacker’s ability to manipulate pointer fields.

4. **Potential Integer Overflow in Size Calculations**  
   *Functions*: `xdr_rpcblist_ptr`, `xdr_rpcb_entry_list_ptr`  
   *Issue*: The size passed to `xdr_reference` is cast to `u_int`. If `sizeof(rpcblist)` or `sizeof(rpcb_entry_list)` ever exceeds `UINT_MAX` (unlikely but conceivable on exotic architectures or with huge struct definitions), the cast could overflow, yielding an incorrect allocation size.  
   *Severity*: **Low** – unlikely in practice.

5. **No Validation of Redirected Structures After Freeing**  
   *Functions*: `xdr_rpcblist_ptr`, `xdr_rpcb_entry_list_ptr`  
   *Issue*: During freeing, the code temporarily stores the next pointer in a local variable and then sets `rp = &next_copy`. While this is valid within the loop, it references a local variable that lives until function exit. An attacker who can prematurely terminate the function via a double‑free or segmentation fault might leave dangling pointers in the caller's data structure, leading to inconsistent state after the function returns.  
   *Severity*: **Low** – not exploitable without additional memory corruption.

**Summary**

The file is largely safe, provided the constants are correctly configured and the XDR library is trusted. The primary exploitable vulnerability is the dereference of a possibly NULL pointer argument, enabling a crash/DoS. The other issues are either mitigated by the XDR API or represent potential resource exhaustion under extreme conditions.

```json
[
  {
    "severity": "High",
    "title": "Null pointer dereference due to unvalidated rp argument",
    "function": "xdr_rpcblist_ptr() and xdr_rpcb_entry_list_ptr()",
    "description": "Both functions immediately dereference the rp pointer without checking if rp itself is NULL. If an attacker can corrupt the rp value (e.g., via prior memory corruption), the code will crash when *rp is accessed. This can be exploited to force the RPC binder to terminate, providing a denial‑of‑service vector."
  },
  {
    "severity": "Medium",
    "title": "Potential memory exhaustion from large RPC strings",
    "function": "xdr_rpcb() and xdr_rpcb_entry()",
    "description": "These routines accept strings up to RPC_MAXDATASIZE. If RPC_MAXDATASIZE is large and attackers send many such requests, the XDR layer will allocate large buffers for each string. This can exhaust system memory or swap, leading to process or system failure."
  },
  {
    "severity": "Low",
    "title": "Possible misuse of pointer during freeing loop",
    "function": "xdr_rpcblist_ptr() and xdr_rpcb_entry_list_ptr()",
    "description": "During freeing, the code stores the next pointer in a local variable and then sets rp = &next_copy. If the function exits prematurely (e.g., due to a double‑free triggered by another vulnerability), the caller’s pointer may be left pointing to a stale local variable, potentially causing inconsistent state after the function returns."
  }
]
```
