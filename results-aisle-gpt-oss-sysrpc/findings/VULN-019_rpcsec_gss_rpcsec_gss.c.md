# VULN-019: Unchecked XDR_INLINE return value

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Unchecked XDR_INLINE return value

The code assigns `rpcbuf.value = XDR_INLINE(xdrs, rpcbuf.length)` without checking if the result is NULL.  If the XDR stream is not contiguous, `XDR_INLINE` returns NULL and `rpcbuf.value` becomes NULL while `rpcbuf.length` remains non‑zero.  Passing this to `gss_get_mic` can lead to a NULL‑pointer dereference inside the GSS library, potentially causing a crash.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code assigns the result of XDR_INLINE to rpcbuf.value without checking for NULL. XDR_INLINE returns NULL when the XDR stream is not contiguous (as is common with mbuf‑based XDR streams). rpcbuf.length is set to the encoded length before the inline call, so when XDR_INLINE returns NULL the buffer structure contains a non‑zero length and a NULL pointer. This rpcbuf is then passed to gss_get_mic. The GSS API expects a valid pointer when length > 0; if it does not perform a NULL check it will dereference the NULL pointer, causing a crash of the kernel’s GSS library. Thus the code contains a real unchecked null‑pointer dereference that can be triggered via a non‑contiguous XDR stream, making the vulnerability valid. 

