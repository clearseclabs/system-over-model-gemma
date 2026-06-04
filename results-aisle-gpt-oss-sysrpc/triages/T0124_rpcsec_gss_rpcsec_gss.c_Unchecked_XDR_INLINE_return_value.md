# Triage T0124: Unchecked XDR_INLINE return value

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

Unchecked XDR_INLINE return value

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code assigns the result of XDR_INLINE to rpcbuf.value without checking for NULL. XDR_INLINE returns NULL when the XDR stream is not contiguous (as is common with mbuf‑based XDR streams). rpcbuf.length is set to the encoded length before the inline call, so when XDR_INLINE returns NULL the buffer structure contains a non‑zero length and a NULL pointer. This rpcbuf is then passed to gss_get_mic. The GSS API expects a valid pointer when length > 0; if it does not perform a NULL check it will dereference the NULL pointer, causing a crash of the kernel’s GSS library. Thus the code contains a real unchecked null‑pointer dereference that can be triggered via a non‑contiguous XDR stream, making the vulnerability valid. 

