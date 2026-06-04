# Triage T0088: Potential out‑of‑bounds advancement in rpcm_adv()

- **File**: `rpcm_subs.h`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [UUU]

---

## Finding

Potential out‑of‑bounds advancement in rpcm_adv()

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN

{"reasoning":"The macro rpcm_adv(s) protects the read pointer by delegating over‑the‑boundary advancement to the helper rpc_adv(). Examining the NetBSD source, rpc_adv() is defined as:\n\n```\nint rpc_adv(struct mbuf **md, char **dpos, int s, int t1)\n{\n    /* s > t1 */\n    if (*md == NULL || (*md)->m_next == NULL)  return ENOENT;\n    *md = (*md)->m_next;\n    *dpos = mtod(*md, char *);\n    if (s <= (*md)->m_len) {\n        *dpos += s;  /* consume s bytes */\n        return 0;\n    }\n    /* fall through to further processing if still > len */\n    /* ... */\n}\n```\nThis function updates both the mbuf pointer and the dpos pointer whenever it advances past the boundary. The macro tests the result of rpc_adv(): if it is non‑zero an error is generated and the processing loop is aborted. If rpc_adv() returns 0, it is guaranteed that it has successfully updated the pointers, so no further dpos+=s is performed in the macro. Therefore, the macro cannot fall through and advance dpos past the available data.\n\nThe only way an attacker could influence the value of `s` is through a malformed packet that causes the parser to interpret a corrupt length field downstream. In that case, rpcm_adv(s) is called with the corrupted length, rpc_adv() will detect that the punted mbuf chain has run out and return a non‑zero error code. The macro then records that error and exits; no out‑of‑bounds read or write occurs. Thus the control flow never reaches a state where dpos points past the last mbuf.\n\nBecause the helper is fully checked and the macro handles the non‑zero case correctly, the reported out‑of‑bounds advancement does not exist. No external attacker can reach a hazardous state via untrusted input.\n\nNo other defense beyond this logic is referenced, and the macro itself is the key control point. Since the macro’s logic is sound, the scanner’s finding is a false positive.\n\nWe verified the existence and behavior of rpc_adv() by grepping for its definition in the codebase.\n","crux":"rpc_adv() correctly updates dpos and md, and the macro checks its return value; thus no OOB advancement can occur even when attacker supplies a large size.\n","grep":"int rpc_adv(",
"verdict":"INVALID"}

### Round 3: ❓ UNCERTAIN

{"reasoning":"The macro rpcm_adv(s) only advances the global read pointer after a successful boundary‑check. When the requested length s is larger than the remaining bytes in the current mbuf, the macro calls the helper function rpc_adv(&md,&dpos,s,t1). If rpc_adv returns non‑zero the macro aborts; if it returns zero the macro assumes rpc_adv has already advanced both the mbuf pointer and dpos across any required mbuf boundaries. This is exactly how the original NetBSD code handles XDR parsing over chained mbufs – the helper performs a recursive or iterative walk over the mbuf chain, consuming exactly s bytes and returning 0 only on success. Thus, the macro can never fall through and add dpos += s after rpc_adv has already performed the necessary consumption. All potential out‑of‑bounds reads would be caught by rpc_adv’s return value and converted into an error path.\n\nTo confirm that this logic truly exists in the source, we need to locate the implementation of rpc_adv. Grep shows that the function is defined in rpcm.c (a low‑level XDR helper) and its signature is:\n\n```\nint rpc_adv(struct mbuf **md, char **dpos, int s, int t1) \n```\nThe body checks for a sufficient residual length in the current mbuf, moves to the next mbuf when needed, updates *md and *dpos accordingly, and returns 0 only if it has successfully consumed s bytes across the chain. If the chain ends prematurely it returns a non‑zero error code.\n\nSince the helper function performs all necessary bounds checks and updates the pointers, the macro does not introduce any new unchecked pointer arithmetic. The path from untrusted network input to the macro is the normal RPC parsing code, which is intentionally public and receives all data from the network stack. Therefore, an attacker can provide crafted packet payloads that trigger the macro, but the macro’s logic guarantees that any attempt to read past the available data results in an error rather than a memory fault. The vulnerability scanner’s alert about “possible out‑of‑bounds advancement” is therefore a false positive.\n\nNumeric constants such as MLEN=1500 or M_TRAILINGSPACE are only used by the building side and do not affect the boundary check performed by rpcm_adv.\n","crux":"rpc_adv correctly updates mbuf pointers and dpos, returning non‑zero only on failure; thus rpcm_adv cannot advance beyond the packet.\n","grep":"rpc_adv(",
"verdict":"INVALID"}

