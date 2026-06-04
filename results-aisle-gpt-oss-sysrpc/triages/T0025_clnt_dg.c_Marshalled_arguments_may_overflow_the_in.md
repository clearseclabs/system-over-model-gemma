# Triage T0025: Marshalled arguments may overflow the initial mbuf header in clnt_dg_call()

- **File**: `clnt_dg.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Marshalled arguments may overflow the initial mbuf header in clnt_dg_call()

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The code correctly allocates an initial mbuf header via m_gethdr, then marshals arguments using XDR‑based `xdrmbuf_create`. If the marshalled argument set exceeds MHLEN, the XDR implementation will allocate additional mbufs for the overflow; these are appended to the original chain. The packet length passed to sosend is calculated with `m_length(mreq, NULL)`, which sums over all chain elements, so the header’s `m_len` or the `cu->cu_mcalllen <= MHLEN` check does not truncate the payload. There is no unchecked write beyond the allocated buffer and no inconsistent length value that could overflow socket or kernel buffers. Therefore, the alleged overflow vulnerability is not real in the given code.}

