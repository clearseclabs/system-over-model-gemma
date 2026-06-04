# Triage T0026: Unchecked integer overflow can under‑allocate the serialization buffer in clnt_nl_call

- **File**: `clnt_nl.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

Unchecked integer overflow can under‑allocate the serialization buffer in clnt_nl_call

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The length of the serialization buffer is calculated in a 32‑bit integer (`uint32_t len`) using 32‑bit values `nl->nl_mpos`, `nl->nl_authlen` and the 64‑bit `size_t` result of `m_length(args,NULL)`. If the sum exceeds 0xFFFFFFFF, the value wraps to a small number that the code subsequently uses for `malloc`. The XDR memory ops (`xdrmem_putbytes`, `xdrmem_putint32`, and `AUTH_MARSHALL`) do not perform bounds‑checking and simply write to the buffer, so an overflow writes beyond the end of the allocated chunk, corrupting kernel heap and enabling arbitrary code execution with kernel privileges. Hence the reported unchecked integer overflow is a valid kernel‑space vulnerability. 

