# VULN-011: Unchecked integer overflow can under‑allocate the serialization buffer in clnt_nl_call

- **File**: `clnt_nl.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Unchecked integer overflow can under‑allocate the serialization buffer in clnt_nl_call

The size of the buffer used for serializing the RPC request is calculated as

    len = nl->nl_mpos + nl->nl_authlen + m_length(args, NULL);

`nl->nl_mpos` and `nl->nl_authlen` are `uint32_t`, and `m_length()` returns a `size_t` (≥32 bits).  If `m_length(args)` is large enough to make the addition wrap around the 32‑bit range, `len` will be a small value.  The code then `malloc`s `len` bytes and proceeds to XDR‑encode the arguments into that buffer.  Since the real number of bytes that will be written can be far larger than the allocated space, an attacker who can inject a large `args` chain into a kernel RPC request can cause an out‑of‑bounds write in kernel memory.  This leads to heap corruption and arbitrary code execution with kernel privileges.  The bug is not mitigated by any bounds check or error handling after `malloc`.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The length of the serialization buffer is calculated in a 32‑bit integer (`uint32_t len`) using 32‑bit values `nl->nl_mpos`, `nl->nl_authlen` and the 64‑bit `size_t` result of `m_length(args,NULL)`. If the sum exceeds 0xFFFFFFFF, the value wraps to a small number that the code subsequently uses for `malloc`. The XDR memory ops (`xdrmem_putbytes`, `xdrmem_putint32`, and `AUTH_MARSHALL`) do not perform bounds‑checking and simply write to the buffer, so an overflow writes beyond the end of the allocated chunk, corrupting kernel heap and enabling arbitrary code execution with kernel privileges. Hence the reported unchecked integer overflow is a valid kernel‑space vulnerability. 

