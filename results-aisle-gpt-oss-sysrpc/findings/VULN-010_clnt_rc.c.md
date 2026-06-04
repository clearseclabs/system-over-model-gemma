# VULN-010: Unbounded memcpy of sockaddr into rc->rc_addr

- **File**: `clnt_rc.c`
- **Confidence**: 25% [UUU→V]
- **Project**: aisle-gpt-oss-sysrpc
- **Date**: 2026-05-06_173506

---

## Scanner finding

Unbounded memcpy of sockaddr into rc->rc_addr

The function copies svcaddr->sa_len bytes into the struct field rc->rc_addr using memcpy without checking that the size of rc->rc_addr is large enough.  If the caller supplies an IPv6 address (or a spoofed address with sa_len > sizeof(struct sockaddr)), the memcpy will write beyond the bounds of rc->rc_addr, corrupting the rc structure on the heap and potentially overwriting kernel pointers.  This overflow can be exploited to execute arbitrary code or crash the kernel.

---

## Triage reasoning

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code copies `svcaddr->sa_len` bytes into `rc->rc_addr` without verifying that the destination is large enough. In FreeBSD, `struct sockaddr` is 16 bytes, while an IPv6 address uses a `struct sockaddr_in6` whose `sa_len` field is 28 bytes. The unconditional `memcpy(&rc->rc_addr, svcaddr, (size_t)svcaddr->sa_len)` therefore overwrites memory beyond the bounds of `rc->rc_addr`, corrupting the heap‐allocated `rc_data` structure and potentially the kernel. This is a classic buffer overflow and constitutes a real security vulnerability. 

