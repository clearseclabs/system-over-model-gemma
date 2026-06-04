# Triage T0011: Unbounded memcpy of sockaddr into rc->rc_addr

- **File**: `clnt_rc.c`
- **Verdict**: VALID
- **Confidence**: 25% [UUU→V]

---

## Finding

Unbounded memcpy of sockaddr into rc->rc_addr

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code copies `svcaddr->sa_len` bytes into `rc->rc_addr` without verifying that the destination is large enough. In FreeBSD, `struct sockaddr` is 16 bytes, while an IPv6 address uses a `struct sockaddr_in6` whose `sa_len` field is 28 bytes. The unconditional `memcpy(&rc->rc_addr, svcaddr, (size_t)svcaddr->sa_len)` therefore overwrites memory beyond the bounds of `rc->rc_addr`, corrupting the heap‐allocated `rc_data` structure and potentially the kernel. This is a classic buffer overflow and constitutes a real security vulnerability. 

