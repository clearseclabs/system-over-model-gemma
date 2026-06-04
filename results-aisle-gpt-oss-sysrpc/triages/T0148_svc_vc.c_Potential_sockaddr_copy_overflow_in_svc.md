# Triage T0148: Potential sockaddr copy overflow in svc_vc_create_conn

- **File**: `svc_vc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Potential sockaddr copy overflow in svc_vc_create_conn

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ❌ INVALID

[ARBITER] The memcpy uses the peer address returned by the kernel’s sopeeraddr or soaccept calls. The kernel sets sa_len to the actual size of the sockaddr it creates (≤ sizeof(sockaddr_storage)), and this value can’t be arbitrarily inflated by userland. Because svc_vc_create_conn is a kernel‑only function and the caller cannot supply an arbitrary sockaddr, the memcpy cannot overflow the 128‑byte sockaddr_storage target. Thus the evidence does not support a real vulnerability.

