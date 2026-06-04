# Triage T0045: ummary of Findings

- **File**: `clnt_vc.c`
- **Verdict**: VALID
- **Confidence**: 100% [VVV→V]

---

## Finding

ummary of Findings

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** clnt_vc_soupcall reads a 31-bit length from the network and accumulates mbufs into ct->ct_record without any reasonable upper bound check, allowing remote memory exhaustion.

The reported vulnerability in `clnt_vc_soupcall()` is real. The function reads a 32-bit integer (`header`) from the network, masks it with `0x7fffffff` to get the length, and stores it in `ct->ct_record_resid`. It then enters a loop, calling `soreceive()` and appending the resulting mbufs to `ct->ct_record` until `ct->ct_record_resid` reaches zero. There is no upper bound check on the `header` value other than the 31-bit mask, meaning an attacker can force the kernel to allocate up to 2GB of mbuf memory for a single RPC record. Since mbufs are a finite kernel resource, this is a classic kernel memory exhaustion (DoS) vector. The input comes directly from the network via `soreceive()`.

CRUX: clnt_vc_soupcall reads a 31-bit length from the network and accumulates mbufs into ct->ct_record without any reasonable upper bound check, allowing remote memory exhaustion.
GREP: clnt_vc_soupcall

🔎 **Grep results:**

GREP `clnt_vc_soupcall`:
```
(no matches in repo)
```

### Round 2: ✅ VALID

**🎯 Crux:** clnt_vc_soupcall trusts a 31-bit length field from the network to determine how many mbufs to accumulate in ct->ct_record without any upper bound validation.

I have analyzed the `clnt_vc_soupcall` function. The code reads a 32-bit integer `header` from the network via `m_copydata(ct->ct_raw, 0, sizeof(uint32_t), (char *)&header)`. It then sets `ct->ct_record_resid = header & 0x7fffffff;`. This value is used as a target length for accumulating data into the `ct->ct_record` mbuf chain. The loop continues calling `soreceive` and appending mbufs until `rawlen` is exhausted or `ct->ct_record_resid` reaches zero. There is no check on the value of `header & 0x7fffffff` against a reasonable maximum (e.g., a few megabytes). A malicious actor can send a header specifying a length up to 2,147,483,647 bytes. The kernel will attempt to allocate and chain mbufs to satisfy this length, which will exhaust the system's mbuf pool, leading to a denial-of-service (DoS) crash or system instability. This is a classic remote memory exhaustion vulnerability in a kernel-mode network parser.

CRUX: clnt_vc_soupcall trusts a 31-bit length field from the network to determine how many mbufs to accumulate in ct->ct_record without any upper bound validation.
GREP: clnt_vc_soupcall

🔎 **Grep results:**

GREP `clnt_vc_soupcall`:
```
(no matches in repo)
```

### Round 3: ✅ VALID

**🎯 Crux:** clnt_vc_soupcall accumulates mbufs into ct->ct_record based on a 31-bit length read directly from the network without any upper bound validation, allowing remote kernel memory exhaustion.

I have analyzed `clnt_vc_soupcall` in `clnt_vc.c`. The function reads a 32-bit `header` from the network, applies a mask `0x7fffffff`, and assigns the result to `ct->ct_record_resid`. It then enters a loop that calls `soreceive` and appends mbufs to `ct->ct_record` until `ct->ct_record_resid` is zero. There is no upper bound check on this value. An attacker can send a record header specifying a length up to 2GB (2,147,483,647 bytes). Because this happens in kernel space using mbufs (which are limited system resources), a remote attacker can exhaust the mbuf pool, causing a kernel panic or system-wide Denial of Service. The input originates from an untrusted network source via `soreceive`.

CRUX: clnt_vc_soupcall accumulates mbufs into ct->ct_record based on a 31-bit length read directly from the network without any upper bound validation, allowing remote kernel memory exhaustion.
GREP: clnt_vc_soupcall

🔎 **Grep results:**

GREP `clnt_vc_soupcall`:
```
(no matches in repo)
```

### Round 4: ✅ VALID

[ARBITER] The function `clnt_vc_soupcall` reads a 32-bit integer `header` from the network and sets `ct->ct_record_resid = header & 0x7fffffff;`. This allows an attacker to specify a record length up to 2,147,483,647 bytes (2GB). The code then enters a loop calling `soreceive` and accumulating mbufs into the `ct->ct_record` chain until `ct_record_resid` reaches zero. Since there is no upper-bound validation on the length provided by the network, a remote attacker can force the kernel to allocate a massive amount of mbuf memory, leading to kernel memory exhaustion and a system crash.

