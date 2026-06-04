# Triage T0169: Memory leak on decryption failure

- **File**: `rpcsec_gss/rpcsec_gss_prot.c`
- **Verdict**: VALID
- **Confidence**: 50% [VUU→V]

---

## Finding

Memory leak on decryption failure

---

## Triage rounds

### Round 1: ✅ VALID

**🎯 Crux:** missing m_freem(results) in the error path after gss_unwrap_mbuf failure in xdr_rpc_gss_unwrap_data, allowing attacker‑controlled network data to cause a leak.

The file implements XDR‐level unmarshalling for RPCSEC_GSS. In xdr_rpc_gss_unwrap_data the caller passes a pointer to an mbuf chain (*resultsp) containing network‑received data. That chain is released only in certain failure paths: if the integrity or privacy sub‑branches detect a checksum or QOP mismatch, the code frees results (or mic) before returning FALSE.  For the privacy branch, after the GSS import of the token, the code calls gss_unwrap_mbuf(&..., &message,…).  When gss_unwrap_mbuf fails (maj_stat != GSS_S_COMPLETE) the routine logs the error and returns FALSE *without* freeing either the original 'results' chain or any newly allocated fragments. The original chain points to kernel memory allocated on the network receive path.  Since callers set *resultsp = NULL before invoking the routine, they will not free that chain after an error return, resulting in a leak.  The attacker can influence the input: the network payload that forms 'results' is under the attacker's control, and malformed ciphertext can trigger gss_unwrap_mbuf failure. No defensive check or freeing occurs, so the omission is real and reachable. Thus the scanner's claim of a memory leak on decryption failure is valid.

CRUX: missing m_freem(results) in the error path after gss_unwrap_mbuf failure in xdr_rpc_gss_unwrap_data, allowing attacker‑controlled network data to cause a leak.
GREP: gss_unwrap_mbuf

🔎 **Grep results:**

GREP `gss_unwrap_mbuf`:
```
sys/kgssapi/gssapi.h:667:OM_uint32 gss_unwrap_mbuf
sys/rpc/rpcsec_gss/rpcsec_gss_prot.c:292:		maj_stat = gss_unwrap_mbuf(&min_stat, ctx, &message,
sys/kgssapi/gss_unwrap.c:82:gss_unwrap_mbuf(OM_uint32 *minor_status,
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



### Round 4: ✅ VALID

[ARBITER] The code in `xdr_rpc_gss_unwrap_data()` sets `*resultsp = NULL` at the start so that the caller does not own the incoming mbuf chain after the function returns. In the privacy branch it pulls the length field, then attempts to decrypt with `gss_unwrap_mbuf()`. When `maj_stat != GSS_S_COMPLETE` the function logs an error and `return (FALSE)` without freeing `results`, which still points to the remaining part of the original mbuf chain. Consequently, each decryption failure leaks that chain’s memory, allowing repeated malformed packets to exhaust kernel memory. No other freeing path handles this case, so the leak is real.

Therefore the reported medium‑severity vulnerability is legitimate.

