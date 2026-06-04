# Triage T0041: Integer Underflow in Record Marking

- **File**: `clnt_vc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Integer Underflow in Record Marking

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The mbuf length `mreq->m_pkthdr.len` is guaranteed to be at least the size of an RPC call header (approx 20+ bytes) due to the preceding `xdr_callhdr` and `XDR_PUTINT32` calls, making the subtraction of 4 bytes safe.

The reported vulnerability is in `clnt_vc_call`, which is the client-side function for sending an RPC request. The code calculates the record marker as `0x80000000 | (mreq->m_pkthdr.len - sizeof(uint32_t))`. For an underflow to occur, `mreq->m_pkthdr.len` must be less than 4 bytes. However, `mreq` is initialized via `m_gethdr` and then `bcopy(ct->ct_mcallc, mreq->m_data, ct->ct_mpos)` is called, setting `mreq->m_len = ct->ct_mpos`. `ct->ct_mpos` is the result of `xdr_callhdr`, which serializes the RPC call header. An RPC call header contains at least the XID, direction, version, program, and version (5 x 4-byte fields = 20 bytes). Furthermore, the code explicitly performs `*mtod(mreq, uint32_t *) = htonl(xid);` and then calls `XDR_PUTINT32` for the procedure number and `AUTH_MARSHALL` for authentication. This guarantees that `mreq->m_pkthdr.len` is significantly larger than 4 bytes before the subtraction occurs. Since this is the client sending data to the server, the data flow originates from internal state and the XDR serialization process, not from untrusted network input. The 'underflow' is mathematically impossible in the current execution path.

CRUX: The mbuf length `mreq->m_pkthdr.len` is guaranteed to be at least the size of an RPC call header (approx 20+ bytes) due to the preceding `xdr_callhdr` and `XDR_PUTINT32` calls, making the subtraction of 4 bytes safe.
GREP: xdr_callhdr

🔎 **Grep results:**

GREP `xdr_callhdr`:
```
(no matches in repo)
```

### Round 2: ❌ INVALID

**🎯 Crux:** The mbuf length is guaranteed to be at least 8 bytes (XID + procedure number) before the subtraction of 4 bytes occurs, and the logic resides in a client-side send path.

The reported bug is an integer underflow in `clnt_vc_call` when calculating the RPC record marker: `(mreq->m_pkthdr.len - sizeof(uint32_t))`. For this to underflow, `mreq->m_pkthdr.len` must be less than 4. 

Tracing the data flow for `mreq` in `clnt_vc_call`:
1. `mreq = m_gethdr(M_WAITOK, MT_DATA);` initializes the mbuf.
2. `bcopy(ct->ct_mcallc, mreq->m_data, ct->ct_mpos);` and `mreq->m_len = ct->ct_mpos;` are called. `ct->ct_mpos` is initialized in `clnt_vc_create` via `xdr_callhdr`.
3. `*mtod(mreq, uint32_t *) = htonl(xid);` writes 4 bytes into the mbuf.
4. `xdrmbuf_create(&xdrs, mreq, XDR_ENCODE);` is called, followed by `XDR_PUTINT32(&xdrs, &proc)` (4 bytes) and `AUTH_MARSHALL` (at least 0 bytes, but typically more).
5. `mreq->m_pkthdr.len = m_length(mreq, NULL);` calculates the total length.

Even if `ct->ct_mpos` were 0 and `AUTH_MARSHALL` added nothing, the `htonl(xid)` and `XDR_PUTINT32` calls ensure that at least 8 bytes are present in the mbuf before the subtraction. Furthermore, `clnt_vc_call` is a client-side function sending data to a server; the values used to construct the packet (XID, procedure number, authentication) are controlled by the kernel/client, not by an external attacker. Thus, the underflow is not reachable via untrusted input, and the sequence of operations guarantees the length is $\ge 4$.

CRUX: The mbuf length is guaranteed to be at least 8 bytes (XID + procedure number) before the subtraction of 4 bytes occurs, and the logic resides in a client-side send path.
GREP: XDR_PUTINT32

🔎 **Grep results:**

GREP `XDR_PUTINT32`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** mreq->m_pkthdr.len is guaranteed to be at least 8 bytes (XID + procedure number) plus the call header size before the subtraction, and the data is client-generated, not attacker-controlled.

The reported vulnerability is a potential integer underflow in `clnt_vc_call` during the calculation of the RPC record marker: `(mreq->m_pkthdr.len - sizeof(uint32_t))`. For an underflow to occur, `mreq->m_pkthdr.len` must be less than 4 bytes. 

Tracing the mbuf `mreq` construction in `clnt_vc_call`:
1. `mreq` is created and partially filled with `ct->ct_mcallc` (the pre-serialized call header). `ct->ct_mpos` is set in `clnt_vc_create` via `xdr_callhdr`. An RPC call header consists of several 32-bit fields, ensuring `ct->ct_mpos` is well above 4 bytes.
2. The code then performs `*mtod(mreq, uint32_t *) = htonl(xid);`, which writes 4 bytes.
3. It then calls `XDR_PUTINT32(&xdrs, &proc)`, which writes another 4 bytes.
4. Finally, it calls `AUTH_MARSHALL`, which adds authentication data.

By the time `mreq->m_pkthdr.len = m_length(mreq, NULL);` is called, the mbuf contains at minimum the call header, the XID, and the procedure number. This totals significantly more than 4 bytes. 

Crucially, this is a client-side transmission path. The data used to populate the mbuf (XID, procedure number, internal call header) is generated by the kernel's RPC client, not provided by an untrusted network source. An attacker cannot control the length of the mbuf being sent by the client to trigger this underflow. The pattern is safe in this context.

CRUX: mreq->m_pkthdr.len is guaranteed to be at least 8 bytes (XID + procedure number) plus the call header size before the subtraction, and the data is client-generated, not attacker-controlled.
GREP: xdr_callhdr

🔎 **Grep results:**

GREP `xdr_callhdr`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The reported integer underflow occurs if `mreq->m_pkthdr.len < 4`. In `clnt_vc_call`, `mreq` is initialized with `ct->ct_mcallc` (the pre-serialized call header). This header is created in `clnt_vc_create` via `xdr_callhdr`. An RPC call header contains an XID, direction, and a call structure (version, program, version), totaling at least 12 bytes (3 x 4-byte units). Furthermore, `clnt_vc_call` explicitly adds the procedure number via `XDR_PUTINT32` and performs `AUTH_MARSHALL` before calculating the length. Consequently, `mreq->m_pkthdr.len` is guaranteed to be significantly larger than 4 bytes, making the subtraction safe. Additionally, this is client-side code operating on internally generated data, not attacker-controlled input.

