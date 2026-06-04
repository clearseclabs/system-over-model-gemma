# Context: xdr.h

This briefing covers `xdr.h`, the header defining the External Data Representation (XDR) serialization framework used for RPC communication.

### 1. Functionality and Location
This code defines the interface for converting C data types to/from a standardized network bit-stream. It sits at the core of the KRPC layer, providing a dispatch mechanism (`XDR` handle) to abstract the underlying transport (memory buffers, mbufs, or TCP streams).

### 2. Untrusted Input Path
Untrusted input enters via network packets (TCP/UDP), which are wrapped in `mbuf` structures or memory buffers, and then passed to `XDR` decode functions (e.g., `xdrmbuf_create` $\rightarrow$ `xdr_decode` calls).

### 3. Attacker-Controlled Data
Data originates from the network stream. Key variables carrying this data:
* **`long l` / `int32_t *ip`**: In `xdr_getint32` and `IXDR_GET_LONG`, data is read directly from the stream.
* **`char *addr`**: In `XDR_GETBYTES`, the destination buffer receives raw network bytes.
* **`len`**: Used in `XDR_GETBYTES` and `XDR_INLINE`, often derived from a previously decoded length field in the stream.

### 4. Fixed-Size Buffers and Constants
* `BYTES_PER_XDR_UNIT`: **4**
* `MAX_NETOBJ_SZ`: **1024** (Used by `struct netobj`)

### 5. Dangerous Data Flows
* **Source:** Network Stream $\rightarrow$ **Destination:** `netobj.n_bytes` via `xdr_netobj` (potential overflow if `n_len` is not validated against `MAX_NETOBJ_SZ`).
* **Source:** Network Stream $\rightarrow$ **Destination:** `addr` via `XDR_GETBYTES` (depends on the caller-provided `len`).
* **Source:** Network Stream $\rightarrow$ **Destination:** `buf` via `XDR_INLINE` (depends on `len`).

### 6. NULL Dereferences
* **`xdrs->x_ops`**: If the `XDR` handle is improperly initialized, all `XDR_GET/PUT` macros will dereference a NULL function pointer table.
* **`argresp`**: The `xdrproc_t` signature notes that if `argresp` is NULL, the routine may allocate memory; failure to handle allocation failure or NULL checks in custom procs is a risk.

### 7. Tagged Unions
The `struct xdr_discrim` and `xdr_union()` function implement tagged unions. The code relies on the `xdr_union` implementation to validate the discriminant `value` against the `xdr_discrim` array before calling the associated `proc`.

### 8. API Visibility
* **Public API:** `xdr_int`, `xdr_string`, `xdrmem_create`, etc. (Used by RPC service stubs).
* **Static Helpers:** `xdr_getint32`, `xdr_putint32` (Inlined helpers).

### 9. Likely Bug Classes
* **Integer Overflows:** Calculation of `len` for `XDR_GETBYTES` or `XDR_INLINE`.
* **Heap Overflows:** `xdr_bytes`, `xdr_string`, and `xdr_array` allocate memory based on stream-provided lengths.
* **Out-of-Bounds Read:** `XDR_INLINE` providing a pointer to a buffer that is smaller than the subsequent `IXDR_GET` macros expect.