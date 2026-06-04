# Context: rpc_prot.c

This briefing covers `rpc_prot.c`, which implements the XDR (External Data Representation) serialization and deserialization for RPC message headers and authentication structures.

### 1. Role and Location
This code provides the low-level serialization logic for RPC messages (`rpc_msg`). It sits between the network transport layer and the RPC client/server state machines, converting raw bytes into C structures.

### 2. Untrusted Input Path
Untrusted data arrives via the network as raw byte streams, which are passed into `XDR` handles. These handles are then passed to the functions in this file during `XDR_DECODE` operations.

### 3. Attacker-Controlled Data Flow
Data flows from `xdrs` (XDR stream) $\rightarrow$ local variables/struct fields:
* **`rmsg->rm_xid`**: Decoded via `IXDR_GET_UINT32` or `xdr_uint32_t`.
* **`rmsg->rm_direction`**: Decoded as `enum msg_type`.
* **`rmsg->rm_reply.rp_stat`**: Decoded as `enum reply_stat`.
* **`ap->oa_flavor`** & **`ap->oa_base`**: Decoded in `xdr_opaque_auth`.
* **`ar->ar_stat`** & **`rr->rj_stat`**: Decoded as status enums.

### 4. Fixed-Size Buffers & Constants
* **`MAX_AUTH_BYTES`**: Used in `xdr_opaque_auth` to limit `xdr_bytes`. 
GREP: `grep -r "MAX_AUTH_BYTES" .` (Usually 64 or 256 in RPC implementations).

### 5. Dangerous Data Flows
* **Source**: `xdrs` $\rightarrow$ **Destination**: `ap->oa_base` via `xdr_bytes`.
* **Function**: `xdr_opaque_auth`.
* **Constraint**: Limited by `MAX_AUTH_BYTES`.

### 6. NULL Dereferences
The code uses `assert()` for `xdrs`, `ap`, `ar`, `rr`, and `rmsg`. In production builds where `KASSERT` is disabled, passing NULL to any of these public API functions will cause a crash.

### 7. Tagged Unions
The code handles several tagged unions:
* **`rmsg->rm_reply`**: Tagged by `rp_stat`. Checked in `xdr_replymsg` before calling `xdr_accepted_reply` or `xdr_rejected_reply`.
* **`ar` (accepted_reply)**: Tagged by `ar_stat`. Validated via `switch(ar->ar_stat)`.
* **`rr` (rejected_reply)**: Tagged by `rj_stat`. Validated via `switch(rr->rj_stat)`.

### 8. API Visibility
* **Public API**: `xdr_opaque_auth`, `xdr_accepted_reply`, `xdr_rejected_reply`, `xdr_replymsg`, `xdr_callhdr`, `_seterr_reply`.
* **Static Helpers**: `accepted`, `rejected`. These are called internally by `_seterr_reply` after the union tag has been checked.

### 9. Likely Bug Classes
* **Integer Overflows**: In length calculations during `xdr_bytes` (if `MAX_AUTH_BYTES` is large).
* **Logic Errors**: Mismatched union member access if `enum` values are spoofed.
* **DoS**: Malformed XDR streams causing excessive resource consumption or crashes via NULL dereferences (if assertions are off).

[GREP RESULTS from codebase]:
GREP `implementations`:
```
contrib/ntp/libntp/lib/isc/unix/include/isc/net.h:98:#define in6_addr in_addr6	/*%< Required for pre RFC2133 implementations. */
sys/dev/ath/ath_hal/ah_eeprom_v14.h:28:#define AR5416_EEPROM_MAX		0xae0 /* Ignore for the moment used only on the flash implementations */
sys/contrib/libsodium/src/libsodium/include/sodium/private/implementations.h:2:#define implementations_H
contrib/googletest/googlemock/include/gmock/gmock-actions.h:269:// Partial implementations of metaprogramming types from the standard library
contrib/googletest/googletest/include/gtest/internal/gtest-string.h:138:  // NB: The implementations on different platforms slightly differ.
contrib/googletest/googletest/include/gtest/gtest-spi.h:144:// Note that even though the implementations of the following two
contrib/googletest/googletest/include/gtest/gtest-spi.h:203:// Note that even though the implementations of the following two
contrib/googletest/googletest/include/gtest/internal/gtest-internal.h:1206:// implementations.
contrib/googletest/googletest/include/gtest/internal/gtest-internal.h:1270:// Some standard library implementations use `struct tuple_size` and some use
contrib/googletest/googletest/include/gtest/internal/gtest-port.h:54:// features and implementations.
contrib/googletest/googletest/include/gtest/internal/gtest-port.h:385:          _Pragma("clang diagnostic ignored \"-Wdeprecated-implementations\"")
contrib/googletest/googletest/include/gtest/internal/gtest-port.h:775:// MinGW has two different printf implementations. Ensure the format macro
sys/bsm/audit_kevents.h:45: * between BSM implementations.  In general, we prefer the OpenSolaris
usr.sbin/nscd/hashtable.h:155: * Generates implementations of the hash table functions
usr.sbin/ppp/ccp.h:102:    void *state;		/* Returned by implementations Init() */
usr.sbin/ppp/ccp.h:108:    void *state;		/* Returned by implementations Init() */
contrib/libpcap/pcap-int.h:415: * Routines that most pcap implementations can use for non-blocking mode.
contrib/libpcap/pcap-int.h:426: * a regular network interface.  There are multiple implementations
contrib/sendmail/include/sm/conf.h:2814:**  Use the lack of LDAP_OPT_SIZELIMIT to detect old API implementations
contrib/sendmail/include/sm/conf.h:2815:**  and assume (falsely) that all old API implementations are broken.
contrib/sendmail/include/sm/conf.h:3043:**  Some snprintf() implementations are rumored not to NUL terminate.
contrib/tzcode/private.h:94:** You can use zdump to help in verifying other implementations.
contrib/wireguard-tools/ctype.h:5: * Specialized constant-time ctype.h reimplementations that aren't locale-specific.
contrib/lib9p/fid.h:72: * different future implementations.)
contrib/libevent/include/event2/buffer.h:548:   implementations.
contrib/libevent/include/event2/buffer.h:553:   implementations (including sendfile and splice).
contrib/libevent/include/event2/event.h:543:	    evconn_listener_new() will use IOCP-backed implementations
contrib/openbsm/sys/bsm/audit_kevents.h:43: * between BSM implementations.  In general, we prefer the OpenSolaris
contrib/libcbor/src/cbor/common.h:27: * linking non-restrict signatures with restrict implementations.
contrib/wpa/wpa_supplicant/config_ssid.h:605:	 * broken implementations and should be avoided when using or
```