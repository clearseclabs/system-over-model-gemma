# Reachability filter — 5 kept / 0 rejected of 5 (model: google/gemma-4-31b-it)

- **VALID** `cve-00.md` (rpcsec_gss/svc_rpcsec_gss.c) — entry: Network Packet -> svc_rpc_gss() -> svc_rpc_gss_validate()
  - The function `svc_rpc_gss_validate` uses a fixed-size stack buffer `rpchdr` (128 bytes) and performs a `memcpy` using `oa->oa_length`, which is derived from the untrusted RPC message `msg->rm_call.cb_
- **VALID** `cve-01.md` (rpcsec_gss/svc_rpcsec_gss.c) — entry: Network Packet -> svc_rpc_gss -> svc_rpc_gss_validate
  - The `svc_rpc_gss_validate` function copies `oa->oa_length` bytes into a fixed 128-byte stack buffer `rpchdr` without bounds checking. `oa` is sourced from `msg->rm_call.cb_cred`, which is derived from
- **VALID** `cve-02.md` (rpcsec_gss/svc_rpcsec_gss.c) — entry: Network packet -> svc_rpc_gss() -> svc_rpc_gss_validate()
  - The `rpchdr` buffer is fixed at 128 bytes, and `oa->oa_length` (derived from the network RPC message) is used in `memcpy` without bounds checking, allowing a stack overflow.
- **VALID** `cve-03.md` (rpcsec_gss/svc_rpcsec_gss.c) — entry: Network packet -> svc_rpc_gss() -> svc_rpc_gss_validate()
  - The `rpchdr` buffer is fixed at 128 bytes. `svc_rpc_gss_validate` performs a `memcpy` using `oa->oa_length` from the `rpc_msg` structure without checking if the total written data exceeds 128 bytes.
- **VALID** `cve-04.md` (rpcsec_gss/svc_rpcsec_gss.c) — entry: Network Packet -> svc_rpc_gss() -> svc_rpc_gss_validate()
  - The `rpchdr` buffer is fixed at 128 bytes. An attacker-controlled `oa->oa_length` from the `rpc_msg` (derived from the network packet) is used in `memcpy` without bounds checking, leading to a stack-b
