# nano-analyzer scan results

- **Target**: `freebsd-prepatch/sys/rpc`
- **Date**: 2026-05-06_173506
- **Model**: openai/gpt-oss-20b
- **Files scanned**: 52 (19,674 lines)
- **Wall time**: 2059s

| File | Lines | Critical | High | Medium | Low |
|------|-------|----------|------|--------|-----|
| rpcsec_gss/rpcsec_gss_conf.c | 162 | 4 | 1 | 1 | 0 |
| rpcb_clnt.h | 88 | 2 | 5 | 1 | 0 |
| svc_dg.c | 297 | 2 | 3 | 1 | 0 |
| auth_unix.c | 372 | 2 | 3 | 0 | 0 |
| clnt_rc.c | 592 | 2 | 2 | 2 | 0 |
| rpcsec_gss/rpcsec_gss.c | 1215 | 2 | 2 | 2 | 1 |
| rpc.h | 122 | 2 | 1 | 2 | 0 |
| rpcsec_tls/rpctls_impl.c | 544 | 2 | 0 | 3 | 1 |
| rpcsec_gss/rpcsec_gss_int.h | 101 | 1 | 2 | 3 | 1 |
| replay.c | 255 | 1 | 2 | 2 | 0 |
| rpcsec_gss.h | 489 | 1 | 2 | 2 | 1 |
| rpcb_prot.h | 576 | 1 | 2 | 2 | 0 |
| clnt_dg.c | 1148 | 1 | 2 | 1 | 2 |
| svc_generic.c | 229 | 1 | 2 | 1 | 1 |
| rpc_generic.c | 975 | 1 | 1 | 3 | 1 |
| rpcsec_gss/rpcsec_gss_prot.c | 373 | 1 | 1 | 3 | 0 |
| svc_auth.h | 76 | 1 | 1 | 2 | 1 |
| rpcsec_gss/svc_rpcsec_gss.c | 1715 | 1 | 1 | 2 | 1 |
| clnt.h | 447 | 1 | 1 | 1 | 1 |
| clnt_bck.c | 610 | 1 | 1 | 1 | 1 |
| getnetconfig.c | 137 | 1 | 1 | 1 | 2 |
| clnt_nl.c | 521 | 1 | 1 | 1 | 0 |
| rpcb_clnt.c | 170 | 1 | 1 | 1 | 0 |
| svc_auth_unix.c | 143 | 1 | 1 | 1 | 0 |
| svc_vc.c | 1185 | 1 | 1 | 1 | 1 |
| rpcsec_tls/auth_tls.c | 165 | 1 | 1 | 1 | 1 |
| rpc_callmsg.c | 195 | 1 | 0 | 1 | 1 |
| pmap_prot.h | 104 | 1 | 0 | 0 | 0 |
| rpc_msg.h | 211 | 1 | 0 | 0 | 0 |
| rpcm_subs.h | 128 | 0 | 2 | 3 | 0 |
| clnt_vc.c | 1301 | 0 | 2 | 2 | 0 |
| rpcsec_tls/rpctlssd.x | 69 | 0 | 2 | 2 | 0 |
| xdr.h | 383 | 0 | 1 | 4 | 0 |
| svc_auth.c | 226 | 0 | 1 | 3 | 0 |
| rpc_com.h | 119 | 0 | 1 | 2 | 1 |
| svc.c | 1498 | 0 | 1 | 2 | 0 |
| rpcsec_tls/rpctlscd.x | 69 | 0 | 1 | 2 | 0 |
| rpcb_prot.c | 239 | 0 | 1 | 1 | 1 |
| rpcsec_gss/rpcsec_gss_misc.c | 52 | 0 | 1 | 1 | 0 |
| krpc.h | 141 | 0 | 1 | 0 | 0 |
| rpc_prot.c | 366 | 0 | 1 | 0 | 0 |
| svc.h | 631 | 0 | 0 | 7 | 0 |
| nettype.h | 68 | 0 | 0 | 5 | 0 |
| authunix_prot.c | 145 | 0 | 0 | 1 | 2 |
| rpcsec_tls.h | 85 | 0 | 0 | 1 | 0 |
| auth_none.c | 149 | 0 | 0 | 0 | 0 |
| auth.h | 368 | 0 | 0 | 0 | 0 |
| clnt_nl.h | 42 | 0 | 0 | 0 | 0 |
| clnt_stat.h | 80 | 0 | 0 | 0 | 0 |
| netconfig.h | 98 | 0 | 0 | 0 | 0 |
| replay.h | 85 | 0 | 0 | 0 | 0 |
| types.h | 115 | 0 | 0 | 0 | 0 |
