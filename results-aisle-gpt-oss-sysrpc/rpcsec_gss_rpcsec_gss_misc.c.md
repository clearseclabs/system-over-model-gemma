# Scan: rpcsec_gss/rpcsec_gss_misc.c

- **Independence of findings** – The file `rpcsec_gss_misc.c` only contains simple error‑handling routines.  
  Untrusted data never reaches a buffer or a pointer‑arithmetic path, therefore no classic memory‑corruption vulnerability (e.g. buffer overflow, use‑after‑free, integer overflow) exists.  
  Nevertheless, a few non‑fatal but exploitable behaviors are possible if the caller is able to influence the call parameters or the asynchronous environment.

```json
[
    {
        "severity": "high",
        "title": "Nul‑pointer Dereference in rpc_gss_get_error",
        "function": "rpc_gss_get_error",
        "description": "The function assumes that the caller passes a valid non‑NULL pointer. If an attacker can force a NULL pointer (for example by causing a remote procedure call that passes an uninitialized pointer), the dereference `*error = _rpc_gss_error;` will trigger a crash, resulting in a denial‑of‑service. This is a classic use‑of‑uninitialized or bad‑pointer bug, but it is not a classic buffer overflow."
    },
    {
        "severity": "medium",
        "title": "Race Condition on Static Error State",
        "function": "_rpc_gss_set_error / rpc_gss_get_error",
        "description": "The static variable `_rpc_gss_error` is shared across all threads in the process. Concurrent calls to `_rpc_gss_set_error()` and `rpc_gss_get_error()` without synchronization can lead to lost updates or partially‑written values. While this does not lead to a memory corruption or arbitrary code execution, it can cause an attacker to observe inconsistent error information, or trigger a subtle denial‑of‑service by repeatedly clobbering the error state in a multi‑threaded environment."
    }
]
```