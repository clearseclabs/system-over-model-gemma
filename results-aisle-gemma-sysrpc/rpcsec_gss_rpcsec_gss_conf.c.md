# Scan: rpcsec_gss/rpcsec_gss_conf.c

### Security Analysis

The file `rpcsec_gss_conf.c` serves as a translation layer between string-based configuration and internal GSS identifiers. My analysis focuses on how untrusted input (mechanism names, QOP strings) interacts with the kernel's GSS framework (`kgss`).

#### 1. NULL Pointer Dereferences (API Contract)
Several functions assume that the output pointers passed by the caller are valid. While this is common in kernel internal APIs, if these functions are reachable via a wrapper that doesn't validate the destination pointers, it could lead to a kernel panic.
*   `rpc_gss_mech_to_oid`: Dereferences `oid_ret` without checking if it is NULL.
*   `rpc_gss_oid_to_mech`: Dereferences `mech_ret` without checking if it is NULL.
*   `rpc_gss_qop_to_num`: Dereferences `num_ret` without checking if it is NULL.
*   `rpc_gss_get_versions`: Dereferences `vers_hi` and `vers_lo` unconditionally.

#### 2. Race Condition and Thread Safety (`rpc_gss_get_mechanisms`)
The function `rpc_gss_get_mechanisms` contains a significant concurrency flaw:
*   **Static State without Locking:** It uses a `static const char **mech_names` to cache the list of mechanisms. However, there is no mutex or read-write lock protecting the check `if (mech_names) return (mech_names);` and the subsequent allocation/population phase.
*   **Double Allocation/Leak:** If two threads call this function simultaneously for the first time, both may find `mech_names` to be NULL, both will call `malloc`, and one will overwrite the other's pointer, leading to a kernel memory leak.
*   **Use-After-Free / Inconsistency:** The function iterates over `&kgss_mechs`. If the `kgss_mechs` list is modified (e.g., a mechanism is unloaded) while `rpc_gss_get_mechanisms` is iterating or after the static list has been cached, the `mech_names` array will contain dangling pointers to `km->km_mech_name`.

#### 3. String Handling
*   `rpc_gss_qop_to_num` uses `strcmp(qop, "default")`. If `qop` is NULL, this will result in an immediate kernel panic. Given the security briefing, `qop` originates from network-derived configuration or userspace, making it a potential attack vector if the caller does not guarantee non-NULL strings.

#### 4. Integer Overflow
*   In `rpc_gss_get_mechanisms`, the `count` variable is an `int`. While the number of GSS mechanisms is typically small, the line `malloc(count * sizeof(const char *), ...)` could theoretically overflow if `count` were extremely large, though this is unlikely to be triggerable in a practical environment.

### Summary of Findings

```json
[
  {
    "severity": "medium",
    "title": "Race condition and memory leak in mechanism caching",
    "function": "rpc_gss_get_mechanisms",
    "description": "The function uses a static pointer 'mech_names' to cache GSS mechanisms without any locking mechanism. Concurrent calls during initialization can lead to multiple allocations (memory leak) and potential crashes. Additionally, the cache does not account for changes in the 'kgss_mechs' list, potentially leading to use-after-free if a mechanism is removed."
  },
  {
    "severity": "medium",
    "title": "Potential NULL pointer dereference in QOP parsing",
    "function": "rpc_gss_qop_to_num",
    "description": "The function calls strcmp() on the 'qop' parameter without verifying it is not NULL. If an attacker can trigger this path with a NULL qop string, it will cause a kernel panic."
  },
  {
    "severity": "low",
    "title": "Unvalidated output pointers",
    "function": "rpc_gss_mech_to_oid, rpc_gss_oid_to_mech, rpc_gss_qop_to_num, rpc_gss_get_versions",
    "description": "These functions dereference their return-value pointers (*oid_ret, *mech_ret, etc.) without validating that the pointers themselves are not NULL."
  }
]
```