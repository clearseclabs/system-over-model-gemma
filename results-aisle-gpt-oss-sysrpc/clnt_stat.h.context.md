# Context: clnt_stat.h

**Context Briefing – `clnt_stat.h`**  
*Author: Security Research Analyst – 250 words*

1. **What the code does & where it sits**  
   `clnt_stat.h` defines the `enum clnt_stat` values that a Sun RPC client library reports as status or error codes. It lives in the `rpc` subsystem, included by client‑side RPC wrappers (e.g., `clnt_create`, `clnt_call`). The header is part of the public API, not implementation code; it is compiled once into any client binary that uses RPC.

2. **Untrusted input reaching this code**  
   The enum itself never receives runtime input. It is only used as a return value from functions that do process untrusted data (network RPC payloads). Therefore, there is no direct data flow from user input to this header.

3. **Variables/fields carrying attacker‑controlled data**  
   – *None.* The enum is static. Any attacker‑controlled data would be in calling code, not in this header.

4. **Fixed‑size buffers / size constants**  
   – *None.* The header contains only constants. No arrays/buffers are declared.

5. **Dangerous data flows**  
   – *None.* No data copies or copies into fixed buffers occur here.

6. **Nullable parameters**  
   – *None.* No functions; no parameters to validate.

7. **Tagged unions / variant types**  
   – *None.* No unions or discriminated types.

8. **Public vs static helpers**  
   – Public: The enum is public. No helpers or static functions are defined in this file.

9. **Likely bug classes**  
   – *None attributable to this file.* Potentially used incorrectly elsewhere (e.g., misinterpreting values), but the header itself is safe.

**Fixed numeric values**: All enum values and their numerical assignments appear directly in the source; no macros are used to compute them. For example, `RPC_SUCCESS = 0`, `RPC_CANTENCODEARGS = 1`, `RPC_CANTDECODERES = 2`, etc., directly as listed.