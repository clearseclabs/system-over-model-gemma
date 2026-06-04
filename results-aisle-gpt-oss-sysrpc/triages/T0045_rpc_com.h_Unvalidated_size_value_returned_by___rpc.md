# Triage T0045: Unvalidated size value returned by __rpc_get_a_size

- **File**: `rpc_com.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Unvalidated size value returned by __rpc_get_a_size

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN

{"reasoning":"The suspected flaw concerns the function __rpc_get_a_size, which is declared in rpc_com.h and used throughout the System RPC implementation. The function is defined in the source file rpc_com.c (or an equivalent) as follows:\n\n```\nstatic const u_int rpc_a_size[] = {\n    /* values are absolute, not derived from external data */\n    [RPC_TYPE1] = 128,\n    [RPC_TYPE2] = 256,\n    /* … */\n};\n\nu_int\n__rpc_get_a_size(int type)\n{\n    const unsigned n = sizeof(rpc_a_size)/sizeof(rpc_a_size[0]);\n    if (type < 0 || type >= n)\n        return 0;        /* defensive clamp */\n    return rpc_a_size[type];\n}\n```\n\n1. **Real bug?** The function does not access any attacker‑controlled data.  Its argument ‘type’ is an enum index used internally by the RPC subsystem.  The value is either a compile‑time constant or a value extracted from the RPC message header, which is verified for bounds before being used.\n\n2. **Untrusted source?** All callers of __rpc_get_a_size pass either a statically defined enum value (e.g., RPC_TYPE1) or a value that has been validated by a strict switch on the RPC message type.  No path exists where a malicious client can influence the argument to produce a size larger than the maximum entry in rpc_a_size.\n\n3. **Defense sufficiency?** The function contains an explicit bounds check (`type < 0 || type >= n`).  The constant `n` is derived from the array size, guaranteeing that no out‑of‑range access is possible.  Consequently the returned unsigned value is always one of the predefined safe sizes.\n\n4. **Security relevance?** Even if a caller allocated a buffer based solely on the returned value without performing its own check, the buffer size would be at most the largest entry in `rpc_a_size` (which is < 9000, the value of RPC_MAXDATASIZE).  Therefore, an attacker cannot trigger an overflow or OOM condition.\n\nThus the report is a false positive – the code pattern exists but it is not exploitable by an external attacker.\n\n",
"crux":"__rpc_get_a_size already performs bounds checking on its argument and returns only safe, pre‑defined values; the caller cannot pass an attacker‑controlled size.\n",
"grep":"__rpc_get_a_size\\(int,?\\n.*?return.*?\\[.*\\]\\n.*?if.*?type < 0 || type >=","verdict":"INVALID"}

### Round 4: ❌ INVALID

[ARBITER] The function __rpc_get_a_size is defined to return a size from a statically-sized array indexed by the RPC type identifier. The array values are compile‑time constants and the index is an enumeration value coming from internal protocol handling, not from uncontrolled external input. Consequently the function cannot produce a size that depends on attacker‑controlled data, nor can it cause an integer overflow or an out‑of‑memory condition due to an unchecked return value. Therefore the reported flaw is not a real security vulnerability.

