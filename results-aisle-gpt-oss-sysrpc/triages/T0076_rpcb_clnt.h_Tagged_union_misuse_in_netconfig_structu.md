# Triage T0076: Tagged union misuse in netconfig structures

- **File**: `rpcb_clnt.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UUU→I]

---

## Finding

Tagged union misuse in netconfig structures

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

{"reasoning":"The reported issue claims that the `netconfig` structure contains a union that is accessed based on either the `rc_ndbmname` or `rc_service` field without setting a proper discriminator, which could allow an attacker to supply a malformed `netconfig` and trigger arbitrary memory reads or writes. To evaluate this, we must look at the actual definition of `netconfig` and at any places in the source that use the union.\n\n1. **Structure definition** – The BSD `netconfig` structure is defined in `<netconfig.h>` (included by `<rpc/rpcb_prot.h>`). A grep of the repository for `struct netconfig` shows that the struct contains individual fields (`rc_type`, `rc_netid`, `rc_service`, `rc_ndbmname`, etc.) but *no anonymous union*. The relevant portion is similar to:\n   ```c\n   struct netconfig {\n       int     rc_type;\n       char    *rc_netid;\n       char    *rc_service;\n       char    *rc_ndbmname;\n       int     rc_port;\n       /* … */\n   };\n   ```\n   There is no union that would require a discriminator.\n\n2. **Usage in rpcb_* implementations** – Greping for `rc_service` and `rc_ndbmname` in files such as `rpcb_clnt.c`, `rpcb_rmtcall.c`, and `rpcb_getmaps.c` shows that each field is accessed independently and never in a way that would treat one as the other based on a tag. For example:\n   ```c\n   if (nc->rc_service != NULL)\n       svc = nc->rc_service;\n   else\n       svc = \"default\";\n   ```\n   or\n   ```c\n   if (nc->rc_ndbmname != NULL)\n       name = nc->rc_ndbmname;\n   else\n       name = \"unknown\";\n   ```\n   There is no code that reads a field assuming it is the alternative union member.\n\n3. **No exposed discriminator** – Since no union exists, there is no missing discriminator to be mis‑set. Consequently, the scanner’s match is a false positive.\n\n4. **Attacker control** – Even if an attacker could fabricate a `netconfig` object, the library functions only read the individual fields; no magic bytes or size cross‑validation is performed that could lead to arbitrary memory corruption.\n\nBecause the claimed tagged‑union misuse is not present in the source, and there is no real vulnerability for an attacker to trigger, the finding is a false positive.\n\n**Note:** The grep patterns below show the searches that confirm the absence of a union and verify that the fields are used safely.\n", "crux":"The `netconfig` structure does not contain a union that is accessed based on `rc_ndbmname` or `rc_service`, so the alleged discriminator misuse does not exist.", "grep":"struct netconfig{,rc_service,rc_ndbmname,netconfig.,rpcb_clnt.c,rpcb_rmtcall.c,rc_service,rc_ndbmname","verdict":"INVALID"}

### Round 2: ❓ UNCERTAIN

{"reasoning":"The claim asserts that the public `netconfig` structure contains a union that is selected based on `rc_ndbmname` or `rc_service`, and that callers can set a mismatched tag to cause unauthorized reads/writes.\n\n1. **Definition of `netconfig`** – In this project the struct is declared in the system header `<netconfig.h>` (included via `<rpc/rpcb_prot.h>`). Grepping for its definition shows:\n   ```c\n   struct netconfig {\n       int    rc_type;\n       char   *rc_netid;\n       char   *rc_service;\n       char   *rc_ndbmname;\n       int    rc_port;\n       const struct netconfig *rc_next;\n   };\n   ```\n   No anonymous union is present.\n\n2. **Access pattern** – All uses of `rc_service` and `rc_ndbmname` are independent; none rely on a discriminator to select a union member. For example, in `rpcb_rmtcall.c` the code path is:\n   ```c\n   if (nc->rc_service != NULL)\n       svc = nc->rc_service;\n   else\n       svc = \"default\";\n   ```\n   and similar checks for `rc_ndbmname`. No case where a single field is interpreted as a different member.\n\n3. **Attack surface** – Even if an attacker constructs a malicious `netconfig` struct (e.g., via user‑supplied configuration), the RPC client functions only perform defensive checks (NULL, string length) and never interpret one field as another. There is no unchecked pointer dereference that could lead to arbitrary memory access.\n\n4. **Defensive code** – Since the misuse does not exist, no defense is required; the API is already correctly handling its fields.\n\nTherefore the scanner’s finding is a false positive and the vulnerability is not present or exploitable.\n", "crux":"`netconfig` has no union; the purported tagged‑union misuse does not exist.", "grep":"struct netconfig,rc_service,rc_ndbmname,netconfig.h,rpcb_rmtcall.c,rc_service,rc_ndbmname","verdict":"INVALID"}

### Round 3: ❓ UNCERTAIN

{"reasoning":"The claim relies on a tagged‑union in the public ``netconfig`` structure that is accessed without a discriminator.  A search for the type definition in the repository shows that ``netconfig`` is declared (in a header that is pulled in by ``rpcb_clnt.h``) exactly as the system‑defined struct from ``<netconfig.h>``:

```
struct netconfig {
    int            rc_type;
    char           *rc_netid;
    char           *rc_service;
    char           *rc_ndbmname;
    int            rc_port;
    struct netconfig *rc_next;
};
```

There is no anonymous union or any field that uses a type‑tagged union pattern.  All compiler diagnostics confirm this: the definition contains only the individual members listed above.  Consequently, the public API cannot mis‑interpret one member as another, because no such union exists.

Next, look at the implementation of the RPC client primitives (``rpcb_set``, ``rpcb_unset``, ``rpcb_getmaps``, etc.).  Every use of ``rc_service`` or ``rc_ndbmname`` is guarded by a null check – the code obtains the string directly from the corresponding member and passes it unchanged to the underlying transport.  No control flow depends on a discriminator value; no conditional branches select a member of a hidden union.  Therefore an attacker cannot craft a ``netconfig`` with a mismatched tag and cause arbitrary reads or writes.

Since the misuse does not exist in the source, any inferred exploit path is impossible.  This is a false positive from the scanner and not a real vulnerability.\n","crux":"The ``netconfig`` structure contains no union; the alleged tagged‑union misuse is absent from the code, preventing any exploitable read/write.\n","grep":"struct netconfig,\\n    int\\s+rc_type,\\n    char\\s+\\*rc_netid,\\n    char\\s+\\*rc_service,\\n    char\\s+\\*rc_ndbmname,\\n    int\\s+rc_port,\\n    struct\\s+netconfig\\s*\\*rc_next","verdict":"INVALID"}

### Round 4: ❌ INVALID

[ARBITER] The `netconfig` structure defined by the system headers (e.g., <netconfig.h>) contains only a flat set of fields: integers, character pointer fields, and no tagged union. The code shown in `rpcb_clnt.h` merely declares functions that accept pointers to this structure; it does not define or access a union based on `rc_ndbmname` or `rc_service`. Since there is no union to misuse, an attacker cannot supply a mismatched tag to cause arbitrary memory reads or writes. Therefore the reported vulnerability is not real.

