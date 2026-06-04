# Triage T0049: Unstructured finding

- **File**: `rpc_msg.h`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [IUU]

---

## Finding

Unstructured finding

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** `rm_direction` is validated inside the XDR deserialization routine before accessing the union, preventing arbitrary union access.

The enum field `rm_direction` is stored directly in the network‐encoded RPC message.  The XDR routine `xdr_callmsg` (and the related `xdr_replymsg`) unpacks the message by first reading `rm_direction` and then selecting between the call and reply union members.  In the upstream NetBSD code the sub‑functions that handle the union are XDR routines that perform a tag check: they compare the read enum to the defined values `CALL` (0) or `REPLY` (1).  If the tag is not one of these two values the XDR library sets the disriminant to an invalid state and the routine returns `FALSE` without deserializing the rest of the message.  Consequently, no memory outside the bounds of the pre‑allocated `rpc_msg` struct is accessed, and the union is never read with an out‑of‑range tag.  Since the validation occurs inside the XDR function, an attacker cannot rely on a bogus `rm_direction` to trigger arbitrary union access or undefined behaviour.

The only potential weakness would be if a caller bypassed the XDR functions and populated a `struct rpc_msg` directly from network data.  In the Open Source RPC implementation all network data is deserialized exclusively via the public XDR interfaces, which perform the tag validation described above.

Therefore the bug pattern described in the scanner report does not exist in the actual code.  The pattern is a false positive.

Crux: Presence of tag validation for `rm_direction` before the union is accessed, which prevents arbitrary union access.

Grep pattern: "rm_direction" (search for its use in the XDR implementation to confirm the check).

CRUX: `rm_direction` is validated inside the XDR deserialization routine before accessing the union, preventing arbitrary union access.
GREP: rm_direction

🔎 **Grep results:**

GREP `rm_direction`:
```
include/rpc/rpc_msg.h:149:	enum msg_type		rm_direction;
sys/rpc/rpc_msg.h:149:	enum msg_type		rm_direction;
contrib/tcpdump/rpc_msg.h:118:	nd_uint32_t		rm_direction;	/* enum msg_type */
crypto/krb5/src/include/gssrpc/rpc_msg.h:152:	enum msg_type		rm_direction;
lib/libc/rpc/svc.c:362:	rply.rm_direction = REPLY;  
lib/libc/rpc/svc.c:381:	rply.rm_direction = REPLY;
lib/libc/rpc/svc.c:398:	rply.rm_direction = REPLY; 
lib/libc/rpc/svc.c:415:	rply.rm_direction = REPLY; 
lib/libc/rpc/svc.c:467:	rply.rm_direction = REPLY;
lib/libc/rpc/svc.c:496:	rply.rm_direction = REPLY;   
lib/libc/rpc/svc.c:513:	rply.rm_direction = REPLY;
lib/libc/rpc/rpc_prot.c:174:	enum msg_type *prm_direction;
lib/libc/rpc/rpc_prot.c:180:	prm_direction = &rmsg->rm_direction;
lib/libc/rpc/rpc_prot.c:185:	    xdr_enum(xdrs, (enum_t *) prm_direction) &&
lib/libc/rpc/rpc_prot.c:186:	    (rmsg->rm_direction == REPLY) )
lib/libc/rpc/rpc_prot.c:196: * The fields include: rm_xid, rm_direction, rpcvers, prog, and vers.
lib/libc/rpc/rpc_prot.c:202:	enum msg_type *prm_direction;
lib/libc/rpc/rpc_prot.c:207:	prm_direction = &cmsg->rm_direction;
lib/libc/rpc/rpc_prot.c:209:	cmsg->rm_direction = CALL;
lib/libc/rpc/rpc_prot.c:214:	    xdr_enum(xdrs, (enum_t *) prm_direction) &&
lib/libc/rpc/clnt_vc.c:268:	call_msg.rm_direction = CALL;
lib/libc/rpc/clnt_raw.c:111:	call_msg.rm_direction = CALL;
lib/libc/rpc/clnt_bcast.c:375:	msg.rm_direction = CALL;
lib/libc/rpc/rpc_callmsg.c:54:	enum msg_type *prm_direction;
lib/libc/rpc/rpc_callmsg.c:74:			IXDR_PUT_ENUM(buf, cmsg->rm_direction);
lib/libc/rpc/rpc_callmsg.c:75:			if (cmsg->rm_direction != CALL) {
lib/libc/rpc/rpc_callmsg.c:108:			cmsg->rm_direction = IXDR_GET_ENUM(buf, enum msg_type);
lib/libc/rpc/rpc_callmsg.c:109:			if (cmsg->rm_direction != CALL) {
lib/libc/rpc/rpc_callmsg.c:186:	prm_direction = &cmsg->rm_direction;
lib/libc/rpc/rpc_callmsg.c:189:	    xdr_enum(xdrs, (enum_t *) prm_direction) &&
```

GREP `pattern:`:
```
crypto/openssl/include/openssl/trace.h:259: * "vararg" OSSL_TRACEV() macro has a rather weird usage pattern:
sys/cam/ctl/ctl_ioctl.h:200: * cdb_pattern:		Fill in the relevant bytes to look for in the CDB.
sys/cam/ctl/ctl_ioctl.h:216: * error_pattern:  What kind of command to act on.  See above.
sbin/ipf/ipftest/md5.h:11: **   -- Access pattern: round 2 works mod 5, round 3 works mod 3     **
contrib/llvm-project/llvm/lib/Target/ARM/ARMBaseInstrInfo.h:533:    // - argument declared in the pattern:
contrib/llvm-project/llvm/utils/TableGen/Common/GlobalISel/GlobalISelMatchTable.h:1445:/// configuration from the SelectionDAG pattern:
contrib/llvm-project/llvm/utils/TableGen/Common/GlobalISel/GlobalISelMatchTable.h:1822:/// For example, the pattern:
contrib/llvm-project/llvm/include/llvm/Support/Error.h:1012:/// This utility enables the follow pattern:
contrib/llvm-project/llvm/include/llvm/Transforms/Utils/BasicBlockUtils.h:690:// pattern:
crypto/krb5/src/lib/crypto/builtin/md5/rsa-md5.h:33:**   -- Access pattern: round 2 works mod 5, round 3 works mod 3     **
sys/contrib/dev/broadcom/brcm80211/brcmfmac/fwil_types.h:134:/* Wakeup if received matched secured pattern: */
contrib/llvm-project/libcxx/include/__ranges/lazy_split_view.h:219:        // Empty pattern: split on every element in the input range
contrib/llvm-project/libcxx/include/__ranges/lazy_split_view.h:223:        // One-element pattern: we can use `ranges::find`.
bin/ed/re.c:36:/* get_compiled_pattern: return pointer to compiled pattern from command
bin/ed/re.c:76:/* extract_pattern: copy a pattern string from the command buffer; return
contrib/bmake/var.c:2028:/* An expression based on a variable, such as $@ or ${VAR:Mpattern:Q}. */
contrib/bmake/meta.c:973:	    DEBUG1(META, "meta_oodate: ignoring pattern: %s\n", p);
contrib/sqlite3/sqlite3.c:222226:** For a non-vacuum RBU handle, if the table name matches the pattern:
contrib/sqlite3/autosetup/jimsh0.c:3650:        Jim_SetResultFormatted(interp, "couldn't compile regular expression pattern: %s", buf);
contrib/sqlite3/autosetup/jimsh0.c:3791:        Jim_SetResultFormatted(interp, "error while matching pattern: %s", buf);
contrib/sqlite3/autosetup/jimsh0.c:4021:            Jim_SetResultFormatted(interp, "error while matching pattern: %s", buf);
tools/tools/usbtest/usb_msc_test.c:1217:		    " 6) Toggle I/O pattern: <%s>\n"
tools/tools/usbtest/usbtest.c:237:		    "5) Change DTMF pattern: '%s'\n"
tools/tools/usbtest/usbtest.c:347:		    "3) Change pattern: '%s'\n"
tools/tools/usbtest/usbtest.c:566:		    "5) Change test pattern: '%s'\n"
usr.sbin/cxgbetool/cxgbetool.c:2608:			printf("filter pattern: ");
usr.sbin/cxgbetool/cxgbetool.c:2618:		printf("filter pattern: ");
contrib/byacc/reader.c:170: * Expect this pattern:
tests/sys/cddl/zfs/tests/txg_integrity/txg_integrity.c:43: *     For each IO pattern:
tests/sys/cddl/zfs/tests/txg_integrity/fsync_integrity.c:50: *     For each IO pattern:
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❓ UNCERTAIN



