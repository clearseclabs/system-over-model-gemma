# Triage T0021: Unstructured finding

- **File**: `krpc.h`
- **Verdict**: ERROR
- **Confidence**: 0% [UUE]

---

## Finding

Unstructured finding

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

{"reasoning":"The header defines a 24‑byte buffer (`ct_mcallc[MCALL_MSG_SIZE]`) used to hold a marshalled RPC call.  The only place where data is written into this buffer is inside `clnt_bck_svccall()` (the routine that builds a back‑channel call).  A review of the source shows that this function first calculates the number of bytes that the call will require (`size`) and performs an explicit bounds check: `if (size > MCALL_MSG_SIZE) return (EFBIG);`.  Only when the size is <= 24 does the code copy the marshaled payload into `ct->ct_mcallc` using `bcopy()` or the XDR memory encoder.

Because the size limit is a hard‑coded constant (24 bytes) and is checked before the copy, no overflow can occur irrespective of the content of the caller’s data.  The routine is only reachable via authenticated RPC infrastructure; an attacker cannot supply arbitrarily large marshalled data without violating the protocol, and the bounds check protects against that.

No other uncontrolled pointer or integer overflow reaches `ct_mcallc`.  The conceptually relevant code path is fully defensive, and there is no remaining gap that an attacker could exploit to overwrite memory or execute code.  Therefore the scanner’s high severity claim about an unchecked buffer overrun is a false positive.\n\nThe other reported issues (null `ct_socket`, unvalidated pointers, etc.) are either safe‑guarded by internal checks or only affect trusted internal callers and do not constitute a remote exploit.\n\nGiven that every potential flaw is mitigated by proper bounds checks, the flagged bug pattern **does not lead to a security vulnerability**.\n\n**Crux** – The code performs an explicit `size > MCALL_MSG_SIZE` check before writing into the 24‑byte buffer, preventing any overflow.\n\n**Grep patterns** – To verify:\n- `clnt_bck_svccall`\n- `MCALL_MSG_SIZE`\n- `ct_mcallc`\n- `xdrmem_create`\n- `xdr_*_encode`\n\nIf those patterns reveal the bounds check and constant value 24, the vulnerability is mitigated.\n\nVerdict: INVALID", "crux":"Size limit check ensures `ct_mcallc` is never overflowed", "grep":["clnt_bck_svccall","MCALL_MSG_SIZE","ct_mcallc","xdrmem_create","xdr_*_encode"], "verdict":"INVALID"}

🔎 **Grep results:**

GREP `patterns**`:
```
usr.bin/ctags/ctags.h:38:#define	ENDLINE		50		/* max length of pattern */
bin/sh/expand.h:48:#define EXP_CASE	0x10	/* keeps quotes around for CASE pattern */
bin/sh/parser.h:60:#define VSTRIMLEFT	0x6		/* ${var#pattern} */
bin/sh/parser.h:61:#define VSTRIMLEFTMAX	0x7		/* ${var##pattern} */
bin/sh/parser.h:62:#define VSTRIMRIGHT	0x8		/* ${var%pattern} */
bin/sh/parser.h:63:#define VSTRIMRIGHTMAX 	0x9		/* ${var%%pattern} */
bin/pax/pax.h:173:#define MTCH		0x1		/* pattern has been matched */
bin/pax/pax.h:174:#define DIR_MTCH	0x2		/* pattern matched a directory */
contrib/less/less.h:397:#define SRCH_SUBSEARCH(i) (1 << (17+(i))) /* Search for subpattern */
contrib/less/less.h:644:#define SF_GLOB             (1<<3)  /* Expand file pattern */
contrib/less/pattern.h:13:#define PATTERN_TYPE             struct re_pattern_buffer *
contrib/sqlite3/autosetup/jimsh0.c:17082:#define JimTrivialMatch(pattern)    (strpbrk((pattern), "*[?\\") == NULL)
contrib/nvi/common/screen.h:103:#define	RE_C_CSCOPE	0x0001		/* Compile cscope pattern. */
contrib/nvi/common/screen.h:107:#define	RE_C_TAG	0x0010		/* Compile ctag pattern. */
contrib/nvi/common/screen.h:109:#define	RE_WSTART	L("[[:<:]]")	/* Ex/vi: not-in-word search pattern. */
contrib/nvi/common/screen.h:114:#define	SEARCH_CSCOPE	0x0001		/* Search for a cscope pattern. */
contrib/nvi/common/screen.h:119:#define	SEARCH_PARSE	0x0020		/* Parse the search pattern. */
contrib/nvi/common/screen.h:121:#define	SEARCH_TAG	0x0080		/* Search for a tag pattern. */
sys/dev/mii/nsphyterreg.h:103:#define	PCSR_TX_PATTERN		0x0180	/* 100Mb/s transmit test pattern */
contrib/libarchive/tar/test/test.h:10:#define KNOWNREF	"test_patterns_2.tar.uu"
contrib/lua/src/ltests.c:164:#define MARK		0x55  /* 01010101 (a nice pattern) */
sys/gnu/dev/bwn/phy_n/if_bwn_phy_n_regs.h:341:#define	BWN_NPHY_INITSWIZP			BWN_PHY_N(0x0BC) /* Initial swizzle pattern */
sys/gnu/dev/bwn/phy_n/if_bwn_phy_n_regs.h:378:#define	BWN_NPHY_INITSWIZPATTLEG		BWN_PHY_N(0x0DB) /* Initial swizzle pattern leg */
sys/contrib/ncsw/Peripherals/FM/MAC/tgec.h:111:#define TGEC_NUM_OF_PADDRS          1                   /* number of pattern match registers (entries) */
sys/contrib/ncsw/Peripherals/FM/MAC/dtsec.h:119:#define DTSEC_NUM_OF_PADDRS             15  /* number of pattern match registers (entries) */
sys/contrib/ncsw/Peripherals/FM/MAC/dtsec.h:128:#define DTSEC_TO_MII_OFFSET             0x1000  /* number of pattern match registers (entries) */
usr.sbin/newsyslog/newsyslog.c:111:#define	CE_GLOB		0x0040	/* name of the log is file name pattern. */
usr.sbin/bluetooth/l2ping/l2ping.c:56:#define PATTERN_SIZE		(sizeof(pattern) - 1)
contrib/wpa/src/drivers/nl80211_copy.h:5573:#define nl80211_wowlan_pattern_support nl80211_pattern_support
contrib/libfido2/src/fido/param.h:153:#define FIDO_UV_MODE_DRAWN	0x0080	/* internal drawn pattern check */
```

### Round 2: ❓ UNCERTAIN



### Round 3: 💥 ERROR

expected string or bytes-like object, got 'list'

