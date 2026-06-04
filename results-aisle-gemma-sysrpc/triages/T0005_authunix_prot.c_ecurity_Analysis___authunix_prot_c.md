# Triage T0005: ecurity Analysis: `authunix_prot.c`

- **File**: `authunix_prot.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

ecurity Analysis: `authunix_prot.c`

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` prevents writing beyond the bounds of the `cr_sgroups` array regardless of the value of `supp_ngroups`.

The vulnerability scanner is suggesting a buffer overflow in the loop that processes supplementary groups. However, the code contains an explicit bounds check inside the loop: `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk`. This ternary operator ensures that any group index beyond the capacity of the `cr_sgroups` array is written to a local stack variable `junk` instead of the `cred` structure. Additionally, there is a pre-loop check `if (xdrs->x_op != XDR_ENCODE && supp_ngroups > AUTH_SYS_MAX_GROUPS) return (FALSE);`. Even if `AUTH_SYS_MAX_GROUPS` were larger than `XU_NGROUPS`, the ternary operator prevents the overflow. The missing NULL check on `cred` is an internal API issue as `xdr_authunix_parms` is called by the RPC framework with allocated structures, and the logic provided for the overflow is explicitly defended against.

CRUX: The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` prevents writing beyond the bounds of the `cr_sgroups` array regardless of the value of `supp_ngroups`.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
sys/sys/ucred.h:104:#define	XU_NGROUPS	16
sys/contrib/openzfs/include/os/freebsd/spl/sys/vfs.h:61:#define	XU_NGROUPS	16
sys/sys/ucred.h:128:			gid_t	cr_sgroups[XU_NGROUPS - 1];
sys/sys/ucred.h:130:		gid_t	cr_groups[XU_NGROUPS];	/* groups */
sys/fs/nfsserver/nfs_nfsdport.c:4310:			if (export.export.ex_ngroups > XU_NGROUPS ||
sys/rpc/authunix_prot.c:109:		MPASS(cred->cr_ngroups <= XU_NGROUPS);
sys/rpc/authunix_prot.c:120:	 * Because we cannot store more than XU_NGROUPS in total (16 at time of
sys/rpc/authunix_prot.c:125:	 * size limits.  Although AUTH_SYS_MAX_GROUPS and XU_NGROUPS are equal,
sys/rpc/authunix_prot.c:137:		if (!xdr_uint32_t(xdrs, i < XU_NGROUPS - 1 ?
sys/rpc/authunix_prot.c:142:		cred->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/rpc/svc_auth_unix.c:112:			if (i < XU_NGROUPS - 1)
sys/rpc/svc_auth_unix.c:117:		xcr->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/kern/vfs_mount.c:1499:				if (export.ex_ngroups <= XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:73:	if (xucred->cr_ngroups > XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:75:		    xucred->cr_ngroups, XU_NGROUPS);
```

### Round 2: ❌ INVALID

**🎯 Crux:** The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` explicitly prevents writing beyond the bounds of the `cr_sgroups` array, regardless of the value of `supp_ngroups` provided by the attacker.

The reported vulnerability concerns a potential buffer overflow when decoding supplementary groups. The code implements two defenses. First, it checks if `supp_ngroups > AUTH_SYS_MAX_GROUPS`. Second, and more critically, inside the loop that reads the group IDs, it uses a ternary operator: `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk`. This ensures that any index `i` that is not strictly less than `XU_NGROUPS - 1` results in the value being written to a local stack variable `junk` rather than the `cred->cr_sgroups` array. Based on the grep results, `XU_NGROUPS` is defined as 16 and `struct xucred` defines `cr_sgroups` as `gid_t cr_sgroups[XU_NGROUPS - 1]`, which is 15 elements. The loop index `i` starts at 0; thus, the valid indices are 0 through 14. The ternary operator correctly protects this boundary. The missing NULL check on `cred` is not a security vulnerability in this context as it is an internal XDR helper called by the RPC framework which manages the lifecycle of the authentication credentials. No other dangerous data flows or integer overflows are present that could bypass these checks.

CRUX: The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` explicitly prevents writing beyond the bounds of the `cr_sgroups` array, regardless of the value of `supp_ngroups` provided by the attacker.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
sys/sys/ucred.h:104:#define	XU_NGROUPS	16
sys/contrib/openzfs/include/os/freebsd/spl/sys/vfs.h:61:#define	XU_NGROUPS	16
sys/sys/ucred.h:128:			gid_t	cr_sgroups[XU_NGROUPS - 1];
sys/sys/ucred.h:130:		gid_t	cr_groups[XU_NGROUPS];	/* groups */
sys/rpc/authunix_prot.c:109:		MPASS(cred->cr_ngroups <= XU_NGROUPS);
sys/rpc/authunix_prot.c:120:	 * Because we cannot store more than XU_NGROUPS in total (16 at time of
sys/rpc/authunix_prot.c:125:	 * size limits.  Although AUTH_SYS_MAX_GROUPS and XU_NGROUPS are equal,
sys/rpc/authunix_prot.c:137:		if (!xdr_uint32_t(xdrs, i < XU_NGROUPS - 1 ?
sys/rpc/authunix_prot.c:142:		cred->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/rpc/svc_auth_unix.c:112:			if (i < XU_NGROUPS - 1)
sys/rpc/svc_auth_unix.c:117:		xcr->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/fs/nfsserver/nfs_nfsdport.c:4310:			if (export.export.ex_ngroups > XU_NGROUPS ||
sys/kern/vfs_mount.c:1499:				if (export.ex_ngroups <= XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:73:	if (xucred->cr_ngroups > XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:75:		    xucred->cr_ngroups, XU_NGROUPS);
```

### Round 3: ❌ INVALID

**🎯 Crux:** The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` ensures that only indices 0-14 are written to the 15-element `cr_sgroups` array, diverting all subsequent writes to a local variable.

I have analyzed the `xdr_authunix_parms` function and the previous reviews. The core concern is whether an attacker-controlled `supp_ngroups` value can lead to a buffer overflow in `cred->cr_sgroups`. 

1. **Buffer Definition**: Grep results confirm `XU_NGROUPS` is 16. `struct xucred` defines `cr_sgroups` as `gid_t cr_sgroups[XU_NGROUPS - 1]`, meaning the array has exactly 15 elements (indices 0 to 14).
2. **The Loop**: The loop `for (i = 0; i < supp_ngroups; ++i)` processes the supplementary groups. 
3. **The Defense**: Inside the loop, the destination address for `xdr_uint32_t` is determined by a ternary operator: `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk`. 
   - For `i = 0` through `14`, the condition `i < 15` is true, and data is written to `&cred->cr_sgroups[0]` through `&cred->cr_sgroups[14]`. This perfectly fills the 15-element array.
   - For `i >= 15`, the condition is false, and data is written to the local variable `junk` on the stack.
4. **Input Reachability**: While `supp_ngroups` is attacker-controlled and can be up to `AUTH_SYS_MAX_GROUPS` (or potentially larger if `AUTH_SYS_MAX_GROUPS` is large), the ternary operator provides an absolute boundary check that is independent of the `supp_ngroups` value itself. 
5. **Other Considerations**: The missing NULL check on `cred` is a quality issue as it's an internal helper; `xdrs` is checked implicitly via `x_op` (though a NULL `xdrs` would crash, it's typically managed by the XDR dispatcher). There are no integer overflows in the arithmetic `supp_ngroups + 1` that could lead to security issues because it is wrapped in a `MIN(..., XU_NGROUPS)` call before being assigned to `cred->cr_ngroups`.

CRUX: The ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` ensures that only indices 0-14 are written to the 15-element `cr_sgroups` array, diverting all subsequent writes to a local variable.
GREP: XU_NGROUPS

🔎 **Grep results:**

GREP `XU_NGROUPS`:
```
sys/sys/ucred.h:104:#define	XU_NGROUPS	16
sys/contrib/openzfs/include/os/freebsd/spl/sys/vfs.h:61:#define	XU_NGROUPS	16
sys/sys/ucred.h:128:			gid_t	cr_sgroups[XU_NGROUPS - 1];
sys/sys/ucred.h:130:		gid_t	cr_groups[XU_NGROUPS];	/* groups */
sys/fs/nfsserver/nfs_nfsdport.c:4310:			if (export.export.ex_ngroups > XU_NGROUPS ||
sys/rpc/authunix_prot.c:109:		MPASS(cred->cr_ngroups <= XU_NGROUPS);
sys/rpc/authunix_prot.c:120:	 * Because we cannot store more than XU_NGROUPS in total (16 at time of
sys/rpc/authunix_prot.c:125:	 * size limits.  Although AUTH_SYS_MAX_GROUPS and XU_NGROUPS are equal,
sys/rpc/authunix_prot.c:137:		if (!xdr_uint32_t(xdrs, i < XU_NGROUPS - 1 ?
sys/rpc/authunix_prot.c:142:		cred->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/rpc/svc_auth_unix.c:112:			if (i < XU_NGROUPS - 1)
sys/rpc/svc_auth_unix.c:117:		xcr->cr_ngroups = MIN(supp_ngroups + 1, XU_NGROUPS);
sys/kern/vfs_mount.c:1499:				if (export.ex_ngroups <= XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:73:	if (xucred->cr_ngroups > XU_NGROUPS) {
tools/regression/sockets/unix_cmsg/t_peercred.c:75:		    xucred->cr_ngroups, XU_NGROUPS);
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability is a buffer overflow in the supplementary groups loop. However, the code uses a ternary operator `i < XU_NGROUPS - 1 ? &cred->cr_sgroups[i] : &junk` which explicitly prevents any write beyond the bounds of the `cr_sgroups` array. Since `XU_NGROUPS` is 16 and `cr_sgroups` is defined as `gid_t cr_sgroups[XU_NGROUPS - 1]` (15 elements), the condition `i < 15` correctly limits writes to indices 0-14. Any values beyond that are written to the local variable `junk`, effectively neutralizing the overflow.

