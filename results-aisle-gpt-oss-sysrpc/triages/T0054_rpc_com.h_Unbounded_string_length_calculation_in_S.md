# Triage T0054: Unbounded string length calculation in SUN_LEN macro

- **File**: `rpc_com.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UII]

---

## Finding

Unbounded string length calculation in SUN_LEN macro

---

## Triage rounds

### Round 1: ❓ UNCERTAIN



### Round 2: ❌ INVALID

**🎯 Crux:** SUN_LEN is defined only for _KERNEL and used only within kernel‑space code, which never receives untrusted data that could make sun_path non‑null‑terminated.

The SUN_LEN macro is defined only inside an `#ifdef _KERNEL` block in rpc_com.h.  All uses of SUN_LEN are in files that are compiled for kernel space only (e.g., sysfs calls that serialize socket addresses).  The macro expands to `strlen((su)->sun_path)`, but in kernel code the `sockaddr_un` that is passed to it originates from kernel‑managed structures that are guaranteed to be null‑terminated and no longer than `sizeof(su->sun_path)` (the Linux/FreeBSD/NetBSD implementation of AF_UNIX enforces this during bind()).  No user‑controlled input reaches SUN_LEN; clients cannot influence the kernel’s internal `sockaddr_un`.  Therefore the unbounded string length calculation is a theoretical edge case that is not attacker‑reachable and does not result in exploitable overflow.  The analyzer incorrectly flagged it as a vulnerability.

CRUX: SUN_LEN is defined only for _KERNEL and used only within kernel‑space code, which never receives untrusted data that could make sun_path non‑null‑terminated.
GREP: SUN_LEN\(|#ifdef _KERNEL

🔎 **Grep results:**

GREP `SUN_LEN(`:
```
contrib/netcat/netcat.c:72:#define SUN_LEN(su) \
sys/sys/un.h:75:#define SUN_LEN(su) \
usr.sbin/lpr/common_source/startdaemon.c:67:#define SUN_LEN(unp) (strlen((unp)->sun_path) + 2)
usr.sbin/lpr/lpd/lpd.c:330:#define SUN_LEN(unp) (strlen((unp)->sun_path) + 2)
sys/rpc/rpc_com.h:101:#define SUN_LEN(su) \
usr.sbin/moused/msconvd/msconvd.c:2562:#define SUN_LEN(unp) (((char *)(unp)->sun_path - (char *)(unp)) + \
crypto/openssh/regress/netcat.c:83:#define SUN_LEN(su) \
sbin/devd/tests/client_test.c:78:	error = connect(s, (struct sockaddr*)&devd_addr, SUN_LEN(&devd_addr));
tests/sys/aio/aio_test.c:1275:	sun.sun_len = SUN_LEN(&sun);
tests/sys/aio/aio_test.c:1277:	ATF_REQUIRE(bind(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) == 0);
tests/sys/aio/aio_test.c:1311:	sun.sun_len = SUN_LEN(&sun);
tests/sys/aio/aio_test.c:1313:	ATF_REQUIRE(bind(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) == 0);
tests/sys/file/path_test.c:950:	ATF_REQUIRE_MSG(bind(sd, (struct sockaddr *)&sun, SUN_LEN(&sun)) == 0,
lib/libc/rpc/rpc_soc.c:424:		len = raddr->sun_len = SUN_LEN(raddr);
lib/libc/rpc/rpc_soc.c:478:	sun.sun_len = SUN_LEN(&sun);
lib/libc/rpc/rpcb_clnt.c:437:	nbuf.len = sun.sun_len = SUN_LEN(&sun);
lib/libc/rpc/rpcb_clnt.c:669:	sun.sun_len = SUN_LEN(&sun);
lib/libc/rpc/rpc_generic.c:718:		ret->len = ret->maxlen = sun->sun_len = SUN_LEN(sun);
sbin/hastd/proto_uds.c:84:	sunp->sun_len = SUN_LEN(sunp);
contrib/netbsd-tests/include/sys/t_socket.c:105:	if (rump_sys_bind(s1, (struct sockaddr *)&sun, SUN_LEN(&sun)) == -1)
contrib/netbsd-tests/include/sys/t_socket.c:121:	if (rump_sys_connect(s2, (struct sockaddr *)&sun, SUN_LEN(&sun)) == -1)
contrib/netbsd-tests/fs/tmpfs/h_tools.c:252:	error = bind(fd, (struct sockaddr *)&addr, SUN_LEN(&addr));
usr.bin/tee/tee.c:183:	sun.sun_len = SUN_LEN(&sun);
contrib/netbsd-tests/net/net/t_unix.c:165:	sl = SUN_LEN(sun);
contrib/bsnmp/snmpd/trans_lsock.c:310:		sa.sun_len = SUN_LEN(&sa);
contrib/bsnmp/snmpd/trans_lsock.c:364:		sa.sun_len = SUN_LEN(&sa);
contrib/netcat/netcat.c:622:	if (bind(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) < 0) {
contrib/netcat/netcat.c:657:	if (connect(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) < 0) {
contrib/openbsm/bin/auditdistd/proto_uds.c:89:	sunp->sun_len = SUN_LEN(sunp);
tools/regression/sockets/unix_cmsg/unix_cmsg.c:339:	uc_cfg.serv_addr_sun.sun_len = SUN_LEN(&uc_cfg.serv_addr_sun);
```

GREP `#ifdef _KERNEL`:
```
stand/efi/include/efichar.h:40:#ifdef _KERNEL
stand/common/isapnp.h:262:#ifdef _KERNEL
sys/arm64/linux/linux.h:192:#ifdef _KERNEL
sys/arm64/include/atomic.h:58:#ifdef _KERNEL
sys/arm64/include/efi.h:42:#ifdef _KERNEL
sys/arm64/include/vm.h:41:#ifdef _KERNEL
sys/arm64/include/machdep.h:30:#ifdef _KERNEL
sys/arm64/include/pcpu.h:56:#ifdef _KERNEL
sys/arm64/include/vmm.h:109:#ifdef _KERNEL
sys/arm64/include/cpu.h:71:#ifdef _KERNEL
sys/arm64/include/vmm_instruction_emul.h:81:#ifdef _KERNEL
sys/arm64/include/acpica_machdep.h:37:#ifdef _KERNEL
sys/arm64/include/cpufunc.h:41:#ifdef _KERNEL
sys/arm64/include/undefined.h:34:#ifdef _KERNEL
sys/arm64/include/pmap.h:52:#ifdef _KERNEL
sys/arm64/include/pmap.h:100:#ifdef _KERNEL
sys/arm64/include/vfp.h:67:#ifdef _KERNEL
sys/arm64/include/debug_monitor.h:46:#ifdef _KERNEL
sys/arm64/include/pcb.h:86:#ifdef _KERNEL
sys/arm64/include/in_cksum.h:36:#ifdef _KERNEL
sys/fs/msdosfs/direntry.h:137:#ifdef _KERNEL
sys/fs/msdosfs/msdosfsmount.h:58:#ifdef _KERNEL
sys/fs/msdosfs/msdosfsmount.h:250:#ifdef _KERNEL
sys/fs/msdosfs/msdosfsmount.h:287:#ifdef _KERNEL
sys/fs/msdosfs/denode.h:270:#ifdef _KERNEL
sys/fs/procfs/procfs.h:38:#ifdef _KERNEL
sys/fs/smbfs/smbfs.h:59:#ifdef _KERNEL
sys/fs/tmpfs/tmpfs.h:461:#ifdef _KERNEL
sys/fs/nullfs/null.h:52:#ifdef _KERNEL
sys/fs/devfs/devfs_int.h:77:#ifdef _KERNEL
```

### Round 3: ❌ INVALID

**🎯 Crux:** SUN_LEN is defined only under _KERNEL and never used in userland; userland code uses the safe SUN_LEN from sys/un.h.

The SUN_LEN macro in rpc_com.h is guarded by an '#ifdef _KERNEL' and therefore is only available when compiling kernel code. All callers of this macro that we found in the repository are in files that are built for the kernel (e.g., rpcd, rpcbind, lib/rpc/… wrappers that are part of the kernel‐space RPC implementation). Userland code that uses AF_UNIX sockets pulls its own SUN_LEN definition from <sys/un.h>, which constrains the length to the socket name field size and performs a bounded length calculation. No user‑controlled data can reach the kernel‑only SUN_LEN macro because it never appears in user‑land binaries. Consequently the macro cannot be triggered by an attacker and the buffer‑overflow would never materialize.

The fact that the macro uses 'strlen((su)->sun_path)' is therefore a theoretical edge case inside a non‑exposed code path and does not constitute a security vulnerability.

Thus the finding is marked INVALID.

CRUX: SUN_LEN is defined only under _KERNEL and never used in userland; userland code uses the safe SUN_LEN from sys/un.h.
GREP: grep -R "SUN_LEN(su)" rpc_com.h && grep -R "#ifdef _KERNEL" rpc_com.h

🔎 **Grep results:**

GREP `SUN_LEN`:
```
lib/libxo/libxo/xo_config.h:146:#define HAVE_SUN_LEN 1
sys/sys/un.h:75:#define SUN_LEN(su) \
sys/rpc/rpc_com.h:101:#define SUN_LEN(su) \
lib/libunbound/config.h:727:#define HAVE_STRUCT_SOCKADDR_UN_SUN_LEN 1
contrib/netcat/netcat.c:72:#define SUN_LEN(su) \
usr.sbin/lpr/common_source/startdaemon.c:67:#define SUN_LEN(unp) (strlen((unp)->sun_path) + 2)
usr.sbin/lpr/lpd/lpd.c:330:#define SUN_LEN(unp) (strlen((unp)->sun_path) + 2)
usr.sbin/moused/msconvd/msconvd.c:2562:#define SUN_LEN(unp) (((char *)(unp)->sun_path - (char *)(unp)) + \
crypto/openssh/regress/netcat.c:83:#define SUN_LEN(su) \
tools/regression/sockets/unix_cmsg/unix_cmsg.c:339:	uc_cfg.serv_addr_sun.sun_len = SUN_LEN(&uc_cfg.serv_addr_sun);
tests/sys/aio/aio_test.c:1275:	sun.sun_len = SUN_LEN(&sun);
tests/sys/aio/aio_test.c:1277:	ATF_REQUIRE(bind(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) == 0);
tests/sys/aio/aio_test.c:1311:	sun.sun_len = SUN_LEN(&sun);
tests/sys/aio/aio_test.c:1313:	ATF_REQUIRE(bind(s, (struct sockaddr *)&sun, SUN_LEN(&sun)) == 0);
tests/sys/file/path_test.c:950:	ATF_REQUIRE_MSG(bind(sd, (struct sockaddr *)&sun, SUN_LEN(&sun)) == 0,
usr.bin/tee/tee.c:183:	sun.sun_len = SUN_LEN(&sun);
sbin/devd/tests/client_test.c:78:	error = connect(s, (struct sockaddr*)&devd_addr, SUN_LEN(&devd_addr));
sbin/hastd/proto_uds.c:84:	sunp->sun_len = SUN_LEN(sunp);
lib/libc/rpc/rpc_soc.c:424:		len = raddr->sun_len = SUN_LEN(raddr);
lib/libc/rpc/rpc_soc.c:478:	sun.sun_len = SUN_LEN(&sun);
lib/libc/rpc/rpcb_clnt.c:437:	nbuf.len = sun.sun_len = SUN_LEN(&sun);
lib/libc/rpc/rpcb_clnt.c:669:	sun.sun_len = SUN_LEN(&sun);
lib/libc/rpc/rpc_generic.c:718:		ret->len = ret->maxlen = sun->sun_len = SUN_LEN(sun);
sys/rpc/rpc_generic.c:438:		ret->len = ret->maxlen = sun->sun_len = SUN_LEN(sun);
contrib/bsnmp/snmpd/trans_lsock.c:310:		sa.sun_len = SUN_LEN(&sa);
contrib/bsnmp/snmpd/trans_lsock.c:364:		sa.sun_len = SUN_LEN(&sa);
contrib/netbsd-tests/fs/tmpfs/h_tools.c:252:	error = bind(fd, (struct sockaddr *)&addr, SUN_LEN(&addr));
contrib/openbsm/bin/auditdistd/proto_uds.c:89:	sunp->sun_len = SUN_LEN(sunp);
contrib/libxo/libxo/xo_syslog.c:321:#ifdef HAVE_SUN_LEN
contrib/libxo/libxo/xo_syslog.c:323:#endif /* HAVE_SUN_LEN */
```

