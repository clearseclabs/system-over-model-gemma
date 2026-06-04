# Triage T0036: Integer Overflow/Underflow in Fragment Reassembly

- **File**: `krpc.h`
- **Verdict**: INVALID
- **Confidence**: 0% [UII→I]

---

## Finding

Integer Overflow/Underflow in Fragment Reassembly

---

## Triage rounds

### Round 1: ❓ UNCERTAIN

**🎯 Crux:** Whether the subtraction from 'cf_conn.resid' is guarded against underflow using the actual number of bytes read from the network.

The report claims an integer overflow/underflow in the 'resid' field of 'struct cf_conn' during fragment reassembly. In RPC over TCP (which 'struct cf_conn' is used for, as indicated by 'strm_stat' and 'mpending' mbufs), 'resid' tracks the bytes remaining in a record fragment. To verify if an underflow is possible and security-relevant, I need to find the code that decrements 'resid' based on the length of received data from the socket. If the code subtracts the received length from 'resid' without checking if the received length is less than or equal to 'resid', a wrap-around could occur. However, since 'resid' is used to determine how much more data to read from the stream, a typical implementation would use the smaller of (available data) and (resid). I need to locate the actual logic performing this subtraction to see if it's guarded.

CRUX: Whether the subtraction from 'cf_conn.resid' is guarded against underflow using the actual number of bytes read from the network.
GREP: resid

🔎 **Grep results:**

GREP `resid`:
```
lib/libkvm/kvm_proc.c:331:#define		pmap_resident_count(pm) ((pm)->pm_stats.resident_count)
sys/dev/isp/isp_freebsd.h:459:#define	XS_GET_RESID(ccb)	(ccb)->resid
sys/dev/isp/isp_freebsd.h:460:#define	XS_SET_RESID(ccb, r)	(ccb)->resid = r
sys/dev/isp/isp_freebsd.h:465:#define	XS_CUR_SNSLEN(ccb)	(ccb->sense_len - ccb->sense_resid)
sys/dev/isp/isp_freebsd.h:506:#define	XS_INITERR(ccb)		XS_SETERR(ccb, CAM_REQ_INPROG), ccb->sense_resid = ccb->sense_len
sys/dev/aic7xxx/aic7xxx_reg.h:277:#define ahc_mwi_residual_print(regvalue, cur_col, wrap) \
sys/dev/aic7xxx/aic7xxx_reg.h:802:#define ahc_scb_residual_sgptr_print(regvalue, cur_col, wrap) \
sys/dev/aic7xxx/aic79xx_reg.h:2230:#define ahd_scb_residual_datacnt_print(regvalue, cur_col, wrap) \
sys/dev/aic7xxx/aic79xx_reg.h:2237:#define ahd_scb_residual_sgptr_print(regvalue, cur_col, wrap) \
sys/dev/vge/if_vgereg.h:105:#define VGE_RXDESC_RESIDUECNT	0x5E	/* RX descriptor residue count */
sys/dev/qlnx/qlnxe/reg_addr.h:5202:  #define PCIEIP_REG_REG_VF_MSIX_CONTROL_VF_MSIX_TBL_SIZ_BB                                                  (0x3f<<0) // This field resides in VF only and does not exist in PF. This register controls the read value of the MSIX_CONTROL[10:0] register in the VF configuration space. A value of "00000000011" indicates a table size of 4. The value is controlled by IOV_MSIX_TBL_SIZ define in version.v
sys/dev/qlnx/qlnxe/reg_addr.h:5213:#define PCIEIP_REG_REG_PF_INITVF_BB                                                                          0x000624UL //Access:RW   DataWidth:0x20   // Register programs the first VF allocation for a PF. All the VFs within IP are assumed to reside in a contiguous space starting at VFNUM =0. This register identifies the first VFNUM location for a PF. This register exists only in a PF
sys/dev/qlnx/qlnxe/reg_addr.h:7175:  #define PCIEIP_REG_TL_IOV_VFCTL_0_VF_NEXTBUS_BB                                                            (0x1<<0) // This bit when set enables the DUT to assume that VFs are residing on a bus number that is different than the one on which the PFs reside. When this bit is enabled, VF_offset is automatically set to be greater than 256. So VFs reside on the next bus number and PCIE IP will consume multiple bus numbers. In this case VFs are accessed using Cfg Type 1 Transactions. This bit should be set if ARI is not supported in the hierarchy.
sys/dev/qlnx/qlnxe/reg_addr.h:36668:#define MISC_REG_SHARED_MEM_ADDR                                                                             0x008c20UL //Access:RW   DataWidth:0x17   // 23 bit GRC address where the scratch-pad of the MCP that is shared with the driver resides.
sys/dev/qlnx/qlnxe/reg_addr.h:40741:  #define DORQ_REG_INT_STS_IEDPM_DPM_E5                                                                      (0x1<<10) // IEDPM interrupt on abort of DpmTbl residing IEDPM doorbell, i.e. IEDPM doorbell that will eventually need DPM processing.      IEDPM doorbell abort due to:      a) Non-first payload QWord (offset other than 0) arives on IEDPM buffer which is free or      b) Non-first QWord (offset other than 0) arives on IEDPM buffer which is not free and non-contigious offset or       c) First QWord (offset 0) arives on IEDPM buffer which is not free
sys/dev/qlnx/qlnxe/reg_addr.h:40791:  #define DORQ_REG_INT_STS_WR_IEDPM_DPM_E5                                                                   (0x1<<10) // IEDPM interrupt on abort of DpmTbl residing IEDPM doorbell, i.e. IEDPM doorbell that will eventually need DPM processing.      IEDPM doorbell abort due to:      a) Non-first payload QWord (offset other than 0) arives on IEDPM buffer which is free or      b) Non-first QWord (offset other than 0) arives on IEDPM buffer which is not free and non-contigious offset or       c) First QWord (offset 0) arives on IEDPM buffer which is not free
sys/dev/qlnx/qlnxe/reg_addr.h:40816:  #define DORQ_REG_INT_STS_CLR_IEDPM_DPM_E5                                                                  (0x1<<10) // IEDPM interrupt on abort of DpmTbl residing IEDPM doorbell, i.e. IEDPM doorbell that will eventually need DPM processing.      IEDPM doorbell abort due to:      a) Non-first payload QWord (offset other than 0) arives on IEDPM buffer which is free or      b) Non-first QWord (offset other than 0) arives on IEDPM buffer which is not free and non-contigious offset or       c) First QWord (offset 0) arives on IEDPM buffer which is not free
sys/cam/scsi/scsi_sa.c:455:#define	last_io_resid	errinfo._last_io_resid
sys/cam/scsi/scsi_sa.c:458:#define	last_ctl_resid	errinfo._last_ctl_resid
sys/sys/resource.h:106:#define	RLIMIT_RSS	5		/* resident set size */
sys/contrib/openzfs/lib/libspl/include/sys/uio.h:81:#define	zfs_uio_resid(uio)		(uio)->uio_resid
sys/contrib/openzfs/include/os/freebsd/spl/sys/uio.h:67:#define	zfs_uio_resid(u)	GET_UIO_STRUCT(u)->uio_resid
sys/contrib/openzfs/include/os/linux/spl/sys/uio.h:93:#define	zfs_uio_resid(u)		(u)->uio_resid
sys/vm/pmap.h:170:#define	pmap_resident_count(pm)	((pm)->pm_stats.resident_count)
sys/netinet/sctp_sysctl.h:421:#define SCTPCTL_MIN_RESIDUAL_DESC	"Minimum residual data chunk in second part of split"
crypto/openssh/ssh_namespace.h:976:#define sshsk_free_resident_keys		Fssh_sshsk_free_resident_keys
crypto/openssh/ssh_namespace.h:977:#define sshsk_load_resident			Fssh_sshsk_load_resident
stand/efi/include/amd64/pe.h:51:    UINT16   ne_cbnrestab;                // Size of non-resident name table
stand/efi/include/amd64/pe.h:54:    UINT16   ne_restab;                   // Offset of resident name table
stand/efi/include/amd64/pe.h:57:    UINT32   ne_nrestab;                  // Offset of Non-resident Names Table
```

### Round 2: ❌ INVALID

**🎯 Crux:** No code implementing the subtraction or manipulation of `cf_conn.resid` was found in the GREP results; the results only show unrelated symbols from other drivers.

The vulnerability report claims an integer overflow/underflow in the `resid` field of `struct cf_conn`. However, the provided GREP results for 'resid' fail to show any implementation code related to the RPC fragment reassembly logic mentioned in the report. Instead, the results show unrelated definitions from SCSI drivers (`isp`, `aic7xxx`), ZFS (`zfs_uio_resid`), and other kernel components. There is no evidence in the provided codebase snippet or GREP results that `cf_conn.resid` is ever manipulated via subtraction from untrusted input. Without the actual implementation logic (which would likely be in a `.c` file handling the `cf_conn` structure, such as a TCP-based RPC transport driver), the claim that a wrap-around is possible is unsupported. Since the 'bug pattern' cannot be found in the provided code and the GREP results are irrelevant to the RPC logic, this is a false positive based on the available evidence.

CRUX: No code implementing the subtraction or manipulation of `cf_conn.resid` was found in the GREP results; the results only show unrelated symbols from other drivers.
GREP: cf_conn

🔎 **Grep results:**

GREP `cf_conn`:
```
(no matches in repo)
```

### Round 3: ❌ INVALID

**🎯 Crux:** The implementation logic that manipulates `cf_conn.resid` is missing from the provided codebase/grep results, meaning the bug pattern cannot be verified as real.

The vulnerability report claims an integer overflow/underflow in the `resid` field of `struct cf_conn`. Looking at the provided header `krpc.h`, `struct cf_conn` is indeed defined with a `uint32_t resid` field. However, the provided grep results for `cf_conn` returned no matches in the repository, and previous greps for `resid` only found unrelated SCSI and ZFS code. Without the actual implementation code where `resid` is modified, it is impossible to verify the bug pattern. More importantly, the previous reviewer's attempt to grep for `cf_conn` failed entirely, suggesting that either the structure is not used in the provided codebase or is defined in a way that the scanner's reported vulnerability cannot be mapped to actual reachable code. Based on the strict rules, if the bug pattern cannot be found in the code, it must be marked INVALID. I cannot assume the existence of a bug based on a header definition alone without the corresponding logic.

CRUX: The implementation logic that manipulates `cf_conn.resid` is missing from the provided codebase/grep results, meaning the bug pattern cannot be verified as real.
GREP: cf_conn

🔎 **Grep results:**

GREP `cf_conn`:
```
(no matches in repo)
```

### Round 4: ❌ INVALID

[ARBITER] The vulnerability report identifies a potential integer underflow in the 'resid' field of 'struct cf_conn'. While 'struct cf_conn' and the 'resid' field exist in the provided header file (krpc.h), no implementation code was provided that demonstrates how this field is manipulated. The GREP results provided in the analysis rounds show that 'cf_conn' does not appear elsewhere in the codebase, and 'resid' matches were found only in unrelated drivers (SCSI, ZFS). Without the logic that performs the subtraction, there is no evidence of a bug, let alone a security vulnerability.

