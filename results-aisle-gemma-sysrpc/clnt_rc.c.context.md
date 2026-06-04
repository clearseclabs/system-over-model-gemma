# Context: clnt_rc.c

This briefing covers `clnt_rc.c`, which implements a reconnection wrapper for RPC clients in the kernel.

### 1. Functionality and Location
This code provides a "reconnect" layer for RPC clients. Instead of a direct connection, it wraps a `CLIENT` handle and automatically attempts to re-establish the underlying transport connection (TCP/UDP/TLS) via `clnt_reconnect_connect` if a call fails or the connection is lost. It sits between the high-level RPC caller and the actual transport-specific client implementations (`clnt_dg` or `clnt_vc`).

### 2. Untrusted Input Path
Input reaches this code via:
*   **Network:** Indirectly through `CLNT_CALL_MBUF` $\rightarrow$ transport layer $\rightarrow$ network.
*   **API/Control:** The `clnt_reconnect_control` function is a primary entry point for configuring the client, potentially receiving data from system calls or other kernel modules.

### 3. Attacker-Controlled Data Flow
Data enters via `clnt_reconnect_control(CLIENT *cl, u_int request, void *info)`.
*   **`info`**: The primary attacker-controlled pointer.
    *   `CLSET_TLSCERTNAME` $\rightarrow$ `info` (string) $\rightarrow$ `rc->rc_tlscertname`.
    *   `CLSET_TIMEOUT` $\rightarrow$ `info` (struct timeval) $\rightarrow$ `rc->rc_timeout`.
    *   `CLSET_VERS`/`PROG` $\rightarrow$ `info` (uint32_t) $\rightarrow$ `rc->rc_vers`/`rc->rc_prog`.

### 4. Fixed-Size Buffers & Constants
No fixed-size arrays are declared in this file. It uses dynamic allocation (`mem_alloc`) and `struct` members.
*   **`NAME_MAX`**: Used in `CLSET_TLSCERTNAME` to limit string length. 
    GREP: `NAME_MAX` (Typically 255 in FreeBSD/similar).

### 5. Dangerous Data Flows
*   **Source:** `info` (pointer) $\rightarrow$ **Destination:** `rc->rc_tlscertname` (heap buffer) via `strlcpy` in `clnt_reconnect_control`. The buffer size is calculated as `strlen(info) + 1`.

### 6. NULL Dereferences
*   **`info`**: Checked at the start of `clnt_reconnect_control`.
*   **`rc->rc_client`**: Frequently checked before use, but `clnt_reconnect_freeres` explicitly assumes it is valid.

### 7. Tagged Unions/Variants
No tagged unions are used in this file.

### 8. API vs Helpers
*   **Public API:** `clnt_reconnect_create` (creates the wrapper).
*   **Static Helpers:** All `clnt_reconnect_ops` implementations (e.g., `clnt_reconnect_call`, `clnt_reconnect_connect`). These are called via the `CLIENT` ops table.

### 9. Likely Bug Classes
*   **Race Conditions:** Complex locking/unlocking around `rc->rc_lock` and `rc->rc_connecting` during reconnection.
*   **Use-After-Free:** Management of `rc->rc_client` references (`CLNT_ACQUIRE`/`CLNT_RELEASE`) across multiple threads.
*   **Integer Overflows:** Possible in `slen = strlen(info) + 1` if `info` is not properly null-terminated (though `strlen` would fail first).

[GREP RESULTS from codebase]:
GREP `NAME_MAX` (Typically 255 in FreeBSD/similar). (simplified to: Typically)`:
```
sys/dev/qlnx/qlnxe/reg_addr.h:4859:  #define PCIEIP_REG_PCIEEP_VSECST_CTL_STATUS_E5                                                             (0xff<<0) // Indicates status of internal core logic to host software driver. Typically 0x0 would indicate to the host driver that CNXXXX firmware is not loaded, and non-zero values indicate some software-defined post-firmware loaded state information or failure code.   This register will be reset on a core reset. This register is not RSL-writable (always reads 0x0 from host) for all PFs other than PF0.
sys/dev/qlnx/qlnxe/reg_addr.h:71195:  #define MCP_REG_MCP_HEARTBEAT_MCP_HEARTBEAT_INC                                                            (0x1<<30) // When set this bit causes MCP heartbeat counter to increment. Typically used by the MCP.
sys/dev/qlnx/qlnxe/reg_addr.h:71197:  #define MCP_REG_MCP_HEARTBEAT_MCP_HEARTBEAT_RESET                                                          (0x1<<31) // When set this bit resets the heartbeat counter. Typically used by the MCP or the driver.
sys/dev/qlnx/qlnxe/reg_addr.h:71202:  #define MCP_REG_WATCHDOG_RESET_WATCHDOG_2_RESET                                                            (0x1<<30) // When set this bit resets the watchdog timer #2. Typically used by the MCP or the driver.
sys/dev/qlnx/qlnxe/reg_addr.h:71204:  #define MCP_REG_WATCHDOG_RESET_WATCHDOG_RESET                                                              (0x1<<31) // When set this bit resets the watchdog timer #1. Typically used by the MCP or the driver.
sys/dev/qlnx/qlnxe/reg_addr.h:71209:  #define MCP_REG_WATCHDOG_CONTROL_WATCHDOG_2_ENABLE                                                         (0x1<<27) // When set this bit enables watchdog timer #2. Typically used by the driver
sys/dev/qlnx/qlnxe/reg_addr.h:71217:  #define MCP_REG_WATCHDOG_CONTROL_WATCHDOG_ENABLE                                                           (0x1<<31) // When set this bit enables watchdog timer #1. Typically used by the driver.
sys/contrib/edk2/Include/IndustryStandard/Usb.h:28:#define USB_MASS_STORE_QIC    0x03   ///< Typically a tape device
sys/contrib/edk2/Include/IndustryStandard/Usb.h:29:#define USB_MASS_STORE_UFI    0x04   ///< Typically a floppy disk driver device
usr.sbin/fstyp/hammer2_disk.h:729:		 *	     restrictive).  Typically only radix values
usr.sbin/fstyp/hammer2_disk.h:890: *	     Typically integrated with the blockref type in the upper 8 bits
contrib/atf/atf-c/detail/map.h:79:/* A list-based map.  Typically very inefficient, but our maps are small
contrib/libxo/libxo/xo.h:624: * the value, but requires the caller to manage the memory.  Typically
contrib/googletest/googlemock/include/gmock/gmock-actions.h:2178:// defines an action that can be used in a mock function.  Typically,
contrib/wpa/src/drivers/nl80211_copy.h:6513: *	protocols. Typically a subset of probe-requests belonging to a
contrib/llvm-project/compiler-rt/lib/xray/xray_buffer_queue.h:49:    /// members. Typically, we want to subtract this 1 byte for sizing
contrib/llvm-project/compiler-rt/lib/nsan/nsan.h:185:    return 0; // Typically, -0.0 and 0.0
contrib/llvm-project/compiler-rt/lib/xray/xray_function_call_trie.h:115:    uint64_t CumulativeLocalTime; // Typically in TSC deltas, not wall-time.
contrib/llvm-project/compiler-rt/lib/ubsan/ubsan_init.h:20:// Initialize UBSan as a standalone tool. Typically should be called early
contrib/llvm-project/clang/include/clang/AST/ODRHash.h:40:// Typically, only one Add* call is needed.  clear can be called to reuse the
contrib/llvm-project/clang/include/clang/AST/Expr.h:5350:  /// Typically, this field is the first named field within the
contrib/llvm-project/clang/include/clang/AST/Type.h:7200:/// Typically the nested-name-specifier is dependent, but in MSVC compatibility
contrib/llvm-project/clang/include/clang/Driver/ToolChain.h:595:  /// Get the default debug info format. Typically, this is DWARF.
contrib/llvm-project/clang/include/clang/Serialization/ASTReader.h:200:  /// that are suggested by the preprocessor options. Typically only used when
contrib/llvm-project/clang/include/clang/Sema/Overload.h:1398:    /// Typically this should be used for reversed operator arguments
contrib/llvm-project/clang/include/clang/Sema/DeclSpec.h:1577:    /// prototype. Typically these are tag declarations.
contrib/llvm-project/clang/include/clang/Analysis/FlowSensitive/DataflowValues.h:10:// values for a CFG.  Typically this is subclassed to provide methods for
contrib/llvm-project/clang/include/clang/Analysis/FlowSensitive/DataflowAnalysisContext.h:87:  /// Typically, this is called from the constructor of a `DataflowAnalysis`
contrib/llvm-project/clang/include/clang/Lex/ModuleMap.h:439:  /// Typically, \ref findModuleForHeader should be used instead, as it picks
contrib/llvm-project/clang/lib/Basic/Targets.h:10:// from a target triple. Typically individual targets will need to include from
```