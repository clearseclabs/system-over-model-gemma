# Triage T0059: Use‑after‑free race between clnt_vc_destroy and clnt_vc_dotlsupcall

- **File**: `clnt_vc.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI]

---

## Finding

Use‑after‑free race between clnt_vc_destroy and clnt_vc_dotlsupcall

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** clnt_vc_destroy waits for the TLS upcall thread to finish by blocking on the RPCRCVSTATE_UPCALLTHREAD flag before freeing ct, preventing a use‑after‑free race.

The code carefully synchronizes the client handle teardown with the auxiliary TLS upcall kthread.  In clnt_vc_destroy the client first calls clnt_vc_close, which stops all pending RPCs and sets the ct->ct_closed flag.  After that the function acquires ct->ct_lock, records the back‑channel pointer, and then waits on the ct_rcvstate bit RPCRCVSTATE_UPCALLTHREAD.  The upcall kthread (clnt_vc_dotlsupcall) sets this bit at entry, clears it just before exiting the loop that terminates when ct->ct_closed becomes TRUE, and then unlocks and exits.  Because clnt_vc_destroy blocks until that flag is cleared, ct is still allocated when the thread runs; ct is only freed after the thread has finished its loop.  No other path frees ct while the thread can still run, and the thread never dereferences ct after the destroy routine unlocks and frees it.  Therefore the alleged use‑after‑free race cannot materialise.

No additional defensive checks are required; the race prevention is inherent in the wait loop.  Many simpler bugs (e.g., missing NULL checks) exist, but they are internal-to‑kernel and not attacker‑reachable.

Verdict: INVALID.

CRUX: clnt_vc_destroy waits for the TLS upcall thread to finish by blocking on the RPCRCVSTATE_UPCALLTHREAD flag before freeing ct, preventing a use‑after‑free race.
GREP: RPCRCVSTATE_UPCALLTHREAD

🔎 **Grep results:**

GREP `RPCRCVSTATE_UPCALLTHREAD`:
```
sys/rpc/krpc.h:97:#define RPCRCVSTATE_UPCALLTHREAD	0x40	/* Upcall kthread running. */
sys/rpc/clnt_vc.c:870:	while ((ct->ct_rcvstate & RPCRCVSTATE_UPCALLTHREAD) != 0)
sys/rpc/clnt_vc.c:1267:	ct->ct_rcvstate |= RPCRCVSTATE_UPCALLTHREAD;
sys/rpc/clnt_vc.c:1295:	ct->ct_rcvstate &= ~RPCRCVSTATE_UPCALLTHREAD;
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** The TLS upcall thread is always joined before the ct_data structure is freed; the destroy function waits on the RPCRCVSTATE_UPCALLTHREAD bit, guaranteeing no post‑free access.

The code path exercised by an attacker starts in a user‑space process that creates an RPC client with clnt_vc_create() and eventually calls clnt_destroy() (which internally invokes clnt_vc_destroy()). The client’s TLS upcall kernel thread (clnt_vc_dotlsupcall) is started only when the caller sets the TLS state via CLSET_TLS (ct->ct_tlsstate == RPCTLS_COMPLETE). During the teardown sequence: 1) clnt_vc_destroy() calls clnt_vc_close() which sets ct->ct_closed = TRUE and wakes the upcall thread via wakeup(&ct->ct_tlsstate). 2) The upcall thread, holding the same ct_lock, observes !ct_closed, exits its loop, clears the RPCRCVSTATE_UPCALLTHREAD bit, wakes the destroy thread with wakeup(&ct->ct_tlsstate), and then exits. 3) clnt_vc_destroy() waits on that bit; it loops while ((ct->ct_rcvstate & RPCRCVSTATE_UPCALLTHREAD) != 0) msleep(&ct->ct_tlsstate,...). Once the bit is cleared, the destroy thread unlocks ct_lock, destroys the lock, and frees ct. The upcall thread is guaranteed to have terminated before this point, so it never dereferences ct after it is freed. No other path frees ct while the thread can still be running, and no unprotected access to ct fields occurs after the destroy routine releases the lock. Since the upcall thread is fully synchronized with the client teardown, there is no use‑after‑free race exploitable by an attacker. Therefore the reported vulnerability is a false positive.

CRUX: The TLS upcall thread is always joined before the ct_data structure is freed; the destroy function waits on the RPCRCVSTATE_UPCALLTHREAD bit, guaranteeing no post‑free access.
GREP: RPCRCVSTATE_UPCALLTHREAD

🔎 **Grep results:**

GREP `RPCRCVSTATE_UPCALLTHREAD`:
```
sys/rpc/krpc.h:97:#define RPCRCVSTATE_UPCALLTHREAD	0x40	/* Upcall kthread running. */
sys/rpc/clnt_vc.c:870:	while ((ct->ct_rcvstate & RPCRCVSTATE_UPCALLTHREAD) != 0)
sys/rpc/clnt_vc.c:1267:	ct->ct_rcvstate |= RPCRCVSTATE_UPCALLTHREAD;
sys/rpc/clnt_vc.c:1295:	ct->ct_rcvstate &= ~RPCRCVSTATE_UPCALLTHREAD;
```

