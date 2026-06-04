# Triage T0133: Race Condition / Use-After-Free in `rpc_gss_secfind`

- **File**: `rpcsec_gss/rpcsec_gss.c`
- **Verdict**: INVALID
- **Confidence**: 0% [III→I]

---

## Finding

Race Condition / Use-After-Free in `rpc_gss_secfind`

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** The `rpc_gss_lock` is held as a shared lock during the entire lookup and refcount acquisition process, and as an exclusive lock during removal from the cache, preventing the race condition described.

The reported vulnerability is a Use-After-Free (UAF) resulting from a race condition in `rpc_gss_secfind`. The eviction logic removes an object (`tgd`) from the cache (`rpc_gss_cache` and `rpc_gss_all`) and then calls `AUTH_DESTROY(tgd->gd_auth)`. `AUTH_DESTROY` calls `rpc_gss_destroy`, which performs `refcount_release(&gd->gd_refs)`. If the refcount is 1, the object is freed. 

Crucially, the lookup loop in `rpc_gss_secfind` performs `sx_slock(&rpc_gss_lock)` (shared lock) and iterates through `rpc_gss_cache[h]`. While iterating, it checks properties of `gd`. If another thread enters the eviction block, it acquires `sx_xlock(&rpc_gss_lock)` (exclusive lock). Since the lookup thread holds a shared lock, the eviction thread will block until the shared lock is released. Conversely, if the eviction thread is running, the lookup thread will block on `sx_slock`. 

However, the race occurs because the lookup thread does not hold the lock *continuously* between the time it finds the object and the time it increments the refcount? No, the `refcount_acquire(&gd->gd_refs)` is called *inside* the `TAILQ_FOREACH` loop while `sx_slock` is held. 

Wait, let's re-examine the eviction logic: 
1. `sx_xlock(&rpc_gss_lock)`
2. `TAILQ_REMOVE` from cache
3. `rpc_gss_count--`
4. `sx_xunlock(&rpc_gss_lock)`
5. `AUTH_DESTROY(tgd->gd_auth)`

The object is removed from the global lists *before* the lock is released. Once `sx_xunlock` is called, the object is no longer reachable via the cache. If a lookup thread started *before* the eviction and was already iterating the list, it would have a pointer. But the lookup thread holds `sx_slock`, which prevents the eviction thread from acquiring `sx_xlock` to remove the item. Thus, the object cannot be removed from the list while a lookup thread is iterating it. 

The only way a lookup thread could have a pointer to `gd` without holding the lock is if it already performed `refcount_acquire`. If it did, `AUTH_DESTROY` (which calls `refcount_release`) will not free the object. 

Therefore, the lock `rpc_gss_lock` correctly synchronizes the removal from the cache and the access during lookup. The refcount ensures that if the object was retrieved, it stays alive. The scanner's claim that a thread could have a pointer but not yet called `refcount_acquire` is negated by the fact that the pointer is only obtained via a list protected by the same lock used for removal.

CRUX: The `rpc_gss_lock` is held as a shared lock during the entire lookup and refcount acquisition process, and as an exclusive lock during removal from the cache, preventing the race condition described.
GREP: sx_slock

🔎 **Grep results:**

GREP `sx_slock`:
```
sys/fs/autofs/autofs.h:60:#define AUTOFS_SLOCK(X)		sx_slock(&X->am_lock)
sys/arm64/nvidia/tegra210/max77620_gpio.c:47:#define	GPIO_LOCK(_sc)	sx_slock(&(_sc)->gpio_lock)
sys/dev/syscon/syscon.c:97:#define SYSCON_TOPO_SLOCK()	sx_slock(&syscon_topo_lock)
sys/dev/clk/clk.c:170:#define CLK_TOPO_SLOCK()	sx_slock(&clk_topo_lock)
sys/dev/clk/clk.c:176:#define CLKNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/phy/phy_internal.h:69:#define PHY_TOPO_SLOCK()	sx_slock(&phynode_topo_lock)
sys/dev/phy/phy_internal.h:75:#define PHYNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/regulator/regulator.c:150:#define REG_TOPO_SLOCK()	sx_slock(&regnode_topo_lock)
sys/dev/regulator/regulator.c:156:#define REGNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/mlx5/mlx5_en/en_rl.h:53:#define	MLX5E_RL_RLOCK(rl) sx_slock(&(rl)->rl_sxlock)
sys/netpfil/ipfw/ip_fw_private.h:483:#define IPFW_UH_RLOCK(p) sx_slock(&(p)->uh_lock)
sys/arm/nvidia/as3722_gpio.c:71:#define	GPIO_LOCK(_sc)	sx_slock(&(_sc)->gpio_lock)
sys/netinet6/in6_src.c:116:#define	ADDRSEL_SLOCK()		sx_slock(&addrsel_sxlock)
sys/sys/filedesc.h:184:#define	FILEDESC_SLOCK(fdp)	sx_slock(&(fdp)->fd_sx)
sys/sys/module.h:219:#define	MOD_SLOCK	sx_slock(&modules_sx)
sys/sys/sx.h:205:#define	sx_slock_(sx, file, line)					\
sys/sys/sx.h:207:#define	sx_slock_sig_(sx, file, line)					\
sys/sys/sx.h:216:#define	sx_slock_(sx, file, line)					\
sys/sys/sx.h:218:#define	sx_slock_sig_(sx, file, line)					\
sys/sys/sx.h:237:#define	sx_slock(sx)		sx_slock_((sx), LOCK_FILE, LOCK_LINE)
sys/sys/sx.h:238:#define	sx_slock_sig(sx)	sx_slock_sig_((sx), LOCK_FILE, LOCK_LINE)
sys/sys/mount.h:1078:#define	vfsconf_slock()		sx_slock(&vfsconf_sx)
sys/netinet/netdump/netdump_client.c:126:#define NETDUMP_RLOCK()			sx_slock(&nd_conf_lk)
sys/security/audit/audit_bsm_db.c:105:#define	EVNAMEMAP_RLOCK()	sx_slock(&evnamemap_lock)
sys/kern/imgact_binmisc.c:105:#define	INTERP_LIST_RLOCK()		sx_slock(&interp_list_sx)
sys/compat/linux/linux_emul.h:76:#define	LINUX_PEM_SLOCK(p)	sx_slock(&(p)->pem_sx)
sys/compat/linuxkpi/common/include/linux/rwsem.h:44:#define	down_read(_rw)			sx_slock(&(_rw)->sx)
sys/net/if_lagg.c:86:#define	LAGG_SLOCK(_sc)		sx_slock(&(_sc)->sc_sx)
sys/net/dummymbuf.c:67:#define DMB_RULES_SLOCK()	sx_slock(&V_dmb_rules_lock)
sys/net/vnet.c:205:#define	VNET_SYSINIT_RLOCK()	sx_slock(&vnet_sysinit_sxlock);
```

### Round 2: ❌ INVALID

**🎯 Crux:** The `rpc_gss_lock` (sx_lock) ensures that an object cannot be removed from the cache lists while another thread is iterating them to acquire a reference, and the reference counting ensures the object remains valid if it was already retrieved.

The reported vulnerability is a Use-After-Free (UAF) race condition during cache eviction in `rpc_gss_secfind`. The key to the analysis is the synchronization mechanism used to protect the `rpc_gss_cache` and `rpc_gss_all` lists. 

1. **Eviction Path:** When `rpc_gss_count > RPC_GSS_MAX`, the code acquires `sx_xlock(&rpc_gss_lock)` (exclusive lock), removes the entry from the hash cache and the global LRU list, decrements the count, and then releases the lock (`sx_xunlock`). Only after releasing the lock is `AUTH_DESTROY` called, which decrements the reference count. 

2. **Lookup Path:** The lookup loop acquires `sx_slock(&rpc_gss_lock)` (shared lock). It iterates through the hash cache and, if a match is found, calls `refcount_acquire(&gd->gd_refs)` while still holding the shared lock.

3. **Race Analysis:** For a UAF to occur, a lookup thread must obtain a pointer to a `gd` object and then have that object freed before it can increment the reference count. However, the `sx_lock` (shared-exclusive lock) prevents this: 
   - If the lookup thread holds `sx_slock`, the eviction thread cannot acquire `sx_xlock` to remove the object from the list. 
   - If the eviction thread holds `sx_xlock`, the lookup thread cannot acquire `sx_slock` to begin iterating the list. 
   - Once the eviction thread removes the object and releases `sx_xlock`, the object is no longer in the list for any subsequent lookup thread to find. 
   - If a lookup thread already held a reference (`refcount_acquire` was called before the eviction), the `AUTH_DESTROY` call (which uses `refcount_release`) will not free the memory until that reference is also released.

Thus, the synchronization is sufficient to prevent the race condition described. The scanner's claim that a thread could have a pointer but not yet have called `refcount_acquire` is impossible because the pointer is only obtainable while holding the lock that prevents removal.

CRUX: The `rpc_gss_lock` (sx_lock) ensures that an object cannot be removed from the cache lists while another thread is iterating them to acquire a reference, and the reference counting ensures the object remains valid if it was already retrieved.
GREP: sx_slock

🔎 **Grep results:**

GREP `sx_slock`:
```
sys/arm64/nvidia/tegra210/max77620_gpio.c:47:#define	GPIO_LOCK(_sc)	sx_slock(&(_sc)->gpio_lock)
sys/arm/nvidia/as3722_gpio.c:71:#define	GPIO_LOCK(_sc)	sx_slock(&(_sc)->gpio_lock)
sys/netinet6/in6_src.c:116:#define	ADDRSEL_SLOCK()		sx_slock(&addrsel_sxlock)
sys/dev/syscon/syscon.c:97:#define SYSCON_TOPO_SLOCK()	sx_slock(&syscon_topo_lock)
sys/dev/clk/clk.c:170:#define CLK_TOPO_SLOCK()	sx_slock(&clk_topo_lock)
sys/dev/clk/clk.c:176:#define CLKNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/phy/phy_internal.h:69:#define PHY_TOPO_SLOCK()	sx_slock(&phynode_topo_lock)
sys/dev/phy/phy_internal.h:75:#define PHYNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/regulator/regulator.c:150:#define REG_TOPO_SLOCK()	sx_slock(&regnode_topo_lock)
sys/dev/regulator/regulator.c:156:#define REGNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/mlx5/mlx5_en/en_rl.h:53:#define	MLX5E_RL_RLOCK(rl) sx_slock(&(rl)->rl_sxlock)
sys/netpfil/ipfw/ip_fw_private.h:483:#define IPFW_UH_RLOCK(p) sx_slock(&(p)->uh_lock)
sys/fs/autofs/autofs.h:60:#define AUTOFS_SLOCK(X)		sx_slock(&X->am_lock)
sys/sys/filedesc.h:184:#define	FILEDESC_SLOCK(fdp)	sx_slock(&(fdp)->fd_sx)
sys/sys/module.h:219:#define	MOD_SLOCK	sx_slock(&modules_sx)
sys/sys/mount.h:1078:#define	vfsconf_slock()		sx_slock(&vfsconf_sx)
sys/netinet/netdump/netdump_client.c:126:#define NETDUMP_RLOCK()			sx_slock(&nd_conf_lk)
sys/sys/sx.h:205:#define	sx_slock_(sx, file, line)					\
sys/sys/sx.h:207:#define	sx_slock_sig_(sx, file, line)					\
sys/sys/sx.h:216:#define	sx_slock_(sx, file, line)					\
sys/sys/sx.h:218:#define	sx_slock_sig_(sx, file, line)					\
sys/sys/sx.h:237:#define	sx_slock(sx)		sx_slock_((sx), LOCK_FILE, LOCK_LINE)
sys/sys/sx.h:238:#define	sx_slock_sig(sx)	sx_slock_sig_((sx), LOCK_FILE, LOCK_LINE)
sys/security/audit/audit_bsm_db.c:105:#define	EVNAMEMAP_RLOCK()	sx_slock(&evnamemap_lock)
sys/kern/imgact_binmisc.c:105:#define	INTERP_LIST_RLOCK()		sx_slock(&interp_list_sx)
sys/compat/linux/linux_emul.h:76:#define	LINUX_PEM_SLOCK(p)	sx_slock(&(p)->pem_sx)
sys/compat/linuxkpi/common/include/linux/rwsem.h:44:#define	down_read(_rw)			sx_slock(&(_rw)->sx)
sys/net/if_lagg.c:86:#define	LAGG_SLOCK(_sc)		sx_slock(&(_sc)->sc_sx)
sys/net/dummymbuf.c:67:#define DMB_RULES_SLOCK()	sx_slock(&V_dmb_rules_lock)
sys/net/vnet.c:205:#define	VNET_SYSINIT_RLOCK()	sx_slock(&vnet_sysinit_sxlock);
```

### Round 3: ❌ INVALID

**🎯 Crux:** The use of a shared-exclusive lock (sx_lock) ensures that list iteration and reference acquisition are atomic with respect to list removal.

The reported vulnerability claims a race condition exists where a lookup thread could hold a pointer to an `rpc_gss_data` object (`gd`) while an eviction thread frees it. However, the `rpc_gss_lock` (an `sx` lock) is used to synchronize access to the cache lists. In `rpc_gss_secfind`, the lookup loop acquires a shared lock (`sx_slock`) before iterating the list and calls `refcount_acquire` while still holding that shared lock. The eviction logic acquires an exclusive lock (`sx_xlock`) before removing the object from the lists. Because an exclusive lock cannot be acquired while any shared locks are held, and a shared lock cannot be acquired while an exclusive lock is held, it is impossible for an object to be removed and destroyed while another thread is in the process of finding and referencing it via the cache. Once the eviction thread releases the exclusive lock, the object is already removed from the lists and cannot be found by new lookups. Any existing holders of the object are protected by the reference count (`gd_refs`).

CRUX: The use of a shared-exclusive lock (sx_lock) ensures that list iteration and reference acquisition are atomic with respect to list removal.
GREP: sx_slock

🔎 **Grep results:**

GREP `sx_slock`:
```
sys/arm64/nvidia/tegra210/max77620_gpio.c:47:#define	GPIO_LOCK(_sc)	sx_slock(&(_sc)->gpio_lock)
sys/dev/syscon/syscon.c:97:#define SYSCON_TOPO_SLOCK()	sx_slock(&syscon_topo_lock)
sys/dev/clk/clk.c:170:#define CLK_TOPO_SLOCK()	sx_slock(&clk_topo_lock)
sys/dev/clk/clk.c:176:#define CLKNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/phy/phy_internal.h:69:#define PHY_TOPO_SLOCK()	sx_slock(&phynode_topo_lock)
sys/dev/phy/phy_internal.h:75:#define PHYNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/regulator/regulator.c:150:#define REG_TOPO_SLOCK()	sx_slock(&regnode_topo_lock)
sys/dev/regulator/regulator.c:156:#define REGNODE_SLOCK(_sc)	sx_slock(&((_sc)->lock))
sys/dev/mlx5/mlx5_en/en_rl.h:53:#define	MLX5E_RL_RLOCK(rl) sx_slock(&(rl)->rl_sxlock)
sys/netpfil/ipfw/ip_fw_private.h:483:#define IPFW_UH_RLOCK(p) sx_slock(&(p)->uh_lock)
sys/arm/nvidia/as3722_gpio.c:71:#define	GPIO_LOCK(_sc)	sx_slock(&(_sc)->gpio_lock)
sys/netinet6/in6_src.c:116:#define	ADDRSEL_SLOCK()		sx_slock(&addrsel_sxlock)
sys/fs/autofs/autofs.h:60:#define AUTOFS_SLOCK(X)		sx_slock(&X->am_lock)
sys/sys/filedesc.h:184:#define	FILEDESC_SLOCK(fdp)	sx_slock(&(fdp)->fd_sx)
sys/sys/module.h:219:#define	MOD_SLOCK	sx_slock(&modules_sx)
sys/sys/mount.h:1078:#define	vfsconf_slock()		sx_slock(&vfsconf_sx)
sys/sys/sx.h:205:#define	sx_slock_(sx, file, line)					\
sys/sys/sx.h:207:#define	sx_slock_sig_(sx, file, line)					\
sys/sys/sx.h:216:#define	sx_slock_(sx, file, line)					\
sys/sys/sx.h:218:#define	sx_slock_sig_(sx, file, line)					\
sys/sys/sx.h:237:#define	sx_slock(sx)		sx_slock_((sx), LOCK_FILE, LOCK_LINE)
sys/sys/sx.h:238:#define	sx_slock_sig(sx)	sx_slock_sig_((sx), LOCK_FILE, LOCK_LINE)
sys/security/audit/audit_bsm_db.c:105:#define	EVNAMEMAP_RLOCK()	sx_slock(&evnamemap_lock)
sys/netinet/netdump/netdump_client.c:126:#define NETDUMP_RLOCK()			sx_slock(&nd_conf_lk)
sys/kern/imgact_binmisc.c:105:#define	INTERP_LIST_RLOCK()		sx_slock(&interp_list_sx)
sys/net/if_lagg.c:86:#define	LAGG_SLOCK(_sc)		sx_slock(&(_sc)->sc_sx)
sys/net/dummymbuf.c:67:#define DMB_RULES_SLOCK()	sx_slock(&V_dmb_rules_lock)
sys/net/vnet.c:205:#define	VNET_SYSINIT_RLOCK()	sx_slock(&vnet_sysinit_sxlock);
sys/net/if_var.h:496:#define	IFNET_RLOCK()		sx_slock(&ifnet_sxlock)
sys/compat/linux/linux_emul.h:76:#define	LINUX_PEM_SLOCK(p)	sx_slock(&(p)->pem_sx)
```

### Round 4: ❌ INVALID

[ARBITER] The reported vulnerability claims a Use-After-Free (UAF) occurs because an object is removed from the cache and destroyed while another thread might be using it. However, the code uses an `sx` lock (`rpc_gss_lock`) to synchronize access. The lookup loop in `rpc_gss_secfind` acquires a shared lock (`sx_slock`) and performs `refcount_acquire` on the object *before* releasing the lock. The eviction logic acquires an exclusive lock (`sx_xlock`), which prevents any thread from being inside the lookup loop. Once the object is removed from the lists under the exclusive lock, any new lookups will not find it. Existing users who already called `refcount_acquire` hold a reference, preventing `rpc_gss_destroy` (called via `AUTH_DESTROY`) from actually freeing the memory until the last reference is released. Thus, the synchronization and reference counting correctly prevent the race condition.

