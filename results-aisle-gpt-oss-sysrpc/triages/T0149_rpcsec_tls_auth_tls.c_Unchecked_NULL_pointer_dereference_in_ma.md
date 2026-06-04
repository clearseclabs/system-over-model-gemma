# Triage T0149: Unchecked NULL pointer dereference in marshal

- **File**: `rpcsec_tls/auth_tls.c`
- **Verdict**: INVALID
- **Confidence**: 0% [IUI→I]

---

## Finding

Unchecked NULL pointer dereference in marshal

---

## Triage rounds

### Round 1: ❌ INVALID

**🎯 Crux:** authtls_marshal never dereferences its AUTH *client argument

The function authtls_marshal only uses a static struct authtls_private (ap) and the XDR stream passed via xdrs. It contains no dereferences of the AUTH *client parameter. The only guard is KASSERT on xdrs, which protects against a NULL XDR stream, not a NULL client. Therefore the alleged NULL pointer dereference does not exist. No attack path can reach a dereference of client, so the finding is a false positive.

CRUX: authtls_marshal never dereferences its AUTH *client argument
GREP: client->

🔎 **Grep results:**

GREP `client->`:
```
sys/ofed/drivers/infiniband/core/sa.h:44:	atomic_inc(&client->users);
sys/ofed/drivers/infiniband/core/sa.h:49:	if (atomic_dec_and_test(&client->users))
sys/ofed/drivers/infiniband/core/sa.h:50:		complete(&client->comp);
sys/dev/bxe/bxe_stats.h:592:        diff = le##size##toh(tclient->s) -                   \
sys/dev/bxe/bxe_stats.h:593:               le##size##toh(old_tclient->s);                \
sys/dev/bxe/bxe_stats.h:594:        old_tclient->s = tclient->s;                         \
sys/dev/bxe/bxe_stats.h:608:        diff = le32toh(uclient->s) - le32toh(old_uclient->s); \
sys/dev/bxe/bxe_stats.h:609:        old_uclient->s = uclient->s;                          \
sys/dev/bxe/bxe_stats.h:621:        diff = le32toh(xclient->s) - le32toh(old_xclient->s); \
sys/dev/bxe/bxe_stats.h:622:        old_xclient->s = xclient->s;                          \
sys/dev/bxe/bxe_stats.h:700:        diff = le32toh(uclient->s) - le32toh(old_uclient->s); \
sbin/dhclient/bpf.c:93:	if (info->client->config->vlan_pcp != 0) {
sbin/dhclient/bpf.c:95:		    &info->client->config->vlan_pcp) < 0)
sbin/dhclient/dhclient.c:214:	if (_ifi->client->active != NULL) {
sbin/dhclient/dhclient.c:217:		    _ifi->client->active);
sbin/dhclient/dhclient.c:218:		if (_ifi->client->alias)
sbin/dhclient/dhclient.c:220:				_ifi->client->alias);
sbin/dhclient/dhclient.c:223:	_ifi->client->state = S_INIT;
sbin/dhclient/dhclient.c:271:		for (l = ifi->client->active; l != NULL; l = l->next)
sbin/dhclient/dhclient.c:349:	if (ifi->client->alias)
sbin/dhclient/dhclient.c:350:		script_write_params("alias_", ifi->client->alias);
sbin/dhclient/dhclient.c:500:	if (ifi->client->alias)
sbin/dhclient/dhclient.c:501:		priv_script_write_params("alias_", ifi->client->alias);
sbin/dhclient/dhclient.c:567:	ifi->client->state = S_INIT;
sbin/dhclient/dhclient.c:623:	if (!ip->client->active || ip->client->active->is_bootp) {
sbin/dhclient/dhclient.c:629:	ip->client->state = S_REBOOTING;
sbin/dhclient/dhclient.c:634:	ip->client->xid = arc4random();
sbin/dhclient/dhclient.c:638:	make_request(ip, ip->client->active);
sbin/dhclient/dhclient.c:639:	ip->client->destination = iaddr_broadcast;
sbin/dhclient/dhclient.c:640:	ip->client->first_sending = cur_time;
```

### Round 2: ❓ UNCERTAIN



### Round 3: ❌ INVALID

**🎯 Crux:** authtls_marshal never dereferences its AUTH *client argument

The authtls_marshal function does not dereference the AUTH *client argument. The only use of client in this function is as the formal parameter, but the body never contains any expression that accesses client-> or *client. The KASSERT guards only the xdrs pointer, not client. Therefore there is no NULL-pointer dereference that an attacker could trigger. Since the function is internal to the RPCTLS implementation and does not use client, the bug pattern is not present and the scanner’s finding is a false positive.

CRUX: authtls_marshal never dereferences its AUTH *client argument
GREP: grep -n "void\s*authtls_marshal" -n auth_tls.c && grep -n "client" auth_tls.c

🔎 **Grep results:**

GREP `authtls_marshal`:
```
sys/rpc/rpcsec_tls/auth_tls.c:64:static bool_t authtls_marshal (AUTH *, uint32_t, XDR *, struct mbuf *);
sys/rpc/rpcsec_tls/auth_tls.c:73:	.ah_marshal =		authtls_marshal,
sys/rpc/rpcsec_tls/auth_tls.c:118:authtls_marshal(AUTH *client, uint32_t xid, XDR *xdrs, struct mbuf *args)
sys/rpc/rpcsec_tls/auth_tls.c:122:	KASSERT(xdrs != NULL, ("authtls_marshal: xdrs is null"));
```

### Round 4: ❌ INVALID

[ARBITER] The function `authtls_marshal` never accesses the `client` pointer; it only uses the static `authtls_private` structure and the supplied `XDR *xdrs`. The only KASSERT checks that `xdrs` is non‑NULL. Therefore a NULL `client` cannot lead to a dereference or a crash, and the reported medium‑severity NULL pointer dereference is a false positive.

