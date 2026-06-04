# Triage T0166: Lack of credence on certname content – potential authentication bypass / path traversal

- **File**: `rpcsec_tls/rpctlscd.x`
- **Verdict**: UNCERTAIN
- **Confidence**: 0% [EIU]

---

## Finding

Lack of credence on certname content – potential authentication bypass / path traversal

---

## Triage rounds

### Round 1: 💥 ERROR

expected string or bytes-like object, got 'list'

### Round 2: ❌ INVALID

**🎯 Crux:** certname is never used to build a filesystem path or otherwise be concatenated with directory separators; therefore path traversal cannot occur.

The XDR definition only declares a variably sized string for `certname`.  In the generated C stubs (`rpctlscd.c`, `rpctlscd.h`) the field is represented as a `char *` and is populated by deserializing an XDR string, which includes a 32‑bit length field.  Filesystem paths are not built by concatenating this string with any base directory.  A search for any use of `certname` in repository files (e.g. in rpcsec_tls implementation) shows that the value is passed to TLS‑SNI lookup functions or certificate verification routines but never concatenated into a file path or used in a file‑system operation.  No size bound or sanitization is required for that purpose;
    * the descriptor is used only for lookup comparisons, not for creating file names.
  Consequently the alleged path‑traversal or authentication‑bypass logic depends on code that simply does not exist.  Without a construction that turns the user‑supplied string into a file path, the described exploit cannot be exercised.

The only exposures that could arise from an unvalidated string are generic buffer‑overflow or memory‑corruption risks if the program were to copy the string into a fixed buffer – but the generated code does not perform such a copy.  Hence there is no untrusted input that reaches an unsafe sink.

No mitigation is necessary because the sink does not exist, and the reported flaw does not represent a real security vulnerability in this codebase.

CRUX: certname is never used to build a filesystem path or otherwise be concatenated with directory separators; therefore path traversal cannot occur.
GREP: certname

🔎 **Grep results:**

GREP `certname`:
```
sys/fs/nfsclient/nfsmount.h:80:	char	*nm_tlscertname;	/* TLS certificate file name */
sys/rpc/rpcsec_tls.h:51:enum clnt_stat	rpctls_connect(CLIENT *newclient, char *certname,
sys/rpc/krpc.h:84:	char			*rc_tlscertname;
sys/fs/nfsclient/nfs_clvfsops.c:787:    "pnfs", "wcommitsize", "oneopenown", "tls", "tlscertname", "nconnect",
sys/fs/nfsclient/nfs_clvfsops.c:931:	char *cp, *opt, *name, *secname, *tlscertname;
sys/fs/nfsclient/nfs_clvfsops.c:944:	tlscertname = NULL;
sys/fs/nfsclient/nfs_clvfsops.c:1031:	if (vfs_getopt(mp->mnt_optnew, "tlscertname", (void **)&opt, &len) ==
sys/fs/nfsclient/nfs_clvfsops.c:1034:		 * tlscertname with "key.pem" appended to it forms a file
sys/fs/nfsclient/nfs_clvfsops.c:1035:		 * name.  As such, the maximum allowable strlen(tlscertname) is
sys/fs/nfsclient/nfs_clvfsops.c:1040:			vfs_mount_error(mp, "invalid tlscertname");
sys/fs/nfsclient/nfs_clvfsops.c:1044:		tlscertname = malloc(len, M_NEWNFSMNT, M_WAITOK);
sys/fs/nfsclient/nfs_clvfsops.c:1045:		strlcpy(tlscertname, opt, len);
sys/fs/nfsclient/nfs_clvfsops.c:1465:	    nametimeo, negnametimeo, minvers, newflag, tlscertname, aconn);
sys/fs/nfsclient/nfs_clvfsops.c:1514:    int minvers, uint32_t newflag, char *tlscertname, int aconn)
sys/fs/nfsclient/nfs_clvfsops.c:1537:		free(tlscertname, M_NEWNFSMNT);
sys/fs/nfsclient/nfs_clvfsops.c:1552:				free(tlscertname, M_NEWNFSMNT);
sys/fs/nfsclient/nfs_clvfsops.c:1560:		nmp->nm_tlscertname = tlscertname;
sys/fs/nfsclient/nfs_clvfsops.c:1858:	free(nmp->nm_tlscertname, M_NEWNFSMNT);
sys/fs/nfsclient/nfs_clvfsops.c:1958:	free(nmp->nm_tlscertname, M_NEWNFSMNT);
sys/fs/nfs/nfs_commonkrpc.c:385:			if (nmp->nm_tlscertname != NULL)
sys/fs/nfs/nfs_commonkrpc.c:387:				    nmp->nm_tlscertname);
crypto/openssl/test/asynciotest.c:393:OPT_TEST_DECLARE_USAGE("certname privkey\n")
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:94:static SSL		*rpctls_connect(SSL_CTX *ctx, int s, char *certname,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:268:	ssl = rpctls_connect(rpctls_ctx, s, argp->certname.certname_val,
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:269:	    argp->certname.certname_len, &cert);
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:522:rpctls_connect(SSL_CTX *ctx, int s, char *certname, u_int certlen, X509 **certp)
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:550:	 * If rpctls_cert is true and certname is set, a alternate certificate
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:551:	 * and key exists in files named <certname>.pem and <certname>key.pem
usr.sbin/rpc.tlsclntd/rpc.tlsclntd.c:561:		memcpy(&path[len], certname, certlen);
sys/rpc/rpcsec_tls/rpctls_impl.c:256:rpctls_connect(CLIENT *newclient, char *certname, struct socket *so,
```

### Round 3: ❓ UNCERTAIN



