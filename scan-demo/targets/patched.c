/*
 * FreeBSD src/sys/rpc/rpcsec_gss/svc_rpcsec_gss.c
 * BSD-3-Clause licensed.
 */

static bool_t
svc_rpc_gss_validate(struct svc_rpc_gss_client *client, struct rpc_msg *msg,
    gss_qop_t *qop, rpc_gss_proc_t gcproc)
{
	struct opaque_auth	*oa;
	gss_buffer_desc		 rpcbuf, checksum;
	OM_uint32		 maj_stat, min_stat;
	gss_qop_t		 qop_state;
	int32_t			 rpchdr[128 / sizeof(int32_t)];
	int32_t			*buf;

	rpc_gss_log_debug("in svc_rpc_gss_validate()");

	memset(rpchdr, 0, sizeof(rpchdr));

	oa = &msg->rm_call.cb_cred;

	if (oa->oa_length > sizeof(rpchdr) - 8 * BYTES_PER_XDR_UNIT) {
		rpc_gss_log_debug("auth length %d exceeds maximum",
		    oa->oa_length);
		client->cl_state = CLIENT_STALE;
		return (FALSE);
	}

	/* Reconstruct RPC header for signing (from xdr_callmsg). */
	buf = rpchdr;
	IXDR_PUT_LONG(buf, msg->rm_xid);
	IXDR_PUT_ENUM(buf, msg->rm_direction);
	IXDR_PUT_LONG(buf, msg->rm_call.cb_rpcvers);
	IXDR_PUT_LONG(buf, msg->rm_call.cb_prog);
	IXDR_PUT_LONG(buf, msg->rm_call.cb_vers);
	IXDR_PUT_LONG(buf, msg->rm_call.cb_proc);
	IXDR_PUT_ENUM(buf, oa->oa_flavor);
	IXDR_PUT_LONG(buf, oa->oa_length);
	if (oa->oa_length) {
		memcpy((caddr_t)buf, oa->oa_base, oa->oa_length);
		buf += RNDUP(oa->oa_length) / sizeof(int32_t);
	}
	rpcbuf.value = rpchdr;
	rpcbuf.length = (u_char *)buf - (u_char *)rpchdr;

	checksum.value = msg->rm_call.cb_verf.oa_base;
	checksum.length = msg->rm_call.cb_verf.oa_length;

	maj_stat = gss_verify_mic(&min_stat, client->cl_ctx, &rpcbuf, &checksum,
				  &qop_state);

	if (maj_stat != GSS_S_COMPLETE) {
		rpc_gss_log_status("gss_verify_mic", client->cl_mech,
		    maj_stat, min_stat);
		/*
		 * A bug in some versions of the Linux client generates a
		 * Destroy operation with a bogus encrypted checksum. Deleting
		 * the credential handle for that case causes the mount to fail.
		 * Since the checksum is bogus (gss_verify_mic() failed), it
		 * doesn't make sense to destroy the handle and not doing so
		 * fixes the Linux mount.
		 */
		if (gcproc != RPCSEC_GSS_DESTROY)
			client->cl_state = CLIENT_STALE;
		return (FALSE);
	}

	*qop = qop_state;
	return (TRUE);
}
