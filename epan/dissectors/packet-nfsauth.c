/* packet-nfsauth.c
 * Stubs for Sun's NFS AUTH RPC service
 *
 * Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "packet-rpc.h"

void proto_register_nfsauth(void);
void proto_reg_handoff_nfsauth(void);

static int proto_nfsauth;
static int hf_nfsauth_procedure_v1;

static int ett_nfsauth;

#define NFSAUTH_PROGRAM	100231

#define NFSAUTHPROC_NULL		0
#define NFSAUTH1_ACCESS			1
/* proc number, "proc name", dissect_request, dissect_reply */
static const vsff nfsauth1_proc[] = {
	{ NFSAUTHPROC_NULL,	"NULL",
		dissect_rpc_void,	dissect_rpc_void },
	{ NFSAUTH1_ACCESS,	"ACCESS",
		dissect_rpc_unknown,	dissect_rpc_unknown },
	{ 0,	NULL,	NULL,	NULL }
};
static const value_string nfsauth1_proc_vals[] = {
	{ NFSAUTHPROC_NULL,	"NULL" },
	{ NFSAUTH1_ACCESS,	"ACCESS" },
	{ 0,	NULL }
};
static const rpc_prog_vers_info nfsauth_vers_info[] = {
	{ 1, nfsauth1_proc, &hf_nfsauth_procedure_v1 },
};


void
proto_register_nfsauth(void)
{
	static hf_register_info hf[] = {
		{ &hf_nfsauth_procedure_v1, {
			"V1 Procedure", "nfsauth.procedure_v1", FT_UINT32, BASE_DEC,
			VALS(nfsauth1_proc_vals), 0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_nfsauth,
	};

	proto_nfsauth = proto_register_protocol("NFSAUTH", "NFSAUTH", "nfsauth");
	proto_register_field_array(proto_nfsauth, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nfsauth(void)
{
	/* Register the protocol as RPC */
	rpc_init_prog(proto_nfsauth, NFSAUTH_PROGRAM, ett_nfsauth,
	    G_N_ELEMENTS(nfsauth_vers_info), nfsauth_vers_info);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
