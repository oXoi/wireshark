/* packet-gluster_pmap.c
 * Routines for Gluster Portmapper and Gluster DUMP dissection
 * Copyright 2012, Niels de Vos <ndevos@redhat.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *
 * References to source files point in general to the glusterfs sources.
 * There is currently no RFC or other document where the protocol is
 * completely described. The glusterfs sources can be found at:
 * - http://git.gluster.com/?p=glusterfs.git
 * - https://github.com/gluster/glusterfs
 *
 * The coding-style is roughly the same as the one use in the Linux kernel,
 * see http://www.kernel.org/doc/Documentation/CodingStyle.
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-rpc.h"
#include "packet-gluster.h"

void proto_register_gluster_pmap(void);
void proto_reg_handoff_gluster_pmap(void);
void proto_register_gluster_dump(void);
void proto_reg_handoff_gluster_dump(void);

/* Initialize the protocol and registered fields */
static int proto_gluster_pmap;
static int proto_gluster_dump;

/* programs and procedures */
static int hf_gluster_pmap_proc;
static int hf_gluster_dump_proc;

/* fields used by multiple programs/procedures */
static int hf_gluster_brick;
static int hf_gluster_brick_status;
static int hf_gluster_brick_port;
static int hf_gluster_gfsid;
static int hf_gluster_progname;
static int hf_gluster_prognum;
static int hf_gluster_progver;

/* Initialize the subtree pointers */
static int ett_gluster_pmap;
static int ett_gluster_dump;
static int ett_gluster_dump_detail;

/* PMAP PORTBYBRICK */
static int
gluster_pmap_portbybrick_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_brick_status, offset);
	offset = dissect_rpc_uint32(tvb, tree, hf_gluster_brick_port, offset);

	return offset;
}

static int
gluster_pmap_portbybrick_call(tvbuff_t *tvb,
				packet_info *pinfo _U_, proto_tree *tree, void* data _U_)
{
	return dissect_rpc_string(tvb, tree, hf_gluster_brick, 0, NULL);
}

/* Based on rpc/rpc-lib/src/rpc-common.c, but xdr encoding/decoding is broken.
 * The structure in rpc/rpc-lib/src/xdr-common.h lists 2x unit64_t, but to
 * encode/decode, xdr_u_quad_t() is used (which is uint32_t).
 */
static int
gluster_dump_reply_detail(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
							proto_tree *tree, void* data _U_)
{
	proto_item *detail_item;
	proto_tree *detail_tree;
	const char *progname = NULL;

	detail_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
							ett_gluster_dump_detail, &detail_item, "Available Program: ");

	/* progname */
	offset = dissect_rpc_string(tvb, detail_tree, hf_gluster_progname,
							offset, &progname);
	proto_item_append_text(detail_item, "%s", progname);

	/* prognumber (marked as uint64) */
	offset = dissect_rpc_uint64(tvb, detail_tree, hf_gluster_prognum,
								offset);
	/* progversion (marked as uint64) */
	offset = dissect_rpc_uint64(tvb, detail_tree, hf_gluster_progver,
								offset);

	return offset;
}

static int
gluster_dump_reply(tvbuff_t *tvb, packet_info *pinfo,
							proto_tree *tree, void* data)
{
	int offset = 0;

	offset = dissect_rpc_uint64(tvb, tree, hf_gluster_gfsid, offset);
	offset = gluster_dissect_common_reply(tvb, offset, pinfo, tree, data);

	offset = dissect_rpc_list(tvb, pinfo, tree, offset,
				  gluster_dump_reply_detail, NULL);

	return offset;
}

/* DUMP request */
static int
gluster_dump_call(tvbuff_t *tvb, packet_info *pinfo _U_,
							proto_tree *tree, void* data _U_)
{
	return dissect_rpc_uint64(tvb, tree, hf_gluster_gfsid, 0);
}

/* GLUSTER_PMAP_PROGRAM from xlators/mgmt/glusterd/src/glusterd-pmap.c */
static const vsff gluster_pmap_proc[] = {
	{
		GF_PMAP_NULL,        "NULL",
		dissect_rpc_void, dissect_rpc_void
	},
	{
		GF_PMAP_PORTBYBRICK, "PORTBYBRICK",
		gluster_pmap_portbybrick_call, gluster_pmap_portbybrick_reply
	},
	{ GF_PMAP_BRICKBYPORT, "BRICKBYPORT", dissect_rpc_unknown, dissect_rpc_unknown },
	{ GF_PMAP_SIGNIN,      "SIGNIN",      dissect_rpc_unknown, dissect_rpc_unknown },
	{ GF_PMAP_SIGNOUT,     "SIGNOUT",     dissect_rpc_unknown, dissect_rpc_unknown },
	{ GF_PMAP_SIGNUP,      "SIGNUP",      dissect_rpc_unknown, dissect_rpc_unknown },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_pmap_proc_vals[] = {
	{ GF_PMAP_NULL,        "NULL" },
	{ GF_PMAP_PORTBYBRICK, "PORTBYBRICK" },
	{ GF_PMAP_BRICKBYPORT, "BRICKBYPORT" },
	{ GF_PMAP_SIGNIN,      "SIGNIN" },
	{ GF_PMAP_SIGNOUT,     "SIGNOUT" },
	{ GF_PMAP_SIGNUP,      "SIGNUP" },
	{ 0, NULL }
};
static const rpc_prog_vers_info gluster_pmap_vers_info[] = {
	{ 1, gluster_pmap_proc, &hf_gluster_pmap_proc }
};

/* procedures for GLUSTER_DUMP_PROGRAM */
static const vsff gluster_dump_proc[] = {
	{ 0, "NULL", dissect_rpc_void, dissect_rpc_void },
	{ GF_DUMP_DUMP, "DUMP", gluster_dump_call, gluster_dump_reply },
	{ 0, NULL, NULL, NULL }
};
static const value_string gluster_dump_proc_vals[] = {
	{ 0,            "NULL" },
	{ GF_DUMP_DUMP, "DUMP" },
	{ 0, NULL }
};
static const rpc_prog_vers_info gluster_dump_vers_info[] = {
	{ 1, gluster_dump_proc, &hf_gluster_dump_proc }
};

void
proto_register_gluster_pmap(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_pmap_proc,
			{ "Gluster Portmap", "gluster.pmap.proc", FT_UINT32,
				BASE_DEC, VALS(gluster_pmap_proc_vals), 0,
				NULL, HFILL }
		},
		{ &hf_gluster_brick,
			{ "Brick", "gluster.brick", FT_STRINGZ, BASE_NONE,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_brick_status,
			{ "Status", "gluster.brick.status", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_brick_port,
			{ "Port", "gluster.brick.port", FT_INT32, BASE_DEC,
				NULL, 0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_gluster_pmap
	};

	proto_gluster_pmap = proto_register_protocol("Gluster Portmap", "Gluster Portmap", "gluster.pmap");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster_pmap, hf, array_length(hf));
}

void
proto_reg_handoff_gluster_pmap(void)
{
	rpc_init_prog(proto_gluster_pmap, GLUSTER_PMAP_PROGRAM,
	    ett_gluster_pmap,
	    G_N_ELEMENTS(gluster_pmap_vers_info), gluster_pmap_vers_info);
}

void
proto_register_gluster_dump(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details */
	static hf_register_info hf[] = {
		/* programs */
		{ &hf_gluster_dump_proc,
			{ "Gluster DUMP", "gluster.dump.proc", FT_UINT32,
				BASE_DEC, VALS(gluster_dump_proc_vals), 0,
				NULL, HFILL }
		},
		{ &hf_gluster_progname,
			{ "Program Name", "gluster.dump.progname", FT_STRING,
				BASE_NONE, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_prognum,
			{ "Program Number", "gluster.dump.prognum",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_progver,
			{ "Program Version", "gluster.dump.progver",
				FT_UINT64, BASE_DEC, NULL, 0, NULL, HFILL }
		},
		{ &hf_gluster_gfsid,
			{ "GFS ID", "gluster.gfsid", FT_UINT64, BASE_HEX, NULL,
				0, NULL, HFILL }
		}
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_gluster_dump,
		&ett_gluster_dump_detail
	};

	proto_gluster_dump = proto_register_protocol("Gluster Dump",
					"Gluster Dump", "gluster.dump");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_gluster_dump, hf, array_length(hf));
}

void
proto_reg_handoff_gluster_dump(void)
{
	rpc_init_prog(proto_gluster_dump, GLUSTER_DUMP_PROGRAM,
	    ett_gluster_dump,
	    G_N_ELEMENTS(gluster_dump_vers_info), gluster_dump_vers_info);
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
