/* packet-v5ef.c
 * Routines for V5 envelope function frame disassembly
 * Rolf Fiedler <rolf.fiedler@innoventif.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
/*
 * V5 bitstream over HDLC handling
 *
 * V5 references:
 *
 * ETS 300 324-1
 * ETS 300 347-1
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

void proto_register_v5ef(void);
void proto_reg_handoff_v5ef(void);

static int proto_v5ef;
static int hf_v5ef_direction;
static int hf_v5ef_address;
static int hf_v5ef_eah;
static int hf_v5ef_ea1;
static int hf_v5ef_eal;
static int hf_v5ef_ea2;

static int ett_v5ef;
static int ett_v5ef_address;

static dissector_handle_t v5dl_handle, lapd_phdr_handle, v5ef_handle;


/*
 * Bits in the address field.
 */
#define	V5EF_EAH		0xfc00	/* Service Access Point Identifier */
#define	V5EF_EAH_SHIFT		10
#define	V5EF_EA1		0x0100	/* First Address Extension bit */
#define	V5EF_EAL		0x00fe	/* Terminal Endpoint Identifier */
#define	V5EF_EAL_SHIFT		1
#define	V5EF_EA2		0x0001	/* Second Address Extension bit */

static const value_string v5ef_direction_vals[] = {
	{ 0,		"AN->LE"},
	{ 1,		"LE->AN"},
	{ 0,		NULL }
};

#define MAX_V5EF_PACKET_LEN 1024

static int
dissect_v5ef(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	struct isdn_phdr *isdn = (struct isdn_phdr *)data;
	proto_tree	*v5ef_tree, *addr_tree;
	proto_item	*v5ef_ti, *addr_ti;
	int		 direction;
	int		 v5ef_header_len;
	uint16_t		 addr, eah, eal, efaddr;
	tvbuff_t	*next_tvb;
	const char	*srcname = "src";
	const char	*dstname = "dst";

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "V5-EF");
	col_clear(pinfo->cinfo, COL_INFO);

	addr		= tvb_get_ntohs(tvb, 0);
	eah		= (addr & V5EF_EAH) >> V5EF_EAH_SHIFT;
	eal		= (addr & V5EF_EAL) >> V5EF_EAL_SHIFT;
	efaddr		= (eah << 7) + eal;
	v5ef_header_len = 2;	/* addr */

	direction = isdn->uton;
	if (direction==0) {
	        srcname = "LE";
	        dstname = "AN";
	 } else if (direction > 0) {
	        srcname = "AN";
	        dstname = "LE";
	}
	col_set_str(pinfo->cinfo, COL_RES_DL_SRC, srcname);
	col_set_str(pinfo->cinfo, COL_RES_DL_DST, dstname);

	if (tree) {
		proto_item *direction_ti;

		v5ef_ti = proto_tree_add_item(tree, proto_v5ef, tvb, 0, -1,
		    ENC_NA);
		v5ef_tree = proto_item_add_subtree(v5ef_ti, ett_v5ef);

		/*
		 * Don't show the direction if we don't know it.
		 */
		if (direction != P2P_DIR_UNKNOWN) {
			direction_ti = proto_tree_add_uint(v5ef_tree, hf_v5ef_direction,
			                                   tvb, 0, 0, direction);
			proto_item_set_generated(direction_ti);
		}

		addr_ti = proto_tree_add_uint(v5ef_tree, hf_v5ef_address, tvb,
		    0, 2, addr);
		addr_tree = proto_item_add_subtree(addr_ti, ett_v5ef_address);

		proto_tree_add_uint(addr_tree, hf_v5ef_eah,  tvb, 0, 1, addr);
		proto_tree_add_uint(addr_tree, hf_v5ef_ea1, tvb, 0, 1, addr);
		proto_tree_add_uint(addr_tree, hf_v5ef_eal, tvb, 1, 1, addr);
		proto_tree_add_uint(addr_tree, hf_v5ef_ea2, tvb, 1, 1, addr);
	}
	else {
		v5ef_ti	  = NULL;
		v5ef_tree = NULL;
	}

	if (tree)
		proto_item_set_len(v5ef_ti, v5ef_header_len);

	next_tvb = tvb_new_subset_remaining(tvb, v5ef_header_len);

	if (efaddr>8175)
		call_dissector(v5dl_handle,next_tvb, pinfo, tree);
	else
		call_dissector_with_data(lapd_phdr_handle, next_tvb, pinfo, tree, isdn);

	return tvb_captured_length(tvb);
}

void
proto_register_v5ef(void)
{
	static hf_register_info hf[] = {

	{ &hf_v5ef_direction,
	  { "Direction", "v5ef.direction", FT_UINT8, BASE_DEC, VALS(v5ef_direction_vals), 0x0,
	  	NULL, HFILL }},

	{ &hf_v5ef_address,
	  { "Address Field", "v5ef.address", FT_UINT16, BASE_HEX, NULL, 0x0,
		NULL, HFILL }},

	{ &hf_v5ef_eah,
	  { "EAH", "v5ef.eah", FT_UINT16, BASE_DEC, NULL, V5EF_EAH,
	  	"Envelope Address High Part", HFILL }},

	{ &hf_v5ef_ea1,
	  { "EA1", "v5ef.ea1", FT_UINT16, BASE_DEC, NULL, V5EF_EA1,
	  	"First Address Extension bit", HFILL }},

	{ &hf_v5ef_eal,
	  { "EAL", "v5ef.eal", FT_UINT16, BASE_DEC, NULL, V5EF_EAL,
	  	"Envelope Address Low Part", HFILL }},

	{ &hf_v5ef_ea2,
	  { "EA2", "v5ef.ea2", FT_UINT16, BASE_DEC, NULL, V5EF_EA2,
	  	"Second Address Extension bit", HFILL }},
	};

	static int *ett[] = {
		&ett_v5ef,
		&ett_v5ef_address,
	};

	proto_v5ef = proto_register_protocol("V5 Envelope Function (v5ef)",
					 "v5ef", "v5ef");
	proto_register_field_array (proto_v5ef, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	v5ef_handle = register_dissector("v5ef", dissect_v5ef, proto_v5ef);
}

void
proto_reg_handoff_v5ef(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_V5_EF, v5ef_handle);

	lapd_phdr_handle = find_dissector_add_dependency("lapd-phdr", proto_v5ef);
	v5dl_handle = find_dissector_add_dependency("v5dl", proto_v5ef);
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
