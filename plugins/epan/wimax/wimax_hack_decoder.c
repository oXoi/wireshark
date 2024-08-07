/* wimax_hack_decoder.c
 * WiMax HARQ ACK Burst decoder
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include "wimax-int.h"

extern int proto_wimax;

static int proto_wimax_hack_decoder;
static int ett_wimax_hack_decoder;

static const value_string vals_flags[] =
{
	{0, "Even Half-Slot (tiles 0,2,4)"},
	{1, "Odd Half-Slot (tiles 1,3,5)"},
	{0, NULL}
};

static const value_string vals_values[] =
{
	{0, "ACK"},
	{1, "NACK"},
	{0, NULL}
};

/* static int hf_hack_burst; */
static int hf_hack_num_of_hacks;
static int hf_hack_half_slot_flag;
static int hf_hack_subchannel;
static int hf_hack_symboloffset;
static int hf_hack_value;


static int dissect_wimax_hack_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	unsigned length, num_of_hacks, i;
	proto_item *hack_item = NULL;
	proto_tree *hack_tree = NULL;

	/* update the info column */
	col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "HARQ ACK Burst:");
	if (tree)
	{	/* we are being asked for details */
		/* get the tvb reported length */
		length = tvb_reported_length(tvb);
		/* display HARQ ACK Burst dissector info */
		hack_item = proto_tree_add_protocol_format(tree, proto_wimax_hack_decoder, tvb, offset, length, "HARQ ACK Burst (%u bytes)", length);
		/* add HARQ ACK Burst subtree */
		hack_tree = proto_item_add_subtree(hack_item, ett_wimax_hack_decoder);
		/* get the number of HARQ ACKs */
		num_of_hacks =  tvb_get_uint8(tvb, offset);
		/* display the number of HARQ ACKs */
		proto_tree_add_item(hack_tree, hf_hack_num_of_hacks, tvb, offset++, 1, ENC_BIG_ENDIAN);
		/* display the HARQ ACKs */
		for(i = 0; i < num_of_hacks; i++)
		{
			proto_tree_add_item(hack_tree, hf_hack_subchannel, tvb, offset++, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(hack_tree, hf_hack_symboloffset, tvb, offset++, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(hack_tree, hf_hack_half_slot_flag, tvb, offset++, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(hack_tree, hf_hack_value, tvb, offset++, 1, ENC_BIG_ENDIAN);
		}
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax HARQ ACK Protocol */
void wimax_proto_register_wimax_hack(void)
{
	/* HARQ ACK display */
	static hf_register_info hf[] =
	{
#if 0
		{
			&hf_hack_burst,
			{"HARQ ACK Burst", "wmx.hack.burst", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
#endif
		{
			&hf_hack_num_of_hacks,
			{"Number Of HARQ ACKs/NACKs", "wmx.hack.num_of_hacks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_hack_subchannel,
			{"Physical Subchannel", "wmx.hack.subchannel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_hack_symboloffset,
			{"Symbol Offset", "wmx.hack.symbol_offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{
			&hf_hack_half_slot_flag,
			{"Half-Slot Flag", "wmx.hack.half_slot_flag", FT_UINT8, BASE_DEC, VALS(vals_flags), 0x0, NULL, HFILL}
		},
		{
			&hf_hack_value,
			{"ACK Value", "wmx.hack.hack_value", FT_UINT8, BASE_DEC, VALS(vals_values), 0x0, NULL, HFILL}
		}
	};

	/* Setup protocol subtree array */
	static int *ett[] =
		{
			&ett_wimax_hack_decoder,
		};

	proto_wimax_hack_decoder = proto_wimax;

	register_dissector("wimax_hack_burst_handler", dissect_wimax_hack_decoder, proto_wimax_hack_decoder);
	proto_register_field_array(proto_wimax_hack_decoder, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
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
