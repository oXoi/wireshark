/* packet-cimetrics.c
 * Routines for Cimetrics LLC OUI dissection
 * Copyright 2008 Steve Karg <skarg@users.sourceforge.net> Alabama
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-llc.h"
#include <epan/oui.h>
#include "packet-mstp.h"

void proto_register_cimetrics(void);
void proto_reg_handoff_cimetrics(void);

/* Probably should be a preference, but here for now */
#define BACNET_MSTP_SUMMARY_IN_TREE

/* the U+4 device does MS/TP, uLAN, Modbus */
static const value_string cimetrics_pid_vals[] = {
	{ 0x0001,	"U+4 MS/TP" },
	{ 0,		NULL }
};

static int proto_cimetrics_mstp;
static int hf_llc_cimetrics_pid;
static int ett_cimetrics_mstp;

static int hf_cimetrics_mstp_timer;
static int hf_cimetrics_mstp_value;

static dissector_handle_t cimetric_handle;

static int
dissect_cimetrics_mstp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *subtree;
	int offset = 0;
#ifdef BACNET_MSTP_SUMMARY_IN_TREE
	uint8_t mstp_frame_type = 0;
	uint8_t mstp_frame_source = 0;
	uint8_t mstp_frame_destination = 0;
#endif

#ifdef BACNET_MSTP_SUMMARY_IN_TREE
	mstp_frame_type = tvb_get_uint8(tvb, offset+3);
	mstp_frame_destination = tvb_get_uint8(tvb, offset+4);
	mstp_frame_source = tvb_get_uint8(tvb, offset+5);
	ti = proto_tree_add_protocol_format(tree,
		proto_cimetrics_mstp, tvb, offset, 9,
		"BACnet MS/TP, Src (%u), Dst (%u), %s",
		mstp_frame_source, mstp_frame_destination,
		mstp_frame_type_text(mstp_frame_type));
#else
	ti = proto_tree_add_item(tree, proto_cimetrics_mstp, tvb, offset, 9, ENC_NA);
#endif
	subtree = proto_item_add_subtree(ti, ett_cimetrics_mstp);
	proto_tree_add_item(subtree, hf_cimetrics_mstp_timer, tvb,
			offset++, 2, ENC_LITTLE_ENDIAN);
	offset++;
	proto_tree_add_item(subtree, hf_cimetrics_mstp_value, tvb,
			offset++, 1, ENC_LITTLE_ENDIAN);
	dissect_mstp(tvb, pinfo, tree, subtree, offset);
	return tvb_captured_length(tvb);
}

void
proto_register_cimetrics(void)
{
	static hf_register_info hf[] = {
		{ &hf_cimetrics_mstp_timer,
		  { "Delta Time", "cimetrics.mstp_timer",
		    FT_UINT16, BASE_DEC, NULL, 0,
		    "Milliseconds", HFILL }
		},
		{ &hf_cimetrics_mstp_value,
		  { "8-bit value", "cimetrics.mstp_value",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		}
	};
	static hf_register_info hf2[] = {
		{ &hf_llc_cimetrics_pid,
		  { "PID", "llc.cimetrics_pid",
		    FT_UINT16, BASE_HEX, VALS(cimetrics_pid_vals), 0,
		    NULL, HFILL }
		}
	};
	static int *ett[] = {
		&ett_cimetrics_mstp
	};

	proto_cimetrics_mstp = proto_register_protocol("Cimetrics MS/TP",
						       "Cimetrics MS/TP", "cimetrics");

	proto_register_field_array(proto_cimetrics_mstp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	cimetric_handle = register_dissector("cimetrics", dissect_cimetrics_mstp, proto_cimetrics_mstp);

	llc_add_oui(OUI_CIMETRICS, "llc.cimetrics_pid",
		    "LLC Cimetrics OUI PID", hf2, proto_cimetrics_mstp);
}

void
proto_reg_handoff_cimetrics(void)
{
	dissector_add_uint("llc.cimetrics_pid", 1, cimetric_handle);
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
