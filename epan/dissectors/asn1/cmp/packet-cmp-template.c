/* packet-cmp.c
 *
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
 * Updated to RFC4210 CMPv2 and associated "Transport Protocols for CMP" draft
 *   Martin Peylo 2008
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <wsutil/array.h>
#include "packet-ber.h"
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-pkcs10.h"
#include "packet-tcp.h"
#include "packet-http.h"
#include <epan/prefs.h>

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

#define TCP_PORT_CMP 829

void proto_register_cmp(void);

static dissector_handle_t cmp_http_handle;
static dissector_handle_t cmp_tcp_style_http_handle;
static dissector_handle_t cmp_tcp_handle;

/* desegmentation of CMP over TCP */
static bool cmp_desegment = true;

static unsigned cmp_alternate_http_port;
static unsigned cmp_alternate_tcp_style_http_port;

/* Initialize the protocol and registered fields */
static int proto_cmp;
static int hf_cmp_type_oid;
static int hf_cmp_tcptrans_len;
static int hf_cmp_tcptrans_type;
static int hf_cmp_tcptrans_poll_ref;
static int hf_cmp_tcptrans_next_poll_ref;
static int hf_cmp_tcptrans_ttcb;
static int hf_cmp_tcptrans10_version;
static int hf_cmp_tcptrans10_flags;
#include "packet-cmp-hf.c"

/* Initialize the subtree pointers */
static int ett_cmp;
#include "packet-cmp-ett.c"
#include "packet-cmp-fn.c"

static int
dissect_cmp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	return dissect_cmp_PKIMessage(false, tvb, 0, &asn1_ctx, tree, -1);
}

#define CMP_TYPE_PKIMSG		0
#define CMP_TYPE_POLLREP	1
#define CMP_TYPE_POLLREQ	2
#define CMP_TYPE_NEGPOLLREP	3
#define CMP_TYPE_PARTIALMSGREP	4
#define CMP_TYPE_FINALMSGREP	5
#define CMP_TYPE_ERRORMSGREP	6
static const value_string cmp_pdu_types[] = {
	{ CMP_TYPE_PKIMSG,		"pkiMsg" },
	{ CMP_TYPE_POLLREP,		"pollRep" },
	{ CMP_TYPE_POLLREQ,		"pollReq" },
	{ CMP_TYPE_NEGPOLLREP,		"negPollRep" },
	{ CMP_TYPE_PARTIALMSGREP,	"partialMsgRep" },
	{ CMP_TYPE_FINALMSGREP,		"finalMsgRep" },
	{ CMP_TYPE_ERRORMSGREP,		"errorMsgRep" },
	{ 0, NULL },
};


static int dissect_cmp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	tvbuff_t   *next_tvb;
	uint32_t   pdu_len;
	uint8_t    pdu_type;
	proto_item *item=NULL;
	proto_item *ti=NULL;
	proto_tree *tree=NULL;
	proto_tree *tcptrans_tree=NULL;
	int offset=0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");
	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_uint8(tvb, 4);

	if (pdu_type < 10) {
		/* RFC2510 TCP transport */
		ti = proto_tree_add_item(tree, proto_cmp, tvb, offset, 5, ENC_NA);
		tcptrans_tree = proto_item_add_subtree(ti, ett_cmp);
		proto_tree_add_item(tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	} else {
		/* post RFC2510 TCP transport - the former "type" field is now "version" */
		tcptrans_tree = proto_tree_add_subtree(tree, tvb, offset, 7, ett_cmp, NULL, "TCP transport");
		pdu_type=tvb_get_uint8(tvb, 6);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_len, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_version, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans10_flags, tvb, offset++, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_type, tvb, offset++, 1, ENC_BIG_ENDIAN);
	}

	col_add_str (pinfo->cinfo, COL_INFO, val_to_str (pdu_type, cmp_pdu_types, "0x%x"));

	switch(pdu_type){
		case CMP_TYPE_PKIMSG:
			next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_reported_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, pinfo, tree, NULL);
			offset += tvb_reported_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_POLLREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CMP_TYPE_POLLREQ:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case CMP_TYPE_NEGPOLLREP:
			break;
		case CMP_TYPE_PARTIALMSGREP:
			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_next_poll_ref, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(tcptrans_tree, hf_cmp_tcptrans_ttcb, tvb, offset, 4, ENC_TIME_SECS|ENC_BIG_ENDIAN);
			offset += 4;

			next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_reported_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, pinfo, tree, NULL);
			offset += tvb_reported_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_FINALMSGREP:
			next_tvb = tvb_new_subset_length_caplen(tvb, offset, tvb_reported_length_remaining(tvb, offset), pdu_len);
			dissect_cmp_pdu(next_tvb, pinfo, tree, NULL);
			offset += tvb_reported_length_remaining(tvb, offset);
			break;
		case CMP_TYPE_ERRORMSGREP:
			/*XXX to be added*/
			break;
	}

	return offset;
}

static unsigned get_cmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                             int offset, void *data _U_)
{
	uint32_t plen;

	/*
	 * Get the length of the CMP-over-TCP packet.
	 */
	plen = tvb_get_ntohl(tvb, offset);

	return plen+4;
}


/* CMP over TCP: RFC2510 section 5.2 and "Transport Protocols for CMP" draft */
static int
dissect_cmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data)
{
	uint32_t pdu_len;
	uint8_t pdu_type;
	int offset=4; /* RFC2510 TCP transport header length */

	/* only attempt to dissect it as CMP over TCP if we have
	 * at least 5 bytes.
	 */
	if (!tvb_bytes_exist(tvb, 0, 5)) {
		return 0;
	}

	pdu_len=tvb_get_ntohl(tvb, 0);
	pdu_type=tvb_get_uint8(tvb, 4);

	if(pdu_type == 10) {
		/* post RFC2510 TCP transport */
		pdu_type = tvb_get_uint8(tvb, 7);
		offset = 7; /* post RFC2510 TCP transport header length */
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 3 byte for post RFC2510 TCP transport
		 */
		if((pdu_len<=2)||(pdu_len>10000)){
			return 0;
		}
	} else {
		/* RFC2510 TCP transport */
		/* type is between 0 and 6 */
		if(pdu_type>6){
			return 0;
		}
		/* arbitrary limit: assume a CMP over TCP pdu is never >10000 bytes
		 * in size.
		 * It is definitely at least 1 byte to accommodate the flags byte
		 */
		if((pdu_len<=0)||(pdu_len>10000)){
			return 0;
		}
	}

	/* type 0 contains a PKI message and must therefore be >= 3 bytes
	 * long (flags + BER TAG + BER LENGTH
	 */
	if((pdu_type==0)&&(pdu_len<3)){
		return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, parent_tree, cmp_desegment, offset, get_cmp_pdu_len,
			dissect_cmp_tcp_pdu, data);

	return tvb_captured_length(tvb);
}


static int
dissect_cmp_http(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");
	col_set_str(pinfo->cinfo, COL_INFO, "PKIXCMP");

	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	return dissect_cmp_pdu(tvb, pinfo, tree, NULL);
}


/*--- proto_register_cmp ----------------------------------------------*/
void proto_register_cmp(void) {

	/* List of fields */
	static hf_register_info hf[] = {
		{ &hf_cmp_type_oid,
			{ "InfoType", "cmp.type.oid",
				FT_STRING, BASE_NONE, NULL, 0,
				"Type of InfoTypeAndValue", HFILL }},
		{ &hf_cmp_tcptrans_len,
			{ "Length", "cmp.tcptrans.length",
				FT_UINT32, BASE_DEC, NULL, 0,
				"TCP transport Length of PDU in bytes", HFILL }},
		{ &hf_cmp_tcptrans_type,
			{ "Type", "cmp.tcptrans.type",
				FT_UINT8, BASE_DEC, VALS(cmp_pdu_types), 0,
				"TCP transport PDU Type", HFILL }},
		{ &hf_cmp_tcptrans_poll_ref,
			{ "Polling Reference", "cmp.tcptrans.poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_next_poll_ref,
			{ "Next Polling Reference", "cmp.tcptrans.next_poll_ref",
				FT_UINT32, BASE_HEX, NULL, 0,
				"TCP transport Next Polling Reference", HFILL }},
		{ &hf_cmp_tcptrans_ttcb,
			{ "Time to check Back", "cmp.tcptrans.ttcb",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				"TCP transport Time to check Back", HFILL }},
		{ &hf_cmp_tcptrans10_version,
			{ "Version", "cmp.tcptrans10.version",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport version", HFILL }},
		{ &hf_cmp_tcptrans10_flags,
			{ "Flags", "cmp.tcptrans10.flags",
				FT_UINT8, BASE_DEC, NULL, 0,
				"TCP transport flags", HFILL }},
#include "packet-cmp-hfarr.c"
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_cmp,
#include "packet-cmp-ettarr.c"
	};
	module_t *cmp_module;

	/* Register protocol */
	proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_cmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register preferences */
	cmp_module = prefs_register_protocol(proto_cmp, proto_reg_handoff_cmp);
	prefs_register_bool_preference(cmp_module, "desegment",
			"Reassemble CMP-over-TCP messages spanning multiple TCP segments",
			"Whether the CMP-over-TCP dissector should reassemble messages spanning multiple TCP segments. "
			"To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&cmp_desegment);

	prefs_register_uint_preference(cmp_module, "http_alternate_port",
			"Alternate HTTP port",
			"Decode this TCP port\'s traffic as CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_http_port);

	prefs_register_uint_preference(cmp_module, "tcp_style_http_alternate_port",
			"Alternate TCP-style-HTTP port",
			"Decode this TCP port\'s traffic as TCP-transport-style CMP-over-HTTP. Set to \"0\" to disable. "
			"Use this if the Content-Type is not set correctly.",
			10,
			&cmp_alternate_tcp_style_http_port);

	/* Register dissectors */
        /* XXX - Since RFC 6712 the plain HTTP transfer method is exclusively
         * preferred now, so possibly it should have the plain "cmp" short
         * name, but leave it.
         * https://datatracker.ietf.org/doc/html/rfc6712#section-1
         */
	cmp_http_handle = register_dissector_with_description("cmp.http", PSNAME, dissect_cmp_http, proto_cmp);
	cmp_tcp_style_http_handle = register_dissector_with_description("cmp.tcp_pdu", PSNAME " TCP-Messaging PDU", dissect_cmp_tcp_pdu, proto_cmp);
	cmp_tcp_handle = register_dissector_with_description("cmp", PSNAME " TCP-Messaging", dissect_cmp_tcp, proto_cmp);
	register_ber_syntax_dissector("PKIMessage", proto_cmp, dissect_cmp_pdu);
}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	static bool inited = false;
	static unsigned cmp_alternate_http_port_prev = 0;
	static unsigned cmp_alternate_tcp_style_http_port_prev = 0;

	if (!inited) {
		dissector_add_string("media_type", "application/pkixcmp", cmp_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp", cmp_http_handle);

		dissector_add_string("media_type", "application/pkixcmp-poll", cmp_tcp_style_http_handle);
		dissector_add_string("media_type", "application/x-pkixcmp-poll", cmp_tcp_style_http_handle);

		dissector_add_uint_with_preference("tcp.port", TCP_PORT_CMP, cmp_tcp_handle);

		oid_add_from_string("Cryptlib-presence-check","1.3.6.1.4.1.3029.3.1.1");
		oid_add_from_string("Cryptlib-PKIBoot","1.3.6.1.4.1.3029.3.1.2");

		oid_add_from_string("HMAC MD5","1.3.6.1.5.5.8.1.1");
		oid_add_from_string("HMAC SHA-1","1.3.6.1.5.5.8.1.2");
		oid_add_from_string("HMAC TIGER","1.3.6.1.5.5.8.1.3");
		oid_add_from_string("HMAC RIPEMD-160","1.3.6.1.5.5.8.1.4");

#include "packet-cmp-dis-tab.c"
		inited = true;
	}

	/* change alternate HTTP port if changed in the preferences */
	if (cmp_alternate_http_port != cmp_alternate_http_port_prev) {
		if (cmp_alternate_http_port_prev != 0) {
			http_tcp_dissector_delete(cmp_alternate_http_port_prev);
		}
		if (cmp_alternate_http_port != 0)
			http_tcp_dissector_add( cmp_alternate_http_port, cmp_http_handle);
		cmp_alternate_http_port_prev = cmp_alternate_http_port;
	}

	/* change alternate TCP-style-HTTP port if changed in the preferences */
	if (cmp_alternate_tcp_style_http_port != cmp_alternate_tcp_style_http_port_prev) {
		if (cmp_alternate_tcp_style_http_port_prev != 0) {
			http_tcp_dissector_delete(cmp_alternate_tcp_style_http_port_prev);
		}
		if (cmp_alternate_tcp_style_http_port != 0)
			http_tcp_dissector_add( cmp_alternate_tcp_style_http_port, cmp_tcp_style_http_handle);
		cmp_alternate_tcp_style_http_port_prev = cmp_alternate_tcp_style_http_port;
	}

}

