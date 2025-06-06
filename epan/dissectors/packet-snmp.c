/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-snmp.c                                                              */
/* asn2wrs.py -b -q -L -p snmp -c ./snmp.cnf -s ./packet-snmp-template -D . -O ../.. snmp.asn */

/* packet-snmp.c
 * Routines for SNMP (simple network management protocol)
 * Copyright (C) 1998 Didier Jorand
 *
 * See RFC 1157 for SNMPv1.
 *
 * See RFCs 1901, 1905, and 1906 for SNMPv2c.
 *
 * See RFCs 1905, 1906, 1909, and 1910 for SNMPv2u [historic].
 *
 * See RFCs 2570-2576 for SNMPv3
 * Updated to use the asn2wrs compiler made by Tomas Kukosa
 * Copyright (C) 2005 - 2006 Anders Broman [AT] ericsson.com
 *
 * See RFC 3414 for User-based Security Model for SNMPv3
 * See RFC 3826 for  (AES) Cipher Algorithm in the SNMP USM
 * See RFC 2578 for Structure of Management Information Version 2 (SMIv2)
 * Copyright (C) 2007 Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Some stuff from:
 *
 * GXSNMP -- An snmp mangament application
 * Copyright (C) 1998 Gregory McLean & Jochen Friedrich
 * Beholder RMON ethernet network monitor,Copyright (C) 1993 DNPAP group
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#if 0
#include <stdio.h>
#define D(args) do {printf args; fflush(stdout); } while(0)
#endif

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/next_tvb.h>
#include <epan/uat.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/srt_table.h>
#include <epan/tap.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-ipx.h"
#include "packet-hpext.h"
#include "packet-ber.h"
#include "packet-snmp.h"
#include <wsutil/wsgcrypt.h>

#define PNAME  "Simple Network Management Protocol"
#define PSNAME "SNMP"
#define PFNAME "snmp"

#define UDP_PORT_SNMP		161
#define UDP_PORT_SNMP_TRAP	162
#define TCP_PORT_SNMP		161
#define TCP_PORT_SNMP_TRAP	162
#define TCP_PORT_SMUX		199
#define UDP_PORT_SNMP_PATROL 8161
#define SNMP_NUM_PROCEDURES 8

/* Initialize the protocol and registered fields */
static int snmp_tap;
static int proto_snmp;
static int proto_smux;

static bool display_oid = true;
static bool snmp_var_in_tree = true;

void proto_register_snmp(void);
void proto_reg_handoff_snmp(void);
void proto_register_smux(void);
void proto_reg_handoff_smux(void);

static void snmp_usm_password_to_key(const snmp_usm_auth_model_t model, const uint8_t *password, unsigned passwordlen,
	const uint8_t *engineID, unsigned engineLength, uint8_t *key);

static tvbuff_t* snmp_usm_priv_des(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, char const**);
static tvbuff_t* snmp_usm_priv_aes128(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, char const**);
static tvbuff_t* snmp_usm_priv_aes192(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, char const**);
static tvbuff_t* snmp_usm_priv_aes256(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, char const**);

static bool snmp_usm_auth(const packet_info *pinfo, const snmp_usm_auth_model_t model, snmp_usm_params_t* p, uint8_t**, unsigned*, char const**);

static const value_string auth_types[] = {
	{SNMP_USM_AUTH_MD5,"MD5"},
	{SNMP_USM_AUTH_SHA1,"SHA1"},
	{SNMP_USM_AUTH_SHA2_224,"SHA2-224"},
	{SNMP_USM_AUTH_SHA2_256,"SHA2-256"},
	{SNMP_USM_AUTH_SHA2_384,"SHA2-384"},
	{SNMP_USM_AUTH_SHA2_512,"SHA2-512"},
	{0,NULL}
};

static const unsigned auth_hash_len[] = {
	HASH_MD5_LENGTH,
	HASH_SHA1_LENGTH,
	HASH_SHA2_224_LENGTH,
	HASH_SHA2_256_LENGTH,
	HASH_SHA2_384_LENGTH,
	HASH_SHA2_512_LENGTH
};

static const unsigned auth_tag_len[] = {
	12,
	12,
	16,
	24,
	32,
	48
};

static const enum gcry_md_algos auth_hash_algo[] = {
	GCRY_MD_MD5,
	GCRY_MD_SHA1,
	GCRY_MD_SHA224,
	GCRY_MD_SHA256,
	GCRY_MD_SHA384,
	GCRY_MD_SHA512
};

#define PRIV_DES	0
#define PRIV_AES128	1
#define PRIV_AES192	2
#define PRIV_AES256	3

static const value_string priv_types[] = {
	{ PRIV_DES,    "DES" },
	{ PRIV_AES128, "AES" },
	{ PRIV_AES192, "AES192" },
	{ PRIV_AES256, "AES256" },
	{ 0, NULL}
};
static snmp_usm_decoder_t priv_protos[] = {
	snmp_usm_priv_des,
	snmp_usm_priv_aes128,
	snmp_usm_priv_aes192,
	snmp_usm_priv_aes256
};

#define PRIVKEYEXP_USM_3DESDESEDE_00	0
#define PRIVKEYEXP_AGENTPP				1

static const value_string priv_key_exp_types[] = {
	{ PRIVKEYEXP_USM_3DESDESEDE_00, "draft-reeder-snmpv3-usm-3desede-00" },
	{ PRIVKEYEXP_AGENTPP, "AGENT++" },
	{ 0, NULL }
};

static snmp_ue_assoc_t* ueas;
static unsigned num_ueas;
static snmp_ue_assoc_t* localized_ues;
static snmp_ue_assoc_t* unlocalized_ues;
/****/

/* Variables used for handling enterprise specific trap types */
typedef struct _snmp_st_assoc_t {
	char *enterprise;
	unsigned trap;
	char *desc;
} snmp_st_assoc_t;
static unsigned num_specific_traps;
static snmp_st_assoc_t *specific_traps;
static const char *enterprise_oid;
static unsigned generic_trap;
static uint32_t snmp_version;
static uint32_t RequestID = -1;

static snmp_usm_params_t usm_p;

#define TH_AUTH   0x01
#define TH_CRYPT  0x02
#define TH_REPORT 0x04

/* desegmentation of SNMP-over-TCP */
static bool snmp_desegment = true;

/* Global variables */

uint32_t MsgSecurityModel;
tvbuff_t *oid_tvb=NULL;
tvbuff_t *value_tvb=NULL;

static dissector_handle_t snmp_handle;
static dissector_handle_t snmp_tcp_handle;
static dissector_handle_t data_handle;
static dissector_handle_t smux_handle;

static next_tvb_list_t *var_list;

static int hf_snmp_response_in;
static int hf_snmp_response_to;
static int hf_snmp_time;

static int hf_snmp_v3_flags_auth;
static int hf_snmp_v3_flags_crypt;
static int hf_snmp_v3_flags_report;

static int hf_snmp_engineid_conform;
static int hf_snmp_engineid_enterprise;
static int hf_snmp_engineid_format;
static int hf_snmp_engineid_ipv4;
static int hf_snmp_engineid_ipv6;
static int hf_snmp_engineid_cisco_type;
static int hf_snmp_engineid_mac;
static int hf_snmp_engineid_text;
static int hf_snmp_engineid_time;
static int hf_snmp_engineid_data;
static int hf_snmp_decryptedPDU;
static int hf_snmp_msgAuthentication;

static int hf_snmp_noSuchObject;
static int hf_snmp_noSuchInstance;
static int hf_snmp_endOfMibView;
static int hf_snmp_unSpecified;

static int hf_snmp_integer32_value;
static int hf_snmp_octetstring_value;
static int hf_snmp_oid_value;
static int hf_snmp_null_value;
static int hf_snmp_ipv4_value;
static int hf_snmp_ipv6_value;
static int hf_snmp_anyaddress_value;
static int hf_snmp_unsigned32_value;
static int hf_snmp_unknown_value;
static int hf_snmp_opaque_value;
static int hf_snmp_nsap_value;
static int hf_snmp_counter_value;
static int hf_snmp_timeticks_value;
static int hf_snmp_big_counter_value;
static int hf_snmp_gauge32_value;

static int hf_snmp_objectname;
static int hf_snmp_scalar_instance_index;

static int hf_snmp_var_bind_str;
static int hf_snmp_agentid_trailer;

static int hf_snmp_SMUX_PDUs_PDU;                 /* SMUX_PDUs */
static int hf_snmp_version;                       /* Version */
static int hf_snmp_community;                     /* Community */
static int hf_snmp_data;                          /* PDUs */
static int hf_snmp_parameters;                    /* OCTET_STRING */
static int hf_snmp_datav2u;                       /* T_datav2u */
static int hf_snmp_v2u_plaintext;                 /* PDUs */
static int hf_snmp_encrypted;                     /* OCTET_STRING */
static int hf_snmp_msgAuthoritativeEngineID;      /* T_msgAuthoritativeEngineID */
static int hf_snmp_msgAuthoritativeEngineBoots;   /* T_msgAuthoritativeEngineBoots */
static int hf_snmp_msgAuthoritativeEngineTime;    /* T_msgAuthoritativeEngineTime */
static int hf_snmp_msgUserName;                   /* T_msgUserName */
static int hf_snmp_msgAuthenticationParameters;   /* T_msgAuthenticationParameters */
static int hf_snmp_msgPrivacyParameters;          /* T_msgPrivacyParameters */
static int hf_snmp_msgVersion;                    /* Version */
static int hf_snmp_msgGlobalData;                 /* HeaderData */
static int hf_snmp_msgSecurityParameters;         /* T_msgSecurityParameters */
static int hf_snmp_msgData;                       /* ScopedPduData */
static int hf_snmp_msgID;                         /* INTEGER_0_2147483647 */
static int hf_snmp_msgMaxSize;                    /* INTEGER_484_2147483647 */
static int hf_snmp_msgFlags;                      /* T_msgFlags */
static int hf_snmp_msgSecurityModel;              /* T_msgSecurityModel */
static int hf_snmp_plaintext;                     /* ScopedPDU */
static int hf_snmp_encryptedPDU;                  /* T_encryptedPDU */
static int hf_snmp_contextEngineID;               /* SnmpEngineID */
static int hf_snmp_contextName;                   /* OCTET_STRING */
static int hf_snmp_get_request;                   /* GetRequest_PDU */
static int hf_snmp_get_next_request;              /* GetNextRequest_PDU */
static int hf_snmp_get_response;                  /* GetResponse_PDU */
static int hf_snmp_set_request;                   /* SetRequest_PDU */
static int hf_snmp_trap;                          /* Trap_PDU */
static int hf_snmp_getBulkRequest;                /* GetBulkRequest_PDU */
static int hf_snmp_informRequest;                 /* InformRequest_PDU */
static int hf_snmp_snmpV2_trap;                   /* SNMPv2_Trap_PDU */
static int hf_snmp_report;                        /* Report_PDU */
static int hf_snmp_request_id;                    /* T_request_id */
static int hf_snmp_error_status;                  /* T_error_status */
static int hf_snmp_error_index;                   /* INTEGER */
static int hf_snmp_variable_bindings;             /* VarBindList */
static int hf_snmp_bulkPDU_request_id;            /* Integer32 */
static int hf_snmp_non_repeaters;                 /* INTEGER_0_2147483647 */
static int hf_snmp_max_repetitions;               /* INTEGER_0_2147483647 */
static int hf_snmp_enterprise;                    /* EnterpriseOID */
static int hf_snmp_agent_addr;                    /* NetworkAddress */
static int hf_snmp_generic_trap;                  /* GenericTrap */
static int hf_snmp_specific_trap;                 /* SpecificTrap */
static int hf_snmp_time_stamp;                    /* TimeTicks */
static int hf_snmp_name;                          /* ObjectName */
static int hf_snmp_valueType;                     /* ValueType */
static int hf_snmp_VarBindList_item;              /* VarBind */
static int hf_snmp_open;                          /* OpenPDU */
static int hf_snmp_close;                         /* ClosePDU */
static int hf_snmp_registerRequest;               /* RReqPDU */
static int hf_snmp_registerResponse;              /* RegisterResponse */
static int hf_snmp_commitOrRollback;              /* SOutPDU */
static int hf_snmp_rRspPDU;                       /* RRspPDU */
static int hf_snmp_pDUs;                          /* PDUs */
static int hf_snmp_smux_simple;                   /* SimpleOpen */
static int hf_snmp_smux_version;                  /* T_smux_version */
static int hf_snmp_identity;                      /* OBJECT_IDENTIFIER */
static int hf_snmp_description;                   /* DisplayString */
static int hf_snmp_password;                      /* OCTET_STRING */
static int hf_snmp_subtree;                       /* ObjectName */
static int hf_snmp_priority;                      /* INTEGER_M1_2147483647 */
static int hf_snmp_operation;                     /* T_operation */

/* Initialize the subtree pointers */
static int ett_smux;
static int ett_snmp;
static int ett_engineid;
static int ett_msgFlags;
static int ett_encryptedPDU;
static int ett_decrypted;
static int ett_authParameters;
static int ett_internet;
static int ett_varbind;
static int ett_name;
static int ett_value;
static int ett_decoding_error;

static int ett_snmp_Message;
static int ett_snmp_Messagev2u;
static int ett_snmp_T_datav2u;
static int ett_snmp_UsmSecurityParameters;
static int ett_snmp_SNMPv3Message;
static int ett_snmp_HeaderData;
static int ett_snmp_ScopedPduData;
static int ett_snmp_ScopedPDU;
static int ett_snmp_PDUs;
static int ett_snmp_PDU;
static int ett_snmp_BulkPDU;
static int ett_snmp_Trap_PDU_U;
static int ett_snmp_VarBind;
static int ett_snmp_VarBindList;
static int ett_snmp_SMUX_PDUs;
static int ett_snmp_RegisterResponse;
static int ett_snmp_OpenPDU;
static int ett_snmp_SimpleOpen_U;
static int ett_snmp_RReqPDU_U;

static expert_field ei_snmp_failed_decrypted_data_pdu;
static expert_field ei_snmp_decrypted_data_bad_formatted;
static expert_field ei_snmp_verify_authentication_error;
static expert_field ei_snmp_authentication_ok;
static expert_field ei_snmp_authentication_error;
static expert_field ei_snmp_varbind_not_uni_class_seq;
static expert_field ei_snmp_varbind_has_indicator;
static expert_field ei_snmp_objectname_not_oid;
static expert_field ei_snmp_objectname_has_indicator;
static expert_field ei_snmp_value_not_primitive_encoding;
static expert_field ei_snmp_invalid_oid;
static expert_field ei_snmp_varbind_wrong_tag;
static expert_field ei_snmp_varbind_response;
static expert_field ei_snmp_no_instance_subid;
static expert_field ei_snmp_wrong_num_of_subids;
static expert_field ei_snmp_index_suboid_too_short;
static expert_field ei_snmp_unimplemented_instance_index;
static expert_field ei_snmp_index_suboid_len0;
static expert_field ei_snmp_index_suboid_too_long;
static expert_field ei_snmp_index_string_too_long;
static expert_field ei_snmp_column_parent_not_row;
static expert_field ei_snmp_uint_too_large;
static expert_field ei_snmp_int_too_large;
static expert_field ei_snmp_integral_value0;
static expert_field ei_snmp_missing_mib;
static expert_field ei_snmp_varbind_wrong_length_value;
static expert_field ei_snmp_varbind_wrong_class_tag;
static expert_field ei_snmp_rfc1910_non_conformant;
static expert_field ei_snmp_rfc3411_non_conformant;
static expert_field ei_snmp_version_unknown;
static expert_field ei_snmp_trap_pdu_obsolete;

static const true_false_string auth_flags = {
	"OK",
	"Failed"
};

/* Security Models */

#define SNMP_SEC_ANY			0
#define SNMP_SEC_V1			1
#define SNMP_SEC_V2C			2
#define SNMP_SEC_USM			3

static const value_string sec_models[] = {
	{ SNMP_SEC_ANY,			"Any" },
	{ SNMP_SEC_V1,			"V1" },
	{ SNMP_SEC_V2C,			"V2C" },
	{ SNMP_SEC_USM,			"USM" },
	{ 0,				NULL }
};

#if 0
/* SMUX PDU types */
#define SMUX_MSG_OPEN 		0
#define SMUX_MSG_CLOSE		1
#define SMUX_MSG_RREQ		2
#define SMUX_MSG_RRSP		3
#define SMUX_MSG_SOUT		4

static const value_string smux_types[] = {
	{ SMUX_MSG_OPEN,	"Open" },
	{ SMUX_MSG_CLOSE,	"Close" },
	{ SMUX_MSG_RREQ,	"Registration Request" },
	{ SMUX_MSG_RRSP,	"Registration Response" },
	{ SMUX_MSG_SOUT,	"Commit Or Rollback" },
	{ 0,			NULL }
};
#endif

/* Procedure names (used in Service Response Time) */
static const value_string snmp_procedure_names[] = {
	{ 0,	"Get" },
	{ 1,	"GetNext" },
	{ 3,	"Set" },
	{ 4,	"Register" },
	{ 5,	"Bulk" },
	{ 6,	"Inform" },
	{ 0,	NULL }
};

#define SNMP_IPA    0		/* IP Address */
#define SNMP_CNT    1		/* Counter (Counter32) */
#define SNMP_GGE    2		/* Gauge (Gauge32) */
#define SNMP_TIT    3		/* TimeTicks */
#define SNMP_OPQ    4		/* Opaque */
#define SNMP_NSP    5		/* NsapAddress */
#define SNMP_C64    6		/* Counter64 */
#define SNMP_U32    7		/* Uinteger32 */

#define SERR_NSO    0
#define SERR_NSI    1
#define SERR_EOM    2


dissector_table_t value_sub_dissectors_table;

/*
 * Data structure attached to a conversation, request/response information
 */
typedef struct snmp_conv_info_t {
	wmem_map_t *request_response;
} snmp_conv_info_t;

static snmp_conv_info_t*
snmp_find_conversation_and_get_conv_data(packet_info *pinfo);

static snmp_request_response_t *
snmp_get_request_response_pointer(wmem_map_t *map, uint32_t requestId)
{
	snmp_request_response_t *srrp=(snmp_request_response_t *)wmem_map_lookup(map, &requestId);
	if (!srrp) {
		srrp=wmem_new0(wmem_file_scope(), snmp_request_response_t);
		srrp->requestId=requestId;
		wmem_map_insert(map, &(srrp->requestId), (void *)srrp);
	}

	return srrp;
}

static snmp_request_response_t*
snmp_match_request_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned requestId, unsigned procedure_id, snmp_conv_info_t *snmp_info)
{
	snmp_request_response_t *srrp=NULL;

	DISSECTOR_ASSERT_HINT(snmp_info, "No SNMP info from ASN1 context");

	/* get or create request/response pointer based on request id */
	srrp=(snmp_request_response_t *)snmp_get_request_response_pointer(snmp_info->request_response, requestId);

	// if not visited fill the request/response data
	if (!PINFO_FD_VISITED(pinfo)) {
		switch(procedure_id)
		{
			case SNMP_REQ_GET:
			case SNMP_REQ_GETNEXT:
			case SNMP_REQ_SET:
			case SNMP_REQ_GETBULK:
			case SNMP_REQ_INFORM:
				srrp->request_frame_id=pinfo->fd->num;
				srrp->response_frame_id=0;
				srrp->request_time=pinfo->abs_ts;
				srrp->request_procedure_id=procedure_id;
				break;
			case SNMP_RES_GET:
				srrp->response_frame_id=pinfo->fd->num;
				break;
			default:
				return NULL;
		}
	}

	/* if request and response was matched */
	if (srrp->request_frame_id!=0 && srrp->response_frame_id!=0)
	{
		proto_item *it;

		// if it is the response
		if (srrp->response_frame_id == pinfo->fd->num)
		{
			nstime_t ns;
			it=proto_tree_add_uint(tree, hf_snmp_response_to, tvb, 0, 0, srrp->request_frame_id);
			proto_item_set_generated(it);
			nstime_delta(&ns, &pinfo->abs_ts, &srrp->request_time);
			it=proto_tree_add_time(tree, hf_snmp_time, tvb, 0, 0, &ns);
			proto_item_set_generated(it);

			return srrp;
		} else {
			it=proto_tree_add_uint(tree, hf_snmp_response_in, tvb, 0, 0, srrp->response_frame_id);
			proto_item_set_generated(it);
		}
	}

	return NULL;
}

static void
snmpstat_init(struct register_srt* srt _U_, GArray* srt_array)
{
	srt_stat_table *snmp_srt_table;
	uint32_t i;

	snmp_srt_table = init_srt_table("SNMP Commands", NULL, srt_array, SNMP_NUM_PROCEDURES, NULL, "snmp.data", NULL);
	for (i = 0; i < SNMP_NUM_PROCEDURES; i++)
	{
		init_srt_table_row(snmp_srt_table, i, val_to_str_const(i, snmp_procedure_names, "<unknown>"));
	}
}

/* This is called only if request and response was matched -> no need to return anything than TAP_PACKET_REDRAW */
static tap_packet_status
snmpstat_packet(void *psnmp, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi, tap_flags_t flags _U_)
{
	unsigned i = 0;
	srt_stat_table *snmp_srt_table;
	const snmp_request_response_t *snmp=(const snmp_request_response_t *)psi;
	srt_data_t *data = (srt_data_t *)psnmp;

	snmp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);

	add_srt_table_data(snmp_srt_table, snmp->request_procedure_id, &snmp->request_time, pinfo);
	return TAP_PACKET_REDRAW;
}

static const char *
snmp_lookup_specific_trap (unsigned specific_trap)
{
	unsigned i;

	for (i = 0; i < num_specific_traps; i++) {
		snmp_st_assoc_t *u = &(specific_traps[i]);

		if ((u->trap == specific_trap) &&
		    (strcmp (u->enterprise, enterprise_oid) == 0))
		{
			return u->desc;
		}
	}

	return NULL;
}

static int
dissect_snmp_variable_string(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{

	proto_tree_add_item(tree, hf_snmp_var_bind_str, tvb, 0, -1, ENC_ASCII);

	return tvb_captured_length(tvb);
}

/*
DateAndTime ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"
    STATUS       current
    DESCRIPTION
            "A date-time specification.

            field  octets  contents                  range
            -----  ------  --------                  -----
              1      1-2   year*                     0..65536
              2       3    month                     1..12
              3       4    day                       1..31
              4       5    hour                      0..23
              5       6    minutes                   0..59
              6       7    seconds                   0..60
                           (use 60 for leap-second)
              7       8    deci-seconds              0..9
              8       9    direction from UTC        '+' / '-'
              9      10    hours from UTC*           0..13
             10      11    minutes from UTC          0..59

            * Notes:
            - the value of year is in network-byte order
            - daylight saving time in New Zealand is +13

            For example, Tuesday May 26, 1992 at 1:30:15 PM EDT would be
            displayed as:

                             1992-5-26,13:30:15.0,-4:0

            Note that if only local time is known, then timezone
            information (fields 8-10) is not present."
    SYNTAX       OCTET STRING (SIZE (8 | 11))
*/
static proto_item *
dissect_snmp_variable_date_and_time(proto_tree *tree, packet_info *pinfo, int hfid, tvbuff_t *tvb, int offset, int length)
{
	uint16_t year;
	uint8_t month;
	uint8_t day;
	uint8_t hour;
	uint8_t minutes;
	uint8_t seconds;
	uint8_t deci_seconds;
	uint8_t hour_from_utc;
	uint8_t min_from_utc;
	char *str;

	year			= tvb_get_ntohs(tvb,offset);
	month			= tvb_get_uint8(tvb,offset+2);
	day			= tvb_get_uint8(tvb,offset+3);
	hour			= tvb_get_uint8(tvb,offset+4);
	minutes			= tvb_get_uint8(tvb,offset+5);
	seconds			= tvb_get_uint8(tvb,offset+6);
	deci_seconds		= tvb_get_uint8(tvb,offset+7);
	if(length > 8){
		hour_from_utc	= tvb_get_uint8(tvb,offset+9);
		min_from_utc	= tvb_get_uint8(tvb,offset+10);

		str = wmem_strdup_printf(pinfo->pool,
			 "%u-%u-%u, %u:%u:%u.%u UTC %s%u:%u",
			 year,
			 month,
			 day,
			 hour,
			 minutes,
			 seconds,
			 deci_seconds,
			 tvb_get_string_enc(pinfo->pool,tvb,offset+8,1,ENC_ASCII|ENC_NA),
			 hour_from_utc,
			 min_from_utc);
	}else{
		 str = wmem_strdup_printf(pinfo->pool,
			 "%u-%u-%u, %u:%u:%u.%u",
			 year,
			 month,
			 day,
			 hour,
			 minutes,
			 seconds,
			 deci_seconds);
	}

	return proto_tree_add_string(tree, hfid, tvb, offset, length, str);

}

/*
 *  dissect_snmp_VarBind
 *  this routine dissects variable bindings, looking for the oid information in our oid reporsitory
 *  to format and add the value adequatelly.
 *
 * The choice to handwrite this code instead of using the asn compiler is to avoid having tons
 * of uses of global variables distributed in very different parts of the code.
 * Other than that there's a cosmetic thing: the tree from ASN generated code would be so
 * convoluted due to the nesting of CHOICEs in the definition of VarBind/value.
 *
 * XXX: the length of this function (~400 lines) is an aberration!
 *  oid_key_t:key_type could become a series of callbacks instead of an enum
 *  the (! oid_info_is_ok) switch could be made into an array (would be slower)
 *

	NetworkAddress ::=  CHOICE { internet IpAddress }
	IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
	TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
	Integer32 ::= INTEGER (-2147483648..2147483647)
	ObjectName ::= OBJECT IDENTIFIER
	Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
	Gauge32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
	Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
	Integer-value ::=  INTEGER (-2147483648..2147483647)
	Integer32 ::= INTEGER (-2147483648..2147483647)
	ObjectID-value ::= OBJECT IDENTIFIER
	Empty ::= NULL
	TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
	Opaque ::= [APPLICATION 4] IMPLICIT OCTET STRING
	Counter64 ::= [APPLICATION 6] IMPLICIT INTEGER (0..18446744073709551615)

	ObjectSyntax ::= CHOICE {
		 simple SimpleSyntax,
		 application-wide ApplicationSyntax
	}

	SimpleSyntax ::= CHOICE {
	   integer-value Integer-value,
	   string-value String-value,
	   objectID-value ObjectID-value,
	   empty  Empty
	}

	ApplicationSyntax ::= CHOICE {
	   ipAddress-value IpAddress,
	   counter-value Counter32,
	   timeticks-value TimeTicks,
	   arbitrary-value Opaque,
	   big-counter-value Counter64,
	   unsigned-integer-value Unsigned32
	}

	ValueType ::=  CHOICE {
	   value ObjectSyntax,
	   unSpecified NULL,
	   noSuchObject[0] IMPLICIT NULL,
	   noSuchInstance[1] IMPLICIT NULL,
	   endOfMibView[2] IMPLICIT NULL
	}

	VarBind ::= SEQUENCE {
	   name ObjectName,
	   valueType ValueType
	}

 */

static int
dissect_snmp_VarBind(bool implicit_tag _U_, tvbuff_t *tvb, int offset,
		     asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
	int seq_offset, name_offset, value_offset, value_start;
	uint32_t seq_len, name_len, value_len;
	int8_t ber_class;
	bool pc;
	int32_t tag;
	bool ind;
	uint32_t* subids;
	uint8_t* oid_bytes;
	oid_info_t* oid_info = NULL;
	unsigned oid_matched, oid_left;
	proto_item *pi_name, *pi_varbind, *pi_value = NULL;
	proto_tree *pt, *pt_varbind, *pt_name, *pt_value;
	char label[ITEM_LABEL_LENGTH];
	const char* repr = NULL;
	const char* info_oid = NULL;
	char* valstr;
	int hfid = -1;
	int min_len = 0, max_len = 0;
	bool oid_info_is_ok;
	const char* oid_string = NULL;
	enum {BER_NO_ERROR, BER_WRONG_LENGTH, BER_WRONG_TAG} format_error = BER_NO_ERROR;

	seq_offset = offset;

	/* first have the VarBind's sequence header */
	offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
	offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &seq_len, &ind);

	if (!pc && ber_class==BER_CLASS_UNI && tag==BER_UNI_TAG_SEQUENCE) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len + (offset - seq_offset),
				ett_decoding_error, &pi, "VarBind must be an universal class sequence");
		expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_not_uni_class_seq);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	if (ind) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len + (offset - seq_offset),
					ett_decoding_error, &pi, "Indicator must be clear in VarBind");
		expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_has_indicator);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	/* we add the varbind tree root with a dummy label we'll fill later on */
	pt_varbind = proto_tree_add_subtree(tree,tvb,offset,seq_len,ett_varbind,&pi_varbind,"VarBind");
	*label = '\0';

	seq_len += offset - seq_offset;

	/* then we have the ObjectName's header */

	offset = dissect_ber_identifier(actx->pinfo, pt_varbind, tvb, offset, &ber_class, &pc, &tag);
	name_offset = offset = dissect_ber_length(actx->pinfo, pt_varbind, tvb, offset, &name_len, &ind);

	if (! ( !pc && ber_class==BER_CLASS_UNI && tag==BER_UNI_TAG_OID) ) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len,
				ett_decoding_error, &pi, "ObjectName must be an OID in primitive encoding");
		expert_add_info(actx->pinfo, pi, &ei_snmp_objectname_not_oid);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	if (ind) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len,
				ett_decoding_error, &pi, "Indicator must be clear in ObjectName");
		expert_add_info(actx->pinfo, pi, &ei_snmp_objectname_has_indicator);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	pi_name = proto_tree_add_item(pt_varbind,hf_snmp_objectname,tvb,name_offset,name_len,ENC_NA);
	pt_name = proto_item_add_subtree(pi_name,ett_name);

	offset += name_len;
	value_start = offset;
	/* then we have the value's header */
	offset = dissect_ber_identifier(actx->pinfo, pt_varbind, tvb, offset, &ber_class, &pc, &tag);
	value_offset = dissect_ber_length(actx->pinfo, pt_varbind, tvb, offset, &value_len, &ind);

	if (! (!pc) ) {
		proto_item* pi;
		pt = proto_tree_add_subtree(pt_varbind, tvb, value_start, value_len,
				ett_decoding_error, &pi, "the value must be in primitive encoding");
		expert_add_info(actx->pinfo, pi, &ei_snmp_value_not_primitive_encoding);
		return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
	}

	/* Now, we know where everything is */

	/* fetch ObjectName and its relative oid_info */
	oid_bytes = (uint8_t*)tvb_memdup(actx->pinfo->pool, tvb, name_offset, name_len);
	oid_info = oid_get_from_encoded(actx->pinfo->pool, oid_bytes, name_len, &subids, &oid_matched, &oid_left);

	add_oid_debug_subtree(oid_info,pt_name);

	if (!subids) {
		proto_item* pi;

		repr = oid_encoded2string(actx->pinfo->pool, oid_bytes, name_len);
		pt = proto_tree_add_subtree_format(pt_name,tvb, 0, 0, ett_decoding_error, &pi, "invalid oid: %s", repr);
		expert_add_info_format(actx->pinfo, pi, &ei_snmp_invalid_oid, "invalid oid: %s", repr);
		return dissect_unknown_ber(actx->pinfo, tvb, name_offset, pt);
	}

	if (oid_matched+oid_left) {
		oid_string = oid_subid2string(actx->pinfo->pool, subids,oid_matched+oid_left);
	}

	if (ber_class == BER_CLASS_CON) {
		/* if we have an error value just add it and get out the way ASAP */
		proto_item* pi;
		const char* note;

		if (value_len != 0) {
			min_len = max_len = 0;
			format_error = BER_WRONG_LENGTH;
		}

		switch (tag) {
			case SERR_NSO:
				hfid = hf_snmp_noSuchObject;
				note = "noSuchObject";
				break;
			case SERR_NSI:
				hfid = hf_snmp_noSuchInstance;
				note = "noSuchInstance";
				break;
			case SERR_EOM:
				hfid = hf_snmp_endOfMibView;
				note = "endOfMibView";
				break;
			default: {
				pt = proto_tree_add_subtree_format(pt_varbind,tvb,0,0,ett_decoding_error,&pi,
								"Wrong tag for Error Value: expected 0, 1, or 2 but got: %d",tag);
				expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_wrong_tag);
				return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
			}
		}

		pi = proto_tree_add_item(pt_varbind,hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
		expert_add_info_format(actx->pinfo, pi, &ei_snmp_varbind_response, "%s",note);
		(void) g_strlcpy (label, note, ITEM_LABEL_LENGTH);
		goto set_label;
	}

	/* now we'll try to figure out which are the indexing sub-oids and whether the oid we know about is the one oid we have to use */
	switch (oid_info->kind) {
		case OID_KIND_SCALAR:
			if (oid_left == 1) {
				/* OK: we got the instance sub-id */
				proto_tree_add_uint64(pt_name,hf_snmp_scalar_instance_index,tvb,name_offset,name_len,subids[oid_matched]);
				oid_info_is_ok = true;
				goto indexing_done;
			} else if (oid_left == 0) {
				if (ber_class == BER_CLASS_UNI && tag == BER_UNI_TAG_NULL) {
					/* unSpecified  does not require an instance sub-id add the new value and get off the way! */
					pi_value = proto_tree_add_item(pt_varbind,hf_snmp_unSpecified,tvb,value_offset,value_len,ENC_NA);
					goto set_label;
				} else {
					proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_no_instance_subid,tvb,0,0);
					oid_info_is_ok = false;
					goto indexing_done;
				}
			} else {
				proto_tree_add_expert_format(pt_name,actx->pinfo,&ei_snmp_wrong_num_of_subids,tvb,0,0,"A scalar should have only one instance sub-id this has: %d",oid_left);
				oid_info_is_ok = false;
				goto indexing_done;
			}
		break;
		case OID_KIND_COLUMN:
			if ( oid_info->parent->kind == OID_KIND_ROW) {
				oid_key_t* k = oid_info->parent->key;
				unsigned key_start = oid_matched;
				unsigned key_len = oid_left;
				oid_info_is_ok = true;

				if ( key_len == 0 && ber_class == BER_CLASS_UNI && tag == BER_UNI_TAG_NULL) {
					/* unSpecified  does not require an instance sub-id add the new value and get off the way! */
					pi_value = proto_tree_add_item(pt_varbind,hf_snmp_unSpecified,tvb,value_offset,value_len,ENC_NA);
					goto set_label;
				}

				if (k) {
					for (;k;k = k->next) {
						unsigned suboid_len;

						if (key_start >= oid_matched+oid_left) {
							proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_suboid_too_short,tvb,0,0);
							oid_info_is_ok = false;
							goto indexing_done;
						}

						switch(k->key_type) {
							case OID_KEY_TYPE_WRONG: {
								proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_unimplemented_instance_index,tvb,0,0);
								oid_info_is_ok = false;
								goto indexing_done;
							}
							case OID_KEY_TYPE_INTEGER: {
								if (FT_IS_INT(k->ft_type)) {
									proto_tree_add_int(pt_name,k->hfid,tvb,name_offset,name_len,(unsigned)subids[key_start]);
								} else { /* if it's not an unsigned int let proto_tree_add_uint throw a warning */
									proto_tree_add_uint64(pt_name,k->hfid,tvb,name_offset,name_len,(unsigned)subids[key_start]);
								}
								key_start++;
								key_len--;
								continue; /* k->next */
							}
							case OID_KEY_TYPE_IMPLIED_OID:
								suboid_len = key_len;

								goto show_oid_index;

							case OID_KEY_TYPE_OID: {
								uint8_t* suboid_buf;
								unsigned suboid_buf_len;
								uint32_t* suboid;

								suboid_len = subids[key_start++];
								key_len--;

show_oid_index:
								suboid = &(subids[key_start]);

								if( suboid_len == 0 ) {
									proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_suboid_len0,tvb,0,0);
									oid_info_is_ok = false;
									goto indexing_done;
								}

								if( key_len < suboid_len ) {
									proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_suboid_too_long,tvb,0,0);
									oid_info_is_ok = false;
									goto indexing_done;
								}

								suboid_buf_len = oid_subid2encoded(actx->pinfo->pool, suboid_len, suboid, &suboid_buf);

								DISSECTOR_ASSERT(suboid_buf_len);

								proto_tree_add_oid(pt_name,k->hfid,tvb,name_offset, suboid_buf_len, suboid_buf);

								key_start += suboid_len;
								key_len -= suboid_len + 1;
								continue; /* k->next */
							}
							default: {
								uint8_t* buf;
								unsigned buf_len;
								uint32_t* suboid;
								unsigned i;


								switch (k->key_type) {
									case OID_KEY_TYPE_IPADDR:
										suboid = &(subids[key_start]);
										buf_len = 4;
										break;
									case OID_KEY_TYPE_IMPLIED_STRING:
									case OID_KEY_TYPE_IMPLIED_BYTES:
									case OID_KEY_TYPE_ETHER:
										suboid = &(subids[key_start]);
										buf_len = key_len;
										break;
									default:
										buf_len = k->num_subids;
										suboid = &(subids[key_start]);

										if(!buf_len) {
											buf_len = *suboid++;
											key_len--;
											key_start++;
										}
										break;
								}

								if( key_len < buf_len ) {
									proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_string_too_long,tvb,0,0);
									oid_info_is_ok = false;
									goto indexing_done;
								}

								buf = (uint8_t*)wmem_alloc(actx->pinfo->pool, buf_len+1);
								for (i = 0; i < buf_len; i++)
									buf[i] = (uint8_t)suboid[i];
								buf[i] = '\0';

								switch(k->key_type) {
									case OID_KEY_TYPE_STRING:
									case OID_KEY_TYPE_IMPLIED_STRING:
										proto_tree_add_string(pt_name,k->hfid,tvb,name_offset,buf_len, buf);
										break;
									case OID_KEY_TYPE_BYTES:
									case OID_KEY_TYPE_NSAP:
									case OID_KEY_TYPE_IMPLIED_BYTES:
										proto_tree_add_bytes(pt_name,k->hfid,tvb,name_offset,buf_len, buf);
										break;
									case OID_KEY_TYPE_ETHER:
										proto_tree_add_ether(pt_name,k->hfid,tvb,name_offset,buf_len, buf);
										break;
									case OID_KEY_TYPE_IPADDR: {
										uint32_t* ipv4_p = (uint32_t*)buf;
										proto_tree_add_ipv4(pt_name,k->hfid,tvb,name_offset,buf_len, *ipv4_p);
										}
										break;
									default:
										DISSECTOR_ASSERT_NOT_REACHED();
										break;
								}

								key_start += buf_len;
								key_len -= buf_len;
								continue; /* k->next*/
							}
						}
					}
					goto indexing_done;
				} else {
					proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_unimplemented_instance_index,tvb,0,0);
					oid_info_is_ok = false;
					goto indexing_done;
				}
			} else {
				proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_column_parent_not_row,tvb,0,0);
				oid_info_is_ok = false;
				goto indexing_done;
			}
		default: {
/*			proto_tree_add_expert (pt_name,actx->pinfo,PI_MALFORMED, PI_WARN,tvb,0,0,"This kind OID should have no value"); */
			oid_info_is_ok = false;
			goto indexing_done;
		}
	}
indexing_done:

	if (oid_info_is_ok && oid_info->value_type) {
		if (ber_class == BER_CLASS_UNI && tag == BER_UNI_TAG_NULL) {
			pi_value = proto_tree_add_item(pt_varbind,hf_snmp_unSpecified,tvb,value_offset,value_len,ENC_NA);
		} else {
			/* Provide a tree_item to attach errors to, if needed. */
			pi_value = pi_name;

			if ((oid_info->value_type->ber_class != BER_CLASS_ANY) &&
				(ber_class != oid_info->value_type->ber_class))
				format_error = BER_WRONG_TAG;
			else if ((oid_info->value_type->ber_tag != BER_TAG_ANY) &&
				(tag != oid_info->value_type->ber_tag))
				format_error = BER_WRONG_TAG;
			else {
				max_len = oid_info->value_type->max_len == -1 ? 0xffffff : oid_info->value_type->max_len;
				min_len = oid_info->value_type->min_len;

				if ((int)value_len < min_len || (int)value_len > max_len)
					format_error = BER_WRONG_LENGTH;
			}

			if (format_error == BER_NO_ERROR) {
				/* Special case DATE AND TIME */
				if((oid_info->value_type)&&(oid_info->value_type->keytype == OID_KEY_TYPE_DATE_AND_TIME)&&(value_len > 7)){
					pi_value = dissect_snmp_variable_date_and_time(pt_varbind, actx->pinfo, oid_info->value_hfid, tvb, value_offset, value_len);
				} else {
					pi_value = proto_tree_add_item(pt_varbind,oid_info->value_hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
				}
			}
		}
	} else {
		switch(ber_class|(tag<<4)) {
			case BER_CLASS_UNI|(BER_UNI_TAG_INTEGER<<4):
			{
				int64_t val=0;
				unsigned int int_val_offset = value_offset;
				unsigned int i;

				max_len = 4; min_len = 1;
				if (value_len > (unsigned)max_len || value_len < (unsigned)min_len) {
					hfid = hf_snmp_integer32_value;
					format_error = BER_WRONG_LENGTH;
					break;
				}

				if(value_len > 0) {
					/* extend sign bit */
					if(tvb_get_uint8(tvb, int_val_offset)&0x80) {
						val=-1;
					}
					for(i=0;i<value_len;i++) {
						val=(val<<8)|tvb_get_uint8(tvb, int_val_offset);
						int_val_offset++;
					}
				}
				pi_value = proto_tree_add_int64(pt_varbind, hf_snmp_integer32_value, tvb,value_offset,value_len, val);

				goto already_added;
			}
			case BER_CLASS_UNI|(BER_UNI_TAG_OCTETSTRING<<4):
				if(oid_info->value_hfid> -1){
					hfid = oid_info->value_hfid;
				}else{
					hfid = hf_snmp_octetstring_value;
				}
				break;
			case BER_CLASS_UNI|(BER_UNI_TAG_OID<<4):
				max_len = -1; min_len = 1;
				if (value_len < (unsigned)min_len) format_error = BER_WRONG_LENGTH;
				hfid = hf_snmp_oid_value;
				break;
			case BER_CLASS_UNI|(BER_UNI_TAG_NULL<<4):
				max_len = 0; min_len = 0;
				if (value_len != 0) format_error = BER_WRONG_LENGTH;
				hfid = hf_snmp_null_value;
				break;
			case BER_CLASS_APP: /* | (SNMP_IPA<<4)*/
				switch(value_len) {
					case 4: hfid = hf_snmp_ipv4_value; break;
					case 16: hfid = hf_snmp_ipv6_value; break;
					default: hfid = hf_snmp_anyaddress_value; break;
				}
				break;
			case BER_CLASS_APP|(SNMP_U32<<4):
				hfid = hf_snmp_unsigned32_value;
				break;
			case BER_CLASS_APP|(SNMP_GGE<<4):
				hfid = hf_snmp_gauge32_value;
				break;
			case BER_CLASS_APP|(SNMP_CNT<<4):
				hfid = hf_snmp_counter_value;
				break;
			case BER_CLASS_APP|(SNMP_TIT<<4):
				hfid = hf_snmp_timeticks_value;
				break;
			case BER_CLASS_APP|(SNMP_OPQ<<4):
				hfid = hf_snmp_opaque_value;
				break;
			case BER_CLASS_APP|(SNMP_NSP<<4):
				hfid = hf_snmp_nsap_value;
				break;
			case BER_CLASS_APP|(SNMP_C64<<4):
				hfid = hf_snmp_big_counter_value;
				break;
			default:
				hfid = hf_snmp_unknown_value;
				break;
		}
		if (value_len > 8) {
			/*
			 * Too long for an FT_UINT64 or an FT_INT64.
			 */
			header_field_info *hfinfo = proto_registrar_get_nth(hfid);
			if (hfinfo->type == FT_UINT64) {
				/*
				 * Check if this is an unsigned int64 with
				 * a big value.
				 */
				if (value_len > 9 || tvb_get_uint8(tvb, value_offset) != 0) {
					/* It is.  Fail. */
					proto_tree_add_expert_format(pt_varbind,actx->pinfo,&ei_snmp_uint_too_large,tvb,value_offset,value_len,"Integral value too large");
					goto already_added;
				}
				/* Cheat and skip the leading 0 byte */
				value_len--;
				value_offset++;
			} else if (hfinfo->type == FT_INT64) {
				/*
				 * For now, just reject these.
				 */
				proto_tree_add_expert_format(pt_varbind,actx->pinfo,&ei_snmp_int_too_large,tvb,value_offset,value_len,"Integral value too large or too small");
				goto already_added;
			}
		} else if (value_len == 0) {
			/*
			 * X.690 section 8.3.1 "Encoding of an integer value":
			 * "The encoding of an integer value shall be
			 * primitive. The contents octets shall consist of
			 * one or more octets."
			 *
			 * Zero is not "one or more".
			 */
			header_field_info *hfinfo = proto_registrar_get_nth(hfid);
			if (hfinfo->type == FT_UINT64 || hfinfo->type == FT_INT64) {
				proto_tree_add_expert_format(pt_varbind,actx->pinfo,&ei_snmp_integral_value0,tvb,value_offset,value_len,"Integral value is zero-length");
				goto already_added;
			}
		}
		/* Special case DATE AND TIME */
		if((oid_info->value_type)&&(oid_info->value_type->keytype == OID_KEY_TYPE_DATE_AND_TIME)&&(value_len > 7)){
			pi_value = dissect_snmp_variable_date_and_time(pt_varbind, actx->pinfo, hfid, tvb, value_offset, value_len);
		}else{
			pi_value = proto_tree_add_item(pt_varbind,hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
		}
		if (format_error != BER_NO_ERROR) {
			expert_add_info(actx->pinfo, pi_value, &ei_snmp_missing_mib);
		}

	}
already_added:
	pt_value = proto_item_add_subtree(pi_value,ett_value);

	if (value_len > 0 && oid_string) {
		tvbuff_t* sub_tvb = tvb_new_subset_length(tvb, value_offset, value_len);

		next_tvb_add_string(var_list, sub_tvb, (snmp_var_in_tree) ? pt_value : NULL, value_sub_dissectors_table, oid_string);
	}


set_label:
	if (pi_value) proto_item_fill_label(PITEM_FINFO(pi_value), label, NULL);

	if (oid_info && oid_info->name) {
		if (oid_left >= 1) {
			repr = wmem_strdup_printf(actx->pinfo->pool, "%s.%s (%s)", oid_info->name,
						oid_subid2string(actx->pinfo->pool, &(subids[oid_matched]),oid_left),
						oid_subid2string(actx->pinfo->pool, subids,oid_matched+oid_left));
			info_oid = wmem_strdup_printf(actx->pinfo->pool, "%s.%s", oid_info->name,
						oid_subid2string(actx->pinfo->pool, &(subids[oid_matched]),oid_left));
		} else {
			repr = wmem_strdup_printf(actx->pinfo->pool, "%s (%s)", oid_info->name,
						oid_subid2string(actx->pinfo->pool, subids,oid_matched));
			info_oid = oid_info->name;
		}
	} else if (oid_string) {
		repr = wmem_strdup(actx->pinfo->pool, oid_string);
		info_oid = oid_string;
	} else {
		repr = wmem_strdup(actx->pinfo->pool, "[Bad OID]");
	}

	valstr = strstr(label,": ");
	valstr = valstr ? valstr+2 : label;

	proto_item_set_text(pi_varbind,"%s: %s",repr,valstr);

	if (display_oid && info_oid) {
		col_append_fstr (actx->pinfo->cinfo, COL_INFO, " %s", info_oid);
	}

	switch (format_error) {
		case BER_WRONG_LENGTH: {
			proto_item* pi;
			proto_tree* p_tree = proto_item_add_subtree(pi_value,ett_decoding_error);
			pt = proto_tree_add_subtree_format(p_tree,tvb,0,0,ett_decoding_error,&pi,
							     "Wrong value length: %u  expecting: %u <= len <= %u",
							     value_len, min_len, max_len == -1 ? 0xFFFFFF : max_len);
			expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_wrong_length_value);
			return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
		}
		case BER_WRONG_TAG: {
			proto_item* pi;
			proto_tree* p_tree = proto_item_add_subtree(pi_value,ett_decoding_error);
			pt = proto_tree_add_subtree_format(p_tree,tvb,0,0,ett_decoding_error,&pi,
							     "Wrong class/tag for Value expected: %d,%d got: %d,%d",
							     oid_info->value_type->ber_class, oid_info->value_type->ber_tag,
							     ber_class, tag);
			expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_wrong_class_tag);
			return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
		}
		default:
			break;
	}

	return seq_offset + seq_len;
}


#define F_SNMP_ENGINEID_CONFORM 0x80
#define SNMP_ENGINEID_RFC1910 0x00
#define SNMP_ENGINEID_RFC3411 0x01

static const true_false_string tfs_snmp_engineid_conform = {
	"RFC3411 (SNMPv3)",
	"RFC1910 (Non-SNMPv3)"
};

#define SNMP_ENGINEID_FORMAT_IPV4 0x01
#define SNMP_ENGINEID_FORMAT_IPV6 0x02
#define SNMP_ENGINEID_FORMAT_MACADDRESS 0x03
#define SNMP_ENGINEID_FORMAT_TEXT 0x04
#define SNMP_ENGINEID_FORMAT_OCTETS 0x05
#define SNMP_ENGINEID_FORMAT_LOCAL 0x06

static const value_string snmp_engineid_format_vals[] = {
	{ SNMP_ENGINEID_FORMAT_IPV4,	"IPv4 address" },
	{ SNMP_ENGINEID_FORMAT_IPV6,	"IPv6 address" },
	{ SNMP_ENGINEID_FORMAT_MACADDRESS,	"MAC address" },
	{ SNMP_ENGINEID_FORMAT_TEXT,	"Text, administratively assigned" },
	{ SNMP_ENGINEID_FORMAT_OCTETS,	"Octets, administratively assigned" },
	{ SNMP_ENGINEID_FORMAT_LOCAL,   "Local engine" },
	{ 0,	NULL }
};

#define SNMP_ENGINEID_CISCO_AGENT 0x00
#define SNMP_ENGINEID_CISCO_MANAGER 0x01

static const value_string snmp_engineid_cisco_type_vals[] = {
	{ SNMP_ENGINEID_CISCO_AGENT,	"Agent" },
	{ SNMP_ENGINEID_CISCO_MANAGER,	"Manager" },
	{ 0,	NULL }
};

/*
 * SNMP Engine ID dissection according to RFC 3411 (SnmpEngineID TC)
 * or historic RFC 1910 (AgentID)
 */
int
dissect_snmp_engineid(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int len)
{
	proto_item *item = NULL;
	uint8_t conformance, format;
	uint32_t enterpriseid;
	time_t seconds;
	nstime_t ts;
	int len_remain = len;

	/* first bit: engine id conformance */
	if (len_remain<1) return offset;
	conformance = ((tvb_get_uint8(tvb, offset)>>7) & 0x01);
	proto_tree_add_item(tree, hf_snmp_engineid_conform, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* 4-byte enterprise number/name */
	if (len_remain<4) return offset;
	enterpriseid = tvb_get_ntohl(tvb, offset);
	if (conformance)
		enterpriseid -= 0x80000000; /* ignore first bit */
	proto_tree_add_uint(tree, hf_snmp_engineid_enterprise, tvb, offset, 4, enterpriseid);
	offset+=4;
	len_remain-=4;

	switch(conformance) {

	case SNMP_ENGINEID_RFC1910:
		/* 12-byte AgentID w/ 8-byte trailer */
		if (len_remain==8) {
			proto_tree_add_item(tree, hf_snmp_agentid_trailer, tvb, offset, 8, ENC_NA);
			offset+=8;
			len_remain-=8;
		} else {
			proto_tree_add_expert(tree, pinfo, &ei_snmp_rfc1910_non_conformant, tvb, offset, len_remain);
			return offset;
		}
		break;

	case SNMP_ENGINEID_RFC3411: /* variable length: 5..32 */

		/* 1-byte format specifier */
		if (len_remain<1) return offset;
		format = tvb_get_uint8(tvb, offset);
		item = proto_tree_add_uint_format(tree, hf_snmp_engineid_format, tvb, offset, 1, format, "Engine ID Format: %s (%d)",
						  val_to_str_const(format, snmp_engineid_format_vals, "Reserved/Enterprise-specific"),
						  format);
		offset+=1;
		len_remain-=1;

		switch(format) {
		case SNMP_ENGINEID_FORMAT_IPV4:
			/* 4-byte IPv4 address */
			if (len_remain==4) {
				proto_tree_add_item(tree, hf_snmp_engineid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset+=4;
				len_remain=0;
			}
			break;
		case SNMP_ENGINEID_FORMAT_IPV6:
			/* 16-byte IPv6 address */
			if (len_remain==16) {
				proto_tree_add_item(tree, hf_snmp_engineid_ipv6, tvb, offset, 16, ENC_NA);
				offset+=16;
				len_remain=0;
			}
			break;
		case SNMP_ENGINEID_FORMAT_MACADDRESS:
			/* See: https://supportforums.cisco.com/message/3010617#3010617 for details. */
			if ((enterpriseid==9)&&(len_remain==7)) {
				proto_tree_add_item(tree, hf_snmp_engineid_cisco_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				len_remain--;
			}
			/* 6-byte MAC address */
			if (len_remain==6) {
				proto_tree_add_item(tree, hf_snmp_engineid_mac, tvb, offset, 6, ENC_NA);
				offset+=6;
				len_remain=0;
			}
			break;
		case SNMP_ENGINEID_FORMAT_TEXT:
			/* max. 27-byte string, administratively assigned */
			if (len_remain<=27) {
				proto_tree_add_item(tree, hf_snmp_engineid_text, tvb, offset, len_remain, ENC_ASCII);
				offset+=len_remain;
				len_remain=0;
			}
			break;
		case SNMP_ENGINEID_FORMAT_LOCAL:
			break;
		case 128:
			/* most common enterprise-specific format: (ucd|net)-snmp random */
			if ((enterpriseid==2021)||(enterpriseid==8072)) {
				proto_item_append_text(item, (enterpriseid==2021) ? ": UCD-SNMP Random" : ": Net-SNMP Random");
				/* demystify: 4B random, 4B/8B epoch seconds */
				if ((len_remain==8) || (len_remain==12)) {
					proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, 4, ENC_NA);
					if (len_remain==8) {
						seconds = (time_t)tvb_get_letohl(tvb, offset + 4);
					} else {
						seconds = (time_t)tvb_get_letohi64(tvb, offset + 4);
					}
					ts.secs = seconds;
					ts.nsecs = 0;
					proto_tree_add_time_format_value(tree, hf_snmp_engineid_time, tvb, offset + 4, len_remain - 4,
									 &ts, "%s",
									 abs_time_secs_to_str(pinfo->pool, seconds, ABSOLUTE_TIME_LOCAL, true));
					offset+=len_remain;
					len_remain=0;
				}
			break;
			}
		/* fall through */
		case SNMP_ENGINEID_FORMAT_OCTETS:
		default:
			/* max. 27 bytes, administratively assigned or unknown format */
			if (len_remain>0 && len_remain<=27) {
				proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, len_remain, ENC_NA);
				offset+=len_remain;
				len_remain=0;
			}
		break;
		}
	}

	if (len_remain>0) {
		proto_tree_add_expert(tree, pinfo, &ei_snmp_rfc3411_non_conformant, tvb, offset, len_remain);
		offset+=len_remain;
	}
	return offset;
}


static void set_ue_keys(snmp_ue_assoc_t* n ) {
	unsigned const key_size = auth_hash_len[n->user.authModel];

	n->user.authKey.data = (uint8_t *)g_malloc(key_size);
	n->user.authKey.len = key_size;
	snmp_usm_password_to_key(n->user.authModel,
				 n->user.authPassword.data,
				 n->user.authPassword.len,
				 n->engine.data,
				 n->engine.len,
				 n->user.authKey.data);

	if (n->priv_proto == PRIV_AES128 || n->priv_proto == PRIV_AES192 || n->priv_proto == PRIV_AES256) {
		unsigned need_key_len =
			(n->priv_proto == PRIV_AES128) ? 16 :
			(n->priv_proto == PRIV_AES192) ? 24 :
			(n->priv_proto == PRIV_AES256) ? 32 :
			0;

		unsigned key_len = key_size;

		while (key_len < need_key_len)
			key_len += key_size;

		n->user.privKey.data = (uint8_t *)g_malloc(key_len);
		n->user.privKey.len  = need_key_len;

		snmp_usm_password_to_key(n->user.authModel,
					 n->user.privPassword.data,
					 n->user.privPassword.len,
					 n->engine.data,
					 n->engine.len,
					 n->user.privKey.data);

		key_len = key_size;

		/* extend key if needed */
		while (key_len < need_key_len) {
			switch (n->priv_key_exp) {
				/* Baed on draft-reeder-snmpv3-usm-3desede-00, section 2.1 */
				case PRIVKEYEXP_USM_3DESDESEDE_00:
				{
					snmp_usm_password_to_key(n->user.authModel,
								n->user.privKey.data + (key_len - key_size),
								key_size,
								n->engine.data,
								n->engine.len,
								n->user.privKey.data + key_len);
					break;
				}
				/* Based on snmp++ method PrivAES::extend_short_key in Agent++ */
				case PRIVKEYEXP_AGENTPP:
				{
					/* Key expansion in Agent++
					 * K1 = key
					 * K2 = hash(K1)
					 * K3 = hash(K1 | K2)
					 * localized_key = K1 | K2 | K3
					 */
					gcry_md_hd_t hash_handle;

					if (gcry_md_open(&hash_handle, auth_hash_algo[n->user.authModel], 0)) {
						return;
					}

					gcry_md_write(hash_handle, n->user.privKey.data, key_len);
					memcpy(n->user.privKey.data + key_len, gcry_md_read(hash_handle, 0), key_size);
					gcry_md_close(hash_handle);

					break;
				}

				default:
					break;
			}

			key_len += key_size;
		}

	} else {
		n->user.privKey.data = (uint8_t *)g_malloc(key_size);
		n->user.privKey.len = key_size;
		snmp_usm_password_to_key(n->user.authModel,
					 n->user.privPassword.data,
					 n->user.privPassword.len,
					 n->engine.data,
					 n->engine.len,
					 n->user.privKey.data);
	}
}

static snmp_ue_assoc_t*
ue_dup(snmp_ue_assoc_t* o)
{
	snmp_ue_assoc_t* d = (snmp_ue_assoc_t*)g_memdup2(o,sizeof(snmp_ue_assoc_t));

	d->user.authModel = o->user.authModel;

	d->user.privProtocol = o->user.privProtocol;

	d->user.userName.data = (uint8_t *)g_memdup2(o->user.userName.data,o->user.userName.len);
	d->user.userName.len = o->user.userName.len;

	d->user.authPassword.data = o->user.authPassword.data ? (uint8_t *)g_memdup2(o->user.authPassword.data,o->user.authPassword.len) : NULL;
	d->user.authPassword.len = o->user.authPassword.len;

	d->user.privPassword.data = o->user.privPassword.data ? (uint8_t *)g_memdup2(o->user.privPassword.data,o->user.privPassword.len) : NULL;
	d->user.privPassword.len = o->user.privPassword.len;

	d->engine.len = o->engine.len;

	if (d->engine.len) {
		d->engine.data = (uint8_t *)g_memdup2(o->engine.data,o->engine.len);
		set_ue_keys(d);
	}

	return d;

}

static void*
snmp_users_copy_cb(void* dest, const void* orig, size_t len _U_)
{
	const snmp_ue_assoc_t* o = (const snmp_ue_assoc_t*)orig;
	snmp_ue_assoc_t* d = (snmp_ue_assoc_t*)dest;

	d->auth_model = o->auth_model;
	d->user.authModel = (snmp_usm_auth_model_t) o->auth_model;

	d->priv_proto = o->priv_proto;
	d->user.privProtocol = priv_protos[o->priv_proto];

	d->user.userName.data = (uint8_t*)g_memdup2(o->user.userName.data,o->user.userName.len);
	d->user.userName.len = o->user.userName.len;

	d->user.authPassword.data = o->user.authPassword.data ? (uint8_t*)g_memdup2(o->user.authPassword.data,o->user.authPassword.len) : NULL;
	d->user.authPassword.len = o->user.authPassword.len;

	d->user.privPassword.data = o->user.privPassword.data ? (uint8_t*)g_memdup2(o->user.privPassword.data,o->user.privPassword.len) : NULL;
	d->user.privPassword.len = o->user.privPassword.len;

	d->engine.len = o->engine.len;
	if (o->engine.data) {
		d->engine.data = (uint8_t*)g_memdup2(o->engine.data,o->engine.len);
	}

	d->user.authKey.data = o->user.authKey.data ? (uint8_t*)g_memdup2(o->user.authKey.data,o->user.authKey.len) : NULL;
	d->user.authKey.len = o->user.authKey.len;

	d->user.privKey.data = o->user.privKey.data ? (uint8_t*)g_memdup2(o->user.privKey.data,o->user.privKey.len) : NULL;
	d->user.privKey.len = o->user.privKey.len;

	return d;
}

static void
snmp_users_free_cb(void* p)
{
	snmp_ue_assoc_t* ue = (snmp_ue_assoc_t*)p;
	g_free(ue->user.userName.data);
	g_free(ue->user.authPassword.data);
	g_free(ue->user.privPassword.data);
	g_free(ue->user.authKey.data);
	g_free(ue->user.privKey.data);
	g_free(ue->engine.data);
}

static bool
snmp_users_update_cb(void* p _U_, char** err)
{
	snmp_ue_assoc_t* ue = (snmp_ue_assoc_t*)p;
	GString* es = g_string_new("");
	unsigned int i;

	*err = NULL;

	if (! ue->user.userName.len) {
		g_string_append_printf(es,"no userName\n");
	} else if ((ue->engine.len > 0) && (ue->engine.len < 5 || ue->engine.len > 32)) {
		/* RFC 3411 section 5 */
		g_string_append_printf(es, "Invalid engineId length (%u). Must be between 5 and 32 (10 and 64 hex digits)\n", ue->engine.len);
	} else if (num_ueas) {
		for (i=0; i<num_ueas-1; i++) {
			snmp_ue_assoc_t* u = &(ueas[i]);

			if ( u->user.userName.len == ue->user.userName.len
				&& u->engine.len == ue->engine.len && (u != ue)) {

				if (u->engine.len > 0 && memcmp( u->engine.data, ue->engine.data, u->engine.len ) == 0) {
					if ( memcmp( u->user.userName.data, ue->user.userName.data, ue->user.userName.len ) == 0 ) {
						/* XXX: make a string for the engineId */
						g_string_append_printf(es,"Duplicate key (userName='%s')\n",ue->user.userName.data);
						break;
					}
				}

				if (u->engine.len == 0) {
					if ( memcmp( u->user.userName.data, ue->user.userName.data, ue->user.userName.len ) == 0 ) {
						g_string_append_printf(es,"Duplicate key (userName='%s' engineId=NONE)\n",ue->user.userName.data);
						break;
					}
				}
			}
		}
	}

	if (es->len) {
		es = g_string_truncate(es,es->len-1);
		*err = g_string_free(es, FALSE);
		return false;
	}

        g_string_free(es, TRUE);
	return true;
}

static void
free_ue_cache(snmp_ue_assoc_t **cache)
{
	static snmp_ue_assoc_t *a, *nxt;

	for (a = *cache; a; a = nxt) {
		nxt = a->next;
		snmp_users_free_cb(a);
		g_free(a);
	}

	*cache = NULL;
}

#define CACHE_INSERT(c,a) if (c) { snmp_ue_assoc_t* t = c; c = a; c->next = t; } else { c = a; a->next = NULL; }

static void
init_ue_cache(void)
{
	unsigned i;

	for (i = 0; i < num_ueas; i++) {
		snmp_ue_assoc_t* a = ue_dup(&(ueas[i]));

		if (a->engine.len) {
			CACHE_INSERT(localized_ues,a);

		} else {
			CACHE_INSERT(unlocalized_ues,a);
		}

	}
}

static void
cleanup_ue_cache(void)
{
	free_ue_cache(&localized_ues);
	free_ue_cache(&unlocalized_ues);
}

/* Called when the user applies changes to UAT preferences. */
static void
renew_ue_cache(void)
{
	cleanup_ue_cache();
	init_ue_cache();
}


static snmp_ue_assoc_t*
localize_ue( snmp_ue_assoc_t* o, const uint8_t* engine, unsigned engine_len )
{
	snmp_ue_assoc_t* n = (snmp_ue_assoc_t*)g_memdup2(o,sizeof(snmp_ue_assoc_t));

	n->user.userName.data = (uint8_t*)g_memdup2(o->user.userName.data,o->user.userName.len);
	n->user.authModel = o->user.authModel;
	n->user.authPassword.data = (uint8_t*)g_memdup2(o->user.authPassword.data,o->user.authPassword.len);
	n->user.authPassword.len = o->user.authPassword.len;
	n->user.privPassword.data = (uint8_t*)g_memdup2(o->user.privPassword.data,o->user.privPassword.len);
	n->user.privPassword.len = o->user.privPassword.len;
	n->user.authKey.data = (uint8_t*)g_memdup2(o->user.authKey.data,o->user.authKey.len);
	n->user.privKey.data = (uint8_t*)g_memdup2(o->user.privKey.data,o->user.privKey.len);
	n->engine.data = (uint8_t*)g_memdup2(engine,engine_len);
	n->engine.len = engine_len;
	n->priv_proto = o->priv_proto;

	set_ue_keys(n);

	return n;
}


#define localized_match(a,u,ul,e,el) \
	( a->user.userName.len == ul \
	&& a->engine.len == el \
	&& memcmp( a->user.userName.data, u, ul ) == 0 \
	&& memcmp( a->engine.data,   e,  el ) == 0 )

#define unlocalized_match(a,u,l) \
	( a->user.userName.len == l && memcmp( a->user.userName.data, u, l) == 0 )

static snmp_ue_assoc_t*
get_user_assoc(tvbuff_t* engine_tvb, tvbuff_t* user_tvb, packet_info *pinfo)
{
	static snmp_ue_assoc_t* a;
	unsigned given_username_len;
	uint8_t* given_username;
	unsigned given_engine_len = 0;
	uint8_t* given_engine = NULL;

	if ( ! (localized_ues || unlocalized_ues ) ) return NULL;

	if (! ( user_tvb && engine_tvb ) ) return NULL;

	given_username_len = tvb_captured_length(user_tvb);
	given_engine_len = tvb_captured_length(engine_tvb);
	if (! ( given_engine_len && given_username_len ) ) return NULL;
	given_username = (uint8_t*)tvb_memdup(pinfo->pool,user_tvb,0,-1);
	given_engine = (uint8_t*)tvb_memdup(pinfo->pool,engine_tvb,0,-1);

	for (a = localized_ues; a; a = a->next) {
		if ( localized_match(a, given_username, given_username_len, given_engine, given_engine_len) ) {
			return a;
		}
	}

	for (a = unlocalized_ues; a; a = a->next) {
		if ( unlocalized_match(a, given_username, given_username_len) ) {
			snmp_ue_assoc_t* n = localize_ue( a, given_engine, given_engine_len );
			CACHE_INSERT(localized_ues,n);
			return n;
		}
	}

	return NULL;
}

static bool
snmp_usm_auth(const packet_info *pinfo, const snmp_usm_auth_model_t model, snmp_usm_params_t* p, uint8_t** calc_auth_p,
	unsigned* calc_auth_len_p, char const** error)
{
	int msg_len;
	uint8_t* msg;
	unsigned auth_len;
	uint8_t* auth;
	uint8_t* key;
	unsigned key_len;
	uint8_t *calc_auth;
	unsigned start;
	unsigned end;
	unsigned i;

	if (!p->auth_tvb) {
		*error = "No Authenticator";
		return false;
	}

	key = p->user_assoc->user.authKey.data;
	key_len = p->user_assoc->user.authKey.len;

	if (! key ) {
		*error = "User has no authKey";
		return false;
	}

	auth_len = tvb_captured_length(p->auth_tvb);

	if (auth_len != auth_tag_len[model]) {
		*error = "Authenticator length wrong";
		return false;
	}

	msg_len = tvb_captured_length(p->msg_tvb);
	if (msg_len <= 0) {
		*error = "Not enough data remaining";
		return false;
	}
	msg = (uint8_t*)tvb_memdup(pinfo->pool,p->msg_tvb,0,msg_len);

	auth = (uint8_t*)tvb_memdup(pinfo->pool,p->auth_tvb,0,auth_len);

	start = p->auth_offset - p->start_offset;
	end =   start + auth_len;

	/* fill the authenticator with zeros */
	for ( i = start ; i < end ; i++ ) {
		msg[i] = '\0';
	}

	calc_auth = (uint8_t*)wmem_alloc(pinfo->pool, auth_hash_len[model]);

	if (ws_hmac_buffer(auth_hash_algo[model], calc_auth, msg, msg_len, key, key_len)) {
		return false;
	}

	if (calc_auth_p) *calc_auth_p = calc_auth;
	if (calc_auth_len_p) *calc_auth_len_p = auth_len;

	return ( memcmp(auth,calc_auth,auth_len) != 0 ) ? false : true;
}

static tvbuff_t*
snmp_usm_priv_des(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, char const** error)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd = NULL;

	uint8_t* cleartext;
	uint8_t* des_key = p->user_assoc->user.privKey.data; /* first 8 bytes */
	uint8_t* pre_iv = &(p->user_assoc->user.privKey.data[8]); /* last 8 bytes */
	uint8_t* salt;
	int salt_len;
	int cryptgrm_len;
	uint8_t* cryptgrm;
	tvbuff_t* clear_tvb;
	uint8_t iv[8];
	unsigned i;


	salt_len = tvb_captured_length(p->priv_tvb);

	if (salt_len != 8) {
		*error = "decryptionError: msgPrivacyParameters length != 8";
		return NULL;
	}

	salt = (uint8_t*)tvb_memdup(pinfo->pool,p->priv_tvb,0,salt_len);

	/*
	 The resulting "salt" is XOR-ed with the pre-IV to obtain the IV.
	 */
	for (i=0; i<8; i++) {
		iv[i] = pre_iv[i] ^ salt[i];
	}

	cryptgrm_len = tvb_captured_length(encryptedData);

	if ((cryptgrm_len <= 0) || (cryptgrm_len % 8)) {
		*error = "decryptionError: the length of the encrypted data is not a multiple of 8 octets";
		return NULL;
	}

	cryptgrm = (uint8_t*)tvb_memdup(pinfo->pool,encryptedData,0,-1);

	cleartext = (uint8_t*)wmem_alloc(pinfo->pool, cryptgrm_len);

	err = gcry_cipher_open(&hd, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setiv(hd, iv, 8);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setkey(hd,des_key,8);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_decrypt(hd, cleartext, cryptgrm_len, cryptgrm, cryptgrm_len);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	gcry_cipher_close(hd);

	clear_tvb = tvb_new_child_real_data(encryptedData, cleartext, cryptgrm_len, cryptgrm_len);

	return clear_tvb;

on_gcry_error:
	*error = (const char *)gcry_strerror(err);
	if (hd) gcry_cipher_close(hd);
	return NULL;
}

static tvbuff_t*
snmp_usm_priv_aes_common(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, char const** error, int algo)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd = NULL;

	uint8_t* cleartext;
	uint8_t* aes_key = p->user_assoc->user.privKey.data;
	int aes_key_len = p->user_assoc->user.privKey.len;
	uint8_t iv[16];
	int priv_len;
	int cryptgrm_len;
	uint8_t* cryptgrm;
	tvbuff_t* clear_tvb;

	priv_len = tvb_captured_length(p->priv_tvb);

	if (priv_len != 8) {
		*error = "decryptionError: msgPrivacyParameters length != 8";
		return NULL;
	}

	iv[0] = (p->boots & 0xff000000) >> 24;
	iv[1] = (p->boots & 0x00ff0000) >> 16;
	iv[2] = (p->boots & 0x0000ff00) >> 8;
	iv[3] = (p->boots & 0x000000ff);
	iv[4] = (p->snmp_time & 0xff000000) >> 24;
	iv[5] = (p->snmp_time & 0x00ff0000) >> 16;
	iv[6] = (p->snmp_time & 0x0000ff00) >> 8;
	iv[7] = (p->snmp_time & 0x000000ff);
	tvb_memcpy(p->priv_tvb,&(iv[8]),0,8);

	cryptgrm_len = tvb_captured_length(encryptedData);
	if (cryptgrm_len <= 0) {
		*error = "Not enough data remaining";
		return NULL;
	}
	cryptgrm = (uint8_t*)tvb_memdup(pinfo->pool,encryptedData,0,-1);

	cleartext = (uint8_t*)wmem_alloc(pinfo->pool, cryptgrm_len);

	err = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setiv(hd, iv, 16);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setkey(hd,aes_key,aes_key_len);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_decrypt(hd, cleartext, cryptgrm_len, cryptgrm, cryptgrm_len);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	gcry_cipher_close(hd);

	clear_tvb = tvb_new_child_real_data(encryptedData, cleartext, cryptgrm_len, cryptgrm_len);

	return clear_tvb;

on_gcry_error:
	*error = (const char *)gcry_strerror(err);
	if (hd) gcry_cipher_close(hd);
	return NULL;
}

static tvbuff_t*
snmp_usm_priv_aes128(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, char const** error)
{
	return snmp_usm_priv_aes_common(p, encryptedData, pinfo, error, GCRY_CIPHER_AES);
}

static tvbuff_t*
snmp_usm_priv_aes192(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, char const** error)
{
	return snmp_usm_priv_aes_common(p, encryptedData, pinfo, error, GCRY_CIPHER_AES192);
}

static tvbuff_t*
snmp_usm_priv_aes256(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, char const** error)
{
	return snmp_usm_priv_aes_common(p, encryptedData, pinfo, error, GCRY_CIPHER_AES256);
}

static bool
check_ScopedPdu(tvbuff_t* tvb)
{
	int offset;
	int8_t ber_class;
	bool pc;
	int32_t tag;
	int hoffset, eoffset;
	uint32_t len;

	offset = get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
	offset = get_ber_length(tvb, offset, NULL, NULL);

	if ( ! (((ber_class!=BER_CLASS_APP) && (ber_class!=BER_CLASS_PRI) )
			&& ( (!pc) || (ber_class!=BER_CLASS_UNI) || (tag!=BER_UNI_TAG_ENUMERATED) )
			)) return false;

	if((tvb_get_uint8(tvb, offset)==0)&&(tvb_get_uint8(tvb, offset+1)==0))
		return true;

	hoffset = offset;

	offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	offset = get_ber_length(tvb, offset, &len, NULL);
	eoffset = offset + len;

	if (eoffset <= hoffset) return false;

	if ((ber_class!=BER_CLASS_APP)&&(ber_class!=BER_CLASS_PRI))
		if( (ber_class!=BER_CLASS_UNI)
			||((tag<BER_UNI_TAG_NumericString)&&(tag!=BER_UNI_TAG_OCTETSTRING)&&(tag!=BER_UNI_TAG_UTF8String)) )
			return false;

	return true;

}




static int
dissect_snmp_EnterpriseOID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	const char* name;

  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &enterprise_oid);


	if (display_oid && enterprise_oid) {
		name = oid_resolved_from_string(actx->pinfo->pool, enterprise_oid);
		if (name) {
		col_append_fstr (actx->pinfo->cinfo, COL_INFO, " %s", name);
		}
	}


  return offset;
}



static int
dissect_snmp_OCTET_STRING_SIZE_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_snmp_NetworkAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, true, dissect_snmp_OCTET_STRING_SIZE_4);

  return offset;
}



static int
dissect_snmp_INTEGER_0_4294967295(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_TimeTicks(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, true, dissect_snmp_INTEGER_0_4294967295);

  return offset;
}



static int
dissect_snmp_Integer32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &RequestID);



  return offset;
}



static int
dissect_snmp_ObjectName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string snmp_Version_vals[] = {
  {   0, "version-1" },
  {   1, "v2c" },
  {   2, "v2u" },
  {   3, "snmpv3" },
  { 0, NULL }
};


static int
dissect_snmp_Version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &snmp_version);

  return offset;
}



static int
dissect_snmp_Community(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_snmp_T_request_id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &RequestID);



  return offset;
}


static const value_string snmp_T_error_status_vals[] = {
  {   0, "noError" },
  {   1, "tooBig" },
  {   2, "noSuchName" },
  {   3, "badValue" },
  {   4, "readOnly" },
  {   5, "genErr" },
  {   6, "noAccess" },
  {   7, "wrongType" },
  {   8, "wrongLength" },
  {   9, "wrongEncoding" },
  {  10, "wrongValue" },
  {  11, "noCreation" },
  {  12, "inconsistentValue" },
  {  13, "resourceUnavailable" },
  {  14, "commitFailed" },
  {  15, "undoFailed" },
  {  16, "authorizationError" },
  {  17, "notWritable" },
  {  18, "inconsistentName" },
  { 0, NULL }
};


static int
dissect_snmp_T_error_status(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static const ber_sequence_t VarBindList_sequence_of[1] = {
  { &hf_snmp_VarBindList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBind },
};

static int
dissect_snmp_VarBindList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      VarBindList_sequence_of, hf_index, ett_snmp_VarBindList);

  return offset;
}


static const ber_sequence_t PDU_sequence[] = {
  { &hf_snmp_request_id     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_request_id },
  { &hf_snmp_error_status   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_error_status },
  { &hf_snmp_error_index    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER },
  { &hf_snmp_variable_bindings, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBindList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDU_sequence, hf_index, ett_snmp_PDU);

  return offset;
}



static int
dissect_snmp_GetRequest_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 0, true, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_GetNextRequest_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 1, true, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_GetResponse_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, true, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_SetRequest_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 3, true, dissect_snmp_PDU);

  return offset;
}


static const value_string snmp_GenericTrap_vals[] = {
  {   0, "coldStart" },
  {   1, "warmStart" },
  {   2, "linkDown" },
  {   3, "linkUp" },
  {   4, "authenticationFailure" },
  {   5, "egpNeighborLoss" },
  {   6, "enterpriseSpecific" },
  { 0, NULL }
};


static int
dissect_snmp_GenericTrap(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &generic_trap);

  return offset;
}



static int
dissect_snmp_SpecificTrap(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  unsigned specific_trap;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &specific_trap);


	if (generic_trap == 6) { /* enterprise specific */
		const char *specific_str = snmp_lookup_specific_trap (specific_trap);
		if (specific_str) {
		proto_item_append_text(actx->created_item, " (%s)", specific_str);
		}
	}

  return offset;
}


static const ber_sequence_t Trap_PDU_U_sequence[] = {
  { &hf_snmp_enterprise     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_snmp_EnterpriseOID },
  { &hf_snmp_agent_addr     , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_snmp_NetworkAddress },
  { &hf_snmp_generic_trap   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_GenericTrap },
  { &hf_snmp_specific_trap  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_SpecificTrap },
  { &hf_snmp_time_stamp     , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_snmp_TimeTicks },
  { &hf_snmp_variable_bindings, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBindList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_Trap_PDU_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	generic_trap = 0;
	enterprise_oid = NULL;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Trap_PDU_U_sequence, hf_index, ett_snmp_Trap_PDU_U);


  if (snmp_version != 0) {
    expert_add_info(actx->pinfo, tree, &ei_snmp_trap_pdu_obsolete);
  }


  return offset;
}



static int
dissect_snmp_Trap_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, true, dissect_snmp_Trap_PDU_U);

  return offset;
}



static int
dissect_snmp_INTEGER_0_2147483647(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t BulkPDU_sequence[] = {
  { &hf_snmp_bulkPDU_request_id, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Integer32 },
  { &hf_snmp_non_repeaters  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_0_2147483647 },
  { &hf_snmp_max_repetitions, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_0_2147483647 },
  { &hf_snmp_variable_bindings, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBindList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_BulkPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BulkPDU_sequence, hf_index, ett_snmp_BulkPDU);

  return offset;
}



static int
dissect_snmp_GetBulkRequest_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 5, true, dissect_snmp_BulkPDU);

  return offset;
}



static int
dissect_snmp_InformRequest_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 6, true, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_SNMPv2_Trap_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 7, true, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_Report_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 8, true, dissect_snmp_PDU);

  return offset;
}


static const value_string snmp_PDUs_vals[] = {
  {   0, "get-request" },
  {   1, "get-next-request" },
  {   2, "get-response" },
  {   3, "set-request" },
  {   4, "trap" },
  {   5, "getBulkRequest" },
  {   6, "informRequest" },
  {   7, "snmpV2-trap" },
  {   8, "report" },
  { 0, NULL }
};

static const ber_choice_t PDUs_choice[] = {
  {   0, &hf_snmp_get_request    , BER_CLASS_CON, 0, BER_FLAGS_NOOWNTAG, dissect_snmp_GetRequest_PDU },
  {   1, &hf_snmp_get_next_request, BER_CLASS_CON, 1, BER_FLAGS_NOOWNTAG, dissect_snmp_GetNextRequest_PDU },
  {   2, &hf_snmp_get_response   , BER_CLASS_CON, 2, BER_FLAGS_NOOWNTAG, dissect_snmp_GetResponse_PDU },
  {   3, &hf_snmp_set_request    , BER_CLASS_CON, 3, BER_FLAGS_NOOWNTAG, dissect_snmp_SetRequest_PDU },
  {   4, &hf_snmp_trap           , BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_snmp_Trap_PDU },
  {   5, &hf_snmp_getBulkRequest , BER_CLASS_CON, 5, BER_FLAGS_NOOWNTAG, dissect_snmp_GetBulkRequest_PDU },
  {   6, &hf_snmp_informRequest  , BER_CLASS_CON, 6, BER_FLAGS_NOOWNTAG, dissect_snmp_InformRequest_PDU },
  {   7, &hf_snmp_snmpV2_trap    , BER_CLASS_CON, 7, BER_FLAGS_NOOWNTAG, dissect_snmp_SNMPv2_Trap_PDU },
  {   8, &hf_snmp_report         , BER_CLASS_CON, 8, BER_FLAGS_NOOWNTAG, dissect_snmp_Report_PDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_PDUs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	int pdu_type=-1;

	snmp_request_response_t *srrp;
	snmp_conv_info_t *snmp_info = (snmp_conv_info_t *)actx->private_data;

	col_clear(actx->pinfo->cinfo, COL_INFO);

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PDUs_choice, hf_index, ett_snmp_PDUs,
                                 &pdu_type);

	if( (pdu_type!=-1) && snmp_PDUs_vals[pdu_type].strptr ){
		col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s", snmp_PDUs_vals[pdu_type].strptr);

		/* pdu_type is the index, not the tag so convert it to the tag value */
		pdu_type = snmp_PDUs_vals[pdu_type].value;

		srrp=snmp_match_request_response(tvb, actx->pinfo, tree, RequestID, pdu_type, snmp_info);
		if (srrp) {
			tap_queue_packet(snmp_tap, actx->pinfo, srrp);
		}
	}



  return offset;
}


static const ber_sequence_t Message_sequence[] = {
  { &hf_snmp_version        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Version },
  { &hf_snmp_community      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_Community },
  { &hf_snmp_data           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_PDUs },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_Message(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Message_sequence, hf_index, ett_snmp_Message);

  return offset;
}



static int
dissect_snmp_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string snmp_T_datav2u_vals[] = {
  {   0, "plaintext" },
  {   1, "encrypted" },
  { 0, NULL }
};

static const ber_choice_t T_datav2u_choice[] = {
  {   0, &hf_snmp_v2u_plaintext  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_PDUs },
  {   1, &hf_snmp_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_T_datav2u(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_datav2u_choice, hf_index, ett_snmp_T_datav2u,
                                 NULL);

  return offset;
}


static const ber_sequence_t Messagev2u_sequence[] = {
  { &hf_snmp_version        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Version },
  { &hf_snmp_parameters     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { &hf_snmp_datav2u        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_T_datav2u },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_Messagev2u(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Messagev2u_sequence, hf_index, ett_snmp_Messagev2u);

  return offset;
}



static int
dissect_snmp_SnmpEngineID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	tvbuff_t* param_tvb = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &param_tvb);
	 if (param_tvb) {
		proto_tree* engine_tree = proto_item_add_subtree(actx->created_item,ett_engineid);
		dissect_snmp_engineid(engine_tree, actx->pinfo, param_tvb, 0, tvb_reported_length_remaining(param_tvb,0));
	}


  return offset;
}



static int
dissect_snmp_T_msgAuthoritativeEngineID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index, &usm_p.engine_tvb);
	 if (usm_p.engine_tvb) {
		proto_tree* engine_tree = proto_item_add_subtree(actx->created_item,ett_engineid);
		dissect_snmp_engineid(engine_tree, actx->pinfo, usm_p.engine_tvb, 0, tvb_reported_length_remaining(usm_p.engine_tvb,0));
	}


  return offset;
}



static int
dissect_snmp_T_msgAuthoritativeEngineBoots(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &usm_p.boots);

  return offset;
}



static int
dissect_snmp_T_msgAuthoritativeEngineTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &usm_p.snmp_time);

  return offset;
}



static int
dissect_snmp_T_msgUserName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &usm_p.user_tvb);

  return offset;
}



static int
dissect_snmp_T_msgAuthenticationParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	offset = dissect_ber_octet_string(false, actx, tree, tvb, offset, hf_index, &usm_p.auth_tvb);
	if (usm_p.auth_tvb) {
		usm_p.auth_item = actx->created_item;
		usm_p.auth_offset = tvb_offset_from_real_beginning(usm_p.auth_tvb);
	}

  return offset;
}



static int
dissect_snmp_T_msgPrivacyParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &usm_p.priv_tvb);

  return offset;
}


static const ber_sequence_t UsmSecurityParameters_sequence[] = {
  { &hf_snmp_msgAuthoritativeEngineID, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthoritativeEngineID },
  { &hf_snmp_msgAuthoritativeEngineBoots, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthoritativeEngineBoots },
  { &hf_snmp_msgAuthoritativeEngineTime, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthoritativeEngineTime },
  { &hf_snmp_msgUserName    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgUserName },
  { &hf_snmp_msgAuthenticationParameters, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthenticationParameters },
  { &hf_snmp_msgPrivacyParameters, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgPrivacyParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_UsmSecurityParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UsmSecurityParameters_sequence, hf_index, ett_snmp_UsmSecurityParameters);

  return offset;
}



static int
dissect_snmp_INTEGER_484_2147483647(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_T_msgFlags(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	tvbuff_t *parameter_tvb = NULL;

   offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

	if (parameter_tvb){
		uint8_t v3_flags = tvb_get_uint8(parameter_tvb, 0);
		proto_tree* flags_tree = proto_item_add_subtree(actx->created_item,ett_msgFlags);

		proto_tree_add_item(flags_tree, hf_snmp_v3_flags_report, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(flags_tree, hf_snmp_v3_flags_crypt, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(flags_tree, hf_snmp_v3_flags_auth, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);

		usm_p.encrypted = v3_flags & TH_CRYPT ? true : false;
		usm_p.authenticated = v3_flags & TH_AUTH ? true : false;
	}



  return offset;
}



static int
dissect_snmp_T_msgSecurityModel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &MsgSecurityModel);

  return offset;
}


static const ber_sequence_t HeaderData_sequence[] = {
  { &hf_snmp_msgID          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_0_2147483647 },
  { &hf_snmp_msgMaxSize     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_484_2147483647 },
  { &hf_snmp_msgFlags       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgFlags },
  { &hf_snmp_msgSecurityModel, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgSecurityModel },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_HeaderData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HeaderData_sequence, hf_index, ett_snmp_HeaderData);

  return offset;
}



static int
dissect_snmp_T_msgSecurityParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	switch(MsgSecurityModel){
		case SNMP_SEC_USM:	/* 3 */
			offset = get_ber_identifier(tvb, offset, NULL, NULL, NULL);
			offset = get_ber_length(tvb, offset, NULL, NULL);
			offset = dissect_snmp_UsmSecurityParameters(false, tvb, offset, actx, tree, -1);
			usm_p.user_assoc = get_user_assoc(usm_p.engine_tvb, usm_p.user_tvb, actx->pinfo);
			break;
		case SNMP_SEC_ANY:	/* 0 */
		case SNMP_SEC_V1:	/* 1 */
		case SNMP_SEC_V2C:	/* 2 */
		default:
			  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

			break;
	}


  return offset;
}


static const ber_sequence_t ScopedPDU_sequence[] = {
  { &hf_snmp_contextEngineID, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_SnmpEngineID },
  { &hf_snmp_contextName    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { &hf_snmp_data           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_PDUs },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_ScopedPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScopedPDU_sequence, hf_index, ett_snmp_ScopedPDU);

  return offset;
}



static int
dissect_snmp_T_encryptedPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	tvbuff_t* crypt_tvb;
	offset = dissect_ber_octet_string(false, actx, tree, tvb, offset, hf_snmp_encryptedPDU, &crypt_tvb);

	if( usm_p.encrypted && crypt_tvb
		&& usm_p.user_assoc
		&& usm_p.user_assoc->user.privProtocol ) {

		const char* error = NULL;
		proto_tree* encryptedpdu_tree = proto_item_add_subtree(actx->created_item,ett_encryptedPDU);
		tvbuff_t* cleartext_tvb = usm_p.user_assoc->user.privProtocol(&usm_p, crypt_tvb, actx->pinfo, &error );

		if (! cleartext_tvb) {
			proto_tree_add_expert_format(encryptedpdu_tree, actx->pinfo, &ei_snmp_failed_decrypted_data_pdu,
				crypt_tvb, 0, -1, "Failed to decrypt encryptedPDU: %s", error);

			col_set_str(actx->pinfo->cinfo, COL_INFO, "encryptedPDU: Failed to decrypt");

			return offset;
		} else {
			proto_item* decrypted_item;
			proto_tree* decrypted_tree;

			if (! check_ScopedPdu(cleartext_tvb)) {
				proto_tree_add_expert(encryptedpdu_tree, actx->pinfo, &ei_snmp_decrypted_data_bad_formatted, cleartext_tvb, 0, -1);

				col_set_str(actx->pinfo->cinfo, COL_INFO, "encryptedPDU: Decrypted data not formatted as expected");

				return offset;
			}


			add_new_data_source(actx->pinfo, cleartext_tvb, "Decrypted ScopedPDU");

			decrypted_item = proto_tree_add_item(encryptedpdu_tree, hf_snmp_decryptedPDU,cleartext_tvb,0,-1,ENC_NA);
			decrypted_tree = proto_item_add_subtree(decrypted_item,ett_decrypted);
			dissect_snmp_ScopedPDU(false, cleartext_tvb, 0, actx, decrypted_tree, -1);
			}
	} else {
			col_set_str(actx->pinfo->cinfo, COL_INFO, "encryptedPDU: privKey Unknown");
	}


  return offset;
}


static const value_string snmp_ScopedPduData_vals[] = {
  {   0, "plaintext" },
  {   1, "encryptedPDU" },
  { 0, NULL }
};

static const ber_choice_t ScopedPduData_choice[] = {
  {   0, &hf_snmp_plaintext      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_ScopedPDU },
  {   1, &hf_snmp_encryptedPDU   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_encryptedPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_ScopedPduData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ScopedPduData_choice, hf_index, ett_snmp_ScopedPduData,
                                 NULL);

  return offset;
}


static const ber_sequence_t SNMPv3Message_sequence[] = {
  { &hf_snmp_msgVersion     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Version },
  { &hf_snmp_msgGlobalData  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_HeaderData },
  { &hf_snmp_msgSecurityParameters, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgSecurityParameters },
  { &hf_snmp_msgData        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_ScopedPduData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_SNMPv3Message(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SNMPv3Message_sequence, hf_index, ett_snmp_SNMPv3Message);


	if( usm_p.authenticated
		&& usm_p.user_assoc ) {
		const char* error = NULL;
		proto_item* authen_item;
		proto_tree* authen_tree = proto_item_add_subtree(usm_p.auth_item,ett_authParameters);
		uint8_t* calc_auth = NULL;
		unsigned calc_auth_len = 0;

		usm_p.authOK = snmp_usm_auth(actx->pinfo, usm_p.user_assoc->user.authModel, &usm_p, &calc_auth, &calc_auth_len, &error );

		if (error) {
			expert_add_info_format( actx->pinfo, usm_p.auth_item, &ei_snmp_verify_authentication_error, "Error while verifying Message authenticity: %s", error );
		} else {
			expert_field* expert;

			authen_item = proto_tree_add_boolean(authen_tree, hf_snmp_msgAuthentication, tvb, 0, 0, usm_p.authOK);
			proto_item_set_generated(authen_item);

			if (usm_p.authOK) {
				expert = &ei_snmp_authentication_ok;
			} else {
				const char* calc_auth_str = bytes_to_str_punct(actx->pinfo->pool, calc_auth,calc_auth_len,' ');
				proto_item_append_text(authen_item, " calculated = %s", calc_auth_str);
				expert = &ei_snmp_authentication_error;
			}

			expert_add_info( actx->pinfo, authen_item, expert);
		}
	}

  return offset;
}


static const value_string snmp_T_smux_version_vals[] = {
  {   0, "version-1" },
  { 0, NULL }
};


static int
dissect_snmp_T_smux_version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_snmp_DisplayString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SimpleOpen_U_sequence[] = {
  { &hf_snmp_smux_version   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_smux_version },
  { &hf_snmp_identity       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_snmp_OBJECT_IDENTIFIER },
  { &hf_snmp_description    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_DisplayString },
  { &hf_snmp_password       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_SimpleOpen_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SimpleOpen_U_sequence, hf_index, ett_snmp_SimpleOpen_U);

  return offset;
}



static int
dissect_snmp_SimpleOpen(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, true, dissect_snmp_SimpleOpen_U);

  return offset;
}


static const value_string snmp_OpenPDU_vals[] = {
  {   0, "smux-simple" },
  { 0, NULL }
};

static const ber_choice_t OpenPDU_choice[] = {
  {   0, &hf_snmp_smux_simple    , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_snmp_SimpleOpen },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_OpenPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OpenPDU_choice, hf_index, ett_snmp_OpenPDU,
                                 NULL);

  return offset;
}


static const value_string snmp_ClosePDU_U_vals[] = {
  {   0, "goingDown" },
  {   1, "unsupportedVersion" },
  {   2, "packetFormat" },
  {   3, "protocolError" },
  {   4, "internalError" },
  {   5, "authenticationFailure" },
  { 0, NULL }
};


static int
dissect_snmp_ClosePDU_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_ClosePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, true, dissect_snmp_ClosePDU_U);

  return offset;
}



static int
dissect_snmp_INTEGER_M1_2147483647(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string snmp_T_operation_vals[] = {
  {   0, "delete" },
  {   1, "readOnly" },
  {   2, "readWrite" },
  { 0, NULL }
};


static int
dissect_snmp_T_operation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RReqPDU_U_sequence[] = {
  { &hf_snmp_subtree        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_snmp_ObjectName },
  { &hf_snmp_priority       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_M1_2147483647 },
  { &hf_snmp_operation      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_operation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_RReqPDU_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RReqPDU_U_sequence, hf_index, ett_snmp_RReqPDU_U);

  return offset;
}



static int
dissect_snmp_RReqPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, true, dissect_snmp_RReqPDU_U);

  return offset;
}


static const value_string snmp_RRspPDU_U_vals[] = {
  {  -1, "failure" },
  { 0, NULL }
};


static int
dissect_snmp_RRspPDU_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_RRspPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, true, dissect_snmp_RRspPDU_U);

  return offset;
}


static const value_string snmp_RegisterResponse_vals[] = {
  {   0, "rRspPDU" },
  {   1, "pDUs" },
  { 0, NULL }
};

static const ber_choice_t RegisterResponse_choice[] = {
  {   0, &hf_snmp_rRspPDU        , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_snmp_RRspPDU },
  {   1, &hf_snmp_pDUs           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_PDUs },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_RegisterResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RegisterResponse_choice, hf_index, ett_snmp_RegisterResponse,
                                 NULL);

  return offset;
}


static const value_string snmp_SOutPDU_U_vals[] = {
  {   0, "commit" },
  {   1, "rollback" },
  { 0, NULL }
};


static int
dissect_snmp_SOutPDU_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_SOutPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, true, dissect_snmp_SOutPDU_U);

  return offset;
}


static const value_string snmp_SMUX_PDUs_vals[] = {
  {   0, "open" },
  {   1, "close" },
  {   2, "registerRequest" },
  {   3, "registerResponse" },
  {   4, "commitOrRollback" },
  { 0, NULL }
};

static const ber_choice_t SMUX_PDUs_choice[] = {
  {   0, &hf_snmp_open           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_OpenPDU },
  {   1, &hf_snmp_close          , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_snmp_ClosePDU },
  {   2, &hf_snmp_registerRequest, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_snmp_RReqPDU },
  {   3, &hf_snmp_registerResponse, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_RegisterResponse },
  {   4, &hf_snmp_commitOrRollback, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_snmp_SOutPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_SMUX_PDUs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	snmp_conv_info_t *snmp_info = snmp_find_conversation_and_get_conv_data(actx->pinfo);

	actx->private_data = snmp_info;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SMUX_PDUs_choice, hf_index, ett_snmp_SMUX_PDUs,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_SMUX_PDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_snmp_SMUX_PDUs(false, tvb, offset, &asn1_ctx, tree, hf_snmp_SMUX_PDUs_PDU);
  return offset;
}


static snmp_conv_info_t*
snmp_find_conversation_and_get_conv_data(packet_info *pinfo) {

	conversation_t *conversation = NULL;
	snmp_conv_info_t *snmp_info = NULL;

	/* Get the conversation with the wildcarded port, if it exists
	 * and is associated with SNMP, so that requests and responses
	 * can be matched even if the response comes from a different,
	 * ephemeral, source port, as originally done in OS/400.
	 * On UDP, we do not automatically call conversation_set_port2()
	 * and we do not want to do so. Possibly this should eventually
	 * use find_conversation_full and separate the "SNMP conversation"
	 * from "the transport layer conversation that carries SNMP."
	 */
        if (pinfo->destport == UDP_PORT_SNMP) {
                conversation = find_conversation_strat(pinfo, conversation_pt_to_conversation_type(pinfo->ptype), NO_PORT_B, 0);
        } else {
                conversation = find_conversation_strat(pinfo, conversation_pt_to_conversation_type(pinfo->ptype), NO_PORT_B, 1);
        }
        if ( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num)!=snmp_handle) ) {
                conversation = conversation_new_strat(pinfo, conversation_pt_to_conversation_type(pinfo->ptype), NO_PORT2);
                conversation_set_dissector(conversation, snmp_handle);

                conversation = conversation_new_strat(pinfo, CONVERSATION_SNMP, NO_PORT2);
        }

	snmp_info = (snmp_conv_info_t *)conversation_get_proto_data(conversation, proto_snmp);
	if (snmp_info == NULL) {
		snmp_info = wmem_new0(wmem_file_scope(), snmp_conv_info_t);
		snmp_info->request_response=wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);

		conversation_add_proto_data(conversation, proto_snmp, snmp_info);
	}
	return snmp_info;
}

unsigned
dissect_snmp_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, int proto, int ett, bool is_tcp)
{

	unsigned length_remaining;
	int8_t ber_class;
	bool pc, ind = 0;
	int32_t tag;
	uint32_t len;
	unsigned message_length;
	int start_offset = offset;
	uint32_t version = 0;
	tvbuff_t	*next_tvb;

	proto_tree *snmp_tree = NULL;
	proto_item *item = NULL;

	snmp_conv_info_t *snmp_info = snmp_find_conversation_and_get_conv_data(pinfo);

	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	asn1_ctx.private_data = snmp_info;

	usm_p.msg_tvb = tvb;
	usm_p.start_offset = tvb_offset_from_real_beginning(tvb);
	usm_p.engine_tvb = NULL;
	usm_p.user_tvb = NULL;
	usm_p.auth_item = NULL;
	usm_p.auth_tvb = NULL;
	usm_p.auth_offset = 0;
	usm_p.priv_tvb = NULL;
	usm_p.user_assoc = NULL;
	usm_p.authenticated = false;
	usm_p.encrypted = false;
	usm_p.boots = 0;
	usm_p.snmp_time = 0;
	usm_p.authOK = false;

	/*
	 * This will throw an exception if we don't have any data left.
	 * That's what we want.  (See "tcp_dissect_pdus()", which is
	 * similar, but doesn't have to deal with ASN.1.
	 * XXX - can we make "tcp_dissect_pdus()" provide enough
	 * information to the "get_pdu_len" routine so that we could
	 * have that routine deal with ASN.1, and just use
	 * "tcp_dissect_pdus()"?)
	 */
	length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

	/* NOTE: we have to parse the message piece by piece, since the
	 * capture length may be less than the message length: a 'global'
	 * parsing is likely to fail.
	 */

	/*
	 * If this is SNMP-over-TCP, we might have to do reassembly
	 * in order to read the "Sequence Of" header.
	 */
	if (is_tcp && snmp_desegment && pinfo->can_desegment) {
		/*
		 * This is TCP, and we should, and can, do reassembly.
		 *
		 * Is the "Sequence Of" header split across segment
		 * boundaries?  We require at least 6 bytes for the
		 * header, which allows for a 4-byte length (ASN.1
		 * BER).
		 */
		if (length_remaining < 6) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us and that we need "some more data."  Don't tell
			 * it exactly how many bytes we need because if/when
			 * we ask for even more (after the header) that will
			 * break reassembly.
			 */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return 0;
		}
	}

	/*
	 * OK, try to read the "Sequence Of" header; this gets the total
	 * length of the SNMP message.
	 */
	offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	/*Get the total octet length of the SNMP data*/
	offset = get_ber_length(tvb, offset, &len, &ind);
	message_length = len + offset;

	/*Get the SNMP version data*/
	/*offset =*/ dissect_ber_integer(false, &asn1_ctx, 0, tvb, offset, -1, &version);


	/*
	 * If this is SNMP-over-TCP, we might have to do reassembly
	 * to get all of this message.
	 */
	if (is_tcp && snmp_desegment && pinfo->can_desegment) {
		/*
		 * Yes - is the message split across segment boundaries?
		 */
		if (length_remaining < message_length) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us, and how many more bytes we need, and
			 * return.
			 */
			pinfo->desegment_offset = start_offset;
			pinfo->desegment_len =
			message_length - length_remaining;

			/*
			 * Return 0, which means "I didn't dissect anything
			 * because I don't have enough data - we need
			 * to desegment".
			 */
			return 0;
		}
	}

	var_list = next_tvb_list_new(pinfo->pool);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_get_protocol_short_name(find_protocol_by_id(proto)));

	item = proto_tree_add_item(tree, proto, tvb, start_offset, message_length, ENC_BIG_ENDIAN);
	snmp_tree = proto_item_add_subtree(item, ett);

	switch (version) {
	case 0: /* v1 */
	case 1: /* v2c */
		offset = dissect_snmp_Message(false , tvb, start_offset, &asn1_ctx, snmp_tree, -1);
		break;
	case 2: /* v2u */
		offset = dissect_snmp_Messagev2u(false , tvb, start_offset, &asn1_ctx, snmp_tree, -1);
		break;
			/* v3 */
	case 3:
		offset = dissect_snmp_SNMPv3Message(false , tvb, start_offset, &asn1_ctx, snmp_tree, -1);
		break;
	default:
		/*
		 * Return the length remaining in the tvbuff, so
		 * if this is SNMP-over-TCP, our caller thinks there's
		 * nothing left to dissect.
		 */
		expert_add_info(pinfo, item, &ei_snmp_version_unknown);
		return length_remaining;
	}

	/* There may be appended data after the SNMP data, so treat as raw
	 * data which needs to be dissected in case of UDP as UDP is PDU oriented.
 	 */
	if((!is_tcp) && (length_remaining > (unsigned)offset)) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	} else {
		next_tvb_call(var_list, pinfo, tree, NULL, data_handle);
	}

	return offset;
}

static int
dissect_snmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset;
	int8_t tmp_class;
	bool tmp_pc;
	int32_t tmp_tag;
	uint32_t tmp_length;
	bool tmp_ind;

	/*
	 * See if this looks like SNMP or not. if not, return 0 so
	 * wireshark can try some other dissector instead.
	 */
	/* All SNMP packets are BER encoded and consist of a SEQUENCE
	 * that spans the entire PDU. The first item is an INTEGER that
	 * has the values 0-2 (version 1-3).
	 * if not it is not snmp.
	 */
	/* SNMP starts with a SEQUENCE */
	offset = get_ber_identifier(tvb, 0, &tmp_class, &tmp_pc, &tmp_tag);
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_SEQUENCE)) {
		return 0;
	}
	/* then comes a length which spans the rest of the tvb */
	offset = get_ber_length(tvb, offset, &tmp_length, &tmp_ind);
	/* Loosen the heuristic a bit to handle the case where data has intentionally
	 * been added after the snmp PDU ( UDP case) (#3684)
	 * If this is fragmented or carried in ICMP, we don't expect the tvb to
	 * have the full legnth, so don't check.
	 */
	if (!pinfo->fragmented && !pinfo->flags.in_error_pkt) {
	    if ( pinfo->ptype == PT_UDP ) {
		    if(tmp_length>(uint32_t)tvb_reported_length_remaining(tvb, offset)) {
			    return 0;
		    }
	    }else{
		    if(tmp_length!=(uint32_t)tvb_reported_length_remaining(tvb, offset)) {
			    return 0;
		    }
	    }
	}
	/* then comes an INTEGER (version)*/
	get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_INTEGER)) {
		return 0;
	}
	/* do we need to test that version is 0 - 2 (version1-3) ? */


	/*
	 * The IBM i (OS/400) SNMP agent, at least originally, would
	 * send responses back from some *other* UDP port, an ephemeral
	 * port above 5000, going back to the same IP address and port
	 * from which the request came, similar to TFTP. This only happens
	 * with the agent port, 161, not with the trap port, etc. As of
	 * 2015 with the latest fixes applied, it no longer does this:
	 * https://www.ibm.com/support/pages/ptf/SI55487
	 * https://www.ibm.com/support/pages/ptf/SI55537
	 *
	 * The SNMP RFCs are silent on this (cf. L2TP RFC 2661, which
	 * supports using either the well-known port or an ephemeral
	 * port as the source port for responses, while noting that
	 * the latter can cause issues with firewalls and NATs.) so
	 * possibly some other implementations could do this.
	 *
	 * If this packet went to the SNMP port, we check to see if
	 * there's already a conversation with one address/port pair
	 * matching the source IP address and port of this packet,
	 * the other address matching the destination IP address of this
	 * packet, and any destination port.
	 *
	 * If not, we create one, with its address 1/port 1 pair being
	 * the source address/port of this packet, its address 2 being
	 * the destination address of this packet, and its port 2 being
	 * wildcarded, and give it the SNMP dissector as a dissector.
	 */

        if (pinfo->destport == UDP_PORT_SNMP) {
                conversation_t *conversation = find_conversation_strat(pinfo, conversation_pt_to_conversation_type(pinfo->ptype), NO_PORT_B|NO_GREEDY, 0);

                if (conversation == NULL) {
                        conversation = conversation_new_strat(pinfo, conversation_pt_to_conversation_type(pinfo->ptype), NO_PORT2);

                        conversation_set_dissector(conversation, snmp_handle);
                }
                else if (conversation_get_dissector(conversation,pinfo->num)!=snmp_handle) {
                        conversation_set_dissector(conversation, snmp_handle);
                }
        }

	return dissect_snmp_pdu(tvb, 0, pinfo, tree, proto_snmp, ett_snmp, false);
}

static int
dissect_snmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	unsigned message_len;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		message_len = dissect_snmp_pdu(tvb, offset, pinfo, tree, proto_snmp, ett_snmp, true);
		if (message_len == 0) {
			/*
			 * We don't have all the data for that message,
			 * so we need to do desegmentation;
			 * "dissect_snmp_pdu()" has set that up.
			 */
			break;
		}
		offset += message_len;
	}
	return tvb_captured_length(tvb);
}

static int
dissect_smux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree *smux_tree = NULL;
	proto_item *item = NULL;

	var_list = next_tvb_list_new(pinfo->pool);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMUX");

	item = proto_tree_add_item(tree, proto_smux, tvb, 0, -1, ENC_NA);
	smux_tree = proto_item_add_subtree(item, ett_smux);

	return dissect_SMUX_PDUs_PDU(tvb, pinfo, smux_tree, data);
}

/*
  MD5 Password to Key Algorithm from RFC 3414 A.2.1
  SHA1 Password to Key Algorithm from RFC 3414 A.2.2
  SHA2 Password to Key Algorithm from RFC 7860 9.3
*/
static void
snmp_usm_password_to_key(const snmp_usm_auth_model_t model, const uint8_t *password,
	unsigned passwordlen, const uint8_t *engineID, unsigned engineLength, uint8_t *key)
{
	gcry_md_hd_t	hash_handle;
	uint8_t	  *cp, password_buf[64];
	uint32_t	 password_index = 0;
	uint32_t	 count = 0, i;
	unsigned	   hash_len;

	if (gcry_md_open(&hash_handle, auth_hash_algo[model], 0)) {
		return;
	}

	hash_len = auth_hash_len[model];

	/**********************************************/
	/* Use while loop until we've done 1 Megabyte */
	/**********************************************/
	while (count < 1048576) {
		cp = password_buf;
		if (passwordlen != 0) {
			for (i = 0; i < 64; i++) {
				/*************************************************/
				/* Take the next octet of the password, wrapping */
				/* to the beginning of the password as necessary.*/
				/*************************************************/
				*cp++ = password[password_index++ % passwordlen];
			}
		} else {
			*cp = 0;
		}
		gcry_md_write(hash_handle, password_buf, 64);
		count += 64;
	}
	memcpy(key, gcry_md_read(hash_handle, 0), hash_len);
	gcry_md_close(hash_handle);

	/*****************************************************/
	/* Now localise the key with the engineID and pass   */
	/* through hash function to produce final key        */
	/* We ignore invalid engineLengths here. More strict */
	/* checking is done in snmp_users_update_cb.         */
	/*****************************************************/
	if (gcry_md_open(&hash_handle, auth_hash_algo[model], 0)) {
		return;
	}
	gcry_md_write(hash_handle, key, hash_len);
	gcry_md_write(hash_handle, engineID, engineLength);
	gcry_md_write(hash_handle, key, hash_len);
	memcpy(key, gcry_md_read(hash_handle, 0), hash_len);
	gcry_md_close(hash_handle);
	return;
}

static void
process_prefs(void)
{
}

UAT_LSTRING_CB_DEF(snmp_users,userName,snmp_ue_assoc_t,user.userName.data,user.userName.len)
UAT_LSTRING_CB_DEF(snmp_users,authPassword,snmp_ue_assoc_t,user.authPassword.data,user.authPassword.len)
UAT_LSTRING_CB_DEF(snmp_users,privPassword,snmp_ue_assoc_t,user.privPassword.data,user.privPassword.len)
UAT_BUFFER_CB_DEF(snmp_users,engine_id,snmp_ue_assoc_t,engine.data,engine.len)
UAT_VS_DEF(snmp_users,auth_model,snmp_ue_assoc_t,unsigned,0,"MD5")
UAT_VS_DEF(snmp_users,priv_proto,snmp_ue_assoc_t,unsigned,0,"DES")
UAT_VS_DEF(snmp_users,priv_key_exp,snmp_ue_assoc_t,unsigned,0,"draft-reeder-snmpv3-usm-3desede-00")

static void *
snmp_specific_trap_copy_cb(void *dest, const void *orig, size_t len _U_)
{
	snmp_st_assoc_t *u = (snmp_st_assoc_t *)dest;
	const snmp_st_assoc_t *o = (const snmp_st_assoc_t *)orig;

	u->enterprise = g_strdup(o->enterprise);
	u->trap = o->trap;
	u->desc = g_strdup(o->desc);

	return dest;
}

static void
snmp_specific_trap_free_cb(void *r)
{
	snmp_st_assoc_t *u = (snmp_st_assoc_t *)r;

	g_free(u->enterprise);
	g_free(u->desc);
}

UAT_CSTRING_CB_DEF(specific_traps, enterprise, snmp_st_assoc_t)
UAT_DEC_CB_DEF(specific_traps, trap, snmp_st_assoc_t)
UAT_CSTRING_CB_DEF(specific_traps, desc, snmp_st_assoc_t)

	/*--- proto_register_snmp -------------------------------------------*/
void proto_register_snmp(void) {
	/* List of fields */
	static hf_register_info hf[] = {
		{ &hf_snmp_response_in,
		{ "Response In", "snmp.response_in", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			"The response to this SNMP request is in this frame", HFILL }},
		{ &hf_snmp_response_to,
		{ "Response To", "snmp.response_to", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			"This is a response to the SNMP request in this frame", HFILL }},
		{ &hf_snmp_time,
		{ "Time", "snmp.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			"The time between the Request and the Response", HFILL }},
		{ &hf_snmp_v3_flags_auth,
		{ "Authenticated", "snmp.v3.flags.auth", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), TH_AUTH, NULL, HFILL }},
		{ &hf_snmp_v3_flags_crypt,
		{ "Encrypted", "snmp.v3.flags.crypt", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), TH_CRYPT, NULL, HFILL }},
		{ &hf_snmp_v3_flags_report,
		{ "Reportable", "snmp.v3.flags.report", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), TH_REPORT, NULL, HFILL }},
		{ &hf_snmp_engineid_conform, {
		    "Engine ID Conformance", "snmp.engineid.conform", FT_BOOLEAN, 8,
		    TFS(&tfs_snmp_engineid_conform), F_SNMP_ENGINEID_CONFORM, "Engine ID RFC3411 Conformance", HFILL }},
		{ &hf_snmp_engineid_enterprise, {
		    "Engine Enterprise ID", "snmp.engineid.enterprise", FT_UINT32, BASE_ENTERPRISES,
		    STRINGS_ENTERPRISES, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_format, {
		    "Engine ID Format", "snmp.engineid.format", FT_UINT8, BASE_DEC,
		    VALS(snmp_engineid_format_vals), 0, NULL, HFILL }},
		{ &hf_snmp_engineid_ipv4, {
		    "Engine ID Data: IPv4 address", "snmp.engineid.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_ipv6, {
		    "Engine ID Data: IPv6 address", "snmp.engineid.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_cisco_type, {
		    "Engine ID Data: Cisco type", "snmp.engineid.cisco.type", FT_UINT8, BASE_HEX,
		    VALS(snmp_engineid_cisco_type_vals), 0, NULL, HFILL }},
		{ &hf_snmp_engineid_mac, {
		    "Engine ID Data: MAC address", "snmp.engineid.mac", FT_ETHER, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_text, {
		    "Engine ID Data: Text", "snmp.engineid.text", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_time, {
		    "Engine ID Data: Creation Time", "snmp.engineid.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_data, {
		    "Engine ID Data", "snmp.engineid.data", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_msgAuthentication, {
		    "Authentication", "snmp.v3.auth", FT_BOOLEAN, BASE_NONE,
		    TFS(&auth_flags), 0, NULL, HFILL }},
		{ &hf_snmp_decryptedPDU, {
		    "Decrypted ScopedPDU", "snmp.decrypted_pdu", FT_BYTES, BASE_NONE,
		    NULL, 0, "Decrypted PDU", HFILL }},
		{ &hf_snmp_noSuchObject, {
		    "noSuchObject", "snmp.noSuchObject", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_noSuchInstance, {
		    "noSuchInstance", "snmp.noSuchInstance", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_endOfMibView, {
		    "endOfMibView", "snmp.endOfMibView", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_unSpecified, {
		    "unSpecified", "snmp.unSpecified", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_snmp_integer32_value, {
		    "Value (Integer32)", "snmp.value.int", FT_INT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_octetstring_value, {
		    "Value (OctetString)", "snmp.value.octets", FT_BYTES, BASE_SHOW_ASCII_PRINTABLE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_oid_value, {
		    "Value (OID)", "snmp.value.oid", FT_OID, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_null_value, {
		    "Value (Null)", "snmp.value.null", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_ipv4_value, {
		    "Value (IpAddress)", "snmp.value.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_ipv6_value, {
		    "Value (IpAddress)", "snmp.value.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_anyaddress_value, {
		    "Value (IpAddress)", "snmp.value.addr", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_unsigned32_value, {
		    "Value (Unsigned32)", "snmp.value.u32", FT_INT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_gauge32_value, {
		    "Value (Gauge32)", "snmp.value.g32", FT_INT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_unknown_value, {
		    "Value (Unknown)", "snmp.value.unk", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_counter_value, {
		    "Value (Counter32)", "snmp.value.counter", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_big_counter_value, {
		    "Value (Counter64)", "snmp.value.counter", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_nsap_value, {
		    "Value (NSAP)", "snmp.value.nsap", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_timeticks_value, {
		    "Value (Timeticks)", "snmp.value.timeticks", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_opaque_value, {
		    "Value (Opaque)", "snmp.value.opaque", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_objectname, {
		    "Object Name", "snmp.name", FT_OID, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_scalar_instance_index, {
		    "Scalar Instance Index", "snmp.name.index", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_var_bind_str, {
		    "Variable-binding-string", "snmp.var-bind_str", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_agentid_trailer, {
		    "AgentID Trailer", "snmp.agentid_trailer", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},


    { &hf_snmp_SMUX_PDUs_PDU,
      { "SMUX-PDUs", "snmp.SMUX_PDUs",
        FT_UINT32, BASE_DEC, VALS(snmp_SMUX_PDUs_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_version,
      { "version", "snmp.version",
        FT_INT32, BASE_DEC, VALS(snmp_Version_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_community,
      { "community", "snmp.community",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_data,
      { "data", "snmp.data",
        FT_UINT32, BASE_DEC, VALS(snmp_PDUs_vals), 0,
        "PDUs", HFILL }},
    { &hf_snmp_parameters,
      { "parameters", "snmp.parameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_datav2u,
      { "datav2u", "snmp.datav2u",
        FT_UINT32, BASE_DEC, VALS(snmp_T_datav2u_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_v2u_plaintext,
      { "plaintext", "snmp.v2u_plaintext",
        FT_UINT32, BASE_DEC, VALS(snmp_PDUs_vals), 0,
        "PDUs", HFILL }},
    { &hf_snmp_encrypted,
      { "encrypted", "snmp.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_msgAuthoritativeEngineID,
      { "msgAuthoritativeEngineID", "snmp.msgAuthoritativeEngineID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgAuthoritativeEngineBoots,
      { "msgAuthoritativeEngineBoots", "snmp.msgAuthoritativeEngineBoots",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgAuthoritativeEngineTime,
      { "msgAuthoritativeEngineTime", "snmp.msgAuthoritativeEngineTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgUserName,
      { "msgUserName", "snmp.msgUserName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgAuthenticationParameters,
      { "msgAuthenticationParameters", "snmp.msgAuthenticationParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgPrivacyParameters,
      { "msgPrivacyParameters", "snmp.msgPrivacyParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgVersion,
      { "msgVersion", "snmp.msgVersion",
        FT_INT32, BASE_DEC, VALS(snmp_Version_vals), 0,
        "Version", HFILL }},
    { &hf_snmp_msgGlobalData,
      { "msgGlobalData", "snmp.msgGlobalData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HeaderData", HFILL }},
    { &hf_snmp_msgSecurityParameters,
      { "msgSecurityParameters", "snmp.msgSecurityParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgData,
      { "msgData", "snmp.msgData",
        FT_UINT32, BASE_DEC, VALS(snmp_ScopedPduData_vals), 0,
        "ScopedPduData", HFILL }},
    { &hf_snmp_msgID,
      { "msgID", "snmp.msgID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2147483647", HFILL }},
    { &hf_snmp_msgMaxSize,
      { "msgMaxSize", "snmp.msgMaxSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_484_2147483647", HFILL }},
    { &hf_snmp_msgFlags,
      { "msgFlags", "snmp.msgFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgSecurityModel,
      { "msgSecurityModel", "snmp.msgSecurityModel",
        FT_UINT32, BASE_DEC, VALS(sec_models), 0,
        NULL, HFILL }},
    { &hf_snmp_plaintext,
      { "plaintext", "snmp.plaintext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScopedPDU", HFILL }},
    { &hf_snmp_encryptedPDU,
      { "encryptedPDU", "snmp.encryptedPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_contextEngineID,
      { "contextEngineID", "snmp.contextEngineID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SnmpEngineID", HFILL }},
    { &hf_snmp_contextName,
      { "contextName", "snmp.contextName",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_get_request,
      { "get-request", "snmp.get_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetRequest_PDU", HFILL }},
    { &hf_snmp_get_next_request,
      { "get-next-request", "snmp.get_next_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNextRequest_PDU", HFILL }},
    { &hf_snmp_get_response,
      { "get-response", "snmp.get_response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetResponse_PDU", HFILL }},
    { &hf_snmp_set_request,
      { "set-request", "snmp.set_request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SetRequest_PDU", HFILL }},
    { &hf_snmp_trap,
      { "trap", "snmp.trap_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Trap_PDU", HFILL }},
    { &hf_snmp_getBulkRequest,
      { "getBulkRequest", "snmp.getBulkRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetBulkRequest_PDU", HFILL }},
    { &hf_snmp_informRequest,
      { "informRequest", "snmp.informRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformRequest_PDU", HFILL }},
    { &hf_snmp_snmpV2_trap,
      { "snmpV2-trap", "snmp.snmpV2_trap_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SNMPv2_Trap_PDU", HFILL }},
    { &hf_snmp_report,
      { "report", "snmp.report_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Report_PDU", HFILL }},
    { &hf_snmp_request_id,
      { "request-id", "snmp.request_id",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_request_id", HFILL }},
    { &hf_snmp_error_status,
      { "error-status", "snmp.error_status",
        FT_INT32, BASE_DEC, VALS(snmp_T_error_status_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_error_index,
      { "error-index", "snmp.error_index",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_snmp_variable_bindings,
      { "variable-bindings", "snmp.variable_bindings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VarBindList", HFILL }},
    { &hf_snmp_bulkPDU_request_id,
      { "request-id", "snmp.bulkPDU_request_id",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_snmp_non_repeaters,
      { "non-repeaters", "snmp.non_repeaters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2147483647", HFILL }},
    { &hf_snmp_max_repetitions,
      { "max-repetitions", "snmp.max_repetitions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2147483647", HFILL }},
    { &hf_snmp_enterprise,
      { "enterprise", "snmp.enterprise",
        FT_OID, BASE_NONE, NULL, 0,
        "EnterpriseOID", HFILL }},
    { &hf_snmp_agent_addr,
      { "agent-addr", "snmp.agent_addr",
        FT_IPv4, BASE_NONE, NULL, 0,
        "NetworkAddress", HFILL }},
    { &hf_snmp_generic_trap,
      { "generic-trap", "snmp.generic_trap",
        FT_INT32, BASE_DEC, VALS(snmp_GenericTrap_vals), 0,
        "GenericTrap", HFILL }},
    { &hf_snmp_specific_trap,
      { "specific-trap", "snmp.specific_trap",
        FT_INT32, BASE_DEC, NULL, 0,
        "SpecificTrap", HFILL }},
    { &hf_snmp_time_stamp,
      { "time-stamp", "snmp.time_stamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeTicks", HFILL }},
    { &hf_snmp_name,
      { "name", "snmp.name",
        FT_OID, BASE_NONE, NULL, 0,
        "ObjectName", HFILL }},
    { &hf_snmp_valueType,
      { "valueType", "snmp.valueType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_VarBindList_item,
      { "VarBind", "snmp.VarBind_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_open,
      { "open", "snmp.open",
        FT_UINT32, BASE_DEC, VALS(snmp_OpenPDU_vals), 0,
        "OpenPDU", HFILL }},
    { &hf_snmp_close,
      { "close", "snmp.close",
        FT_INT32, BASE_DEC, VALS(snmp_ClosePDU_U_vals), 0,
        "ClosePDU", HFILL }},
    { &hf_snmp_registerRequest,
      { "registerRequest", "snmp.registerRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RReqPDU", HFILL }},
    { &hf_snmp_registerResponse,
      { "registerResponse", "snmp.registerResponse",
        FT_UINT32, BASE_DEC, VALS(snmp_RegisterResponse_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_commitOrRollback,
      { "commitOrRollback", "snmp.commitOrRollback",
        FT_INT32, BASE_DEC, VALS(snmp_SOutPDU_U_vals), 0,
        "SOutPDU", HFILL }},
    { &hf_snmp_rRspPDU,
      { "rRspPDU", "snmp.rRspPDU",
        FT_INT32, BASE_DEC, VALS(snmp_RRspPDU_U_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_pDUs,
      { "pDUs", "snmp.pDUs",
        FT_UINT32, BASE_DEC, VALS(snmp_PDUs_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_smux_simple,
      { "smux-simple", "snmp.smux_simple_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SimpleOpen", HFILL }},
    { &hf_snmp_smux_version,
      { "smux-version", "snmp.smux_version",
        FT_INT32, BASE_DEC, VALS(snmp_T_smux_version_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_identity,
      { "identity", "snmp.identity",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_snmp_description,
      { "description", "snmp.description",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DisplayString", HFILL }},
    { &hf_snmp_password,
      { "password", "snmp.password",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_subtree,
      { "subtree", "snmp.subtree",
        FT_OID, BASE_NONE, NULL, 0,
        "ObjectName", HFILL }},
    { &hf_snmp_priority,
      { "priority", "snmp.priority",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1_2147483647", HFILL }},
    { &hf_snmp_operation,
      { "operation", "snmp.operation",
        FT_INT32, BASE_DEC, VALS(snmp_T_operation_vals), 0,
        NULL, HFILL }},
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_snmp,
		&ett_engineid,
		&ett_msgFlags,
		&ett_encryptedPDU,
		&ett_decrypted,
		&ett_authParameters,
		&ett_internet,
		&ett_varbind,
		&ett_name,
		&ett_value,
		&ett_decoding_error,
    &ett_snmp_Message,
    &ett_snmp_Messagev2u,
    &ett_snmp_T_datav2u,
    &ett_snmp_UsmSecurityParameters,
    &ett_snmp_SNMPv3Message,
    &ett_snmp_HeaderData,
    &ett_snmp_ScopedPduData,
    &ett_snmp_ScopedPDU,
    &ett_snmp_PDUs,
    &ett_snmp_PDU,
    &ett_snmp_BulkPDU,
    &ett_snmp_Trap_PDU_U,
    &ett_snmp_VarBind,
    &ett_snmp_VarBindList,
    &ett_snmp_SMUX_PDUs,
    &ett_snmp_RegisterResponse,
    &ett_snmp_OpenPDU,
    &ett_snmp_SimpleOpen_U,
    &ett_snmp_RReqPDU_U,
	};
	static ei_register_info ei[] = {
		{ &ei_snmp_failed_decrypted_data_pdu, { "snmp.failed_decrypted_data_pdu", PI_MALFORMED, PI_WARN, "Failed to decrypt encryptedPDU", EXPFILL }},
		{ &ei_snmp_decrypted_data_bad_formatted, { "snmp.decrypted_data_bad_formatted", PI_MALFORMED, PI_WARN, "Decrypted data not formatted as expected, wrong key?", EXPFILL }},
		{ &ei_snmp_verify_authentication_error, { "snmp.verify_authentication_error", PI_MALFORMED, PI_ERROR, "Error while verifying Message authenticity", EXPFILL }},
		{ &ei_snmp_authentication_ok, { "snmp.authentication_ok", PI_CHECKSUM, PI_CHAT, "SNMP Authentication OK", EXPFILL }},
		{ &ei_snmp_authentication_error, { "snmp.authentication_error", PI_CHECKSUM, PI_WARN, "SNMP Authentication Error", EXPFILL }},
		{ &ei_snmp_varbind_not_uni_class_seq, { "snmp.varbind.not_uni_class_seq", PI_MALFORMED, PI_WARN, "VarBind is not an universal class sequence", EXPFILL }},
		{ &ei_snmp_varbind_has_indicator, { "snmp.varbind.has_indicator", PI_MALFORMED, PI_WARN, "VarBind has indicator set", EXPFILL }},
		{ &ei_snmp_objectname_not_oid, { "snmp.objectname_not_oid", PI_MALFORMED, PI_WARN, "ObjectName not an OID", EXPFILL }},
		{ &ei_snmp_objectname_has_indicator, { "snmp.objectname_has_indicator", PI_MALFORMED, PI_WARN, "ObjectName has indicator set", EXPFILL }},
		{ &ei_snmp_value_not_primitive_encoding, { "snmp.value_not_primitive_encoding", PI_MALFORMED, PI_WARN, "value not in primitive encoding", EXPFILL }},
		{ &ei_snmp_invalid_oid, { "snmp.invalid_oid", PI_MALFORMED, PI_WARN, "invalid oid", EXPFILL }},
		{ &ei_snmp_varbind_wrong_tag, { "snmp.varbind.wrong_tag", PI_MALFORMED, PI_WARN, "Wrong tag for SNMP VarBind error value", EXPFILL }},
		{ &ei_snmp_varbind_response, { "snmp.varbind.response", PI_RESPONSE_CODE, PI_NOTE, "Response", EXPFILL }},
		{ &ei_snmp_no_instance_subid, { "snmp.no_instance_subid", PI_MALFORMED, PI_WARN, "No instance sub-id in scalar value", EXPFILL }},
		{ &ei_snmp_wrong_num_of_subids, { "snmp.wrong_num_of_subids", PI_MALFORMED, PI_WARN, "Wrong number of instance sub-ids in scalar value", EXPFILL }},
		{ &ei_snmp_index_suboid_too_short, { "snmp.index_suboid_too_short", PI_MALFORMED, PI_WARN, "index sub-oid shorter than expected", EXPFILL }},
		{ &ei_snmp_unimplemented_instance_index, { "snmp.unimplemented_instance_index", PI_UNDECODED, PI_WARN, "OID instances not handled, if you want this implemented please contact the wireshark developers", EXPFILL }},
		{ &ei_snmp_index_suboid_len0, { "snmp.ndex_suboid_len0", PI_MALFORMED, PI_WARN, "an index sub-oid OID cannot be 0 bytes long!", EXPFILL }},
		{ &ei_snmp_index_suboid_too_long, { "snmp.index_suboid_too_long", PI_MALFORMED, PI_WARN, "index sub-oid should not be longer than remaining oid size", EXPFILL }},
		{ &ei_snmp_index_string_too_long, { "snmp.index_string_too_long", PI_MALFORMED, PI_WARN, "index string should not be longer than remaining oid size", EXPFILL }},
		{ &ei_snmp_column_parent_not_row, { "snmp.column_parent_not_row", PI_MALFORMED, PI_ERROR, "COLUMNS's parent is not a ROW", EXPFILL }},
		{ &ei_snmp_uint_too_large, { "snmp.uint_too_large", PI_UNDECODED, PI_NOTE, "Unsigned integer value > 2^64 - 1", EXPFILL }},
		{ &ei_snmp_int_too_large, { "snmp.int_too_large", PI_UNDECODED, PI_NOTE, "Signed integer value > 2^63 - 1 or <= -2^63", EXPFILL }},
		{ &ei_snmp_integral_value0, { "snmp.integral_value0", PI_UNDECODED, PI_NOTE, "Integral value is zero-length", EXPFILL }},
		{ &ei_snmp_missing_mib, { "snmp.missing_mib", PI_UNDECODED, PI_NOTE, "Unresolved value, Missing MIB", EXPFILL }},
		{ &ei_snmp_varbind_wrong_length_value, { "snmp.varbind.wrong_length_value", PI_MALFORMED, PI_WARN, "Wrong length for SNMP VarBind/value", EXPFILL }},
		{ &ei_snmp_varbind_wrong_class_tag, { "snmp.varbind.wrong_class_tag", PI_MALFORMED, PI_WARN, "Wrong class/tag for SNMP VarBind/value", EXPFILL }},
		{ &ei_snmp_rfc1910_non_conformant, { "snmp.rfc1910_non_conformant", PI_PROTOCOL, PI_WARN, "Data not conforming to RFC1910", EXPFILL }},
		{ &ei_snmp_rfc3411_non_conformant, { "snmp.rfc3411_non_conformant", PI_PROTOCOL, PI_WARN, "Data not conforming to RFC3411", EXPFILL }},
		{ &ei_snmp_version_unknown, { "snmp.version.unknown", PI_PROTOCOL, PI_WARN, "Unknown version", EXPFILL }},
		{ &ei_snmp_trap_pdu_obsolete, { "snmp.trap_pdu_obsolete", PI_PROTOCOL, PI_WARN, "Trap-PDU is obsolete in this SNMP version", EXPFILL }},

	};

	expert_module_t* expert_snmp;
	module_t *snmp_module;

	static uat_field_t users_fields[] = {
		UAT_FLD_BUFFER(snmp_users,engine_id,"Engine ID","Engine-id for this entry (empty = any)"),
		UAT_FLD_LSTRING(snmp_users,userName,"Username","The username"),
		UAT_FLD_VS(snmp_users,auth_model,"Authentication model",auth_types,"Algorithm to be used for authentication."),
		UAT_FLD_LSTRING(snmp_users,authPassword,"Password","The password used for authenticating packets for this entry"),
		UAT_FLD_VS(snmp_users,priv_proto,"Privacy protocol",priv_types,"Algorithm to be used for privacy."),
		UAT_FLD_LSTRING(snmp_users,privPassword,"Privacy password","The password used for encrypting packets for this entry"),
		UAT_FLD_VS(snmp_users,priv_key_exp,"Key expansion method",priv_key_exp_types,"Privacy protocol key expansion method"),
		UAT_END_FIELDS
	};

	uat_t *assocs_uat = uat_new("SNMP Users",
				    sizeof(snmp_ue_assoc_t),
				    "snmp_users",
				    true,
				    &ueas,
				    &num_ueas,
				    UAT_AFFECTS_DISSECTION,	/* affects dissection of packets, but not set of named fields */
				    "ChSNMPUsersSection",
				    snmp_users_copy_cb,
				    snmp_users_update_cb,
				    snmp_users_free_cb,
				    renew_ue_cache,
				    NULL,
				    users_fields);

	static const char *assocs_uat_defaults[] = {
		NULL, NULL, NULL, NULL, NULL, NULL, "draft-reeder-snmpv3-usm-3desede-00"};
	uat_set_default_values(assocs_uat, assocs_uat_defaults);

	static uat_field_t specific_traps_flds[] = {
		UAT_FLD_CSTRING(specific_traps,enterprise,"Enterprise OID","Enterprise Object Identifier"),
		UAT_FLD_DEC(specific_traps,trap,"Trap Id","The specific-trap value"),
		UAT_FLD_CSTRING(specific_traps,desc,"Description","Trap type description"),
		UAT_END_FIELDS
	};

	uat_t* specific_traps_uat = uat_new("SNMP Enterprise Specific Trap Types",
					    sizeof(snmp_st_assoc_t),
					    "snmp_specific_traps",
					    true,
					    &specific_traps,
					    &num_specific_traps,
					    UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
					    "ChSNMPEnterpriseSpecificTrapTypes",
					    snmp_specific_trap_copy_cb,
					    NULL,
					    snmp_specific_trap_free_cb,
					    NULL,
					    NULL,
					    specific_traps_flds);

	/* Register protocol */
	proto_snmp = proto_register_protocol(PNAME, PSNAME, PFNAME);
	snmp_handle = register_dissector("snmp", dissect_snmp, proto_snmp);

	/* Register fields and subtrees */
	proto_register_field_array(proto_snmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_snmp = expert_register_protocol(proto_snmp);
	expert_register_field_array(expert_snmp, ei, array_length(ei));

	/* Register dissector */
	snmp_tcp_handle = register_dissector("snmp.tcp", dissect_snmp_tcp, proto_snmp);

	/* Register configuration preferences */
	snmp_module = prefs_register_protocol(proto_snmp, process_prefs);
	prefs_register_bool_preference(snmp_module, "display_oid",
			"Show SNMP OID in info column",
			"Whether the SNMP OID should be shown in the info column",
			&display_oid);

	prefs_register_obsolete_preference(snmp_module, "mib_modules");
	prefs_register_obsolete_preference(snmp_module, "users_file");

	prefs_register_bool_preference(snmp_module, "desegment",
			"Reassemble SNMP-over-TCP messages spanning multiple TCP segments",
			"Whether the SNMP dissector should reassemble messages spanning multiple TCP segments."
			" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&snmp_desegment);

	prefs_register_bool_preference(snmp_module, "var_in_tree",
			"Display dissected variables inside SNMP tree",
			"ON - display dissected variables inside SNMP tree, OFF - display dissected variables in root tree after SNMP",
			&snmp_var_in_tree);

	prefs_register_uat_preference(snmp_module, "users_table",
				"Users Table",
				"Table of engine-user associations used for authentication and decryption",
				assocs_uat);

	prefs_register_uat_preference(snmp_module, "specific_traps_table",
				"Enterprise Specific Trap Types",
				"Table of enterprise specific-trap type descriptions",
				specific_traps_uat);

#ifdef HAVE_LIBSMI
	prefs_register_static_text_preference(snmp_module, "info_mibs",
				"MIB settings can be changed in the Name Resolution preferences",
				"MIB settings can be changed in the Name Resolution preferences");
#endif

	value_sub_dissectors_table = register_dissector_table("snmp.variable_oid","SNMP Variable OID", proto_snmp, FT_STRING, STRING_CASE_SENSITIVE);

	register_init_routine(init_ue_cache);
	register_cleanup_routine(cleanup_ue_cache);

	register_ber_syntax_dissector("SNMP", proto_snmp, dissect_snmp_tcp);

	snmp_tap=register_tap("snmp");

	register_srt_table(proto_snmp, NULL, 1, snmpstat_packet, snmpstat_init, NULL);
}


/*--- proto_reg_handoff_snmp ---------------------------------------*/
void proto_reg_handoff_snmp(void) {

	dissector_add_uint_with_preference("udp.port", UDP_PORT_SNMP, snmp_handle);
	dissector_add_uint("ethertype", ETHERTYPE_SNMP, snmp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_SNMP_AGENT, snmp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_SNMP_SINK, snmp_handle);
	dissector_add_uint("hpext.dxsap", HPEXT_SNMP, snmp_handle);

	dissector_add_uint_with_preference("tcp.port", TCP_PORT_SNMP, snmp_tcp_handle);
	/* Since "regular" SNMP port and "trap" SNMP port use the same handler,
	   the "trap" port doesn't really need a separate preference.  Just register
	   normally */
	dissector_add_uint("tcp.port", TCP_PORT_SNMP_TRAP, snmp_tcp_handle);
	dissector_add_uint("udp.port", UDP_PORT_SNMP_TRAP, snmp_handle);
	dissector_add_uint("udp.port", UDP_PORT_SNMP_PATROL, snmp_handle);

	data_handle = find_dissector("data");

	/* SNMPv2-MIB sysDescr "1.3.6.1.2.1.1.1.0" */
	dissector_add_string("snmp.variable_oid", "1.3.6.1.2.1.1.1.0",
		create_dissector_handle(dissect_snmp_variable_string, proto_snmp));
	/* SNMPv2-MIB::sysName.0 (1.3.6.1.2.1.1.5.0) */
	dissector_add_string("snmp.variable_oid", "1.3.6.1.2.1.1.5.0",
		create_dissector_handle(dissect_snmp_variable_string, proto_snmp));

	/*
	 * Process preference settings.
	 *
	 * We can't do this in the register routine, as preferences aren't
	 * read until all dissector register routines have been called (so
	 * that all dissector preferences have been registered).
	 */
	process_prefs();

}

void
proto_register_smux(void)
{
	static int *ett[] = {
		&ett_smux,
	};

	proto_smux = proto_register_protocol("SNMP Multiplex Protocol",
	    "SMUX", "smux");

	proto_register_subtree_array(ett, array_length(ett));

	smux_handle = register_dissector("smux", dissect_smux, proto_smux);
}

void
proto_reg_handoff_smux(void)
{
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_SMUX, smux_handle);
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
