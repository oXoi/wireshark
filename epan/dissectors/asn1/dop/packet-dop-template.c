/* packet-dop.c
 * Routines for X.501 (DSA Operational Attributes)  packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"

#include "packet-x509sat.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-dap.h"
#include "packet-dsp.h"
#include "packet-crmf.h"


#include "packet-dop.h"

#define PNAME  "X.501 Directory Operational Binding Management Protocol"
#define PSNAME "DOP"
#define PFNAME "dop"

void proto_register_dop(void);
void proto_reg_handoff_dop(void);

/* Initialize the protocol and registered fields */
static int proto_dop;

static const char *binding_type; /* binding_type */

static int call_dop_oid_callback(const char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char *col_info, void* data);

#include "packet-dop-hf.c"

/* Initialize the subtree pointers */
static int ett_dop;
static int ett_dop_unknown;
#include "packet-dop-ett.c"

static expert_field ei_dop_unknown_binding_parameter;
static expert_field ei_dop_unsupported_opcode;
static expert_field ei_dop_unsupported_errcode;
static expert_field ei_dop_unsupported_pdu;
static expert_field ei_dop_zero_pdu;

static dissector_handle_t dop_handle;

/* Dissector table */
static dissector_table_t dop_dissector_table;

static void append_oid(packet_info *pinfo, const char *oid)
{
  	const char *name = NULL;

    name = oid_resolved_from_string(pinfo->pool, oid);
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", name ? name : oid);
}

#include "packet-dop-fn.c"

static int
call_dop_oid_callback(const char *base_string, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, const char *col_info, void* data)
{
  char* binding_param;

  binding_param = wmem_strdup_printf(pinfo->pool, "%s.%s", base_string, binding_type ? binding_type : "");

  col_append_fstr(pinfo->cinfo, COL_INFO, " %s", col_info);

  if (dissector_try_string_with_data(dop_dissector_table, binding_param, tvb, pinfo, tree, true, data)) {
     offset = tvb_reported_length (tvb);
  } else {
     proto_item *item;
     proto_tree *next_tree;

     next_tree = proto_tree_add_subtree_format(tree, tvb, 0, -1, ett_dop_unknown, &item,
         "Dissector for parameter %s OID:%s not implemented. Contact Wireshark developers if you want this supported", base_string, binding_type ? binding_type : "<empty>");

     offset = dissect_unknown_ber(pinfo, tvb, offset, next_tree);
     expert_add_info(pinfo, item, &ei_dop_unknown_binding_parameter);
   }

   return offset;
}


/*
* Dissect DOP PDUs inside a ROS PDUs
*/
static int
dissect_dop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	int offset = 0;
	int old_offset;
	proto_item *item;
	proto_tree *tree;
	struct SESSION_DATA_STRUCTURE* session;
	int (*dop_dissector)(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) = NULL;
	const char *dop_op_name;
	asn1_ctx_t asn1_ctx;

	/* do we have operation information from the ROS dissector? */
	if (data == NULL)
		return 0;
	session = (struct SESSION_DATA_STRUCTURE*)data;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	item = proto_tree_add_item(parent_tree, proto_dop, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_dop);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DOP");
  	col_clear(pinfo->cinfo, COL_INFO);

	asn1_ctx.private_data = session;

	switch(session->ros_op & ROS_OP_MASK) {
	case (ROS_OP_BIND | ROS_OP_ARGUMENT):	/*  BindInvoke */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindArgument;
	  dop_op_name = "DSA-Operational-Bind-Argument";
	  break;
	case (ROS_OP_BIND | ROS_OP_RESULT):	/*  BindResult */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindResult;
	  dop_op_name = "DSA-Operational-Bind-Result";
	  break;
	case (ROS_OP_BIND | ROS_OP_ERROR):	/*  BindError */
	  dop_dissector = dissect_dop_DSAOperationalManagementBindError;
	  dop_op_name = "DSA-Operational-Management-Bind-Error";
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ARGUMENT):	/*  Invoke Argument */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* establish */
	    dop_dissector = dissect_dop_EstablishOperationalBindingArgument;
	    dop_op_name = "Establish-Operational-Binding-Argument";
	    break;
	  case 101: /* terminate */
	    dop_dissector = dissect_dop_TerminateOperationalBindingArgument;
	    dop_op_name = "Terminate-Operational-Binding-Argument";
	    break;
	  case 102: /* modify */
	    dop_dissector = dissect_dop_ModifyOperationalBindingArgument;
	    dop_op_name = "Modify-Operational-Binding-Argument";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_dop_unsupported_opcode, tvb, offset, -1,
	        "Unsupported DOP Argument opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_RESULT):	/*  Return Result */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* establish */
	    dop_dissector = dissect_dop_EstablishOperationalBindingResult;
	    dop_op_name = "Establish-Operational-Binding-Result";
	    break;
	  case 101: /* terminate */
	    dop_dissector = dissect_dop_TerminateOperationalBindingResult;
	    dop_op_name = "Terminate-Operational-Binding-Result";
	    break;
	  case 102: /* modify */
	    dop_dissector = dissect_dop_ModifyOperationalBindingResult;
	    dop_op_name = "Modify-Operational-Binding-Result";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_dop_unsupported_opcode, tvb, offset, -1,
	            "Unsupported DOP Result opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	case (ROS_OP_INVOKE | ROS_OP_ERROR):	/*  Return Error */
	  switch(session->ros_op & ROS_OP_OPCODE_MASK) {
	  case 100: /* operational-binding */
	    dop_dissector = dissect_dop_OpBindingErrorParam;
	    dop_op_name = "Operational-Binding-Error";
	    break;
	  default:
	    proto_tree_add_expert_format(tree, pinfo, &ei_dop_unsupported_errcode, tvb, offset, -1,
	        "Unsupported DOP Error opcode (%d)", session->ros_op & ROS_OP_OPCODE_MASK);
	    break;
	  }
	  break;
	default:
	  proto_tree_add_expert(tree, pinfo, &ei_dop_unsupported_pdu, tvb, offset, -1);
	  return tvb_captured_length(tvb);
	}

	if(dop_dissector) {
      col_set_str(pinfo->cinfo, COL_INFO, dop_op_name);

	  while (tvb_reported_length_remaining(tvb, offset) > 0){
	    old_offset=offset;
	    offset=(*dop_dissector)(false, tvb, offset, &asn1_ctx, tree, -1);
	    if(offset == old_offset){
	      proto_tree_add_expert(tree, pinfo, &ei_dop_zero_pdu, tvb, offset, -1);
	      break;
	    }
	  }
	}

	return tvb_captured_length(tvb);
}



/*--- proto_register_dop -------------------------------------------*/
void proto_register_dop(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-dop-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_dop,
    &ett_dop_unknown,
#include "packet-dop-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_dop_unknown_binding_parameter, { "dop.unknown_binding_parameter", PI_UNDECODED, PI_WARN, "Unknown binding-parameter", EXPFILL }},
     { &ei_dop_unsupported_opcode, { "dop.unsupported_opcode", PI_UNDECODED, PI_WARN, "Unsupported DOP opcode", EXPFILL }},
     { &ei_dop_unsupported_errcode, { "dop.unsupported_errcode", PI_UNDECODED, PI_WARN, "Unsupported DOP errcode", EXPFILL }},
     { &ei_dop_unsupported_pdu, { "dop.unsupported_pdu", PI_UNDECODED, PI_WARN, "Unsupported DOP PDU", EXPFILL }},
     { &ei_dop_zero_pdu, { "dop.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte DOP PDU", EXPFILL }},
  };

  expert_module_t* expert_dop;
  module_t *dop_module;

  /* Register protocol */
  proto_dop = proto_register_protocol(PNAME, PSNAME, PFNAME);

  dop_handle = register_dissector("dop", dissect_dop, proto_dop);

  dop_dissector_table = register_dissector_table("dop.oid", "DOP OID", proto_dop, FT_STRING, STRING_CASE_SENSITIVE);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dop, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dop = expert_register_protocol(proto_dop);
  expert_register_field_array(expert_dop, ei, array_length(ei));

  /* Register our configuration options for DOP, particularly our port */

  dop_module = prefs_register_protocol_subtree("OSI/X.500", proto_dop, NULL);

  prefs_register_obsolete_preference(dop_module, "tcp.port");

  prefs_register_static_text_preference(dop_module, "tcp_port_info",
            "The TCP ports used by the DOP protocol should be added to the TPKT preference \"TPKT TCP ports\", or by selecting \"TPKT\" as the \"Transport\" protocol in the \"Decode As\" dialog.",
            "DOP TCP Port preference moved information");

}


/*--- proto_reg_handoff_dop --- */
void proto_reg_handoff_dop(void) {

#include "packet-dop-dis-tab.c"
  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-operational-binding-management","2.5.3.3");

  /* ABSTRACT SYNTAXES */

  /* Register DOP with ROS (with no use of RTSE) */
  register_ros_oid_dissector_handle("2.5.9.4", dop_handle, 0, "id-as-directory-operational-binding-management", false);

  /* BINDING TYPES */

  oid_add_from_string("shadow-agreement","2.5.19.1");
  oid_add_from_string("hierarchical-agreement","2.5.19.2");
  oid_add_from_string("non-specific-hierarchical-agreement","2.5.19.3");

  /* ACCESS CONTROL SCHEMES */
  oid_add_from_string("basic-ACS","2.5.28.1");
  oid_add_from_string("simplified-ACS","2.5.28.2");
  oid_add_from_string("ruleBased-ACS","2.5.28.3");
  oid_add_from_string("ruleAndBasic-ACS","2.5.28.4");
  oid_add_from_string("ruleAndSimple-ACS","2.5.28.5");

  /* ADMINISTRATIVE ROLES */
  oid_add_from_string("id-ar-autonomousArea","2.5.23.1");
  oid_add_from_string("id-ar-accessControlSpecificArea","2.5.23.2");
  oid_add_from_string("id-ar-accessControlInnerArea","2.5.23.3");
  oid_add_from_string("id-ar-subschemaAdminSpecificArea","2.5.23.4");
  oid_add_from_string("id-ar-collectiveAttributeSpecificArea","2.5.23.5");
  oid_add_from_string("id-ar-collectiveAttributeInnerArea","2.5.23.6");
  oid_add_from_string("id-ar-contextDefaultSpecificArea","2.5.23.7");
  oid_add_from_string("id-ar-serviceSpecificArea","2.5.23.8");
}
