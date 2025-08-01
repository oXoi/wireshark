/* packet-zbee-zcl-ha.c
 * Dissector routines for the ZigBee ZCL HA clusters like
 * Appliance Identification, Meter Identification ...
 * By Fabio Tarabelloni <fabio.tarabelloni@reloc.it>
 * Copyright 2013 RELOC s.r.l.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  Include Files */
#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>

#include "packet-zbee.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

/* ########################################################################## */
/* #### (0x0B00) APPLIANCE IDENTIFICATION CLUSTER ########################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_APPL_IDT_NUM_GENERIC_ETT               2
#define ZBEE_ZCL_APPL_IDT_NUM_ETT                       ZBEE_ZCL_APPL_IDT_NUM_GENERIC_ETT

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_BASIC_IDENT           0x0000  /* Basic Identification */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_NAME          0x0010  /* Company Name */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_ID            0x0011  /* Company ID */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_NAME            0x0012  /* Brand Name */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_ID              0x0013  /* Brand ID */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_MODEL                 0x0014  /* Model */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PART_NUM              0x0015  /* Part Number */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_REV              0x0016  /* Product Revision */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_SW_REV                0x0017  /* Software Revision */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_NAME        0x0018  /* Product Type Name */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_ID          0x0019  /* Product Type ID */
#define ZBEE_ZCL_ATTR_ID_APPL_IDT_CECED_SPEC_VER        0x001A  /* CECED Specification Version */

/* Server Commands Received - None */

/* Server Commands Generated - None */

/* Companies Id */
#define ZBEE_ZCL_APPL_IDT_COMPANY_ID_IC                 0x4943  /* Indesit Company */

/* Brands Id */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_AR                   0x4152  /* Ariston */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_IN                   0x494E  /* Indesit */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_SC                   0x5343  /* Scholtes */
#define ZBEE_ZCL_APPL_IDT_BRAND_ID_ST                   0x5354  /* Stinol */

/* Product Types Id */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WG               0x0000  /* WhiteGoods */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_DW               0x5601  /* Dishwasher */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_TD               0x5602  /* Tumble Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WD               0x5603  /* Washer Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WM               0x5604  /* Washing Machine */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_GO               0x5E01  /* Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_HB               0x5E03  /* Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_OV               0x5E06  /* Electrical Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_IH               0x5E09  /* Induction Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_RF               0x6601  /* Refrigerator Freezer */

/* Product Name Types Id */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WG          0x0000  /* WhiteGoods */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_DW          0x4457  /* Dishwasher */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_TD          0x5444  /* Tumble Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WD          0x5744  /* Washer Dryer */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WM          0x574D  /* Washing Machine */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_GO          0x474F  /* Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_HB          0x4842  /* Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_OV          0x4F56  /* Electrical Oven */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_IH          0x4948  /* Induction Hobs */
#define ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_RF          0x5246  /* Refrigerator Freezer */

/* CECED Specification Version values */
#define ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_NOT_CERT   0x10  /* Compliant with v1.0, not certified */
#define ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_CERT       0x1A  /* Compliant with v1.0, certified */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_appl_idt(void);
void proto_reg_handoff_zbee_zcl_appl_idt(void);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_idt;

static int hf_zbee_zcl_appl_idt_attr_id;
static int hf_zbee_zcl_appl_idt_company_id;
static int hf_zbee_zcl_appl_idt_brand_id;
static int hf_zbee_zcl_appl_idt_string_len;
static int hf_zbee_zcl_appl_idt_prod_type_name;
static int hf_zbee_zcl_appl_idt_prod_type_id;
static int hf_zbee_zcl_appl_idt_ceced_spec_ver;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_appl_idt;
static int ett_zbee_zcl_appl_idt_basic;

/* Attributes */
static const value_string zbee_zcl_appl_idt_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_BASIC_IDENT,      "Basic Identification" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_NAME,     "Company Name" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_ID,       "Company Id" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_NAME,       "Brand Name" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_ID,         "Brand Id" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_MODEL,            "Model" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PART_NUM,         "Part Number" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_REV,         "Product Revision" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_SW_REV,           "Software Revision" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_NAME,   "Product Type Name" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_ID,     "Product Type Id" },
    { ZBEE_ZCL_ATTR_ID_APPL_IDT_CECED_SPEC_VER,   "CECED Specification Version" },
    { 0, NULL }
};

/* Company Names */
static const value_string zbee_zcl_appl_idt_company_names[] = {
    { ZBEE_ZCL_APPL_IDT_COMPANY_ID_IC,      "Indesit Company" },
    { 0, NULL }
};

/* Brand Names */
static const value_string zbee_zcl_appl_idt_brand_names[] = {
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_AR,        "Ariston" },
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_IN,        "Indesit" },
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_SC,        "Scholtes" },
    { ZBEE_ZCL_APPL_IDT_BRAND_ID_ST,        "Stinol" },
    { 0, NULL }
};

/* Product Type Names */
static const value_string zbee_zcl_appl_idt_prod_type_names[] = {
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WG,    "WhiteGoods" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_DW,    "Dishwasher" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_TD,    "Tumble Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WD,    "Washer Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_WM,    "Washing Machine" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_GO,    "Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_HB,    "Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_OV,    "Electrical Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_IH,    "Induction Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_ID_RF,    "Refrigerator Freezer" },
    { 0, NULL }
};

/* Product Type Name Names */
static const value_string zbee_zcl_appl_idt_prod_type_name_names[] = {
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WG,    "WhiteGoods" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_DW,    "Dishwasher" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_TD,    "Tumble Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WD,    "Washer Dryer" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_WM,    "Washing Machine" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_GO,    "Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_HB,    "Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_OV,    "Electrical Oven" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_IH,    "Induction Hobs" },
    { ZBEE_ZCL_APPL_IDT_PROD_TYPE_NAME_ID_RF,    "Refrigerator Freezer" },
    { 0, NULL }
};

/* CECED Specification Version Names */
static const value_string zbee_zcl_appl_idt_ceced_spec_ver_names[] = {
    { ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_NOT_CERT,  "Compliant with v1.0, not certified" },
    { ZBEE_ZCL_APPL_IDT_CECED_SPEC_VAL_1_0_CERT,      "Compliant with v1.0, certified" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Appliance Identification cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_appl_idt(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
	return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_appl_idt*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
 *@param client_attr ZCL client
*/
static void
dissect_zcl_appl_idt_attr_data(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    proto_tree  *sub_tree;
    uint64_t    value64;

    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_BASIC_IDENT:
            value64 = tvb_get_letoh56(tvb, *offset);
            sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 8, ett_zbee_zcl_appl_idt_basic, NULL,
                    "Basic Identification: 0x%" PRIx64, value64);

            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_company_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_brand_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_prod_type_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            proto_tree_add_item(sub_tree, hf_zbee_zcl_appl_idt_ceced_spec_ver, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_COMPANY_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_company_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_BRAND_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_brand_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_NAME:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_string_len, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_prod_type_name, tvb, *offset, 2, ENC_BIG_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_PROD_TYPE_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_prod_type_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_APPL_IDT_CECED_SPEC_VER:
            proto_tree_add_item(tree, hf_zbee_zcl_appl_idt_ceced_spec_ver, tvb, *offset, 1, ENC_NA);
            *offset += 1;
            break;

        default:
            dissect_zcl_attr_data(tvb, pinfo, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_appl_idt_attr_data*/

/**
 *This function registers the ZCL Appliance Identification dissector
 *
*/
void
proto_register_zbee_zcl_appl_idt(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_idt_attr_id,
            { "Attribute", "zbee_zcl_ha.applident.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_company_id,
            { "Company ID", "zbee_zcl_ha.applident.attr.company.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_company_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_brand_id,
            { "Brand ID", "zbee_zcl_ha.applident.attr.brand.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_brand_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_string_len,
            { "Length", "zbee_zcl_ha.applident.string.len", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_prod_type_name,
            { "Product Type Name", "zbee_zcl_ha.applident.attr.prod_type.name", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_prod_type_name_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_prod_type_id,
            { "Product Type ID", "zbee_zcl_ha.applident.attr.prod_type.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_idt_prod_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_appl_idt_ceced_spec_ver,
            { "CECED Spec. Version", "zbee_zcl_ha.applident.attr.ceced_spec_ver", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_idt_ceced_spec_ver_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Appliance Identification subtrees */
    int *ett[ZBEE_ZCL_APPL_IDT_NUM_ETT];

    ett[0] = &ett_zbee_zcl_appl_idt;
    ett[1] = &ett_zbee_zcl_appl_idt_basic;

    /* Register the ZigBee ZCL Appliance Identification cluster protocol name and description */
    proto_zbee_zcl_appl_idt = proto_register_protocol("ZigBee ZCL Appliance Identification", "ZCL Appliance Identification", ZBEE_PROTOABBREV_ZCL_APPLIDT);
    proto_register_field_array(proto_zbee_zcl_appl_idt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Identification dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_APPLIDT, dissect_zbee_zcl_appl_idt, proto_zbee_zcl_appl_idt);
} /*proto_register_zbee_zcl_appl_idt*/

/**
 *Hands off the Zcl Appliance Identification dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_appl_idt(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_APPLIDT,
                            proto_zbee_zcl_appl_idt,
                            ett_zbee_zcl_appl_idt,
                            ZBEE_ZCL_CID_APPLIANCE_IDENTIFICATION,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_appl_idt_attr_id,
                            hf_zbee_zcl_appl_idt_attr_id,
                            -1, -1,
                            dissect_zcl_appl_idt_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_appl_idt*/

/* ########################################################################## */
/* #### (0x0B01) METER IDENTIFICATION CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_COMPANY_NAME                   0x0000  /* Company Name */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_METER_TYPE_ID                  0x0001  /* Meter Type ID */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_DATA_QUALITY_ID                0x0004  /* Data Quality ID */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_CUSTOMER_NAME                  0x0005  /* Customer Name */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_MODEL                          0x0006  /* Model */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_PART_NUM                       0x0007  /* Part Number */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_PRODUCT_REVISION               0x0008  /* Product Revision */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_SW_REVISION                    0x000a  /* Software Revision */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_UTILITY_NAME                   0x000b  /* Utility Name */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_POD                            0x000c  /* POD */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_AVAILABLE_PWR                  0x000d  /* Available Power */
#define ZBEE_ZCL_ATTR_ID_MET_IDT_PWR_TH                         0x000e  /* Power Threshold */

/* Server Commands Received - None */

/* Server Commands Generated - None */


/* Meter Type IDs */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_1_METER               0x0000 /* Utility Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_P_METER               0x0001 /* Utility Production Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_2_METER               0x0002 /* Utility Secondary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_1_METER               0x0100 /* Private Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_P_METER               0x0101 /* Private Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_2_METER               0x0102 /* Private Primary Meter */
#define ZBEE_ZCL_MET_IDT_MET_TYPE_GENERIC_METER                 0x0110 /* Generic Meter */


/* Data Quality IDs */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_DATA_CERTIF              0x0000 /* All Data Certified */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_INST_PWR       0x0001 /* Only Instantaneous Power not Certified */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_CUM_CONS       0x0002 /* Only Cumulated Consumption not Certified */
#define ZBEE_ZCL_MET_IDT_DATA_QLTY_NOT_CERTIF_DATA              0x0003 /* Not Certified Data */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_met_idt(void);
void proto_reg_handoff_zbee_zcl_met_idt(void);

/* Private functions prototype */

/*************************/
/* Global Variables      */
/*************************/

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_met_idt;

static int hf_zbee_zcl_met_idt_attr_id;
static int hf_zbee_zcl_met_idt_meter_type_id;
static int hf_zbee_zcl_met_idt_data_quality_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_met_idt;

/* Attributes */
static const value_string zbee_zcl_met_idt_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_MET_IDT_COMPANY_NAME,            "Company Name" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_METER_TYPE_ID,           "Meter Type ID" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_DATA_QUALITY_ID,         "Data Quality ID" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_CUSTOMER_NAME,           "Customer Name" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_MODEL,                   "Model" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_PART_NUM,                "Part Number" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_PRODUCT_REVISION,        "Product Revision" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_SW_REVISION,             "Software Revision" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_UTILITY_NAME,            "Utility Name" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_POD,                     "POD" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_AVAILABLE_PWR,           "Available Power" },
    { ZBEE_ZCL_ATTR_ID_MET_IDT_PWR_TH,                  "Power Threshold" },
    { 0, NULL }
};

/* Meter Type IDs */
static const value_string zbee_zcl_met_idt_meter_type_names[] = {
    { ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_1_METER,        "Utility Primary Meter" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_P_METER,        "Meter Type ID" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_UTILITY_2_METER,        "Data Quality ID" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_1_METER,        "Customer Name" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_P_METER,        "Model" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_PRIVATE_2_METER,        "Part Number" },
    { ZBEE_ZCL_MET_IDT_MET_TYPE_GENERIC_METER,          "Product Revision" },
    { 0, NULL }
};

/* Data Quality IDs */
static const value_string zbee_zcl_met_idt_data_quality_names[] = {
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_DATA_CERTIF,               "All Data Certified" },
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_INST_PWR,        "Only Instantaneous Power not Certified" },
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_ALL_CERTIF_WO_CUM_CONS,        "Only Cumulated Consumption not Certified" },
    { ZBEE_ZCL_MET_IDT_DATA_QLTY_NOT_CERTIF_DATA,               "Not Certified Data" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Meter Identification cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_met_idt(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_met_idt*/

/**
 *This function is called by ZCL foundation dissector in order to decode
 *
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param tvb pointer to buffer containing raw packet.
 *@param offset pointer to buffer offset
 *@param attr_id attribute identifier
 *@param data_type attribute data type
 *@param client_attr ZCL client
*/
static void
dissect_zcl_met_idt_attr_data (proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr)
{
    /* Dissect attribute data type and data */
    switch ( attr_id ) {

        case ZBEE_ZCL_ATTR_ID_MET_IDT_METER_TYPE_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_met_idt_meter_type_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        case ZBEE_ZCL_ATTR_ID_MET_IDT_DATA_QUALITY_ID:
            proto_tree_add_item(tree, hf_zbee_zcl_met_idt_data_quality_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
            *offset += 2;
            break;

        default:
            dissect_zcl_attr_data(tvb, pinfo, tree, offset, data_type, client_attr);
            break;
    }

} /*dissect_zcl_met_idt_attr_data*/

/**
 *This function registers the ZCL Meter Identification dissector
 *
*/
void
proto_register_zbee_zcl_met_idt(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_met_idt_attr_id,
            { "Attribute",   "zbee_zcl_ha.metidt.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_idt_attr_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_idt_meter_type_id,
            { "Meter Type ID", "zbee_zcl_ha.metidt.attr.meter_type.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_idt_meter_type_names),
            0x00, NULL, HFILL } },

        { &hf_zbee_zcl_met_idt_data_quality_id,
            { "Data Quality ID", "zbee_zcl_ha.metidt.attr.data_quality.id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_met_idt_data_quality_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Meter Identification subtrees */
    int *ett[] = {
        &ett_zbee_zcl_met_idt
    };

    /* Register the ZigBee ZCL Meter Identification cluster protocol name and description */
    proto_zbee_zcl_met_idt = proto_register_protocol("ZigBee ZCL Meter Identification", "ZCL Meter Identification", ZBEE_PROTOABBREV_ZCL_METIDT);
    proto_register_field_array(proto_zbee_zcl_met_idt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Meter Identification dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_METIDT, dissect_zbee_zcl_met_idt, proto_zbee_zcl_met_idt);
} /*proto_register_zbee_zcl_met_idt*/

/**
 *Hands off the Zcl Meter Identification dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_met_idt(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_METIDT,
                            proto_zbee_zcl_met_idt,
                            ett_zbee_zcl_met_idt,
                            ZBEE_ZCL_CID_METER_IDENTIFICATION,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_met_idt_attr_id,
                            hf_zbee_zcl_met_idt_attr_id,
                            -1, -1,
                            dissect_zcl_met_idt_attr_data
                         );
} /*proto_reg_handoff_zbee_zcl_met_idt*/

/* ########################################################################## */
/* #### (0x0B02) APPLIANCE EVENTS AND ALERT CLUSTER ######################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_APPL_EVTALT_NUM_GENERIC_ETT              1
#define ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT               15
#define ZBEE_ZCL_APPL_EVTALT_NUM_ETT                      (ZBEE_ZCL_APPL_EVTALT_NUM_GENERIC_ETT + \
                                                          ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT)
/* Attributes - None */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_CMD        0x00  /* Get Alerts */

/* Server Commands Generated */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_RSP_CMD    0x00  /* Get Alerts Response */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_ALERTS_NOTIF_CMD      0x01  /* Alerts Notification */
#define ZBEE_ZCL_CMD_ID_APPL_EVTALT_EVENT_NOTIF_CMD       0x02  /* Event Notification */

/* Alert Count masks */
#define ZBEE_ZCL_APPL_EVTALT_COUNT_NUM_MASK               0x0F  /* Number of Alerts : [0..3] */
#define ZBEE_ZCL_APPL_EVTALT_COUNT_TYPE_MASK              0xF0  /* Type of Alerts : [4..7] */

/* Alert structure masks */
#define ZBEE_ZCL_APPL_EVTALT_ALERT_ID_MASK                0x0000FF  /* Alerts Id : [0..7] */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_MASK                0x000F00  /* Category : [8..11] */
#define ZBEE_ZCL_APPL_EVTALT_STATUS_MASK                  0x003000  /* Presence / Recovery: [12..13] */
#define ZBEE_ZCL_APPL_EVTALT_RESERVED_MASK                0x00C000  /* Reserved : [14..15] */
#define ZBEE_ZCL_APPL_EVTALT_PROPRIETARY_MASK             0xFF0000  /* Non-Standardized / Proprietary : [16..23] */

/* Category values */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_RESERVED            0x00  /* Reserved */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_WARNING             0x01  /* Warning */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_DANGER              0x02  /* Danger */
#define ZBEE_ZCL_APPL_EVTALT_CATEGORY_FAILURE             0x03  /* Failure */

/* Status values */
#define ZBEE_ZCL_APPL_EVTALT_STATUS_RECOVERY              0x00  /* Recovery */
#define ZBEE_ZCL_APPL_EVTALT_STATUS_PRESENCE              0x01  /* Presence */

/* Event Identification */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_CYCLE           0x01  /* End Of Cycle */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_1             0x02  /* Reserved */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_2             0x03  /* Reserved */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_TEMP_REACHED           0x04  /* Temperature Reached */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_COOKING         0x05  /* End Of Cooking */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_SW_OFF                 0x06  /* Switching Off */
#define ZBEE_ZCL_APPL_EVTALT_EVENT_WRONG_DATA             0xf7  /* Wrong Data */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_appl_evtalt(void);
void proto_reg_handoff_zbee_zcl_appl_evtalt(void);

/* Command Dissector Helpers */
static void dissect_zcl_appl_evtalt_get_alerts_rsp        (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_appl_evtalt_event_notif           (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_evtalt;

static int hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id;
static int hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id;
static int hf_zbee_zcl_appl_evtalt_count_num;
static int hf_zbee_zcl_appl_evtalt_count_type;
static int hf_zbee_zcl_appl_evtalt_alert_id;
static int hf_zbee_zcl_appl_evtalt_category;
static int hf_zbee_zcl_appl_evtalt_status;
static int hf_zbee_zcl_appl_evtalt_reserved;
static int hf_zbee_zcl_appl_evtalt_proprietary;
static int hf_zbee_zcl_appl_evtalt_event_hdr;
static int hf_zbee_zcl_appl_evtalt_event_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_appl_evtalt;
static int ett_zbee_zcl_appl_evtalt_alerts_struct[ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT];

/* Server Commands Received */
static const value_string zbee_zcl_appl_evtalt_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_CMD,       "Get Alerts" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_appl_evtalt_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_RSP_CMD,   "Get Alerts Response" },
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_ALERTS_NOTIF_CMD,     "Alerts Notification" },
    { ZBEE_ZCL_CMD_ID_APPL_EVTALT_EVENT_NOTIF_CMD,      "Event Notification" },
    { 0, NULL }
};

/* Event Identification */
static const value_string zbee_zcl_appl_evtalt_event_id_names[] = {
    { ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_CYCLE,          "End Of Cycle" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_1,            "Reserved" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_RESERVED_2,            "Reserved" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_TEMP_REACHED,          "Temperature Reached" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_END_OF_COOKING,        "End Of Cooking" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_SW_OFF,                "Switching Off" },
    { ZBEE_ZCL_APPL_EVTALT_EVENT_WRONG_DATA,            "Wrong Data" },
    { 0, NULL }
};

/* Category values */
static const value_string zbee_zcl_appl_evtalt_category_names[] = {
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_RESERVED,           "Reserved" },
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_WARNING,            "Warning" },
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_DANGER,             "Danger" },
    { ZBEE_ZCL_APPL_EVTALT_CATEGORY_FAILURE,            "Failure" },
    { 0, NULL }
};

/* Status values */
static const value_string zbee_zcl_appl_evtalt_status_names[] = {
    { ZBEE_ZCL_APPL_EVTALT_STATUS_RECOVERY,             "Recovery" },
    { ZBEE_ZCL_APPL_EVTALT_STATUS_PRESENCE,             "Presence" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Appliance Events and Alerts cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_appl_evtalt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_evtalt_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            /*payload_tree = */proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_evtalt, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_CMD:
                    /* No payload */
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_evtalt_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_evtalt, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_GET_ALERTS_RSP_CMD:
                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_ALERTS_NOTIF_CMD:
                    dissect_zcl_appl_evtalt_get_alerts_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_EVTALT_EVENT_NOTIF_CMD:
                    dissect_zcl_appl_evtalt_event_notif(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_appl_evtalt*/

/**
 *This function is called in order to decode alerts structure payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset offset in the tvb buffer
*/
static void
dissect_zcl_appl_evtalt_alerts_struct(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_alert_id, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_category, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_status, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_reserved, tvb, *offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_proprietary, tvb, *offset, 3, ENC_BIG_ENDIAN);
    *offset += 3;
} /*dissect_zcl_appl_evtalt_alerts_struct*/

/**
 *This function is called in order to decode the GetAlertsRespose payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset offset in the tvb buffer
*/
static void
dissect_zcl_appl_evtalt_get_alerts_rsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    proto_tree  *sub_tree = NULL;
    unsigned    i;
    uint8_t     count;

    /* Retrieve "Alert Count" field */
    count = tvb_get_uint8(tvb, *offset) & ZBEE_ZCL_APPL_EVTALT_COUNT_NUM_MASK;
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_count_num, tvb, *offset, 1, ENC_NA);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_count_type, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Alerts structure decoding */
    for ( i=0 ; i<count ; i++)
    {
        /* Create subtree */
        sub_tree = proto_tree_add_subtree_format(tree, tvb, *offset, 1,
                    ett_zbee_zcl_appl_evtalt_alerts_struct[i], NULL, "Alerts Structure #%u", i);

        dissect_zcl_appl_evtalt_alerts_struct(tvb, sub_tree, offset);
    }
} /*dissect_zcl_appl_evtalt_get_alerts_rsp*/

/**
 *This function is called in order to decode the EventNotification payload
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset offset in the tvb buffer
*/
static void
dissect_zcl_appl_evtalt_event_notif(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve "Event Header" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_event_hdr, tvb, *offset, 1, ENC_NA);
    *offset += 1;
    /* Retrieve "Event Identification" field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_evtalt_event_id, tvb, *offset, 1, ENC_NA);
    *offset += 1;
} /*dissect_zcl_appl_evtalt_event_notif*/

/**
 *This function registers the ZCL Appliance Events and Alert dissector
 *
*/
void
proto_register_zbee_zcl_appl_evtalt(void)
{
    unsigned i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id,
            { "Command", "zbee_zcl_ha.applevtalt.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_evtalt_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id,
            { "Command", "zbee_zcl_ha.applevtalt.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_evtalt_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_count_num,
            { "Number of Alerts", "zbee_zcl_ha.applevtalt.count.num", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_APPL_EVTALT_COUNT_NUM_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_count_type,
            { "Type of Alerts", "zbee_zcl_ha.applevtalt.count.type", FT_UINT8, BASE_DEC, NULL,
            ZBEE_ZCL_APPL_EVTALT_COUNT_TYPE_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_alert_id,
            { "Alert Id", "zbee_zcl_ha.applevtalt.alert_id", FT_UINT24, BASE_HEX, NULL,
            ZBEE_ZCL_APPL_EVTALT_ALERT_ID_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_category,
            { "Category", "zbee_zcl_ha.applevtalt.category", FT_UINT24, BASE_HEX, VALS(zbee_zcl_appl_evtalt_category_names),
            ZBEE_ZCL_APPL_EVTALT_CATEGORY_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_status,
            { "Status", "zbee_zcl_ha.applevtalt.status", FT_UINT24, BASE_HEX, VALS(zbee_zcl_appl_evtalt_status_names),
            ZBEE_ZCL_APPL_EVTALT_STATUS_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_reserved,
            { "Reserved", "zbee_zcl_ha.applevtalt.reserved", FT_UINT24, BASE_HEX, NULL,
            ZBEE_ZCL_APPL_EVTALT_RESERVED_MASK, NULL, HFILL } },

        { &hf_zbee_zcl_appl_evtalt_proprietary,
            { "Proprietary", "zbee_zcl_ha.applevtalt.proprietary", FT_UINT24, BASE_HEX, NULL,
            ZBEE_ZCL_APPL_EVTALT_PROPRIETARY_MASK, NULL, HFILL } },

         { &hf_zbee_zcl_appl_evtalt_event_hdr,
            { "Event Header", "zbee_zcl_ha.applevtalt.event.header", FT_UINT8, BASE_HEX, NULL,
            0x00, NULL, HFILL } },

         { &hf_zbee_zcl_appl_evtalt_event_id,
            { "Event Id", "zbee_zcl_ha.applevtalt.event.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_evtalt_event_id_names),
            0x00, NULL, HFILL } }

    };

    /* ZCL Appliance Events And Alerts subtrees */
    int *ett[ZBEE_ZCL_APPL_EVTALT_NUM_ETT];

    ett[0] = &ett_zbee_zcl_appl_evtalt;

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_APPL_EVTALT_NUM_GENERIC_ETT; i < ZBEE_ZCL_APPL_EVTALT_NUM_STRUCT_ETT; i++, j++) {
        ett[j] = &ett_zbee_zcl_appl_evtalt_alerts_struct[i];
    }

    /* Register the ZigBee ZCL Appliance Events And Alerts cluster protocol name and description */
    proto_zbee_zcl_appl_evtalt = proto_register_protocol("ZigBee ZCL Appliance Events & Alert", "ZCL Appliance Events & Alert", ZBEE_PROTOABBREV_ZCL_APPLEVTALT);
    proto_register_field_array(proto_zbee_zcl_appl_evtalt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Control dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_APPLEVTALT, dissect_zbee_zcl_appl_evtalt, proto_zbee_zcl_appl_evtalt);
} /*proto_register_zbee_zcl_appl_evtalt*/

/**
 *Hands off the Zcl Appliance Events And Alerts dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_appl_evtalt(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_APPLEVTALT,
                            proto_zbee_zcl_appl_evtalt,
                            ett_zbee_zcl_appl_evtalt,
                            ZBEE_ZCL_CID_APPLIANCE_EVENTS_AND_ALERT,
                            ZBEE_MFG_CODE_NONE,
                            -1, -1,
                            hf_zbee_zcl_appl_evtalt_srv_rx_cmd_id,
                            hf_zbee_zcl_appl_evtalt_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_appl_evtalt*/

/* ########################################################################## */
/* #### (0x0B03) APPLIANCE STATISTICS CLUSTER ############################### */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

#define ZBEE_ZCL_APPL_STATS_NUM_GENERIC_ETT                     1
#define ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT                        16
#define ZBEE_ZCL_APPL_STATS_NUM_ETT                             (ZBEE_ZCL_APPL_STATS_NUM_GENERIC_ETT + \
                                                                 ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT)

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_MAX_SIZE                0x0000  /* Log Max Size */
#define ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_QUEUE_MAX_SIZE          0x0001  /* Log Queue Max Size */

/* Server Commands Received */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_REQ                      0x00  /* Log Request */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_REQ                0x01  /* Log Queue Request */

/* Server Commands Generated - None */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_NOTIF                    0x00  /* Log Notification */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_RSP                      0x01  /* Log Response */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_RSP                0x02  /* Log Queue Response */
#define ZBEE_ZCL_CMD_ID_APPL_STATS_STATS_AVAILABLE              0x03  /* Statistics Available */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_appl_stats(void);
void proto_reg_handoff_zbee_zcl_appl_stats(void);

/* Command Dissector Helpers */
static void dissect_zcl_appl_stats_log_req              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_appl_stats_log_rsp              (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);
static void dissect_zcl_appl_stats_log_queue_rsp        (tvbuff_t *tvb, proto_tree *tree, unsigned *offset);

/*************************/
/* Global Variables      */
/*************************/
/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_appl_stats;

static int hf_zbee_zcl_appl_stats_attr_id;
static int hf_zbee_zcl_appl_stats_srv_tx_cmd_id;
static int hf_zbee_zcl_appl_stats_srv_rx_cmd_id;
static int hf_zbee_zcl_appl_stats_utc_time;
static int hf_zbee_zcl_appl_stats_log_length;
static int hf_zbee_zcl_appl_stats_log_payload;
static int hf_zbee_zcl_appl_stats_log_queue_size;
static int hf_zbee_zcl_appl_stats_log_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_appl_stats;
static int ett_zbee_zcl_appl_stats_logs[ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT];

/* Attributes */
static const value_string zbee_zcl_appl_stats_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_MAX_SIZE,         "Log Max Size" },
    { ZBEE_ZCL_ATTR_ID_APPL_STATS_LOG_QUEUE_MAX_SIZE,   "Log Queue Max Size" },
    { 0, NULL }
};

/* Server Commands Received */
static const value_string zbee_zcl_appl_stats_srv_rx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_REQ,               "Log Request" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_REQ,         "Log Queue Request" },
    { 0, NULL }
};

/* Server Commands Generated */
static const value_string zbee_zcl_appl_stats_srv_tx_cmd_names[] = {
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_NOTIF,             "Log Notification" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_RSP,               "Log Response" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_RSP,         "Log Queue Response" },
    { ZBEE_ZCL_CMD_ID_APPL_STATS_STATS_AVAILABLE,       "Statistics Available" },
    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Appliance Statistics cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_appl_stats (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree        *payload_tree;
    zbee_zcl_packet   *zcl;
    unsigned          offset = 0;
    uint8_t           cmd_id;
    int               rem_len;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    zcl = (zbee_zcl_packet *)data;
    cmd_id = zcl->cmd_id;

    /*  Create a subtree for the ZCL Command frame, and add the command ID to it. */
    if (zcl->direction == ZBEE_ZCL_FCF_TO_SERVER) {
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_stats_srv_rx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_srv_rx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_stats, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_REQ:
                    dissect_zcl_appl_stats_log_req(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_REQ:
                    /* No payload */
                    break;

                default:
                    break;
            }
        }
    }
    else { /* ZBEE_ZCL_FCF_TO_CLIENT */
        /* Append the command name to the info column. */
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s, Seq: %u",
            val_to_str_const(cmd_id, zbee_zcl_appl_stats_srv_tx_cmd_names, "Unknown Command"),
            zcl->tran_seqno);

        /* Add the command ID. */
        proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_srv_tx_cmd_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);

        /* Check is this command has a payload, than add the payload tree */
        rem_len = tvb_reported_length_remaining(tvb, ++offset);
        if (rem_len > 0) {
            payload_tree = proto_tree_add_subtree(tree, tvb, offset, rem_len, ett_zbee_zcl_appl_stats, NULL, "Payload");

            /* Call the appropriate command dissector */
            switch (cmd_id) {
                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_NOTIF:
                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_RSP:
                    dissect_zcl_appl_stats_log_rsp(tvb, payload_tree, &offset);
                    break;

                case ZBEE_ZCL_CMD_ID_APPL_STATS_LOG_QUEUE_RSP:
                case ZBEE_ZCL_CMD_ID_APPL_STATS_STATS_AVAILABLE:
                    dissect_zcl_appl_stats_log_queue_rsp(tvb, payload_tree, &offset);
                    break;

                default:
                    break;
            }
        }
    }

    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_appl_stats*/

/**
 *This function is called in order to decode "LogRequest" payload command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_appl_stats_log_req(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    /* Retrieve 'Log ID' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;
} /*dissect_zcl_appl_stats_log_req*/

/**
 *This function is called in order to decode "LogNotification" and
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_appl_stats_log_rsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    uint32_t log_len;

    /* Retrieve 'UTCTime' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_utc_time, tvb, *offset, 4, ENC_TIME_ZBEE_ZCL|ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Log ID' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Log Length' field */
    log_len = tvb_get_letohl(tvb, *offset);
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_length, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
    *offset += 4;

    /* Retrieve 'Log Payload' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_payload, tvb, *offset, log_len, ENC_NA);
    *offset += log_len;
}/*dissect_zcl_appl_stats_log_rsp*/

/**
 *This function is called in order to decode "LogQueueResponse" and
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param offset pointer to buffer offset
*/
static void
dissect_zcl_appl_stats_log_queue_rsp(tvbuff_t *tvb, proto_tree *tree, unsigned *offset)
{
    int list_len;

    /* Retrieve 'Log Queue Size' field */
    proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_queue_size, tvb, *offset, 1, ENC_NA);
    *offset += 1;

    /* Dissect the attribute id list */
    list_len = tvb_reported_length_remaining(tvb, *offset);
    if ( list_len > 0 ) {
        while ( *offset < (unsigned)list_len ) {
            /* Retrieve 'Log ID' field */
            proto_tree_add_item(tree, hf_zbee_zcl_appl_stats_log_id, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
            *offset += 4;
        }
    }
}/*dissect_zcl_appl_stats_log_queue_rsp*/

/**
 *This function registers the ZCL Appliance Statistics dissector
 *
*/
void
proto_register_zbee_zcl_appl_stats(void)
{
    unsigned i, j;

    static hf_register_info hf[] = {

        { &hf_zbee_zcl_appl_stats_attr_id,
            { "Attribute", "zbee_zcl_ha.applstats.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_appl_stats_attr_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_srv_tx_cmd_id,
            { "Command", "zbee_zcl_ha.applstats.cmd.srv_tx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_stats_srv_tx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_srv_rx_cmd_id,
            { "Command", "zbee_zcl_ha.applstats.cmd.srv_rx.id", FT_UINT8, BASE_HEX, VALS(zbee_zcl_appl_stats_srv_rx_cmd_names),
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_utc_time,
            { "UTC Time", "zbee_zcl_ha.applstats.utc_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, TIME_VALS(zbee_zcl_utctime_strings),
            0x0, NULL, HFILL }},

        { &hf_zbee_zcl_appl_stats_log_length,
            { "Log Length", "zbee_zcl_ha.applstats.log.length", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_log_id,
            { "Log ID", "zbee_zcl_ha.applstats.log.id", FT_UINT32, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_log_queue_size,
            { "Log Queue Size", "zbee_zcl_ha.applstats.log_queue_size", FT_UINT8, BASE_DEC, NULL,
            0x0, NULL, HFILL } },

        { &hf_zbee_zcl_appl_stats_log_payload,
            { "Log Payload", "zbee_zcl_ha.applstats.log.payload", FT_BYTES, SEP_COLON, NULL,
            0x00, NULL, HFILL } },

    };

    /* ZCL ApplianceStatistics subtrees */
    static int *ett[ZBEE_ZCL_APPL_STATS_NUM_ETT];

    ett[0] = &ett_zbee_zcl_appl_stats;

    /* initialize attribute subtree types */
    for ( i = 0, j = ZBEE_ZCL_APPL_STATS_NUM_GENERIC_ETT; i < ZBEE_ZCL_APPL_STATS_NUM_LOGS_ETT; i++, j++ ) {
        ett[j] = &ett_zbee_zcl_appl_stats_logs[i];
    }

    /* Register the ZigBee ZCL Appliance Statistics cluster protocol name and description */
    proto_zbee_zcl_appl_stats = proto_register_protocol("ZigBee ZCL Appliance Statistics", "ZCL Appliance Statistics", ZBEE_PROTOABBREV_ZCL_APPLSTATS);
    proto_register_field_array(proto_zbee_zcl_appl_stats, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Appliance Statistics dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_APPLSTATS, dissect_zbee_zcl_appl_stats, proto_zbee_zcl_appl_stats);
} /* proto_register_zbee_zcl_appl_stats */

/**
 *Hands off the Zcl Appliance Statistics cluster dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_appl_stats(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_APPLSTATS,
                            proto_zbee_zcl_appl_stats,
                            ett_zbee_zcl_appl_stats,
                            ZBEE_ZCL_CID_APPLIANCE_STATISTICS,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_appl_stats_attr_id,
                            hf_zbee_zcl_appl_stats_attr_id,
                            hf_zbee_zcl_appl_stats_srv_rx_cmd_id,
                            hf_zbee_zcl_appl_stats_srv_tx_cmd_id,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_appl_stats*/

/* ########################################################################## */
/* #### (0x0B05) DIAGNOSTICS CLUSTER ######################################## */
/* ########################################################################## */

/*************************/
/* Defines               */
/*************************/

/* Attributes */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NUMBER_OF_RESETS                       0x0000  /* Number of Resets */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PERSISTENT_MEMORY_WRITES               0x0001  /* Persistent Memory Writes */

#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_RX_BCAST                           0x0100 /* MAC RX Broadcast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_BCAST                           0x0101 /* MAC TX Broadcast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_RX_UCAST                           0x0102 /* MAC RX Unicast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_UCAST                           0x0103 /* MAC TX Unicast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_UCAST_RETRY                     0x0104 /* MAC TX Unicast Retry */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_UCAST_FAIL                      0x0105 /* MAC TX Unicast Fail */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_RX_BCAST                           0x0106 /* APS RX Broadcast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_BCAST                           0x0107 /* APS TX Broadcast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_RX_UCAST                           0x0108 /* APS RX Unicast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_UCAST_SUCCESS                   0x0109 /* APS TX Unicast Success */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_UCAST_RETRY                     0x010A /* APS TX Unicast Retry */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_UCAST_FAIL                      0x010B /* APS TX Unicast Fail */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_ROUTE_DISC_INITIATED                   0x010C /* Route Disc Initiated */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NEIGHBOR_ADDED                         0x010D /* Neighbor Added */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NEIGHBOR_REMOVED                       0x010E /* Neighbor Removed */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NEIGHBOR_STALE                         0x010F /* Neighbor Stale */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_JOIN_INDICATION                        0x0110 /* Join Indication */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_CHILD_MOVED                            0x0111 /* Child Moved */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NWK_FC_FAILURE                         0x0112 /* NWK FC Failure */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_FC_FAILURE                         0x0113 /* APS FC Failure */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_UNAUTHORIZED_KEY                   0x0114 /* APS Unauthorized Key */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NWK_DECRYPT_FAILURES                   0x0115 /* NWK Decrypt Failures */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_DECRYPT_FAILURES                   0x0116 /* APS Decrypt Failures */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PACKET_BUFFER_ALLOCATE_FAILURES        0x0117 /* Packet Buffer Allocate Failures */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_RELAYED_UCAST                          0x0118 /* Relayed Unicast */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PHYTO_MAC_QUEUE_LIMIT_REACHED          0x0119 /* Phyto MAC Queue Limit Reached */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PACKET_VALIDATE_DROP_COUNT             0x011A /* Packet Validate Drop Count */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_AVERAGE_MACRETRY_PER_APS_MESSAGE_SENT  0x011B /* Average MAC Retry Per APS Message Sent */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_LAST_MESSAGE_LQI                       0x011C /* Last Message LQI */
#define ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_LAST_MESSAGE_RSSI                      0x011D /* Last Message RSSI */

/*************************/
/* Function Declarations */
/*************************/

void proto_register_zbee_zcl_diagnostics(void);
void proto_reg_handoff_zbee_zcl_diagnostics(void);

/* Initialize the protocol and registered fields */
static int proto_zbee_zcl_diagnostics;

static int hf_zbee_zcl_diagnostics_attr_id;

/* Initialize the subtree pointers */
static int ett_zbee_zcl_diagnostics;

/* Attributes */
static const value_string zbee_zcl_diagnostics_attr_names[] = {
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NUMBER_OF_RESETS,                        "Number of Resets" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PERSISTENT_MEMORY_WRITES,                "Persistent Memory Writes" },

    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_RX_BCAST,                            "MAC RX Broadcast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_BCAST,                            "MAC TX Broadcast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_RX_UCAST,                            "MAC RX Unicast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_UCAST,                            "MAC TX Unicast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_UCAST_RETRY,                      "MAC TX Unicast Retry" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_MAC_TX_UCAST_FAIL,                       "MAC TX Unicast Fail" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_RX_BCAST,                            "APS RX Broadcast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_BCAST,                            "APS TX Broadcast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_RX_UCAST,                            "APS RX Unicast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_UCAST_SUCCESS,                    "APS TX Unicast Success" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_UCAST_RETRY,                      "APS TX Unicast Retry" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_TX_UCAST_FAIL,                       "APS TX Unicast Fail" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_ROUTE_DISC_INITIATED,                    "Route Disc Initiated" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NEIGHBOR_ADDED,                          "Neighbor Added" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NEIGHBOR_REMOVED,                        "Neighbor Removed" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NEIGHBOR_STALE,                          "Neighbor Stale" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_JOIN_INDICATION,                         "Join Indication" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_CHILD_MOVED,                             "Child Moved" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NWK_FC_FAILURE,                          "NWK FC Failure" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_FC_FAILURE,                          "APS FC Failure" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_UNAUTHORIZED_KEY,                    "APS Unauthorized Key" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_NWK_DECRYPT_FAILURES,                    "NWK Decrypt Failures" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_APS_DECRYPT_FAILURES,                    "APS Decrypt Failures" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PACKET_BUFFER_ALLOCATE_FAILURES,         "Packet Buffer Allocate Failures" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_RELAYED_UCAST,                           "Relayed Unicast" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PHYTO_MAC_QUEUE_LIMIT_REACHED,           "Phyto MAC Queue Limit Reached" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_PACKET_VALIDATE_DROP_COUNT,              "Packet Validate Drop Count" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_AVERAGE_MACRETRY_PER_APS_MESSAGE_SENT,   "Average MAC Retry Per APS Message Sent" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_LAST_MESSAGE_LQI,                        "Last Message LQI" },
    { ZBEE_ZCL_ATTR_ID_DIAGNOSTICS_LAST_MESSAGE_RSSI,                       "Last Message RSSI" },

    { 0, NULL }
};

/*************************/
/* Function Bodies       */
/*************************/

/**
 *ZigBee ZCL Diagnostics cluster dissector for wireshark.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields
 *@param tree pointer to data tree Wireshark uses to display packet.
*/
static int
dissect_zbee_zcl_diagnostics(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void* data _U_)
{
    return tvb_captured_length(tvb);
} /*dissect_zbee_zcl_diagnostics*/

/**
 *This function registers the ZCL Diagnostics dissector
 *
*/
void
proto_register_zbee_zcl_diagnostics(void)
{
    static hf_register_info hf[] = {

        { &hf_zbee_zcl_diagnostics_attr_id,
            { "Attribute", "zbee_zcl_ha.diagnostics.attr_id", FT_UINT16, BASE_HEX, VALS(zbee_zcl_diagnostics_attr_names),
            0x0, NULL, HFILL } },

    };

    /* ZCL Diagnostics subtrees */
    int *ett[] = {
        &ett_zbee_zcl_diagnostics
    };

    /* Register the ZigBee ZCL Diagnostics cluster protocol name and description */
    proto_zbee_zcl_diagnostics = proto_register_protocol("ZigBee ZCL Diagnostics", "ZCL Diagnostics", ZBEE_PROTOABBREV_ZCL_DIAGNOSTICS);
    proto_register_field_array(proto_zbee_zcl_diagnostics, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the ZigBee ZCL Diagnostics dissector. */
    register_dissector(ZBEE_PROTOABBREV_ZCL_DIAGNOSTICS, dissect_zbee_zcl_diagnostics, proto_zbee_zcl_diagnostics);
} /* proto_register_zbee_zcl_diagnostics */

/**
 *Hands off the Zcl Diagnostics cluster dissector.
 *
*/
void
proto_reg_handoff_zbee_zcl_diagnostics(void)
{
    zbee_zcl_init_cluster(  ZBEE_PROTOABBREV_ZCL_DIAGNOSTICS,
                            proto_zbee_zcl_diagnostics,
                            ett_zbee_zcl_diagnostics,
                            ZBEE_ZCL_CID_DIAGNOSTICS,
                            ZBEE_MFG_CODE_NONE,
                            hf_zbee_zcl_diagnostics_attr_id,
                            hf_zbee_zcl_diagnostics_attr_id,
                            -1, -1,
                            NULL
                         );
} /*proto_reg_handoff_zbee_zcl_diagnostics*/

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
