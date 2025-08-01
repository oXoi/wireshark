/* packet-zbee-nwk-gp.c
 * Dissector routines for the ZigBee Green Power profile (GP)
 * Copyright 2013 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Used Owen Kirby's packet-zbee-aps module as a template. Based
 * on ZigBee Cluster Library Specification document 075123r02ZB
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files. */
#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <wsutil/bits_ctz.h>
#include <wsutil/pint.h>
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-security.h"
#include "packet-zbee-aps.h"
#include "packet-zbee-zcl.h"

void proto_register_zbee_nwk_gp(void);
void proto_reg_handoff_zbee_nwk_gp(void);

/**************************/
/* Defines. */
/**************************/

/* ZigBee NWK GP FCF frame types. */
#define ZBEE_NWK_GP_FCF_DATA        0x00
#define ZBEE_NWK_GP_FCF_MAINTENANCE 0x01

/* ZigBee NWK GP FCF fields. */
#define ZBEE_NWK_GP_FCF_AUTO_COMMISSIONING  0x40
#define ZBEE_NWK_GP_FCF_CONTROL_EXTENSION   0x80
#define ZBEE_NWK_GP_FCF_FRAME_TYPE          0x03
#define ZBEE_NWK_GP_FCF_VERSION             0x3C

/* Extended NWK Frame Control field. */
#define ZBEE_NWK_GP_FCF_EXT_APP_ID          0x07 /* 0 - 2 b. */
#define ZBEE_NWK_GP_FCF_EXT_SECURITY_LEVEL  0x18 /* 3 - 4 b. */
#define ZBEE_NWK_GP_FCF_EXT_SECURITY_KEY    0x20 /* 5 b. */
#define ZBEE_NWK_GP_FCF_EXT_RX_AFTER_TX     0x40 /* 6 b. */
#define ZBEE_NWK_GP_FCF_EXT_DIRECTION       0x80 /* 7 b. */

/* Definitions for application IDs. */
#define ZBEE_NWK_GP_APP_ID_DEFAULT  0x00
#define ZBEE_NWK_GP_APP_ID_LPED     0x01
#define ZBEE_NWK_GP_APP_ID_ZGP      0x02

/* Definitions for GP directions. */
#define ZBEE_NWK_GP_FC_EXT_DIRECTION_DEFAULT    0x00
#define ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD  0x00
#define ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPP  0x01

/* Definitions for ZGPD Source IDs. */
#define ZBEE_NWK_GP_ZGPD_SRCID_ALL      0xFFFFFFFF
#define ZBEE_NWK_GP_ZGPD_SRCID_UNKNOWN  0x00000000

/* Security level values. */
#define ZBEE_NWK_GP_SECURITY_LEVEL_NO       0x00
#define ZBEE_NWK_GP_SECURITY_LEVEL_1LSB     0x01
#define ZBEE_NWK_GP_SECURITY_LEVEL_FULL     0x02
#define ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR 0x03

/* GP Security key types. */
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_NO_KEY                            0x00
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_ZB_NWK_KEY                        0x01
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_GPD_GROUP_KEY                     0x02
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_NWK_KEY_DERIVED_GPD_KEY_GROUP_KEY 0x03
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_PRECONFIGURED_INDIVIDUAL_GPD_KEY  0x04
#define ZBEE_NWK_GP_SECURITY_KEY_TYPE_DERIVED_INDIVIDUAL_GPD_KEY        0x07

typedef struct {
    /* FCF Data. */
    uint8_t frame_type;
    bool nwk_frame_control_extension;

    /* Ext FCF Data. */
    uint8_t application_id;
    uint8_t security_level;
    uint8_t direction;

    /* Src ID. */
    uint32_t source_id;

    /* GPD Endpoint */
    uint8_t endpoint;

    /* Security Frame Counter. */
    uint32_t security_frame_counter;

    /* MIC. */
    uint8_t mic_size;
    uint32_t mic;

    /* Application Payload. */
    uint8_t payload_len;

    /* Source IEEE address from parent */
    uint64_t ieee_packet_src64;
} zbee_nwk_green_power_packet;

/* Definitions for GP Commissioning command opt field (bitmask). */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MAC_SEQ           0x01
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_RX_ON_CAP         0x02
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_APPLICATION_INFO  0x04
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_PAN_ID_REQ        0x10
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_GP_SEC_KEY_REQ    0x20
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_FIXED_LOCATION    0x40
#define ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_EXT_OPTIONS       0x80

/* Definitions for GP Commissioning command ext_opt field (bitmask). */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_SEC_LEVEL_CAP     0x03
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_KEY_TYPE          0x1C
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_PRESENT   0x20
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_ENCR      0x40
#define ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_OUT_COUNTER       0x80

/* Definitions for GP Commissioning command application information field (bitmask). */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_MIP    0x01
#define ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_MMIP   0x02
#define ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_GCLP   0x04
#define ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_CRP    0x08

/* Definitions for GP Commissioning command Number of server ClusterIDs (bitmask) */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_SRV 0x0F
#define ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_CLI 0xF0

/* Definitions for GP Decommissioning command opt field (bitmask). */
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_PAN_ID_PRESENT    0x01
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT   0x02
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR          0x04
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL         0x18
#define ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_TYPE          0xE0

/* Definition for GP read attributes command opt field (bitmask). */
#define ZBEE_NWK_GP_CMD_READ_ATTRIBUTE_OPT_MULTI_RECORD         0x01
#define ZBEE_NWK_GP_CMD_READ_ATTRIBUTE_OPT_MAN_FIELD_PRESENT    0x02

/* Definitions for GP Channel Request command. */
#define ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_1ST 0x0F
#define ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_2ND 0xF0

/* GP Channel Configuration command. */
#define ZBEE_NWK_GP_CMD_CHANNEL_CONFIGURATION_OPERATION_CH 0x0F

/* GP GENERIC IDS. */
#define GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_1STATE_SWITCH   0x00
#define GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_2STATE_SWITCH   0x01
#define GPD_DEVICE_ID_GENERIC_GP_ON_OFF_SWITCH                  0x02
#define GPD_DEVICE_ID_GENERIC_GP_LEVEL_CONTROL_SWITCH           0x03
#define GPD_DEVICE_ID_GENERIC_GP_SIMPLE_SENSOR                  0x04
#define GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_1STATE_SWITCH 0x05
#define GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_2STATE_SWITCH 0x06

/* GP LIGHTING IDS. */
#define GPD_DEVICE_ID_LIGHTING_GP_COLOR_DIMMER_SWITCH           0x10
#define GPD_DEVICE_ID_LIGHTING_GP_LIGHT_SENSOR                  0x11
#define GPD_DEVICE_ID_LIGHTING_GP_OCCUPANCY_SENSOR              0x12

/* GP CLOSURES IDS. */
#define GPD_DEVICE_ID_CLOSURES_GP_DOOR_LOCK_CONTROLLER          0x20

/* HVAC IDS. */
#define GPD_DEVICE_ID_HVAC_GP_TEMPERATURE_SENSOR                0x30
#define GPD_DEVICE_ID_HVAC_GP_PRESSURE_SENSOR                   0x31
#define GPD_DEVICE_ID_HVAC_GP_FLOW_SENSOR                       0x32
#define GPD_DEVICE_ID_HVAC_GP_INDOOR_ENVIRONMENT_SENSOR         0x33

/* Manufacturer specific device. */
#define GPD_DEVICE_ID_MANUFACTURER_SPECIFIC                     0xFE

/* GPD manufacturers. */
#define ZBEE_NWK_GP_MANUF_ID_GREENPEAK      0x10D0

/* GPD devices by GreenPeak. */
#define ZBEE_NWK_GP_MANUF_GREENPEAK_IZDS    0x0000
#define ZBEE_NWK_GP_MANUF_GREENPEAK_IZDWS   0x0001
#define ZBEE_NWK_GP_MANUF_GREENPEAK_IZLS    0x0002
#define ZBEE_NWK_GP_MANUF_GREENPEAK_IZRHS   0x0003

/*********************/
/* Global variables. */
/*********************/

/* GP proto handle. */
static int proto_zbee_nwk_gp;

/* GP NWK FC. */
static int hf_zbee_nwk_gp_auto_commissioning;
static int hf_zbee_nwk_gp_fc_ext;
static int hf_zbee_nwk_gp_fcf;
static int hf_zbee_nwk_gp_frame_type;
static int hf_zbee_nwk_gp_proto_version;

/* GP NWK FC extension. */
static int hf_zbee_nwk_gp_fc_ext_field;
static int hf_zbee_nwk_gp_fc_ext_app_id;
static int hf_zbee_nwk_gp_fc_ext_direction;
static int hf_zbee_nwk_gp_fc_ext_rx_after_tx;
static int hf_zbee_nwk_gp_fc_ext_sec_key;
static int hf_zbee_nwk_gp_fc_ext_sec_level;

/* ZGPD Src ID. */
static int hf_zbee_nwk_gp_zgpd_src_id;

/* ZGPD Endpoint */
static int hf_zbee_nwk_gp_zgpd_endpoint;

/* Security frame counter. */
static int hf_zbee_nwk_gp_security_frame_counter;

/* Security MIC. */
static int hf_zbee_nwk_gp_security_mic_2b;
static int hf_zbee_nwk_gp_security_mic_4b;

/* Payload subframe. */
static int hf_zbee_nwk_gp_command_id;

/* Commissioning. */
static int hf_zbee_nwk_gp_cmd_comm_device_id;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_encr;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_present;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_key_type;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_outgoing_counter;
static int hf_zbee_nwk_gp_cmd_comm_ext_opt_sec_level_cap;
static int hf_zbee_nwk_gp_cmd_comm_security_key;
static int hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic;
static int hf_zbee_nwk_gp_cmd_comm_opt_ext_opt;
static int hf_zbee_nwk_gp_cmd_comm_opt;
static int hf_zbee_nwk_gp_cmd_comm_opt_fixed_location;
static int hf_zbee_nwk_gp_cmd_comm_opt_mac_sec_num_cap;
static int hf_zbee_nwk_gp_cmd_comm_opt_appli_info_present;
static int hf_zbee_nwk_gp_cmd_comm_opt_panid_req;
static int hf_zbee_nwk_gp_cmd_comm_opt_rx_on_cap;
static int hf_zbee_nwk_gp_cmd_comm_opt_sec_key_req;
static int hf_zbee_nwk_gp_cmd_comm_outgoing_counter;
static int hf_zbee_nwk_gp_cmd_comm_manufacturer_greenpeak_dev_id;
static int hf_zbee_nwk_gp_cmd_comm_manufacturer_dev_id;
static int hf_zbee_nwk_gp_cmd_comm_manufacturer_id;
static int hf_zbee_nwk_gp_cmd_comm_appli_info;
static int hf_zbee_nwk_gp_cmd_comm_appli_info_crp;
static int hf_zbee_nwk_gp_cmd_comm_appli_info_gclp;
static int hf_zbee_nwk_gp_cmd_comm_appli_info_mip;
static int hf_zbee_nwk_gp_cmd_comm_appli_info_mmip;
static int hf_zbee_nwk_gp_cmd_comm_gpd_cmd_num;
static int hf_zbee_nwk_gp_cmd_comm_gpd_cmd_id_list;
static int hf_zbee_nwk_gp_cmd_comm_length_of_clid_list;
static int hf_zbee_nwk_gp_cmd_comm_length_of_clid_list_server;
static int hf_zbee_nwk_gp_cmd_comm_length_of_clid_list_client;
static int hf_zbee_nwk_cmd_comm_clid_list_server;
static int hf_zbee_nwk_cmd_comm_clid_list_client;
static int hf_zbee_nwk_cmd_comm_cluster_id;

/* Commissioning reply. */
static int hf_zbee_nwk_gp_cmd_comm_rep_opt;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_key_encr;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_panid_present;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_key_present;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_level;
static int hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_type;
static int hf_zbee_nwk_gp_cmd_comm_rep_pan_id;
static int hf_zbee_nwk_gp_cmd_comm_rep_frame_counter;

/* Read attribute and read attribute response. */
static int hf_zbee_nwk_gp_cmd_read_att_opt_multi_rec;
static int hf_zbee_nwk_gp_cmd_read_att_opt_man_field_present;
static int hf_zbee_nwk_gp_cmd_read_att_opt;
static int hf_zbee_nwk_gp_cmd_read_att_record_len;

/* Common to commands returning data */
static int hf_zbee_nwk_gp_zcl_attr_status;
static int hf_zbee_nwk_gp_zcl_attr_data_type;
static int hf_zbee_nwk_gp_zcl_attr_cluster_id;

/* Common to all manufacturer specific commands */
static int hf_zbee_zcl_gp_cmd_ms_manufacturer_code;

/* Channel request. */
static int hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour;
static int hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_1st;
static int hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_2nd;

/* Channel Configuration command. */
static int hf_zbee_nwk_gp_cmd_operational_channel;
static int hf_zbee_nwk_gp_cmd_channel_configuration;

/* Move Color command. */
static int hf_zbee_nwk_gp_cmd_move_color_ratex;
static int hf_zbee_nwk_gp_cmd_move_color_ratey;

/* Move Up/Down command. */
static int hf_zbee_nwk_gp_cmd_move_up_down_rate;

/* Step Color command. */
static int hf_zbee_nwk_gp_cmd_step_color_stepx;
static int hf_zbee_nwk_gp_cmd_step_color_stepy;
static int hf_zbee_nwk_gp_cmd_step_color_transition_time;

/* Step Up/Down command. */
static int hf_zbee_nwk_gp_cmd_step_up_down_step_size;
static int hf_zbee_nwk_gp_cmd_step_up_down_transition_time;

static expert_field ei_zbee_nwk_gp_no_payload;
static expert_field ei_zbee_nwk_gp_inval_residual_data;
static expert_field ei_zbee_nwk_gp_com_rep_no_out_cnt;

/* Proto tree elements. */
static int ett_zbee_nwk;
static int ett_zbee_nwk_cmd;
static int ett_zbee_nwk_cmd_cinfo;
static int ett_zbee_nwk_cmd_appli_info;
static int ett_zbee_nwk_cmd_options;
static int ett_zbee_nwk_fcf;
static int ett_zbee_nwk_fcf_ext;
static int ett_zbee_nwk_clu_rec;
static int ett_zbee_nwk_att_rec;
static int ett_zbee_nwk_cmd_comm_gpd_cmd_id_list;
static int ett_zbee_nwk_cmd_comm_length_of_clid_list;
static int ett_zbee_nwk_cmd_comm_clid_list_server;
static int ett_zbee_nwk_cmd_comm_clid_list_client;

/* Common. */
static GSList *zbee_gp_keyring;
static unsigned num_uat_key_records;

typedef struct {
    char *string;
    uint8_t byte_order;
    char *label;
    uint8_t key[ZBEE_SEC_CONST_KEYSIZE];
} uat_key_record_t;

static const uint8_t empty_key[ZBEE_SEC_CONST_KEYSIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uat_key_record_t *gp_uat_key_records;
static uat_t *zbee_gp_sec_key_table_uat;

/* UAT. */
UAT_CSTRING_CB_DEF(gp_uat_key_records, string, uat_key_record_t)
UAT_VS_DEF(gp_uat_key_records, byte_order, uat_key_record_t, uint8_t, 0, "Normal")
UAT_CSTRING_CB_DEF(gp_uat_key_records, label, uat_key_record_t)

/****************/
/* Field names. */
/****************/

/* Byte order. */
static const value_string byte_order_vals[] = {
    { 0, "Normal"},
    { 1, "Reverse"},

    { 0, NULL }
};

/* Application ID names. */
static const value_string zbee_nwk_gp_app_id_names[] = {
    { ZBEE_NWK_GP_APP_ID_LPED, "LPED" },
    { ZBEE_NWK_GP_APP_ID_ZGP, "ZGP" },

    { 0, NULL }
};

/* Green Power commands. */

/* Abbreviations:
 * GPDF commands sent:
 *   From GPD w/o payload: "F "
 *   From GPD w   payload: "FP"
 *   To GPD:               "T "
 */

#define zbee_nwk_gp_cmd_names_VALUE_STRING_LIST(XXX) \
    XXX( /*F */ ZB_GP_CMD_ID_IDENTIFY                                 , 0x00, "Identify" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE0                            , 0x10, "Recall Scene 0" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE1                            , 0x11, "Recall Scene 1" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE2                            , 0x12, "Recall Scene 2" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE3                            , 0x13, "Recall Scene 3" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE4                            , 0x14, "Recall Scene 4" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE5                            , 0x15, "Recall Scene 5" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE6                            , 0x16, "Recall Scene 6" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RECALL_SCENE7                            , 0x17, "Recall Scene 7" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE0                             , 0x18, "Store Scene 0" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE1                             , 0x19, "Store Scene 1" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE2                             , 0x1A, "Store Scene 2" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE3                             , 0x1B, "Store Scene 3" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE4                             , 0x1C, "Store Scene 4" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE5                             , 0x1D, "Store Scene 5" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE6                             , 0x1E, "Store Scene 6" ) \
    XXX( /*F */ ZB_GP_CMD_ID_STORE_SCENE7                             , 0x1F, "Store Scene 7" ) \
    XXX( /*F */ ZB_GP_CMD_ID_OFF                                      , 0x20, "Off" ) \
    XXX( /*F */ ZB_GP_CMD_ID_ON                                       , 0x21, "On" ) \
    XXX( /*F */ ZB_GP_CMD_ID_TOGGLE                                   , 0x22, "Toggle" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RELEASE                                  , 0x23, "Release" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_UP                                  , 0x30, "Move Up" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_DOWN                                , 0x31, "Move Down" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_UP                                  , 0x32, "Step Up" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_DOWN                                , 0x33, "Step Down" ) \
    XXX( /*F */ ZB_GP_CMD_ID_LEVEL_CONTROL_STOP                       , 0x34, "Level Control/Stop" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_UP_WITH_ON_OFF                      , 0x35, "Move Up (with On/Off)" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_DOWN_WITH_ON_OFF                    , 0x36, "Move Down (with On/Off)" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_UP_WITH_ON_OFF                      , 0x37, "Step Up (with On/Off)" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_DOWN_WITH_ON_OFF                    , 0x38, "Step Down (with On/Off)" ) \
    XXX( /*F */ ZB_GP_CMD_ID_MOVE_HUE_STOP                            , 0x40, "Move Hue Stop" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_HUE_UP                              , 0x41, "Move Hue Up" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_HUE_DOWN                            , 0x42, "Move Hue Down" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_HUE_UP                              , 0x43, "Step Hue Up" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_HUW_DOWN                            , 0x44, "Step Hue Down" ) \
    XXX( /*F */ ZB_GP_CMD_ID_MOVE_SATURATION_STOP                     , 0x45, "Move Saturation Stop" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_SATURATION_UP                       , 0x46, "Move Saturation Up" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_SATURATION_DOWN                     , 0x47, "Move Saturation Down" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_SATURATION_UP                       , 0x48, "Step Saturation Up" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_SATURATION_DOWN                     , 0x49, "Step Saturation Down" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MOVE_COLOR                               , 0x4A, "Move Color" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_STEP_COLOR                               , 0x4B, "Step Color" ) \
    XXX( /*F */ ZB_GP_CMD_ID_LOCK_DOOR                                , 0x50, "Lock Door" ) \
    XXX( /*F */ ZB_GP_CMD_ID_UNLOCK_DOOR                              , 0x51, "Unlock Door" ) \
    XXX( /*F */ ZB_GP_CMD_ID_PRESS11                                  , 0x60, "Press 1 of 1" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RELEASE11                                , 0x61, "Release 1 of 1" ) \
    XXX( /*F */ ZB_GP_CMD_ID_PRESS12                                  , 0x62, "Press 1 of 2" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RELEASE12                                , 0x63, "Release 1 of 2" ) \
    XXX( /*F */ ZB_GP_CMD_ID_PRESS22                                  , 0x64, "Press 2 of 2" ) \
    XXX( /*F */ ZB_GP_CMD_ID_RELEASE22                                , 0x65, "Release 2 of 2" ) \
    XXX( /*F */ ZB_GP_CMD_ID_SHORT_PRESS11                            , 0x66, "Short press 1 of 1" ) \
    XXX( /*F */ ZB_GP_CMD_ID_SHORT_PRESS12                            , 0x67, "Short press 1 of 2" ) \
    XXX( /*F */ ZB_GP_CMD_ID_SHORT_PRESS22                            , 0x68, "Short press 2 of 2" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_ATTRIBUTE_REPORTING                      , 0xA0, "Attribute reporting" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MANUFACTURE_SPECIFIC_ATTR_REPORTING      , 0xA1, "Manufacturer-specific attribute reporting" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MULTI_CLUSTER_REPORTING                  , 0xA2, "Multi-cluster reporting" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_MANUFACTURER_SPECIFIC_MCLUSTER_REPORTING , 0xA3, "Manufacturer-specific multi-cluster reporting" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_REQUEST_ATTRIBUTES                       , 0xA4, "Request Attributes" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_READ_ATTRIBUTES_RESPONSE                 , 0xA5, "Read Attributes Response" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_ANY_SENSOR_COMMAND_A0_A3                 , 0xAF, "Any GPD sensor command (0xA0 - 0xA3)" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_COMMISSIONING                            , 0xE0, "Commissioning" ) \
    XXX( /*F */ ZB_GP_CMD_ID_DECOMMISSIONING                          , 0xE1, "Decommissioning" ) \
    XXX( /*F */ ZB_GP_CMD_ID_SUCCESS                                  , 0xE2, "Success" ) \
    XXX( /*FP*/ ZB_GP_CMD_ID_CHANNEL_REQUEST                          , 0xE3, "Channel Request" ) \
    XXX( /*T */ ZB_GP_CMD_ID_COMMISSIONING_REPLY                      , 0xF0, "Commissioning Reply" ) \
    XXX( /*T */ ZB_GP_CMD_ID_WRITE_ATTRIBUTES                         , 0xF1, "Write Attributes" ) \
    XXX( /*T */ ZB_GP_CMD_ID_READ_ATTRIBUTES                          , 0xF2, "Read Attributes" ) \
    XXX( /*T */ ZB_GP_CMD_ID_CHANNEL_CONFIGURATION                    , 0xF3, "Channel Configuration" )

VALUE_STRING_ENUM(zbee_nwk_gp_cmd_names);

VALUE_STRING_ARRAY(zbee_nwk_gp_cmd_names);
value_string_ext zbee_nwk_gp_cmd_names_ext = VALUE_STRING_EXT_INIT(zbee_nwk_gp_cmd_names);


/* Green Power devices. */
const value_string zbee_nwk_gp_device_ids_names[] = {

    /* GP GENERIC */
    { GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_1STATE_SWITCH,   "Generic: GP Simple Generic 1-state Switch" },
    { GPD_DEVICE_ID_GENERIC_GP_SIMPLE_GENERIC_2STATE_SWITCH,   "Generic: GP Simple Generic 2-state Switch" },
    { GPD_DEVICE_ID_GENERIC_GP_ON_OFF_SWITCH,                  "Generic: GP On/Off Switch" },
    { GPD_DEVICE_ID_GENERIC_GP_LEVEL_CONTROL_SWITCH,           "Generic: GP Level Control Switch" },
    { GPD_DEVICE_ID_GENERIC_GP_SIMPLE_SENSOR,                  "Generic: GP Simple Sensor" },
    { GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_1STATE_SWITCH, "Generic: GP Advanced Generic 1-state Switch" },
    { GPD_DEVICE_ID_GENERIC_GP_ADVANCED_GENERIC_2STATE_SWITCH, "Generic: GP Advanced Generic 2-state Switch" },

    /* GP LIGHTING */
    { GPD_DEVICE_ID_LIGHTING_GP_COLOR_DIMMER_SWITCH,           "Lighting: GP Color Dimmer Switch" },
    { GPD_DEVICE_ID_LIGHTING_GP_LIGHT_SENSOR,                  "Lighting: GP Light Sensor" },
    { GPD_DEVICE_ID_LIGHTING_GP_OCCUPANCY_SENSOR,              "Lighting: GP Occupancy Sensor" },

    /* GP CLOSURES */
    { GPD_DEVICE_ID_CLOSURES_GP_DOOR_LOCK_CONTROLLER,          "Closures: GP Door Lock Controller" },

    /* HVAC */
    { GPD_DEVICE_ID_HVAC_GP_TEMPERATURE_SENSOR,                "HVAC: GP Temperature Sensor" },
    { GPD_DEVICE_ID_HVAC_GP_PRESSURE_SENSOR,                   "HVAC: GP Pressure Sensor" },
    { GPD_DEVICE_ID_HVAC_GP_FLOW_SENSOR,                       "HVAC: GP Flow Sensor" },
    { GPD_DEVICE_ID_HVAC_GP_INDOOR_ENVIRONMENT_SENSOR,         "HVAC: GP Indoor Environment Sensor" },

    /* CUSTOM */
    { GPD_DEVICE_ID_MANUFACTURER_SPECIFIC,                     "Manufacturer Specific" },

    { 0, NULL }
};
static value_string_ext zbee_nwk_gp_device_ids_names_ext = VALUE_STRING_EXT_INIT(zbee_nwk_gp_device_ids_names);

/* GP directions. */
static const value_string zbee_nwk_gp_directions[] = {
    { ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD, "From ZGPD" },
    { ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPP, "From ZGPP" },

    { 0, NULL }
};

/* Frame types for Green Power profile. */
static const value_string zbee_nwk_gp_frame_types[] = {
    { ZBEE_NWK_GP_FCF_DATA,        "Data" },
    { ZBEE_NWK_GP_FCF_MAINTENANCE, "Maintenance" },

    { 0, NULL }
};

/* GreenPeak Green Power devices. */
static const value_string zbee_nwk_gp_manufacturer_greenpeak_dev_names[] = {
    { ZBEE_NWK_GP_MANUF_GREENPEAK_IZDS,  "IAS Zone Door Sensor" },
    { ZBEE_NWK_GP_MANUF_GREENPEAK_IZDWS, "IAS Zone Door/Window Sensor" },
    { ZBEE_NWK_GP_MANUF_GREENPEAK_IZLS,  "IAS Zone Leakage Sensor" },
    { ZBEE_NWK_GP_MANUF_GREENPEAK_IZRHS, "IAS Zone Relative Humidity Sensor" },

    { 0, NULL }
};

/* GP Src ID names. */
static const value_string zbee_nwk_gp_src_id_names[] = {
    { ZBEE_NWK_GP_ZGPD_SRCID_ALL,     "All" },
    { ZBEE_NWK_GP_ZGPD_SRCID_UNKNOWN, "Unspecified" },

    { 0, NULL }
};

/* GP security key type names. */
static const value_string zbee_nwk_gp_src_sec_keys_type_names[] = {
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_DERIVED_INDIVIDUAL_GPD_KEY,        "Derived individual GPD key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_GPD_GROUP_KEY,                     "GPD group key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_NO_KEY,                            "No key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_NWK_KEY_DERIVED_GPD_KEY_GROUP_KEY, "NWK key derived GPD group key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_PRECONFIGURED_INDIVIDUAL_GPD_KEY,  "Individual, out of the box GPD key" },
    { ZBEE_NWK_GP_SECURITY_KEY_TYPE_ZB_NWK_KEY,                        "ZigBee NWK key" },

    { 0, NULL }
};

/* GP security levels. */
static const value_string zbee_nwk_gp_src_sec_levels_names[] = {
    { ZBEE_NWK_GP_SECURITY_LEVEL_1LSB,     "1 LSB of frame counter and short MIC only" },
    { ZBEE_NWK_GP_SECURITY_LEVEL_FULL,     "Full frame counter and full MIC only" },
    { ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR, "Encryption with full frame counter and full MIC" },
    { ZBEE_NWK_GP_SECURITY_LEVEL_NO,       "No security" },

    { 0, NULL }
};

/*************************/
/* Function definitions. */
/*************************/

/* UAT record copy callback. */
static void *
uat_key_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_key_record_t *new_key = (uat_key_record_t *)n;
    const uat_key_record_t *old_key = (const uat_key_record_t *)o;

    new_key->string = g_strdup(old_key->string);
    new_key->label = g_strdup(old_key->label);

    return new_key;
}

/* UAT record free callback. */
static void
uat_key_record_free_cb(void *r)
{
    uat_key_record_t *key = (uat_key_record_t *)r;
    g_free(key->string);
    g_free(key->label);
}

/**
 *Parses a key string from left to right into a buffer with increasing (normal byte order) or decreasing (reverse
 *
 *@param key_str pointer to the string
 *@param key_buf destination buffer in memory
 *@param byte_order byte order
*/
static bool
zbee_gp_security_parse_key(const char *key_str, uint8_t *key_buf, bool byte_order)
{
    bool string_mode = false;
    char temp;
    int i, j;

    memset(key_buf, 0, ZBEE_SEC_CONST_KEYSIZE);
    if (key_str == NULL) {
        return false;
    }
    if ((temp = *key_str++) == '"') {
        string_mode = true;
        temp = *key_str++;
    }
    j = byte_order ? ZBEE_SEC_CONST_KEYSIZE - 1 : 0;
    for (i = ZBEE_SEC_CONST_KEYSIZE - 1; i >= 0; i--) {
        if (string_mode) {
            if (g_ascii_isprint(temp)) {
                key_buf[j] = temp;
                temp = *key_str++;
            } else {
                return false;
            }
        } else {
            if ((temp == ':') || (temp == '-') || (temp == ' ')) {
                temp = *(key_str++);
            }
            if (g_ascii_isxdigit(temp)) {
                key_buf[j] = g_ascii_xdigit_value(temp) << 4;
            } else {
                return false;
            }
            temp = *(key_str++);
            if (g_ascii_isxdigit(temp)) {
                key_buf[j] |= g_ascii_xdigit_value(temp);
            } else {
                return false;
            }
            temp = *(key_str++);
        }
        if (byte_order) {
            j--;
        } else {
            j++;
        }
    }
    return true;
}

/* UAT record update callback. */
static bool
uat_key_record_update_cb(void *r, char **err)
{
    uat_key_record_t *rec = (uat_key_record_t *)r;

    if (rec->string == NULL) {
         *err = g_strdup("Key can't be blank.");
         return false;
    } else {
        g_strstrip(rec->string);
        if (rec->string[0] != 0) {
            *err = NULL;
            if (!zbee_gp_security_parse_key(rec->string, rec->key, rec->byte_order)) {
                *err = ws_strdup_printf("Expecting %d hexadecimal bytes or a %d character double-quoted string",
                    ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
                return false;
            }
        } else {
            *err = g_strdup("Key can't be blank.");
            return false;
        }
    }
    return true;
}

static void uat_key_record_post_update_cb(void) {
    unsigned i;

    for (i = 0; i < num_uat_key_records; i++) {
        if (memcmp(gp_uat_key_records[i].key, empty_key, ZBEE_SEC_CONST_KEYSIZE) == 0) {
            /* key was not loaded from string yet */
            zbee_gp_security_parse_key(gp_uat_key_records[i].string, gp_uat_key_records[i].key,
                                       gp_uat_key_records[i].byte_order);
        }
    }
}

/**
 *Fills in ZigBee GP security nonce from the provided packet structure.
 *
 *@param packet ZigBee NWK packet.
 *@param nonce nonce buffer.
*/
static void
zbee_gp_make_nonce(zbee_nwk_green_power_packet *packet, char *nonce)
{
    memset(nonce, 0, ZBEE_SEC_CONST_NONCE_LEN);

    /* Source address */
    if (packet->application_id == ZBEE_NWK_GP_APP_ID_DEFAULT)
    {
        if (packet->direction == ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD) {
            phtole32(nonce, packet->source_id);
        }
        phtole32(nonce+4, packet->source_id);
    }
    else if (packet->application_id == ZBEE_NWK_GP_APP_ID_ZGP)
    {
        phtole64(nonce, packet->ieee_packet_src64);
    }

    /* Frame counter */
    phtole32(nonce+8, packet->security_frame_counter);

    /* Security control */
    if ((packet->application_id == ZBEE_NWK_GP_APP_ID_ZGP) &&
        (packet->direction != ZBEE_NWK_GP_FC_EXT_DIRECTION_FROM_ZGPD)) {
        nonce[12] = (char)0xc5;    /* Security level = 0b101, Key Identifier = 0x00,
                                        Extended nonce = 0b0, Reserved = 0b00 */
    } else {
        nonce[12] = (char)0x05;    /* Security level = 0b101, Key Identifier = 0x00,
                                        Extended nonce = 0b0, Reserved = 0b11 */
    }
}

/**
 *Creates a nonce and decrypts secured ZigBee GP payload.
 *
 *@param packet ZigBee NWK packet.
 *@param enc_buffer encoded payload buffer.
 *@param offset payload offset.
 *@param dec_buffer decoded payload buffer.
 *@param payload_len payload length.
 *@param mic_len MIC length.
 *@param key key.
*/
static bool
zbee_gp_decrypt_payload(zbee_nwk_green_power_packet *packet, const char *enc_buffer, const char offset, uint8_t
    *dec_buffer, unsigned payload_len, unsigned mic_len, uint8_t *key)
{
    uint8_t *key_buffer = key;
    uint8_t nonce[ZBEE_SEC_CONST_NONCE_LEN];

    zbee_gp_make_nonce(packet, nonce);
    if (zbee_sec_ccm_decrypt(key_buffer, nonce, enc_buffer, enc_buffer + offset, dec_buffer, offset, payload_len,
        mic_len)) {
        return true;
    }

    return false;
}

/**
 *Dissector for ZigBee Green Power commissioning.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_commissioning(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    zbee_nwk_green_power_packet *packet, unsigned offset)
{
    uint8_t comm_options;
    uint8_t comm_ext_options = 0;
    uint8_t appli_info_options = 0;
    uint16_t manufacturer_id = 0;

    uint8_t i;
    uint8_t gpd_cmd_num = 0;
    proto_item *gpd_cmd_list;
    proto_tree *gpd_cmd_list_tree;

    uint8_t length_of_clid_list_bm;
    uint8_t server_clid_num;
    uint8_t client_clid_num;
    proto_item *server_clid_list, *client_clid_list;
    proto_tree *server_clid_list_tree, *client_clid_list_tree;

    void *enc_buffer;
    uint8_t *enc_buffer_withA;
    uint8_t *dec_buffer;
    bool gp_decrypted;
    GSList *GSList_i;
    tvbuff_t *payload_tvb;

    static int * const options[] = {
        &hf_zbee_nwk_gp_cmd_comm_opt_mac_sec_num_cap,
        &hf_zbee_nwk_gp_cmd_comm_opt_rx_on_cap,
        &hf_zbee_nwk_gp_cmd_comm_opt_appli_info_present,
        &hf_zbee_nwk_gp_cmd_comm_opt_panid_req,
        &hf_zbee_nwk_gp_cmd_comm_opt_sec_key_req,
        &hf_zbee_nwk_gp_cmd_comm_opt_fixed_location,
        &hf_zbee_nwk_gp_cmd_comm_opt_ext_opt,
        NULL
    };
    static int * const ext_options[] = {
        &hf_zbee_nwk_gp_cmd_comm_ext_opt_sec_level_cap,
        &hf_zbee_nwk_gp_cmd_comm_ext_opt_key_type,
        &hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_present,
        &hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_encr,
        &hf_zbee_nwk_gp_cmd_comm_ext_opt_outgoing_counter,
        NULL
    };
    static int * const appli_info[] = {
        &hf_zbee_nwk_gp_cmd_comm_appli_info_mip,
        &hf_zbee_nwk_gp_cmd_comm_appli_info_mmip,
        &hf_zbee_nwk_gp_cmd_comm_appli_info_gclp,
        &hf_zbee_nwk_gp_cmd_comm_appli_info_crp,
        NULL
    };
    static int * const length_of_clid_list[] = {
        &hf_zbee_nwk_gp_cmd_comm_length_of_clid_list_server,
        &hf_zbee_nwk_gp_cmd_comm_length_of_clid_list_client,
        NULL
    };

    /* Get Device ID and display it. */
    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_device_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* Get Options Field, build subtree and display the results. */
    comm_options = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_comm_opt, ett_zbee_nwk_cmd_options, options, ENC_NA);
    offset += 1;

    if (comm_options & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_EXT_OPTIONS) {
        /* Get extended Options Field, build subtree and display the results. */
        comm_ext_options = tvb_get_uint8(tvb, offset);
        proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_comm_ext_opt, ett_zbee_nwk_cmd_options, ext_options, ENC_NA);
        offset += 1;
        if (comm_ext_options & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_PRESENT) {
            /* Get security key and display it. */
            proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_security_key, tvb, offset, ZBEE_SEC_CONST_KEYSIZE, ENC_NA);
            offset += ZBEE_SEC_CONST_KEYSIZE;

            /* Key is encrypted */
            if (comm_ext_options & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_ENCR) {
                /* Get Security MIC and display it. */
                proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                if (packet != NULL)
                {
                    /* Decrypt the security key */
                    dec_buffer = (uint8_t *)wmem_alloc(pinfo->pool, ZBEE_SEC_CONST_KEYSIZE);
                    enc_buffer_withA = (uint8_t *)wmem_alloc(pinfo->pool, 4 + ZBEE_SEC_CONST_KEYSIZE + 4); /* CCM* a (this is SrcID) + encKey + MIC */
                    enc_buffer = tvb_memdup(pinfo->pool, tvb, offset - ZBEE_SEC_CONST_KEYSIZE - 4, ZBEE_SEC_CONST_KEYSIZE + 4);
                    phtole32(enc_buffer_withA, packet->source_id);
                    memcpy(enc_buffer_withA+4, enc_buffer, ZBEE_SEC_CONST_KEYSIZE + 4);
                    gp_decrypted = false;

                    for (GSList_i = zbee_gp_keyring; GSList_i && !gp_decrypted; GSList_i = g_slist_next(GSList_i)) {
                        packet->security_frame_counter = packet->source_id; /* for Nonce creation*/
                        gp_decrypted = zbee_gp_decrypt_payload(packet, enc_buffer_withA, 4
                            , dec_buffer, ZBEE_SEC_CONST_KEYSIZE, 4, ((key_record_t *)(GSList_i->data))->key);
                    }

                    if (gp_decrypted) {
                        key_record_t key_record;

                        key_record.frame_num = 0;
                        key_record.label = NULL;
                        memcpy(key_record.key, dec_buffer, ZBEE_SEC_CONST_KEYSIZE);
                        zbee_gp_keyring = g_slist_prepend(zbee_gp_keyring, g_memdup2(&key_record, sizeof(key_record_t)));

                        payload_tvb = tvb_new_child_real_data(tvb, dec_buffer, ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
                        add_new_data_source(pinfo, payload_tvb, "Decrypted security key");
                    }
                }
            }
            else
            {
                key_record_t key_record;
                void *key;

                key_record.frame_num = 0;
                key_record.label = NULL;
                key = tvb_memdup(pinfo->pool, tvb, offset - ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
                memcpy(key_record.key, key, ZBEE_SEC_CONST_KEYSIZE);
                zbee_gp_keyring = g_slist_prepend(zbee_gp_keyring, g_memdup2(&key_record, sizeof(key_record_t)));
            }
        }

        if (comm_ext_options & ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_OUT_COUNTER) {
            /* Get GPD Outgoing Frame Counter and display it. */
            proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_outgoing_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
        }
    }
    /* Display manufacturer specific data. */
    if (comm_options & ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_APPLICATION_INFO) {
        /* Display application information. */
        appli_info_options = tvb_get_uint8(tvb, offset);
        proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_comm_appli_info, ett_zbee_nwk_cmd_appli_info, appli_info, ENC_NA);
        offset += 1;
        if (appli_info_options & ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_MIP) {
            /* Get Manufacturer ID. */
            manufacturer_id = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_manufacturer_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
        }
        if (appli_info_options & ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_MMIP) {
            /* Get Manufacturer Device ID. */
            switch (manufacturer_id) {
                case ZBEE_NWK_GP_MANUF_ID_GREENPEAK:
                    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_manufacturer_greenpeak_dev_id, tvb, offset, 2,
                        ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;
                default:
                    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_manufacturer_dev_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;
            }
        }
        if (appli_info_options & ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_GCLP) {
            /* Get and display number of GPD commands */
            gpd_cmd_num = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_gpd_cmd_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            /* Display GPD command list */
            if (gpd_cmd_num > 0) {
                gpd_cmd_list = proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_gpd_cmd_id_list,
                    tvb, offset, gpd_cmd_num, ENC_NA);
                gpd_cmd_list_tree = proto_item_add_subtree(gpd_cmd_list, ett_zbee_nwk_cmd_comm_gpd_cmd_id_list);
                for (i = 0; i < gpd_cmd_num; i++, offset++) {
                    /* Display command id */
                    proto_tree_add_item(gpd_cmd_list_tree, hf_zbee_nwk_gp_command_id,
                        tvb, offset, 1, ENC_LITTLE_ENDIAN);
                }
            }
        }
        if (appli_info_options & ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_CRP) {
            /* Get and display Cluster List */
            length_of_clid_list_bm = tvb_get_uint8(tvb, offset);
            server_clid_num = (length_of_clid_list_bm & ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_SRV) >>
                ws_ctz(ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_SRV);
            client_clid_num = (length_of_clid_list_bm & ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_CLI ) >>
                ws_ctz(ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_CLI);

            proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_comm_length_of_clid_list,
                ett_zbee_nwk_cmd_comm_length_of_clid_list, length_of_clid_list, ENC_NA);
            offset += 1;

            if (server_clid_num > 0) {
                /* Display server cluster list */
                server_clid_list = proto_tree_add_item(tree, hf_zbee_nwk_cmd_comm_clid_list_server,
                    tvb, offset, 2*server_clid_num, ENC_NA);
                server_clid_list_tree = proto_item_add_subtree(server_clid_list, ett_zbee_nwk_cmd_comm_clid_list_server);
                /* Retrieve server clusters */
                for (i = 0; i < server_clid_num; i++, offset += 2) {
                    proto_tree_add_item(server_clid_list_tree, hf_zbee_nwk_cmd_comm_cluster_id,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
            }
            if (client_clid_num > 0) {
                /* Display client cluster list */
                client_clid_list = proto_tree_add_item(tree, hf_zbee_nwk_cmd_comm_clid_list_client,
                    tvb, offset, 2*client_clid_num, ENC_NA);
                client_clid_list_tree = proto_item_add_subtree(client_clid_list, ett_zbee_nwk_cmd_comm_clid_list_client);
                /* Retrieve client clusters */
                for (i = 0; i < client_clid_num; i++, offset += 2) {
                    proto_tree_add_item(client_clid_list_tree, hf_zbee_nwk_cmd_comm_cluster_id,
                        tvb, offset, 2, ENC_LITTLE_ENDIAN);
                }
            }
        }
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_commissioning */

/**
 *Dissector for ZigBee Green Power channel request.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_channel_request(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    static int * const channels[] = {
        &hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_1st,
        &hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_2nd,
        NULL
    };

    /* Get Command Options Field, build subtree and display the results. */
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour, ett_zbee_nwk_cmd_options, channels, ENC_NA);
    offset += 1;
    return offset;
} /* dissect_zbee_nwk_gp_cmd_channel_request */

/**
 *Dissector for ZigBee Green Power channel configuration.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_channel_configuration(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    static int * const channels[] = {
        &hf_zbee_nwk_gp_cmd_channel_configuration,
        NULL
    };

    /* Get Command Options Field, build subtree and display the results. */
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_operational_channel, ett_zbee_nwk_cmd_options, channels, ENC_NA);

    offset += 1;
    return offset;
} /* dissect_zbee_nwk_gp_cmd_channel_configuration */

/**
 *Dissector for ZigBee Green Power commands attrib reporting.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@param mfr_code manufacturer code.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_attr_reporting(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset, uint16_t mfr_code)
{
    uint16_t cluster_id;
    proto_tree *field_tree;

    /* Get cluster ID and add it into the tree. */
    cluster_id = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_zbee_nwk_gp_zcl_attr_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);

    offset += 2;
    /* Create subtree and parse ZCL Write Attribute Payload. */
    field_tree = proto_tree_add_subtree_format(tree, tvb, offset, 2, ett_zbee_nwk_cmd_options, NULL,
                                "Attribute reporting command for cluster: 0x%04X", cluster_id);

    dissect_zcl_report_attr(tvb, pinfo, field_tree, &offset, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);

    return offset;
} /* dissect_zbee_nwk_gp_cmd_attr_reporting */


/**
 *      Dissector for ZigBee Green Power manufacturer specific attribute reporting.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
 */
static unsigned
dissect_zbee_nwk_gp_cmd_MS_attr_reporting(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    uint16_t mfr_code;

    /*dissect manufacturer ID*/
    proto_tree_add_item(tree, hf_zbee_zcl_gp_cmd_ms_manufacturer_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    mfr_code = tvb_get_letohs(tvb, offset);
    offset += 2;

    offset = dissect_zbee_nwk_gp_cmd_attr_reporting(tvb, pinfo, tree, packet, offset, mfr_code);

    return offset;
}/*dissect_zbee_nwk_gp_cmd_MS_attr_reporting*/




/**
 *Dissector for ZigBee Green Power commissioning reply.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_commissioning_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    zbee_nwk_green_power_packet *packet, unsigned offset)
{
    uint8_t cr_options;
    uint8_t cr_sec_level;

    void *enc_buffer;
    uint8_t *enc_buffer_withA;
    uint8_t *dec_buffer;
    bool gp_decrypted;
    GSList *GSList_i;
    tvbuff_t *payload_tvb;

    static int * const options[] = {
        &hf_zbee_nwk_gp_cmd_comm_rep_opt_panid_present,
        &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_key_present,
        &hf_zbee_nwk_gp_cmd_comm_rep_opt_key_encr,
        &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_level,
        &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_type,
        NULL
    };

    /* Get Options Field, build subtree and display the results. */
    cr_options = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_comm_rep_opt, ett_zbee_nwk_cmd_options, options, ENC_NA);
    offset += 1;

    /* Parse and display security Pan ID value. */
    if (cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_PAN_ID_PRESENT) {
        proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_rep_pan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }

    cr_sec_level = (cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL) >>
        ws_ctz(ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL);

    /* Parse and display security key. */
    if (cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT) {
        proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_security_key, tvb, offset, ZBEE_SEC_CONST_KEYSIZE, ENC_NA);
        offset += ZBEE_SEC_CONST_KEYSIZE;

        /* Key is present clear, add to the key ring */
        if (!(cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR)) {
            key_record_t key_record;
            void *key;

            key_record.frame_num = 0;
            key_record.label = NULL;
            key = tvb_memdup(pinfo->pool, tvb, offset - ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
            memcpy(key_record.key, key, ZBEE_SEC_CONST_KEYSIZE);
            zbee_gp_keyring = g_slist_prepend(zbee_gp_keyring, g_memdup2(&key_record, sizeof(key_record_t)));
        }
    }
    /* Parse and display security MIC. */
    if ((cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR) &&
        (cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT)) {
        proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
    }

    /* Parse and display Frame Counter and decrypt key */
    if ((cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR) &&
        (cr_options & ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT) &&
        ((cr_sec_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULL) ||
        (cr_sec_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR))) {
        if (offset + 4 <= tvb_captured_length(tvb)){
            proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_comm_rep_frame_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            if (packet != NULL)
            {
                /* decrypt the security key*/
                dec_buffer = (uint8_t *)wmem_alloc(pinfo->pool, ZBEE_SEC_CONST_KEYSIZE);
                enc_buffer_withA = (uint8_t *)wmem_alloc(pinfo->pool, 4 + ZBEE_SEC_CONST_KEYSIZE + 4); /* CCM* a (this is SrcID) + encKey + MIC */
                enc_buffer = tvb_memdup(pinfo->pool, tvb, offset - ZBEE_SEC_CONST_KEYSIZE - 4 - 4, ZBEE_SEC_CONST_KEYSIZE + 4);
                phtole32(enc_buffer_withA, packet->source_id); /* enc_buffer_withA = CCM* a (srcID) | enc_buffer */
                memcpy(enc_buffer_withA+4, enc_buffer, ZBEE_SEC_CONST_KEYSIZE + 4);
                gp_decrypted = false;

                for (GSList_i = zbee_gp_keyring; GSList_i && !gp_decrypted; GSList_i = g_slist_next(GSList_i)) {
                    packet->security_frame_counter = tvb_get_uint32(tvb, offset - 4, ENC_LITTLE_ENDIAN); /*for Nonce creation */
                    gp_decrypted = zbee_gp_decrypt_payload(packet, enc_buffer_withA, 4
                        , dec_buffer, ZBEE_SEC_CONST_KEYSIZE, 4, ((key_record_t *)(GSList_i->data))->key);
                }

                if (gp_decrypted) {
                    key_record_t key_record;

                    key_record.frame_num = 0;
                    key_record.label = NULL;
                    memcpy(key_record.key, dec_buffer, ZBEE_SEC_CONST_KEYSIZE);
                    zbee_gp_keyring = g_slist_prepend(zbee_gp_keyring, g_memdup2(&key_record, sizeof(key_record_t)));

                    payload_tvb = tvb_new_child_real_data(tvb, dec_buffer, ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
                    add_new_data_source(pinfo, payload_tvb, "Decrypted security key");
                }
            }
        }
        else{
            /* This field is new in 2016 specification, older implementation may exist without it */
            proto_tree_add_expert(tree, pinfo, &ei_zbee_nwk_gp_com_rep_no_out_cnt, tvb, 0, -1);
        }
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_commissioning_reply */

/**
 * Dissector for ZigBee Green Power read attributes and request attributes commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
 */
static unsigned
dissect_zbee_nwk_gp_cmd_read_attributes(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    uint8_t cr_options = 0;
    proto_tree *subtree = NULL;
    uint16_t cluster_id;
    uint16_t mfr_code = ZBEE_MFG_CODE_NONE;
    uint8_t record_list_len;
    unsigned tvb_len;
    uint8_t i;

    static int * const options[] = {
        &hf_zbee_nwk_gp_cmd_read_att_opt_multi_rec,
        &hf_zbee_nwk_gp_cmd_read_att_opt_man_field_present,
        NULL
    };

    /* Get Options Field, build subtree and display the results. */
    cr_options = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_read_att_opt, ett_zbee_nwk_cmd_options, options, ENC_NA);

    offset += 1;
    /* Parse and display manufacturer ID value. */
    if (cr_options & ZBEE_NWK_GP_CMD_READ_ATTRIBUTE_OPT_MAN_FIELD_PRESENT) {
        proto_tree_add_item(tree, hf_zbee_zcl_gp_cmd_ms_manufacturer_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        mfr_code = tvb_get_letohs(tvb, offset);
        offset += 2;
    }

    tvb_len = tvb_captured_length(tvb);
    while (offset < tvb_len)
    {
        /* Create subtree and parse attributes list. */
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_zbee_nwk_clu_rec, NULL, "Cluster Record Request");

        /* Get cluster ID and add it into the subtree. */
        cluster_id = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(subtree, hf_zbee_nwk_gp_zcl_attr_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        /* Get length of record list (number of attributes * 2). */
        record_list_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(subtree, hf_zbee_nwk_gp_cmd_read_att_record_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        for(i=0 ; i<record_list_len ; i+=2)
        {
            /* Dissect the attribute identifier */
            dissect_zcl_attr_id(tvb, subtree, &offset, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);
        }
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_read_attributes */
/**
 * Dissector for ZigBee Green Power write attributes commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
 */
static unsigned
dissect_zbee_nwk_gp_cmd_write_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    uint8_t cr_options = 0;
    proto_tree *subtree = NULL;
    proto_tree *att_tree = NULL;
    uint16_t mfr_code = ZBEE_MFG_CODE_NONE;
    uint16_t cluster_id;
    uint8_t record_list_len;
    unsigned tvb_len;
    uint16_t attr_id;
    unsigned end_byte;
    //uint8_t i;

    static int * const options[] = {
        &hf_zbee_nwk_gp_cmd_read_att_opt_multi_rec,
        &hf_zbee_nwk_gp_cmd_read_att_opt_man_field_present,
        NULL
    };

    /* Get Options Field, build subtree and display the results. */
    cr_options = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_read_att_opt, ett_zbee_nwk_cmd_options, options, ENC_NA);

    offset += 1;
    /* Parse and display manufacturer ID value. */
    if (cr_options & ZBEE_NWK_GP_CMD_READ_ATTRIBUTE_OPT_MAN_FIELD_PRESENT) {
        proto_tree_add_item(tree, hf_zbee_zcl_gp_cmd_ms_manufacturer_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        mfr_code = tvb_get_letohs(tvb, offset);
        offset += 2;
    }

    tvb_len = tvb_captured_length(tvb);
    while (offset < tvb_len)
    {
        /* Create subtree and parse attributes list. */
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_zbee_nwk_clu_rec, NULL, "Write Cluster Record");

        /* Get cluster ID and add it into the subtree. */
        cluster_id = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(subtree, hf_zbee_nwk_gp_zcl_attr_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        /* Get length of record list. */
        record_list_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(subtree, hf_zbee_nwk_gp_cmd_read_att_record_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        end_byte = offset + record_list_len;
        while ( offset < end_byte)
        {
            /* Create subtree for attribute status field */
            att_tree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_zbee_nwk_att_rec, NULL, "Write Attribute record");

            /* Dissect the attribute identifier */
            attr_id = tvb_get_letohs(tvb, offset);
            dissect_zcl_attr_id(tvb, att_tree, &offset, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);

            /* Dissect the attribute data type and data */
            dissect_zcl_attr_data_type_val(tvb, pinfo, att_tree, &offset, attr_id, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);
        }
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_write_attributes */


/**
 * Dissector for ZigBee Green Power read attribute response command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
 */
static unsigned
dissect_zbee_nwk_gp_cmd_read_attributes_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    uint8_t cr_options;
    proto_tree *subtree = NULL;
    proto_tree *att_tree = NULL;
    uint16_t cluster_id;
    uint16_t attr_id;
    uint16_t mfr_code = ZBEE_MFG_CODE_NONE;
    uint8_t record_list_len;
    unsigned tvb_len;
    unsigned end_byte;

    static int * const options[] = {
        &hf_zbee_nwk_gp_cmd_read_att_opt_multi_rec,
        &hf_zbee_nwk_gp_cmd_read_att_opt_man_field_present,
        NULL
    };

    /* Get Options Field, build subtree and display the results. */
    cr_options = tvb_get_uint8(tvb, offset);
    proto_tree_add_bitmask(tree, tvb, offset, hf_zbee_nwk_gp_cmd_read_att_opt, ett_zbee_nwk_cmd_options, options, ENC_NA);
    offset += 1;

    /* Parse and display manufacturer ID value. */
    if (cr_options & ZBEE_NWK_GP_CMD_READ_ATTRIBUTE_OPT_MAN_FIELD_PRESENT) {
        proto_tree_add_item(tree, hf_zbee_zcl_gp_cmd_ms_manufacturer_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        mfr_code = tvb_get_letohs(tvb, offset);
        offset += 2;
    }

    tvb_len = tvb_captured_length(tvb);
    while (offset < tvb_len)
    {
        /* Create subtree and parse attributes list. */
        subtree = proto_tree_add_subtree_format(tree, tvb, offset,0, ett_zbee_nwk_clu_rec, NULL, "Cluster record");

        /* Get cluster ID and add it into the subtree. */
        cluster_id = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(subtree, hf_zbee_nwk_gp_zcl_attr_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        /* Get length of record list in bytes. */
        record_list_len = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(subtree, hf_zbee_nwk_gp_cmd_read_att_record_len, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;

        end_byte = offset + record_list_len;
        while ( offset < end_byte)
        {
            /* Create subtree for attribute status field */
            /* TODO ett_ could be an array to permit not to unroll all always */
            att_tree = proto_tree_add_subtree_format(subtree, tvb, offset, 0, ett_zbee_nwk_att_rec, NULL, "Read Attribute record");

            /* Dissect the attribute identifier */
            attr_id = tvb_get_letohs(tvb, offset);
            dissect_zcl_attr_id(tvb, att_tree, &offset, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);

            /* Dissect the status and optionally the data type and value */
            if (dissect_zcl_attr_uint8(tvb, att_tree, &offset, &hf_zbee_nwk_gp_zcl_attr_status)
                == ZBEE_ZCL_STAT_SUCCESS)
            {
                /* Dissect the attribute data type and data */
                dissect_zcl_attr_data_type_val(tvb, pinfo, att_tree, &offset, attr_id, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);
            }
            else
            {
                /* Data type field is always present (not like in ZCL read attribute response command) */
                dissect_zcl_attr_data(tvb, pinfo, att_tree, &offset,
                    dissect_zcl_attr_uint8(tvb, att_tree, &offset, &hf_zbee_nwk_gp_zcl_attr_data_type), ZBEE_ZCL_FCF_TO_CLIENT );
            }
        }
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_read_attributes_response */


/**
 *Dissector for ZigBee Green Power multi-cluster reporting command.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@param mfr_code manufacturer code.
 *@return payload processed offset.
 */
static unsigned
dissect_zbee_nwk_gp_cmd_multi_cluster_reporting(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset, uint16_t mfr_code)
{
    proto_tree *subtree = NULL;
    uint16_t cluster_id;
    uint16_t attr_id;
    unsigned tvb_len;

    tvb_len = tvb_captured_length(tvb);
    while (offset < tvb_len)
    {
        /* Create subtree and parse attributes list. */
        subtree = proto_tree_add_subtree_format(tree, tvb, offset, 0, ett_zbee_nwk_clu_rec, NULL, "Cluster record"); //TODO for cluster %% blabla

        /* Get cluster ID and add it into the subtree. */
        cluster_id = tvb_get_letohs(tvb, offset);
        proto_tree_add_item(subtree, hf_zbee_nwk_gp_zcl_attr_cluster_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        /* Dissect the attribute identifier */
        attr_id = tvb_get_letohs(tvb, offset);
        dissect_zcl_attr_id(tvb, subtree, &offset, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);

        /* Dissect the attribute data type and data */
        dissect_zcl_attr_data_type_val(tvb, pinfo, subtree, &offset, attr_id, cluster_id, mfr_code, ZBEE_ZCL_FCF_TO_CLIENT);
        // TODO how to dissect when data type is different from expected one for this attribute ? this shouldn't happen
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_multi_cluster_reporting */


/**
 *Dissector for ZigBee Green Power commands manufacturer specific attrib reporting.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
 */
static unsigned
dissect_zbee_nwk_gp_cmd_MS_multi_cluster_reporting(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    uint16_t mfr_code;

    /*dissect manufacturer ID*/
    proto_tree_add_item(tree, hf_zbee_zcl_gp_cmd_ms_manufacturer_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    mfr_code = tvb_get_letohs(tvb, offset);
    offset += 2;

    offset = dissect_zbee_nwk_gp_cmd_multi_cluster_reporting(tvb, pinfo, tree, packet, offset, mfr_code);

    return offset;
}/*dissect_zbee_nwk_gp_cmd_MS_multi_cluster_reporting*/

/**
 *Dissector for ZigBee Green Power Move Color.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_move_color(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_move_color_ratex, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_move_color_ratey, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    return offset;
} /* dissect_zbee_nwk_gp_cmd_move_color */

/**
 *Dissector for ZigBee Green Power Move Up/Down.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_move_up_down(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    /* Optional rate field. */
    if (tvb_reported_length(tvb) - offset >= 1) {
        proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_move_up_down_rate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_move_up_down */

/**
 *Dissector for ZigBee Green Power Step Color.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_step_color(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_step_color_stepx, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_step_color_stepy, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    /* Optional time field. */
    if (tvb_reported_length(tvb) - offset >= 2) {
        proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_step_color_transition_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_step_color */

/**
 *Dissector for ZigBee Green Power Step Up/Down.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param packet packet data.
 *@param offset current payload offset.
 *@return payload processed offset.
*/
static unsigned
dissect_zbee_nwk_gp_cmd_step_up_down(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
    zbee_nwk_green_power_packet *packet _U_, unsigned offset)
{
    proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_step_up_down_step_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    /* Optional time field. */
    if (tvb_reported_length(tvb) - offset >= 2) {
        proto_tree_add_item(tree, hf_zbee_nwk_gp_cmd_step_up_down_transition_time, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd_step_up_down */

/**
 *Dissector for ZigBee Green Power commands.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param data raw packet private data.
 *@return payload processed offset
*/
static int
dissect_zbee_nwk_gp_cmd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    unsigned offset = 0;
    uint8_t cmd_id = tvb_get_uint8(tvb, offset);
    proto_item *cmd_root;
    proto_tree *cmd_tree;
    zbee_nwk_green_power_packet *packet = (zbee_nwk_green_power_packet *)data;

    /* Create a subtree for the command. */
    cmd_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_zbee_nwk_cmd, &cmd_root,
                                        "Command Frame: %s", val_to_str_ext_const(cmd_id,
                                                            &zbee_nwk_gp_cmd_names_ext,
                                                            "Unknown Command Frame"));
    /* Add the command ID. */
    proto_tree_add_uint(cmd_tree, hf_zbee_nwk_gp_command_id, tvb, offset, 1, cmd_id);

    offset += 1;
    /* Add the command name to the info column. */
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(cmd_id, &zbee_nwk_gp_cmd_names_ext, "Unknown command"));
    /* Handle the command for one of the following devices:
     * - Door Lock Controller (IDs: 0x50 - 0x51);
     * - GP Flow Sensor (IDs: 0xE0, 0xA0 - 0xA3);
     * - GP Temperature Sensor (IDs: 0xE0, 0xA0 - 0xA3); */
    switch(cmd_id) {
        /* Payloadless GPDF commands sent by GPD. */
        case ZB_GP_CMD_ID_IDENTIFY:
        case ZB_GP_CMD_ID_RECALL_SCENE0:
        case ZB_GP_CMD_ID_RECALL_SCENE1:
        case ZB_GP_CMD_ID_RECALL_SCENE2:
        case ZB_GP_CMD_ID_RECALL_SCENE3:
        case ZB_GP_CMD_ID_RECALL_SCENE4:
        case ZB_GP_CMD_ID_RECALL_SCENE5:
        case ZB_GP_CMD_ID_RECALL_SCENE6:
        case ZB_GP_CMD_ID_RECALL_SCENE7:
        case ZB_GP_CMD_ID_STORE_SCENE0:
        case ZB_GP_CMD_ID_STORE_SCENE1:
        case ZB_GP_CMD_ID_STORE_SCENE2:
        case ZB_GP_CMD_ID_STORE_SCENE3:
        case ZB_GP_CMD_ID_STORE_SCENE4:
        case ZB_GP_CMD_ID_STORE_SCENE5:
        case ZB_GP_CMD_ID_STORE_SCENE6:
        case ZB_GP_CMD_ID_STORE_SCENE7:
        case ZB_GP_CMD_ID_OFF:
        case ZB_GP_CMD_ID_ON:
        case ZB_GP_CMD_ID_TOGGLE:
        case ZB_GP_CMD_ID_RELEASE:
        case ZB_GP_CMD_ID_LEVEL_CONTROL_STOP:
        case ZB_GP_CMD_ID_MOVE_HUE_STOP:
        case ZB_GP_CMD_ID_MOVE_SATURATION_STOP:
        case ZB_GP_CMD_ID_LOCK_DOOR:
        case ZB_GP_CMD_ID_UNLOCK_DOOR:
        case ZB_GP_CMD_ID_PRESS11:
        case ZB_GP_CMD_ID_RELEASE11:
        case ZB_GP_CMD_ID_PRESS12:
        case ZB_GP_CMD_ID_RELEASE12:
        case ZB_GP_CMD_ID_PRESS22:
        case ZB_GP_CMD_ID_RELEASE22:
        case ZB_GP_CMD_ID_SHORT_PRESS11:
        case ZB_GP_CMD_ID_SHORT_PRESS12:
        case ZB_GP_CMD_ID_SHORT_PRESS22:
        case ZB_GP_CMD_ID_DECOMMISSIONING:
        case ZB_GP_CMD_ID_SUCCESS:
            break;
        /* GPDF commands with payload sent by GPD. */
        case ZB_GP_CMD_ID_MOVE_UP:
        case ZB_GP_CMD_ID_MOVE_DOWN:
        case ZB_GP_CMD_ID_MOVE_UP_WITH_ON_OFF:
        case ZB_GP_CMD_ID_MOVE_DOWN_WITH_ON_OFF:
        case ZB_GP_CMD_ID_MOVE_HUE_UP:
        case ZB_GP_CMD_ID_MOVE_HUE_DOWN:
        case ZB_GP_CMD_ID_MOVE_SATURATION_UP:
        case ZB_GP_CMD_ID_MOVE_SATURATION_DOWN:
            offset = dissect_zbee_nwk_gp_cmd_move_up_down(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_STEP_UP:
        case ZB_GP_CMD_ID_STEP_DOWN:
        case ZB_GP_CMD_ID_STEP_UP_WITH_ON_OFF:
        case ZB_GP_CMD_ID_STEP_DOWN_WITH_ON_OFF:
        case ZB_GP_CMD_ID_STEP_HUE_UP:
        case ZB_GP_CMD_ID_STEP_HUW_DOWN:
        case ZB_GP_CMD_ID_STEP_SATURATION_UP:
        case ZB_GP_CMD_ID_STEP_SATURATION_DOWN:
            offset = dissect_zbee_nwk_gp_cmd_step_up_down(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_MOVE_COLOR:
            offset = dissect_zbee_nwk_gp_cmd_move_color(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_STEP_COLOR:
            offset = dissect_zbee_nwk_gp_cmd_step_color(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_ATTRIBUTE_REPORTING:
            offset = dissect_zbee_nwk_gp_cmd_attr_reporting(tvb, pinfo, cmd_tree, packet, offset, ZBEE_MFG_CODE_NONE);
            break;
        case ZB_GP_CMD_ID_MANUFACTURE_SPECIFIC_ATTR_REPORTING:
            offset = dissect_zbee_nwk_gp_cmd_MS_attr_reporting(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_MULTI_CLUSTER_REPORTING:
            offset = dissect_zbee_nwk_gp_cmd_multi_cluster_reporting(tvb, pinfo, cmd_tree, packet, offset, ZBEE_MFG_CODE_NONE);
            break;
        case ZB_GP_CMD_ID_MANUFACTURER_SPECIFIC_MCLUSTER_REPORTING:
            offset = dissect_zbee_nwk_gp_cmd_MS_multi_cluster_reporting(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_READ_ATTRIBUTES_RESPONSE:
            offset = dissect_zbee_nwk_gp_cmd_read_attributes_response(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_ANY_SENSOR_COMMAND_A0_A3:
            /* TODO: implement it. */
            break;
        case ZB_GP_CMD_ID_COMMISSIONING:
            offset = dissect_zbee_nwk_gp_cmd_commissioning(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_CHANNEL_REQUEST:
            offset = dissect_zbee_nwk_gp_cmd_channel_request(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_REQUEST_ATTRIBUTES:
        /* GPDF commands sent to GPD. */
        case ZB_GP_CMD_ID_READ_ATTRIBUTES:
            offset = dissect_zbee_nwk_gp_cmd_read_attributes(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_COMMISSIONING_REPLY:
            offset = dissect_zbee_nwk_gp_cmd_commissioning_reply(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_WRITE_ATTRIBUTES:
            offset = dissect_zbee_nwk_gp_cmd_write_attributes(tvb, pinfo, cmd_tree, packet, offset);
            break;
        case ZB_GP_CMD_ID_CHANNEL_CONFIGURATION:
            offset = dissect_zbee_nwk_gp_cmd_channel_configuration(tvb, pinfo, cmd_tree, packet, offset);
            break;
    }
    if (offset < tvb_reported_length(tvb)) {
        /* There are leftover bytes! */
        proto_tree *root;
        tvbuff_t *leftover_tvb = tvb_new_subset_remaining(tvb, offset);

        /* Correct the length of the command tree. */
        root = proto_tree_get_root(tree);
        proto_item_set_len(cmd_root, offset);

        /* Dump the tail. */
        call_data_dissector(leftover_tvb, pinfo, root);
    }
    return offset;
} /* dissect_zbee_nwk_gp_cmd */

/**
 *ZigBee NWK packet dissection routine for Green Power profile.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param data raw packet private data.
*/
static int
dissect_zbee_nwk_gp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet *ieee_packet = (ieee802154_packet *)data;
    bool gp_decrypted;
    GSList *GSList_i;
    unsigned offset = 0;
    uint8_t *dec_buffer;
    uint8_t *enc_buffer;
    uint8_t fcf;
    proto_tree *nwk_tree;
    proto_item *proto_root;
    proto_item *ti = NULL;
    tvbuff_t *payload_tvb;
    zbee_nwk_green_power_packet packet;
    static int * const fields[] = {
        &hf_zbee_nwk_gp_frame_type,
        &hf_zbee_nwk_gp_proto_version,
        &hf_zbee_nwk_gp_auto_commissioning,
        &hf_zbee_nwk_gp_fc_ext,
        NULL
    };
    static int * const ext_fields[] = {
        &hf_zbee_nwk_gp_fc_ext_app_id,
        &hf_zbee_nwk_gp_fc_ext_sec_level,
        &hf_zbee_nwk_gp_fc_ext_sec_key,
        &hf_zbee_nwk_gp_fc_ext_rx_after_tx,
        &hf_zbee_nwk_gp_fc_ext_direction,
        NULL
    };

    if (data == NULL)
        return 0;

    memset(&packet, 0, sizeof(packet));
    packet.ieee_packet_src64 = ieee_packet->src64;
    /* Add ourself to the protocol column, clear the info column and create the protocol tree. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZigBee Green Power");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_root = proto_tree_add_protocol_format(tree, proto_zbee_nwk_gp, tvb, offset, tvb_captured_length(tvb),
            "ZGP stub NWK header");
    nwk_tree = proto_item_add_subtree(proto_root, ett_zbee_nwk);

    enc_buffer = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, tvb_captured_length(tvb));
    /* Get and parse the FCF. */
    fcf = tvb_get_uint8(tvb, offset);
    packet.frame_type = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_FRAME_TYPE);
    packet.nwk_frame_control_extension = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_CONTROL_EXTENSION);

    /* Display the FCF. */
    ti = proto_tree_add_bitmask(nwk_tree, tvb, offset, hf_zbee_nwk_gp_fcf, ett_zbee_nwk_fcf, fields, ENC_NA);
    proto_item_append_text(ti, " %s", val_to_str_const(packet.frame_type, zbee_nwk_gp_frame_types, "Unknown Frame Type"));
    offset += 1;

    /* Add the frame type to the info column and protocol root. */
    proto_item_append_text(proto_root, " %s", val_to_str_const(packet.frame_type, zbee_nwk_gp_frame_types, "Unknown type"));
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(packet.frame_type, zbee_nwk_gp_frame_types, "Reserved frame type"));

    if (packet.nwk_frame_control_extension) {
        /* Display ext FCF. */
        fcf = tvb_get_uint8(tvb, offset);
        packet.application_id = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_APP_ID);
        packet.security_level = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_SECURITY_LEVEL);
        packet.direction = zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_EXT_DIRECTION);

        /* Create a subtree for the extended FCF. */
        proto_tree_add_bitmask(nwk_tree, tvb, offset, hf_zbee_nwk_gp_fc_ext_field, ett_zbee_nwk_fcf_ext, ext_fields, ENC_NA);
        offset += 1;
    }
    if ((packet.frame_type == ZBEE_NWK_GP_FCF_DATA && !packet.nwk_frame_control_extension) || (packet.frame_type ==
        ZBEE_NWK_GP_FCF_DATA && packet.nwk_frame_control_extension && packet.application_id ==
        ZBEE_NWK_GP_APP_ID_DEFAULT) || (packet.frame_type == ZBEE_NWK_GP_FCF_MAINTENANCE &&
        packet.nwk_frame_control_extension && packet.application_id == ZBEE_NWK_GP_APP_ID_DEFAULT && tvb_get_uint8(tvb,
        offset) != ZB_GP_CMD_ID_CHANNEL_CONFIGURATION)) {
        /* Display GPD Src ID. */
        packet.source_id = tvb_get_letohl(tvb, offset);
        proto_tree_add_item(nwk_tree, hf_zbee_nwk_gp_zgpd_src_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_item_append_text(proto_root, ", GPD Src ID: 0x%08x", packet.source_id);

        col_append_fstr(pinfo->cinfo, COL_INFO, ", GPD Src ID: 0x%08x", packet.source_id);

        col_clear(pinfo->cinfo, COL_DEF_SRC);
        col_append_fstr(pinfo->cinfo, COL_DEF_SRC, "0x%08x", packet.source_id);

        offset += 4;
    }
    if (packet.application_id == ZBEE_NWK_GP_APP_ID_ZGP) {
        /* Display GPD endpoint */
        packet.endpoint = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(nwk_tree, hf_zbee_nwk_gp_zgpd_endpoint, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_item_append_text(proto_root, ", Endpoint: %d", packet.endpoint);

        col_append_fstr(pinfo->cinfo, COL_INFO, ", Endpoint: %d", packet.endpoint);
        offset += 1;
    }
    /* Display Security Frame Counter. */
    packet.mic_size = 0;
    if (packet.nwk_frame_control_extension) {
        if (packet.application_id == ZBEE_NWK_GP_APP_ID_DEFAULT || packet.application_id == ZBEE_NWK_GP_APP_ID_ZGP
            || packet.application_id == ZBEE_NWK_GP_APP_ID_LPED) {
            if (packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_1LSB
                && packet.application_id != ZBEE_NWK_GP_APP_ID_LPED) {
                packet.mic_size = 2;
            } else if (packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULL || packet.security_level ==
                ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR) {
                /* Get Security Frame Counter and display it. */
                packet.mic_size = 4;
                packet.security_frame_counter = tvb_get_letohl(tvb, offset);
                proto_tree_add_item(nwk_tree, hf_zbee_nwk_gp_security_frame_counter, tvb, offset, 4,
                    ENC_LITTLE_ENDIAN);
                offset += 4;
            }
        }
    }
    /* Parse application payload. */
    /* This is a uint8_t, but tvb_reported_length might be larger; e.g.,
     * SCOP over TCP, presumably with errors. It's bogus either way; perhaps
     * we should warn.
     */
    packet.payload_len = tvb_reported_length(tvb) - offset - packet.mic_size;
    /* Ensure that the payload exists. */
    if (packet.payload_len <= 0) {
        proto_tree_add_expert(nwk_tree, pinfo, &ei_zbee_nwk_gp_no_payload, tvb, 0, -1);
        return offset;
    }
    /* OK, payload exists. Parse MIC field if needed. */
    if (packet.mic_size == 2) {
        packet.mic = tvb_get_letohs(tvb, offset + packet.payload_len);
    } else if (packet.mic_size == 4) {
        packet.mic = tvb_get_letohl(tvb, offset + packet.payload_len);
    }
    /* Save packet private data. */
    data = (void *)&packet;
    payload_tvb = tvb_new_subset_length(tvb, offset, packet.payload_len);
    if (packet.security_level != ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR) {
        dissect_zbee_nwk_gp_cmd(payload_tvb, pinfo, nwk_tree, data);
    }
    offset += packet.payload_len;
    /* Display MIC field. */
    if (packet.mic_size) {
        proto_tree_add_uint(nwk_tree, packet.mic_size == 4 ? hf_zbee_nwk_gp_security_mic_4b :
                hf_zbee_nwk_gp_security_mic_2b, tvb, offset, packet.mic_size, packet.mic);
        offset += packet.mic_size;
    }
    if ((offset < tvb_captured_length(tvb)) && (packet.security_level != ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR)) {
        proto_tree_add_expert(nwk_tree, pinfo, &ei_zbee_nwk_gp_inval_residual_data, tvb, offset, -1);
        return offset;
    }
    if (packet.security_level == ZBEE_NWK_GP_SECURITY_LEVEL_FULLENCR) {
        gp_decrypted = false;

        if (tvb_captured_length(tvb) >= tvb_reported_length(tvb)) {
            dec_buffer = (uint8_t *)wmem_alloc(pinfo->pool, packet.payload_len);
            for (GSList_i = zbee_gp_keyring; GSList_i && !gp_decrypted; GSList_i = g_slist_next(GSList_i)) {
                gp_decrypted = zbee_gp_decrypt_payload(&packet, enc_buffer, offset - packet.payload_len -
                    packet.mic_size, dec_buffer, packet.payload_len, packet.mic_size,
                    ((key_record_t *)(GSList_i->data))->key);
            }
        }

        if (gp_decrypted) {
            payload_tvb = tvb_new_child_real_data(tvb, dec_buffer, packet.payload_len, packet.payload_len);
            add_new_data_source(pinfo, payload_tvb, "Decrypted GP Payload");
            dissect_zbee_nwk_gp_cmd(payload_tvb, pinfo, nwk_tree, data);
        } else {
            payload_tvb = tvb_new_subset_length_caplen(tvb, offset - packet.payload_len - packet.mic_size, packet.payload_len, -1);
            call_data_dissector(payload_tvb, pinfo, tree);
        }
    }
    return tvb_captured_length(tvb);
} /* dissect_zbee_nwk_gp */

/**
 *Heuristic interpreter for the ZigBee Green Power dissectors.
 *
 *@param tvb pointer to buffer containing raw packet.
 *@param pinfo pointer to packet information fields.
 *@param tree pointer to data tree Wireshark uses to display packet.
 *@param data raw packet private data.
*/
static bool
dissect_zbee_nwk_heur_gp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    ieee802154_packet   *packet = (ieee802154_packet *)data;
    uint8_t             fcf;

    /* We must have the IEEE 802.15.4 headers. */
    if (packet == NULL) return false;
    /* ZigBee green power never uses 16-bit source addresses. */
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_SHORT) return false;

    /* If the frame type and version are not sane, then it's probably not ZGP. */
    fcf = tvb_get_uint8(tvb, 0);
    if (zbee_get_bit_field(fcf, ZBEE_NWK_GP_FCF_VERSION) != ZBEE_VERSION_GREEN_POWER) return false;
    if (!try_val_to_str(zbee_get_bit_field(fcf, ZBEE_NWK_FCF_FRAME_TYPE), zbee_nwk_gp_frame_types)) return false;

    /* ZigBee greenpower frames are either sent to broadcast or the extended address. */
    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_SHORT && packet->dst16 == IEEE802154_BCAST_ADDR) {
        dissect_zbee_nwk_gp(tvb, pinfo, tree, data);
        return true;
    }
    /* 64-bit destination addressing mode support. */
    if (packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        dissect_zbee_nwk_gp(tvb, pinfo, tree, data);
        return true;
    }

    return false;
} /* dissect_zbee_nwk_heur_gp */

/**
 *Init routine for the ZigBee GP profile security.
 *
*/
static void
gp_init_zbee_security(void)
{
    unsigned i;
    key_record_t key_record;

    for (i = 0; gp_uat_key_records && (i < num_uat_key_records); i++) {
        key_record.frame_num = 0;
        key_record.label = g_strdup(gp_uat_key_records[i].label);
        memcpy(key_record.key, gp_uat_key_records[i].key, ZBEE_SEC_CONST_KEYSIZE);
        zbee_gp_keyring = g_slist_prepend(zbee_gp_keyring, g_memdup2(&key_record, sizeof(key_record_t)));
    }
}

static void zbee_free_key_record(void *ptr)
{
    key_record_t *k;

    k = (key_record_t *)ptr;
    if (!k)
        return;

    g_free(k->label);
    g_free(k);
}

static void
gp_cleanup_zbee_security(void)
{
    if (!zbee_gp_keyring)
        return;

    g_slist_free_full(zbee_gp_keyring, zbee_free_key_record);
    zbee_gp_keyring = NULL;
}

/**
 *ZigBee NWK GP protocol registration routine.
 *
*/
void
proto_register_zbee_nwk_gp(void)
{
    module_t *gp_zbee_prefs;
    expert_module_t* expert_zbee_nwk_gp;

    static hf_register_info hf[] = {
        { &hf_zbee_nwk_gp_auto_commissioning,
            { "Auto Commissioning", "zbee_nwk_gp.auto_commissioning", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_FCF_AUTO_COMMISSIONING, NULL, HFILL }},

        { &hf_zbee_nwk_gp_fc_ext,
            { "NWK Frame Extension", "zbee_nwk_gp.fc_extension", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_FCF_CONTROL_EXTENSION,
                NULL, HFILL }},

        { &hf_zbee_nwk_gp_fcf,
            { "Frame Control Field", "zbee_nwk_gp.fcf", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_frame_type,
            { "Frame Type", "zbee_nwk_gp.frame_type", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_frame_types),
                ZBEE_NWK_GP_FCF_FRAME_TYPE, NULL, HFILL }},

        { &hf_zbee_nwk_gp_proto_version,
            { "Protocol Version", "zbee_nwk_gp.proto_version", FT_UINT8, BASE_DEC, NULL, ZBEE_NWK_GP_FCF_VERSION, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_fc_ext_field,
            { "Extended NWK Frame Control Field", "zbee_nwk_gp.fc_ext", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_fc_ext_app_id,
            { "Application ID", "zbee_nwk_gp.fc_ext_app_id", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_app_id_names),
                ZBEE_NWK_GP_FCF_EXT_APP_ID, NULL, HFILL }},

        { &hf_zbee_nwk_gp_fc_ext_direction,
            { "Direction", "zbee_nwk_gp.fc_ext_direction", FT_UINT8, BASE_HEX, VALS(zbee_nwk_gp_directions),
                ZBEE_NWK_GP_FCF_EXT_DIRECTION, NULL, HFILL }},

        { &hf_zbee_nwk_gp_fc_ext_rx_after_tx,
            { "Rx After Tx", "zbee_nwk_gp.fc_ext_rxaftertx", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_FCF_EXT_RX_AFTER_TX, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_fc_ext_sec_key,
            { "Security Key", "zbee_nwk_gp.fc_ext_security_key", FT_BOOLEAN, 8, NULL, ZBEE_NWK_GP_FCF_EXT_SECURITY_KEY,
                NULL, HFILL }},

        { &hf_zbee_nwk_gp_fc_ext_sec_level,
            { "Security Level", "zbee_nwk_gp.fc_ext_security_level", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_gp_src_sec_levels_names), ZBEE_NWK_GP_FCF_EXT_SECURITY_LEVEL, NULL, HFILL }},

        { &hf_zbee_nwk_gp_zgpd_src_id,
            { "Src ID", "zbee_nwk_gp.source_id", FT_UINT32, BASE_HEX, VALS(zbee_nwk_gp_src_id_names), 0x0, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_zgpd_endpoint,
            { "Endpoint", "zbee_nwk_gp.endpoint", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_security_frame_counter,
            { "Security Frame Counter", "zbee_nwk_gp.security_frame_counter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_security_mic_2b,
            { "Security MIC", "zbee_nwk_gp.security_mic2", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_security_mic_4b,
            { "Security MIC", "zbee_nwk_gp.security_mic4", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_command_id,
            { "ZGPD Command ID", "zbee_nwk_gp.command_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &zbee_nwk_gp_cmd_names_ext, 0x0, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_device_id,
            { "ZGPD Device ID", "zbee_nwk_gp.cmd.comm.dev_id", FT_UINT8, BASE_HEX | BASE_EXT_STRING, &zbee_nwk_gp_device_ids_names_ext,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_encr,
            { "GPD Key Encryption", "zbee_nwk_gp.cmd.comm.ext_opt.gpd_key_encr", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_ENCR, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_ext_opt_gpd_key_present,
            { "GPD Key Present", "zbee_nwk_gp.cmd.comm.ext_opt.gpd_key_present", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_GPD_KEY_PRESENT, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_ext_opt_key_type,
            { "Key Type", "zbee_nwk_gp.cmd.comm.ext_opt.key_type", FT_UINT8, BASE_HEX,
                VALS(zbee_nwk_gp_src_sec_keys_type_names), ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_KEY_TYPE, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_outgoing_counter,
            { "GPD Outgoing Counter", "zbee_nwk_gp.cmd.comm.out_counter", FT_UINT32, BASE_HEX, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_ext_opt_sec_level_cap,
            { "Security Level Capabilities", "zbee_nwk_gp.cmd.comm.ext_opt.seclevel_cap", FT_UINT8, BASE_HEX, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_SEC_LEVEL_CAP, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_security_key,
            { "Security Key", "zbee_nwk_gp.cmd.comm.security_key", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_gpd_sec_key_mic,
            { "GPD Key MIC", "zbee_nwk_gp.cmd.comm.gpd_key_mic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt_ext_opt,
            { "Extended Option Field", "zbee_nwk_gp.cmd.comm.opt.ext_opt_field", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_EXT_OPTIONS, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt,
            { "Options Field", "zbee_nwk_gp.cmd.comm.opt", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt_fixed_location,
            { "Fixed Location", "zbee_nwk_gp.cmd.comm.opt.fixed_location", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_FIXED_LOCATION, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt_mac_sec_num_cap,
            { "MAC Sequence number capability", "zbee_nwk_gp.cmd.comm.opt.mac_seq_num_cap", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_MAC_SEQ, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt_appli_info_present,
            { "Application information present", "zbee_nwk_gp.cmd.comm.opt.appli_info_present", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_APPLICATION_INFO, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt_panid_req,
            { "PANId request", "zbee_nwk_gp.cmd.comm.opt.panid_req", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_PAN_ID_REQ, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt_rx_on_cap,
            { "RxOnCapability", "zbee_nwk_gp.cmd.comm.opt.rxon_cap", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_RX_ON_CAP, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_opt_sec_key_req,
            { "GP Security Key Request", "zbee_nwk_gp.cmd.comm.opt.seq_key_req", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_OPT_GP_SEC_KEY_REQ, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_ext_opt,
            { "Extended Options Field", "zbee_nwk_gp.cmd.comm.ext_opt", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_ext_opt_outgoing_counter,
            { "GPD Outgoing present", "zbee_nwk_gp.cmd.comm.ext_opt.outgoing_counter", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_EXT_OPT_OUT_COUNTER, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_manufacturer_greenpeak_dev_id,
            { "Manufacturer Model ID", "zbee_nwk_gp.cmd.comm.manufacturer_model_id", FT_UINT16, BASE_HEX,
                VALS(zbee_nwk_gp_manufacturer_greenpeak_dev_names), 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_manufacturer_dev_id,
            { "Manufacturer Model ID", "zbee_nwk_gp.cmd.comm.manufacturer_model_id", FT_UINT16, BASE_HEX,
                NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_manufacturer_id,
            { "Manufacturer ID", "zbee_nwk_gp.cmd.comm.manufacturer_id", FT_UINT16, BASE_HEX,
                VALS(zbee_mfr_code_names), 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_appli_info_crp,
            { "Cluster reports present", "zbee_nwk_gp.cmd.comm.appli_info.crp", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_CRP , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_appli_info_gclp,
            { "GP commands list present", "zbee_nwk_gp.cmd.comm.appli_info.gclp", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_GCLP , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_appli_info,
            { "Application information Field", "zbee_nwk_gp.cmd.comm.appli_info", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_appli_info_mip,
            { "Manufacturer ID present", "zbee_nwk_gp.cmd.comm.appli_info.mip", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_MIP , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_appli_info_mmip,
            { "Manufacturer Model ID present", "zbee_nwk_gp.cmd.comm.appli_info.mmip", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_APPLI_INFO_MMIP , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_gpd_cmd_num,
            { "Number of GPD commands", "zbee_nwk_gp.cmd.comm.gpd_cmd_num", FT_UINT8, BASE_DEC, NULL,
                0x0 , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_gpd_cmd_id_list,
            { "GPD CommandID list", "zbee_nwk_gp.cmd.comm.gpd_cmd_id_list", FT_NONE, BASE_NONE, NULL,
                0x0 , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_length_of_clid_list,
            { "Length of ClusterID list", "zbee_nwk_gp.cmd.comm.length_of_clid_list", FT_UINT8, BASE_HEX, NULL,
                0x0 , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_length_of_clid_list_server,
            { "Number of server ClusterIDs", "zbee_nwk_gp.cmd.comm.length_of_clid_list_srv", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_SRV, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_length_of_clid_list_client,
            { "Number of client ClusterIDs", "zbee_nwk_gp.cmd.comm.length_of_clid_list_cli", FT_UINT8, BASE_DEC, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_CLID_LIST_LEN_CLI, NULL, HFILL }},

        { &hf_zbee_nwk_cmd_comm_clid_list_server,
            { "Cluster ID List Server", "zbee_nwk_gp.cmd.comm.clid_list_server", FT_NONE, BASE_NONE, NULL,
                0x0 , NULL, HFILL }},

        { &hf_zbee_nwk_cmd_comm_clid_list_client,
            { "ClusterID List Client", "zbee_nwk_gp.cmd.comm.clid_list_client", FT_NONE, BASE_NONE, NULL,
                0x0 , NULL, HFILL }},

        { &hf_zbee_nwk_cmd_comm_cluster_id,
            { "Cluster ID", "zbee_nwk_gp.cmd.comm.cluster_id", FT_UINT16, BASE_HEX, NULL,
                0x0 , NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_opt_key_encr,
            { "GPD Key Encryption", "zbee_nwk_gp.cmd.comm_reply.opt.sec_key_encr", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_ENCR, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_opt,
            { "Options Field", "zbee_nwk_gp.cmd.comm_reply.opt", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_opt_panid_present,
            { "PANID Present", "zbee_nwk_gp.cmd.comm_reply.opt.pan_id_present", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_PAN_ID_PRESENT, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_key_present,
            { "GPD Security Key Present", "zbee_nwk_gp.cmd.comm_reply.opt.sec_key_present", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_KEY_PRESENT, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_level,
            { "Security Level", "zbee_nwk_gp.cmd.comm_reply.opt.sec_level", FT_UINT8, BASE_HEX, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_SEC_LEVEL, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_opt_sec_type,
            { "Key Type", "zbee_nwk_gp.cmd.comm_reply.opt.key_type", FT_UINT8, BASE_HEX, NULL,
                ZBEE_NWK_GP_CMD_COMMISSIONING_REP_OPT_KEY_TYPE, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_pan_id,
            { "PAN ID", "zbee_nwk_gp.cmd.comm_reply.pan_id", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_comm_rep_frame_counter,
            { "Frame Counter", "zbee_nwk_gp.cmd.comm_reply.frame_counter", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_read_att_opt_multi_rec,
            { "Multi-record", "zbee_nwk_gp.cmd.read_att.opt.multi_record", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_READ_ATTRIBUTE_OPT_MULTI_RECORD, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_read_att_opt_man_field_present,
            { "Manufacturer field present", "zbee_nwk_gp.cmd.read_att.opt.man_field_present", FT_BOOLEAN, 8, NULL,
                ZBEE_NWK_GP_CMD_READ_ATTRIBUTE_OPT_MAN_FIELD_PRESENT, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_read_att_opt,
            { "Option field", "zbee_nwk_gp.cmd.read_att.opt", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_zcl_gp_cmd_ms_manufacturer_code,
            { "Manufacturer Code", "zbee_nwk_gp.cmd.manufacturer_code", FT_UINT16, BASE_HEX, VALS(zbee_mfr_code_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_read_att_record_len,
            { "Length of Record List",  "zbee_nwk_gp.cmd.read_att.record_len", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_zbee_nwk_gp_zcl_attr_status,
            { "Status", "zbee_nwk_gp.zcl.attr.status", FT_UINT8, BASE_HEX, VALS(zbee_zcl_status_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_zcl_attr_data_type,
            { "Data Type", "zbee_nwk_gp.zcl.attr.datatype", FT_UINT8, BASE_HEX, VALS(zbee_zcl_short_data_type_names),
                0x0, NULL, HFILL } },

        { &hf_zbee_nwk_gp_zcl_attr_cluster_id,
            { "ZigBee Cluster ID", "zbee_nwk_gp.zcl.attr.cluster_id", FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(zbee_aps_cid_names),
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour,
            { "Channel Toggling Behaviour", "zbee_nwk_gp.cmd.ch_req", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_1st,
            { "Rx channel in the next attempt", "zbee_nwk_gp.cmd.ch_req.1st", FT_UINT8, BASE_HEX, NULL,
                ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_1ST, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_channel_request_toggling_behaviour_2nd,
            { "Rx channel in the second next attempt", "zbee_nwk_gp.ch_req.2nd", FT_UINT8, BASE_HEX, NULL,
                ZBEE_NWK_GP_CMD_CHANNEL_REQUEST_2ND, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_operational_channel,
            { "Operational Channel", "zbee_nwk_gp.cmd.configuration_ch", FT_UINT8, BASE_HEX, NULL,
                0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_channel_configuration,
            { "Operation channel", "zbee_nwk_gp.cmd.configuration_ch.operation_ch", FT_UINT8, BASE_HEX, NULL,
                ZBEE_NWK_GP_CMD_CHANNEL_CONFIGURATION_OPERATION_CH, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_move_color_ratex,
            { "RateX", "zbee_nwk_gp.cmd.move_color.ratex", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_move_color_ratey,
            { "RateY", "zbee_nwk_gp.cmd.move_color.ratey", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_move_up_down_rate,
            { "Rate", "zbee_nwk_gp.cmd.move_up_down.rate", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_step_color_stepx,
            { "StepX", "zbee_nwk_gp.cmd.step_color.stepx", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_step_color_stepy,
            { "StepY", "zbee_nwk_gp.cmd.step_color.stepy", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_step_color_transition_time,
            { "Transition Time", "zbee_nwk_gp.cmd.step_color.transition_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
                HFILL }},

        { &hf_zbee_nwk_gp_cmd_step_up_down_step_size,
            { "Step Size", "zbee_nwk_gp.cmd.step_up_down.step_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_zbee_nwk_gp_cmd_step_up_down_transition_time,
            { "Transition Time", "zbee_nwk_gp.cmd.step_up_down.transition_time", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
                HFILL }}
    };

    static ei_register_info ei[] = {
        { &ei_zbee_nwk_gp_no_payload,
            { "zbee_nwk_gp.no_payload", PI_MALFORMED, PI_ERROR,
                "Payload is missing", EXPFILL }},
        { &ei_zbee_nwk_gp_inval_residual_data,
            { "zbee_nwk_gp.inval_residual_data", PI_MALFORMED, PI_ERROR,
                "Invalid residual data", EXPFILL }},
        { &ei_zbee_nwk_gp_com_rep_no_out_cnt,
            { "zbee_nwk_gp.com_rep_no_out_cnt", PI_DEBUG, PI_WARN,
                "Missing outgoing frame counter", EXPFILL }}
    };

    static int *ett[] = {
        &ett_zbee_nwk,
        &ett_zbee_nwk_cmd,
        &ett_zbee_nwk_cmd_cinfo,
        &ett_zbee_nwk_cmd_appli_info,
        &ett_zbee_nwk_cmd_options,
        &ett_zbee_nwk_fcf,
        &ett_zbee_nwk_fcf_ext,
        &ett_zbee_nwk_clu_rec,
        &ett_zbee_nwk_att_rec,
        &ett_zbee_nwk_cmd_comm_gpd_cmd_id_list,
        &ett_zbee_nwk_cmd_comm_length_of_clid_list,
        &ett_zbee_nwk_cmd_comm_clid_list_server,
        &ett_zbee_nwk_cmd_comm_clid_list_client
    };

    static uat_field_t key_uat_fields[] = {
        UAT_FLD_CSTRING(gp_uat_key_records, string, "Key", "A 16-byte key."),
        UAT_FLD_VS(gp_uat_key_records, byte_order, "Byte Order", byte_order_vals, "Byte order of a key."),
        UAT_FLD_LSTRING(gp_uat_key_records, label, "Label", "User label for a key."),
        UAT_END_FIELDS
    };

    proto_zbee_nwk_gp = proto_register_protocol("ZigBee Green Power Profile", "ZigBee Green Power",
        ZBEE_PROTOABBREV_NWK_GP);

    gp_zbee_prefs = prefs_register_protocol(proto_zbee_nwk_gp, NULL);

    zbee_gp_sec_key_table_uat = uat_new("ZigBee GP Security Keys", sizeof(uat_key_record_t), "zigbee_gp_keys", true,
        &gp_uat_key_records, &num_uat_key_records, UAT_AFFECTS_DISSECTION, NULL, uat_key_record_copy_cb,
        uat_key_record_update_cb, uat_key_record_free_cb, uat_key_record_post_update_cb, NULL, key_uat_fields);

    prefs_register_uat_preference(gp_zbee_prefs, "gp_key_table", "Pre-configured GP Security Keys",
        "Pre-configured GP Security Keys.", zbee_gp_sec_key_table_uat);

    register_init_routine(gp_init_zbee_security);
    register_cleanup_routine(gp_cleanup_zbee_security);

    /* Register the Wireshark protocol. */
    proto_register_field_array(proto_zbee_nwk_gp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_zbee_nwk_gp = expert_register_protocol(proto_zbee_nwk_gp);
    expert_register_field_array(expert_zbee_nwk_gp, ei, array_length(ei));

    /* Register the dissectors. */
    register_dissector(ZBEE_PROTOABBREV_NWK_GP, dissect_zbee_nwk_gp, proto_zbee_nwk_gp);
    register_dissector(ZBEE_PROTOABBREV_NWK_GP_CMD, dissect_zbee_nwk_gp_cmd, proto_zbee_nwk_gp);
} /* proto_register_zbee_nwk_gp */

/**
 *Registers the ZigBee dissector with Wireshark.
 *
*/
void
proto_reg_handoff_zbee_nwk_gp(void)
{
    /* Register our dissector with IEEE 802.15.4. */
    dissector_add_for_decode_as(IEEE802154_PROTOABBREV_WPAN_PANID, find_dissector(ZBEE_PROTOABBREV_NWK_GP));
    heur_dissector_add(IEEE802154_PROTOABBREV_WPAN, dissect_zbee_nwk_heur_gp, "ZigBee Green Power over IEEE 802.15.4", "zbee_nwk_gp_wlan", proto_zbee_nwk_gp, HEURISTIC_ENABLE);
} /* proto_reg_handoff_zbee */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
