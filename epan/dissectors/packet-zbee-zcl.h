/* packet-zbee-zcl.h
 * Dissector routines for the ZigBee Cluster Library (ZCL)
 * By Fred Fierling <fff@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ZBEE_ZCL_H
#define PACKET_ZBEE_ZCL_H

#include <wsutil/epochs.h>

/*  Structure to contain the ZCL frame information */
typedef struct{
    bool        mfr_spec;
    bool        direction;
    bool        disable_default_resp;

    uint8_t     frame_type;
    uint16_t    mfr_code;
    uint8_t     tran_seqno;
    uint8_t     cmd_id;
} zbee_zcl_packet;

/* ZCL Commands */
#define ZBEE_ZCL_CMD_READ_ATTR                  0x00
#define ZBEE_ZCL_CMD_READ_ATTR_RESP             0x01
#define ZBEE_ZCL_CMD_WRITE_ATTR                 0x02
#define ZBEE_ZCL_CMD_WRITE_ATTR_UNDIVIDED       0x03
#define ZBEE_ZCL_CMD_WRITE_ATTR_RESP            0x04
#define ZBEE_ZCL_CMD_WRITE_ATTR_NO_RESP         0x05
#define ZBEE_ZCL_CMD_CONFIG_REPORT              0x06
#define ZBEE_ZCL_CMD_CONFIG_REPORT_RESP         0x07
#define ZBEE_ZCL_CMD_READ_REPORT_CONFIG         0x08
#define ZBEE_ZCL_CMD_READ_REPORT_CONFIG_RESP    0x09
#define ZBEE_ZCL_CMD_REPORT_ATTR                0x0a
#define ZBEE_ZCL_CMD_DEFAULT_RESP               0x0b
#define ZBEE_ZCL_CMD_DISCOVER_ATTR              0x0c
#define ZBEE_ZCL_CMD_DISCOVER_ATTR_RESP         0x0d
#define ZBEE_ZCL_CMD_READ_ATTR_STRUCT           0x0e
#define ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT          0x0f
#define ZBEE_ZCL_CMD_WRITE_ATTR_STRUCT_RESP     0x10
#define ZBEE_ZCL_CMD_DISCOVER_CMDS_REC          0x11
#define ZBEE_ZCL_CMD_DISCOVER_CMDS_REC_RESP     0x12
#define ZBEE_ZCL_CMD_DISCOVER_CMDS_GEN          0x13
#define ZBEE_ZCL_CMD_DISCOVER_CMDS_GEN_RESP     0x14
#define ZBEE_ZCL_CMD_DISCOVER_ATTR_EXTENDED     0x15
#define ZBEE_ZCL_CMD_DISCOVER_ATTR_EXTENDED_RESP 0x16


/* ZCL Data Types */
#define ZBEE_ZCL_NO_DATA            0x00

#define ZBEE_ZCL_8_BIT_DATA         0x08
#define ZBEE_ZCL_16_BIT_DATA        0x09
#define ZBEE_ZCL_24_BIT_DATA        0x0a
#define ZBEE_ZCL_32_BIT_DATA        0x0b
#define ZBEE_ZCL_40_BIT_DATA        0x0c
#define ZBEE_ZCL_48_BIT_DATA        0x0d
#define ZBEE_ZCL_56_BIT_DATA        0x0e
#define ZBEE_ZCL_64_BIT_DATA        0x0f

#define ZBEE_ZCL_BOOLEAN            0x10

#define ZBEE_ZCL_8_BIT_BITMAP       0x18
#define ZBEE_ZCL_16_BIT_BITMAP      0x19
#define ZBEE_ZCL_24_BIT_BITMAP      0x1a
#define ZBEE_ZCL_32_BIT_BITMAP      0x1b
#define ZBEE_ZCL_40_BIT_BITMAP      0x1c
#define ZBEE_ZCL_48_BIT_BITMAP      0x1d
#define ZBEE_ZCL_56_BIT_BITMAP      0x1e
#define ZBEE_ZCL_64_BIT_BITMAP      0x1f

#define ZBEE_ZCL_8_BIT_UINT         0x20
#define ZBEE_ZCL_16_BIT_UINT        0x21
#define ZBEE_ZCL_24_BIT_UINT        0x22
#define ZBEE_ZCL_32_BIT_UINT        0x23
#define ZBEE_ZCL_40_BIT_UINT        0x24
#define ZBEE_ZCL_48_BIT_UINT        0x25
#define ZBEE_ZCL_56_BIT_UINT        0x26
#define ZBEE_ZCL_64_BIT_UINT        0x27

#define ZBEE_ZCL_8_BIT_INT          0x28
#define ZBEE_ZCL_16_BIT_INT         0x29
#define ZBEE_ZCL_24_BIT_INT         0x2a
#define ZBEE_ZCL_32_BIT_INT         0x2b
#define ZBEE_ZCL_40_BIT_INT         0x2c
#define ZBEE_ZCL_48_BIT_INT         0x2d
#define ZBEE_ZCL_56_BIT_INT         0x2e
#define ZBEE_ZCL_64_BIT_INT         0x2f

#define ZBEE_ZCL_8_BIT_ENUM         0x30
#define ZBEE_ZCL_16_BIT_ENUM        0x31

#define ZBEE_ZCL_SEMI_FLOAT         0x38
#define ZBEE_ZCL_SINGLE_FLOAT       0x39
#define ZBEE_ZCL_DOUBLE_FLOAT       0x3a

#define ZBEE_ZCL_OCTET_STRING       0x41
#define ZBEE_ZCL_CHAR_STRING        0x42
#define ZBEE_ZCL_LONG_OCTET_STRING  0x43
#define ZBEE_ZCL_LONG_CHAR_STRING   0x44

#define ZBEE_ZCL_ARRAY              0x48
#define ZBEE_ZCL_STRUCT             0x4c

#define ZBEE_ZCL_SET                0x50
#define ZBEE_ZCL_BAG                0x51

#define ZBEE_ZCL_TIME               0xe0
#define ZBEE_ZCL_DATE               0xe1
#define ZBEE_ZCL_UTC                0xe2

#define ZBEE_ZCL_CLUSTER_ID         0xe8
#define ZBEE_ZCL_ATTR_ID            0xe9
#define ZBEE_ZCL_BACNET_OID         0xea

#define ZBEE_ZCL_IEEE_ADDR          0xf0
#define ZBEE_ZCL_SECURITY_KEY       0xf1

#define ZBEE_ZCL_UNKNOWN            0xff

/* ZCL Miscellaneous */
#define ZBEE_ZCL_DIR_REPORTED                   0
#define ZBEE_ZCL_DIR_RECEIVED                   1

#define IS_ANALOG_SUBTYPE(x)    ( (x & 0xF0) == 0x20 || (x & 0xF8) == 0x38 || (x & 0xF8) == 0xE0 )

/* ZCL Status Enumerations */
#define ZBEE_ZCL_STAT_SUCCESS                       0x00
#define ZBEE_ZCL_STAT_FAILURE                       0x01

#define ZBEE_ZCL_STAT_NOT_AUTHORIZED                0x7e
#define ZBEE_ZCL_STAT_RESERVED_FIELD_NOT_ZERO       0x7f
#define ZBEE_ZCL_STAT_MALFORMED_CMD                 0x80
#define ZBEE_ZCL_STAT_UNSUP_CLUSTER_CMD             0x81
#define ZBEE_ZCL_STAT_UNSUP_GENERAL_CMD             0x82
#define ZBEE_ZCL_STAT_UNSUP_MFR_CLUSTER_CMD         0x83
#define ZBEE_ZCL_STAT_UNSUP_MFR_GENERAL_CMD         0x84
#define ZBEE_ZCL_STAT_INVALID_FIELD                 0x85
#define ZBEE_ZCL_STAT_UNSUPPORTED_ATTR              0x86
#define ZBEE_ZCL_STAT_INVALID_VALUE                 0x87
#define ZBEE_ZCL_STAT_READ_ONLY                     0x88
#define ZBEE_ZCL_STAT_INSUFFICIENT_SPACE            0x89
#define ZBEE_ZCL_STAT_DUPLICATE_EXISTS              0x8a
#define ZBEE_ZCL_STAT_NOT_FOUND                     0x8b
#define ZBEE_ZCL_STAT_UNREPORTABLE_ATTR             0x8c
#define ZBEE_ZCL_STAT_INVALID_DATA_TYPE             0x8d
#define ZBEE_ZCL_STAT_INVALID_SELECTOR              0x8e
#define ZBEE_ZCL_STAT_WRITE_ONLY                    0x8f
#define ZBEE_ZCL_STAT_INCONSISTENT_STARTUP_STATE    0x90
#define ZBEE_ZCL_STAT_DEFINED_OUT_OF_BAND           0x91
#define ZBEE_ZCL_STAT_INCONSISTENT                  0x92
#define ZBEE_ZCL_STAT_ACTION_DENIED                 0x93
#define ZBEE_ZCL_STAT_TIMEOUT                       0x94
#define ZBEE_ZCL_STAT_OTA_ABORT                     0x95
#define ZBEE_ZCL_STAT_OTA_INVALID_IMAGE             0x96
#define ZBEE_ZCL_STAT_OTA_WAIT_FOR_DATA             0x97
#define ZBEE_ZCL_STAT_OTA_NO_IMAGE_AVAILABLE        0x98
#define ZBEE_ZCL_STAT_OTA_REQUIRE_MORE_IMAGE        0x99
#define ZBEE_ZCL_STAT_OTA_NOTIFICATION_PENDING      0x9a
#define ZBEE_ZCL_STAT_HARDWARE_FAILURE              0xc0
#define ZBEE_ZCL_STAT_SOFTWARE_FAILURE              0xc1
#define ZBEE_ZCL_STAT_CALIBRATION_ERROR             0xc2
#define ZBEE_ZCL_STAT_UNSUPPORTED_CLUSTER           0xc3
#define ZBEE_ZCL_STAT_LIMIT_REACHED                 0xc4

/* Misc. */
#define INT24_SIGN_BITS                             0xffff8000
#define MONTHS_PER_YEAR                             12
#define YEAR_OFFSET                                 1900

/* ZigBee ZCL Cluster Key */
#define ZCL_CLUSTER_MFR_KEY(cluster_id,mfr_code)    (((mfr_code)<<16) | (cluster_id))

typedef void (*zbee_zcl_fn_attr_data)(proto_tree *tree, packet_info* pinfo, tvbuff_t *tvb, unsigned *offset, uint16_t attr_id, unsigned data_type, bool client_attr);

typedef struct _zbee_zcl_cluster_desc {
    int         proto_id;
    protocol_t  *proto;
    const char  *name;
    int         ett;
    int         hf_attr_server_id;
    int         hf_attr_client_id;
    int         hf_cmd_rx_id;
    int         hf_cmd_tx_id;
    uint16_t    cluster_id;
    uint16_t    mfr_code;
    zbee_zcl_fn_attr_data fn_attr_data;
} zbee_zcl_cluster_desc;

extern const value_string zbee_zcl_short_data_type_names[];
extern const value_string zbee_mfr_code_names[];
extern const value_string zbee_zcl_status_names[];

extern const time_value_string now_strings[];
extern const time_value_string zbee_zcl_utctime_strings[];

/* Dissector functions */
extern void dissect_zcl_read_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, uint16_t cluster_id, uint16_t mfr_code, bool direction);
extern void dissect_zcl_write_attr (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, uint16_t cluster_id, uint16_t mfr_code, bool direction);
extern void dissect_zcl_report_attr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, unsigned *offset, uint16_t cluster_id, uint16_t mfr_code, bool direction);
extern void dissect_zcl_read_attr_resp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, unsigned *offset, uint16_t cluster_id, uint16_t mfr_code, bool direction);
extern void dissect_zcl_attr_id(tvbuff_t *tvb, proto_tree *tree, unsigned *offset, uint16_t cluster_id, uint16_t mfr_code, bool client_attr);
extern void dissect_zcl_attr_data_type_val(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, unsigned *offset, uint16_t attr_id, uint16_t cluster_id, uint16_t mfr_code, bool client_attr);
extern unsigned dissect_zcl_attr_uint8 (tvbuff_t *tvb, proto_tree *tree, unsigned *offset, int *length);

/* Helper functions */

/* Exported DLL functions */
WS_DLL_PUBLIC void decode_zcl_time_in_100ms (char *s, uint16_t value);
WS_DLL_PUBLIC void decode_zcl_time_in_seconds (char *s, uint16_t value);
WS_DLL_PUBLIC void decode_zcl_time_in_minutes (char *s, uint16_t value);
WS_DLL_PUBLIC void dissect_zcl_attr_data (tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, unsigned *offset, unsigned data_type, bool client_attr);

WS_DLL_PUBLIC void zbee_zcl_init_cluster(const char *proto_abbrev, int proto, int ett, uint16_t cluster_id, uint16_t mfr_code, int hf_attr_server_id, int hf_attr_client_id, int hf_cmd_rx_id, int hf_cmd_tx_id, zbee_zcl_fn_attr_data fn_attr_data);

/* Cluster-specific commands and parameters */
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_NEP             0x02
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_NS              0x01
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_S               0x00
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ERC_TMZ             0x03
#define ZBEE_ZCL_CSC_IAS_ZONE_C_ZER                 0x00
#define ZBEE_ZCL_CSC_IAS_ZONE_S_ZER                 0x01
#define ZBEE_ZCL_CSC_IAS_ZONE_S_ZSCN                0x00
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_CIR             0x00
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_FPS             0x01
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_SLPI            0x02
#define ZBEE_ZCL_CSC_POLL_CONTROL_C_SSPI            0x03
#define ZBEE_ZCL_CSC_POLL_CONTROL_S_CI              0x00
#define ZBEE_ZCL_CSC_THERMOSTAT_C_CWS               0x03
#define ZBEE_ZCL_CSC_THERMOSTAT_C_GWS               0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SRL               0x00
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS               0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_AV        0x80
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_FR        0x20
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_MO        0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SA        0x40
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_SU        0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TH        0x10
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_TU        0x04
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_DOW_WE        0x08
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_B          0x03
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_C          0x02
#define ZBEE_ZCL_CSC_THERMOSTAT_C_SWS_SP_H          0x01
#define ZBEE_ZCL_CSC_THERMOSTAT_S_GWSR              0x00

/*
 * Convert a given Zigbee time value to an nstime_t, for initializing
 * fields in a time_value_string.
 */
#define NSTIME_INIT_ZBEE(t) \
    NSTIME_INIT_SECS(((uint32_t)(t)) + EPOCH_DELTA_2000_01_01_00_00_00_UTC)

#endif /* PACKET_ZBEE_ZCL_H*/
