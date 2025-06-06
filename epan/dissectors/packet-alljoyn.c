/* packet-allJoyn.c
 * Routines for AllJoyn (AllJoyn.org) packet dissection
 * Copyright (c) 2013-2014, The Linux Foundation.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/ws_roundup.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>

void proto_register_AllJoyn(void);
void proto_reg_handoff_AllJoyn(void);

static dissector_handle_t alljoyn_handle_ns;
static dissector_handle_t alljoyn_handle_ardp;

#define ALLJOYN_NAME_SERVER_PORT      9956 /* IANA lists only UDP as being registered (dissector also uses TCP port) */
#define ALLJOYN_MESSAGE_PORT      9955

/* DBus limits array length to 2^26. AllJoyn limits it to 2^17 */
#define MAX_ARRAY_LEN 131072
/* DBus limits packet length to 2^27. AllJoyn limits it further to 2^17 + 4096 to allow for 2^17 payload */
#define MAX_PACKET_LEN (MAX_ARRAY_LEN + 4096)

/* The following are protocols within a frame.
   The actual value of the handle is set when the various fields are
   registered in proto_register_AllJoyn() with a call to
   proto_register_protocol().
*/
static int proto_AllJoyn_mess; /* The top level. Entire AllJoyn message protocol. */

/* These are Wireshark header fields. You can search/filter on these values. */
/* The initial byte sent when first connecting. */
static int hf_alljoyn_connect_byte_value;

/* SASL fields. */
static int hf_alljoyn_sasl_command;
static int hf_alljoyn_sasl_parameter;
/* Message header fields.
See http://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-messages
for details. */
static int hf_alljoyn_mess_header;              /* The complete header. */
static int hf_alljoyn_mess_header_endian;       /* 1st byte. */
static int hf_alljoyn_mess_header_type;         /* 2nd byte. */
static int hf_alljoyn_mess_header_flags;        /* 3rd byte. */
static int hf_alljoyn_mess_header_majorversion; /* 4th byte. */
static int hf_alljoyn_mess_header_body_length;  /* 1st uint32. */
static int hf_alljoyn_mess_header_serial;       /* 2nd uint32. */
static int hf_alljoyn_mess_header_header_length;/* 3rd uint32. AllJoyn extension. */

static int hf_alljoyn_mess_header_flags_no_reply;          /* Part of 3rd byte. */
static int hf_alljoyn_mess_header_flags_no_auto_start;     /* Part of 3rd byte. */
static int hf_alljoyn_mess_header_flags_allow_remote_msg;  /* Part of 3rd byte. */
static int hf_alljoyn_mess_header_flags_sessionless;       /* Part of 3rd byte. */
static int hf_alljoyn_mess_header_flags_global_broadcast;  /* Part of 3rd byte. */
static int hf_alljoyn_mess_header_flags_compressed;        /* Part of 3rd byte. */
static int hf_alljoyn_mess_header_flags_encrypted;         /* Part of 3rd byte. */
static int hf_alljoyn_mess_header_field;
static int hf_alljoyn_mess_header_fields;
static int hf_alljoyn_mess_body_header_fieldcode;
static int hf_alljoyn_mess_body_header_typeid;
static int hf_alljoyn_mess_body_array;
static int hf_alljoyn_mess_body_structure;
static int hf_alljoyn_mess_body_dictionary_entry;
static int hf_alljoyn_mess_body_parameters;
static int hf_alljoyn_mess_body_variant;
static int hf_alljoyn_mess_body_signature;
static int hf_alljoyn_mess_body_signature_length;

static int hf_alljoyn_boolean;
static int hf_alljoyn_uint8;
static int hf_alljoyn_int16;
static int hf_alljoyn_uint16;
static int hf_alljoyn_int32;
static int hf_alljoyn_handle;
static int hf_alljoyn_uint32;
static int hf_alljoyn_int64;
static int hf_alljoyn_uint64;
static int hf_alljoyn_double;
static int hf_padding;         /* Some fields are padded to an even number of 2, 4, or 8 bytes. */

#define MESSAGE_HEADER_FLAG_NO_REPLY_EXPECTED 0x01
#define MESSAGE_HEADER_FLAG_NO_AUTO_START     0x02
#define MESSAGE_HEADER_FLAG_ALLOW_REMOTE_MSG  0x04
#define MESSAGE_HEADER_FLAG_SESSIONLESS       0x10
#define MESSAGE_HEADER_FLAG_GLOBAL_BROADCAST  0x20
#define MESSAGE_HEADER_FLAG_COMPRESSED        0x40
#define MESSAGE_HEADER_FLAG_ENCRYPTED         0x80

/* Protocol identifiers. */
static int proto_AllJoyn_ns;  /* The top level. Entire AllJoyn Name Service protocol. */

static int hf_alljoyn_answer;
static int hf_alljoyn_isat_entry;
static int hf_alljoyn_isat_guid_string;

static int hf_alljoyn_ns_header;
static int hf_alljoyn_ns_sender_version;
static int hf_alljoyn_ns_message_version;
static int hf_alljoyn_ns_questions;
static int hf_alljoyn_ns_answers;
static int hf_alljoyn_ns_timer;

/* These are bit masks for version 0 "who has" records. */
/* These bits are deprecated and do not exist for version 1. */
#define WHOHAS_T 0x08
#define WHOHAS_U 0x04
#define WHOHAS_S 0x02
#define WHOHAS_F 0x01

static int hf_alljoyn_ns_whohas;
static int hf_alljoyn_ns_whohas_t_flag;   /* 0x8 -- TCP  */
static int hf_alljoyn_ns_whohas_u_flag;   /* 0x4 -- UDP  */
static int hf_alljoyn_ns_whohas_s_flag;   /* 0x2 -- IPV6 */
static int hf_alljoyn_ns_whohas_f_flag;   /* 0x1 -- IPV4 */
/* End of version 0 bit masks. */

static int hf_alljoyn_ns_whohas_count;    /* octet count of bus names */

/* Bitmasks common to v0 and v1 IS-AT messages. */
#define ISAT_C 0x10
#define ISAT_G 0x20

/* Bitmasks for v0 IS-AT messages. */
#define ISAT_F 0x01
#define ISAT_S 0x02
#define ISAT_U 0x04
#define ISAT_T 0x08

/* Bitmasks for v1 IS-AT messages. */
#define ISAT_U6 0x01
#define ISAT_R6 0x02
#define ISAT_U4 0x04
#define ISAT_R4 0x08

/* Bitmasks for v1 transports. */
#define TRANSPORT_LOCAL     0x0001  /* Local (same device) transport. */
#define TRANSPORT_BLUETOOTH 0x0002  /* Bluetooth transport. */
#define TRANSPORT_TCP       0x0004  /* Transport using TCP (same as TRANSPORT_WLAN). */
#define TRANSPORT_WWAN      0x0008  /* Wireless wide-area network transport. */
#define TRANSPORT_LAN       0x0010  /* Wired local-area network transport. */
#define TRANSPORT_ICE       0x0020  /* Transport using ICE protocol. */
#define TRANSPORT_WFD       0x0080  /* Transport using Wi-Fi Direct transport. */

/* Tree indexes common to v0 and v1 IS-AT messages. */
static int hf_alljoyn_ns_isat_g_flag;     /* 0x20 -- GUID present */
static int hf_alljoyn_ns_isat_c_flag;     /* 0x10 -- Complete */

/* Tree indexes for v0 IS-AT messages. */
static int hf_alljoyn_ns_isat_t_flag;     /* 0x8 -- TCP */
static int hf_alljoyn_ns_isat_u_flag;     /* 0x4 -- UDP */
static int hf_alljoyn_ns_isat_s_flag;     /* 0x2 -- IPV6 */
static int hf_alljoyn_ns_isat_f_flag;     /* 0x1 -- IPV4 */
static int hf_alljoyn_ns_isat_count;      /* octet count of bus names */
static int hf_alljoyn_ns_isat_port;       /* two octets of port number */
static int hf_alljoyn_ns_isat_ipv4;       /* four octets of IPv4 address */
static int hf_alljoyn_ns_isat_ipv6;       /* sixteen octets of IPv6 address */

/* Tree indexes for v1 IS-AT messages. */
static int hf_alljoyn_ns_isat_u6_flag;    /* 0x8 -- UDP IPV6 */
static int hf_alljoyn_ns_isat_r6_flag;    /* 0x4 -- TCP IPV6 */
static int hf_alljoyn_ns_isat_u4_flag;    /* 0x2 -- UDP IPV4 */
static int hf_alljoyn_ns_isat_r4_flag;    /* 0x1 -- TCP IPV4 */

static int hf_alljoyn_ns_isat_transport_mask; /* All bits of the transport mask. */

/* Individual bits of the mask. */
static int hf_alljoyn_ns_isat_transport_mask_local;    /* Local (same device) transport */
static int hf_alljoyn_ns_isat_transport_mask_bluetooth;/* Bluetooth transport */
static int hf_alljoyn_ns_isat_transport_mask_tcp;      /* Transport using TCP (same as TRANSPORT_WLAN) */
static int hf_alljoyn_ns_isat_transport_mask_wwan;     /* Wireless wide-area network transport */
static int hf_alljoyn_ns_isat_transport_mask_lan;      /* Wired local-area network transport */
static int hf_alljoyn_ns_isat_transport_mask_ice;      /* Transport using ICE protocol */
static int hf_alljoyn_ns_isat_transport_mask_wfd;      /* Transport using Wi-Fi Direct transport */

static int hf_alljoyn_string;
static int hf_alljoyn_string_size_8bit;    /* 8-bit size of string */
static int hf_alljoyn_string_size_32bit;   /* 32-bit size of string */
static int hf_alljoyn_string_data;         /* string characters */

/* Protocol identifiers. */
static int proto_AllJoyn_ardp;  /* The top level. Entire AllJoyn Reliable Datagram Protocol. */

#define ARDP_SYN_FIXED_HDR_LEN  28 /* Size of the fixed part for the ARDP connection packet header. */
#define ARDP_FIXED_HDR_LEN      34 /* Size of the fixed part for the ARDP header. */
#define ARDP_DATA_LENGTH_OFFSET  6 /* Offset into the ARDP header for the data length. */
#define ARDP_HEADER_LEN_OFFSET   1 /* Offset into the ARDP header for the actual length of the header. */

/* These are bit masks for ARDP flags. */
/* These bits are deprecated and do not exist for version 1. */
#define ARDP_SYN 0x01
#define ARDP_ACK 0x02
#define ARDP_EAK 0x04
#define ARDP_RST 0x08
#define ARDP_NUL 0x10
#define ARDP_UNUSED 0x20
#define ARDP_VER0 0x40
#define ARDP_VER1 0x80
#define ARDP_VER (ARDP_VER0 | ARDP_VER1)

static int hf_ardp_syn_flag;       /* 0x01 -- SYN */
static int hf_ardp_ack_flag;       /* 0x02 -- ACK */
static int hf_ardp_eak_flag;       /* 0x04 -- EAK */
static int hf_ardp_rst_flag;       /* 0x08 -- RST */
static int hf_ardp_nul_flag;       /* 0x10 -- NUL */
static int hf_ardp_unused_flag;    /* 0x20 -- UNUSED */
static int hf_ardp_version_field;  /* 0xc0 */

static int hf_ardp_hlen;   /* header length */
static int hf_ardp_src;    /* source port */
static int hf_ardp_dst;    /* destination port */
static int hf_ardp_dlen;   /* data length */
static int hf_ardp_seq;    /* sequence number */
static int hf_ardp_ack;    /* acknowledge number */
static int hf_ardp_ttl;    /* time to live (ms) */
static int hf_ardp_lcs;    /* last consumed sequence number */
static int hf_ardp_nsa;    /* next sequence to ack */
static int hf_ardp_fss;    /* fragment starting sequence number */
static int hf_ardp_fcnt;   /* fragment count */
static int hf_ardp_bmp;    /* EACK bitmap */
static int hf_ardp_segmax; /* The maximum number of outstanding segments the other side can send without acknowledgment. */
static int hf_ardp_segbmax;/* The maximum segment size we are willing to receive. */
static int hf_ardp_dackt;  /* Receiver's delayed ACK timeout. Used in TTL estimate prior to sending a message. */
static int hf_ardp_options;/* Options for the connection. Always Sequenced Delivery Mode (SDM). */

static expert_field ei_alljoyn_empty_arg;

/* These are the ids of the subtrees we will be creating */
static int ett_alljoyn_ns;    /* This is the top NS tree. */
static int ett_alljoyn_ns_header;
static int ett_alljoyn_ns_answers;
static int ett_alljoyn_ns_guid_string;
static int ett_alljoyn_ns_isat_entry;
static int ett_alljoyn_ns_string;
static int ett_alljoyn_whohas;
static int ett_alljoyn_string;
static int ett_alljoyn_isat_entry;
static int ett_alljoyn_mess;  /* This is the top message tree. */
static int ett_alljoyn_header;
static int ett_alljoyn_header_flags;
static int ett_alljoyn_mess_header_field;
static int ett_alljoyn_mess_header;
static int ett_alljoyn_mess_body_parameters;
static int ett_alljoyn_ardp;  /* This is the top ARDP tree. */

#define ROUND_TO_2BYTE(len) WS_ROUNDUP_2(len)
#define ROUND_TO_4BYTE(len) WS_ROUNDUP_4(len)
#define ROUND_TO_8BYTE(len) WS_ROUNDUP_8(len)

static const value_string endian_encoding_vals[] = {
    { 'B', "Big endian" },
    { 'l', "Little endian" },
    { 0, NULL },
};

#define MESSAGE_TYPE_INVALID        0
#define MESSAGE_TYPE_METHOD_CALL    1
#define MESSAGE_TYPE_METHOD_REPLY   2
#define MESSAGE_TYPE_ERROR_REPLY    3
#define MESSAGE_TYPE_SIGNAL         4

static const value_string message_header_encoding_vals[] = {
    { MESSAGE_TYPE_INVALID,      "Invalid type" },
    { MESSAGE_TYPE_METHOD_CALL,  "Method call" },
    { MESSAGE_TYPE_METHOD_REPLY, "Method reply with returned data" },
    { MESSAGE_TYPE_ERROR_REPLY,  "Error reply" },
    { MESSAGE_TYPE_SIGNAL,       "Signal emission" },
    { 0, NULL }
};

/*
 * The array at the end of the header contains header fields,
 * where each field is a 1-byte field code followed by a field value.
 * See also: http://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-messages
 *
 * In the D-Bus world these are the "field codes".
 * In the AllJoyn world these are called "field types".
 */
#define HDR_INVALID               0x00
#define HDR_OBJ_PATH              0x01
#define HDR_INTERFACE             0x02
#define HDR_MEMBER                0x03
#define HDR_ERROR_NAME            0x04
#define HDR_REPLY_SERIAL          0x05
#define HDR_DESTINATION           0x06
#define HDR_SENDER                0x07
#define HDR_SIGNATURE             0x08
#define HDR_HANDLES               0x09
#define HDR_TIMESTAMP             0x10 /* AllJoyn specific headers start at 0x10 */
#define HDR_TIME_TO_LIVE          0x11
#define HDR_COMPRESSION_TOKEN     0x12
#define HDR_SESSION_ID            0x13

static const value_string mess_header_field_encoding_vals[] = {
    { HDR_INVALID,           "Invalid" },           /* Not a valid field name (error if it appears in a message). */
    { HDR_OBJ_PATH,          "Object Path" },       /* The object to send a call to, or the object a signal
                                                       is emitted from. */
    { HDR_INTERFACE,         "Interface" },         /* The interface to invoke a method call on, or that a
                                                       signal is emitted from. Optional for method calls,
                                                       required for signals. */
    { HDR_MEMBER,            "Member" },            /* The member, either the method name or signal name. */
    { HDR_ERROR_NAME,        "Error Name" },        /* The name of the error that occurred, for errors. */
    { HDR_REPLY_SERIAL,      "Reply Serial" },      /* The serial number of the message this message is a reply to. */
    { HDR_DESTINATION,       "Destination" },       /* The name of the connection this message is intended for. */
    { HDR_SENDER,            "Sender" },            /* Unique name of the sending connection. */
    { HDR_SIGNATURE,         "Signature" },         /* The signature of the message body. */
    { HDR_HANDLES,           "Handles" },           /* The number of handles (Unix file descriptors) that
                                                       accompany the message.  */
    { HDR_TIMESTAMP,         "Time stamp" },
    { HDR_TIME_TO_LIVE,      "Time to live" },
    { HDR_COMPRESSION_TOKEN, "Compression token" },
    { HDR_SESSION_ID,        "Session ID" },
    { 0, NULL }
};

/* This is used to round up offsets into a packet to an even two byte
 * boundary from starting_offset.
 * @param current_offset is the current offset into the packet.
 * @param starting_offset is offset into the packet from the beginning of
 *        the message.
 * @returns the offset rounded up to the next even two byte boundary from
            start of the message.
 */
static int round_to_2byte(int current_offset,
                           int starting_offset)
{
    int length = current_offset - starting_offset;

    return starting_offset + ROUND_TO_2BYTE(length);
}

/* This is used to round up offsets into a packet to an even four byte
 * boundary from starting_offset.
 * @param current_offset is the current offset into the packet.
 * @param starting_offset is offset into the packet from the beginning of
 *        the message.
 * @returns the offset rounded up to the next even four byte boundary from
            start of the message.
 */
static int round_to_4byte(int current_offset,
                           int starting_offset)
{
    int length = current_offset - starting_offset;

    return starting_offset + ROUND_TO_4BYTE(length);
}

/* This is used to round up offsets into a packet to an even eight byte
 * boundary from starting_offset.
 * @param current_offset is the current offset into the packet.
 * @param starting_offset is offset into the packet from the beginning of
 *        the message.
 * @returns the offset rounded up to the next even eight byte boundary from
            start of the message.
 */
static int round_to_8byte(int current_offset,
                           int starting_offset)
{
    int length = current_offset - starting_offset;

    return starting_offset + ROUND_TO_8BYTE(length);
}

/* This is the maximum number of rounding bytes that is ever used.
 * This define is used for error checking. */
#define MAX_ROUND_TO_BYTES 7

/* This is called by dissect_AllJoyn_message() to handle the initial byte for
 * a connect message.
 * If it was the initial byte for a connect message and was handled then return
 * the number of bytes consumed out of the packet. If not an connect initial
 * byte message or unhandled return 0.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param offset is the offset into the packet to check for the connect message.
 * @param message_tree is the subtree that any connect data items should be added to.
 * @returns the offset into the packet that has successfully been handled or
 * the input offset value if it was not the connect initial byte of 0.
 */
static int
handle_message_connect(tvbuff_t    *tvb,
                       packet_info *pinfo,
                       int          offset,
                       proto_tree  *message_tree)
{
    uint8_t the_one_byte;

    the_one_byte = tvb_get_uint8(tvb, offset);

    if(0 == the_one_byte) {
        col_set_str(pinfo->cinfo, COL_INFO, "CONNECT-initial byte");

        /* Now add the value as a subtree to the initial byte. */
        proto_tree_add_item(message_tree, hf_alljoyn_connect_byte_value, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    return offset;
}

typedef struct _sasl_cmd
{
    const char *text;
    unsigned     length;
} sasl_cmd;

static const char CMD_AUTH[]     = "AUTH";
static const char CMD_CANCEL[]   = "CANCEL";
static const char CMD_BEGIN[]    = "BEGIN";
static const char CMD_DATA[]     = "DATA";
static const char CMD_ERROR[]    = "ERROR";
static const char CMD_REJECTED[] = "REJECTED";
static const char CMD_OK[]       = "OK";

#define MAX_SASL_COMMAND_LENGTH sizeof(CMD_REJECTED)
/* The 256 is just something I pulled out of the air. */
#define MAX_SASL_PACKET_LENGTH (MAX_SASL_COMMAND_LENGTH + 256)

static const sasl_cmd sasl_commands[] = {
    {CMD_AUTH,      G_N_ELEMENTS(CMD_AUTH) - 1},
    {CMD_CANCEL,    G_N_ELEMENTS(CMD_CANCEL) - 1},
    {CMD_BEGIN,     G_N_ELEMENTS(CMD_BEGIN) - 1},
    {CMD_DATA,      G_N_ELEMENTS(CMD_DATA) - 1},
    {CMD_ERROR,     G_N_ELEMENTS(CMD_ERROR) - 1},
    {CMD_REJECTED,  G_N_ELEMENTS(CMD_REJECTED) - 1},
    {CMD_OK,        G_N_ELEMENTS(CMD_OK) - 1},
};

static const int sasl_commands_count = G_N_ELEMENTS(sasl_commands);

static const sasl_cmd *
find_sasl_command(tvbuff_t *tvb,
                  int       offset)
{
    int command_index;

    for(command_index = 0; command_index < sasl_commands_count; command_index++) {
        const sasl_cmd *cmd;

        cmd = &sasl_commands[command_index];

        if(0 == tvb_strneql(tvb, offset, cmd->text, cmd->length)) {
            return cmd;
        }
    }

    return NULL;
}

/* Call this to test whether desegmentation is possible and if so correctly
 * set the pinfo structure with the applicable data.
 * @param pinfo contains information about the incoming packet.
 * @param next_offset is the offset into the tvbuff where it is desired to start processing next time.
 * @param addition_bytes_needed is the additional bytes required beyond what is already available.
 * @returns true if desegmentation is possible. false if not.
 */
static bool set_pinfo_desegment(packet_info *pinfo, int next_offset, int addition_bytes_needed)
{
    if(pinfo->can_desegment) {
        pinfo->desegment_offset = next_offset;
        pinfo->desegment_len = addition_bytes_needed;

        return true;
    }

    return false;
}

/* This is called by dissect_AllJoyn_message() to handle SASL messages.
 * If it was a SASL message and was handled then return the number of bytes
 * used (should be the entire packet). If not a SASL message or unhandled return 0.
 * If more bytes are needed then return the negative of the bytes expected.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param offset is the offset into the packet to start processing.
 * @param message_tree is the subtree that any connect data items should be added to.
 * @returns the offset into the packet that has successfully been handled or
 *         the input offset value if it was not a sasl message.
 */
static int
handle_message_sasl(tvbuff_t    *tvb,
                    packet_info *pinfo,
                    int          offset,
                    proto_tree  *message_tree)
{
    int             return_value = offset;
    const sasl_cmd *command;

    command = find_sasl_command(tvb, offset);

    if(command) {
        /* This gives us the offset into the buffer of the terminating character of
         * the command, the '\n'. + 1 to get the number of bytes used for the
         * command in the buffer. tvb_find_uint8() returns -1 if not found so the + 1
         * will result in a newline_offset of 0 if not found.
         */
        int newline_offset = tvb_find_uint8(tvb, offset + command->length, -1, '\n') + 1;

        /* If not found see if we should request another segment. */
        if(0 == newline_offset) {
            if((unsigned)tvb_captured_length_remaining(tvb, offset) < MAX_SASL_PACKET_LENGTH &&
                set_pinfo_desegment(pinfo, offset, DESEGMENT_ONE_MORE_SEGMENT)) {

                /* Return the length of the buffer we successfully parsed. */
                return_value = offset + command->length;
            } else {
                /* If we can't desegment then return 0 meaning we didn't do anything. */
                return_value = 0;
            }

            return return_value;
        }

        if(newline_offset > 0) {
            int length = command->length;

            col_add_fstr(pinfo->cinfo, COL_INFO, "SASL-%s", command->text);

            /* Add a subtree/row for the command. */
            proto_tree_add_item(message_tree, hf_alljoyn_sasl_command, tvb, offset, length, ENC_ASCII);
            offset += length;
            length = newline_offset - offset;

            /* Add a subtree for the parameter. */
            proto_tree_add_item(message_tree, hf_alljoyn_sasl_parameter, tvb, offset, length, ENC_ASCII);

            return_value = newline_offset;
        }
    }

    return return_value;
}

#define ENC_ALLJOYN_BAD_ENCODING 0xBADF00D

#define ENDIANNESS_OFFSET 0 /* The offset for endianness is always 0. */

/* This is called by handle_message_header_body() to get the endianness from
 * message headers.
 * @param tvb is the incoming network data buffer.
 * @param offset is the current offset into network data buffer.
 * @return The type of encoding, ENC_LITTLE_ENDIAN or ENC_BIG_ENDIAN, for
 * the message.
 */
static uint32_t
get_message_header_endianness(tvbuff_t *tvb,
                              int       offset)
{
    uint8_t endianness;
    unsigned  encoding;

    /* The endianness field. */
    endianness = tvb_get_uint8(tvb, offset + ENDIANNESS_OFFSET);

    switch(endianness)
    {
    case 'l':
        encoding = ENC_LITTLE_ENDIAN;
        break;
    case 'B':
        encoding = ENC_BIG_ENDIAN;
        break;
    default:
        encoding = ENC_ALLJOYN_BAD_ENCODING;
        break;
    }

    return encoding;
}

/* This is called by handle_message_field() to handle bytes of particular values
 * in messages.
 * @param tvb is the incoming network data buffer.
 * @param offset is the offset into the packet to start processing.
 * @param field_tree is the subtree that we connect data items to.
 * @param expected_value is the value the byte is expected to have.
 */
static void
handle_message_header_expected_byte(tvbuff_t   *tvb,
                                    int         offset,
                                    proto_tree *field_tree,
                                    uint8_t     expected_value)
{
    proto_item *item;
    uint8_t     byte_value;

    item = proto_tree_add_item(field_tree, hf_alljoyn_uint8, tvb, offset, 1, ENC_NA);
    byte_value = tvb_get_uint8(tvb, offset);

    if(expected_value == byte_value) {
        proto_item_set_text(item, "0x%02x byte", expected_value);
    } else {
        proto_item_set_text(item, "Expected '0x%02x byte' but found '0x%02x'", expected_value, byte_value);
    }
}

/*
 * Message argument types
 */
#define ARG_INVALID           '\0'
#define ARG_ARRAY             'a'    /* AllJoyn array container type */
#define ARG_BOOLEAN           'b'    /* AllJoyn boolean basic type */
#define ARG_DOUBLE            'd'    /* AllJoyn IEEE 754 double basic type */
#define ARG_SIGNATURE         'g'    /* AllJoyn signature basic type */
#define ARG_HANDLE            'h'    /* AllJoyn socket handle basic type */
#define ARG_INT32             'i'    /* AllJoyn 32-bit signed integer basic type */
#define ARG_INT16             'n'    /* AllJoyn 16-bit signed integer basic type */
#define ARG_OBJ_PATH          'o'    /* AllJoyn Name of an AllJoyn object instance basic type */
#define ARG_UINT16            'q'    /* AllJoyn 16-bit unsigned integer basic type */
#define ARG_STRING            's'    /* AllJoyn UTF-8 NULL terminated string basic type */
#define ARG_UINT64            't'    /* AllJoyn 64-bit unsigned integer basic type */
#define ARG_UINT32            'u'    /* AllJoyn 32-bit unsigned integer basic type */
#define ARG_VARIANT           'v'    /* AllJoyn variant container type */
#define ARG_INT64             'x'    /* AllJoyn 64-bit signed integer basic type */
#define ARG_BYTE              'y'    /* AllJoyn 8-bit unsigned integer basic type */
#define ARG_STRUCT            '('    /* AllJoyn struct container type */
#define ARG_DICT_ENTRY        '{'    /* AllJoyn dictionary or map container type - an array of key-value pairs */

static const value_string header_type_vals[] = {
    { ARG_INVALID,    "invalid" },
    { ARG_ARRAY,      "array" },
    { ARG_BOOLEAN,    "boolean" },
    { ARG_DOUBLE,     "IEEE 754 double" },
    { ARG_SIGNATURE,  "signature" },
    { ARG_HANDLE,     "socket handle" },
    { ARG_INT32,      "int32" },
    { ARG_INT16,      "int16" },
    { ARG_OBJ_PATH,   "object path" },
    { ARG_UINT16,     "uint16" },
    { ARG_STRING,     "string" },
    { ARG_UINT64,     "uint64" },
    { ARG_UINT32,     "uint32" },
    { ARG_VARIANT,    "variant" },
    { ARG_INT64,      "int64" },
    { ARG_BYTE,       "byte" },
    { ARG_STRUCT,     "structure" },
    { ARG_DICT_ENTRY, "dictionary" },
    { 0, NULL }
};

static int
pad_according_to_type(int offset, int field_starting_offset, int max_offset, uint8_t type)
{
    switch(type)
    {
    case ARG_BYTE:
        break;

    case ARG_DOUBLE:
    case ARG_UINT64:
    case ARG_INT64:
    case ARG_STRUCT:
    case ARG_DICT_ENTRY:
        offset = round_to_8byte(offset, field_starting_offset);
        break;

    case ARG_SIGNATURE:
        break;

    case ARG_HANDLE:
        break;

    case ARG_INT32:
    case ARG_UINT32:
    case ARG_BOOLEAN:
        offset = round_to_4byte(offset, field_starting_offset);
        break;

    case ARG_INT16:
    case ARG_UINT16:
        offset = round_to_2byte(offset, field_starting_offset);
        break;

    case ARG_STRING:
        break;

    case ARG_VARIANT:
        break;

    case ARG_OBJ_PATH:
        break;

    default:
        break;
    }

    if(offset > max_offset) {
        offset = max_offset;
    }

    return offset;
}

/* This is called by parse_arg to append the signature of structure or dictionary
 * to an item. This is complicated a bit by the fact that structures can be nested.
 * @param item is the item to append the signature data to.
 * @param signature points to the signature to be appended.
 * @param signature_max_length is the specified maximum length of this signature.
 * @param type_stop is the character when indicates the end of the signature.
 */
static void
append_struct_signature(proto_item   *item,
                        const uint8_t *signature,
                        int           signature_max_length,
                        const uint8_t type_stop)
{
    int    depth            = 0;
    uint8_t type_start;
    int    signature_length = 0;
    char c;

    proto_item_append_text(item, "%c", ' ');
    type_start = *signature;

    do {
        if(type_start == *signature) {
            depth++;
        }

        if(type_stop == *signature) {
            depth--;
        }

        c = *signature++;
        proto_item_append_text(item, "%c", g_ascii_isprint(c) ? c : '?');
    } while(depth > 0 && ++signature_length < signature_max_length);

    if(signature_length >= signature_max_length) {
        proto_item_append_text(item, "... Invalid signature!");
    }
}

/* This is called to advance the signature pointer to the end of the signature
 * it is currently pointing at. signature_length is decreased by the appropriate
 * amount before returning.
 * @param signature is a pointer to the signature. It could be simple data type
 * such as 'i', 'b', etc. In these cases *signature is advanced by 1 and
 * *signature_length is decreased by 1. Or it could be an array, structure, dictionary,
 * array of arrays or even more complex things. In these cases the advancement could
 * be much larger. For example with the signature "a(bdas)i" *signature will be advanced
 * to the 'i' and *signature_length will be set to '1'.
 * @param signature_length is a pointer to the length of the signature.
 */
static void
// NOLINTNEXTLINE(misc-no-recursion)
advance_to_end_of_signature(packet_info *pinfo, const uint8_t **signature, uint8_t *signature_length)
{
    bool done = false;
    int8_t current_type;
    int8_t end_type = ARG_INVALID;

    increment_dissection_depth(pinfo);

    while (*signature_length > 0 && **signature && !done) {
        current_type = *(++(*signature));
        --*signature_length;

        /* Were we looking for the end of a structure or dictionary? If so, did we find it? */
        if(end_type != ARG_INVALID) {
            if(end_type == current_type) {
                done = true; /* Found the end of the structure or dictionary. All done. */
            }

            continue;
        }

        switch(current_type)
        {
        case ARG_ARRAY:
            advance_to_end_of_signature(pinfo, signature, signature_length);
            break;
        case ARG_STRUCT:
            end_type = ')';
            advance_to_end_of_signature(pinfo, signature, signature_length);
            break;
        case ARG_DICT_ENTRY:
            end_type = '}';
            advance_to_end_of_signature(pinfo, signature, signature_length);
            break;

        case ARG_BYTE:
        case ARG_DOUBLE:
        case ARG_UINT64:
        case ARG_INT64:
        case ARG_SIGNATURE:
        case ARG_HANDLE:
        case ARG_INT32:
        case ARG_UINT32:
        case ARG_BOOLEAN:
        case ARG_INT16:
        case ARG_UINT16:
        case ARG_STRING:
        case ARG_VARIANT:
        case ARG_OBJ_PATH:
            done = true;
            break;

        default:    /* Unrecognized signature. Bail out. */
            done = true;
            break;
        }
    }
    decrement_dissection_depth(pinfo);
}

/* This is called to add a padding item. There is not padding done for each call made.
 * There is testing for the padding length which must be greater than zero. It's also possible,
 * in the case of bad packets, that the end of the padding is wrong so range checking is
 * also done. In the case of something being obviously wrong this function returns
 * without adding the padding item.
 * @param padding_start is the offset into tvb at which the (possible) padding starts.
 * @param padding_end is the offset into tvb at which the (possible) padding ends.
 * @param tvb is the incoming network data buffer.
 * @param tree is the tree to which the new item should be attached.
 */
static void add_padding_item(int padding_start, int padding_end, tvbuff_t *tvb, proto_tree *tree)
{
    if(padding_end > padding_start && padding_end < (int)tvb_reported_length(tvb)) {
        int padding_length = padding_end - padding_start;

        if (padding_length <= MAX_ROUND_TO_BYTES) {
            proto_tree_add_item(tree, hf_padding, tvb, padding_start, padding_length, ENC_NA);
        }
    }
}

/* This is called to handle a single typed argument. Recursion is used
 * to handle arrays and structures.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param header_item if not NULL, is appended with the text name of the data type.
 * @param encoding indicates big (ENC_BIG_ENDIAN) or little (ENC_LITTLE_ENDIAN)
 * @param offset is the offset into tvb to get the field from.
 * @param field_tree is the tree to which this argument should be attached.
 * @param is_reply_to if true, means this uint32 value should be used to update
 *         header_item and pinfo->cinfo with a special message.
 * @param type_id is the type of this argument.
 * @param field_code is the type of header, or HDR_INVALID if not used, which this
 *         arg is a part of. If field_code is HDR_MEMBER or HDR_SIGNATURE then
 *         pinfo->cinfo is updated with information.
 * @param signature is a pointer to the signature of the parameters. If type_id is
 *         ARG_SIGNATURE this is a return value for the caller to pass to the function
 *         that parses the parameters. If type_id is something like ARG_STRUCT then it points
 *         to the actual signature of the type.
 * @param signature_length is a pointer to the length of the signature and if type_id is
 *         ARG_SIGNATURE this is a return value for the caller to pass to the function
 *         that parses the parameters.
 * @param field_starting_offset is the offset at the beginning of the field that contains
 *         this arg. When rounding this starting_offset is used rather than the absolute offset.
 * @return The new offset into the buffer after removing the field code and value.
 *         the message or the packet length to stop further processing if "really bad"
 *         parameters come in.
 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
parse_arg(tvbuff_t      *tvb,
          packet_info   *pinfo,
          proto_item    *header_item,
          unsigned       encoding,
          int            offset,
          proto_tree    *field_tree,
          bool           is_reply_to,
          uint8_t        type_id,
          uint8_t        field_code,
          const uint8_t **signature,
          uint8_t       *signature_length,
          int            field_starting_offset)
{
    int length;
    int padding_start;
    int saved_offset = offset;

    switch(type_id)
    {
    case ARG_INVALID:
        offset = round_to_8byte(offset + 1, field_starting_offset);
        break;

    case ARG_ARRAY:      /* AllJoyn array container type */
        {
            proto_item   *item;
            proto_tree   *tree;
            const uint8_t *sig_saved;
            int           starting_offset;
            int           number_of_items      = 0;
            int           packet_length        = (int)tvb_reported_length(tvb);

            if(*signature == NULL || *signature_length < 1) {
                col_set_str(pinfo->cinfo, COL_INFO, "BAD DATA: An array argument needs a signature.");
                return tvb_reported_length(tvb);
            }

            /* *sig_saved will now be the element type after the 'a'. */
            sig_saved = (*signature) + 1;

            padding_start = offset;
            offset = round_to_4byte(offset, field_starting_offset);
            add_padding_item(padding_start, offset, tvb, field_tree);

            /* This is the length of the entire array in bytes but does not include the length field. */
            length = (int)tvb_get_uint32(tvb, offset, encoding);

            padding_start = offset + 4;
            starting_offset = pad_according_to_type(padding_start, field_starting_offset, packet_length, *sig_saved); /* Advance to the data elements. */

            if(length < 0 || length > MAX_ARRAY_LEN || starting_offset + length > packet_length) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: Array length (in bytes) is %d. Remaining packet length is %d.",
                    length, tvb_reported_length_remaining(tvb, starting_offset));
                return tvb_reported_length(tvb);
            }

            /* This item is the entire array including the length specifier plus any pad bytes. */
            item = proto_tree_add_item(field_tree, hf_alljoyn_mess_body_array, tvb, offset, (starting_offset-offset) + length, encoding);
            tree = proto_item_add_subtree(item, ett_alljoyn_mess_body_parameters);

            offset = starting_offset;
            add_padding_item(padding_start, offset, tvb, tree);

            if(0 == length) {
                advance_to_end_of_signature(pinfo, signature, signature_length);
            } else {
                uint8_t sig_length_saved = *signature_length - 1;

                increment_dissection_depth(pinfo);

                while((offset - starting_offset) < length) {
                    const uint8_t *sig_pointer;
                    uint8_t       remaining_sig_length;

                    number_of_items++;
                    sig_pointer = sig_saved;
                    remaining_sig_length = sig_length_saved;

                    offset = parse_arg(tvb,
                                       pinfo,
                                       header_item,
                                       encoding,
                                       offset,
                                       tree,
                                       is_reply_to,
                                       *sig_pointer,
                                       field_code,
                                       &sig_pointer,
                                       &remaining_sig_length,
                                       field_starting_offset);

                    /* Set the signature pointer to be just past the type just handled. */
                    *signature = sig_pointer;
                    *signature_length = remaining_sig_length;
                }
                decrement_dissection_depth(pinfo);
            }

            if(item) {
                proto_item_append_text(item, " of %d '%s' elements", number_of_items, format_char(pinfo->pool, *sig_saved));
            }
        }
        break;

    case ARG_BOOLEAN:    /* AllJoyn boolean basic type */
        padding_start = offset;
        offset = round_to_4byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_boolean, tvb, offset, 4, encoding);
        offset += 4;
        break;

    case ARG_DOUBLE:     /* AllJoyn IEEE 754 double basic type */
        padding_start = offset;
        offset = round_to_8byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_double, tvb, offset, 8, encoding);
        offset += 8;
        break;

    case ARG_SIGNATURE:  /* AllJoyn signature basic type */
        length = tvb_get_uint8(tvb, offset);

        if (length + 2 > tvb_reported_length_remaining(tvb, offset)) {
            int bytes_left = tvb_reported_length_remaining(tvb, offset);

            col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: Signature length is %d. Only %d bytes left in packet.",
                         length, bytes_left);
            return tvb_reported_length(tvb);
        }

        /* Include the terminating '/0'. */
        length++;

        proto_tree_add_item(field_tree, hf_alljoyn_mess_body_signature_length, tvb, offset, 1, encoding);
        offset += 1;

        /* Extract signature from tvb and return to caller. */
        /* XXX should this extract "length - 1" since we always expect /0? */
        proto_tree_add_item_ret_string(field_tree, hf_alljoyn_mess_body_signature, tvb, offset, length, ENC_ASCII|ENC_NA, pinfo->pool, signature);
        *signature_length = length;

        if(HDR_SIGNATURE == field_code) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", *signature);
        }

        offset += length;
        break;

    case ARG_HANDLE:     /* AllJoyn socket handle basic type. */
        padding_start = offset;
        offset = round_to_4byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_handle, tvb, offset, 4, encoding);
        offset += 4;
        break;

    case ARG_INT32:      /* AllJoyn 32-bit signed integer basic type. */
        padding_start = offset;
        offset = round_to_4byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_int32, tvb, offset, 4, encoding);
        offset += 4;
        break;

    case ARG_INT16:      /* AllJoyn 16-bit signed integer basic type. */
        padding_start = offset;
        offset = round_to_2byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_int16, tvb, offset, 2, encoding);
        offset += 2;
        break;

    case ARG_OBJ_PATH:   /* AllJoyn Name of an AllJoyn object instance basic type */
        length = tvb_get_uint32(tvb, offset, encoding) + 1;

        /* The + 4 is for the length specifier. Object paths may be of "any length"
           according to D-Bus spec. But there are practical limits. */
        if(length < 0 || length > MAX_ARRAY_LEN || length + 4 > tvb_reported_length_remaining(tvb, offset)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: Object path length is %d. Only %d bytes left in packet.",
                length, tvb_reported_length_remaining(tvb, offset + 4));
            return tvb_reported_length(tvb);
        }

        proto_tree_add_item(field_tree, hf_alljoyn_uint32, tvb, offset, 4, encoding);
        offset += 4;

        proto_tree_add_item(field_tree, hf_alljoyn_string_data, tvb, offset, length, ENC_ASCII);
        offset += length;
        break;

    case ARG_UINT16:     /* AllJoyn 16-bit unsigned integer basic type */
        padding_start = offset;
        offset = round_to_2byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_uint16, tvb, offset, 2, encoding);
        offset += 2;
        break;

    case ARG_STRING:     /* AllJoyn UTF-8 NULL terminated string basic type */
        {
        const uint8_t *member_name;

        padding_start = offset;
        offset = round_to_4byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_string_size_32bit, tvb, offset, 4, encoding);

        /* Get the length so we can display the string. */
        length = (int)tvb_get_uint32(tvb, offset, encoding);

        if(length < 0 || length > tvb_reported_length_remaining(tvb, offset)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: String length is %d. Remaining packet length is %d.",
                length, (int)tvb_reported_length_remaining(tvb, offset));
            return tvb_reported_length(tvb);
        }

        length += 1;    /* Include the '\0'. */
        offset += 4;

        proto_tree_add_item_ret_string(field_tree, hf_alljoyn_string_data, tvb, offset, length, ENC_UTF_8|ENC_NA, pinfo->pool, &member_name);

        if(HDR_MEMBER == field_code) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", member_name);
        }

        offset += length;
        }
        break;

    case ARG_UINT64:     /* AllJoyn 64-bit unsigned integer basic type */
        padding_start = offset;
        offset = round_to_8byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_uint64, tvb, offset, 8, encoding);
        offset += 8;
        break;

    case ARG_UINT32:     /* AllJoyn 32-bit unsigned integer basic type */
        padding_start = offset;
        offset = round_to_4byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        if(is_reply_to) {
            static const char format[] = " Replies to: %09u";
            uint32_t replies_to;

            replies_to = tvb_get_uint32(tvb, offset, encoding);
            col_append_fstr(pinfo->cinfo, COL_INFO, format, replies_to);

            if(header_item) {
                proto_item *item;

                item = proto_tree_add_item(field_tree, hf_alljoyn_uint32, tvb, offset, 4, encoding);
                proto_item_set_text(item, format + 1, replies_to);
            }
        } else {
            proto_tree_add_item(field_tree, hf_alljoyn_uint32, tvb, offset, 4, encoding);
        }

        offset += 4;
        break;

    case ARG_VARIANT:    /* AllJoyn variant container type */
        {
            proto_item   *item;
            proto_tree   *tree;
            const uint8_t *sig_saved;
            const uint8_t *sig_pointer;
            uint8_t       variant_sig_length;

            variant_sig_length = tvb_get_uint8(tvb, offset);
            length = variant_sig_length;

            if(length > tvb_reported_length_remaining(tvb, offset)) {
                int bytes_left = tvb_reported_length_remaining(tvb, offset);

                col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: Variant signature length is %d. Only %d bytes left in packet.",
                             length, bytes_left);
                offset = tvb_reported_length(tvb);
            }

            length += 1;    /* Include the terminating '\0'. */

            /* This length (4) will be updated later with the length of the entire variant object. */
            item = proto_tree_add_item(field_tree, hf_alljoyn_mess_body_variant, tvb, offset, 4, encoding);
            tree = proto_item_add_subtree(item, ett_alljoyn_mess_body_parameters);

            proto_tree_add_item(tree, hf_alljoyn_mess_body_signature_length, tvb, offset, 1, encoding);

            offset += 1;

            tree = proto_item_add_subtree(item, ett_alljoyn_mess_body_parameters);
            proto_tree_add_item_ret_string(tree, hf_alljoyn_mess_body_signature, tvb, offset, length, ENC_ASCII|ENC_NA, pinfo->pool, &sig_saved);

            offset += length;
            sig_pointer = sig_saved;

            increment_dissection_depth(pinfo);

            /* The signature of the variant has now been taken care of.  So now take care of the variant data. */
            while(((sig_pointer - sig_saved) < (length - 1)) && (tvb_reported_length_remaining(tvb, offset) > 0)) {
                proto_item_append_text(item, "%c", g_ascii_isprint(*sig_pointer) ? *sig_pointer : '?');

                offset = parse_arg(tvb, pinfo, header_item, encoding, offset, tree, is_reply_to,
                                   *sig_pointer, field_code, &sig_pointer, &variant_sig_length, field_starting_offset);

            }

            decrement_dissection_depth(pinfo);
            proto_item_append_text(item, "'");
            proto_item_set_end(item, tvb, offset);
        }
        break;

    case ARG_INT64:      /* AllJoyn 64-bit signed integer basic type */
        padding_start = offset;
        offset = round_to_8byte(offset, field_starting_offset);
        add_padding_item(padding_start, offset, tvb, field_tree);

        proto_tree_add_item(field_tree, hf_alljoyn_int64, tvb, offset, 8, encoding);
        offset += 8;
        break;

    case ARG_BYTE:       /* AllJoyn 8-bit unsigned integer basic type */

        proto_tree_add_item(field_tree, hf_alljoyn_uint8, tvb, offset, 1, encoding);
        offset += 1;
        break;

    case ARG_DICT_ENTRY: /* AllJoyn dictionary or map container type - an array of key-value pairs */
    case ARG_STRUCT:     /* AllJoyn struct container type */
        {
            proto_item *item;
            proto_tree *tree;
            int         hf;
            uint8_t     type_stop;

            if(type_id == ARG_STRUCT) {
                hf = hf_alljoyn_mess_body_structure;
                type_stop = ')';
            } else {
                hf = hf_alljoyn_mess_body_dictionary_entry;
                type_stop = '}';
            }

            if(*signature == NULL || *signature_length < 1) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: A %s argument needs a signature.", val_to_str_const(type_id, header_type_vals, "Unexpected type"));
                return tvb_reported_length(tvb);
            }

            /* This length (4) will be updated later with the length of the entire struct. */
            item = proto_tree_add_item(field_tree, hf, tvb, offset, 4, encoding);
            append_struct_signature(item, *signature, *signature_length, type_stop);
            tree = proto_item_add_subtree(item, ett_alljoyn_mess_body_parameters);

            padding_start = offset;
            offset = pad_according_to_type(offset, field_starting_offset, tvb_reported_length(tvb), type_id);
            add_padding_item(padding_start, offset, tvb, tree);

            (*signature)++; /* Advance past the '(' or '{'. */
            (*signature_length)--;

            increment_dissection_depth(pinfo);

            /* *signature should never be NULL but just make sure to avoid potential issues. */
            while(*signature && **signature && **signature != type_stop
                    && tvb_reported_length_remaining(tvb, offset) > 0) {
                offset = parse_arg(tvb,
                                   pinfo,
                                   header_item,
                                   encoding,
                                   offset,
                                   tree,
                                   is_reply_to,
                                   **signature,
                                   field_code,
                                   signature,
                                   signature_length,
                                   field_starting_offset);
            }

            decrement_dissection_depth(pinfo);

            proto_item_set_end(item, tvb, offset);
        }
        break;

    default:
        /* Just say we are done with this packet. */
        offset = tvb_reported_length(tvb);
        break;
    }

    if (*signature && *signature_length > 0 && ARG_ARRAY != type_id && HDR_INVALID == field_code) {
        (*signature)++;
        (*signature_length)--;
    }

    /* Make sure we never return something longer than the buffer for an offset. */
    if(offset > (int)tvb_reported_length(tvb)) {
        offset = (int)tvb_reported_length(tvb);
    } else if (offset == saved_offset) {
        /* The argument has a null size. Let's report the packet length to avoid an infinite loop. */
        /*expert_add_info(pinfo, header_item, &ei_alljoyn_empty_arg);*/
        proto_tree_add_expert(field_tree, pinfo, &ei_alljoyn_empty_arg, tvb, offset, 0);
        offset = (int)tvb_reported_length(tvb);
    }

    return offset;
}

/* This is called by handle_message_header_fields() to handle a single
 * message header field.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param header_tree is the subtree that we connect data items to.
 * @param encoding indicates big (ENC_BIG_ENDIAN) or little (ENC_LITTLE_ENDIAN)
 * @param offset is the offset into tvb to get the field from.
 *         endianness.
 * @param signature pointer to the signature of the parameters. This is a return
 *         value for the caller to pass to the function that parses the parameters.
 * @param signature_length pointer to the length of the signature. This is a return
 *         value for the caller to pass to the function that parses the parameters.
 * @return The new offset into the buffer after removing the field code and value.
 *         the message.
 */
static int
handle_message_field(tvbuff_t      *tvb,
                     packet_info   *pinfo,
                     proto_item    *header_tree,
                     unsigned       encoding,
                     int            offset,
                     const uint8_t **signature,
                     uint8_t       *signature_length)
{
    proto_tree *field_tree;
    proto_item *item, *field_item;
    uint8_t     field_code;
    uint8_t     type_id;
    bool        is_reply_to = false;
    int         starting_offset = offset;
    int         padding_start;

    field_code = tvb_get_uint8(tvb, offset);

    if(HDR_REPLY_SERIAL == field_code) {
        is_reply_to = true;
    }

    field_item = proto_tree_add_item(header_tree, hf_alljoyn_mess_header_field, tvb, offset, 1, ENC_NA);
    field_tree = proto_item_add_subtree(field_item, ett_alljoyn_mess_header_field);

    proto_tree_add_item(field_tree, hf_alljoyn_mess_body_header_fieldcode, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* We expect a byte of 0x01 here. */
    handle_message_header_expected_byte(tvb, offset, field_tree, 0x01);
    offset += 1;

    item = proto_tree_add_item(field_tree, hf_alljoyn_mess_body_header_typeid, tvb, offset, 1, ENC_ASCII);
    type_id = tvb_get_uint8(tvb, offset);
    offset += 1;

    /* We expect a byte of 0x00 here. */
    handle_message_header_expected_byte(tvb, offset, field_tree, 0x00);
    offset += 1;

    offset = parse_arg(tvb,
                       pinfo,
                       item,
                       encoding,
                       offset,
                       field_tree,
                       is_reply_to,
                       type_id,
                       field_code,
                       signature,
                       signature_length,
                       starting_offset);

    padding_start = offset;
    offset = round_to_8byte(offset, starting_offset);
    add_padding_item(padding_start, offset, tvb, field_tree);

    if(offset < 0 || offset > (int)tvb_reported_length(tvb)) {
        offset = (int)tvb_reported_length(tvb);
    }

    proto_item_set_end(field_tree, tvb, offset);

    return offset;
}

/* This is called by handle_message() to handle the message body.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param header_tree is the subtree that we connect data items to.
 * @param encoding indicates big (ENC_BIG_ENDIAN) or little (ENC_LITTLE_ENDIAN)
 * @param offset contains the offset into tvb for the start of the header fields.
 * @param header_length contains the length of the message fields.
 * @param signature_length contains the signature field length.
 */
static const uint8_t *
handle_message_header_fields(tvbuff_t    *tvb,
                             packet_info *pinfo,
                             proto_item  *header_tree,
                             unsigned    encoding,
                             int         offset,
                             uint32_t    header_length,
                             uint8_t     *signature_length)
{
    int         end_of_header;
    proto_item *item;
    proto_tree *tree;
    const uint8_t *signature = NULL;

    item = proto_tree_add_item(header_tree, hf_alljoyn_mess_header_fields, tvb, offset, header_length, ENC_NA);
    tree = proto_item_add_subtree(item, ett_alljoyn_mess_header);

    end_of_header = offset + header_length;

    while(offset < end_of_header) {
        offset = handle_message_field(tvb, pinfo, tree, encoding, offset, &signature, signature_length);
    }

    return signature;
}

/* This is called by handle_message() to handle the message body.
 * @param tvb is the incoming network data buffer.
 * @param header_tree is the subtree that we connect data items to.
 * @param encoding indicates big (ENC_BIG_ENDIAN) or little (ENC_LITTLE_ENDIAN)
 * @param offset contains the offset into tvb for the start of the parameters.
 * @param body_length contains the length of the body parameters.
 * @param signature the signature of the parameters.
 * @param signature_length contains the signature field length.
 */
static int
handle_message_body_parameters(tvbuff_t     *tvb,
                               packet_info  *pinfo,
                               proto_tree   *header_tree,
                               unsigned      encoding,
                               int           offset,
                               int32_t       body_length,
                               const uint8_t *signature,
                               uint8_t       signature_length)
{
    int         packet_length, end_of_body;
    proto_tree *tree;
    proto_item *item;
    const int   starting_offset = offset;

    packet_length = tvb_reported_length(tvb);

    /* Add a subtree/row for the message body parameters. */
    item = proto_tree_add_item(header_tree, hf_alljoyn_mess_body_parameters, tvb, offset, body_length, ENC_NA);
    tree = proto_item_add_subtree(item, ett_alljoyn_mess_body_parameters);

    end_of_body = offset + body_length;

    if(end_of_body > packet_length) {
        end_of_body = packet_length;
    }

    while(offset < end_of_body && signature_length > 0 && signature && *signature) {
        offset = parse_arg(tvb,
                           pinfo,
                           NULL,
                           encoding,
                           offset,
                           tree,    /* Add the args to the Parameters tree. */
                           false,
                           *signature,
                           HDR_INVALID,
                           &signature,
                           &signature_length,
                           starting_offset);
    }

    return offset;
}

#define MESSAGE_HEADER_LENGTH   16
#define TYPE_OFFSET              1
#define FLAGS_OFFSET             2
#define MAJORVERSION_OFFSET      3
#define BODY_LENGTH_OFFSET       4
#define SERIAL_OFFSET            8
#define HEADER_LENGTH_OFFSET    12

/* This is called by dissect_AllJoyn_message() to handle the actual message.
 * If it was a message with valid header and optional body then return true.
 * If not a valid message return false.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet.
 * @param offset is the offset into the packet to start processing.
 * @param message_tree is the subtree that any connect data items should be added to.
 * @param is_ardp is true if this is an ARDP packet.
 * @returns the offset into the packet that has successfully been handled or
 *         the input offset value if it was not a message header body.
 */
static int
handle_message_header_body(tvbuff_t    *tvb,
                           packet_info *pinfo,
                           int          offset,
                           proto_item  *message_tree,
                           bool        is_ardp)
{
    int           remaining_packet_length;
    const uint8_t *signature;
    uint8_t       signature_length = 0;
    proto_tree   *header_tree, *flag_tree;
    proto_item   *header_item, *flag_item;
    unsigned      encoding;
    int           packet_length_needed;
    int           header_length = 0, body_length = 0;

    remaining_packet_length = tvb_reported_length_remaining(tvb, offset);
    encoding = get_message_header_endianness(tvb, offset);

    if(ENC_ALLJOYN_BAD_ENCODING == encoding) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: Endian encoding '0x%0x'. Expected 'l' or 'B'",
            tvb_get_uint8(tvb, offset + ENDIANNESS_OFFSET));

        /* We are done with everything in this packet don't try anymore. */
        return offset + remaining_packet_length;
    }

    if(remaining_packet_length < MESSAGE_HEADER_LENGTH) {
        if(!set_pinfo_desegment(pinfo, offset, MESSAGE_HEADER_LENGTH - remaining_packet_length)) {
            col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: Remaining packet length is %d. Expected >= %d && <= %d",
            remaining_packet_length, MESSAGE_HEADER_LENGTH, MAX_PACKET_LEN);
        }

        return offset + remaining_packet_length;
    }

    header_length = tvb_get_uint32(tvb, offset + HEADER_LENGTH_OFFSET, encoding);
    body_length = tvb_get_uint32(tvb, offset + BODY_LENGTH_OFFSET, encoding);
    packet_length_needed = ROUND_TO_8BYTE(header_length) + body_length + MESSAGE_HEADER_LENGTH;

    /* ARDP (UDP) packets can't be desegmented by Wireshark and it is normal to see them in
     * fragments. Don't scare the user when they occur. Dissect as much as we easily can.
     * It should be possible to desegment TCIP packets. If not then something is wrong so tell
     * the user.
     */
    if(packet_length_needed > remaining_packet_length) {
        if(!set_pinfo_desegment(pinfo, offset, packet_length_needed - remaining_packet_length)) {
            if(!is_ardp) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "BAD DATA: Remaining packet length is %d. Expected %d",
                    remaining_packet_length, packet_length_needed);

                return offset + remaining_packet_length;
            }

            /* In this case we can't desegment but it is an ARDP message so we want to dissect
             * at least the header. Therefore we fall through to the header parsing code if the packet size
             * is greater than or equal to the header size. Otherwise we return and report what we know.
             */
            if (remaining_packet_length < header_length) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "Fragmented ARDP message: Remaining packet length is %d. Expected %d",
                    remaining_packet_length, packet_length_needed);
                return offset + remaining_packet_length;
            }
        }
        else {
            /* In this case we can desegment */
            return offset + remaining_packet_length;
        }
    }

    /* Add a subtree/row for the header. */
    header_item = proto_tree_add_item(message_tree, hf_alljoyn_mess_header, tvb, offset, MESSAGE_HEADER_LENGTH, ENC_NA);
    header_tree = proto_item_add_subtree(header_item, ett_alljoyn_header);

    proto_tree_add_item(header_tree, hf_alljoyn_mess_header_endian, tvb, offset + ENDIANNESS_OFFSET, 1, ENC_ASCII);
    proto_tree_add_item(header_tree, hf_alljoyn_mess_header_type, tvb, offset + TYPE_OFFSET, 1, ENC_NA);

    /* The flags byte. */
    flag_item = proto_tree_add_item(header_tree, hf_alljoyn_mess_header_flags,    tvb, offset + FLAGS_OFFSET, 1, ENC_NA);
    flag_tree = proto_item_add_subtree(flag_item, ett_alljoyn_header_flags);

    /* Now the individual bits. */
    proto_tree_add_item(flag_tree, hf_alljoyn_mess_header_flags_encrypted,        tvb, offset + FLAGS_OFFSET, 1, ENC_NA);
    proto_tree_add_item(flag_tree, hf_alljoyn_mess_header_flags_compressed,       tvb, offset + FLAGS_OFFSET, 1, ENC_NA);
    proto_tree_add_item(flag_tree, hf_alljoyn_mess_header_flags_global_broadcast, tvb, offset + FLAGS_OFFSET, 1, ENC_NA);
    proto_tree_add_item(flag_tree, hf_alljoyn_mess_header_flags_sessionless,      tvb, offset + FLAGS_OFFSET, 1, ENC_NA);
    proto_tree_add_item(flag_tree, hf_alljoyn_mess_header_flags_allow_remote_msg, tvb, offset + FLAGS_OFFSET, 1, ENC_NA);
    proto_tree_add_item(flag_tree, hf_alljoyn_mess_header_flags_no_auto_start,    tvb, offset + FLAGS_OFFSET, 1, ENC_NA);
    proto_tree_add_item(flag_tree, hf_alljoyn_mess_header_flags_no_reply,         tvb, offset + FLAGS_OFFSET, 1, ENC_NA);

    proto_tree_add_item(header_tree, hf_alljoyn_mess_header_majorversion,         tvb, offset + MAJORVERSION_OFFSET, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_alljoyn_mess_header_body_length,          tvb, offset + BODY_LENGTH_OFFSET, 4, encoding);

    proto_tree_add_item(header_tree, hf_alljoyn_mess_header_serial,               tvb, offset + SERIAL_OFFSET, 4, encoding);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Message %010u: '%s'", tvb_get_uint32(tvb, offset + SERIAL_OFFSET, encoding),
            val_to_str_const(tvb_get_uint8(tvb, offset + TYPE_OFFSET), message_header_encoding_vals, "Unexpected message type"));

    proto_tree_add_item(header_tree, hf_alljoyn_mess_header_header_length, tvb, offset + HEADER_LENGTH_OFFSET, 4, encoding);
    offset += MESSAGE_HEADER_LENGTH;
    packet_length_needed -= MESSAGE_HEADER_LENGTH;

    signature = handle_message_header_fields(tvb, pinfo, message_tree, encoding,
                                             offset, header_length, &signature_length);
    /* No need to call add_padding_item() after the following operation. It's not needed
     * because all message header fields widths are multiples of 8 and are padded as necessary.
     * Because the padding is taken care of in the individual message header field there is no
     * need for it here. The rounding here just gets the offset to the end of the last header
     * field and its (possible) padding.
     */
    offset += ROUND_TO_8BYTE(header_length);
    packet_length_needed -= ROUND_TO_8BYTE(header_length);
    remaining_packet_length = tvb_reported_length_remaining(tvb, offset);

    if (packet_length_needed > remaining_packet_length) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Fragmented ARDP message or bad data: Remaining packet length is %d. Expected %d",
            remaining_packet_length, packet_length_needed);
        return offset + remaining_packet_length;
    }

    if(body_length > 0 && signature != NULL && signature_length > 0) {
        offset = handle_message_body_parameters(tvb,
                                                pinfo,
                                                message_tree,
                                                encoding,
                                                offset,
                                                body_length,
                                                signature,
                                                signature_length);
    }

    return offset;
}

/* Test to see if this buffer contains something that might be an AllJoyn message.
 * @param tvb is the incoming network data buffer.
 * @param offset where to start parsing the buffer.
 * @param is_ardp If true then this is an ARDP packet which needs special treatment.
 * @returns true if probably an AllJoyn message.
 *          false if probably not an AllJoyn message.
 */
static bool
protocol_is_alljoyn_message(tvbuff_t *tvb, int offset, bool is_ardp)
{
    int length = tvb_captured_length(tvb);

    if(length < offset + 1)
        return false;

    /* There is no initial connect byte or SASL when using ARDP. */
    if(!is_ardp) {
        /* initial byte for a connect message. */
        if(tvb_get_uint8(tvb, offset) == 0)
            return true;

        if(find_sasl_command(tvb, offset) != NULL)
            return true;
    }

    if(get_message_header_endianness(tvb, offset) == ENC_ALLJOYN_BAD_ENCODING)
        return false;

    if((length < offset + 2) || (try_val_to_str(tvb_get_uint8(tvb, offset + 1), message_header_encoding_vals) == NULL))
        return false;

    return true;
}

/* This is called by Wireshark for packet types that are registered
 * in the proto_reg_handoff_AllJoyn() function. This function handles
 * the packets for the traffic on port 9955.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param tree is the tree data items should be added to.
 * @param offset is the offset into the already partial dissected buffer
 *         from dissect_AllJoyn_ardp() or 0 because this is just a bare
 *         AllJoyn message.
 * @return 0 if not AllJoyn message protocol, or
 *         the offset into the buffer we have successfully dissected (which
 *         should normally be the packet length), or
 *         the offset into the buffer we have dissected with
 *         pinfo->desegment_len == additional bytes needed from the next packet
 *         before we can dissect, or
 *         0 with pinfo->desegment_len == DESEGMENT_ONE_MORE_SEGMENT if another
 *         segment is needed, or
 *         packet_length if "really bad" parameters come in.
 */
static int
dissect_AllJoyn_message(tvbuff_t    *tvb,
                        packet_info *pinfo,
                        proto_tree  *tree,
                        int         offset)
{
    proto_item *message_item;
    proto_tree *message_tree;
    int         last_offset = -1;
    int         packet_length;
    bool        is_ardp = false;

    /* If called after dissecting the ARDP protocol. This is the only time the offset will not be zero. */
    if(offset != 0) {
        is_ardp = true;
    }

    pinfo->desegment_len = 0;
    packet_length = tvb_reported_length(tvb);

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ALLJOYN");

    /* Add a subtree covering the remainder of the packet */
    message_item = proto_tree_add_item(tree, proto_AllJoyn_mess, tvb, offset, -1, ENC_NA);
    message_tree = proto_item_add_subtree(message_item, ett_alljoyn_mess);

    /* Continue as long as we are making progress and we haven't finished with the packet. */
    while(offset < packet_length && offset > last_offset) {
        last_offset = offset;

        /* There is no initial connect byte or SASL when using ARDP. */
        if(!is_ardp) {
            offset = handle_message_connect(tvb, pinfo, offset, message_tree);

            if(offset >= packet_length) {
                break;
            }

            offset = handle_message_sasl(tvb, pinfo, offset, message_tree);

            if(offset >= packet_length) {
                break;
            }
        }

        offset = handle_message_header_body(tvb, pinfo, offset, message_tree, is_ardp);
    }

    return offset;
}

static void
ns_parse_questions(tvbuff_t *tvb, int* offset, proto_tree* alljoyn_tree, uint8_t questions, unsigned message_version)
{
    while(questions--) {
        proto_item *alljoyn_questions_ti;
        proto_tree *alljoyn_questions_tree;
        int         count;

        alljoyn_questions_ti = proto_tree_add_item(alljoyn_tree, hf_alljoyn_ns_whohas, tvb, *offset, 2, ENC_NA); /* "Who-Has Message" */
        alljoyn_questions_tree = proto_item_add_subtree(alljoyn_questions_ti, ett_alljoyn_whohas);

        if(0 == message_version) {
            proto_tree_add_item(alljoyn_questions_tree, hf_alljoyn_ns_whohas_t_flag, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(alljoyn_questions_tree, hf_alljoyn_ns_whohas_u_flag, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(alljoyn_questions_tree, hf_alljoyn_ns_whohas_s_flag, tvb, *offset, 1, ENC_NA);
            proto_tree_add_item(alljoyn_questions_tree, hf_alljoyn_ns_whohas_f_flag, tvb, *offset, 1, ENC_NA);
        }

        (*offset) += 1;

        proto_tree_add_item(alljoyn_questions_tree, hf_alljoyn_ns_whohas_count, tvb, *offset, 1, ENC_NA);
        count = tvb_get_uint8(tvb, *offset);
        (*offset) += 1;

        while(count--) {
            proto_item *alljoyn_bus_name_ti;
            proto_tree *alljoyn_bus_name_tree;
            int         bus_name_size = 0;

            bus_name_size = tvb_get_uint8(tvb, *offset);

            alljoyn_bus_name_ti = proto_tree_add_item(alljoyn_questions_tree, hf_alljoyn_string, tvb,
                *offset, 1 + bus_name_size, ENC_NA);
            alljoyn_bus_name_tree = proto_item_add_subtree(alljoyn_bus_name_ti, ett_alljoyn_ns_string);

            proto_tree_add_item(alljoyn_bus_name_tree, hf_alljoyn_string_size_8bit, tvb, *offset, 1, ENC_NA);
            (*offset) += 1;

            proto_tree_add_item(alljoyn_bus_name_tree, hf_alljoyn_string_data, tvb, *offset, bus_name_size, ENC_ASCII);
            (*offset) += bus_name_size;
        }

    }
}

/* The version 0 protocol looks like this:
 * Byte 0:
 *      Bit 0 (ISAT_F): If '1' indicates the daemon is listening on an IPv4
 *      address and that an IPv4 address is present in the message.  If '0'
 *      there is no IPv4 address present.
 *
 *      Bit 1 (ISAT_S): If '1' the responding daemon is listening on an IPv6
 *      address and that an IPv6 address is present in the message.  If '0'
 *      there is no IPv6 address present.
 *
 *      Bit 2 (ISAT_U): If '1' the daemon is listening on UDP.
 *
 *      Bit 3 (ISAT_T): If '1' the daemon is listening on TCP.
 *
 *      Bit 4 (ISAT_C): If '1' the list of StringData records is a complete
 *      list of all well-known names exported by the daemon.
 *
 *      Bit 5 (ISAT_G): If '1' a variable length daemon GUID string is present.
 *
 *      Bits 6-7: The message type of the IS-AT message.  Defined to be '01' (1).
 *
 * Byte 1 (Count): The number of StringData items.  Each StringData item
 * describes one well-known bus name supported by the daemon.
 *
 * Bytes 2-3 (Port): The port on which the daemon is listening.
 *
 * If the ISAT_F bit is set then the next four bytes is the IPv4 address on
 * which the daemon is listening.
 *
 * If the ISAT_S bit is set then the next 16 bytes is the IPv6 address on
 * which the daemon is listening.
 *
 * If the ISAT_G bit is set then the next data is daemon GUID StringData.
 *
 * The next data is a variable number of StringData records.
 */
static void
ns_parse_answers_v0(tvbuff_t *tvb, int* offset, proto_tree* alljoyn_tree, uint8_t answers)
{
    while(answers--) {
        proto_item *alljoyn_answers_ti;
        proto_tree *alljoyn_answers_tree;
        int         flags;
        int         count;

        alljoyn_answers_ti = proto_tree_add_item(alljoyn_tree, hf_alljoyn_answer, tvb, *offset, 2, ENC_NA);
        alljoyn_answers_tree = proto_item_add_subtree(alljoyn_answers_ti, ett_alljoyn_ns_answers);

        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_g_flag, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_c_flag, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_t_flag, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_u_flag, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_s_flag, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_f_flag, tvb, *offset, 1, ENC_NA);
        flags = tvb_get_uint8(tvb, *offset);
        (*offset) += 1;

        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_count,  tvb, *offset, 1, ENC_NA);
        count = tvb_get_uint8(tvb, *offset);
        (*offset) += 1;

        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_port,   tvb, *offset, 2, ENC_BIG_ENDIAN);
        (*offset) += 2;

        if(flags & ISAT_S) {
            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_ipv6, tvb, *offset, 16, ENC_NA);
            (*offset) += 16;
        }

        if(flags & ISAT_F) {
            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_ipv4, tvb, *offset, 4, ENC_BIG_ENDIAN);
            (*offset) += 4;
        }

        if(flags & ISAT_G) {
            proto_item *alljoyn_string_ti;
            proto_tree *alljoyn_string_tree;
            int         guid_size = 0;

            guid_size = tvb_get_uint8(tvb, *offset);

            alljoyn_string_ti = proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_isat_guid_string, tvb,
                *offset, 1 + guid_size, ENC_NA);
            alljoyn_string_tree = proto_item_add_subtree(alljoyn_string_ti, ett_alljoyn_ns_guid_string);

            proto_tree_add_item(alljoyn_string_tree, hf_alljoyn_string_size_8bit, tvb, *offset, 1, ENC_NA);
            (*offset) += 1;

            proto_tree_add_item(alljoyn_string_tree, hf_alljoyn_string_data, tvb, *offset, guid_size, ENC_ASCII);
            (*offset) += guid_size;
        }

        while(count--) {
            proto_item *alljoyn_entry_ti;
            proto_tree *alljoyn_entry_tree;
            proto_item *alljoyn_bus_name_ti;
            proto_tree *alljoyn_bus_name_tree;
            int         bus_name_size = tvb_get_uint8(tvb, *offset);

            alljoyn_entry_ti = proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_isat_entry, tvb,
                *offset, 1 + bus_name_size, ENC_NA);
            alljoyn_entry_tree = proto_item_add_subtree(alljoyn_entry_ti, ett_alljoyn_ns_isat_entry);

            alljoyn_bus_name_ti = proto_tree_add_item(alljoyn_entry_tree, hf_alljoyn_string, tvb, *offset,
                1 + bus_name_size, ENC_NA);
            alljoyn_bus_name_tree = proto_item_add_subtree(alljoyn_bus_name_ti, ett_alljoyn_string);

            proto_tree_add_item(alljoyn_bus_name_tree, hf_alljoyn_string_size_8bit, tvb, *offset, 1, ENC_NA);
            (*offset) += 1;

            proto_tree_add_item(alljoyn_bus_name_tree, hf_alljoyn_string_data, tvb, *offset, bus_name_size, ENC_ASCII);
            (*offset) += bus_name_size;
        }
    }
}

/* The version 1 protocol looks like this:
 * Byte 0:
 *      Bit 0 (ISAT_U6): If '1' then the IPv6 endpoint of an unreliable method
 *      (UDP) transport (IP address and port) is present.
 *
 *      Bit 1 (ISAT_R6): If '1' then the IPv6 endpoint of a reliable method
 *      (TCP) transport (IP address and port) is present.
 *
 *      Bit 2 (ISAT_U4): If '1' then the IPv4 endpoint of an unreliable method
 *      (UDP) transport (IP address and port) is present.
 *
 *      Bit 3 (ISAT_R4): If '1' then the IPv4 endpoint of a reliable method
 *      (TCP) transport (IP address and port) is present.
 *
 *      Bit 4 (ISAT_C): If '1' the list of StringData records is a complete
 *      list of all well-known names exported by the daemon.
 *
 *      Bit 5 (ISAT_G): If '1' a variable length daemon GUID string is present.
 *
 *      Bits 6-7: The message type of the IS-AT message.  Defined to be '01' (1).
 *
 * Byte 1 (Count): The number of StringData items.  Each StringData item
 * describes one well-known bus name supported by the daemon.
 *
 * Bytes 2-3 (TransportMask): The bit mask of transport identifiers that
 * indicates which AllJoyn transport is making the advertisement.
 *
 * If the ISAT_R4 bit is set then the next four bytes is the IPv4 address on
 * which the daemon is listening.
 *
 * If the ISAT_R4 bit is set then the next two bytes is the IPv4 port on
 * which the daemon is listening.
 *
 * If the ISAT_R6 bit is set then the next 16 bytes is the IPv6 address on
 * which the daemon is listening for TCP traffic.
 *
 * If the ISAT_R6 bit is set then the next two bytes is the IPv6 port on
 * which the daemon is listening for TCP traffic.
 *
 * If the ISAT_U6 bit is set then the next 16 bytes is the IPv6 address on
 * which the daemon is listening for UDP traffic.
 *
 * If the ISAT_U6 bit is set then the next two bytes is the IPv6 port on
 * which the daemon is listening for UDP traffic.
 *
 * If the ISAT_G bit is set then the next data is daemon GUID StringData.
 *
 * The next data is a variable number of StringData records.
 */
static void
ns_parse_answers_v1(tvbuff_t *tvb, int* offset, proto_tree* alljoyn_tree, uint8_t answers)
{
    while(answers--) {
        proto_item *alljoyn_answers_ti;
        proto_tree *alljoyn_answers_tree;
        int         flags;
        int         count;

        alljoyn_answers_ti = proto_tree_add_item(alljoyn_tree, hf_alljoyn_answer, tvb, *offset, 2, ENC_NA);
        alljoyn_answers_tree = proto_item_add_subtree(alljoyn_answers_ti, ett_alljoyn_ns_answers);

        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_g_flag,  tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_c_flag,  tvb, *offset, 1, ENC_NA);

        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_r4_flag, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_u4_flag, tvb, *offset, 1, ENC_NA);

        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_r6_flag, tvb, *offset, 1, ENC_NA);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_u6_flag, tvb, *offset, 1, ENC_NA);

        flags = tvb_get_uint8(tvb, *offset);
        (*offset) += 1;

        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_count,   tvb, *offset, 1, ENC_NA);
        count = tvb_get_uint8(tvb, *offset);
        (*offset) += 1;

        /* The entire transport mask. */
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask, tvb, *offset, 2, ENC_BIG_ENDIAN);

        /* The individual bits of the transport mask. */
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask_wfd,       tvb, *offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask_ice,       tvb, *offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask_lan,       tvb, *offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask_wwan,      tvb, *offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask_tcp,       tvb, *offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask_bluetooth, tvb, *offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_transport_mask_local,     tvb, *offset, 2, ENC_BIG_ENDIAN);

        (*offset) += 2;

        if(flags & ISAT_R4) {
            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_ipv4, tvb, *offset, 4, ENC_BIG_ENDIAN);
            (*offset) += 4;

            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
            (*offset) += 2;
        }

        if(flags & ISAT_U4) {
            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_ipv4, tvb, *offset, 4, ENC_BIG_ENDIAN);
            (*offset) += 4;

            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
            (*offset) += 2;
        }

        if(flags & ISAT_R6) {
            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_ipv6, tvb, *offset, 16, ENC_NA);
            (*offset) += 16;

            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
            (*offset) += 2;
        }

        if(flags & ISAT_U6) {
            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_ipv6, tvb, *offset, 16, ENC_NA);
            (*offset) += 16;

            proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_ns_isat_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
            (*offset) += 2;
        }

        if(flags & ISAT_G) {
            proto_item *alljoyn_string_ti;
            proto_tree *alljoyn_string_tree;
            int         guid_size;

            guid_size = tvb_get_uint8(tvb, *offset);

            alljoyn_string_ti = proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_isat_guid_string, tvb,
                *offset, 1 + guid_size, ENC_NA);
            alljoyn_string_tree = proto_item_add_subtree(alljoyn_string_ti, ett_alljoyn_ns_guid_string);

            proto_tree_add_item(alljoyn_string_tree, hf_alljoyn_string_size_8bit, tvb, *offset, 1, ENC_NA);
            (*offset) += 1;

            proto_tree_add_item(alljoyn_string_tree, hf_alljoyn_string_data, tvb, *offset, guid_size, ENC_ASCII);
            (*offset) += guid_size;
        }

        /* The string data records. */
        while(count--) {
            proto_item *alljoyn_entry_ti;
            proto_tree *alljoyn_entry_tree;

            proto_tree *alljoyn_bus_name_ti;
            proto_tree *alljoyn_bus_name_tree;
            int         bus_name_size = tvb_get_uint8(tvb, *offset);

            alljoyn_entry_ti = proto_tree_add_item(alljoyn_answers_tree, hf_alljoyn_isat_entry, tvb,
                *offset, 1 + bus_name_size, ENC_NA);
            alljoyn_entry_tree = proto_item_add_subtree(alljoyn_entry_ti, ett_alljoyn_isat_entry);

            alljoyn_bus_name_ti = proto_tree_add_item(alljoyn_entry_tree, hf_alljoyn_string, tvb, *offset,
                1 + bus_name_size, ENC_NA);
            alljoyn_bus_name_tree = proto_item_add_subtree(alljoyn_bus_name_ti, ett_alljoyn_string);

            proto_tree_add_item(alljoyn_bus_name_tree, hf_alljoyn_string_size_8bit, tvb, *offset, 1, ENC_NA);
            (*offset) += 1;

            proto_tree_add_item(alljoyn_bus_name_tree, hf_alljoyn_string_data, tvb, *offset, bus_name_size, ENC_ASCII);
            (*offset) += bus_name_size;
        }
    }
}

/* This is called by Wireshark for packet types that are registered
   in the proto_reg_handoff_AllJoyn() function. This function handles
   the packets for the name server traffic.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param tree is the tree data items should be added to.
 */
static int
dissect_AllJoyn_name_server(tvbuff_t    *tvb,
                            packet_info *pinfo,
                            proto_tree  *tree,
                            void *data   _U_)
{
    proto_item *alljoyn_item, *header_item;
    proto_tree *alljoyn_tree, *header_tree;
    uint8_t     questions, answers;
    uint8_t     version;
    int         offset = 0;

    /* This is name service traffic. Mark it as such at the top level. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ALLJOYN-NS");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Add a subtree covering the remainder of the packet */
    alljoyn_item = proto_tree_add_item(tree, proto_AllJoyn_ns, tvb, 0, -1, ENC_NA);
    alljoyn_tree = proto_item_add_subtree(alljoyn_item, ett_alljoyn_ns);

    /* Add the "header protocol" as a subtree from the AllJoyn Name Service Protocol. */
    header_item = proto_tree_add_item(alljoyn_tree, hf_alljoyn_ns_header, tvb, offset, 4, ENC_NA);
    header_tree = proto_item_add_subtree(header_item, ett_alljoyn_ns_header);

    /* The the sender and message versions as fields for the header protocol. */
    proto_tree_add_item(header_tree, hf_alljoyn_ns_sender_version, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(header_tree, hf_alljoyn_ns_message_version, tvb, offset, 1, ENC_NA);
    version = tvb_get_uint8(tvb, offset) & 0xF;
    offset += 1;

    col_add_fstr(pinfo->cinfo, COL_INFO, "VERSION %u", version);
    if(version > 1)
        col_append_str(pinfo->cinfo, COL_INFO, " (UNSUPPORTED)");

    proto_tree_add_item(header_tree, hf_alljoyn_ns_questions, tvb, offset, 1, ENC_NA);
    questions = tvb_get_uint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(header_tree, hf_alljoyn_ns_answers, tvb, offset, 1, ENC_NA);
    answers = tvb_get_uint8(tvb, offset);
    offset += 1;

    if(answers > 0)
        col_append_str(pinfo->cinfo, COL_INFO, " ISAT");

    if(questions > 0)
        col_append_str(pinfo->cinfo, COL_INFO, " WHOHAS");

    proto_tree_add_item(header_tree, hf_alljoyn_ns_timer, tvb, offset, 1, ENC_NA);
    offset += 1;


    if(tree) {  /* we are being asked for details */
        ns_parse_questions(tvb, &offset, alljoyn_tree, questions, version);

        switch(version) {
        case 0:
            ns_parse_answers_v0(tvb, &offset, alljoyn_tree, answers);
            break;
        case 1:
            ns_parse_answers_v1(tvb, &offset, alljoyn_tree, answers);
            break;
        default:
            /* XXX - expert info */
            /* This case being unsupported is reported in the column info by
             * the caller of this function. */
            break;
        }
    }

    return tvb_reported_length(tvb);
}

/* This is a container for the ARDP info and Wireshark tree information.
 */
typedef struct _alljoyn_ardp_tree_data
{
    int offset;
    bool syn;
    bool ack;
    bool eak;
    bool rst;
    bool nul;
    unsigned sequence;
    unsigned start_sequence;
    uint16_t fragment_count;
    int acknowledge;
    proto_tree *alljoyn_tree;
} alljoyn_ardp_tree_data;

/* This is called by dissect_AllJoyn_ardp() to read the header
 * and fill out most of tree_data.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 *         we update as we dissect the packet.
 * @param tree_data is the destination of the data..
 */
static void
ardp_parse_header(tvbuff_t *tvb,
                  packet_info *pinfo,
                  alljoyn_ardp_tree_data *tree_data)
{
    uint8_t     flags, header_length;
    int         eaklen, packet_length;
    uint16_t    data_length;

    packet_length = tvb_reported_length(tvb);

    flags = tvb_get_uint8(tvb, 0);

    tree_data->syn = (flags & ARDP_SYN) != 0;
    tree_data->ack = (flags & ARDP_ACK) != 0;
    tree_data->eak = (flags & ARDP_EAK) != 0;
    tree_data->rst = (flags & ARDP_RST) != 0;
    tree_data->nul = (flags & ARDP_NUL) != 0;

    /* The packet length has to be ARDP_HEADER_LEN_OFFSET long or protocol_is_ardp() would
       have returned false. Length is expressed in words so multiply by 2. */
    header_length = 2 * tvb_get_uint8(tvb, ARDP_HEADER_LEN_OFFSET);

    if(packet_length < ARDP_DATA_LENGTH_OFFSET + 2) {
        /* If we need more data before dissecting then communicate the number of additional bytes needed. */
        set_pinfo_desegment(pinfo, 0, ARDP_DATA_LENGTH_OFFSET + 2 - packet_length);

        /* Inform the caller we made it this far. Returning zero means we made no progress.
           This is the offset just past the last byte we successfully retrieved. */
        tree_data->offset = ARDP_HEADER_LEN_OFFSET + 1;

        return;
    }

    data_length = tvb_get_ntohs(tvb, ARDP_DATA_LENGTH_OFFSET);

    if(packet_length < header_length + data_length) {
        /* If we need more data before dissecting then communicate the number of additional bytes needed. */
        set_pinfo_desegment(pinfo, 0, header_length + data_length - packet_length);

        /* Inform the caller we made it this far. Returning zero it means we made no progress.
           This is the offset just past the last byte we successfully retrieved. */
        tree_data->offset = ARDP_DATA_LENGTH_OFFSET + 2;
        return;
    }

    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_syn_flag, tvb, tree_data->offset, 1, ENC_NA);
    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_ack_flag, tvb, tree_data->offset, 1, ENC_NA);
    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_eak_flag, tvb, tree_data->offset, 1, ENC_NA);
    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_rst_flag, tvb, tree_data->offset, 1, ENC_NA);
    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_nul_flag, tvb, tree_data->offset, 1, ENC_NA);
    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_unused_flag, tvb, tree_data->offset, 1, ENC_NA);
    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_version_field, tvb, tree_data->offset, 1, ENC_NA);

    tree_data->offset += 1;

    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_hlen, tvb, tree_data->offset, 1, ENC_NA);
    tree_data->offset += 1;

    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_src, tvb, tree_data->offset, 2, ENC_BIG_ENDIAN);
    tree_data->offset += 2;

    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_dst, tvb, tree_data->offset, 2, ENC_BIG_ENDIAN);
    tree_data->offset += 2;

    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_dlen, tvb, tree_data->offset, 2, ENC_BIG_ENDIAN);
    tree_data->offset += 2;

    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_seq, tvb, tree_data->offset, 4, ENC_BIG_ENDIAN);
    tree_data->sequence = tvb_get_ntohl(tvb, tree_data->offset);
    tree_data->offset += 4;

    proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_ack, tvb, tree_data->offset, 4, ENC_BIG_ENDIAN);
    tree_data->acknowledge = tvb_get_ntohl(tvb, tree_data->offset);
    tree_data->offset += 4;

    if(tree_data->syn) {
        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_segmax, tvb, tree_data->offset, 2, ENC_BIG_ENDIAN);
        tree_data->offset += 2;

        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_segbmax, tvb, tree_data->offset, 2, ENC_BIG_ENDIAN);
        tree_data->offset += 2;

        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_dackt, tvb, tree_data->offset, 4, ENC_BIG_ENDIAN);
        tree_data->offset += 4;

        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_options, tvb, tree_data->offset, 2, ENC_BIG_ENDIAN);
        tree_data->offset += 2;
    } else {
        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_ttl, tvb, tree_data->offset, 4, ENC_BIG_ENDIAN);
        tree_data->offset += 4;

        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_lcs, tvb, tree_data->offset, 4, ENC_BIG_ENDIAN);
        tree_data->offset += 4;

        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_nsa, tvb, tree_data->offset, 4, ENC_BIG_ENDIAN);
        tree_data->offset += 4;

        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_fss, tvb, tree_data->offset, 4, ENC_BIG_ENDIAN);
        tree_data->start_sequence = tvb_get_ntohl(tvb, tree_data->offset);
        tree_data->offset += 4;

        proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_fcnt, tvb, tree_data->offset, 2, ENC_BIG_ENDIAN);
        tree_data->fragment_count = tvb_get_ntohs(tvb, tree_data->offset);
        tree_data->offset += 2;

        eaklen = header_length - ARDP_FIXED_HDR_LEN;

        /* In the case of a corrupted packet eaklen could be < 0 and bad things could happen. */
        if(eaklen > 0) {
            if(tree_data->eak) {
                proto_tree_add_item(tree_data->alljoyn_tree, hf_ardp_bmp, tvb, tree_data->offset, eaklen, ENC_NA);
            }

            tree_data->offset += eaklen;
        }

        /* The data_length bytes, if any, will be passed on to the dissect_AllJoyn_message() handler. */
    }
}

/* Test to see if this buffer contains something that might be the AllJoyn ARDP protocol.
 * @param tvb is the incoming network data buffer.
 * @returns true if probably the AllJoyn ARDP protocol.
 *          false if probably not the AllJoyn ARDP protocol.
 */
static bool
protocol_is_ardp(tvbuff_t *tvb)
{
    uint8_t     flags, header_length;
    int length = tvb_captured_length(tvb);

    /* We must be able to get the byte value at this offset to determine if it is an ARDP protocol. */
    if(length < ARDP_HEADER_LEN_OFFSET + 1) {
        return false;
    }

    /* Length is expressed in words. */
    header_length = 2 * tvb_get_uint8(tvb, ARDP_HEADER_LEN_OFFSET);

    flags = tvb_get_uint8(tvb, 0);

    if((flags & ARDP_SYN) && header_length != ARDP_SYN_FIXED_HDR_LEN) {
        return false;
    }

    if(!(flags & ARDP_SYN) && header_length < ARDP_FIXED_HDR_LEN) {
        return false;
    }

    return true;
}

/* This is called by Wireshark for packet types that are registered
   in the proto_reg_handoff_AllJoyn() function. This function handles
   the packets for the ARDP and bare AllJoyn message protocols. A test
   for bare AllJoyn message protocol is done first. If it is an AllJoyn
   packet then only dissect_AllJoyn_message() is called to dissect the
   data. If protocol_is_alljoyn_message() returns false then a test for
   the ARDP protocol is performed. If it succeeds then ARDP dissection
   proceeds and may call dissect_AllJoyn_message() with the offset just
   past the ARDP protocol.
 * @param tvb is the incoming network data buffer.
 * @param pinfo contains information about the incoming packet which
 * we update as we dissect the packet.
 * @param tree is the tree data items should be added to.
 * @return 0 if not AllJoyn ARDP protocol, or
 *         the offset into the buffer we have dissected (which should normally
 *         be the packet length), or
 *         the offset into the buffer we have dissected with
 *         pinfo->desegment_len == additional bytes needed from the next packet
 *         before we can dissect.
 */
static int
dissect_AllJoyn_ardp(tvbuff_t    *tvb,
                     packet_info *pinfo,
                     proto_tree  *tree,
                     void *data   _U_)
{
    alljoyn_ardp_tree_data tree_data = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int packet_length = tvb_reported_length(tvb);
    proto_item *alljoyn_item = NULL;
    bool fragmentedPacket = false;

    if(protocol_is_alljoyn_message(tvb, 0, false)) {
        return dissect_AllJoyn_message(tvb, pinfo, tree, 0);
    }

    if(!protocol_is_ardp(tvb)) {
        return 0;
    }

    pinfo->desegment_len = 0;

    /* Add a subtree covering the remainder of the packet */
    alljoyn_item = proto_tree_add_item(tree, proto_AllJoyn_ardp, tvb, 0, -1, ENC_NA);
    tree_data.alljoyn_tree = proto_item_add_subtree(alljoyn_item, ett_alljoyn_ardp);

    ardp_parse_header(tvb, pinfo, &tree_data);

    /* Is desegmentation needed? */
    if(pinfo->desegment_len != 0) {
        return tree_data.offset;
    }

    if(tree_data.offset != 0) {
        /* This is ARDP traffic. Mark it as such at the top level. */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "ALLJOYN-ARDP");
    }

    if(tree_data.offset < packet_length) {
        int return_value = 0;

        /* We have dissected the ARDP portion. Is the remainder an AllJoyn message? */
        if(protocol_is_alljoyn_message(tvb, tree_data.offset, true)) {
            return_value = dissect_AllJoyn_message(tvb, pinfo, tree, tree_data.offset);
        }
        else {
            fragmentedPacket = !tree_data.syn && (tree_data.sequence > tree_data.start_sequence);
        }

        /* return_value will be the offset into the successfully parsed
         * buffer, the requested length of a reassembled packet (with pinfo->desegment_len
         * and pinfo->desegment_offset set appropriately), 0 if desegmentation is needed but
         * isn't available, or the initial value (tree_data.offset) if no progress was made.
         * If dissect_AllJoyn_message() made progress or is requesting desegmentation then
         * return leaving the column info as handled by the AllJoyn message dissector. If
         * not then we fall through to set the column info in this dissector.
         */
        if(return_value > tree_data.offset) {
            return return_value;
        }
    }

    col_clear(pinfo->cinfo, COL_INFO);

    col_append_str(pinfo->cinfo, COL_INFO, "flags:");
    if(tree_data.syn) {
        col_append_str(pinfo->cinfo, COL_INFO, " SYN");
    }
    if(tree_data.ack) {
        col_append_str(pinfo->cinfo, COL_INFO, " ACK");
    }
    if(tree_data.eak) {
        col_append_str(pinfo->cinfo, COL_INFO, " EAK");
    }
    if(tree_data.rst) {
        col_append_str(pinfo->cinfo, COL_INFO, " RST");
    }
    if(tree_data.nul) {
        col_append_str(pinfo->cinfo, COL_INFO, " NUL");
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " SEQ: %10u", tree_data.sequence);
    col_append_fstr(pinfo->cinfo, COL_INFO, " ACK: %10u", tree_data.acknowledge);

    if(fragmentedPacket) {
        unsigned fragment = (tree_data.sequence - tree_data.start_sequence) + 1;

        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Fragment %d of %d for a previous ALLJOYN message", fragment, tree_data.fragment_count);
    }

    return tree_data.offset;
}

void
proto_register_AllJoyn(void)
{
    expert_module_t* expert_alljoyn;

    /* A header field is something you can search/filter on.
     *
     * We create a structure to register our fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
     * The array below defines what elements we will be displaying. These
     * declarations are simply a definition Wireshark uses to determine the data
     * type, when we later dissect the packet.
     */
    static hf_register_info hf[] = {
        /******************
         * Wireshark header fields for the name service protocol.
         ******************/
        {&hf_alljoyn_ns_header,
         {"Header", "alljoyn.header",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_sender_version,
         {"Sender Version", "alljoyn.header.sendversion",
          FT_UINT8, BASE_DEC, NULL, 0xF0,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_message_version,
         {"Message Version", "alljoyn.header.messageversion",
          FT_UINT8, BASE_DEC, NULL, 0x0F,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_questions,
         {"Questions", "alljoyn.header.questions",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_answers,
         {"Answers", "alljoyn.header.answers",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_timer,
         {"Timer", "alljoyn.header.timer",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_alljoyn_ns_whohas,
         {"Who-Has Message", "alljoyn.whohas",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_whohas_t_flag,
         {"TCP", "alljoyn.whohas.T",
          FT_BOOLEAN, 8, NULL, WHOHAS_T,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_whohas_u_flag,
         {"UDP", "alljoyn.whohas.U",
          FT_BOOLEAN, 8, NULL, WHOHAS_U,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_whohas_s_flag,
         {"IPv6", "alljoyn.whohas.S",
          FT_BOOLEAN, 8, NULL, WHOHAS_S,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_whohas_f_flag,
         {"IPv4", "alljoyn.whohas.F",
          FT_BOOLEAN, 8, NULL, WHOHAS_F,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_whohas_count,
         {"Count", "alljoyn.whohas.count",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_alljoyn_answer,
         {"Is-At Message", "alljoyn.isat",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_isat_entry,
         {"Advertisement Entry", "alljoyn.isat_entry",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_isat_guid_string,
         {"GUID String", "alljoyn.isat_guid_string",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        /* Common to V0 and V1 IS-AT messages. */
        {&hf_alljoyn_ns_isat_g_flag,
         {"GUID", "alljoyn.isat.G",
          FT_BOOLEAN, 8, NULL, ISAT_G,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_c_flag,
         {"Complete", "alljoyn.isat.C",
          FT_BOOLEAN, 8, NULL, ISAT_C,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_count,
         {"Count", "alljoyn.isat.count",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_ipv6,
         {"IPv6 Address", "alljoyn.isat.ipv6",
          FT_IPv6, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_ipv4,
         {"IPv4 Address", "alljoyn.isat.ipv4",
          FT_IPv4, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        /* Version 0 IS-AT messages. */
        {&hf_alljoyn_ns_isat_t_flag,
         {"TCP", "alljoyn.isat.T",
          FT_BOOLEAN, 8, NULL, ISAT_T,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_u_flag,
         {"UDP", "alljoyn.isat.U",
          FT_BOOLEAN, 8, NULL, ISAT_U,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_s_flag,
         {"IPv6", "alljoyn.isat.S",
          FT_BOOLEAN, 8, NULL, ISAT_S,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_f_flag,
         {"IPv4", "alljoyn.isat.F",
          FT_BOOLEAN, 8, NULL, ISAT_F,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_port,
         {"Port", "alljoyn.isat.port",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },

        /* Version 1 IS-AT messages. */
        {&hf_alljoyn_ns_isat_u6_flag,
         {"IPv6 UDP", "alljoyn.isat.U6",
          FT_BOOLEAN, 8, NULL, ISAT_U6,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_r6_flag,
         {"IPv6 TCP", "alljoyn.isat.R6",
          FT_BOOLEAN, 8, NULL, ISAT_R6,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_u4_flag,
         {"IPv4 UDP", "alljoyn.isat.U4",
          FT_BOOLEAN, 8, NULL, ISAT_U4,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_r4_flag,
         {"IPv4 TCP", "alljoyn.isat.R4",
          FT_BOOLEAN, 8, NULL, ISAT_R4,
          NULL, HFILL}
        },

        {&hf_alljoyn_ns_isat_transport_mask,
         {"Transport Mask", "alljoyn.isat.TransportMask",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_alljoyn_ns_isat_transport_mask_local,
         {"Local Transport", "alljoyn.isat.TransportMask.Local",
          FT_BOOLEAN, 16, NULL, TRANSPORT_LOCAL,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_transport_mask_bluetooth,
         {"Bluetooth Transport", "alljoyn.isat.TransportMask.Bluetooth",
          FT_BOOLEAN, 16, NULL, TRANSPORT_BLUETOOTH,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_transport_mask_tcp,
         {"TCP Transport", "alljoyn.isat.TransportMask.TCP",
          FT_BOOLEAN, 16, NULL, TRANSPORT_TCP,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_transport_mask_wwan,
         {"Wireless WAN Transport", "alljoyn.isat.TransportMask.WWAN",
          FT_BOOLEAN, 16, NULL, TRANSPORT_WWAN,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_transport_mask_lan,
         {"Wired LAN Transport", "alljoyn.isat.TransportMask.LAN",
          FT_BOOLEAN, 16, NULL, TRANSPORT_LAN,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_transport_mask_ice,
         {"ICE protocol Transport", "alljoyn.isat.TransportMask.ICE",
          FT_BOOLEAN, 16, NULL, TRANSPORT_ICE,
          NULL, HFILL}
        },
        {&hf_alljoyn_ns_isat_transport_mask_wfd,
         {"Wi-Fi Direct Transport", "alljoyn.isat.TransportMask.WFD",
          FT_BOOLEAN, 16, NULL, TRANSPORT_WFD,
          NULL, HFILL}
        },

        /******************
         * Wireshark header fields for the message protocol.
         ******************/
        {&hf_alljoyn_connect_byte_value,
         {"Connect Initial Byte", "alljoyn.InitialByte",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },

        /*
         * Wireshark header fields for the SASL messages.
         */
        {&hf_alljoyn_sasl_command,
         {"SASL command", "alljoyn.SASL.command",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_sasl_parameter,
         {"SASL parameter", "alljoyn.SASL.parameter",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        /*
         * Wireshark header fields for the AllJoyn message header.
         */
        {&hf_alljoyn_mess_header,
         {"Message Header", "alljoyn.mess_header",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_endian,
         {"Endianness", "alljoyn.mess_header.endianness",
          FT_CHAR, BASE_HEX, VALS(endian_encoding_vals), 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_type,
         {"Message type", "alljoyn.mess_header.type",
          FT_UINT8, BASE_DEC, VALS(message_header_encoding_vals), 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_flags,
         {"Flags", "alljoyn.mess_header.flags",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}
        },

        /* Individual fields of the flags byte. */
        {&hf_alljoyn_mess_header_flags_no_reply,
         {"No reply expected", "alljoyn.mess_header.flags.noreply",
          FT_BOOLEAN, 8, NULL, MESSAGE_HEADER_FLAG_NO_REPLY_EXPECTED,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_flags_no_auto_start,
         {"No auto start", "alljoyn.mess_header.flags.noautostart",
          FT_BOOLEAN, 8, NULL, MESSAGE_HEADER_FLAG_NO_AUTO_START,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_flags_allow_remote_msg,
         {"Allow remote messages", "alljoyn.mess_header.flags.allowremotemessages",
          FT_BOOLEAN, 8, NULL, MESSAGE_HEADER_FLAG_ALLOW_REMOTE_MSG,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_flags_sessionless,
         {"Sessionless", "alljoyn.mess_header.flags.sessionless",
          FT_BOOLEAN, 8, NULL, MESSAGE_HEADER_FLAG_SESSIONLESS,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_flags_global_broadcast,
         {"Allow global broadcast", "alljoyn.mess_header.flags.globalbroadcast",
          FT_BOOLEAN, 8, NULL, MESSAGE_HEADER_FLAG_GLOBAL_BROADCAST,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_flags_compressed,
         {"Compressed", "alljoyn.mess_header.flags.compressed",
          FT_BOOLEAN, 8, NULL, MESSAGE_HEADER_FLAG_COMPRESSED,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_flags_encrypted,
         {"Encrypted", "alljoyn.mess_header.flags.encrypted",
          FT_BOOLEAN, 8, NULL, MESSAGE_HEADER_FLAG_ENCRYPTED,
          NULL, HFILL}
        },

        {&hf_alljoyn_mess_header_majorversion,
         {"Major version", "alljoyn.mess_header.majorversion",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_body_length,
         {"Body length", "alljoyn.mess_header.bodylength",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_serial,
         {"Serial number", "alljoyn.mess_header.serial",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_header_length,
         {"Header length", "alljoyn.mess_header.headerlength",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },

        {&hf_alljoyn_mess_header_fields,
         {"Header fields", "alljoyn.mess_header.fields",
          FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_header_field,
         {"Header field", "alljoyn.mess_header.field",
          FT_UINT8, BASE_HEX, VALS(mess_header_field_encoding_vals), 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_header_fieldcode,
         {"Field code", "alljoyn.message.fieldcode",
          FT_UINT8, BASE_HEX, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_header_typeid,
         {"Type ID", "alljoyn.message.typeid",
          FT_CHAR, BASE_HEX, VALS(header_type_vals), 0,
          NULL, HFILL}
        },

        {&hf_alljoyn_mess_body_parameters,
         {"Parameters", "alljoyn.parameters",
          FT_NONE, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_array,
         {"Array", "alljoyn.array",
          FT_NONE, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_structure,
         {"struct", "alljoyn.structure",
          FT_NONE, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_dictionary_entry,
         {"dictionary entry", "alljoyn.dictionary_entry",
          FT_NONE, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_variant,
         {"Variant '", "alljoyn.variant",
          FT_NONE, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_signature_length,
         {"Signature length", "alljoyn.parameter.signature_length",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_mess_body_signature,
         {"Signature", "alljoyn.parameter.signature",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

        {&hf_alljoyn_boolean,
         {"Boolean", "alljoyn.boolean",
          FT_BOOLEAN, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_uint8,
         {"Unsigned byte", "alljoyn.uint8",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_int16,
         {"Signed int16", "alljoyn.int16",
          FT_INT16, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_uint16,
         {"Unsigned int16", "alljoyn.uint16",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_handle,
         {"Handle", "alljoyn.handle",
          FT_UINT32, BASE_HEX, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_int32,
         {"Signed int32", "alljoyn.int32",
          FT_INT32, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_uint32,
         {"Unsigned int32", "alljoyn.uint32",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_int64,
         {"Signed int64", "alljoyn.int64",
          FT_INT64, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_uint64,
         {"Unsigned int64", "alljoyn.uint64",
          FT_UINT64, BASE_DEC, NULL, 0,
          NULL, HFILL}
        },
        {&hf_alljoyn_double,
         {"Double", "alljoyn.double",
          FT_DOUBLE, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },
        {&hf_padding,
         {"Padding", "alljoyn.padding",
          FT_BYTES, BASE_NONE, NULL, 0,
          NULL, HFILL}
        },

        /*
         * Strings are composed of a size and a data array.
         */
        {&hf_alljoyn_string,
         {"Bus Name", "alljoyn.string",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_string_size_8bit,
         {"String Size 8-bit", "alljoyn.string.size8bit",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_string_size_32bit,
         {"String Size 32-bit", "alljoyn.string.size32bit",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}
        },
        {&hf_alljoyn_string_data,
         {"String Data", "alljoyn.string.data",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },
        /******************
         * Wireshark header fields for the AllJoyn Reliable Data Protocol.
         ******************/
        {&hf_ardp_syn_flag,
         {"SYN", "ardp.hdr.SYN",
          FT_BOOLEAN, 8, NULL, ARDP_SYN,
          NULL, HFILL}
        },
        {&hf_ardp_ack_flag,
         {"ACK", "ardp.hdr.ACK",
          FT_BOOLEAN, 8, NULL, ARDP_ACK,
          NULL, HFILL}},
        {&hf_ardp_eak_flag,
         {"EAK", "ardp.hdr.EAK",
          FT_BOOLEAN, 8, NULL, ARDP_EAK,
          NULL, HFILL}},
        {&hf_ardp_rst_flag,
         {"RST", "ardp.hdr.RST",
          FT_BOOLEAN, 8, NULL, ARDP_RST,
          NULL, HFILL}},
        {&hf_ardp_nul_flag,
         {"NUL", "ardp.hdr.NUL",
          FT_BOOLEAN, 8, NULL, ARDP_NUL,
          NULL, HFILL}},
        {&hf_ardp_unused_flag,
         {"UNUSED", "ardp.hdr.UNUSED",
          FT_BOOLEAN, 8, NULL, ARDP_UNUSED,
          NULL, HFILL}},
        {&hf_ardp_version_field,
         {"VER", "ardp.hdr.ver",
          FT_UINT8, BASE_HEX, NULL, ARDP_VER,
          NULL, HFILL}},
        {&hf_ardp_hlen,
         {"Header Length", "ardp.hdr.hlen",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_src,
         {"Source Port", "ardp.hdr.src",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_dst,
         {"Destination Port", "ardp.hdr.dst",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_dlen,
         {"Data Length", "ardp.hdr.dlen",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_seq,
         {"Sequence", "ardp.hdr.seq",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_ack,
         {"Acknowledge", "ardp.hdr.ack",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_ttl,
         {"Time to Live", "ardp.hdr.ttl",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_lcs,
         {"Last Consumed Sequence", "ardp.hdr.lcs",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_nsa,
         {"Next Sequence to ACK", "ardp.hdr.nsa",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_fss,
         {"Fragment Starting Sequence", "ardp.hdr.fss",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_fcnt,
         {"Fragment Count", "ardp.hdr.fcnt",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_bmp,
         {"EACK Bitmap", "ardp.hdr.bmp",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_segmax,
         {"Segment Max", "ardp.hdr.segmentmax",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_segbmax,
         {"Segment Buffer Max", "ardp.hdr.segmentbmax",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_dackt,
         {"Receiver's delayed ACK timeout", "ardp.hdr.dackt",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_ardp_options,
         {"Options", "ardp.hdr.options",
          FT_UINT16, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},
    };

    static int *ett[] = {
        &ett_alljoyn_ns,
        &ett_alljoyn_ns_header,
        &ett_alljoyn_ns_answers,
        &ett_alljoyn_ns_guid_string,
        &ett_alljoyn_ns_isat_entry,
        &ett_alljoyn_ns_string,
        &ett_alljoyn_whohas,
        &ett_alljoyn_string,
        &ett_alljoyn_isat_entry,
        &ett_alljoyn_mess,
        &ett_alljoyn_header,
        &ett_alljoyn_header_flags,
        &ett_alljoyn_mess_header_field,
        &ett_alljoyn_mess_header,
        &ett_alljoyn_mess_body_parameters,
        &ett_alljoyn_ardp
    };

    static ei_register_info ei[] = {
        { &ei_alljoyn_empty_arg,
            { "alljoyn.empty_arg", PI_MALFORMED, PI_ERROR,
                "Argument is empty", EXPFILL }}
    };

    /* The following are protocols as opposed to data within a protocol. These appear
     * in Wireshark a divider/header between different groups of data.
     */

    /* Name service protocols. */                        /* name, short name, abbrev */
    proto_AllJoyn_ns = proto_register_protocol("AllJoyn Name Service Protocol", "AllJoyn NS", "ajns");
    alljoyn_handle_ns = register_dissector("ajns", dissect_AllJoyn_name_server, proto_AllJoyn_ns);

    /* Message protocols */
    proto_AllJoyn_mess = proto_register_protocol("AllJoyn Message Protocol", "AllJoyn", "aj");

    proto_register_field_array(proto_AllJoyn_ns, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_alljoyn = expert_register_protocol(proto_AllJoyn_mess);
    expert_register_field_array(expert_alljoyn, ei, array_length(ei));

    /* ARDP */                        /* name, short name, abbrev */
    proto_AllJoyn_ardp = proto_register_protocol("AllJoyn Reliable Datagram Protocol", "AllJoyn ARDP", "ardp");
    alljoyn_handle_ardp = register_dissector("ardp", dissect_AllJoyn_ardp, proto_AllJoyn_ardp);
}

void
proto_reg_handoff_AllJoyn(void)
{
    dissector_add_uint_with_preference("tcp.port", ALLJOYN_NAME_SERVER_PORT, alljoyn_handle_ns);
    dissector_add_uint_with_preference("tcp.port", ALLJOYN_MESSAGE_PORT, alljoyn_handle_ardp);

    dissector_add_uint_with_preference("udp.port", ALLJOYN_NAME_SERVER_PORT, alljoyn_handle_ns);

    /* The ARDP dissector will directly call the AllJoyn message dissector if needed.
     * This includes the case where there is no ARDP data. */
    dissector_add_uint_with_preference("udp.port", ALLJOYN_MESSAGE_PORT, alljoyn_handle_ardp);
}

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
