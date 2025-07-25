/* packet-zbee-security.c
 * Dissector helper routines for encrypted ZigBee frames.
 * By Owen Kirby <osk@exegin.com>; portions by Fred Fierling <fff@exegin.com>
 * Copyright 2009 Exegin Technologies Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*  Include Files */
#include "config.h"

#define WS_LOG_DOMAIN "zcl"

#include <wireshark.h>
#include <epan/packet.h>
#include <epan/exceptions.h>

#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/proto_data.h>

/* We require libgcrpyt in order to decrypt ZigBee packets. Without it the best
 * we can do is parse the security header and give up.
 */
#include <wsutil/wsgcrypt.h>
#include <wsutil/pint.h>

#include "packet-ieee802154.h"
#include "packet-zbee.h"
#include "packet-zbee-nwk.h"
#include "packet-zbee-aps.h"    /* for ZBEE_APS_CMD_KEY_LENGTH */
#include "packet-zbee-security.h"

void proto_reg_handoff_zbee_security(void);

/* Helper Functions */
static void        zbee_sec_key_hash(uint8_t *, uint8_t, uint8_t *);
static void        zbee_sec_make_nonce (zbee_security_packet *, uint8_t *);
static bool        zbee_sec_decrypt_payload(zbee_security_packet *, const char *, const char, uint8_t *,
        unsigned, unsigned, uint8_t *);
static bool        zbee_security_parse_key(const char *, uint8_t *, bool);

/* Field pointers. */
static int hf_zbee_sec_field;
static int hf_zbee_sec_level;
static int hf_zbee_sec_key_id;
static int hf_zbee_sec_nonce;
static int hf_zbee_sec_verified_fc;
static int hf_zbee_sec_counter;
static int hf_zbee_sec_src64;
static int hf_zbee_sec_key_seqno;
static int hf_zbee_sec_mic;
static int hf_zbee_sec_key;
static int hf_zbee_sec_key_origin;
static int hf_zbee_sec_decryption_key;

/* Subtree pointers. */
static int ett_zbee_sec;
static int ett_zbee_sec_control;

static expert_field ei_zbee_sec_encrypted_payload;
static expert_field ei_zbee_sec_encrypted_payload_sliced;
static expert_field ei_zbee_sec_extended_source_unknown;

/* Cached protocol identifiers */
static int proto_zbee_nwk;
static int proto_ieee802154;

static const value_string zbee_sec_key_names[] = {
    { ZBEE_SEC_KEY_LINK,        "Link Key" },
    { ZBEE_SEC_KEY_NWK,         "Network Key" },
    { ZBEE_SEC_KEY_TRANSPORT,   "Key-Transport Key" },
    { ZBEE_SEC_KEY_LOAD,        "Key-Load Key" },
    { 0, NULL }
};

#if 0
/* These aren't really used anymore, as ZigBee no longer includes them in the
 * security control field. If we were to display them all we would ever see is
 * security level 0.
 */
static const value_string zbee_sec_level_names[] = {
    { ZBEE_SEC_NONE,        "None" },
    { ZBEE_SEC_MIC32,       "No Encryption, 32-bit MIC" },
    { ZBEE_SEC_MIC64,       "No Encryption, 64-bit MIC" },
    { ZBEE_SEC_MIC128,      "No Encryption, 128-bit MIC" },
    { ZBEE_SEC_ENC,         "Encryption, No MIC" },
    { ZBEE_SEC_ENC_MIC32,   "Encryption, 32-bit MIC" },
    { ZBEE_SEC_ENC_MIC64,   "Encryption, 64-bit MIC" },
    { ZBEE_SEC_ENC_MIC128,  "Encryption, 128-bit MIC" },
    { 0, NULL }
};
#endif

/* The ZigBee security level, in enum_val_t for the security preferences. */
static const enum_val_t zbee_sec_level_enums[] = {
    { "None",       "No Security",                                      ZBEE_SEC_NONE },
    { "MIC32",      "No Encryption, 32-bit Integrity Protection",       ZBEE_SEC_MIC32 },
    { "MIC64",      "No Encryption, 64-bit Integrity Protection",       ZBEE_SEC_MIC64 },
    { "MIC128",     "No Encryption, 128-bit Integrity Protection",      ZBEE_SEC_MIC128 },
    { "ENC",        "AES-128 Encryption, No Integrity Protection",      ZBEE_SEC_ENC },
    { "ENC-MIC32",  "AES-128 Encryption, 32-bit Integrity Protection",  ZBEE_SEC_ENC_MIC32 },
    { "ENC-MIC64",  "AES-128 Encryption, 64-bit Integrity Protection",  ZBEE_SEC_ENC_MIC64 },
    { "ENC-MIC128", "AES-128 Encryption, 128-bit Integrity Protection", ZBEE_SEC_ENC_MIC128 },
    { NULL, NULL, 0 }
};

static int          gPREF_zbee_sec_level = ZBEE_SEC_ENC_MIC32;
static uat_t       *zbee_sec_key_table_uat;

static const value_string byte_order_vals[] = {
    { 0, "Normal"},
    { 1, "Reverse"},
    { 0, NULL }
};

/* UAT Key Entry */
typedef struct _uat_key_record_t {
    char     *string;
    uint8_t   byte_order;
    char     *label;
} uat_key_record_t;

UAT_CSTRING_CB_DEF(uat_key_records, string, uat_key_record_t)
UAT_VS_DEF(uat_key_records, byte_order, uat_key_record_t, uint8_t, 0, "Normal")
UAT_CSTRING_CB_DEF(uat_key_records, label, uat_key_record_t)

static GSList           *zbee_pc_keyring;
static uat_key_record_t *uat_key_records;
static unsigned          num_uat_key_records;

static void* uat_key_record_copy_cb(void* n, const void* o, size_t siz _U_) {
    uat_key_record_t* new_key = (uat_key_record_t *)n;
    const uat_key_record_t* old_key = (const uat_key_record_t *)o;

    new_key->string     = g_strdup(old_key->string);
    new_key->label      = g_strdup(old_key->label);
    new_key->byte_order = old_key->byte_order;

    return new_key;
}

static bool uat_key_record_update_cb(void* r, char** err) {
    uat_key_record_t* rec = (uat_key_record_t *)r;
    uint8_t key[ZBEE_SEC_CONST_KEYSIZE];

    if (rec->string == NULL) {
        *err = g_strdup("Key can't be blank");
        return false;
    } else {
        g_strstrip(rec->string);

        if (rec->string[0] != 0) {
            *err = NULL;
            if ( !zbee_security_parse_key(rec->string, key, rec->byte_order) ) {
                *err = ws_strdup_printf("Expecting %d hexadecimal bytes or\n"
                        "a %d character double-quoted string", ZBEE_SEC_CONST_KEYSIZE, ZBEE_SEC_CONST_KEYSIZE);
                return false;
            }
        } else {
            *err = g_strdup("Key can't be blank");
            return false;
        }
    }
    return true;
}

static void uat_key_record_free_cb(void*r) {
    uat_key_record_t* key = (uat_key_record_t *)r;

    g_free(key->string);
    g_free(key->label);
}

static void zbee_free_key_record(void *ptr)
{
    key_record_t *k = (key_record_t *)ptr;

    g_free(k->label);
    g_free(k);
}

static void uat_key_record_post_update(void) {
    unsigned        i;
    key_record_t    key_record;
    uint8_t         key[ZBEE_SEC_CONST_KEYSIZE];

    /* empty the key ring */
    if (zbee_pc_keyring) {
       g_slist_free_full(zbee_pc_keyring, zbee_free_key_record);
       zbee_pc_keyring = NULL;
    }

    /* Load the pre-configured slist from the UAT. */
    for (i=0; (uat_key_records) && (i<num_uat_key_records) ; i++) {
        if (zbee_security_parse_key(uat_key_records[i].string, key, uat_key_records[i].byte_order)) {
            key_record.frame_num = ZBEE_SEC_PC_KEY; /* means it's a user PC key */
            key_record.label = g_strdup(uat_key_records[i].label);
            memcpy(key_record.key, key, ZBEE_SEC_CONST_KEYSIZE);
            zbee_pc_keyring = g_slist_prepend(zbee_pc_keyring, g_memdup2(&key_record, sizeof(key_record_t)));
        }
    }
}

/*
 * Enable this macro to use libgcrypt's CBC_MAC mode for the authentication
 * phase. Unfortunately, this is broken, and I don't know why. However, using
 * the messier EBC mode (to emulate CCM*) still works fine.
 */
#if 0
#define ZBEE_SEC_USE_GCRYPT_CBC_MAC
#endif
/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_security_register
 *  DESCRIPTION
 *      Called by proto_register_zbee_nwk() to initialize the security
 *      dissectors.
 *  PARAMETERS
 *      module_t    zbee_prefs   - Prefs module to load preferences under.
 *  RETURNS
 *      none
 *---------------------------------------------------------------
 */
void zbee_security_register(module_t *zbee_prefs, int proto)
{
    static hf_register_info hf[] = {
        { &hf_zbee_sec_field,
          { "Security Control Field",   "zbee.sec.field", FT_UINT8, BASE_HEX, NULL,
            0x0, NULL, HFILL }},

        { &hf_zbee_sec_level,
          { "Security Level",          "zbee.sec.sec_level", FT_UINT8, BASE_HEX, NULL,
            ZBEE_SEC_CONTROL_LEVEL, NULL, HFILL }},

        { &hf_zbee_sec_key_id,
          { "Key Id",                    "zbee.sec.key_id", FT_UINT8, BASE_HEX, VALS(zbee_sec_key_names),
            ZBEE_SEC_CONTROL_KEY, NULL, HFILL }},

        { &hf_zbee_sec_nonce,
          { "Extended Nonce",         "zbee.sec.ext_nonce", FT_BOOLEAN, 8, NULL, ZBEE_SEC_CONTROL_NONCE,
            NULL, HFILL }},

        { &hf_zbee_sec_verified_fc,
          { "Require Verified Frame Counter", "zbee.sec.verified_fc", FT_UINT8, BASE_HEX, NULL,
            ZBEE_SEC_CONTROL_VERIFIED_FC, NULL, HFILL }},

        { &hf_zbee_sec_counter,
          { "Frame Counter",          "zbee.sec.counter", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_src64,
          { "Extended Source",                 "zbee.sec.src64", FT_EUI64, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_key_seqno,
          { "Key Sequence Number",    "zbee.sec.key_seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_mic,
          { "Message Integrity Code", "zbee.sec.mic", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_key,
          { "Key", "zbee.sec.key", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_key_origin,
          { "Key Origin", "zbee.sec.key.origin", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_zbee_sec_decryption_key,
          { "Key Label", "zbee.sec.decryption_key", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }}
    };

    static int *ett[] = {
        &ett_zbee_sec,
        &ett_zbee_sec_control
    };

    static ei_register_info ei[] = {
        { &ei_zbee_sec_encrypted_payload, { "zbee_sec.encrypted_payload", PI_UNDECODED, PI_WARN, "Encrypted Payload", EXPFILL }},
        { &ei_zbee_sec_encrypted_payload_sliced, { "zbee_sec.encrypted_payload_sliced", PI_UNDECODED, PI_WARN, "Encrypted payload, cut short when capturing - can't decrypt", EXPFILL }},
        { &ei_zbee_sec_extended_source_unknown, { "zbee_sec.extended_source_unknown", PI_PROTOCOL, PI_NOTE, "Extended Source: Unknown", EXPFILL }},
    };

    expert_module_t* expert_zbee_sec;

    static uat_field_t key_uat_fields[] = {
        UAT_FLD_CSTRING(uat_key_records, string, "Key",
                        "A 16-byte key in hexadecimal with optional dash-,\n"
                        "colon-, or space-separator characters, or a\n"
                        "a 16-character string in double-quotes."),
        UAT_FLD_VS(uat_key_records, byte_order, "Byte Order", byte_order_vals,
                        "Byte order of key."),
        UAT_FLD_CSTRING(uat_key_records, label, "Label", "User label for key."),
        UAT_END_FIELDS
    };

    /* If no prefs module was supplied, register our own. */
    if (zbee_prefs == NULL) {
        zbee_prefs = prefs_register_protocol(proto, NULL);
    }

    /*  Register preferences */
    prefs_register_enum_preference(zbee_prefs, "seclevel", "Security Level",
                 "Specifies the security level to use in the\n"
                 "decryption process. This value is ignored\n"
                 "for ZigBee 2004 and unsecured networks.",
                 &gPREF_zbee_sec_level, zbee_sec_level_enums, false);

    zbee_sec_key_table_uat = uat_new("Pre-configured Keys",
                               sizeof(uat_key_record_t),
                               "zigbee_pc_keys",
                               true,
                               &uat_key_records,
                               &num_uat_key_records,
                               UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                               NULL,  /* TODO: ptr to help manual? */
                               uat_key_record_copy_cb,
                               uat_key_record_update_cb,
                               uat_key_record_free_cb,
                               uat_key_record_post_update,
                               NULL,
                               key_uat_fields );

    prefs_register_uat_preference(zbee_prefs,
                                  "key_table",
                                  "Pre-configured Keys",
                                  "Pre-configured link or network keys.",
                                  zbee_sec_key_table_uat);

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_zbee_sec = expert_register_protocol(proto);
    expert_register_field_array(expert_zbee_sec, ei, array_length(ei));

} /* zbee_security_register */

void proto_reg_handoff_zbee_security(void)
{
    proto_zbee_nwk = proto_get_id_by_filter_name(ZBEE_PROTOABBREV_NWK);
    proto_ieee802154 = proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN);
}


/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_security_parse_key
 *  DESCRIPTION
 *      Parses a key string from left to right into a buffer with
 *      increasing (normal byte order) or decreasing (reverse byte
 *      order) address.
 *  PARAMETERS
 *      const char     *key_str - pointer to the string
 *      uint8_t        *key_buf - destination buffer in memory
 *      bool            big_end - fill key_buf with incrementing address
 *  RETURNS
 *      bool
 *---------------------------------------------------------------
 */
static bool
zbee_security_parse_key(const char *key_str, uint8_t *key_buf, bool byte_order)
{
    int             i, j;
    char            temp;
    bool            string_mode = false;

    /* Clear the key. */
    memset(key_buf, 0, ZBEE_SEC_CONST_KEYSIZE);
    if (key_str == NULL) {
        return false;
    }

    /*
     * Attempt to parse the key string. The key string must
     * be at least 16 pairs of hexidecimal digits with the
     * following optional separators: ':', '-', " ", or 16
     * alphanumeric characters after a double-quote.
     */
    if ( (temp = *key_str++) == '"') {
        string_mode = true;
        temp = *key_str++;
    }

    j = byte_order?ZBEE_SEC_CONST_KEYSIZE-1:0;
    for (i=ZBEE_SEC_CONST_KEYSIZE-1; i>=0; i--) {
        if ( string_mode ) {
            if ( g_ascii_isprint(temp) ) {
                key_buf[j] = temp;
                temp = *key_str++;
            } else {
                return false;
            }
        }
        else {
            /* If this character is a separator, skip it. */
            if ( (temp == ':') || (temp == '-') || (temp == ' ') ) temp = *(key_str++);

            /* Process a nibble. */
            if ( g_ascii_isxdigit (temp) ) key_buf[j] = g_ascii_xdigit_value(temp)<<4;
            else return false;

            /* Get the next nibble. */
            temp = *(key_str++);

            /* Process another nibble. */
            if ( g_ascii_isxdigit (temp) ) key_buf[j] |= g_ascii_xdigit_value(temp);
            else return false;

            /* Get the next nibble. */
            temp = *(key_str++);
        }

        /* Move key_buf pointer */
        if ( byte_order ) {
            j--;
        } else {
            j++;
        }

    } /* for */

    /* If we get this far, then the key was good. */
    return true;
} /* zbee_security_parse_key */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_zbee_secure
 *  DESCRIPTION
 *      Dissects and decrypts secured ZigBee frames.
 *
 *      Will return a valid tvbuff only if security processing was
 *      successful. If processing fails, then this function will
 *      handle internally and return NULL.
 *  PARAMETERS
 *      tvbuff_t    *tvb    - pointer to buffer containing raw packet.
 *      packet_info *pinfo  - pointer to packet information fields
 *      proto_tree  *tree   - pointer to data tree Wireshark uses to display packet.
 *      unsigned    offset  - pointer to the start of the auxiliary security header.
 *      uint64_t    src64   - extended source address, or 0 if unknown.
 *  RETURNS
 *      tvbuff_t *
 *---------------------------------------------------------------
 */
tvbuff_t *
dissect_zbee_secure(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree, unsigned offset)
{
    proto_tree     *sec_tree;

    zbee_security_packet    packet;
    unsigned        mic_len;
    int             payload_len;
    tvbuff_t       *payload_tvb;

    proto_item         *ti;
    proto_item         *key_item;
    uint8_t            *enc_buffer;
    uint8_t            *dec_buffer;
    bool                decrypted;
    GSList            **nwk_keyring;
    GSList             *GSList_i;
    key_record_t       *key_rec = NULL;
    zbee_nwk_hints_t   *nwk_hints;
    ieee802154_hints_t *ieee_hints;
    ieee802154_map_rec *map_rec = NULL;

    static int * const sec_flags[] = {
        &hf_zbee_sec_level,
        &hf_zbee_sec_key_id,
        &hf_zbee_sec_nonce,
        &hf_zbee_sec_verified_fc,
        NULL
    };

    /* Init */
    memset(&packet, 0, sizeof(zbee_security_packet));

    /* Get pointers to any useful frame data from lower layers */
    nwk_hints = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_zbee_nwk, 0);
    ieee_hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ieee802154, 0);

    /* Create a subtree for the security information. */
    sec_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_zbee_sec, NULL, "ZigBee Security Header");

    /*  Get and display the Security control field */
    packet.control  = tvb_get_uint8(tvb, offset);

    /* Patch the security level. */
    packet.control &= ~ZBEE_SEC_CONTROL_LEVEL;
    packet.control |= (ZBEE_SEC_CONTROL_LEVEL & gPREF_zbee_sec_level);

    /*
     * Eww, I think I just threw up a little...  ZigBee requires this field
     * to be patched before computing the MIC, but we don't have write-access
     * to the tvbuff. So we need to allocate a copy of the whole thing just
     * so we can fix these 3 bits. Memory allocated by tvb_memdup(pinfo->pool,...)
     * is automatically freed before the next packet is processed.
     */
    enc_buffer = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, tvb_captured_length(tvb));
    /*
     * Override the const qualifiers and patch the security level field, we
     * know it is safe to overide the const qualifiers because we just
     * allocated this memory via tvb_memdup(pinfo->pool,...).
     */
    enc_buffer[offset] = packet.control;
    packet.level    = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_LEVEL);
    packet.key_id   = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_KEY);
    packet.nonce    = zbee_get_bit_field(packet.control, ZBEE_SEC_CONTROL_NONCE);

    proto_tree_add_bitmask(sec_tree, tvb, offset, hf_zbee_sec_field, ett_zbee_sec_control, sec_flags, ENC_NA);
    offset += 1;

    /* Get and display the frame counter field. */
    packet.counter = tvb_get_letohl(tvb, offset);
    proto_tree_add_uint(sec_tree, hf_zbee_sec_counter, tvb, offset, 4, packet.counter);
    offset += 4;

    if (packet.nonce) {
        /* Get and display the source address of the device that secured this payload. */
        packet.src64 = tvb_get_letoh64(tvb, offset);
        proto_tree_add_item(sec_tree, hf_zbee_sec_src64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
#if 1
        if (!pinfo->fd->visited) {
            switch ( packet.key_id ) {
                case ZBEE_SEC_KEY_LINK:
                if (nwk_hints && ieee_hints) {
                    /* Map this long address with the nwk layer short address. */
                    nwk_hints->map_rec = ieee802154_addr_update(&zbee_nwk_map, nwk_hints->src,
                            ieee_hints->src_pan, packet.src64, pinfo->current_proto, pinfo->num);
                }
                break;

                case ZBEE_SEC_KEY_NWK:
                if (ieee_hints) {
                    /* Map this long address with the ieee short address. */
                    ieee_hints->map_rec = ieee802154_addr_update(&zbee_nwk_map, ieee_hints->src16,
                        ieee_hints->src_pan, packet.src64, pinfo->current_proto, pinfo->num);
                    if (nwk_hints && !nwk_hints->map_rec) {
                        /* Map this long address with the nwk layer short address. */
                        nwk_hints->map_rec = ieee802154_addr_update(&zbee_nwk_map, nwk_hints->src,
                                ieee_hints->src_pan, packet.src64, pinfo->current_proto, pinfo->num);
                    }
                }
                break;

                /* We ignore the extended source addresses used to encrypt payloads with these
                 * types of keys, because they can emerge from APS tunnels created by nodes whose
                 * short address is not recorded in the packet. */
                case ZBEE_SEC_KEY_TRANSPORT:
                case ZBEE_SEC_KEY_LOAD:
                break;
            }
        }
#endif
        offset += 8;
    }
    else {
        /* Look for a source address in hints */
        switch ( packet.key_id ) {
            case ZBEE_SEC_KEY_NWK:
                /* use the ieee extended source address for NWK decryption */
                if ( ieee_hints && (map_rec = ieee_hints->map_rec) )
                    packet.src64 = map_rec->addr64;
                else
                    proto_tree_add_expert(sec_tree, pinfo, &ei_zbee_sec_extended_source_unknown, tvb, 0, 0);
                break;

            default:
                /* use the nwk extended source address for APS decryption */
                if ( nwk_hints && (map_rec = nwk_hints->map_rec) )
                {
                    switch (nwk_hints->relay_type)
                    {
                        case ZBEE_APS_RELAY_DOWNSTREAM:
                        {
                            ieee802154_short_addr   addr16;
                            /* In case of downstream Relay must use long address
                             * of ZC. Seek for it in the address translation
                             * table. */
                            addr16.addr = 0;
                            addr16.pan = ieee_hints->src_pan;
                            map_rec = (ieee802154_map_rec *) g_hash_table_lookup(zbee_nwk_map.short_table, &addr16);
                            if (map_rec)
                            {
                                packet.src64 = map_rec->addr64;
                            }
                        }
                        break;
                        case ZBEE_APS_RELAY_UPSTREAM:
                            /* In case of downstream Relay must use long address of Joiner from the Relay message */
                            packet.src64 = nwk_hints->joiner_addr64;
                            break;
                        default:
                            packet.src64 = map_rec->addr64;
                            break;
                    }
                }
                else
                    proto_tree_add_expert(sec_tree, pinfo, &ei_zbee_sec_extended_source_unknown, tvb, 0, 0);
                break;
        }
    }

    if (packet.key_id == ZBEE_SEC_KEY_NWK) {
        /* Get and display the key sequence number. */
        packet.key_seqno = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(sec_tree, hf_zbee_sec_key_seqno, tvb, offset, 1, packet.key_seqno);
        offset += 1;
    }

    /* Determine the length of the MIC. */
    switch (packet.level) {
        case ZBEE_SEC_ENC:
        case ZBEE_SEC_NONE:
        default:
            mic_len=0;
            break;

        case ZBEE_SEC_ENC_MIC32:
        case ZBEE_SEC_MIC32:
            mic_len=4;
            break;

        case ZBEE_SEC_ENC_MIC64:
        case ZBEE_SEC_MIC64:
            mic_len=8;
            break;

        case ZBEE_SEC_ENC_MIC128:
        case ZBEE_SEC_MIC128:
            mic_len=16;
            break;
    } /* switch */

    /* Empty payload has to be security checked as well,
     * since it contains MIC authentication tag */
    payload_len = tvb_reported_length_remaining(tvb, offset+mic_len);

    /**********************************************
     *  Perform Security Operations on the Frame  *
     **********************************************
     */
    if ((packet.level == ZBEE_SEC_NONE) ||
        (packet.level == ZBEE_SEC_MIC32) ||
        (packet.level == ZBEE_SEC_MIC64) ||
        (packet.level == ZBEE_SEC_MIC128)) {

        /* Payload is only integrity protected. Just return the sub-tvbuff. */
        return tvb_new_subset_length(tvb, offset, payload_len);
    }

    /* Have we captured all the payload? */
    if (tvb_captured_length_remaining(tvb, offset+mic_len) < payload_len
            || !tvb_bytes_exist(tvb, offset+payload_len, mic_len) /* there are at least enough bytes for MIC */ ) {
        /*
         * No - don't try to decrypt it.
         *
         * XXX - it looks as if the decryption code is assuming we have the
         * MIC, which won't be the case if the packet was cut short.  Is
         * that in fact that case, or can we still make this work with a
         * partially-captured packet?
         */
        /* Add expert info. */
        expert_add_info(pinfo, sec_tree, &ei_zbee_sec_encrypted_payload_sliced);
        /* Create a buffer for the undecrypted payload. */
        payload_tvb = tvb_new_subset_length(tvb, offset, payload_len);
        /* Dump the payload to the data dissector. */
        call_data_dissector(payload_tvb, pinfo, tree);
        /* Couldn't decrypt, so return NULL. */
        return NULL;
    }

    /* Get and display the MIC. */
    if (mic_len) {
        /* Display the MIC. */
        proto_tree_add_item(sec_tree, hf_zbee_sec_mic, tvb, (int)(tvb_reported_length(tvb)-mic_len),
                mic_len, ENC_NA);
    }

    /* Allocate memory to decrypt the payload into.
     * If there is no payload, dec_buffer will be NULL */
    dec_buffer = (uint8_t *)wmem_alloc(pinfo->pool, payload_len);

    decrypted = false;
    if ( packet.src64 ) {
        if (pinfo->fd->visited) {
            if ( nwk_hints ) {
                /* Use previously found key */
                switch ( packet.key_id ) {
                    case ZBEE_SEC_KEY_NWK:
                        if ( (key_rec = nwk_hints->nwk) ) {
                            decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                                payload_len, mic_len, nwk_hints->nwk->key);
                        }
                        break;

                    default:
                        if ( (key_rec = nwk_hints->link) ) {
                            decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                                payload_len, mic_len, nwk_hints->link->key);
                        }
                        break;
                }
            }
        } /* ( !pinfo->fd->visited ) */
        else {
            /* We only search for sniffed keys in the first pass,
             * to save time, and because decrypting with keys
             * transported in future packets is cheating */

            /* Lookup NWK and link key in hash for this pan. */
            /* This overkill approach is a placeholder for a hash that looks up
             * a key ring for a link key associated with a pair of devices.
             */
            if ( nwk_hints ) {
                nwk_keyring = (GSList **)g_hash_table_lookup(zbee_table_nwk_keyring, &nwk_hints->src_pan);

                if ( nwk_keyring ) {
                    GSList_i = *nwk_keyring;
                    while ( GSList_i && !decrypted ) {
                        decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                                payload_len, mic_len, ((key_record_t *)(GSList_i->data))->key);

                        if (decrypted) {
                            /* save pointer to the successful key record */
                            switch (packet.key_id) {
                                case ZBEE_SEC_KEY_NWK:
                                    key_rec = nwk_hints->nwk = (key_record_t *)(GSList_i->data);
                                    break;

                                default:
                                    key_rec = nwk_hints->link = (key_record_t *)(GSList_i->data);
                                    break;
                            }
                        } else {
                            GSList_i = g_slist_next(GSList_i);
                        }
                    }
                }

                /* Loop through user's password table for preconfigured keys, our last resort */
                GSList_i = zbee_pc_keyring;
                while ( GSList_i && !decrypted ) {
                    decrypted = zbee_sec_decrypt_payload( &packet, enc_buffer, offset, dec_buffer,
                            payload_len, mic_len, ((key_record_t *)(GSList_i->data))->key);

                    if (decrypted) {
                        /* save pointer to the successful key record */
                        switch (packet.key_id) {
                            case ZBEE_SEC_KEY_NWK:
                                key_rec = nwk_hints->nwk = (key_record_t *)(GSList_i->data);
                                break;

                            default:
                                key_rec = nwk_hints->link = (key_record_t *)(GSList_i->data);
                                break;
                        }
                    } else {
                        GSList_i = g_slist_next(GSList_i);
                    }
                }
            }
        } /* ( ! pinfo->fd->visited ) */
    } /* ( packet.src64 ) */

    if ( decrypted ) {
        if ( tree && key_rec ) {
            /* Key is not present in decrypted payload, so its length may not match bytes length */
            key_item = proto_tree_add_bytes_with_length(sec_tree, hf_zbee_sec_key, tvb, 0, 0, key_rec->key, ZBEE_SEC_CONST_KEYSIZE);
            proto_item_set_generated(key_item);

            if ( key_rec->frame_num == ZBEE_SEC_PC_KEY ) {
                ti = proto_tree_add_string(sec_tree, hf_zbee_sec_decryption_key, tvb, 0, 0, key_rec->label);
            } else {
                ti = proto_tree_add_uint(sec_tree, hf_zbee_sec_key_origin, tvb, 0, 0,
                        key_rec->frame_num);
            }
            proto_item_set_generated(ti);
        }

        /* Found a key that worked, setup the new tvbuff_t and return */
        if(dec_buffer != NULL) {
            payload_tvb = tvb_new_child_real_data(tvb, dec_buffer, payload_len, payload_len);
            add_new_data_source(pinfo, payload_tvb, "Decrypted ZigBee Payload");
        }
        else {
            /* Only MIC authentication tag was checked */
            payload_tvb = NULL;
        }

        /* Done! */
        return payload_tvb;
    }

    /* Add expert info. */
    expert_add_info(pinfo, sec_tree, &ei_zbee_sec_encrypted_payload);
    /* Create a buffer for the undecrypted payload. */
    payload_tvb = tvb_new_subset_length(tvb, offset, payload_len);
    /* Dump the payload to the data dissector. */
    call_data_dissector(payload_tvb, pinfo, tree);
    /* Couldn't decrypt, so return NULL. */
    return NULL;
} /* dissect_zbee_secure */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_decrypt_payload
 *  DESCRIPTION
 *      Creates a nonce and decrypts a secured payload.
 *  PARAMETERS
 *      char                 *nonce  - Nonce Buffer.
 *      zbee_security_packet *packet - Security information.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static bool
zbee_sec_decrypt_payload(zbee_security_packet *packet, const char *enc_buffer, const char offset, uint8_t *dec_buffer,
        unsigned payload_len, unsigned mic_len, uint8_t *key)
{
    uint8_t nonce[ZBEE_SEC_CONST_NONCE_LEN];
    uint8_t buffer[ZBEE_SEC_CONST_BLOCKSIZE+1];
    uint8_t *key_buffer = buffer;

    switch (packet->key_id) {
        case ZBEE_SEC_KEY_NWK:
            /* Decrypt with the PAN's current network key */
        case ZBEE_SEC_KEY_LINK:
            /* Decrypt with the unhashed link key assigned by the trust center to this
             * source/destination pair */
            key_buffer = key;
            break;

        case ZBEE_SEC_KEY_TRANSPORT:
            /* Decrypt with a Key-Transport key, a hashed link key that protects network
             * keys sent from the trust center */
            zbee_sec_key_hash(key, 0x00, buffer);
            key_buffer = buffer;
            break;

        case ZBEE_SEC_KEY_LOAD:
            /* Decrypt with a Key-Load key, a hashed link key that protects link keys
             * sent from the trust center. */
            zbee_sec_key_hash(key, 0x02, buffer);
            key_buffer = buffer;
            break;

        default:
            break;
    } /* switch */

    /* Perform Decryption. */
    zbee_sec_make_nonce(packet, nonce);

    if ( zbee_sec_ccm_decrypt(key_buffer,   /* key */
                        nonce,              /* Nonce */
                        enc_buffer,         /* a, length l(a) */
                        enc_buffer+offset,  /* c, length l(c) = l(m) + M */
                        dec_buffer,         /* m, length l(m) */
                        offset,             /* l(a) */
                        payload_len,        /* l(m) */
                        mic_len) ) {        /* M */
        return true;
    }
    else return false;
}

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_make_nonce
 *  DESCRIPTION
 *      Fills in the ZigBee security nonce from the provided security
 *      packet structure.
 *  PARAMETERS
 *      zbee_security_packet *packet - Security information.
 *      char            *nonce  - Nonce Buffer.
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zbee_sec_make_nonce(zbee_security_packet *packet, uint8_t *nonce)
{
    /* First 8 bytes are the extended source address (little endian). */
    phtole64(nonce, packet->src64);
    nonce += 8;
    /* Next 4 bytes are the frame counter (little endian). */
    phtole32(nonce, packet->counter);
    nonce += 4;
    /* Next byte is the security control field. */
    *(nonce) = packet->control;
} /* zbee_sec_make_nonce */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_ccm_decrypt
 *  DESCRIPTION
 *      Performs the Reverse CCM* Transformation (specified in
 *      section A.3 of ZigBee Specification (053474r17).
 *
 *      The length of parameter c (l(c)) is derived from the length
 *      of the payload and length of the MIC tag. Input buffer a
 *      will NOT be modified.
 *
 *      When l_m is 0, then there is no payload to encrypt (ie: the
 *      payload is in plaintext), and this function will perform
 *      MIC verification only. When l_m is 0, m may be NULL.
 *  PARAMETERS
 *      char    *key    - ZigBee Security Key (must be ZBEE_SEC_CONST_KEYSIZE) in length.
 *      char    *nonce  - ZigBee CCM* Nonce (must be ZBEE_SEC_CONST_NONCE_LEN) in length.
 *      char    *a      - CCM* Parameter a (must be l(a) in length). Additional data covered
 *                          by the authentication process.
 *      char    *c      - CCM* Parameter c (must be l(c) = l(m) + M in length). Encrypted
 *                          payload + encrypted authentication tag U.
 *      char    *m      - CCM* Output (must be l(m) in length). Decrypted Payload.
 *      unsigned   l_a     - l(a), length of CCM* parameter a.
 *      unsigned   l_m     - l(m), length of expected payload.
 *      unsigned   M       - M, length of CCM* authentication tag.
 *  RETURNS
 *      bool            - true if successful.
 *---------------------------------------------------------------
 */
bool
zbee_sec_ccm_decrypt(const char     *key,   /* Input */
                    const char      *nonce, /* Input */
                    const char      *a,     /* Input */
                    const char      *c,     /* Input */
                    char            *m,     /* Output */
                    unsigned        l_a,    /* sizeof(a) */
                    unsigned        l_m,    /* sizeof(m) */
                    unsigned        M)      /* sizeof(c) - sizeof(m) = sizeof(MIC) */
{
    uint8_t             cipher_in[ZBEE_SEC_CONST_BLOCKSIZE];
    uint8_t             cipher_out[ZBEE_SEC_CONST_BLOCKSIZE];
    uint8_t             decrypted_mic[ZBEE_SEC_CONST_BLOCKSIZE];
    unsigned            i, j;
    /* Cipher Instance. */
    gcry_cipher_hd_t    cipher_hd;

    /* Sanity-Check. */
    if (M > ZBEE_SEC_CONST_BLOCKSIZE) return false;
    /*
     * The CCM* counter is L bytes in length, ensure that the payload
     * isn't long enough to overflow it.
     */
    if ((1 + (l_a/ZBEE_SEC_CONST_BLOCKSIZE)) > (1<<(ZBEE_SEC_CONST_L*8))) return false;

    /******************************************************
     * Step 1: Encryption/Decryption Transformation
     ******************************************************
     */
    /* Create the CCM* counter block A0 */
    memset(cipher_in, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in + 1, nonce, ZBEE_SEC_CONST_NONCE_LEN);
    /*
     * The encryption/decryption process of CCM* works in CTR mode. Open a CTR
     * mode cipher for this phase. NOTE: The 'counter' part of the CCM* counter
     * block is the last two bytes, and is big-endian.
     */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0)) {
        return false;
    }
    /* Set the Key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    /* Set the counter. */
    if (gcry_cipher_setctr(cipher_hd, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    /*
     * Copy the MIC into the stack buffer. We need to feed the cipher a full
     * block when decrypting the MIC (so that the payload starts on the second
     * block). However, the MIC may be less than a full block so use a fixed
     * size buffer to store the MIC, letting the CTR cipher overstep the MIC
     * if need be.
     */
    memset(decrypted_mic, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    memcpy(decrypted_mic, c + l_m, M);
    /* Encrypt/Decrypt the MIC in-place. */
    if (gcry_cipher_encrypt(cipher_hd, decrypted_mic, ZBEE_SEC_CONST_BLOCKSIZE, decrypted_mic, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    /* Encrypt/Decrypt the payload. */
    if (gcry_cipher_encrypt(cipher_hd, m, l_m, c, l_m)) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    /* Done with the CTR Cipher. */
    gcry_cipher_close(cipher_hd);

    /******************************************************
     * Step 3: Authentication Transformation
     ******************************************************
     */
    if (M == 0) {
        /* There is no authentication tag. We're done! */
        return true;
    }
    /*
     * The authentication process in CCM* operates in CBC-MAC mode, but
     * unfortunately, the input to the CBC-MAC process needs some substantial
     * transformation and padding before we can feed it into the CBC-MAC
     * algorithm. Instead we will operate in ECB mode and perform the
     * transformation and padding on the fly.
     *
     * I also think that libgcrypt requires the input to be memory-aligned
     * when using CBC-MAC mode, in which case can't just feed it with data
     * from the packet buffer. All things considered it's just a lot easier
     * to use ECB mode and do CBC-MAC manually.
     */
    /* Re-open the cipher in ECB mode. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return false;
    }
    /* Re-load the key. */
    if (gcry_cipher_setkey(cipher_hd, key, ZBEE_SEC_CONST_KEYSIZE)) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    /* Generate the first cipher block B0. */
    cipher_in[0] = ZBEE_SEC_CCM_FLAG_M(M) |
                    ZBEE_SEC_CCM_FLAG_ADATA(l_a) |
                    ZBEE_SEC_CCM_FLAG_L;
    memcpy(cipher_in+sizeof(char), nonce, ZBEE_SEC_CONST_NONCE_LEN);
    for (i=0;i<ZBEE_SEC_CONST_L; i++) {
        cipher_in[(ZBEE_SEC_CONST_BLOCKSIZE-1)-i] = (l_m >> (8*i)) & 0xff;
    } /* for */
    /* Generate the first cipher block, X1 = E(Key, 0^128 XOR B0). */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    /*
     * We avoid mallocing() big chunks of memory by recycling small stack
     * buffers for the encryption process. Throughout this process, j is always
     * pointed to the position within the current buffer.
     */
    j = 0;
    /* AuthData = L(a) || a || Padding || m || Padding
     * Where L(a) =
     *      - an empty string if l(a) == 0.
     *      - 2-octet encoding of l(a) if 0 < l(a) < (2^16 - 2^8)
     *      - 0xff || 0xfe || 4-octet encoding of l(a) if (2^16 - 2^8) <= l(a) < 2^32
     *      - 0xff || 0xff || 8-octet encoding of l(a)
     * But for ZigBee, the largest packet size we should ever see is 2^7, so we
     * are only really concerned with the first two cases.
     *
     * To generate the MIC tag CCM* operates similar to CBC-MAC mode. Each block
     * of AuthData is XOR'd with the last block of cipher output to produce the
     * next block of cipher output. Padding sections have the minimum non-negative
     * length such that the padding ends on a block boundary. Padded bytes are 0.
     */
    if (l_a > 0) {
        /* Process L(a) into the cipher block. */
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 8) & 0xff);
        j++;
        cipher_in[j] = cipher_out[j] ^ ((l_a >> 0) & 0xff);
        j++;
        /* Process a into the cipher block. */
        for (i=0;i<l_a;i++,j++) {
            if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
                /* Generate the next cipher block. */
                if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                            ZBEE_SEC_CONST_BLOCKSIZE)) {
                    gcry_cipher_close(cipher_hd);
                    return false;
                }
                /* Reset j to point back to the start of the new cipher block. */
                j = 0;
            }
            /* Cipher in = cipher_out ^ a */
            cipher_in[j] = cipher_out[j] ^ a[i];
        } /* for */
        /* Process padding into the cipher block. */
        for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
            cipher_in[j] = cipher_out[j];
    }
    /* Process m into the cipher block. */
    for (i=0; i<l_m; i++, j++) {
        if (j>=ZBEE_SEC_CONST_BLOCKSIZE) {
            /* Generate the next cipher block. */
            if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in,
                       ZBEE_SEC_CONST_BLOCKSIZE)) {
                gcry_cipher_close(cipher_hd);
                return false;
            }
            /* Reset j to point back to the start of the new cipher block. */
            j = 0;
        }
        /* Cipher in = cipher out ^ m */
        cipher_in[j] = cipher_out[j] ^ m[i];
    } /* for */
    /* Padding. */
    for (;j<ZBEE_SEC_CONST_BLOCKSIZE;j++)
        cipher_in[j] = cipher_out[j];
    /* Generate the last cipher block, which will be the MIC tag. */
    if (gcry_cipher_encrypt(cipher_hd, cipher_out, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE)) {
        gcry_cipher_close(cipher_hd);
        return false;
    }
    /* Done with the Cipher. */
    gcry_cipher_close(cipher_hd);

    /* Compare the MIC's */
    return (memcmp(cipher_out, decrypted_mic, M) == 0);
} /* zbee_ccm_decrypt */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_hash
 *  DESCRIPTION
 *      ZigBee Cryptographic Hash Function, described in ZigBee
 *      specification sections B.1.3 and B.6.
 *
 *      This is a Matyas-Meyer-Oseas hash function using the AES-128
 *      cipher. We use the ECB mode of libgcrypt to get a raw block
 *      cipher.
 *
 *      Input may be any length, and the output must be exactly 1-block in length.
 *
 *      Implements the function:
 *          Hash(text) = Hash[t];
 *          Hash[0] = 0^(blocksize).
 *          Hash[i] = E(Hash[i-1], M[i]) XOR M[j];
 *          M[i] = i'th block of text, with some padding and flags concatenated.
 *  PARAMETERS
 *      uint8_t *    input       - Hash Input (any length).
 *      uint8_t      input_len   - Hash Input Length.
 *      uint8_t *    output      - Hash Output (exactly one block in length).
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zbee_sec_hash(uint8_t *input, unsigned input_len, uint8_t *output)
{
    uint8_t             cipher_in[ZBEE_SEC_CONST_BLOCKSIZE];
    unsigned            i, j;
    /* Cipher Instance. */
    gcry_cipher_hd_t    cipher_hd;

    /* Clear the first hash block (Hash0). */
    memset(output, 0, ZBEE_SEC_CONST_BLOCKSIZE);
    /* Create the cipher instance in ECB mode. */
    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return; /* Failed. */
    }
    /* Create the subsequent hash blocks using the formula: Hash[i] = E(Hash[i-1], M[i]) XOR M[i]
     *
     * because we can't guarantee that M will be exactly a multiple of the
     * block size, we will need to copy it into local buffers and pad it.
     *
     * Note that we check for the next cipher block at the end of the loop
     * rather than the start. This is so that if the input happens to end
     * on a block boundary, the next cipher block will be generated for the
     * start of the padding to be placed into.
     */
    i = 0;
    j = 0;
    while (i<input_len) {
        /* Copy data into the cipher input. */
        cipher_in[j++] = input[i++];
        /* Check if this cipher block is done. */
        if (j >= ZBEE_SEC_CONST_BLOCKSIZE) {
            /* We have reached the end of this block. Process it with the
             * cipher, note that the Key input to the cipher is actually
             * the previous hash block, which we are keeping in output.
             */
            (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
            (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
            /* Now we have to XOR the input into the hash block. */
            for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
            /* Reset j to start again at the beginning at the next block. */
            j = 0;
        }
    } /* for */
    /* Need to append the bit '1', followed by '0' padding long enough to end
     * the hash input on a block boundary. However, because 'n' is 16, and 'l'
     * will be a multiple of 8, the padding will be >= 7-bits, and we can just
     * append the byte 0x80.
     */
    cipher_in[j++] = 0x80;
    /* Pad with '0' until the current block is exactly 'n' bits from the
     * end.
     */
    while (j!=(ZBEE_SEC_CONST_BLOCKSIZE-2)) {
        if (j >= ZBEE_SEC_CONST_BLOCKSIZE) {
            /* We have reached the end of this block. Process it with the
             * cipher, note that the Key input to the cipher is actually
             * the previous hash block, which we are keeping in output.
             */
            (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
            (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
            /* Now we have to XOR the input into the hash block. */
            for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
            /* Reset j to start again at the beginning at the next block. */
            j = 0;
        }
        /* Pad the input with 0. */
        cipher_in[j++] = 0x00;
    } /* while */
    /* Add the 'n'-bit representation of 'l' to the end of the block. */
    cipher_in[j++] = ((input_len * 8) >> 8) & 0xff;
    cipher_in[j] = ((input_len * 8) >> 0) & 0xff;
    /* Process the last cipher block. */
    (void)gcry_cipher_setkey(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE);
    (void)gcry_cipher_encrypt(cipher_hd, output, ZBEE_SEC_CONST_BLOCKSIZE, cipher_in, ZBEE_SEC_CONST_BLOCKSIZE);
    /* XOR the last input block back into the cipher output to get the hash. */
    for (j=0;j<ZBEE_SEC_CONST_BLOCKSIZE;j++) output[j] ^= cipher_in[j];
    /* Cleanup the cipher. */
    gcry_cipher_close(cipher_hd);
    /* Done */
} /* zbee_sec_hash */

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      zbee_sec_key_hash
 *  DESCRIPTION
 *      ZigBee Keyed Hash Function. Described in ZigBee specification
 *      section B.1.4, and in FIPS Publication 198. Strictly speaking
 *      there is nothing about the Keyed Hash Function which restricts
 *      it to only a single byte input, but that's all ZigBee ever uses.
 *
 *      This function implements the hash function:
 *          Hash(Key, text) = H((Key XOR opad) || H((Key XOR ipad) || text));
 *          ipad = 0x36 repeated.
 *          opad = 0x5c repeated.
 *          H() = ZigBee Cryptographic Hash (B.1.3 and B.6).
 *  PARAMETERS
 *      uint8_t *key      - ZigBee Security Key (must be ZBEE_SEC_CONST_KEYSIZE) in length.
 *      uint8_t input     - ZigBee CCM* Nonce (must be ZBEE_SEC_CONST_NONCE_LEN) in length.
 *      uint8_t *hash_out - buffer into which the key-hashed output is placed
 *  RETURNS
 *      void
 *---------------------------------------------------------------
 */
static void
zbee_sec_key_hash(uint8_t *key, uint8_t input, uint8_t *hash_out)
{
    uint8_t             hash_in[2*ZBEE_SEC_CONST_BLOCKSIZE];
    int                 i;
    static const uint8_t ipad = 0x36;
    static const uint8_t opad = 0x5c;

    /* Copy the key into hash_in and XOR with opad to form: (Key XOR opad) */
    for (i=0; i<ZBEE_SEC_CONST_KEYSIZE; i++) hash_in[i] = key[i] ^ opad;
    /* Copy the Key into hash_out and XOR with ipad to form: (Key XOR ipad) */
    for (i=0; i<ZBEE_SEC_CONST_KEYSIZE; i++) hash_out[i] = key[i] ^ ipad;
    /* Append the input byte to form: (Key XOR ipad) || text. */
    hash_out[ZBEE_SEC_CONST_BLOCKSIZE] = input;
    /* Hash the contents of hash_out and append the contents to hash_in to
     * form: (Key XOR opad) || H((Key XOR ipad) || text).
     */
    zbee_sec_hash(hash_out, ZBEE_SEC_CONST_BLOCKSIZE+1, hash_in+ZBEE_SEC_CONST_BLOCKSIZE);
    /* Hash the contents of hash_in to get the final result. */
    zbee_sec_hash(hash_in, 2*ZBEE_SEC_CONST_BLOCKSIZE, hash_out);
} /* zbee_sec_key_hash */

/**
 *Add NWK or APS key into NWK keyring
 *
 *@param pinfo pointer to packet information fields
 *@param key APS or NWK key
 */
void zbee_sec_add_key_to_keyring(packet_info *pinfo, const uint8_t *key)
{
    GSList            **nwk_keyring;
    key_record_t        key_record;
    zbee_nwk_hints_t   *nwk_hints;

    /* Update the key ring for this pan */
    if ( !pinfo->fd->visited && (nwk_hints = (zbee_nwk_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo,
                    proto_zbee_nwk, 0))) {
        nwk_keyring = (GSList **)g_hash_table_lookup(zbee_table_nwk_keyring, &nwk_hints->src_pan);
        if ( !nwk_keyring ) {
            nwk_keyring = (GSList **)g_malloc0(sizeof(GSList*));
            g_hash_table_insert(zbee_table_nwk_keyring,
                g_memdup2(&nwk_hints->src_pan, sizeof(nwk_hints->src_pan)), nwk_keyring);
        }

        if ( nwk_keyring ) {
            if ( !*nwk_keyring ||
                    memcmp( ((key_record_t *)((GSList *)(*nwk_keyring))->data)->key, key,
                        ZBEE_APS_CMD_KEY_LENGTH) ) {
                /* Store a new or different key in the key ring */
                key_record.frame_num = pinfo->num;
                key_record.label = NULL;
                memcpy(&key_record.key, key, ZBEE_APS_CMD_KEY_LENGTH);
                *nwk_keyring = g_slist_prepend(*nwk_keyring, g_memdup2(&key_record, sizeof(key_record_t)));
            }
        }
    }
} /* nwk_add_key_to_keyring */

/**
 *Add NWK or APS key into NWK keyring
 *
 *@param pinfo pointer to packet information fields
 *@param key APS or NWK key
 */
void zbee_sec_add_key_to_keyring_panid(packet_info *pinfo, const uint8_t *key, int panid)
{
    GSList            **nwk_keyring;
    key_record_t        key_record;

    /* Update the key ring for this pan */
    if ( !pinfo->fd->visited ) {
        nwk_keyring = (GSList **)g_hash_table_lookup(zbee_table_nwk_keyring, &panid);
        if ( !nwk_keyring ) {
            nwk_keyring = (GSList **)g_malloc0(sizeof(GSList*));
            g_hash_table_insert(zbee_table_nwk_keyring,
                g_memdup2(&panid, sizeof(panid)), nwk_keyring);
        }

        if ( nwk_keyring ) {
            if ( !*nwk_keyring ||
                    memcmp( ((key_record_t *)((GSList *)(*nwk_keyring))->data)->key, key,
                        ZBEE_APS_CMD_KEY_LENGTH) ) {
                /* Store a new or different key in the key ring */
                key_record.frame_num = pinfo->num;
                key_record.label = NULL;
                memcpy(&key_record.key, key, ZBEE_APS_CMD_KEY_LENGTH);
                *nwk_keyring = g_slist_prepend(*nwk_keyring, g_memdup2(&key_record, sizeof(key_record_t)));
            }
        }
    }
} /* zbee_sec_add_key_to_keyring_panid */

/**
 *Get key from keyring
 *
 *@param label key label
 *@param key NWK key
 */
bool zbee_sec_get_key_from_keyring(const char *label, uint8_t *key)
{
    GSList *GSList_i;
    /* Loop through user's password table for preconfigured keys, our last resort */
    GSList_i = zbee_pc_keyring;
    while ( GSList_i ) {
        key_record_t * rec = (key_record_t *)GSList_i->data;
        ws_debug("'%s': %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", rec->label, (uint8_t)rec->key[0x0], (uint8_t)rec->key[0x1], (uint8_t)rec->key[0x2], (uint8_t)rec->key[0x3], (uint8_t)rec->key[0x4], (uint8_t)rec->key[0x5], (uint8_t)rec->key[0x6], (uint8_t)rec->key[0x7], (uint8_t)rec->key[0x8], (uint8_t)rec->key[0x9], (uint8_t)rec->key[0xA], (uint8_t)rec->key[0xB], (uint8_t)rec->key[0xC], (uint8_t)rec->key[0xD], (uint8_t)rec->key[0xE], (uint8_t)rec->key[0xF]);

        if(!strcmp(label, rec->label)){
            memcpy(key, rec->key, ZBEE_SEC_CONST_KEYSIZE);
            return 1;
        }

        GSList_i = g_slist_next(GSList_i);
    }
    return 0;
} /* zbee_sec_get_key_from_keyring */

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
