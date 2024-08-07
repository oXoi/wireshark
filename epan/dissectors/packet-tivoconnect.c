/* packet-tivoconnect.c
 * Routines for TiVoConnect Discovery Protocol dissection
 * Copyright 2006, Kees Cook <kees@outflux.net>
 * IANA UDP/TCP port: 2190 (tivoconnect)
 * Protocol Spec: http://tivo.com/developer/i/TiVoConnectDiscovery.pdf
 *
 * IANA's full name is "TiVoConnect Beacon", where as TiVo's own
 * documentation calls this protocol "TiVoConnect Discovery Protocol".
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * TODO
 * - split services into a subtree
 * - split platform into a subtree
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_reg_handoff_tivoconnect(void);
void proto_register_tivoconnect(void);

static dissector_handle_t tivoconnect_tcp_handle;
static dissector_handle_t tivoconnect_udp_handle;

#define TIVOCONNECT_PORT 2190

static int proto_tivoconnect;
static int hf_tivoconnect_flavor;
static int hf_tivoconnect_method;
static int hf_tivoconnect_platform;
static int hf_tivoconnect_machine;
static int hf_tivoconnect_identity;
static int hf_tivoconnect_services;
static int hf_tivoconnect_version;

static int ett_tivoconnect;

static int
dissect_tivoconnect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool is_tcp)
{
    /* parsing variables */
    char * string;
    int length;
    /* value strings */
    const char * proto_name;
    char * packet_identity = NULL;
    char * packet_machine = NULL;

    /* validate that we have a tivoconnect packet */
    if ( tvb_strncaseeql(tvb, 0, "tivoconnect", 11) != 0) {
        return 0;
    }

    length = tvb_captured_length(tvb);
    string = (char*)tvb_get_string_enc(pinfo->pool, tvb, 0, length, ENC_ASCII);

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TiVoConnect");

    /* make a distinction between UDP and TCP packets */
    proto_name = is_tcp ? "Discovery Connection" : "Discovery Beacon";

    col_set_str(pinfo->cinfo, COL_INFO, proto_name);

    /* if (tree) */ {
        /* Set up structures needed to add the protocol subtree and manage it */
        proto_item *ti;
        proto_tree *tivoconnect_tree;

        /* parsing variables */
        unsigned offset = 0;
        char * field;

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_tivoconnect, tvb, 0, -1, ENC_NA);

        tivoconnect_tree = proto_item_add_subtree(ti, ett_tivoconnect);

        /* process the packet */
        for ( field = strtok(string, "\n");
              field;
              offset += length, field = strtok(NULL, "\n") ) {
            char * value;
            int fieldlen;

            length = (int)strlen(field) + 1;

            if ( !(value = strchr(field, '=')) ) {
                /* bad packet: missing the field separator */
                continue;
            }
            *value++ = '\0';
            fieldlen = (int)strlen(field) + 1;

            if ( g_ascii_strcasecmp(field, "tivoconnect") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_flavor, tvb, offset+fieldlen,
                    length-fieldlen-1, ENC_ASCII);
            }
            else if ( g_ascii_strcasecmp(field, "method") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_method, tvb, offset+fieldlen,
                    length-fieldlen-1, ENC_ASCII);
            }
            else if ( g_ascii_strcasecmp(field, "platform") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_platform, tvb, offset+fieldlen,
                    length-fieldlen-1, ENC_ASCII);
            }
            else if ( g_ascii_strcasecmp(field, "machine") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_machine, tvb, offset+fieldlen,
                    length-fieldlen-1, ENC_ASCII);
                packet_machine = value;
            }
            else if ( g_ascii_strcasecmp(field, "identity") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_identity, tvb, offset+fieldlen,
                    length-fieldlen-1, ENC_ASCII);
                packet_identity = value;
            }
            else if ( g_ascii_strcasecmp(field, "services") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_services, tvb, offset+fieldlen,
                    length-fieldlen-1, ENC_ASCII);
            }
            else if ( g_ascii_strcasecmp(field, "swversion") == 0 ) {
                proto_tree_add_item(tivoconnect_tree,
                    hf_tivoconnect_version, tvb, offset+fieldlen,
                    length-fieldlen-1, ENC_ASCII);
            }
            else {
                /* unknown field! */
            }
        }

        /* Adjust "Info" column and top of tree into more useful info */
        if (packet_machine) {
            proto_item_append_text(ti, ", %s", packet_machine);
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s",
                                            proto_name, packet_machine);
        }
        if (packet_identity) {
            proto_item_append_text(ti,
                        packet_machine ? " (%s)" : ", ID:%s",
                        packet_identity);
            if (packet_machine) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s (%s)",
                                 proto_name, packet_machine, packet_identity);
            }
            else {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s ID:%s",
                                 proto_name, packet_identity);
            }
        }

    }

    return tvb_reported_length(tvb);
}

static int
dissect_tivoconnect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_tivoconnect(tvb, pinfo, tree, true);
}

static int
dissect_tivoconnect_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    return dissect_tivoconnect(tvb, pinfo, tree, false);
}

void
proto_register_tivoconnect(void)
{
    static hf_register_info hf[] = {
        { &hf_tivoconnect_flavor,
            { "Flavor",           "tivoconnect.flavor",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Protocol Flavor supported by the originator", HFILL }},
        { &hf_tivoconnect_method,
            { "Method",           "tivoconnect.method",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Packet was delivered via UDP(broadcast) or TCP(connected)", HFILL }},
        { &hf_tivoconnect_platform,
            { "Platform",           "tivoconnect.platform",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "System platform, either tcd(TiVo) or pc(Computer)", HFILL }},
        { &hf_tivoconnect_machine,
            { "Machine",           "tivoconnect.machine",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Human-readable system name", HFILL }},
        { &hf_tivoconnect_identity,
            { "Identity",           "tivoconnect.identity",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "Unique serial number for the system", HFILL }},
        { &hf_tivoconnect_services,
            { "Services",           "tivoconnect.services",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "List of available services on the system", HFILL }},
        { &hf_tivoconnect_version,
            { "Version",           "tivoconnect.version",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            "System software version", HFILL }},
    };

    static int *ett[] = {
        &ett_tivoconnect,
    };

    proto_tivoconnect = proto_register_protocol("TiVoConnect Discovery Protocol",
        "TiVoConnect", "tivoconnect");

    proto_register_field_array(proto_tivoconnect, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tivoconnect_tcp_handle = register_dissector("tivo.tcp", dissect_tivoconnect_tcp, proto_tivoconnect);
    tivoconnect_udp_handle = register_dissector("tivo.udp", dissect_tivoconnect_udp, proto_tivoconnect);
}


void
proto_reg_handoff_tivoconnect(void)
{
    dissector_add_uint_with_preference("udp.port", TIVOCONNECT_PORT, tivoconnect_udp_handle);
    dissector_add_uint_with_preference("tcp.port", TIVOCONNECT_PORT, tivoconnect_tcp_handle);
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
