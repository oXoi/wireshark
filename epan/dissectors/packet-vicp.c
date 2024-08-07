/* packet-vicp.c
 * LeCroy VICP (GPIB-over-Ethernet-but-lets-not-do-LXI) dissector
 *
 * Written by Frank Kingswood <frank.kingswood@artimi.com>
 * Copyright 2008, Artimi Ltd.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/ptvcursor.h>

/* registration object IDs */
static int proto_vicp;
static int hf_vicp_operation;
static int hf_vicp_version;
static int hf_vicp_sequence;
static int hf_vicp_unused;
static int hf_vicp_length;
static int hf_vicp_data;
static int ett_vicp;

#define VICP_PORT 1861

void proto_register_vicp(void);
void proto_reg_handoff_vicp(void);

static dissector_handle_t vicp_handle;

static int dissect_vicp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_item *ti;
   proto_tree *vicp_tree;
   ptvcursor_t* cursor;

   unsigned len;

   if (tvb_reported_length_remaining(tvb, 0) < 8)
   {
      /* Payload too small for VICP */
      return 0;
   }

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "VICP");

   col_clear(pinfo->cinfo, COL_INFO);

   ti = proto_tree_add_item(tree, proto_vicp, tvb, 0, -1, ENC_NA);
   vicp_tree = proto_item_add_subtree(ti, ett_vicp);
   cursor = ptvcursor_new(pinfo->pool, vicp_tree, tvb, 0);

   ptvcursor_add(cursor, hf_vicp_operation, 1, ENC_BIG_ENDIAN);
   ptvcursor_add(cursor, hf_vicp_version,   1, ENC_BIG_ENDIAN);
   ptvcursor_add(cursor, hf_vicp_sequence,  1, ENC_BIG_ENDIAN);
   ptvcursor_add(cursor, hf_vicp_unused,    1, ENC_BIG_ENDIAN);

   len=tvb_get_ntohl(tvb, ptvcursor_current_offset(cursor));
   ptvcursor_add(cursor, hf_vicp_length, 4, ENC_BIG_ENDIAN);

   ptvcursor_add(cursor, hf_vicp_data, len, ENC_NA);

   ptvcursor_free(cursor);
   return tvb_captured_length(tvb);
}

void proto_register_vicp(void)
{
   static hf_register_info hf[] =
   {
      {  &hf_vicp_operation,
         { "Operation","vicp.operation",FT_UINT8,BASE_HEX,NULL,0x0,NULL,HFILL }
      },
      {  &hf_vicp_version,
         { "Protocol version","vicp.version",FT_UINT8,BASE_DEC,NULL,0x0,NULL,HFILL }
      },
      {  &hf_vicp_sequence,
         { "Sequence number","vicp.sequence",FT_UINT8,BASE_DEC,NULL,0x0,NULL,HFILL }
      },
      {  &hf_vicp_unused,
         { "Unused","vicp.unused",FT_UINT8,BASE_HEX,NULL,0x0,NULL,HFILL }
      },
      {  &hf_vicp_length,
         { "Data length","vicp.length",FT_UINT32,BASE_DEC,NULL,0x0,NULL,HFILL }
      },
      {  &hf_vicp_data,
         { "Data","vicp.data",FT_BYTES,BASE_NONE,NULL,0x0,NULL,HFILL }
      }
   };

   static int *ett[] =
   {  &ett_vicp
   };

   proto_vicp = proto_register_protocol("LeCroy VICP", "VICP", "vicp");
   proto_register_field_array(proto_vicp, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
   vicp_handle = register_dissector("vicp", dissect_vicp, proto_vicp);
}

void proto_reg_handoff_vicp(void)
{
   dissector_add_uint_with_preference("tcp.port", VICP_PORT, vicp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
