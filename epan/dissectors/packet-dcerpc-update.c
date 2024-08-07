/* packet-dcerpc-update.c
 *
 * Routines for dcerpc upserv dissection
 * Copyright 2002, Jaime Fournier <Jaime.Fournier@hush.com>
 * This information is based off the released idl files from opengroup.
 * ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/update/update.idl
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"


#include <epan/packet.h>
#include "packet-dcerpc.h"

void proto_register_dce_update(void);
void proto_reg_handoff_dce_update(void);

static int proto_dce_update;
static int hf_dce_update_opnum;

static int ett_dce_update;

static e_guid_t uuid_dce_update =
  { 0x4d37f2dd, 0xed43, 0x0000, {0x02, 0xc0, 0x37, 0xcf, 0x1e, 0x00, 0x10,
                                 0x00}
};
static uint16_t ver_dce_update = 4;


static const dcerpc_sub_dissector dce_update_dissectors[] = {
  {0, "UPDATE_GetServerInterfaces", NULL, NULL},
  {1, "UPDATE_FetchInfo", NULL, NULL},
  {2, "UPDATE_FetchFile", NULL, NULL},
  {3, "UPDATE_FetchObjectInfo", NULL, NULL},
  {0, NULL, NULL, NULL},
};

void
proto_register_dce_update (void)
{
  static hf_register_info hf[] = {
    {&hf_dce_update_opnum,
     {"Operation", "dce_update.opnum", FT_UINT16, BASE_DEC,
      NULL, 0x0, NULL, HFILL}}

  };

  static int *ett[] = {
    &ett_dce_update,
  };
  proto_dce_update =
    proto_register_protocol ("DCE/RPC UpServer", "dce_update", "dce_update");
  proto_register_field_array (proto_dce_update, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void
proto_reg_handoff_dce_update (void)
{
  /* Register the protocol as dcerpc */
  dcerpc_init_uuid (proto_dce_update, ett_dce_update, &uuid_dce_update,
                    ver_dce_update, dce_update_dissectors,
                    hf_dce_update_opnum);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
