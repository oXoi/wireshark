/* tap-smbsids.c
 * smbstat   2003 Ronnie Sahlberg
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/dissectors/packet-smb-sidsnooping.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/value_string.h>
#include <epan/dissectors/packet-smb.h>

#include <wsutil/cmdarg_err.h>

void register_tap_listener_smbsids(void);

static tap_packet_status
smbsids_packet(void *pss _U_, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *psi _U_, tap_flags_t flags _U_)
{
	return TAP_PACKET_REDRAW;
}

static void
enum_sids(void *key, void *value, void *userdata _U_)
{
	const char *sid = (const char *)key;
	const char *name = (const char *)value;

	printf("%-60s %s\n", sid, name);
}

static void
smbsids_draw(void *pss _U_)
{
	printf("\n");
	printf("===================================================================\n");
	printf("SMB SID List:\n");
	g_hash_table_foreach(sid_name_table, enum_sids, NULL);
	printf("===================================================================\n");
}


static bool
smbsids_init(const char *opt_arg _U_, void *userdata _U_)
{
	GString *error_string;

	if (!sid_name_snooping) {
		cmdarg_err("The -z smb,sids function needs SMB/SID-Snooping to be enabled.\n"
			"Either enable Edit/Preferences/Protocols/SMB/Snoop SID name mappings in wireshark\n"
			"or override the preference file by specifying\n"
			"  -o \"smb.sid_name_snooping=true\"\n"
			"on the tshark command line.\n");
		return false;
	}


	error_string = register_tap_listener("smb", NULL, NULL, 0, NULL, smbsids_packet, smbsids_draw, NULL);
	if (error_string) {
		cmdarg_err("Couldn't register smb,sids tap: %s",
			error_string->str);
		g_string_free(error_string, TRUE);
		return false;
	}

	return true;
}

static stat_tap_ui smbsids_ui = {
	REGISTER_STAT_GROUP_GENERIC,
	NULL,
	"smb,sids",
	smbsids_init,
	0,
	NULL
};

void
register_tap_listener_smbsids(void)
{
	register_stat_tap_ui(&smbsids_ui, NULL);
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
