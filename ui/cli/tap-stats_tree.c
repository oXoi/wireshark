/* tap-stats_tree.c
 * tshark's tap implememntation of stats_tree
 * 2005, Luis E. G. Ontanon
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <stdio.h>
#include <glib.h>

#include <wsutil/report_message.h>

#include <epan/prefs.h>
#include <epan/stats_tree_priv.h>
#include <epan/stat_tap_ui.h>

void register_tap_listener_stats_tree_stat(void);

/* actually unused */
struct _st_node_pres {
	void *dummy;
};

struct _tree_pres {
	void **dummy;
};

struct _tree_cfg_pres {
	char *init_string;
};

static void
draw_stats_tree(void *psp)
{
	stats_tree *st = (stats_tree *)psp;
	GString *s;

	s= stats_tree_format_as_str(st, prefs.st_format, stats_tree_get_default_sort_col(st),
				    stats_tree_is_default_sort_DESC(st));

	printf("%s", s->str);
	g_string_free(s, TRUE);
}

static void
free_stats_tree(void *psp)
{
	stats_tree *st = (stats_tree *)psp;
	stats_tree_free(st);
}

static bool
init_stats_tree(const char *opt_arg, void *userdata _U_)
{
	char *abbr = stats_tree_get_abbr(opt_arg);
	GString	*error_string;
	stats_tree_cfg *cfg = NULL;
	stats_tree *st = NULL;
	const char* filter = NULL;
	size_t len;

	if (abbr) {
		cfg = stats_tree_get_cfg_by_abbr(abbr);

		if (cfg != NULL) {
			len = strlen(cfg->pr->init_string);
			if (strncmp(opt_arg, cfg->pr->init_string, len) == 0) {
				if (opt_arg[len] == ',') {
					filter = opt_arg + len + 1;
				}
				st = stats_tree_new(cfg, NULL, filter);
			} else {
				report_failure("Wrong stats_tree (%s) found when looking at ->init_string", abbr);
				return false;
			}
		} else {
			report_failure("no such stats_tree (%s) found in stats_tree registry", abbr);
			return false;
		}

		g_free(abbr);

	} else {
		report_failure("could not obtain stats_tree from arg '%s'", opt_arg);
		return false;
	}

	error_string = register_tap_listener(st->cfg->tapname,
					     st,
					     st->filter,
					     st->cfg->flags,
					     stats_tree_reset,
					     stats_tree_packet,
					     draw_stats_tree,
					     free_stats_tree);

	if (error_string) {
		report_failure("stats_tree for: %s failed to attach to the tap: %s", cfg->path, error_string->str);
		return false;
	}

	if (cfg->init)
		cfg->init(st);

	return true;
}

static void
register_stats_tree_tap (void *k _U_, void *v, void *p _U_)
{
	stats_tree_cfg *cfg = (stats_tree_cfg *)v;
	stat_tap_ui ui_info;

	cfg->pr = wmem_new(wmem_epan_scope(), tree_cfg_pres);
	cfg->pr->init_string = wmem_strdup_printf(wmem_epan_scope(), "%s,tree", cfg->abbr);

	ui_info.group = REGISTER_STAT_GROUP_GENERIC;
	ui_info.title = NULL;
	ui_info.cli_string = cfg->pr->init_string;
	ui_info.tap_init_cb = init_stats_tree;
	ui_info.nparams = 0;
	ui_info.params = NULL;
	register_stat_tap_ui(&ui_info, NULL);

}

static void
free_tree_presentation(stats_tree *st)
{
	g_free(st->pr);
}


void
register_tap_listener_stats_tree_stat(void)
{
	stats_tree_presentation(register_stats_tree_tap, NULL,
                free_tree_presentation, NULL);
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
