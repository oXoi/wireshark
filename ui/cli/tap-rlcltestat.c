/* tap-rlclte_stat.c
 * Copyright 2011 Martin Mathieson
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

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>

#include <epan/dissectors/packet-rlc-lte.h>
#include <epan/dissectors/packet-rlc-3gpp-common.h>


void register_tap_listener_rlc_lte_stat(void);

enum {
    RAT_COLUMN,
    UEID_COLUMN,
    UL_FRAMES_COLUMN,
    UL_BYTES_COLUMN,
    UL_BW_COLUMN,
    UL_ACKS_COLUMN,
    UL_NACKS_COLUMN,
    UL_MISSING_COLUMN,
    DL_FRAMES_COLUMN,
    DL_BYTES_COLUMN,
    DL_BW_COLUMN,
    DL_ACKS_COLUMN,
    DL_NACKS_COLUMN,
    DL_MISSING_COLUMN,
    NUM_UE_COLUMNS
};

static const char *ue_titles[] = { "RAT", " UEId",
                                    "UL Frames", "UL Bytes", "   UL Mbs", "UL ACKs", "UL NACKs", "UL Missed",
                                    "DL Frames", "DL Bytes", "   DL Mbs", "DL ACKs", "DL NACKs", "DL Missed"};

/* Stats for one UE */
typedef struct rlc_lte_row_data {
    /* Key for matching this row */
    uint8_t  rat;
    uint16_t ueid;

    bool is_predefined_data;

    uint32_t UL_frames;
    uint32_t UL_total_bytes;
    nstime_t UL_time_start;
    nstime_t UL_time_stop;
    uint32_t UL_total_acks;
    uint32_t UL_total_nacks;
    uint32_t UL_total_missing;

    uint32_t DL_frames;
    uint32_t DL_total_bytes;
    nstime_t DL_time_start;
    nstime_t DL_time_stop;
    uint32_t DL_total_acks;
    uint32_t DL_total_nacks;
    uint32_t DL_total_missing;

} rlc_lte_row_data;


/* Common channel stats (i.e. independent of UEs) */
typedef struct rlc_lte_common_stats {
    uint32_t bcch_frames;
    uint32_t bcch_bytes;
    uint32_t pcch_frames;
    uint32_t pcch_bytes;
} rlc_lte_common_stats;


/* One row/UE in the UE table */
typedef struct rlc_lte_ep {
    struct rlc_lte_ep *next;
    struct rlc_lte_row_data stats;
} rlc_lte_ep_t;


/* Top-level struct for RLC LTE statistics */
typedef struct rlc_lte_stat_t {
    rlc_lte_ep_t  *ep_list;
    uint32_t      total_frames;

    /* Common stats */
    rlc_lte_common_stats common_stats;
} rlc_lte_stat_t;


/* Reset RLC stats */
static void
rlc_lte_stat_reset(void *phs)
{
    rlc_lte_stat_t *rlc_lte_stat = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t *list = rlc_lte_stat->ep_list;

    rlc_lte_stat->total_frames = 0;
    memset(&rlc_lte_stat->common_stats, 0, sizeof(rlc_lte_common_stats));

    while (list != NULL) {
        rlc_lte_ep_t *ptr = list;
        list = list->next;
        g_free(ptr);
    }
    rlc_lte_stat->ep_list = NULL;
}


/* Free memory used by tap */
static void
rlc_lte_stat_finish(void *phs)
{
    rlc_lte_stat_t *rlc_lte_stat = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t *list = rlc_lte_stat->ep_list;

    while (list != NULL) {
        rlc_lte_ep_t *ptr = list;
        list = list->next;
        g_free(ptr);
    }

    g_free(rlc_lte_stat);
}


/* Allocate a rlc_lte_ep_t struct to store info for new UE */
static rlc_lte_ep_t *alloc_rlc_lte_ep(const struct rlc_3gpp_tap_info *si, packet_info *pinfo _U_)
{
    rlc_lte_ep_t *ep;

    if (!si) {
        return NULL;
    }

    if (!(ep = g_new(rlc_lte_ep_t, 1))) {
        return NULL;
    }

    /* Copy SI data into ep->stats */
    ep->stats.rat = si->rat;
    ep->stats.ueid = si->ueid;

    /* Counts for new UE are all 0 */
    ep->stats.UL_frames = 0;
    ep->stats.DL_frames = 0;
    ep->stats.UL_total_bytes = 0;
    ep->stats.DL_total_bytes = 0;
    memset(&ep->stats.DL_time_start, 0, sizeof(nstime_t));
    memset(&ep->stats.DL_time_stop, 0, sizeof(nstime_t));
    ep->stats.UL_total_acks = 0;
    ep->stats.DL_total_acks = 0;
    ep->stats.UL_total_nacks = 0;
    ep->stats.DL_total_nacks = 0;
    ep->stats.UL_total_missing = 0;
    ep->stats.DL_total_missing = 0;

    ep->next = NULL;

    return ep;
}


/* Process stat struct for a RLC LTE frame */
static tap_packet_status
rlc_lte_stat_packet(void *phs, packet_info *pinfo, epan_dissect_t *edt _U_,
                    const void *phi, tap_flags_t flags _U_)
{
    /* Get reference to stats struct */
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t *tmp = NULL, *te = NULL;

    /* Cast tap info struct */
    const struct rlc_3gpp_tap_info *si = (const struct rlc_3gpp_tap_info *)phi;

    /* Need this */
    if (!hs) {
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Inc top-level frame count */
    hs->total_frames++;

    /* Common channel stats */
    switch (si->channelType) {
        case CHANNEL_TYPE_BCCH_BCH:
        case CHANNEL_TYPE_BCCH_DL_SCH:
            hs->common_stats.bcch_frames++;
            hs->common_stats.bcch_bytes += si->pduLength;
            return TAP_PACKET_REDRAW;

        case CHANNEL_TYPE_PCCH:
            hs->common_stats.pcch_frames++;
            hs->common_stats.pcch_bytes += si->pduLength;
            return TAP_PACKET_REDRAW;

        default:
            break;
    }

    /* For per-UE data, must create a new row if none already existing */
    if (!hs->ep_list) {
        /* Allocate new list */
        hs->ep_list = alloc_rlc_lte_ep(si, pinfo);
        /* Make it the first/only entry */
        te = hs->ep_list;
    } else {
        /* Look among existing rows for this rat/UEId */
        /* TODO: with different data structures, could avoid this linear search */
        for (tmp = hs->ep_list; (tmp != NULL); tmp = tmp->next) {
            if ((tmp->stats.rat == si->rat) &&
                (tmp->stats.ueid == si->ueid))
            {
                te = tmp;
                break;
            }
        }

        /* Not found among existing, so create a new one now */
        if (te == NULL) {
            if ((te = alloc_rlc_lte_ep(si, pinfo))) {
                /* Add new item to end of list */
                rlc_lte_ep_t *p = hs->ep_list;
                while (p->next) {
                    p = p->next;
                }
                p->next = te;
                te->next = NULL;
            }
        }
    }

    /* Really should have a row pointer by now */
    if (!te) {
        return TAP_PACKET_DONT_REDRAW;
    }

    /* Update entry with details from si */
    te->stats.ueid = si->ueid;

    /* Top-level traffic stats */
    if (si->direction == DIRECTION_UPLINK) {
        /* Update time range */
        if (te->stats.UL_frames == 0) {
            te->stats.UL_time_start = si->rlc_time;
        }
        te->stats.UL_time_stop = si->rlc_time;

        te->stats.UL_frames++;
        te->stats.UL_total_bytes += si->pduLength;
    }
    else {
        /* Update time range */
        if (te->stats.DL_frames == 0) {
            te->stats.DL_time_start = si->rlc_time;
        }
        te->stats.DL_time_stop = si->rlc_time;

        te->stats.DL_frames++;
        te->stats.DL_total_bytes += si->pduLength;
    }


    if (si->direction == DIRECTION_UPLINK) {
        if (si->isControlPDU) {
            te->stats.UL_total_acks++;
        }
        te->stats.UL_total_nacks += si->noOfNACKs;
        te->stats.UL_total_missing += si->missingSNs;
    }
    else {
        if (si->isControlPDU) {
            te->stats.DL_total_acks++;
        }
        te->stats.DL_total_nacks += si->noOfNACKs;
        te->stats.DL_total_missing += si->missingSNs;
    }

    return TAP_PACKET_REDRAW;
}


/* Calculate and return a bandwidth figure, in Mbs */
static float calculate_bw(nstime_t *start_time, nstime_t *stop_time, uint32_t bytes)
{
    /* Can only calculate bandwidth if have time delta */
    if (memcmp(start_time, stop_time, sizeof(nstime_t)) != 0) {
        float elapsed_ms = (((float)stop_time->secs - (float)start_time->secs) * 1000) +
                           (((float)stop_time->nsecs - (float)start_time->nsecs) / 1000000);

        /* Only really meaningful if have a few frames spread over time...
           For now at least avoid dividing by something very close to 0.0 */
        if (elapsed_ms < 2.0) {
           return 0.0f;
        }
        return ((bytes * 8) / elapsed_ms) / 1000;
    }
    else {
        return 0.0f;
    }
}



/* (Re)draw RLC stats */
static void
rlc_lte_stat_draw(void *phs)
{
    uint16_t number_of_ues = 0;
    int i;

    /* Look up the statistics struct */
    rlc_lte_stat_t *hs = (rlc_lte_stat_t *)phs;
    rlc_lte_ep_t *list = hs->ep_list, *tmp = 0;

    /* Common channel data */
    printf("Common Data:\n");
    printf("==============\n");
    printf("BCCH Frames: %u   BCCH Bytes: %u   PCCH Frames: %u   PCCH Bytes: %u\n\n",
           hs->common_stats.bcch_frames, hs->common_stats.bcch_bytes,
           hs->common_stats.pcch_frames, hs->common_stats.pcch_bytes);

    /* Per-UE table entries */


    /* Set title that shows how many UEs currently in table */
    for (tmp = list; (tmp!=NULL); tmp=tmp->next, number_of_ues++);
    printf("Per UE Data - %u UEs (%u frames)\n", number_of_ues, hs->total_frames);
    printf("==========================================\n");

    /* Show column titles */
    for (i=0; i < NUM_UE_COLUMNS; i++) {
        printf("%s  ", ue_titles[i]);
    }
    printf("\n");

    /* For each row/UE in the model */
    for (tmp = list; tmp; tmp=tmp->next) {
        /* Calculate bandwidth */
        float UL_bw = calculate_bw(&tmp->stats.UL_time_start,
                                   &tmp->stats.UL_time_stop,
                                   tmp->stats.UL_total_bytes);
        float DL_bw = calculate_bw(&tmp->stats.DL_time_start,
                                   &tmp->stats.DL_time_stop,
                                   tmp->stats.DL_total_bytes);

        printf("%s  %5u %10u %9u %10f %8u %9u %10u %10u %9u %10f %8u %9u %10u\n",
               (tmp->stats.rat == RLC_RAT_LTE) ? "LTE" : "NR ",
               tmp->stats.ueid,
               tmp->stats.UL_frames,
               tmp->stats.UL_total_bytes, UL_bw,
               tmp->stats.UL_total_acks,
               tmp->stats.UL_total_nacks,
               tmp->stats.UL_total_missing,
               tmp->stats.DL_frames,
               tmp->stats.DL_total_bytes, DL_bw,
               tmp->stats.DL_total_acks,
               tmp->stats.DL_total_nacks,
               tmp->stats.DL_total_missing);
    }
}




/* Create a new RLC LTE stats struct */
static bool rlc_lte_stat_init(const char *opt_arg, void *userdata _U_)
{
    rlc_lte_stat_t    *hs;
    const char        *filter = NULL;
    GString           *error_string;

    /* Check for a filter string */
    if (strncmp(opt_arg, "rlc-3gpp,stat,", 14) == 0) {
        /* Skip those characters from filter to display */
        filter = opt_arg + 14;
    }
    else {
        /* No filter */
        filter = NULL;
    }

    /* Create top-level struct */
    hs = g_new0(rlc_lte_stat_t, 1);
    hs->ep_list = NULL;


    /**********************************************/
    /* Register the tap listener                  */
    /**********************************************/

    error_string = register_tap_listener("rlc-3gpp", hs,
                                         filter, TL_REQUIRES_NOTHING,
                                         rlc_lte_stat_reset,
                                         rlc_lte_stat_packet,
                                         rlc_lte_stat_draw,
                                         rlc_lte_stat_finish);
    if (error_string) {
        g_string_free(error_string, TRUE);
        g_free(hs);
        return false;
    }

    return true;
}


/* Register this tap listener (need void on own so line register function found) */
static stat_tap_ui rlc_lte_stat_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    NULL,
    "rlc-3gpp,stat",
    rlc_lte_stat_init,
    0,
    NULL
};

void
register_tap_listener_rlc_lte_stat(void)
{
    register_stat_tap_ui(&rlc_lte_stat_ui, NULL);
}
