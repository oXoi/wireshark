/** @file
 *
 * RTP streams summary addition for Wireshark
 *
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RTP_STREAM_H__
#define __RTP_STREAM_H__

#include <glib.h>

#include "tap-rtp-analysis.h"
#include <stdio.h>

#include "cfile.h"

#include <epan/address.h>
#include <epan/tap.h>

#include "ui/rtp_stream_id.h"

/** @file
 *  "RTP Streams" dialog box common routines.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** Defines an rtp stream */
typedef struct _rtpstream_info {
    rtpstream_id_t  id;

    uint8_t         first_payload_type; /**< Numeric payload type */
    const char     *first_payload_type_name; /**< Payload type name */
    const char     *payload_type_names[256]; /**< Seen payload type names. Array index is payload type (byte), filled only during TAP_ANALYSE */
    char           *all_payload_type_names; /**< All seen payload names for a stream in one string */

    bool            is_srtp;
    uint32_t        packet_count;
    bool            end_stream; /**< Used to track streams across payload types */
    int             rtp_event;

    int             call_num; /**< Used to match call_num in voip_calls_info_t */
    uint32_t        setup_frame_number; /**< frame number of setup message */
    /* Start and stop packets needed for .num and .abs_ts */
    frame_data     *start_fd;
    frame_data     *stop_fd;
    nstime_t        start_rel_time;     /**< relative start time from pinfo */
    nstime_t        stop_rel_time;      /**< relative stop time from pinfo */
    nstime_t        start_abs_time;     /**< abs start time from pinfo */
    uint16_t        vlan_id;
    bool            tag_vlan_error;
    bool            tag_diffserv_error;

    tap_rtp_stat_t  rtp_stats;  /**< here goes the RTP statistics info */
    bool            problem;    /**< if the streams had wrong sequence numbers or wrong timestamps */
    const char     *ed137_info; /** pointer to static text, no freeing is required */
} rtpstream_info_t;

/** tapping modes */
typedef enum
{
    TAP_ANALYSE,
    TAP_SAVE,
    TAP_MARK
} tap_mode_t;

typedef struct _rtpstream_tapinfo rtpstream_tapinfo_t;

typedef void (*rtpstream_tap_reset_cb)(rtpstream_tapinfo_t *tapinfo);
typedef void (*rtpstream_tap_draw_cb)(rtpstream_tapinfo_t *tapinfo);
typedef void (*tap_mark_packet_cb)(rtpstream_tapinfo_t *tapinfo, frame_data *fd);
typedef void (*rtpstream_tap_error_cb)(GString *error_string);

/* structure that holds the information about all detected streams */
/** struct holding all information of the tap */
struct _rtpstream_tapinfo {
    rtpstream_tap_reset_cb tap_reset;       /**< tap reset callback */
    rtpstream_tap_draw_cb tap_draw;         /**< tap draw callback */
    tap_mark_packet_cb tap_mark_packet;     /**< packet marking callback */
    void              *tap_data;            /**< data for tap callbacks */
    int                nstreams; /**< number of streams in the list */
    GList             *strinfo_list; /**< list of rtpstream_info_t* */
    GHashTable        *strinfo_hash; /**< multihash of rtpstream_info_t **/
                                     /*   multihash means that there can be */
                                     /*   more values related to one hash key */
    int                npackets; /**< total number of rtp packets of all streams */
    /* used while tapping. user shouldn't modify these */
    tap_mode_t         mode;
    rtpstream_info_t  *filter_stream_fwd; /**< used as filter in some tap modes */
    rtpstream_info_t  *filter_stream_rev; /**< used as filter in some tap modes */
    FILE              *save_file;
    bool               is_registered; /**< if the tap listener is currently registered or not */
    bool               apply_display_filter; /**< if apply display filter during analyse */
};

#if 0
#define RTP_STREAM_DEBUG(...) { \
    char *RTP_STREAM_DEBUG_MSG = ws_strdup_printf(__VA_ARGS__); \
    ws_warning("rtp_stream: %s:%d %s", G_STRFUNC, __LINE__, RTP_STREAM_DEBUG_MSG); \
    g_free(RTP_STREAM_DEBUG_MSG); \
}
#else
#define RTP_STREAM_DEBUG(...)
#endif

/****************************************************************************/
/* INTERFACE */

void show_tap_registration_error(GString *error_string);

/**
* Scans all packets for RTP streams and updates the RTP streams list.
* (redissects all packets)
*/
void rtpstream_scan(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, const char *fstring);

/**
* Saves an RTP stream as raw data stream with timestamp information for later RTP playback.
* (redissects all packets)
*/
bool rtpstream_save(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtpstream_info_t* stream, const char *filename);

/**
* Marks all packets belonging to either of stream_fwd or stream_rev.
* (both can be NULL)
* (redissects all packets)
*/
void rtpstream_mark(rtpstream_tapinfo_t *tapinfo, capture_file *cap_file, rtpstream_info_t* stream_fwd, rtpstream_info_t* stream_rev);

/**
* Sets whether only packets that pass the current main display filter should
* be scanned for RTP streams.
*/
void rtpstream_set_apply_display_filter(rtpstream_tapinfo_t *tapinfo, bool apply);

/* Constant based on fix for bug 4119/5902: don't insert too many silence
 * frames.
 */
#define MAX_SILENCE_FRAMES 14400000

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __RTP_STREAM_H__ */
