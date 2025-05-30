/* dbs-etherwatch.c
 *
 * Wiretap Library
 * Copyright (c) 2001 by Marc Milgram <ethereal@mmilgram.NOSPAMmail.net>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "dbs-etherwatch.h"
#include "wtap-int.h"
#include "file_wrappers.h"

#include <stdlib.h>
#include <string.h>

/* This module reads the text output of the 'DBS-ETHERTRACE' command in VMS
 * It was initially based on vms.c.
 */

/*
   Example 'ETHERWATCH' output data (with "printable" characters in the
   "printable characters" section of the output replaced by "." if they have
   the 8th bit set, so as not to upset compilers that are expecting text
   in comments to be in a particular character encoding that can't handle
   those values):
ETHERWATCH  X5-008
42 names and addresses were loaded
Reading recorded data from PERSISTENCE
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   60 byte buffer at 10-OCT-2001 10:20:45.16
  [E..<8...........]-    0-[45 00 00 3C 38 93 00 00 1D 06 D2 12 80 93 11 1A]
  [.........(......]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 90 00 00 00 00]
  [................]-   32-[A0 02 FF FF 95 BD 00 00 02 04 05 B4 03 03 04 01]
  [............    ]-   48-[01 01 08 0A 90 90 E5 14 00 00 00 00]
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   50 byte buffer at 10-OCT-2001 10:20:45.17
  [E..(8......%....]-    0-[45 00 00 28 38 94 00 00 1D 06 D2 25 80 93 11 1A]
  [.........(..Z.4w]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 91 5A 1C 34 77]
  [P.#(.s..........]-   32-[50 10 23 28 C1 73 00 00 02 04 05 B4 03 03 00 00]
  [..              ]-   48-[02 04]


Alternative HEX only output, slightly more efficient and all wireshark needs:
------------------------------------------------------------------------------
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   50 byte buffer at 10-OCT-2001 10:20:45.17
     0-[45 00 00 28 38 9B 00 00 1D 06 D2 1E 80 93 11 1A 80 93 80 D6]
    20-[02 D2 02 03 00 28 A4 BF 5A 1C 34 79 50 10 23 28 C1 43 00 00]
    40-[03 30 30 30 30 30 00 00 03 30]
 */

/* Magic text to check for DBS-ETHERWATCH-ness of file */
static const char dbs_etherwatch_hdr_magic[]  =
{ 'E', 'T', 'H', 'E', 'R', 'W', 'A', 'T', 'C', 'H', ' '};
#define DBS_ETHERWATCH_HDR_MAGIC_SIZE  \
        array_length(dbs_etherwatch_hdr_magic)

/* Magic text for start of packet */
static const char dbs_etherwatch_rec_magic[]  =
{'F', 'r', 'o', 'm', ' '};
#define DBS_ETHERWATCH_REC_MAGIC_SIZE \
    array_length(dbs_etherwatch_rec_magic)

/*
 * Default packet size - maximum normal Ethernet packet size, without an
 * FCS.
 */
#define DBS_ETHERWATCH_MAX_ETHERNET_PACKET_LEN   1514

static bool dbs_etherwatch_read(wtap *wth, wtap_rec *rec,
    int *err, char **err_info, int64_t *data_offset);
static bool dbs_etherwatch_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, int *err, char **err_info);
static bool parse_dbs_etherwatch_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
    int *err, char **err_info);
static unsigned parse_single_hex_dump_line(char* rec, uint8_t *buf,
    int byte_offset);
static unsigned parse_hex_dump(char* dump, uint8_t *buf, char separator, char end);

static int dbs_etherwatch_file_type_subtype = -1;

void register_dbs_etherwatch(void);

/* Seeks to the beginning of the next packet, and returns the
   byte offset.  Returns -1 on failure, and sets "*err" to the error
   and "*err_info" to null or an additional error string. */
static int64_t dbs_etherwatch_seek_next_packet(wtap *wth, int *err,
                                              char **err_info)
{
    int byte;
    unsigned int level = 0;
    int64_t cur_off;

    while ((byte = file_getc(wth->fh)) != EOF) {
        if (byte == dbs_etherwatch_rec_magic[level]) {
            level++;
            if (level >= DBS_ETHERWATCH_REC_MAGIC_SIZE) {
                /* note: we're leaving file pointer right after the magic characters */
                cur_off = file_tell(wth->fh);
                if (cur_off == -1) {
                    /* Error. */
                    *err = file_error(wth->fh, err_info);
                    return -1;
                }
                return cur_off + 1;
            }
        } else {
            level = 0;
        }
    }
    /* EOF or error. */
    *err = file_error(wth->fh, err_info);
    return -1;
}

#define DBS_ETHERWATCH_HEADER_LINES_TO_CHECK    200
#define DBS_ETHERWATCH_LINE_LENGTH      240

/* Look through the first part of a file to see if this is
 * a DBS Ethertrace text trace file.
 *
 * Returns true if it is, false if it isn't or if we get an I/O error;
 * if we get an I/O error, "*err" will be set to a non-zero value and
 * "*err_info" will be set to null or an error string.
 */
static bool dbs_etherwatch_check_file_type(wtap *wth, int *err,
    char **err_info)
{
    char    buf[DBS_ETHERWATCH_LINE_LENGTH];
    int line, byte;
    size_t  reclen;
    unsigned int i, level;

    buf[DBS_ETHERWATCH_LINE_LENGTH-1] = 0;

    for (line = 0; line < DBS_ETHERWATCH_HEADER_LINES_TO_CHECK; line++) {
        if (file_gets(buf, DBS_ETHERWATCH_LINE_LENGTH, wth->fh) == NULL) {
            /* EOF or error. */
            *err = file_error(wth->fh, err_info);
            return false;
        }

        reclen = strlen(buf);
        if (reclen < DBS_ETHERWATCH_HDR_MAGIC_SIZE)
            continue;

        level = 0;
        for (i = 0; i < reclen; i++) {
            byte = buf[i];
            if (byte == dbs_etherwatch_hdr_magic[level]) {
                level++;
                if (level >=
                      DBS_ETHERWATCH_HDR_MAGIC_SIZE) {
                    return true;
                }
            }
            else
                level = 0;
        }
    }
    *err = 0;
    return false;
}


wtap_open_return_val dbs_etherwatch_open(wtap *wth, int *err, char **err_info)
{
    /* Look for DBS ETHERWATCH header */
    if (!dbs_etherwatch_check_file_type(wth, err, err_info)) {
        if (*err != 0 && *err != WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_ERROR;
        return WTAP_OPEN_NOT_MINE;
    }

    wth->file_encap = WTAP_ENCAP_ETHERNET;
    wth->file_type_subtype = dbs_etherwatch_file_type_subtype;
    wth->snapshot_length = 0;   /* not known */
    wth->subtype_read = dbs_etherwatch_read;
    wth->subtype_seek_read = dbs_etherwatch_seek_read;
    wth->file_tsprec = WTAP_TSPREC_10_MSEC;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/* Find the next packet and parse it; called from wtap_read(). */
static bool dbs_etherwatch_read(wtap *wth, wtap_rec *rec,
    int *err, char **err_info, int64_t *data_offset)
{
    int64_t offset;

    /* Find the next packet */
    offset = dbs_etherwatch_seek_next_packet(wth, err, err_info);
    if (offset < 1)
        return false;
    *data_offset = offset;

    /* Parse the packet */
    return parse_dbs_etherwatch_packet(wth, wth->fh, rec, err, err_info);
}

/* Used to read packets in random-access fashion */
static bool
dbs_etherwatch_seek_read(wtap *wth, int64_t seek_off,
    wtap_rec *rec, int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off - 1, SEEK_SET, err) == -1)
        return false;

    return parse_dbs_etherwatch_packet(wth, wth->random_fh, rec, err, err_info);
}

/* Parse a packet */
/*
Packet header:
          1         2         3         4
0123456789012345678901234567890123456789012345
From 00-D0-C0-D2-4D-60 [MF1] to AA-00-04-00-FC-94 [PSERVB]
Protocol 08-00 00 00-00-00-00-00,   50 byte buffer at 10-OCT-2001 10:20:45.17
*/
#define MAC_ADDR_LENGTH     6           /* Length MAC address */
#define DEST_MAC_PREFIX     "] to "     /* Prefix to the dest. MAC address */
#define PROTOCOL_LENGTH     2           /* Length protocol */
#define PROTOCOL_POS        9           /* Position protocol */
#define SAP_LENGTH          2           /* Length DSAP+SSAP */
#define SAP_POS             9           /* Position DSAP+SSAP */
#define CTL_UNNUMB_LENGTH   1           /* Length unnumbered control field */
#define CTL_NUMB_LENGTH     2           /* Length numbered control field */
#define CTL_POS             15          /* Position control field */
#define PID_LENGTH          5           /* Length PID */
#define PID_POS             18          /* Position PID */
#define LENGTH_POS          33          /* Position length */
#define HEX_HDR_SPR         '-'         /* Separator char header hex values */
#define HEX_HDR_END         ' '         /* End char hdr. hex val. except PID */
#define HEX_PID_END         ','         /* End char PID hex value */
#define IEEE802_LEN_LEN     2           /* Length of the IEEE 802 len. field */
/*
To check whether it is Ethernet II or IEEE 802 we check the values of the
control field and PID, when they are all 0's we assume it is Ethernet II
else IEEE 802. In IEEE 802 the DSAP and SSAP are behind protocol, the
length in the IEEE data we have to construct.
*/
#define ETH_II_CHECK_POS    15
#define ETH_II_CHECK_STR    "00 00-00-00-00-00,"
/*
To check whether it IEEE 802.3 with SNAP we check that both the DSAP & SSAP
values are 0xAA and the control field 0x03.
*/
#define SNAP_CHECK_POS      9
#define SNAP_CHECK_STR      "AA-AA 03"
/*
To check whether the control field is 1 or two octets we check if it is
unnumbered. Unnumbered has length 1, numbered 2.
*/
#define CTL_UNNUMB_MASK     0x03
#define CTL_UNNUMB_VALUE    0x03
static bool
parse_dbs_etherwatch_packet(wtap *wth, FILE_T fh, wtap_rec *rec,
    int *err, char **err_info)
{
    uint8_t *pd;
    char    line[DBS_ETHERWATCH_LINE_LENGTH];
    int num_items_scanned;
    int eth_hdr_len, pkt_len, csec;
    int length_pos, length_from, length;
    struct tm tm;
    char mon[4] = "xxx";
    char *p;
    static const char months[] = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC";
    int count, line_count;

    /* Make sure we have enough room for a regular Ethernet packet */
    ws_buffer_assure_space(&rec->data, DBS_ETHERWATCH_MAX_ETHERNET_PACKET_LEN);
    pd = ws_buffer_start_ptr(&rec->data);

    eth_hdr_len = 0;
    memset(&tm, 0, sizeof(tm));
    /* Our file pointer should be on the first line containing the
     * summary information for a packet. Read in that line and
     * extract the useful information
     */
    if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
        *err = file_error(fh, err_info);
        if (*err == 0) {
            *err = WTAP_ERR_SHORT_READ;
        }
        return false;
    }

    /* Get the destination address */
    p = strstr(line, DEST_MAC_PREFIX);
    if(!p) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("dbs_etherwatch: destination address not found");
        return false;
    }
    p += strlen(DEST_MAC_PREFIX);
    if(parse_hex_dump(p, &pd[eth_hdr_len], HEX_HDR_SPR, HEX_HDR_END)
                != MAC_ADDR_LENGTH) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("dbs_etherwatch: destination address not valid");
        return false;
    }
    eth_hdr_len += MAC_ADDR_LENGTH;

    /* Get the source address */
    /*
     * Since the first part of the line is already skipped in order to find
     * the start of the record we cannot index, just look for the first
     * 'HEX' character
     */
    p = line;
    while(!g_ascii_isxdigit(*p)) {
        p++;
    }
    if(parse_hex_dump(p, &pd[eth_hdr_len], HEX_HDR_SPR,
        HEX_HDR_END) != MAC_ADDR_LENGTH) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("dbs_etherwatch: source address not valid");
        return false;
    }
    eth_hdr_len += MAC_ADDR_LENGTH;

    /* Read the next line of the record header */
    if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
        *err = file_error(fh, err_info);
        if (*err == 0) {
            *err = WTAP_ERR_SHORT_READ;
        }
        return false;
    }

    /* Check the lines is as least as long as the length position */
    if(strlen(line) < LENGTH_POS) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("dbs_etherwatch: line too short");
        return false;
    }

    num_items_scanned = sscanf(line + LENGTH_POS,
                "%9d byte buffer at %2d-%3s-%4d %2d:%2d:%2d.%9d",
                &pkt_len,
                &tm.tm_mday, mon,
                &tm.tm_year, &tm.tm_hour, &tm.tm_min,
                &tm.tm_sec, &csec);

    if (num_items_scanned != 8) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("dbs_etherwatch: header line not valid");
        return false;
    }

    if (pkt_len < 0) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("dbs_etherwatch: packet header has a negative packet length");
        return false;
    }

    /* Determine whether it is Ethernet II or IEEE 802 */
    if(strncmp(&line[ETH_II_CHECK_POS], ETH_II_CHECK_STR,
        strlen(ETH_II_CHECK_STR)) == 0) {
        /* Ethernet II */
        /* Get the Protocol */
        if(parse_hex_dump(&line[PROTOCOL_POS], &pd[eth_hdr_len], HEX_HDR_SPR,
                    HEX_HDR_END) != PROTOCOL_LENGTH) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("dbs_etherwatch: Ethernet II protocol value not valid");
            return false;
        }
        eth_hdr_len += PROTOCOL_LENGTH;
    } else {
        /* IEEE 802 */
        /* Remember where to put the length in the header */
        length_pos = eth_hdr_len;
        /* Leave room in the header for the length */
        eth_hdr_len += IEEE802_LEN_LEN;
        /* Remember how much of the header should not be added to the length */
        length_from = eth_hdr_len;
        /* Get the DSAP + SSAP */
        if(parse_hex_dump(&line[SAP_POS], &pd[eth_hdr_len], HEX_HDR_SPR,
                    HEX_HDR_END) != SAP_LENGTH) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("dbs_etherwatch: 802.2 DSAP+SSAP value not valid");
            return false;
        }
        eth_hdr_len += SAP_LENGTH;
        /* Get the (first part of the) control field */
        if(parse_hex_dump(&line[CTL_POS], &pd[eth_hdr_len], HEX_HDR_SPR,
                    HEX_HDR_END) != CTL_UNNUMB_LENGTH) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("dbs_etherwatch: 802.2 control field first part not valid");
            return false;
        }
        /* Determine whether the control is numbered, and thus longer */
        if((pd[eth_hdr_len] & CTL_UNNUMB_MASK) != CTL_UNNUMB_VALUE) {
            /* Get the rest of the control field, the first octet in the PID */
            if(parse_hex_dump(&line[PID_POS],
                        &pd[eth_hdr_len + CTL_UNNUMB_LENGTH], HEX_HDR_END,
                        HEX_HDR_SPR) != CTL_NUMB_LENGTH - CTL_UNNUMB_LENGTH) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("dbs_etherwatch: 802.2 control field second part value not valid");
                return false;
            }
            eth_hdr_len += CTL_NUMB_LENGTH;
        } else {
            eth_hdr_len += CTL_UNNUMB_LENGTH;
        }
        /* Determine whether it is SNAP */
        if(strncmp(&line[SNAP_CHECK_POS], SNAP_CHECK_STR,
                strlen(SNAP_CHECK_STR)) == 0) {
            /* Get the PID */
            if(parse_hex_dump(&line[PID_POS], &pd[eth_hdr_len], HEX_HDR_SPR,
                        HEX_PID_END) != PID_LENGTH) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("dbs_etherwatch: 802.2 PID value not valid");
                return false;
            }
            eth_hdr_len += PID_LENGTH;
        }
        /* Write the length in the header */
        length = eth_hdr_len - length_from + pkt_len;
        pd[length_pos] = (length) >> 8;
        pd[length_pos+1] = (length) & 0xFF;
    }

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;

    p = strstr(months, mon);
    if (p)
        tm.tm_mon = (int)(p - months) / 3;
    tm.tm_year -= 1900;

    tm.tm_isdst = -1;
    rec->ts.secs = mktime(&tm);
    rec->ts.nsecs = csec * 10000000;
    rec->rec_header.packet_header.caplen = eth_hdr_len + pkt_len;
    rec->rec_header.packet_header.len = eth_hdr_len + pkt_len;

    if (rec->rec_header.packet_header.caplen > WTAP_MAX_PACKET_SIZE_STANDARD) {
        /*
         * Probably a corrupt capture file; return an error,
         * so that our caller doesn't blow up trying to allocate
         * space for an immensely-large packet.
         */
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("dbs_etherwatch: File has %u-byte packet, bigger than maximum of %u",
                                    rec->rec_header.packet_header.caplen, WTAP_MAX_PACKET_SIZE_STANDARD);
        return false;
    }

    /* Make sure we have enough room, even for an oversized Ethernet packet */
    ws_buffer_assure_space(&rec->data, rec->rec_header.packet_header.caplen);
    pd = ws_buffer_start_ptr(&rec->data);

    /*
     * We don't have an FCS in this frame.
     */
    rec->rec_header.packet_header.pseudo_header.eth.fcs_len = 0;

    /* Parse the hex dump */
    count = 0;
    while (count < pkt_len) {
        if (file_gets(line, DBS_ETHERWATCH_LINE_LENGTH, fh) == NULL) {
            *err = file_error(fh, err_info);
            if (*err == 0) {
                *err = WTAP_ERR_SHORT_READ;
            }
            return false;
        }
        if (!(line_count = parse_single_hex_dump_line(line,
                &pd[eth_hdr_len + count], count))) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("dbs_etherwatch: packet data value not valid");
            return false;
        }
        count += line_count;
        if (count > pkt_len) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("dbs_etherwatch: packet data value has too many bytes");
            return false;
        }
    }
    return true;
}

/* Parse a hex dump line */
/*
/DISPLAY=BOTH output:

          1         2         3         4
0123456789012345678901234567890123456789012345
  [E..(8...........]-    0-[45 00 00 28 38 9B 00 00 1D 06 D2 1E 80 93 11 1A]
  [.........(..Z.4y]-   16-[80 93 80 D6 02 D2 02 03 00 28 A4 BF 5A 1C 34 79]
  [P.#(.C...00000..]-   32-[50 10 23 28 C1 43 00 00 03 30 30 30 30 30 00 00]
  [.0              ]-   48-[03 30]

/DISPLAY=HEXADECIMAL output:

          1         2         3         4
0123456789012345678901234567890123456789012345
     0-[45 00 00 28 38 9B 00 00 1D 06 D2 1E 80 93 11 1A 80 93 80 D6]
    20-[02 D2 02 03 00 28 A4 BF 5A 1C 34 79 50 10 23 28 C1 43 00 00]
    40-[03 30 30 30 30 30 00 00 03 30]

*/

#define TYPE_CHECK_POS      2   /* Position to check the type of hex dump */
#define TYPE_CHECK_BOTH     '[' /* Value at pos. that indicates BOTH type */
#define COUNT_POS_BOTH      21  /* Count position BOTH type */
#define COUNT_POS_HEX       1   /* Count position HEX type */
#define COUNT_SIZE      5   /* Length counter */
#define HEX_DUMP_START      '[' /* Start char */
#define HEX_DUMP_SPR        ' ' /* Separator char */
#define HEX_DUMP_END        ']' /* End char */

/* Take a string representing one line from a hex dump and converts the
 * text to binary data. We check the printed offset with the offset
 * we are passed to validate the record. We place the bytes in the buffer
 * at the specified offset.
 *
 * Returns length parsed if a good hex dump, 0 if bad.
 */
static unsigned
parse_single_hex_dump_line(char* rec, uint8_t *buf, int byte_offset) {

    int     pos, i;
    int     value;


    /* Check that the record is as least as long as the check offset */
    for(i = 0; i < TYPE_CHECK_POS; i++)
    {
        if(rec[i] == '\0') {
            return 0;
        }
    }
    /* determine the format and thus the counter offset and hex dump length */
    if(rec[TYPE_CHECK_POS] == TYPE_CHECK_BOTH)
    {
        pos = COUNT_POS_BOTH;
    }
    else
    {
        pos = COUNT_POS_HEX;
    }

    /* Check that the record is as least as long as the start position */
    while(i < pos)
    {
        if(rec[i] == '\0') {
            return 0;
        }
        i++;
    }

    /* Get the byte_offset directly from the record */
    value = 0;
    for(i = 0; i < COUNT_SIZE; i++) {
        if(!g_ascii_isspace(rec[pos])) {
            if(g_ascii_isdigit(rec[pos])) {
                value *= 10;
                value += rec[pos] - '0';
            } else {
                return 0;
            }
        }
        pos++;
    }

    if (value != byte_offset) {
        return 0;
    }

    /* find the start of the hex dump */
    while(rec[pos] != HEX_DUMP_START) {
        if(rec[pos] == '\0') {
            return 0;
        }
        pos++;
    }
    pos++;
    return parse_hex_dump(&rec[pos], buf, HEX_DUMP_SPR, HEX_DUMP_END);
}

/* Parse a hex dump */
static unsigned
parse_hex_dump(char* dump, uint8_t *buf, char separator, char end) {
    int     pos, count;

    /* Parse the hex dump */
    pos = 0;
    count = 0;
    while(dump[pos] != end) {
        /* Check the hex value */
        if(!(g_ascii_isxdigit(dump[pos]) &&
            g_ascii_isxdigit(dump[pos + 1]))) {
            return 0;
        }
        /* Get the hex value */
        if(g_ascii_isdigit(dump[pos])) {
            buf[count] = (dump[pos] - '0') << 4;
        } else {
            buf[count] = (g_ascii_toupper(dump[pos]) - 'A' + 10) << 4;
        }
        pos++;
        if(g_ascii_isdigit(dump[pos])) {
            buf[count] += dump[pos] - '0';
        } else {
            buf[count] += g_ascii_toupper(dump[pos]) - 'A' + 10;
        }
        pos++;
        count++;
        /* Skip the separator characters */
        while(dump[pos] == separator) {
            pos++;
        }
    }
    return count;
}

static const struct supported_block_type dbs_etherwatch_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info dbs_etherwatch_info = {
    "DBS Etherwatch (VMS)", "etherwatch", "txt", NULL,
    false, BLOCKS_SUPPORTED(dbs_etherwatch_blocks_supported),
    NULL, NULL, NULL
};

void register_dbs_etherwatch(void)
{
    dbs_etherwatch_file_type_subtype = wtap_register_file_type_subtype(&dbs_etherwatch_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("DBS_ETHERWATCH",
                                                   dbs_etherwatch_file_type_subtype);
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
