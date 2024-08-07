/* packet-umts_mac.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_UMTS_MAC_H
#define PACKET_UMTS_MAC_H

/* Target Channel Type Field (TCTF) values */
#define TCTF_CCCH_RACH_FDD      0x0
#define TCTF_DCCH_DTCH_RACH_FDD 0x1

#define TCTF_BCCH_FACH_FDD      0x0
#define TCTF_DCCH_DTCH_FACH_FDD 0x3
#define TCTF_MTCH_FACH_FDD      0x6
#define TCTF_CCCH_FACH_FDD      0x40
#define TCTF_MCCH_FACH_FDD      0x50
#define TCTF_MSCH_FACH_FDD      0x5f
#define TCTF_CTCH_FACH_FDD      0x80

/* UeID Type values */
#define MAC_UEID_TYPE_URNTI     0x0
#define MAC_UEID_TYPE_CRNTI     0x1

enum mac_content_type {
    MAC_CONTENT_UNKNOWN,
    MAC_CONTENT_DCCH,
    MAC_CONTENT_PS_DTCH,
    MAC_CONTENT_CS_DTCH,
    MAC_CONTENT_CCCH
};

/* Used for mapping id to string names*/
#define MAC_PCCH    0
#define MAC_CCCH    1
#define MAC_CTCH    2
#define MAC_DCCH    3
#define MAC_DTCH    4
#define MAC_BCCH    5
#define MAC_MCCH    6
#define MAC_MSCH    7
#define MAC_MTCH    8
#define MAC_N_A     9

#define MAX_MAC_FRAMES 64
typedef struct umts_mac_info
{
    bool ctmux[MAX_MAC_FRAMES];
    uint8_t content[MAX_MAC_FRAMES];
    uint8_t lchid[MAX_MAC_FRAMES];       /*Makes displaying logical channel a lot easier*/
    uint8_t macdflow_id[MAX_MAC_FRAMES]; /*Makes displaying logical channel a lot easier*/

    bool fake_chid[MAX_MAC_FRAMES]; /*Indicate if the child ID is faked or not*/
    unsigned pdu_len;                      /*Length of MAC PDU, same for all PDUs in one FP frame*/
    uint8_t trchid[MAX_MAC_FRAMES];      /*Makes displaying logical channel a lot easier*/
} umts_mac_info;

typedef struct
{
    unsigned number_of_mac_is_sdus;
    uint8_t lchid[MAX_MAC_FRAMES];
    int sdulength[MAX_MAC_FRAMES];
} umts_mac_is_info;

enum enum_mac_tsn_size {
    MAC_TSN_6BITS,
    MAC_TSN_14BITS
};
int get_mac_tsn_size(void);

#endif
