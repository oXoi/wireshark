/* packet-ipx.h
 * Routines for NetWare's IPX
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * NDPS support and SPX Defragmentation added by Greg Morris (gmorris@novell.com)
 *
 * Portions Copyright (c) by Gilbert Ramirez 2000-2002
 * Portions Copyright (c) Novell, Inc. 2002-2003
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 *  ipxlib.h
 *
 *  Copyright (C) 1995 by Volker Lendecke
 *
 */

#ifndef __PACKET_IPX_H__
#define __PACKET_IPX_H__

#define IPX_NODE_LEN	6

typedef uint32_t	IPXNet;
typedef uint16_t	IPXPort;
typedef uint8_t	IPXNode[IPX_NODE_LEN];
typedef const uint8_t	CIPXNode[IPX_NODE_LEN];

#define IPX_USER_PTYPE (0x00)
#define IPX_RIP_PTYPE (0x01)
#define IPX_SAP_PTYPE (0x04)
#define IPX_AUTO_PORT (0x0000)
#define IPX_SAP_PORT  (0x0452)
#define IPX_RIP_PORT  (0x0453)

#define IPX_SAP_GENERAL_QUERY (0x0001)
#define IPX_SAP_GENERAL_RESPONSE (0x0002)
#define IPX_SAP_NEAREST_QUERY (0x0003)
#define IPX_SAP_NEAREST_RESPONSE (0x0004)

#define IPX_SAP_FILE_SERVER (0x0004)

struct sap_query
{
	uint16_t	query_type;	/* net order */
	uint16_t	server_type;	/* net order */
};

#define IPX_RIP_REQUEST (0x1)
#define IPX_RIP_RESPONSE (0x2)

typedef struct _ipx_rt_def
{
	uint32_t network ;
	uint16_t hops ;
	uint16_t ticks ;
} ipx_rt_def_t;

struct ipx_rip_packet
{
	uint16_t operation ;
	ipx_rt_def_t rt[1] ;
};

#define IPX_BROADCAST_NODE ("\xff\xff\xff\xff\xff\xff")
#define IPX_THIS_NODE      ("\0\0\0\0\0\0")
#define IPX_THIS_NET (0)

#ifndef IPX_NODE_LEN
#define IPX_NODE_LEN (6)
#endif

/*
 * From:
 *
 *	http://alr.base2co.com:457/netguide/dipxD.ipx_packet_struct.html
 *
 * which is part of SCO's "Network Programmer's Guide and Reference".
 *
 * It calls type 20 "NetBIOS name packet".  Microsoft Network Monitor
 * calls it "WAN Broadcast"; it's also used for SMB browser announcements,
 * i.e. NetBIOS (broadcast) datagrams.
 */
#define IPX_PACKET_TYPE_IPX		0
#define IPX_PACKET_TYPE_RIP		1
#define	IPX_PACKET_TYPE_ECHO		2
#define	IPX_PACKET_TYPE_ERROR		3
#define IPX_PACKET_TYPE_PEP		4
#define IPX_PACKET_TYPE_SPX		5
#define IPX_PACKET_TYPE_NCP		17
#define IPX_PACKET_TYPE_WANBCAST	20	/* propagated NetBIOS packet? */

/* info on these sockets can be found in this listing from Novell:

	http://developer.novell.com/engsup/sample/tids/dsoc1b/dsoc1b.htm
*/

#define IPX_SOCKET_PING_CISCO           0x0002 /* In cisco this is set with: ipx ping-default cisco */
#define IPX_SOCKET_NCP			0x0451
#define IPX_SOCKET_SAP			0x0452
#define IPX_SOCKET_IPXRIP		0x0453
#define IPX_SOCKET_NETBIOS		0x0455
#define IPX_SOCKET_DIAGNOSTIC		0x0456
#define IPX_SOCKET_SERIALIZATION	0x0457
#define IPX_SOCKET_NWLINK_SMB_SERVER	0x0550
#define IPX_SOCKET_NWLINK_SMB_NAMEQUERY	0x0551
#define IPX_SOCKET_NWLINK_SMB_REDIR	0x0552
#define IPX_SOCKET_NWLINK_SMB_MAILSLOT	0x0553
#define IPX_SOCKET_NWLINK_SMB_MESSENGER	0x0554
#define IPX_SOCKET_NWLINK_SMB_BROWSE	0x0555 /* ? not sure on this
	but I guessed based on the content of the packet I saw */
#define IPX_SOCKET_ATTACHMATE_GW	0x055d
#define IPX_SOCKET_IPX_MESSAGE		0x4001
#define IPX_SOCKET_IPX_MESSAGE1		0x4003
#define IPX_SOCKET_ADSM                 0x8522 /* www.tivoli.com */
#define IPX_SOCKET_EIGRP                0x85be /* cisco ipx eigrp */
#define IPX_SOCKET_NLSP			0x9001 /* NetWare Link Services Protocol */
#define IPX_SOCKET_IPXWAN               0x9004 /* IPX WAN (RFC 1362, NLSP spec) */
#define IPX_SOCKET_SNMP_AGENT           0x900F /* RFC 1906 */
#define IPX_SOCKET_SNMP_SINK            0x9010 /* RFC 1906 */
#define IPX_SOCKET_PING_NOVELL          0x9086 /* In cisco this is set with: ipx ping-default novell */
#define IPX_SOCKET_TCP_TUNNEL           0x9091 /* RFC 1791 */
#define IPX_SOCKET_UDP_TUNNEL           0x9092 /* RFC 1791 */
#define SPX_SOCKET_PA                   0x90b2 /* NDPS Printer Agent */
#define SPX_SOCKET_BROKER               0x90b3 /* NDPS Broker */
#define SPX_SOCKET_SRS                  0x90b4 /* NDPS Service Registry Service */
#define SPX_SOCKET_ENS                  0x90b5 /* NDPS Event Notification Service */
#define SPX_SOCKET_RMS                  0x90b6 /* NDPS Remote Management Service */
#define SPX_SOCKET_NOTIFY_LISTENER      0x90b7 /* NDPS Notify Listener */

extern value_string_ext ipx_socket_vals_ext;
extern value_string_ext novell_server_vals_ext;

/*
 * Structure passed to SPX subdissectors, containing information from
 * the SPX header that might be useful to the subdissector.
 */
typedef struct {
	bool eom;			/* end-of-message flag in SPX header */
	uint8_t	datastream_type;	/* datastream type from SPX header */
} spx_info;



/* handed off to tap listeners,  expand it as is required by what any
   tap listeners needs */
typedef struct _ipxhdr_t
{
	uint16_t ipx_ssocket;
	uint16_t ipx_dsocket;
	uint16_t ipx_length;
	uint8_t ipx_type;
	address ipx_src;
	address ipx_dst;
} ipxhdr_t;


#endif
