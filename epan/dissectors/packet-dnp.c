/* packet-dnp.c
 * Routines for DNP dissection
 * Copyright 2003, 2006, 2007, 2013 Graham Bloice <graham.bloice<at>trihedral.com>
 *
 * DNP3.0 Application Layer Object dissection added by Chris Bontje (cbontje<at>gmail.com)
 * Device attribute and Secure Authentication object dissection added by Chris Bontje
 * Copyright 2005, 2013, 2023
 *
 * Major updates: tcp and application layer defragmentation, more object dissections by Graham Bloice
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-tcp.h"
#include "packet-udp.h"
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/crc16-tvb.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/crc16.h>
#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/tap.h>
#include <epan/conversation_table.h>
#include "packet-tls.h"

/*
 * See
 *
 * http://www.dnp.org/
 *
 * although note that you have to join the DNP organization to get to
 * see the protocol specs online - otherwise, you have to buy a
 * dead-tree version.
 *
 * ...Application Layer Notes...
 *
 * Application Layer Decoding based on information available in
 * DNP3 Basic 4 Documentation Set, specifically the document:
 * "DNP V3.00 Application Layer" v0.03 P009-0PD.APP & Technical Bulletins
 *
 * ---------------------------------------------------------------------------
 *
 * Several command codes were missing, causing the dissector to abort decoding
 * on valid packets.  Those commands have been added.
 *
 * The semantics of Variation 0 have been cleaned up.  Variation 0 is the
 * "Default Variation".  It is used only in Master -> Slave read commands
 * to request the data in whatever variation the Slave is configured to use by
 * default. Decoder strings have been added to the Binary Output and
 * Analog Output objects (10 and 40) so that group read commands will
 * decode properly.
 *
 * Roy M. Silvernail <roy@rant-central.com> 01/05/2009
 *
 */

/***************************************************************************/
/* DNP 3.0 Constants */
/***************************************************************************/
#define DNP_HDR_LEN     10
#define TCP_PORT_DNP    20000
#define UDP_PORT_DNP    20000
#define TCP_PORT_DNP_TLS    19999

/***************************************************************************/
/* Datalink and Transport Layer Bit-Masks */
/***************************************************************************/
#define DNP3_CTL_DIR    0x80
#define DNP3_CTL_PRM    0x40
#define DNP3_CTL_FCB    0x20
#define DNP3_CTL_FCV    0x10
#define DNP3_CTL_RES    0x20
#define DNP3_CTL_DFC    0x10
#define DNP3_CTL_FUNC   0x0f

#define DNP3_TR_FIR     0x40
#define DNP3_TR_FIN     0x80
#define DNP3_TR_SEQ     0x3f

#define AL_MAX_CHUNK_SIZE 16

/***************************************************************************/
/* Data Link Function codes */
/***************************************************************************/
/* Primary to Secondary */
#define DL_FUNC_RESET_LINK  0x00
#define DL_FUNC_RESET_PROC  0x01
#define DL_FUNC_TEST_LINK   0x02
#define DL_FUNC_USER_DATA   0x03
#define DL_FUNC_UNC_DATA    0x04
#define DL_FUNC_LINK_STAT   0x09

/* Secondary to Primary */
#define DL_FUNC_ACK         0x00
#define DL_FUNC_NACK        0x01
#define DL_FUNC_STAT_LINK   0x0B
#define DL_FUNC_NO_FUNC     0x0E
#define DL_FUNC_NOT_IMPL    0x0F

/***************************************************************************/
/* Application Layer Bit-Masks */
/***************************************************************************/
#define DNP3_AL_UNS   0x10
#define DNP3_AL_CON   0x20
#define DNP3_AL_FIN   0x40
#define DNP3_AL_FIR   0x80
#define DNP3_AL_SEQ   0x0f
#define DNP3_AL_FUNC  0xff

/***************************************************************************/
/* Application Layer Function codes */
/***************************************************************************/
#define AL_FUNC_CONFIRM    0x00    /* 00  - Confirm */
#define AL_FUNC_READ       0x01    /* 01  - Read */
#define AL_FUNC_WRITE      0x02    /* 02  - Write */
#define AL_FUNC_SELECT     0x03    /* 03  - Select */
#define AL_FUNC_OPERATE    0x04    /* 04  - Operate */
#define AL_FUNC_DIROP      0x05    /* 05  - Direct Operate */
#define AL_FUNC_DIROPNACK  0x06    /* 06  - Direct Operate No ACK */
#define AL_FUNC_FRZ        0x07    /* 07  - Immediate Freeze */
#define AL_FUNC_FRZNACK    0x08    /* 08  - Immediate Freeze No ACK */
#define AL_FUNC_FRZCLR     0x09    /* 09  - Freeze and Clear */
#define AL_FUNC_FRZCLRNACK 0x0A    /* 10  - Freeze and Clear No ACK */
#define AL_FUNC_FRZT       0x0B    /* 11  - Freeze With Time */
#define AL_FUNC_FRZTNACK   0x0C    /* 12  - Freeze With Time No ACK */
#define AL_FUNC_COLDRST    0x0D    /* 13  - Cold Restart */
#define AL_FUNC_WARMRST    0x0E    /* 14  - Warm Restart */
#define AL_FUNC_INITDATA   0x0F    /* 15  - Initialize Data */
#define AL_FUNC_INITAPP    0x10    /* 16  - Initialize Application */
#define AL_FUNC_STARTAPP   0x11    /* 17  - Start Application */
#define AL_FUNC_STOPAPP    0x12    /* 18  - Stop Application */
#define AL_FUNC_SAVECFG    0x13    /* 19  - Save Configuration */
#define AL_FUNC_ENSPMSG    0x14    /* 20  - Enable Spontaneous Msg */
#define AL_FUNC_DISSPMSG   0x15    /* 21  - Disable Spontaneous Msg */
#define AL_FUNC_ASSIGNCL   0x16    /* 22  - Assign Classes */
#define AL_FUNC_DELAYMST   0x17    /* 23  - Delay Measurement */
#define AL_FUNC_RECCT      0x18    /* 24  - Record Current Time */
#define AL_FUNC_OPENFILE   0x19    /* 25  - Open File */
#define AL_FUNC_CLOSEFILE  0x1A    /* 26  - Close File */
#define AL_FUNC_DELETEFILE 0x1B    /* 27  - Delete File */
#define AL_FUNC_GETFILEINF 0x1C    /* 28  - Get File Info */
#define AL_FUNC_AUTHFILE   0x1D    /* 29  - Authenticate File */
#define AL_FUNC_ABORTFILE  0x1E    /* 30  - Abort File */
#define AL_FUNC_ACTCNF     0x1F    /* 31  - Activate Config */
#define AL_FUNC_AUTHREQ    0x20    /* 32  - Authentication Request */
#define AL_FUNC_AUTHERR    0x21    /* 33  - Authentication Error */
#define AL_FUNC_RESPON     0x81    /* 129 - Response */
#define AL_FUNC_UNSOLI     0x82    /* 130 - Unsolicited Response */
#define AL_FUNC_AUTHRESP   0x83    /* 131 - Authentication Response */

/***************************************************************************/
/* Application Layer Internal Indication (IIN) bits */
/* 2 Bytes, message formatting: [First Octet] | [Second Octet] */
/***************************************************************************/
/* Octet 1 */
#define AL_IIN_BMSG        0x0100   /* Bit 0 - Broadcast message rx'd */
#define AL_IIN_CLS1D       0x0200   /* Bit 1 - Class 1 Data Available */
#define AL_IIN_CLS2D       0x0400   /* Bit 2 - Class 2 Data Available */
#define AL_IIN_CLS3D       0x0800   /* Bit 3 - Class 3 Data Available */
#define AL_IIN_TSR         0x1000   /* Bit 4 - Time Sync Req'd from Master */
#define AL_IIN_DOL         0x2000   /* Bit 5 - Outputs in Local Mode */
#define AL_IIN_DT          0x4000   /* Bit 6 - Device Trouble */
#define AL_IIN_RST         0x8000   /* Bit 7 - Device Restart */

/* Octet 2 */
#define AL_IIN_FCNI        0x0001   /* Bit 0 - Function code not implemented */
#define AL_IIN_OBJU        0x0002   /* Bit 1 - Requested Objects Unknown */
#define AL_IIN_PIOOR       0x0004   /* Bit 2 - Parameters Invalid or Out of Range */
#define AL_IIN_EBO         0x0008   /* Bit 3 - Event Buffer Overflow */
#define AL_IIN_OAE         0x0010   /* Bit 4 - Operation Already Executing */
#define AL_IIN_CC          0x0020   /* Bit 5 - Device Configuration Corrupt */
                        /* 0x0040      Bit 6 - Reserved */
                        /* 0x0080      Bit 7 - Reserved */

/***************************************************************************/
/* Application Layer Data Object Qualifier */
/***************************************************************************/
/* Bit-Masks */
#define AL_OBJQ_PREFIX         0x70    /* x111xxxx Masks Prefix from Qualifier */
#define AL_OBJQ_RANGE          0x0F    /* xxxx1111 Masks Range from Qualifier */

/* Index Size (3-bits x111xxxx) */
/* When Qualifier Code != 11    */
#define AL_OBJQL_PREFIX_NI     0x00    /* Objects are Packed with no index */
#define AL_OBJQL_PREFIX_1O     0x01    /* Objects are prefixed w/ 1-octet index */
#define AL_OBJQL_PREFIX_2O     0x02    /* Objects are prefixed w/ 2-octet index */
#define AL_OBJQL_PREFIX_4O     0x03    /* Objects are prefixed w/ 4-octet index */
#define AL_OBJQL_PREFIX_1OS    0x04    /* Objects are prefixed w/ 1-octet object size */
#define AL_OBJQL_PREFIX_2OS    0x05    /* Objects are prefixed w/ 2-octet object size */
#define AL_OBJQL_PREFIX_4OS    0x06    /* Objects are prefixed w/ 4-octet object size */

/* When Qualifier Code == 11 */
#define AL_OBJQL_IDX11_1OIS    0x01    /* 1 octet identifier size */
#define AL_OBJQL_IDX11_2OIS    0x02    /* 2 octet identifier size */
#define AL_OBJQL_IDX11_4OIS    0x03    /* 4 octet identifier size */

/* Qualifier Code (4-bits) */
/* 4-bits ( xxxx1111 ) */
#define AL_OBJQL_RANGE_SSI8    0x00    /* 00 8-bit Start and Stop Indices in Range Field */
#define AL_OBJQL_RANGE_SSI16   0x01    /* 01 16-bit Start and Stop Indices in Range Field */
#define AL_OBJQL_RANGE_SSI32   0x02    /* 02 32-bit Start and Stop Indices in Range Field */
#define AL_OBJQL_RANGE_AA8     0x03    /* 03 8-bit Absolute Address in Range Field */
#define AL_OBJQL_RANGE_AA16    0x04    /* 04 16-bit Absolute Address in Range Field */
#define AL_OBJQL_RANGE_AA32    0x05    /* 05 32-bit Absolute Address in Range Field */
#define AL_OBJQL_RANGE_R0      0x06    /* 06 Length of Range field is 0 (no range field) */
#define AL_OBJQL_RANGE_SF8     0x07    /* 07 8-bit Single Field Quantity */
#define AL_OBJQL_RANGE_SF16    0x08    /* 08 16-bit Single Field Quantity */
#define AL_OBJQL_RANGE_SF32    0x09    /* 09 32-bit Single Field Quantity */
                           /*  0x0A       10 Reserved  */
#define AL_OBJQL_RANGE_FF      0x0B    /* 11 Free-format Qualifier, range field has 1 octet count of objects */
                           /*  0x0C       12 Reserved  */
                           /*  0x0D       13 Reserved  */
                           /*  0x0E       14 Reserved  */
                           /*  0x0F       15 Reserved  */

/***************************************************************************/
/* Application Layer Data Object Definitions                               */
/***************************************************************************/

/* Masks for Object group and variation */
#define AL_OBJ_GRP_MASK 0xFF00
#define AL_OBJ_VAR_MASK 0x00FF

/* Accessors for group and mask */
#define AL_OBJ_GROUP(GV)        (((GV) & AL_OBJ_GRP_MASK) >> 8)
#define AL_OBJ_VARIATION(GV)    ((GV) & AL_OBJ_VAR_MASK)

/* Data Type values */
#define AL_DATA_TYPE_NONE         0x0
#define AL_DATA_TYPE_VSTR         0x1
#define AL_DATA_TYPE_UINT         0x2
#define AL_DATA_TYPE_INT          0x3
#define AL_DATA_TYPE_FLT          0x4
#define AL_DATA_TYPE_OSTR         0x5
#define AL_DATA_TYPE_BSTR         0x6
#define AL_DATA_TYPE_TIME         0x7
#define AL_DATA_TYPE_UNCD         0x8
#define AL_DATA_TYPE_U8BS8LIST    0xFE
#define AL_DATA_TYPE_U8BS8EXLIST  0xFF

/* Device Attributes */
#define AL_OBJ_DA_GRP           0x0000   /* 00 00 Device Attributes Group and null variation */
#define AL_OBJ_DA_CFG_ID        0x00C4   /* 00 196 Device Attributes - Configuration ID */
#define AL_OBJ_DA_CFG_VER       0x00C5   /* 00 197 Device Attributes - Configuration version */
#define AL_OBJ_DA_CFG_BLD_DATE  0x00C6   /* 00 198 Device Attributes - Configuration build date */
#define AL_OBJ_DA_CFG_CHG_DATE  0x00C7   /* 00 199 Device Attributes - Configuration last change date */
#define AL_OBJ_DA_CFG_SIG       0x00C8   /* 00 200 Device Attributes - Configuration signature */
#define AL_OBJ_DA_CFG_SIG_ALG   0x00C9   /* 00 201 Device Attributes - Configuration signature algorithm */
#define AL_OBJ_DA_MRID          0x00CA   /* 00 202 Device Attributes - Master Resource ID (mRID) */
#define AL_OBJ_DA_ALT           0x00CB   /* 00 203 Device Attributes - Device altitude */
#define AL_OBJ_DA_LONG          0x00CC   /* 00 204 Device Attributes - Device longitude */
#define AL_OBJ_DA_LAT           0x00CD   /* 00 205 Device Attributes - Device latitude */
#define AL_OBJ_DA_SEC_OP        0x00CE   /* 00 206 Device Attributes - User-assigned secondary operator name */
#define AL_OBJ_DA_PRM_OP        0x00CF   /* 00 207 Device Attributes - User-assigned primary operator name */
#define AL_OBJ_DA_SYS_NAME      0x00D0   /* 00 208 Device Attributes - User-assigned system name */
#define AL_OBJ_DA_SEC_VER       0x00D1   /* 00 209 Device Attributes - Secure authentication version */
#define AL_OBJ_DA_SEC_STAT      0x00D2   /* 00 210 Device Attributes - Number of security statistics per association */
#define AL_OBJ_DA_USR_ATTR      0x00D3   /* 00 211 Device Attributes - Identifier of support for user-specific attributes */
#define AL_OBJ_DA_MSTR_DSP      0x00D4   /* 00 212 Device Attributes - Number of master-defined data set prototypes  */
#define AL_OBJ_DA_OS_DSP        0x00D5   /* 00 213 Device Attributes - Number of outstation-defined data set prototypes */
#define AL_OBJ_DA_MSTR_DS       0x00D6   /* 00 214 Device Attributes - Number of master-defined data sets  */
#define AL_OBJ_DA_OS_DS         0x00D7   /* 00 215 Device Attributes - Number of outstation-defined data sets  */
#define AL_OBJ_DA_BO_REQ        0x00D8   /* 00 216 Device Attributes - Max number of binary outputs per request  */
#define AL_OBJ_DA_LOC_TA        0x00D9   /* 00 217 Device Attributes - Local timing accuracy             */
#define AL_OBJ_DA_DUR_TA        0x00DA   /* 00 218 Device Attributes - Duration of timing accuracy       */
#define AL_OBJ_DA_AO_EVT        0x00DB   /* 00 219 Device Attributes - Support for analog output events  */
#define AL_OBJ_DA_MAX_AO        0x00DC   /* 00 220 Device Attributes - Max analog output index           */
#define AL_OBJ_DA_NUM_AO        0x00DD   /* 00 221 Device Attributes - Number of analog outputs          */
#define AL_OBJ_DA_BO_EVT        0x00DE   /* 00 222 Device Attributes - Support for binary output events  */
#define AL_OBJ_DA_MAX_BO        0x00DF   /* 00 223 Device Attributes - Max binary output index           */
#define AL_OBJ_DA_NUM_BO        0x00E0   /* 00 224 Device Attributes - Number of binary outputs          */
#define AL_OBJ_DA_FCTR_EVT      0x00E1   /* 00 225 Device Attributes - Support for frozen counter events */
#define AL_OBJ_DA_FCTR          0x00E2   /* 00 226 Device Attributes - Support for frozen counters       */
#define AL_OBJ_DA_CTR_EVT       0x00E3   /* 00 227 Device Attributes - Support for counter events        */
#define AL_OBJ_DA_MAX_CTR       0x00E4   /* 00 228 Device Attributes - Max counter index                 */
#define AL_OBJ_DA_NUM_CTR       0x00E5   /* 00 229 Device Attributes - Number of counter points          */
#define AL_OBJ_DA_AIF           0x00E6   /* 00 230 Device Attributes - Support for frozen analog inputs  */
#define AL_OBJ_DA_AI_EVT        0x00E7   /* 00 231 Device Attributes - Support for analog input events   */
#define AL_OBJ_DA_MAX_AI        0x00E8   /* 00 232 Device Attributes - Maximum analog input index        */
#define AL_OBJ_DA_NUM_AI        0x00E9   /* 00 233 Device Attributes - Number of analog input points     */
#define AL_OBJ_DA_2BI_EVT       0x00EA   /* 00 234 Device Attributes - Support for Double-Bit BI Events  */
#define AL_OBJ_DA_MAX_2BI       0x00EB   /* 00 235 Device Attributes - Max Double-bit BI Point Index     */
#define AL_OBJ_DA_NUM_2BI       0x00EC   /* 00 236 Device Attributes - Number of Double-bit BI Points    */
#define AL_OBJ_DA_BI_EVT        0x00ED   /* 00 237 Device Attributes - Support for Binary Input Events   */
#define AL_OBJ_DA_MAX_BI        0x00EE   /* 00 238 Device Attributes - Max Binary Input Point Index      */
#define AL_OBJ_DA_NUM_BI        0x00EF   /* 00 239 Device Attributes - Number of Binary Input Points     */
#define AL_OBJ_DA_MXTX_FR       0x00F0   /* 00 240 Device Attributes - Maximum Transmit Fragment Size    */
#define AL_OBJ_DA_MXRX_FR       0x00F1   /* 00 241 Device Attributes - Maximum Receive Fragment Size     */
#define AL_OBJ_DA_SWVER         0x00F2   /* 00 242 Device Attributes - Device Manufacturers SW Version   */
#define AL_OBJ_DA_HWVER         0x00F3   /* 00 243 Device Attributes - Device Manufacturers HW Version   */
#define AL_OBJ_DA_OWNER         0x00F4   /* 00 244 Device Attributes - User-assigned owner name          */
#define AL_OBJ_DA_LOC           0x00F5   /* 00 245 Device Attributes - User-Assigned Location            */
#define AL_OBJ_DA_ID            0x00F6   /* 00 246 Device Attributes - User-Assigned ID code/number      */
#define AL_OBJ_DA_DEVNAME       0x00F7   /* 00 247 Device Attributes - User-Assigned Device Name         */
#define AL_OBJ_DA_SERNUM        0x00F8   /* 00 248 Device Attributes - Device Serial Number              */
#define AL_OBJ_DA_CONF          0x00F9   /* 00 249 Device Attributes - DNP Subset and Conformance        */
#define AL_OBJ_DA_PROD          0x00FA   /* 00 250 Device Attributes - Device Product Name and Model     */
                                         /* 00 251 Future Assignment                                     */
#define AL_OBJ_DA_MFG           0x00FC   /* 00 252 Device Attributes - Device Manufacturers Name         */
                                         /* 00 253 Future Assignment                                     */
#define AL_OBJ_DA_ALL           0x00FE   /* 00 254 Device Attributes - Non-specific All-attributes Req   */
#define AL_OBJ_DA_LVAR          0x00FF   /* 00 255 Device Attributes - List of Attribute Variations      */

/* Binary Input Objects */
#define AL_OBJ_BI_ALL      0x0100   /* 01 00 Binary Input Default Variation */
#define AL_OBJ_BI_1BIT     0x0101   /* 01 01 Single-bit Binary Input */
#define AL_OBJ_BI_STAT     0x0102   /* 01 02 Binary Input With Status */
#define AL_OBJ_BIC_ALL     0x0200   /* 02 00 Binary Input Change Default Variation */
#define AL_OBJ_BIC_NOTIME  0x0201   /* 02 01 Binary Input Change Without Time */
#define AL_OBJ_BIC_TIME    0x0202   /* 02 02 Binary Input Change With Time */
#define AL_OBJ_BIC_RTIME   0x0203   /* 02 03 Binary Input Change With Relative Time */

/* Double-bit Input Objects */
#define AL_OBJ_2BI_ALL     0x0300   /* 03 00 Double-bit Input Default Variation */
#define AL_OBJ_2BI_NF      0x0301   /* 03 01 Double-bit Input No Flags */
#define AL_OBJ_2BI_STAT    0x0302   /* 03 02 Double-bit Input With Status */
#define AL_OBJ_2BIC_ALL    0x0400   /* 04 00 Double-bit Input Change Default Variation */
#define AL_OBJ_2BIC_NOTIME 0x0401   /* 04 01 Double-bit Input Change Without Time */
#define AL_OBJ_2BIC_TIME   0x0402   /* 04 02 Double-bit Input Change With Time */
#define AL_OBJ_2BIC_RTIME  0x0403   /* 04 03 Double-bit Input Change With Relative Time */

/* Binary Input Quality Flags */
#define AL_OBJ_BI_FLAG0    0x01     /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_BI_FLAG1    0x02     /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_BI_FLAG2    0x04     /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_BI_FLAG3    0x08     /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_BI_FLAG4    0x10     /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_BI_FLAG5    0x20     /* Chatter Filter (0=Normal; 1=Filter On) */
#define AL_OBJ_BI_FLAG6    0x40     /* Double-bit LSB (0=Off; 1=On) */
#define AL_OBJ_BI_FLAG7    0x80     /* Point State (0=Off; 1=On) or Double-bit MSB */

#define AL_OBJ_2BI_STATE_INTERMEDIATE 0x00
#define AL_OBJ_2BI_STATE_OFF          0x01
#define AL_OBJ_2BI_STATE_ON           0x02
#define AL_OBJ_2BI_STATE_INDETERM     0x03

#define AL_OBJ_DBI_MASK    0xC0     /* Double bit point state mask
(0 = Intermediate, 1 = Determined off, 2 = Determined on, 3 = Indeterminate */

/***************************************************************************/
/* Binary Output Objects */
#define AL_OBJ_BO_ALL      0x0A00   /* 10 00 Binary Output Default Variation */
#define AL_OBJ_BO          0x0A01   /* 10 01 Binary Output */
#define AL_OBJ_BO_STAT     0x0A02   /* 10 02 Binary Output Status */
#define AL_OBJ_BOC_ALL     0x0B00   /* 11 00 Binary Output Change Default Variation */
#define AL_OBJ_BOC_NOTIME  0x0B01   /* 11 01 Binary Output Change Without Time */
#define AL_OBJ_BOC_TIME    0x0B02   /* 11 02 Binary Output Change With Time */
#define AL_OBJ_CTLOP_BLK   0x0C01   /* 12 01 Control Relay Output Block */
#define AL_OBJ_CTL_PCB     0x0C02   /* 12 02 Pattern Control Block */
#define AL_OBJ_CTL_PMASK   0x0C03   /* 12 03 Pattern Mask */
#define AL_OBJ_BOE_ALL     0x0D00   /* 13 00 Binary Output Command Event Default Variation */
#define AL_OBJ_BOE_NOTIME  0x0D01   /* 13 01 Binary Output Command Event Without Time */
#define AL_OBJ_BOE_TIME    0x0D02   /* 13 02 Binary Output Command Event With Time */

#define AL_OBJCTLC_CODE    0x0F    /* Bit-Mask xxxx1111 for Control Code 'Code' */
#define AL_OBJCTLC_MISC    0x30    /* Bit-Mask xx11xxxx for Control Code Queue (obsolete) and Clear Fields */
#define AL_OBJCTLC_TC      0xC0    /* Bit-Mask 11xxxxxx for Control Code 'Trip/Close' */

#define AL_OBJCTLC_CODE0   0x00    /* xxxx0000 NUL Operation; only process R attribute */
#define AL_OBJCTLC_CODE1   0x01    /* xxxx0001 Pulse On ^On-Time -> vOff-Time, remain off */
#define AL_OBJCTLC_CODE2   0x02    /* xxxx0010 Pulse Off vOff-Time -> ^On-Time, remain on */
#define AL_OBJCTLC_CODE3   0x03    /* xxxx0011 Latch On */
#define AL_OBJCTLC_CODE4   0x04    /* xxxx0100 Latch Off */
                        /* 0x05-0x15  Reserved */

#define AL_OBJCTLC_NOTSET  0x00    /* xx00xxxx for Control Code, Clear and Queue not set */
#define AL_OBJCTLC_QUEUE   0x01    /* xxx1xxxx for Control Code, Clear Field 'Queue' */
#define AL_OBJCTLC_CLEAR   0x02    /* xx1xxxxx for Control Code, Clear Field 'Clear' */
#define AL_OBJCTLC_BOTHSET 0x03    /* xx11xxxx for Control Code, Clear and Queue both set */

#define AL_OBJCTLC_TC0     0x00    /* 00xxxxxx NUL */
#define AL_OBJCTLC_TC1     0x01    /* 01xxxxxx Close */
#define AL_OBJCTLC_TC2     0x02    /* 10xxxxxx Trip */
#define AL_OBJCTLC_TC3     0x03    /* 11xxxxxx Reserved */

#define AL_OBJCTL_STAT0    0x00    /* Request Accepted, Initiated or Queued */
#define AL_OBJCTL_STAT1    0x01    /* Request Not Accepted; Arm-timer expired */
#define AL_OBJCTL_STAT2    0x02    /* Request Not Accepted; No 'SELECT' rx'd */
#define AL_OBJCTL_STAT3    0x03    /* Request Not Accepted; Format errors in ctrl request */
#define AL_OBJCTL_STAT4    0x04    /* Control Operation Not Supported for this point */
#define AL_OBJCTL_STAT5    0x05    /* Request Not Accepted; Ctrl Queue full or pt. active */
#define AL_OBJCTL_STAT6    0x06    /* Request Not Accepted; Ctrl HW Problems */
#define AL_OBJCTL_STAT7    0x07    /* Request Not Accepted; Local/Remote switch in Local*/
#define AL_OBJCTL_STAT8    0x08    /* Request Not Accepted; Too many operations requested */
#define AL_OBJCTL_STAT9    0x09    /* Request Not Accepted; Insufficient authorization */
#define AL_OBJCTL_STAT10   0x0A    /* Request Not Accepted; Local automation proc active */
#define AL_OBJCTL_STAT11   0x0B    /* Request Not Accepted; Processing limited */
#define AL_OBJCTL_STAT12   0x0C    /* Request Not Accepted; Out of range value */
#define AL_OBJCTL_STAT126  0x7E    /* Non Participating (NOP request) */
#define AL_OBJCTL_STAT127  0x7F    /* Request Not Accepted; Undefined error */

#define AL_OBJCTL_STATUS_MASK 0x7F

/* Binary Output Quality Flags */
#define AL_OBJ_BO_FLAG0    0x01     /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_BO_FLAG1    0x02     /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_BO_FLAG2    0x04     /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_BO_FLAG3    0x08     /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_BO_FLAG4    0x10     /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_BO_FLAG5    0x20     /* Reserved */
#define AL_OBJ_BO_FLAG6    0x40     /* Reserved */
#define AL_OBJ_BO_FLAG7    0x80     /* Point State (0=Off; 1=On) */

/***************************************************************************/
/* Counter Objects */
#define AL_OBJ_CTR_ALL     0x1400   /* 20 00 Binary Counter Default Variation */
#define AL_OBJ_CTR_32      0x1401   /* 20 01 32-Bit Binary Counter */
#define AL_OBJ_CTR_16      0x1402   /* 20 02 16-Bit Binary Counter */
#define AL_OBJ_DCTR_32     0x1403   /* 20 03 32-Bit Delta Counter */
#define AL_OBJ_DCTR_16     0x1404   /* 20 04 16-Bit Delta Counter */
#define AL_OBJ_CTR_32NF    0x1405   /* 20 05 32-Bit Binary Counter Without Flag */
#define AL_OBJ_CTR_16NF    0x1406   /* 20 06 16-Bit Binary Counter Without Flag */
#define AL_OBJ_DCTR_32NF   0x1407   /* 20 07 32-Bit Delta Counter Without Flag */
#define AL_OBJ_DCTR_16NF   0x1408   /* 20 08 16-Bit Delta Counter Without Flag */
#define AL_OBJ_FCTR_ALL    0x1500   /* 21 00 Frozen Binary Counter Default Variation */
#define AL_OBJ_FCTR_32     0x1501   /* 21 01 32-Bit Frozen Counter */
#define AL_OBJ_FCTR_16     0x1502   /* 21 02 16-Bit Frozen Counter */
#define AL_OBJ_FDCTR_32    0x1503   /* 21 03 32-Bit Frozen Delta Counter */
#define AL_OBJ_FDCTR_16    0x1504   /* 21 04 16-Bit Frozen Delta Counter */
#define AL_OBJ_FCTR_32T    0x1505   /* 21 05 32-Bit Frozen Counter w/ Time of Freeze */
#define AL_OBJ_FCTR_16T    0x1506   /* 21 06 16-Bit Frozen Counter w/ Time of Freeze */
#define AL_OBJ_FDCTR_32T   0x1507   /* 21 07 32-Bit Frozen Delta Counter w/ Time of Freeze */
#define AL_OBJ_FDCTR_16T   0x1508   /* 21 08 16-Bit Frozen Delta Counter w/ Time of Freeze */
#define AL_OBJ_FCTR_32NF   0x1509   /* 21 09 32-Bit Frozen Counter Without Flag */
#define AL_OBJ_FCTR_16NF   0x150A   /* 21 10 16-Bit Frozen Counter Without Flag */
#define AL_OBJ_FDCTR_32NF  0x150B   /* 21 11 32-Bit Frozen Delta Counter Without Flag */
#define AL_OBJ_FDCTR_16NF  0x150C   /* 21 12 16-Bit Frozen Delta Counter Without Flag */
#define AL_OBJ_CTRC_ALL    0x1600   /* 22 00 Counter Change Event Default Variation */
#define AL_OBJ_CTRC_32     0x1601   /* 22 01 32-Bit Counter Change Event w/o Time */
#define AL_OBJ_CTRC_16     0x1602   /* 22 02 16-Bit Counter Change Event w/o Time */
#define AL_OBJ_DCTRC_32    0x1603   /* 22 03 32-Bit Delta Counter Change Event w/o Time */
#define AL_OBJ_DCTRC_16    0x1604   /* 22 04 16-Bit Delta Counter Change Event w/o Time */
#define AL_OBJ_CTRC_32T    0x1605   /* 22 05 32-Bit Counter Change Event with Time */
#define AL_OBJ_CTRC_16T    0x1606   /* 22 06 16-Bit Counter Change Event with Time */
#define AL_OBJ_DCTRC_32T   0x1607   /* 22 07 32-Bit Delta Counter Change Event with Time */
#define AL_OBJ_DCTRC_16T   0x1608   /* 22 08 16-Bit Delta Counter Change Event with Time */
#define AL_OBJ_FCTRC_ALL   0x1700   /* 23 00 Frozen Binary Counter Change Event Default Variation */
#define AL_OBJ_FCTRC_32    0x1701   /* 23 01 32-Bit Frozen Counter Change Event */
#define AL_OBJ_FCTRC_16    0x1702   /* 23 02 16-Bit Frozen Counter Change Event */
#define AL_OBJ_FDCTRC_32   0x1703   /* 23 03 32-Bit Frozen Delta Counter Change Event */
#define AL_OBJ_FDCTRC_16   0x1704   /* 23 04 16-Bit Frozen Delta Counter Change Event */
#define AL_OBJ_FCTRC_32T   0x1705   /* 23 05 32-Bit Frozen Counter Change Event w/ Time of Freeze */
#define AL_OBJ_FCTRC_16T   0x1706   /* 23 06 16-Bit Frozen Counter Change Event w/ Time of Freeze */
#define AL_OBJ_FDCTRC_32T  0x1707   /* 23 07 32-Bit Frozen Delta Counter Change Event w/ Time of Freeze */
#define AL_OBJ_FDCTRC_16T  0x1708   /* 23 08 16-Bit Frozen Delta Counter Change Event w/ Time of Freeze */

/* Counter Quality Flags */
#define AL_OBJ_CTR_FLAG0   0x01     /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_CTR_FLAG1   0x02     /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_CTR_FLAG2   0x04     /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_CTR_FLAG3   0x08     /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_CTR_FLAG4   0x10     /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_CTR_FLAG5   0x20     /* Roll-over (0=Normal; 1=Roll-Over) */
#define AL_OBJ_CTR_FLAG6   0x40     /* Discontinuity (0=Normal; 1=Discontinuity) */
#define AL_OBJ_CTR_FLAG7   0x80     /* Reserved */

/***************************************************************************/
/* Analog Input Objects */
#define AL_OBJ_AI_ALL      0x1E00   /* 30 00 Analog Input Default Variation */
#define AL_OBJ_AI_32       0x1E01   /* 30 01 32-Bit Analog Input */
#define AL_OBJ_AI_16       0x1E02   /* 30 02 16-Bit Analog Input */
#define AL_OBJ_AI_32NF     0x1E03   /* 30 03 32-Bit Analog Input Without Flag */
#define AL_OBJ_AI_16NF     0x1E04   /* 30 04 16-Bit Analog Input Without Flag */
#define AL_OBJ_AI_FLT      0x1E05   /* 30 05 32-Bit Floating Point Input */
#define AL_OBJ_AI_DBL      0x1E06   /* 30 06 64-Bit Floating Point Input */
#define AL_OBJ_AIF_ALL     0x1F00   /* 31 00 Frozen Analog Input Default Variation */
#define AL_OBJ_AIF_32      0x1F01   /* 31 01 32-Bit Frozen Analog Input */
#define AL_OBJ_AIF_16      0x1F02   /* 31 02 16-Bit Frozen Analog Input */
#define AL_OBJ_AIF_32TOF   0x1F03   /* 31 03 32-Bit Frozen Analog Input w/ Time of Freeze */
#define AL_OBJ_AIF_16TOF   0x1F04   /* 31 04 16-Bit Frozen Analog Input w/ Time of Freeze */
#define AL_OBJ_AIF_32NF    0x1F05   /* 31 05 32-Bit Frozen Analog Input Without Flag */
#define AL_OBJ_AIF_16NF    0x1F06   /* 31 06 16-Bit Frozen Analog Input Without Flag */
#define AL_OBJ_AIF_FLT     0x1F07   /* 31 07 32-Bit Frozen Floating Point Input */
#define AL_OBJ_AIF_DBL     0x1F08   /* 31 08 64-Bit Frozen Floating Point Input */
#define AL_OBJ_AIC_ALL     0x2000   /* 32 00 Analog Input Change Default Variation */
#define AL_OBJ_AIC_32NT    0x2001   /* 32 01 32-Bit Analog Change Event w/o Time */
#define AL_OBJ_AIC_16NT    0x2002   /* 32 02 16-Bit Analog Change Event w/o Time */
#define AL_OBJ_AIC_32T     0x2003   /* 32 03 32-Bit Analog Change Event w/ Time */
#define AL_OBJ_AIC_16T     0x2004   /* 32 04 16-Bit Analog Change Event w/ Time */
#define AL_OBJ_AIC_FLTNT   0x2005   /* 32 05 32-Bit Floating Point Change Event w/o Time*/
#define AL_OBJ_AIC_DBLNT   0x2006   /* 32 06 64-Bit Floating Point Change Event w/o Time*/
#define AL_OBJ_AIC_FLTT    0x2007   /* 32 07 32-Bit Floating Point Change Event w/ Time*/
#define AL_OBJ_AIC_DBLT    0x2008   /* 32 08 64-Bit Floating Point Change Event w/ Time*/
#define AL_OBJ_AIFC_ALL    0x2100   /* 33 00 Frozen Analog Event Default Variation */
#define AL_OBJ_AIFC_32NT   0x2101   /* 33 01 32-Bit Frozen Analog Event w/o Time */
#define AL_OBJ_AIFC_16NT   0x2102   /* 33 02 16-Bit Frozen Analog Event w/o Time */
#define AL_OBJ_AIFC_32T    0x2103   /* 33 03 32-Bit Frozen Analog Event w/ Time */
#define AL_OBJ_AIFC_16T    0x2104   /* 33 04 16-Bit Frozen Analog Event w/ Time */
#define AL_OBJ_AIFC_FLTNT  0x2105   /* 33 05 32-Bit Floating Point Frozen Change Event w/o Time*/
#define AL_OBJ_AIFC_DBLNT  0x2106   /* 33 06 64-Bit Floating Point Frozen Change Event w/o Time*/
#define AL_OBJ_AIFC_FLTT   0x2107   /* 33 07 32-Bit Floating Point Frozen Change Event w/ Time*/
#define AL_OBJ_AIFC_DBLT   0x2108   /* 33 08 64-Bit Floating Point Frozen Change Event w/ Time*/

/* Analog Input Quality Flags */
#define AL_OBJ_AI_FLAG0    0x01     /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_AI_FLAG1    0x02     /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_AI_FLAG2    0x04     /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_AI_FLAG3    0x08     /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_AI_FLAG4    0x10     /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_AI_FLAG5    0x20     /* Over-Range (0=Normal; 1=Over-Range) */
#define AL_OBJ_AI_FLAG6    0x40     /* Reference Check (0=Normal; 1=Error) */
#define AL_OBJ_AI_FLAG7    0x80     /* Reserved */

#define AL_OBJ_AIDB_ALL    0x2200   /* 34 00 Analog Input Deadband Default Variation */
#define AL_OBJ_AIDB_16     0x2201   /* 34 01 16-Bit Analog Input Deadband */
#define AL_OBJ_AIDB_32     0x2202   /* 34 02 32-Bit Analog Input Deadband */
#define AL_OBJ_AIDB_FLT    0x2203   /* 34 03 Floating Point Analog Input Deadband */

/***************************************************************************/
/* Analog Output Objects */
#define AL_OBJ_AO_ALL      0x2800   /* 40 00 Analog Output Default Variation */
#define AL_OBJ_AO_32       0x2801   /* 40 01 32-Bit Analog Output Status */
#define AL_OBJ_AO_16       0x2802   /* 40 02 16-Bit Analog Output Status */
#define AL_OBJ_AO_FLT      0x2803   /* 40 03 32-Bit Floating Point Output Status */
#define AL_OBJ_AO_DBL      0x2804   /* 40 04 64-Bit Floating Point Output Status */
#define AL_OBJ_AO_32OPB    0x2901   /* 41 01 32-Bit Analog Output Block */
#define AL_OBJ_AO_16OPB    0x2902   /* 41 02 16-Bit Analog Output Block */
#define AL_OBJ_AO_FLTOPB   0x2903   /* 41 03 32-Bit Floating Point Output Block */
#define AL_OBJ_AO_DBLOPB   0x2904   /* 41 04 64-Bit Floating Point Output Block */
#define AL_OBJ_AOC_ALL     0x2A00   /* 42 00 Analog Output Event Default Variation */
#define AL_OBJ_AOC_32NT    0x2A01   /* 42 01 32-Bit Analog Output Event w/o Time */
#define AL_OBJ_AOC_16NT    0x2A02   /* 42 02 16-Bit Analog Output Event w/o Time */
#define AL_OBJ_AOC_32T     0x2A03   /* 42 03 32-Bit Analog Output Event w/ Time */
#define AL_OBJ_AOC_16T     0x2A04   /* 42 04 16-Bit Analog Output Event w/ Time */
#define AL_OBJ_AOC_FLTNT   0x2A05   /* 42 05 32-Bit Floating Point Output Event w/o Time */
#define AL_OBJ_AOC_DBLNT   0x2A06   /* 42 06 64-Bit Floating Point Output Event w/o Time */
#define AL_OBJ_AOC_FLTT    0x2A07   /* 42 07 32-Bit Floating Point Output Event w/ Time */
#define AL_OBJ_AOC_DBLT    0x2A08   /* 42 08 64-Bit Floating Point Output Event w/ Time */
#define AL_OBJ_AOC_32EVNT  0x2B01   /* 43 01 32-Bit Analog Output Command Event w/o Time */
#define AL_OBJ_AOC_16EVNT  0x2B02   /* 43 02 16-Bit Analog Output Command Event w/o Time */
#define AL_OBJ_AOC_32EVTT  0x2B03   /* 43 03 32-Bit Analog Output Command Event w/ Time */
#define AL_OBJ_AOC_16EVTT  0x2B04   /* 43 04 16-Bit Analog Output Command Event w/ Time */
#define AL_OBJ_AOC_FLTEVNT 0x2B05   /* 43 05 32-Bit Floating Point Analog Output Command Event w/o Time */
#define AL_OBJ_AOC_DBLEVNT 0x2B06   /* 43 06 64-Bit Floating Point Analog Output Command Event w/o Time */
#define AL_OBJ_AOC_FLTEVTT 0x2B07   /* 43 07 32-Bit Floating Point Analog Output Command Event w/ Time */
#define AL_OBJ_AOC_DBLEVTT 0x2B08   /* 43 08 64-Bit Floating Point Analog Output Command Event w/ Time */

/* Analog Output Quality Flags */
#define AL_OBJ_AO_FLAG0    0x01     /* Point Online (0=Offline; 1=Online) */
#define AL_OBJ_AO_FLAG1    0x02     /* Restart (0=Normal; 1=Restart) */
#define AL_OBJ_AO_FLAG2    0x04     /* Comms Lost (0=Normal; 1=Lost) */
#define AL_OBJ_AO_FLAG3    0x08     /* Remote Force (0=Normal; 1=Forced) */
#define AL_OBJ_AO_FLAG4    0x10     /* Local Force (0=Normal; 1=Forced) */
#define AL_OBJ_AO_FLAG5    0x20     /* Reserved */
#define AL_OBJ_AO_FLAG6    0x40     /* Reserved */
#define AL_OBJ_AO_FLAG7    0x80     /* Reserved */

/***************************************************************************/
/* Time Objects */
#define AL_OBJ_TD_ALL      0x3200   /* 50 00 Time and Date Default Variation */
#define AL_OBJ_TD          0x3201   /* 50 01 Time and Date */
#define AL_OBJ_TDI         0x3202   /* 50 02 Time and Date w/ Interval */
#define AL_OBJ_TDR         0x3203   /* 50 03 Last Recorded Time and Date */
#define AL_OBJ_TDCTO       0x3301   /* 51 01 Time and Date CTO */
#define AL_OBJ_UTDCTO      0x3302   /* 51 02 Unsynchronized Time and Date CTO */
#define AL_OBJ_TDELAYC     0x3401   /* 52 01 Time Delay Coarse */
#define AL_OBJ_TDELAYF     0x3402   /* 52 02 Time Delay Fine */

/***************************************************************************/
/* Class Data Objects */
#define AL_OBJ_CLASS0      0x3C01   /* 60 01 Class 0 Data */
#define AL_OBJ_CLASS1      0x3C02   /* 60 02 Class 1 Data */
#define AL_OBJ_CLASS2      0x3C03   /* 60 03 Class 2 Data */
#define AL_OBJ_CLASS3      0x3C04   /* 60 04 Class 3 Data */

/***************************************************************************/
/* File Objects */
#define AL_OBJ_FILE_CMD         0x4603   /* 70 03 File Control - Command */
#define AL_OBJ_FILE_STAT        0x4604   /* 70 04 File Control - Status */
#define AL_OBJ_FILE_TRANS       0x4605   /* 70 05 File Control - Transport */
#define AL_OBJ_FILE_TRAN_ST     0x4606   /* 70 05 File Control - Transport Status */

/* File Control Mode flags */
#define AL_OBJ_FILE_MODE_NULL   0x00   /* NULL */
#define AL_OBJ_FILE_MODE_READ   0x01   /* READ */
#define AL_OBJ_FILE_MODE_WRITE  0x02   /* WRITE */
#define AL_OBJ_FILE_MODE_APPEND 0x03   /* APPEND */

/***************************************************************************/
/* Device Objects */
#define AL_OBJ_IIN         0x5001   /* 80 01 Internal Indications */

/***************************************************************************/
/* Data Sets */
#define AL_OBJ_DS_PROTO    0x5501   /* 85 01 Data-Set Prototype, with UUID  */
#define AL_OBJ_DSD_CONT    0x5601   /* 86 01 Data-Set Descriptor, Data-Set Contents  */
#define AL_OBJ_DSD_CHAR    0x5602   /* 86 02 Data-Set Descriptor, Characteristics  */
#define AL_OBJ_DSD_PIDX    0x5603   /* 86 03 Data-Set Descriptor, Point Index Attributes  */
#define AL_OBJ_DS_PV       0x5701   /* 87 01 Data-Set, Present Value  */
#define AL_OBJ_DS_SS       0x5801   /* 88 01 Data-Set, Snapshot  */

/***************************************************************************/
/* Octet String Objects */
#define AL_OBJ_OCT         0x6E00   /* 110 xx Octet string */
#define AL_OBJ_OCT_EVT     0x6F00   /* 111 xx Octet string event */

/***************************************************************************/
/* Virtual Terminal Objects */
#define AL_OBJ_VT_OBLK     0x7000   /* 112 xx Virtual Terminal Output Block */
#define AL_OBJ_VT_EVTD     0x7100   /* 113 xx Virtual Terminal Event Data */

/***************************************************************************/
/* Secure Authentication ('SA') Objects */
#define AL_OBJ_SA_AUTH_CH     0x7801   /* 120 01 Authentication Challenge */
#define AL_OBJ_SA_AUTH_RP     0x7802   /* 120 02 Authentication Reply */
#define AL_OBJ_SA_AUTH_AGMRQ  0x7803   /* 120 03 Authentication Aggressive Mode Request */
#define AL_OBJ_SA_AUTH_SKSR   0x7804   /* 120 04 Authentication Session Key Status Request */
#define AL_OBJ_SA_AUTH_SKS    0x7805   /* 120 05 Authentication Session Key Status */
#define AL_OBJ_SA_AUTH_SKC    0x7806   /* 120 06 Authentication Session Key Change */
#define AL_OBJ_SA_AUTH_ERR    0x7807   /* 120 07 Authentication Error */
#define AL_OBJ_SA_AUTH_MAC    0x7809   /* 120 09 Authentication Message Authentication Code */
#define AL_OBJ_SA_AUTH_USC    0x780A   /* 120 10 Authentication User Status Change - Not supported */
#define AL_OBJ_SA_AUTH_UKCR   0x780B   /* 120 11 Authentication Update Key Change Request */
#define AL_OBJ_SA_AUTH_UKCRP  0x780C   /* 120 12 Authentication Update Key Change Reply */
#define AL_OBJ_SA_AUTH_UKC    0x780D   /* 120 13 Authentication Update Key Change */
#define AL_OBJ_SA_AUTH_UKCC   0x780F   /* 120 15 Authentication Update Key Change Confirmation */
#define AL_OBJ_SA_SECSTAT     0x7901   /* 121 01 Security Statistics */
#define AL_OBJ_SA_SECSTATEVT  0x7A01   /* 122 01 Security Statistic Event */
#define AL_OBJ_SA_SECSTATEVTT 0x7A02   /* 122 02 Security Statistic Event w/ Time */


/***************************************************************************/
/* End of Application Layer Data Object Definitions */
/***************************************************************************/

void proto_register_dnp3(void);
void proto_reg_handoff_dnp3(void);

/* Initialize the protocol and registered fields */
static int proto_dnp3;
static int hf_dnp3_start;
static int hf_dnp3_len;
static int hf_dnp3_ctl;
static int hf_dnp3_ctl_prifunc;
static int hf_dnp3_ctl_secfunc;
static int hf_dnp3_ctl_dir;
static int hf_dnp3_ctl_prm;
static int hf_dnp3_ctl_fcb;
static int hf_dnp3_ctl_fcv;
static int hf_dnp3_ctl_dfc;
static int hf_dnp3_dst;
static int hf_dnp3_src;
static int hf_dnp3_addr;
static int hf_dnp3_data_hdr_crc;
static int hf_dnp3_data_hdr_crc_status;
static int hf_dnp3_tr_ctl;
static int hf_dnp3_tr_fin;
static int hf_dnp3_tr_fir;
static int hf_dnp3_tr_seq;
static int hf_dnp3_data_chunk;
static int hf_dnp3_data_chunk_len;
static int hf_dnp3_data_chunk_crc;
static int hf_dnp3_data_chunk_crc_status;

/* Added for Application Layer Decoding */
static int hf_dnp3_al_ctl;
static int hf_dnp3_al_fir;
static int hf_dnp3_al_fin;
static int hf_dnp3_al_con;
static int hf_dnp3_al_uns;
static int hf_dnp3_al_seq;
static int hf_dnp3_al_func;
static int hf_dnp3_al_iin;
static int hf_dnp3_al_iin_bmsg;
static int hf_dnp3_al_iin_cls1d;
static int hf_dnp3_al_iin_cls2d;
static int hf_dnp3_al_iin_cls3d;
static int hf_dnp3_al_iin_tsr;
static int hf_dnp3_al_iin_dol;
static int hf_dnp3_al_iin_dt;
static int hf_dnp3_al_iin_rst;
static int hf_dnp3_al_iin_fcni;
static int hf_dnp3_al_iin_obju;
static int hf_dnp3_al_iin_pioor;
static int hf_dnp3_al_iin_ebo;
static int hf_dnp3_al_iin_oae;
static int hf_dnp3_al_iin_cc;
static int hf_dnp3_al_obj;
static int hf_dnp3_al_objq_prefix;
static int hf_dnp3_al_objq_range;
static int hf_dnp3_al_range_start8;
static int hf_dnp3_al_range_stop8;
static int hf_dnp3_al_range_start16;
static int hf_dnp3_al_range_stop16;
static int hf_dnp3_al_range_start32;
static int hf_dnp3_al_range_stop32;
static int hf_dnp3_al_range_abs8;
static int hf_dnp3_al_range_abs16;
static int hf_dnp3_al_range_abs32;
static int hf_dnp3_al_range_quant8;
static int hf_dnp3_al_range_quant16;
static int hf_dnp3_al_range_quant32;
static int hf_dnp3_al_index8;
static int hf_dnp3_al_index16;
static int hf_dnp3_al_index32;
static int hf_dnp3_al_size8;
static int hf_dnp3_al_size16;
static int hf_dnp3_al_size32;
static int hf_dnp3_bocs_bit;

/* static int hf_dnp3_al_objq;*/
/* static int hf_dnp3_al_nobj; */
static int hf_dnp3_al_biq_b0;
static int hf_dnp3_al_biq_b1;
static int hf_dnp3_al_biq_b2;
static int hf_dnp3_al_biq_b3;
static int hf_dnp3_al_biq_b4;
static int hf_dnp3_al_biq_b5;
static int hf_dnp3_al_biq_b6;
static int hf_dnp3_al_biq_b7;
static int hf_dnp3_al_boq_b0;
static int hf_dnp3_al_boq_b1;
static int hf_dnp3_al_boq_b2;
static int hf_dnp3_al_boq_b3;
static int hf_dnp3_al_boq_b4;
static int hf_dnp3_al_boq_b5;
static int hf_dnp3_al_boq_b6;
static int hf_dnp3_al_boq_b7;
static int hf_dnp3_al_ctrq_b0;
static int hf_dnp3_al_ctrq_b1;
static int hf_dnp3_al_ctrq_b2;
static int hf_dnp3_al_ctrq_b3;
static int hf_dnp3_al_ctrq_b4;
static int hf_dnp3_al_ctrq_b5;
static int hf_dnp3_al_ctrq_b6;
static int hf_dnp3_al_ctrq_b7;
static int hf_dnp3_al_aiq_b0;
static int hf_dnp3_al_aiq_b1;
static int hf_dnp3_al_aiq_b2;
static int hf_dnp3_al_aiq_b3;
static int hf_dnp3_al_aiq_b4;
static int hf_dnp3_al_aiq_b5;
static int hf_dnp3_al_aiq_b6;
static int hf_dnp3_al_aiq_b7;
static int hf_dnp3_al_aoq_b0;
static int hf_dnp3_al_aoq_b1;
static int hf_dnp3_al_aoq_b2;
static int hf_dnp3_al_aoq_b3;
static int hf_dnp3_al_aoq_b4;
static int hf_dnp3_al_aoq_b5;
static int hf_dnp3_al_aoq_b6;
static int hf_dnp3_al_aoq_b7;
static int hf_dnp3_al_timestamp;
static int hf_dnp3_al_file_perms;
static int hf_dnp3_al_file_perms_read_owner;
static int hf_dnp3_al_file_perms_write_owner;
static int hf_dnp3_al_file_perms_exec_owner;
static int hf_dnp3_al_file_perms_read_group;
static int hf_dnp3_al_file_perms_write_group;
static int hf_dnp3_al_file_perms_exec_group;
static int hf_dnp3_al_file_perms_read_world;
static int hf_dnp3_al_file_perms_write_world;
static int hf_dnp3_al_file_perms_exec_world;
static int hf_dnp3_al_rel_timestamp;
static int hf_dnp3_al_ana16;
static int hf_dnp3_al_ana32;
static int hf_dnp3_al_anaflt;
static int hf_dnp3_al_anadbl;
static int hf_dnp3_al_bit;
static int hf_dnp3_al_bit0;
static int hf_dnp3_al_bit1;
static int hf_dnp3_al_bit2;
static int hf_dnp3_al_bit3;
static int hf_dnp3_al_bit4;
static int hf_dnp3_al_bit5;
static int hf_dnp3_al_bit6;
static int hf_dnp3_al_bit7;
static int hf_dnp3_al_2bit;
static int hf_dnp3_al_2bit0;
static int hf_dnp3_al_2bit1;
static int hf_dnp3_al_2bit2;
static int hf_dnp3_al_2bit3;
static int hf_dnp3_al_cnt16;
static int hf_dnp3_al_cnt32;
static int hf_dnp3_al_ctrlstatus;
static int hf_dnp3_al_anaout16;
static int hf_dnp3_al_anaout32;
static int hf_dnp3_al_anaoutflt;
static int hf_dnp3_al_anaoutdbl;
static int hf_dnp3_al_file_mode;
static int hf_dnp3_al_file_auth;
static int hf_dnp3_al_file_size;
static int hf_dnp3_al_file_maxblk;
static int hf_dnp3_al_file_reqID;
static int hf_dnp3_al_file_handle;
static int hf_dnp3_al_file_status;
static int hf_dnp3_al_file_blocknum;
static int hf_dnp3_al_file_lastblock;
static int hf_dnp3_al_file_data;
static int hf_dnp3_ctlobj_code_c;
static int hf_dnp3_ctlobj_code_m;
static int hf_dnp3_ctlobj_code_tc;
static int hf_dnp3_al_datatype;
static int hf_dnp3_al_da_length;
static int hf_dnp3_al_da_uint8;
static int hf_dnp3_al_da_uint16;
static int hf_dnp3_al_da_uint32;
static int hf_dnp3_al_da_int8;
static int hf_dnp3_al_da_int16;
static int hf_dnp3_al_da_int32;
static int hf_dnp3_al_da_flt;
static int hf_dnp3_al_da_dbl;
static int hf_dnp3_al_sa_cd;
static int hf_dnp3_al_sa_cdl;
static int hf_dnp3_al_sa_csq;
static int hf_dnp3_al_sa_err;
static int hf_dnp3_al_sa_key;
static int hf_dnp3_al_sa_kcm;
static int hf_dnp3_al_sa_ks;
static int hf_dnp3_al_sa_ksq;
static int hf_dnp3_al_sa_kwa;
static int hf_dnp3_al_sa_mac;
static int hf_dnp3_al_sa_mal;
static int hf_dnp3_al_sa_rfc;
static int hf_dnp3_al_sa_seq;
static int hf_dnp3_al_sa_uk;
static int hf_dnp3_al_sa_ukl;
static int hf_dnp3_al_sa_usr;
static int hf_dnp3_al_sa_usrn;
static int hf_dnp3_al_sa_usrnl;
static int hf_dnp3_al_sa_assoc_id;

static int hf_dnp3_al_bi_index;
static int hf_dnp3_al_bi_static_index;
static int hf_dnp3_al_bi_event_index;
static int hf_dnp3_al_dbi_index;
static int hf_dnp3_al_dbi_static_index;
static int hf_dnp3_al_dbi_event_index;
static int hf_dnp3_al_bo_index;
static int hf_dnp3_al_bo_static_index;
static int hf_dnp3_al_bo_event_index;
static int hf_dnp3_al_bo_cmnd_index;
static int hf_dnp3_al_counter_index;
static int hf_dnp3_al_counter_static_index;
static int hf_dnp3_al_counter_event_index;
static int hf_dnp3_al_ai_index;
static int hf_dnp3_al_ai_static_index;
static int hf_dnp3_al_ai_event_index;
static int hf_dnp3_al_ao_index;
static int hf_dnp3_al_ao_static_index;
static int hf_dnp3_al_ao_event_index;
static int hf_dnp3_al_ao_cmnd_index;
static int hf_dnp3_al_os_index;
static int hf_dnp3_al_os_static_index;
static int hf_dnp3_al_os_event_index;
/* Generated from convert_proto_tree_add_text.pl */
static int hf_dnp3_al_point_index;
static int hf_dnp3_al_da_value;
static int hf_dnp3_al_count;
static int hf_dnp3_al_on_time;
static int hf_dnp3_al_off_time;
static int hf_dnp3_al_time_delay;
static int hf_dnp3_al_file_string_offset;
static int hf_dnp3_al_file_string_length;
static int hf_dnp3_al_file_name;
static int hf_dnp3_al_octet_string;
static int hf_dnp3_unknown_data_chunk;

/***************************************************************************/
/* Value String Look-Ups */
/***************************************************************************/
static const value_string dnp3_ctl_func_pri_vals[] = {
  { DL_FUNC_RESET_LINK, "Reset of Remote Link" },
  { DL_FUNC_RESET_PROC, "Reset of User Process" },
  { DL_FUNC_TEST_LINK,  "Test Function For Link" },
  { DL_FUNC_USER_DATA,  "User Data" },
  { DL_FUNC_UNC_DATA,   "Unconfirmed User Data" },
  { DL_FUNC_LINK_STAT,  "Request Link Status" },
  { 0, NULL }
};

static const value_string dnp3_ctl_func_sec_vals[] = {
  { DL_FUNC_ACK,        "ACK" },
  { DL_FUNC_NACK,       "NACK" },
  { DL_FUNC_STAT_LINK,  "Status of Link" },
  { DL_FUNC_NO_FUNC,    "Link Service Not Functioning" },
  { DL_FUNC_NOT_IMPL,   "Link Service Not Used or Implemented" },
  { 0,  NULL }
};

#if 0
static const value_string dnp3_ctl_flags_pri_vals[] = {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_FCB, "FCB" },
  { DNP3_CTL_FCV, "FCV" },
  { 0,  NULL }
};
#endif

#if 0
static const value_string dnp3_ctl_flags_sec_vals[]= {
  { DNP3_CTL_DIR, "DIR" },
  { DNP3_CTL_PRM, "PRM" },
  { DNP3_CTL_RES, "RES" },
  { DNP3_CTL_DFC, "DFC" },
  { 0,  NULL }
};
#endif

#if 0
static const value_string dnp3_tr_flags_vals[] = {
  { DNP3_TR_FIN,  "FIN" },
  { DNP3_TR_FIR,  "FIR" },
  { 0,  NULL }
};
#endif

#if 0
static const value_string dnp3_al_flags_vals[] = {
  { DNP3_AL_FIR,  "FIR" },
  { DNP3_AL_FIN,  "FIN" },
  { DNP3_AL_CON,  "CON" },
  { DNP3_AL_UNS,  "UNS" },
  { 0,  NULL }
};
#endif

/* Application Layer Function Code Values */
static const value_string dnp3_al_func_vals[] = {
  { AL_FUNC_CONFIRM,    "Confirm" },
  { AL_FUNC_READ,       "Read" },
  { AL_FUNC_WRITE,      "Write" },
  { AL_FUNC_SELECT,     "Select" },
  { AL_FUNC_OPERATE,    "Operate" },
  { AL_FUNC_DIROP,      "Direct Operate" },
  { AL_FUNC_DIROPNACK,  "Direct Operate No Ack" },
  { AL_FUNC_FRZ,        "Immediate Freeze" },
  { AL_FUNC_FRZNACK,    "Immediate Freeze No Ack" },
  { AL_FUNC_FRZCLR,     "Freeze and Clear" },
  { AL_FUNC_FRZCLRNACK, "Freeze and Clear No ACK" },
  { AL_FUNC_FRZT,       "Freeze With Time" },
  { AL_FUNC_FRZTNACK,   "Freeze With Time No ACK" },
  { AL_FUNC_COLDRST,    "Cold Restart" },
  { AL_FUNC_WARMRST,    "Warm Restart" },
  { AL_FUNC_INITDATA,   "Initialize Data" },
  { AL_FUNC_INITAPP,    "Initialize Application" },
  { AL_FUNC_STARTAPP,   "Start Application" },
  { AL_FUNC_STOPAPP,    "Stop Application" },
  { AL_FUNC_SAVECFG,    "Save Configuration" },
  { AL_FUNC_ENSPMSG,    "Enable Spontaneous Messages" },
  { AL_FUNC_DISSPMSG,   "Disable Spontaneous Messages" },
  { AL_FUNC_ASSIGNCL,   "Assign Classes" },
  { AL_FUNC_DELAYMST,   "Delay Measurement" },
  { AL_FUNC_RECCT,      "Record Current Time" },
  { AL_FUNC_OPENFILE,   "Open File" },
  { AL_FUNC_CLOSEFILE,  "Close File" },
  { AL_FUNC_DELETEFILE, "Delete File" },
  { AL_FUNC_GETFILEINF, "Get File Info" },
  { AL_FUNC_AUTHFILE,   "Authenticate File" },
  { AL_FUNC_ABORTFILE,  "Abort File" },
  { AL_FUNC_ACTCNF,     "Activate Config" },
  { AL_FUNC_AUTHREQ,    "Authentication Request" },
  { AL_FUNC_AUTHERR,    "Authentication Error" },
  { AL_FUNC_RESPON,     "Response" },
  { AL_FUNC_UNSOLI,     "Unsolicited Response" },
  { AL_FUNC_AUTHRESP,   "Authentication Response" },
  { 0, NULL }
};
static value_string_ext dnp3_al_func_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_func_vals);

/* Application Layer Internal Indication (IIN) bit Values */
static const value_string dnp3_al_iin_vals[] = {
  { AL_IIN_BMSG,    "Broadcast message Rx'd" },
  { AL_IIN_CLS1D,   "Class 1 Data Available" },
  { AL_IIN_CLS2D,   "Class 2 Data Available" },
  { AL_IIN_CLS3D,   "Class 3 Data Available" },
  { AL_IIN_TSR,     "Time Sync Required from Master" },
  { AL_IIN_DOL,     "Outputs in Local Mode" },
  { AL_IIN_DT,      "Device Trouble" },
  { AL_IIN_RST,     "Device Restart" },
  { AL_IIN_FCNI,    "Function Code not implemented" },
  { AL_IIN_OBJU,    "Requested Objects Unknown" },
  { AL_IIN_PIOOR,   "Parameters Invalid or Out of Range" },
  { AL_IIN_EBO,     "Event Buffer Overflow" },
  { AL_IIN_OAE,     "Operation Already Executing" },
  { AL_IIN_CC,      "Device Configuration Corrupt" },
  { 0, NULL }
};

/* Application Layer Object Qualifier Prefix Values When Qualifier Code != 11 */
static const value_string dnp3_al_objq_prefix_vals[] = {
  { AL_OBJQL_PREFIX_NI,    "None" },
  { AL_OBJQL_PREFIX_1O,    "1-Octet Index Prefix" },
  { AL_OBJQL_PREFIX_2O,    "2-Octet Index Prefix" },
  { AL_OBJQL_PREFIX_4O,    "4-Octet Index Prefix" },
  { AL_OBJQL_PREFIX_1OS,   "1-Octet Object Size Prefix" },
  { AL_OBJQL_PREFIX_2OS,   "2-Octet Object Size Prefix" },
  { AL_OBJQL_PREFIX_4OS,   "4-Octet Object Size Prefix" },
  { 0, NULL }
};
static value_string_ext dnp3_al_objq_prefix_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_objq_prefix_vals);

/* Application Layer Object Qualifier Range Values */
static const value_string dnp3_al_objq_range_vals[] = {
  { AL_OBJQL_RANGE_SSI8,    "8-bit Start and Stop Indices" },
  { AL_OBJQL_RANGE_SSI16,   "16-bit Start and Stop Indices" },
  { AL_OBJQL_RANGE_SSI32,   "32-bit Start and Stop Indices" },
  { AL_OBJQL_RANGE_AA8,     "8-bit Absolute Address in Range Field" },
  { AL_OBJQL_RANGE_AA16,    "16-bit Absolute Address in Range Field" },
  { AL_OBJQL_RANGE_AA32,    "32-bit Absolute Address in Range Field" },
  { AL_OBJQL_RANGE_R0,      "No Range Field" },
  { AL_OBJQL_RANGE_SF8,     "8-bit Single Field Quantity" },
  { AL_OBJQL_RANGE_SF16,    "16-bit Single Field Quantity" },
  { AL_OBJQL_RANGE_SF32,    "32-bit Single Field Quantity" },
  { 10,                     "Reserved" },
  { AL_OBJQL_RANGE_FF,      "Free-format Qualifier" },
  { 0, NULL }
};
static value_string_ext dnp3_al_objq_range_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_objq_range_vals);

/* Application Layer Data Object Values */
static const value_string dnp3_al_obj_vals[] = {
  { AL_OBJ_DA_CFG_ID,      "Device Attributes - Configuration ID (Obj:00, Var:196)" },
  { AL_OBJ_DA_CFG_VER,     "Device Attributes - Configuration version (Obj:00, Var:197)" },
  { AL_OBJ_DA_CFG_BLD_DATE,"Device Attributes - Configuration build date (Obj:00, Var:198)" },
  { AL_OBJ_DA_CFG_CHG_DATE,"Device Attributes - Configuration last change date (Obj:00, Var:199)" },
  { AL_OBJ_DA_CFG_SIG,     "Device Attributes - Configuration signature (Obj:00, Var:200)" },
  { AL_OBJ_DA_CFG_SIG_ALG, "Device Attributes - Configuration signature algorithm (Obj:00, Var:201)" },
  { AL_OBJ_DA_MRID,        "Device Attributes - Master Resource ID (mRID) (Obj:00, Var:202)" },
  { AL_OBJ_DA_ALT,         "Device Attributes - Device altitude (Obj:00, Var:203)" },
  { AL_OBJ_DA_LONG,        "Device Attributes - Device longitude (Obj:00, Var:204)" },
  { AL_OBJ_DA_LAT,         "Device Attributes - Device latitude (Obj:00, Var:205)" },
  { AL_OBJ_DA_SEC_OP,      "Device Attributes - User-assigned secondary operator name (Obj:00, Var:206)" },
  { AL_OBJ_DA_PRM_OP,      "Device Attributes - User-assigned primary operator name (Obj:00, Var:207)" },
  { AL_OBJ_DA_SYS_NAME,    "Device Attributes - User-assigned system name (Obj:00, Var:208)" },
  { AL_OBJ_DA_SEC_VER,     "Device Attributes - Secure authentication version (Obj:00, Var:209)" },
  { AL_OBJ_DA_SEC_STAT,    "Device Attributes - Number of security statistics per association (Obj:00, Var:210)" },
  { AL_OBJ_DA_USR_ATTR,    "Device Attributes - Identifier of support for user-specific attributes (Obj:00, Var:211)" },
  { AL_OBJ_DA_MSTR_DSP,    "Device Attributes - Number of master-defined data set prototypes (Obj:00, Var:212)" },
  { AL_OBJ_DA_OS_DSP,      "Device Attributes - Number of outstation-defined data set prototypes (Obj:00, Var:213)" },
  { AL_OBJ_DA_MSTR_DS,     "Device Attributes - Number of master-defined data sets (Obj:00, Var:214)" },
  { AL_OBJ_DA_OS_DS,       "Device Attributes - Number of outstation-defined data sets (Obj:00, Var:215)" },
  { AL_OBJ_DA_BO_REQ,      "Device Attributes - Max number of binary outputs per request (Obj:00, Var:216)" },
  { AL_OBJ_DA_LOC_TA,      "Device Attributes - Local timing accuracy (Obj:00, Var:217)" },
  { AL_OBJ_DA_DUR_TA,      "Device Attributes - Duration of timing accuracy (Obj:00, Var:218)" },
  { AL_OBJ_DA_AO_EVT,      "Device Attributes - Support for analog output events (Obj:00, Var:219)" },
  { AL_OBJ_DA_MAX_AO,      "Device Attributes - Max analog output index (Obj:00, Var:220)" },
  { AL_OBJ_DA_NUM_AO,      "Device Attributes - Number of analog outputs (Obj:00, Var:221)" },
  { AL_OBJ_DA_BO_EVT,      "Device Attributes - Support for binary output events (Obj:00, Var:222)" },
  { AL_OBJ_DA_MAX_BO,      "Device Attributes - Max binary output index (Obj:00, Var:223)" },
  { AL_OBJ_DA_NUM_BO,      "Device Attributes - Number of binary outputs (Obj:00, Var:224)" },
  { AL_OBJ_DA_FCTR_EVT,    "Device Attributes - Support for frozen counter events (Obj:00, Var:225)" },
  { AL_OBJ_DA_FCTR,        "Device Attributes - Support for frozen counters (Obj:00, Var:226)" },
  { AL_OBJ_DA_CTR_EVT,     "Device Attributes - Support for counter events (Obj:00, Var:227)" },
  { AL_OBJ_DA_MAX_CTR,     "Device Attributes - Max counter index (Obj:00, Var:228)" },
  { AL_OBJ_DA_NUM_CTR,     "Device Attributes - Number of counter points (Obj:00, Var:229)" },
  { AL_OBJ_DA_AIF,         "Device Attributes - Support for frozen analog inputs (Obj:00, Var:230)" },
  { AL_OBJ_DA_AI_EVT,      "Device Attributes - Support for analog input events (Obj:00, Var:231)" },
  { AL_OBJ_DA_MAX_AI,      "Device Attributes - Maximum analog input index (Obj:00, Var:232)" },
  { AL_OBJ_DA_NUM_AI,      "Device Attributes - Number of analog input points (Obj:00, Var:233)" },
  { AL_OBJ_DA_2BI_EVT,     "Device Attributes - Support for Double-Bit BI Events (Obj:00, Var:234)" },
  { AL_OBJ_DA_MAX_2BI,     "Device Attributes - Max Double-bit BI Point Index (Obj:00, Var:235)" },
  { AL_OBJ_DA_NUM_2BI,     "Device Attributes - Number of Double-bit BI Points (Obj:00, Var:236)" },
  { AL_OBJ_DA_BI_EVT,      "Device Attributes - Support for Binary Input Events (Obj:00, Var:237)" },
  { AL_OBJ_DA_MAX_BI,      "Device Attributes - Max Binary Input Point Index (Obj:00, Var:238)" },
  { AL_OBJ_DA_NUM_BI,      "Device Attributes - Number of Binary Input Points (Obj:00, Var:239)" },
  { AL_OBJ_DA_MXTX_FR,     "Device Attributes - Maximum Transmit Fragment Size (Obj:00, Var:240)" },
  { AL_OBJ_DA_MXRX_FR,     "Device Attributes - Maximum Receive Fragment Size (Obj:00, Var:241)" },
  { AL_OBJ_DA_SWVER,       "Device Attributes - Device Manufacturers SW Version (Obj:00, Var:242)" },
  { AL_OBJ_DA_HWVER,       "Device Attributes - Device Manufacturers HW Version (Obj:00, Var:243)" },
  { AL_OBJ_DA_LOC,         "Device Attributes - User-Assigned Location (Obj:00, Var:245)" },
  { AL_OBJ_DA_ID,          "Device Attributes - User-Assigned ID code/number (Obj:00, Var:246)" },
  { AL_OBJ_DA_DEVNAME,     "Device Attributes - User-Assigned Device Name (Obj:00, Var:247)" },
  { AL_OBJ_DA_SERNUM,      "Device Attributes - Device Serial Number (Obj:00, Var:248)" },
  { AL_OBJ_DA_CONF,        "Device Attributes - DNP Subset and Conformance (Obj:00, Var:249)" },
  { AL_OBJ_DA_PROD,        "Device Attributes - Device Product Name and Model (Obj:00, Var:250)" },
  { AL_OBJ_DA_MFG,         "Device Attributes - Device Manufacturers Name (Obj:00, Var:252)" },
  { AL_OBJ_DA_ALL,         "Device Attributes - Non-specific All-attributes Request (Obj:00, Var:254)" },
  { AL_OBJ_DA_LVAR,        "Device Attributes - List of Attribute Variations (Obj:00, Var:255)" },
  { AL_OBJ_BI_ALL,         "Binary Input Default Variation (Obj:01, Var:Default)" },
  { AL_OBJ_BI_1BIT,        "Single-Bit Binary Input (Obj:01, Var:01)" },
  { AL_OBJ_BI_STAT,        "Binary Input With Status (Obj:01, Var:02)" },
  { AL_OBJ_BIC_ALL,        "Binary Input Change Default Variation (Obj:02, Var:Default)" },
  { AL_OBJ_BIC_NOTIME,     "Binary Input Change Without Time (Obj:02, Var:01)" },
  { AL_OBJ_BIC_TIME,       "Binary Input Change With Time (Obj:02, Var:02)" },
  { AL_OBJ_BIC_RTIME,      "Binary Input Change With Relative Time (Obj:02, Var:03)" },
  { AL_OBJ_2BI_ALL,        "Double-bit Input Default Variation (Obj:03, Var:Default)" },
  { AL_OBJ_2BI_NF,         "Double-bit Input No Flags (Obj:03, Var:01)" },
  { AL_OBJ_2BI_STAT,       "Double-bit Input With Status (Obj:03, Var:02)" },
  { AL_OBJ_2BIC_ALL,       "Double-bit Input Change Default Variation (Obj:04, Var:Default)" },
  { AL_OBJ_2BIC_NOTIME,    "Double-bit Input Change Without Time (Obj:04, Var:01)" },
  { AL_OBJ_2BIC_TIME,      "Double-bit Input Change With Time (Obj:04, Var:02)" },
  { AL_OBJ_2BIC_RTIME,     "Double-bit Input Change With Relative Time (Obj:04, Var:03)" },
  { AL_OBJ_BO_ALL,         "Binary Output Default Variation (Obj:10, Var:Default)" },
  { AL_OBJ_BO,             "Binary Output (Obj:10, Var:01)" },
  { AL_OBJ_BO_STAT,        "Binary Output Status (Obj:10, Var:02)" },
  { AL_OBJ_BOC_ALL,        "Binary Output Change Default Variation (Obj:11, Var:Default)" },
  { AL_OBJ_BOC_NOTIME,     "Binary Output Change Without Time (Obj:11, Var:01)" },
  { AL_OBJ_BOC_TIME,       "Binary Output Change With Time (Obj:11, Var:02)" },
  { AL_OBJ_CTLOP_BLK,      "Control Relay Output Block (Obj:12, Var:01)" },
  { AL_OBJ_CTL_PCB,        "Pattern Control Block (Obj:12, Var:02)" },
  { AL_OBJ_CTL_PMASK,      "Pattern Mask (Obj:12, Var:03)" },
  { AL_OBJ_BOE_NOTIME,     "Binary Command Event Without Time (Obj 13, Var:01)" },
  { AL_OBJ_BOE_TIME,       "Binary Command Event With Time (Obj 13, Var:02)" },
  { AL_OBJ_CTR_ALL,        "Binary Counter Default Variation (Obj:20, Var:Default)" },
  { AL_OBJ_CTR_32,         "32-Bit Binary Counter (Obj:20, Var:01)" },
  { AL_OBJ_CTR_16,         "16-Bit Binary Counter (Obj:20, Var:02)" },
  { AL_OBJ_DCTR_32,        "32-Bit Binary Delta Counter (Obj:20, Var:03)" },
  { AL_OBJ_DCTR_16,        "16-Bit Binary Delta Counter (Obj:20, Var:04)" },
  { AL_OBJ_CTR_32NF,       "32-Bit Binary Counter Without Flag (Obj:20, Var:05)" },
  { AL_OBJ_CTR_16NF,       "16-Bit Binary Counter Without Flag (Obj:20, Var:06)" },
  { AL_OBJ_DCTR_32NF,      "32-Bit Binary Delta Counter Without Flag (Obj:20, Var:07)" },
  { AL_OBJ_DCTR_16NF,      "16-Bit Binary Delta Counter Without Flag (Obj:20, Var:08)" },
  { AL_OBJ_FCTR_ALL,       "Frozen Binary Counter Default Variation (Obj:21, Var:Default)" },
  { AL_OBJ_FCTR_32,        "32-Bit Frozen Binary Counter (Obj:21, Var:01)" },
  { AL_OBJ_FCTR_16,        "16-Bit Frozen Binary Counter (Obj:21, Var:02)" },
  { AL_OBJ_FDCTR_32,       "32-Bit Frozen Binary Delta Counter (Obj:21, Var:03)" },
  { AL_OBJ_FDCTR_16,       "16-Bit Frozen Binary Delta Counter (Obj:21, Var:04)" },
  { AL_OBJ_FCTR_32T,       "32-Bit Frozen Binary Counter With Flag and Time (Obj:21, Var:05)" },
  { AL_OBJ_FCTR_16T,       "16-Bit Frozen Binary Counter With Flag and Time (Obj:21, Var:06)" },
  { AL_OBJ_FDCTR_32T,      "32-Bit Frozen Binary Delta Counter With Flag and Time (Obj:21, Var:07)" },
  { AL_OBJ_FDCTR_16T,      "16-Bit Frozen Binary Delta Counter With Flag and Time (Obj:21, Var:08)" },
  { AL_OBJ_FCTR_32NF,      "32-Bit Frozen Binary Counter Without Flag (Obj:21, Var:09)" },
  { AL_OBJ_FCTR_16NF,      "16-Bit Frozen Binary Counter Without Flag (Obj:21, Var:10)" },
  { AL_OBJ_FDCTR_32NF,     "32-Bit Frozen Binary Delta Counter Without Flag (Obj:21, Var:11)" },
  { AL_OBJ_FDCTR_16NF,     "16-Bit Frozen Binary Delta Counter Without Flag (Obj:21, Var:12)" },
  { AL_OBJ_CTRC_ALL,       "Binary Counter Change Default Variation (Obj:22, Var:Default)" },
  { AL_OBJ_CTRC_32,        "32-Bit Counter Change Event w/o Time (Obj:22, Var:01)" },
  { AL_OBJ_CTRC_16,        "16-Bit Counter Change Event w/o Time (Obj:22, Var:02)" },
  { AL_OBJ_DCTRC_32,       "32-Bit Delta Counter Change Event w/o Time (Obj:22, Var:03)" },
  { AL_OBJ_DCTRC_16,       "16-Bit Delta Counter Change Event w/o Time (Obj:22, Var:04)" },
  { AL_OBJ_CTRC_32T,       "32-Bit Counter Change Event with Time (Obj:22, Var:05)" },
  { AL_OBJ_CTRC_16T,       "16-Bit Counter Change Event with Time (Obj:22, Var:06)" },
  { AL_OBJ_DCTRC_32T,      "32-Bit Delta Counter Change Event with Time (Obj:22, Var:07)" },
  { AL_OBJ_DCTRC_16T,      "16-Bit Delta Counter Change Event with Time (Obj:22, Var:08)" },
  { AL_OBJ_FCTRC_ALL,      "Frozen Binary Counter Change Default Variation (Obj:23, Var:Default)" },
  { AL_OBJ_FCTRC_32,       "32-Bit Frozen Counter Change Event w/o Time (Obj:23, Var:01)" },
  { AL_OBJ_FCTRC_16,       "16-Bit Frozen Counter Change Event w/o Time (Obj:23, Var:02)" },
  { AL_OBJ_FDCTRC_32,      "32-Bit Frozen Delta Counter Change Event w/o Time (Obj:23, Var:03)" },
  { AL_OBJ_FDCTRC_16,      "16-Bit Frozen Delta Counter Change Event w/o Time (Obj:23, Var:04)" },
  { AL_OBJ_FCTRC_32T,      "32-Bit Frozen Counter Change Event with Time (Obj:23, Var:05)" },
  { AL_OBJ_FCTRC_16T,      "16-Bit Frozen Counter Change Event with Time (Obj:23, Var:06)" },
  { AL_OBJ_FDCTRC_32T,     "32-Bit Frozen Delta Counter Change Event with Time (Obj:23, Var:07)" },
  { AL_OBJ_FDCTRC_16T,     "16-Bit Frozen Delta Counter Change Event with Time (Obj:23, Var:08)" },
  { AL_OBJ_AI_ALL,         "Analog Input Default Variation (Obj:30, Var:Default)" },
  { AL_OBJ_AI_32,          "32-Bit Analog Input (Obj:30, Var:01)" },
  { AL_OBJ_AI_16,          "16-Bit Analog Input (Obj:30, Var:02)" },
  { AL_OBJ_AI_32NF,        "32-Bit Analog Input Without Flag (Obj:30, Var:03)" },
  { AL_OBJ_AI_16NF,        "16-Bit Analog Input Without Flag (Obj:30, Var:04)" },
  { AL_OBJ_AI_FLT,         "32-Bit Floating Point Input (Obj:30, Var:05)" },
  { AL_OBJ_AI_DBL,         "64-Bit Floating Point Input (Obj:30, Var:06)" },
  { AL_OBJ_AIF_32,         "32-Bit Frozen Analog Input (Obj:31, Var:01)" },
  { AL_OBJ_AIF_16,         "16-Bit Frozen Analog Input (Obj:31, Var:02)" },
  { AL_OBJ_AIF_32TOF,      "32-Bit Frozen Analog Input w/ Time of Freeze (Obj:31, Var:03)" },
  { AL_OBJ_AIF_16TOF,      "16-Bit Frozen Analog Input w/ Time of Freeze (Obj:31, Var:04)" },
  { AL_OBJ_AIF_32NF,       "32-Bit Frozen Analog Input Without Flag (Obj:31, Var:05)" },
  { AL_OBJ_AIF_16NF,       "16-Bit Frozen Analog Input Without Flag (Obj:31, Var:06)" },
  { AL_OBJ_AIF_FLT,        "32-Bit Frozen Floating Point Input (Obj:31, Var:07)" },
  { AL_OBJ_AIF_DBL,        "64-Bit Frozen Floating Point Input (Obj:31, Var:08)" },
  { AL_OBJ_AIC_ALL,        "Analog Input Change Default Variation (Obj:32, Var:Default)" },
  { AL_OBJ_AIC_32NT,       "32-Bit Analog Change Event w/o Time (Obj:32, Var:01)" },
  { AL_OBJ_AIC_16NT,       "16-Bit Analog Change Event w/o Time (Obj:32, Var:02)" },
  { AL_OBJ_AIC_32T,        "32-Bit Analog Change Event with Time (Obj:32, Var:03)" },
  { AL_OBJ_AIC_16T,        "16-Bit Analog Change Event with Time (Obj:32, Var:04)" },
  { AL_OBJ_AIC_FLTNT,      "32-Bit Floating Point Change Event w/o Time (Obj:32, Var:05)" },
  { AL_OBJ_AIC_DBLNT,      "64-Bit Floating Point Change Event w/o Time (Obj:32, Var:06)" },
  { AL_OBJ_AIC_FLTT,       "32-Bit Floating Point Change Event w/ Time (Obj:32, Var:07)" },
  { AL_OBJ_AIC_DBLT,       "64-Bit Floating Point Change Event w/ Time (Obj:32, Var:08)" },
  { AL_OBJ_AIFC_32NT,      "32-Bit Frozen Analog Event w/o Time (Obj:33, Var:01)" },
  { AL_OBJ_AIFC_16NT,      "16-Bit Frozen Analog Event w/o Time (Obj:33, Var:02)" },
  { AL_OBJ_AIFC_32T,       "32-Bit Frozen Analog Event w/ Time (Obj:33, Var:03)" },
  { AL_OBJ_AIFC_16T,       "16-Bit Frozen Analog Event w/ Time (Obj:33, Var:04)" },
  { AL_OBJ_AIFC_FLTNT,     "32-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:05)" },
  { AL_OBJ_AIFC_DBLNT,     "64-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:06)" },
  { AL_OBJ_AIFC_FLTT,      "32-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:07)" },
  { AL_OBJ_AIFC_DBLT,      "64-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:08)" },
  { AL_OBJ_AIDB_ALL,       "Analog Input Deadband Default Variation (Obj:34, Var:Default)" },
  { AL_OBJ_AIDB_16,        "16-Bit Analog Input Deadband (Obj:34, Var:01)" },
  { AL_OBJ_AIDB_32,        "32-Bit Analog Input Deadband (Obj:34, Var:02)" },
  { AL_OBJ_AIDB_FLT,       "32-Bit Floating Point Analog Input Deadband (Obj:34, Var:03)" },
  { AL_OBJ_AO_ALL,         "Analog Output Default Variation (Obj:40, Var:Default)" },
  { AL_OBJ_AO_32,          "32-Bit Analog Output Status (Obj:40, Var:01)" },
  { AL_OBJ_AO_16,          "16-Bit Analog Output Status (Obj:40, Var:02)" },
  { AL_OBJ_AO_FLT,         "32-Bit Floating Point Output Status (Obj:40, Var:03)" },
  { AL_OBJ_AO_DBL,         "64-Bit Floating Point Output Status (Obj:40, Var:04)" },
  { AL_OBJ_AO_32OPB,       "32-Bit Analog Output Block (Obj:41, Var:01)" },
  { AL_OBJ_AO_16OPB,       "16-Bit Analog Output Block (Obj:41, Var:02)" },
  { AL_OBJ_AO_FLTOPB,      "32-Bit Floating Point Output Block (Obj:41, Var:03)" },
  { AL_OBJ_AO_DBLOPB,      "64-Bit Floating Point Output Block (Obj:41, Var:04)" },
  { AL_OBJ_AOC_ALL,        "Analog Output Event Default Variation (Obj:42, Var:Default)" },
  { AL_OBJ_AOC_32NT,       "32-Bit Analog Output Event w/o Time (Obj:42, Var:01)" },
  { AL_OBJ_AOC_16NT,       "16-Bit Analog Output Event w/o Time (Obj:42, Var:02)" },
  { AL_OBJ_AOC_32T,        "32-Bit Analog Output Event with Time (Obj:42, Var:03)" },
  { AL_OBJ_AOC_16T,        "16-Bit Analog Output Event with Time (Obj:42, Var:04)" },
  { AL_OBJ_AOC_FLTNT,      "32-Bit Floating Point Output Event w/o Time (Obj:42, Var:05)" },
  { AL_OBJ_AOC_DBLNT,      "64-Bit Floating Point Output Event w/o Time (Obj:42, Var:06)" },
  { AL_OBJ_AOC_FLTT,       "32-Bit Floating Point Output Event w/ Time (Obj:42, Var:07)" },
  { AL_OBJ_AOC_DBLT,       "64-Bit Floating Point Output Event w/ Time (Obj:42, Var:08)" },
  { AL_OBJ_AOC_32EVNT,     "32-Bit Analog Output Event w/o Time (Obj:43, Var:01)" },
  { AL_OBJ_AOC_16EVNT,     "16-Bit Analog Output Event w/o Time (Obj:43, Var:02)" },
  { AL_OBJ_AOC_32EVTT,     "32-Bit Analog Output Event with Time (Obj:43, Var:03)" },
  { AL_OBJ_AOC_16EVTT,     "16-Bit Analog Output Event with Time (Obj:43, Var:04)" },
  { AL_OBJ_AOC_FLTEVNT,    "32-Bit Floating Point Output Event w/o Time (Obj:43, Var:05)" },
  { AL_OBJ_AOC_DBLEVNT,    "64-Bit Floating Point Output Event w/o Time (Obj:43, Var:06)" },
  { AL_OBJ_AOC_FLTEVTT,    "32-Bit Floating Point Output Event w/ Time (Obj:43, Var:07)" },
  { AL_OBJ_AOC_DBLEVTT,    "64-Bit Floating Point Output Event w/ Time (Obj:43, Var:08)" },
  { AL_OBJ_TD_ALL,         "Time and Date Default Variations (Obj:50, Var:Default)" },
  { AL_OBJ_TD,             "Time and Date (Obj:50, Var:01)" },
  { AL_OBJ_TDI,            "Time and Date w/Interval (Obj:50, Var:02)" },
  { AL_OBJ_TDR,            "Last Recorded Time and Date (Obj:50, Var:03)" },
  { AL_OBJ_TDCTO,          "Time and Date CTO (Obj:51, Var:01)" },
  { AL_OBJ_UTDCTO,         "Unsynchronized Time and Date CTO (Obj:51, Var:02)"},
  { AL_OBJ_TDELAYF,        "Time Delay - Fine (Obj:52, Var:02)" },
  { AL_OBJ_CLASS0,         "Class 0 Data (Obj:60, Var:01)" },
  { AL_OBJ_CLASS1,         "Class 1 Data (Obj:60, Var:02)" },
  { AL_OBJ_CLASS2,         "Class 2 Data (Obj:60, Var:03)" },
  { AL_OBJ_CLASS3,         "Class 3 Data (Obj:60, Var:04)" },
  { AL_OBJ_FILE_CMD,       "File Control - File Command (Obj:70, Var:03)" },
  { AL_OBJ_FILE_STAT,      "File Control - File Status (Obj:70, Var:04)" },
  { AL_OBJ_FILE_TRANS,     "File Control - File Transport (Obj:70, Var:05)" },
  { AL_OBJ_FILE_TRAN_ST,   "File Control - File Transport Status (Obj:70, Var:06)" },
  { AL_OBJ_IIN,            "Internal Indications (Obj:80, Var:01)" },
  { AL_OBJ_DS_PROTO,       "Data-Set Prototype, with UUID (Obj:85, Var:01)" },
  { AL_OBJ_DSD_CONT,       "Data-Set Descriptor, Data-Set Contents (Obj:86, Var:01)" },
  { AL_OBJ_DSD_CHAR,       "Data-Set Descriptor, Characteristics (Obj:86, Var:02)" },
  { AL_OBJ_DSD_PIDX,       "Data-Set Descriptor, Point Index Attributes (Obj:86, Var:03)" },
  { AL_OBJ_DS_PV,          "Data-Set, Present Value (Obj:87, Var:01)" },
  { AL_OBJ_DS_SS,          "Data-Set, Snapshot (Obj:88, Var:01)" },
  { AL_OBJ_OCT,            "Octet String (Obj:110)" },
  { AL_OBJ_OCT_EVT,        "Octet String Event (Obj:111)" },
  { AL_OBJ_VT_OBLK,        "Virtual Terminal Output Block (Obj:112)" },
  { AL_OBJ_VT_EVTD,        "Virtual Terminal Event Data (Obj:113)" },
  { AL_OBJ_SA_AUTH_CH,     "Authentication Challenge (Obj:120, Var:01)" },
  { AL_OBJ_SA_AUTH_RP,     "Authentication Reply (Obj:120, Var:02)" },
  { AL_OBJ_SA_AUTH_AGMRQ,  "Authentication Aggressive Mode Request (Obj:120, Var:03)" },
  { AL_OBJ_SA_AUTH_SKSR,   "Authentication Session Key Status Request (Obj:120, Var:04)" },
  { AL_OBJ_SA_AUTH_SKS,    "Authentication Session Key Status (Obj:120, Var:05)" },
  { AL_OBJ_SA_AUTH_SKC,    "Authentication Session Key Change (Obj:120, Var:06)" },
  { AL_OBJ_SA_AUTH_ERR,    "Authentication Error (Obj:120, Var:07)" },
  { AL_OBJ_SA_AUTH_MAC,    "Authentication Message Authentication Code (Obj:120, Var:09)" },
  { AL_OBJ_SA_AUTH_UKCR,   "Authentication Update Key Change Request (Obj:120, Var:11)" },
  { AL_OBJ_SA_AUTH_UKCRP,  "Authentication Update Key Change Reply (Obj:120, Var:12)"},
  { AL_OBJ_SA_AUTH_UKC,    "Authentication Update Key Change (Obj:120, Var:13)"},
  { AL_OBJ_SA_AUTH_UKCC,   "Authentication Update Key Change Confirmation (Obj:120, Var:15)"},
  { AL_OBJ_SA_SECSTAT,     "Security Statistics (Obj:121, Var:01)" },
  { AL_OBJ_SA_SECSTATEVT,  "Security Statistic Event (Obj:122, Var:01)" },
  { AL_OBJ_SA_SECSTATEVTT, "Security Statistic Event w/ Time (Obj:122, Var:02)" },
  { 0, NULL }
};
static value_string_ext dnp3_al_obj_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_obj_vals);

/* Application Layer Control Code 'Operation Type' Values */
static const value_string dnp3_al_ctlc_code_vals[] = {
  { AL_OBJCTLC_CODE0,     "NUL Operation" },
  { AL_OBJCTLC_CODE1,     "Pulse On" },
  { AL_OBJCTLC_CODE2,     "Pulse Off" },
  { AL_OBJCTLC_CODE3,     "Latch On" },
  { AL_OBJCTLC_CODE4,     "Latch Off" },
  { 0, NULL }
};

/* Application Layer Control Code 'Clear Field' Values */
static const value_string dnp3_al_ctlc_misc_vals[] = {
  { AL_OBJCTLC_QUEUE,     "Queue" },
  { AL_OBJCTLC_CLEAR,     "Clear" },
  { AL_OBJCTLC_NOTSET,    "Not Set" },
  { AL_OBJCTLC_BOTHSET,   "Queue and Clear" },
  { 0, NULL }
};

/* Application Layer Control Code 'Trip Close Code' Values */
static const value_string dnp3_al_ctlc_tc_vals[] = {
  { AL_OBJCTLC_TC0,     "NUL" },
  { AL_OBJCTLC_TC1,     "Close" },
  { AL_OBJCTLC_TC2,     "Trip" },
  { AL_OBJCTLC_TC3,     "Reserved" },
  { 0, NULL }
};

/* Application Layer Control Status Values */
static const value_string dnp3_al_ctl_status_vals[] = {
  { AL_OBJCTL_STAT0,     "Req. Accepted/Init/Queued" },
  { AL_OBJCTL_STAT1,     "Req. Not Accepted; Arm-Timer Expired" },
  { AL_OBJCTL_STAT2,     "Req. Not Accepted; No 'SELECT' Received" },
  { AL_OBJCTL_STAT3,     "Req. Not Accepted; Format Err. in Ctl Req." },
  { AL_OBJCTL_STAT4,     "Ctl Oper. Not Supported For This Point" },
  { AL_OBJCTL_STAT5,     "Req. Not Accepted; Ctrl Queue Full/Point Active" },
  { AL_OBJCTL_STAT6,     "Req. Not Accepted; Ctrl Hardware Problems" },
  { AL_OBJCTL_STAT7,     "Req. Not Accepted; Local/Remote switch in Local" },
  { AL_OBJCTL_STAT8,     "Req. Not Accepted; Too many operations" },
  { AL_OBJCTL_STAT9,     "Req. Not Accepted; Insufficient authorization" },
  { AL_OBJCTL_STAT10,    "Req. Not Accepted; Local automation proc active" },
  { AL_OBJCTL_STAT11,    "Req. Not Accepted; Processing limited" },
  { AL_OBJCTL_STAT12,    "Req. Not Accepted; Out of range value" },
  { AL_OBJCTL_STAT126,   "Req. Not Accepted; Non-participating (NOP request)" },
  { AL_OBJCTL_STAT127,   "Req. Not Accepted; Undefined error" },
  { 0, NULL }
};
static value_string_ext dnp3_al_ctl_status_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_ctl_status_vals);

#if 0
/* Application Layer Binary Input Quality Flag Values */
static const value_string dnp3_al_biflag_vals[] = {
  { AL_OBJ_BI_FLAG0, "Online" },
  { AL_OBJ_BI_FLAG1, "Restart" },
  { AL_OBJ_BI_FLAG2, "Comm Fail" },
  { AL_OBJ_BI_FLAG3, "Remote Forced" },
  { AL_OBJ_BI_FLAG4, "Locally Forced" },
  { AL_OBJ_BI_FLAG5, "Chatter Filter" },
  { 0, NULL }
};
#endif

#if 0
/* Application Layer Counter Quality Flag Values */
static const value_string dnp3_al_ctrflag_vals[] = {
  { AL_OBJ_CTR_FLAG0, "Online" },
  { AL_OBJ_CTR_FLAG1, "Restart" },
  { AL_OBJ_CTR_FLAG2, "Comm Fail" },
  { AL_OBJ_CTR_FLAG3, "Remote Forced" },
  { AL_OBJ_CTR_FLAG4, "Locally Forced" },
  { AL_OBJ_CTR_FLAG5, "Roll-Over" },
  { AL_OBJ_CTR_FLAG6, "Discontinuity" },
  { 0, NULL }
};
#endif

#if 0
/* Application Layer Analog Input Quality Flag Values */
static const value_string dnp3_al_aiflag_vals[] = {
  { AL_OBJ_AI_FLAG0, "Online" },
  { AL_OBJ_AI_FLAG1, "Restart" },
  { AL_OBJ_AI_FLAG2, "Comm Fail" },
  { AL_OBJ_AI_FLAG3, "Remote Forced" },
  { AL_OBJ_AI_FLAG4, "Locally Forced" },
  { AL_OBJ_AI_FLAG5, "Over-Range" },
  { AL_OBJ_AI_FLAG6, "Ref. Error" },
  { 0, NULL }
};
#endif

/* Application Layer Double-bit status values */
static const value_string dnp3_al_2bit_vals[] = {
  { AL_OBJ_2BI_STATE_INTERMEDIATE, "Intermediate" },
  { AL_OBJ_2BI_STATE_OFF,          "Determined Off" },
  { AL_OBJ_2BI_STATE_ON,           "Determined On" },
  { AL_OBJ_2BI_STATE_INDETERM,     "Indeterminate" },
  { 0, NULL }
};
static value_string_ext dnp3_al_dbi_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_2bit_vals);

/* Application Layer File Control Mode values */
static const value_string dnp3_al_file_mode_vals[] = {
  { AL_OBJ_FILE_MODE_NULL,    "NULL" },
  { AL_OBJ_FILE_MODE_READ,    "READ" },
  { AL_OBJ_FILE_MODE_WRITE,   "WRITE" },
  { AL_OBJ_FILE_MODE_APPEND,  "APPEND" },
  { 0, NULL }
};

/* Application Layer File Control Status values */
static const value_string dnp3_al_file_status_vals[] = {
  { 0,    "SUCCESS" },
  { 1,    "PERMISSION DENIED" },
  { 2,    "INVALID MODE" },
  { 3,    "FILE NOT FOUND" },
  { 4,    "FILE LOCKED" },
  { 5,    "TOO MANY OPEN" },
  { 6,    "INVALID HANDLE" },
  { 7,    "WRITE BLOCK SIZE" },
  { 8,    "COMM LOST" },
  { 9,    "CANNOT ABORT" },
  { 16,   "NOT OPENED" },
  { 17,   "HANDLE EXPIRED" },
  { 18,   "BUFFER OVERRUN" },
  { 19,   "FATAL" },
  { 20,   "BLOCK SEQUENCE" },
  { 255,  "UNDEFINED" },
  { 0, NULL }
};
static value_string_ext dnp3_al_file_status_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_file_status_vals);

/* Application Layer Data Type values */
static const value_string dnp3_al_data_type_vals[] = {
  { AL_DATA_TYPE_NONE,        "NONE (Placeholder)" },
  { AL_DATA_TYPE_VSTR,        "VSTR (Visible ASCII String)" },
  { AL_DATA_TYPE_UINT,        "UINT (Unsigned Integer)" },
  { AL_DATA_TYPE_INT,         "INT (Signed Integer)" },
  { AL_DATA_TYPE_FLT,         "FLT (Floating Point)" },
  { AL_DATA_TYPE_OSTR,        "OSTR (Octet String)" },
  { AL_DATA_TYPE_BSTR,        "BSTR (Bit String)" },
  { AL_DATA_TYPE_TIME,        "TIME (DNP3 Time UINT48)" },
  { AL_DATA_TYPE_UNCD,        "UNCD (Unicode String)" },
  { AL_DATA_TYPE_U8BS8LIST,   "U8BS8LIST (List of UINT8 - BSTR8 pairs)" },
  { AL_DATA_TYPE_U8BS8EXLIST, "U8BS8EXLIST (Extended List of UINT8 - BSTR8 pairs)" },
  { 0, NULL }
};

/* Application Layer Read Object Type values */
static const value_string dnp3_al_read_obj_vals[] = {
  { (AL_OBJ_DA_GRP     & 0xFF00),  "Device Attribute"            },
  { (AL_OBJ_BI_ALL     & 0xFF00),  "Binary Input"                },
  { (AL_OBJ_BIC_ALL    & 0xFF00),  "Binary Input Change"         },
  { (AL_OBJ_2BI_ALL    & 0xFF00),  "Double-bit Input"            },
  { (AL_OBJ_2BIC_ALL   & 0xFF00),  "Double-bit Input Change"     },
  { (AL_OBJ_BO_ALL     & 0xFF00),  "Binary Output"               },
  { (AL_OBJ_BOC_ALL    & 0xFF00),  "Binary Output Change"        },
  { (AL_OBJ_CTR_ALL    & 0xFF00),  "Counter"                     },
  { (AL_OBJ_FCTR_ALL   & 0xFF00),  "Frozen Counter"              },
  { (AL_OBJ_CTRC_ALL   & 0xFF00),  "Counter Change"              },
  { (AL_OBJ_FCTRC_ALL  & 0xFF00),  "Frozen Counter Change"       },
  { (AL_OBJ_AI_ALL     & 0xFF00),  "Analog Input"                },
  { (AL_OBJ_AIC_ALL    & 0xFF00),  "Analog Input Change"         },
  { (AL_OBJ_AO_ALL     & 0xFF00),  "Analog Output"               },
  { (AL_OBJ_AOC_ALL    & 0xFF00),  "Analog Output Change"        },
  { (AL_OBJ_TD_ALL     & 0xFF00),  "Time and Date"               },
  { (AL_OBJ_FILE_CMD   & 0xFF00),  "File Control"                },
  { (AL_OBJ_IIN        & 0xFF00),  "Internal Indications"        },
  { (AL_OBJ_OCT        & 0xFF00),  "Octet String"                },
  { (AL_OBJ_OCT_EVT    & 0xFF00),  "Octet String Event"          },
  { (AL_OBJ_VT_EVTD    & 0xFF00),  "Virtual Terminal Event Data" },
  { (AL_OBJ_SA_AUTH_CH & 0xFF00),  "Secure Authentication" },
  { 0, NULL }
};

static value_string_ext dnp3_al_read_obj_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_read_obj_vals);

/* Application Layer Write Object Type values */
static const value_string dnp3_al_write_obj_vals[] = {
  { (AL_OBJ_TD_ALL     & 0xFF00),  "Time and Date"                 },
  { (AL_OBJ_FILE_CMD   & 0xFF00),  "File Control"                  },
  { (AL_OBJ_IIN        & 0xFF00),  "Internal Indications"          },
  { (AL_OBJ_OCT        & 0xFF00),  "Octet String"                  },
  { (AL_OBJ_OCT_EVT    & 0xFF00),  "Octet String Event"            },
  { (AL_OBJ_VT_OBLK    & 0xFF00),  "Virtual Terminal Output Block" },
  { (AL_OBJ_SA_AUTH_CH & 0xFF00),  "Secure Authentication" },
  { 0, NULL }
};

static value_string_ext dnp3_al_write_obj_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_write_obj_vals);

/* DNP SA Key Wrap Algorithm Values */
static const value_string dnp3_al_sa_kwa_vals[] = {
  { 0,  "Unused"       },
  { 1,  "AES-128"      },
  { 2,  "AES-256"      },
  { 0, NULL }
};

/* DNP SA Key Status Values */
static const value_string dnp3_al_sa_ks_vals[] = {
  { 0,  "Not Used"    },
  { 1,  "OK"          },
  { 2,  "NOT_INIT"    },
  { 3,  "COMM_FAIL"   },
  { 4,  "AUTH_FAIL"   },
  { 0, NULL }
};

/* DNP SA MAC Algorithm Values */
static const value_string dnp3_al_sa_mal_vals[] = {
  { 0,  "No MAC value in this message"                     },
  { 1,  "HMAC SHA-1 truncated to 4 octets (serial)"        },
  { 2,  "HMAC SHA-1 truncated to 10 octets (networked)"    },
  { 3,  "HMAC SHA-256 truncated to 8 octets (serial)"      },
  { 4,  "HMAC SHA-256 truncated to 16 octets (networked)"  },
  { 5,  "HMAC SHA-1 truncated to 8 octets (serial)"        },
  { 6,  "AES-GMAC (output is 12 octets)"                   },
  { 0, NULL }
};

/* DNP SA Error Values */
static const value_string dnp3_al_sa_err_vals[] = {
  { 0,  "Not used"                                 },
  { 1,  "Authentication failed"                    },
  { 2,  "Unexpected Response"                      },
  { 3,  "No response"                              },
  { 4,  "Aggressive Mode not supported"            },
  { 5,  "MAC Algorithm not supported"              },
  { 6,  "Key Wrap Algorithm not supported"         },
  { 7,  "Authorization failed"                     },
  { 8,  "Update Key Change Method not permitted"   },
  { 9,  "Invalid Signature"                        },
  { 10, "Invalid Certification Data"               },
  { 11, "Unknown User"                             },
  { 12, "Max Session Key Status Requests Exceeded" },
  { 0, NULL }
};

/* DNP SA Key Change Method Values */
static const value_string dnp3_al_sa_kcm_vals[] = {
  { 0,  "Not used"                                          },
  { 1,  "Obsolete. Do Not Use"                              },
  { 2,  "Obsolete. Do Not Use"                              },
  { 3,  "Symmetric AES-128 / SHA-1-HMAC"                    },
  { 4,  "Symmetric AES-256 / SHA-256-HMAC"                  },
  { 5,  "Symmetric AES-256 / AES-GMAC"                      },
  { 64,  "Obsolete. Do Not Use"                             },
  { 65,  "Obsolete. Do Not Use"                             },
  { 66,  "Obsolete. Do Not Use"                             },
  { 67,  "Asymmetric RSA-1024 / DSA SHA-1 / SHA-1-HMAC"     },
  { 68,  "Asymmetric RSA-2048 / DSA SHA-256 / SHA-256-HMAC" },
  { 69,  "Asymmetric RSA-3072 / DSA SHA-256 / SHA-256-HMAC" },
  { 70,  "Asymmetric RSA-2048 / DSA SHA-256 / AES-GMAC"     },
  { 71,  "Asymmetric RSA-3072 / DSA SHA-256 / AES-GMAC"     },
  { 0, NULL }
};

/* DNP SA Reason for Challenge Values */
static const value_string dnp3_al_sa_rfc_vals[] = {
  { 0,  "Not Used"    },
  { 1,  "CRITICAL"    },
  { 0, NULL }
};

/* DNP SA Security Statistic Values */
static const value_string dnp3_al_sa_secstat_vals[] = {
  { 0,  "(Unexpected Messages)"                   },
  { 1,  "(Authorization Failures)"                },
  { 2,  "(Authentication Failures)"               },
  { 3,  "(Reply Timeouts)"                        },
  { 4,  "(Rekeys Due to Authentication Failure)"  },
  { 5,  "(Total Messages Sent)"                   },
  { 6,  "(Total Messages Received)"               },
  { 7,  "(Critical Messages Sent)"                },
  { 8,  "(Critical Messages Received)"            },
  { 9,  "(Discarded Messages)"                    },
  { 10,  "(Error Messages Sent)"                  },
  { 11,  "(Error Messages Rxed)"                  },
  { 12,  "(Successful Authentications)"           },
  { 13,  "(Session Key Changes)"                  },
  { 14,  "(Failed Session Key Changes)"           },
  { 15,  "(Update Key Changes)"                   },
  { 16,  "(Failed Update Key Changes)"            },
  { 17,  "(Rekeys Due to Restarts)"               },
  { 0, NULL }
};

static value_string_ext dnp3_al_sa_secstat_vals_ext = VALUE_STRING_EXT_INIT(dnp3_al_sa_secstat_vals);

/* Initialize the subtree pointers */
static int ett_dnp3;
static int ett_dnp3_dl;
static int ett_dnp3_dl_ctl;
static int ett_dnp3_tr_ctl;
static int ett_dnp3_dl_data;
static int ett_dnp3_dl_chunk;
static int ett_dnp3_al;
static int ett_dnp3_al_ctl;
static int ett_dnp3_al_obj_point_tcc;

/* Added for Application Layer Decoding */
static int ett_dnp3_al_iin;
static int ett_dnp3_al_obj;
static int ett_dnp3_al_obj_qualifier;
static int ett_dnp3_al_obj_range;
static int ett_dnp3_al_objdet;
static int ett_dnp3_al_obj_quality;
static int ett_dnp3_al_obj_point;
static int ett_dnp3_al_obj_point_perms;

static expert_field ei_dnp_num_items_neg;
static expert_field ei_dnp_invalid_length;
static expert_field ei_dnp_iin_abnormal;
static expert_field ei_dnp3_data_hdr_crc_incorrect;
static expert_field ei_dnp3_data_chunk_crc_incorrect;
static expert_field ei_dnp3_unknown_object;
static expert_field ei_dnp3_unknown_group0_variation;
static expert_field ei_dnp3_num_items_invalid;
/* Generated from convert_proto_tree_add_text.pl */
#if 0
static expert_field ei_dnp3_buffering_user_data_until_final_frame_is_received;
#endif

/* Tables for reassembly of fragments. */
static reassembly_table al_reassembly_table;

/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int   hf_al_frag_data;
static int   hf_dnp3_fragment;
static int   hf_dnp3_fragments;
static int   hf_dnp3_fragment_overlap;
static int   hf_dnp3_fragment_overlap_conflict;
static int   hf_dnp3_fragment_multiple_tails;
static int   hf_dnp3_fragment_too_long_fragment;
static int   hf_dnp3_fragment_error;
static int   hf_dnp3_fragment_count;
static int   hf_dnp3_fragment_reassembled_in;
static int   hf_dnp3_fragment_reassembled_length;
static int ett_dnp3_fragment;
static int ett_dnp3_fragments;

static dissector_handle_t dnp3_tcp_handle;
static dissector_handle_t dnp3_udp_handle;

static const fragment_items dnp3_frag_items = {
  &ett_dnp3_fragment,
  &ett_dnp3_fragments,
  &hf_dnp3_fragments,
  &hf_dnp3_fragment,
  &hf_dnp3_fragment_overlap,
  &hf_dnp3_fragment_overlap_conflict,
  &hf_dnp3_fragment_multiple_tails,
  &hf_dnp3_fragment_too_long_fragment,
  &hf_dnp3_fragment_error,
  &hf_dnp3_fragment_count,
  &hf_dnp3_fragment_reassembled_in,
  &hf_dnp3_fragment_reassembled_length,
  /* Reassembled data field */
  NULL,
  "DNP 3.0 fragments"
};

/* desegmentation of DNP3 over TCP */
static bool dnp3_desegment = true;

/* Enum for different quality type fields */
enum QUALITY_TYPE {
  BIN_IN,
  DBIN_IN,
  BIN_OUT,
  ANA_IN,
  ANA_OUT,
  COUNTER
};

/* calculates crc given a buffer of characters and a length of buffer */
static uint16_t
calculateCRC(const void *buf, unsigned len) {
  uint16_t crc = crc16_0x3D65_seed((const uint8_t *)buf, len, 0);
  return ~crc;
}

/* calculates crc given a tvbuff, offset, and length */
static uint16_t
calculateCRCtvb(tvbuff_t *tvb, unsigned offset, unsigned len) {
  uint16_t crc = crc16_0x3D65_tvb_offset_seed(tvb, offset, len, 0);
  return ~crc;
}

/* calculate the extended sequence number - top 26 bits of the previous sequence number,
 * plus our own; then correct for wrapping */
static uint32_t
calculate_extended_seqno(uint32_t previous_seqno, uint8_t raw_seqno, bool fir)
{
  uint32_t seqno = (previous_seqno & 0xffffffc0) | raw_seqno;
  /* IEEE Std 1815-2012 8.3.1.4 Rules
   * "Rule 4: A transport segment with the FIR bit set may have any
   * sequence number from 0 to 63 without regard to prior history.
   * Rule 5: 2) A received transport segment having the FIR bit set shall
   * cause the entire, in-progress transport segment-series to be discarded,
   * and a new transport segment-series shall be started with the newly
   * received transport segment as its first member."
   */
  if (fir) {
    /* This is to handle Rule 4 by advancing a cycle on a segment with the
     * FIR bit set. If the implementation does not avail itself of Rule 4,
     * and the sequence number is a rolling counter that increments for each
     * transport segment (as opposed to resetting to 0 or anything else upon
     * a segment with the FIR bit set), then we could skip this and be able
     * to handle reordered segments received out of order after a segment with
     * the FIR bit set belonging to a different segment-series.
     *
     * We would need a preference.
     */
    seqno += 0x40;
  } else if (seqno + 0x20 < previous_seqno) {
    seqno += 0x40;
  } else if (previous_seqno + 0x20 < seqno) {
    /* we got an out-of-order packet which happened to go backwards over the
     * wrap boundary */
    seqno -= 0x40;
  }
  return seqno;
}

static int dnp3_tap;

typedef struct _dnp3_packet_info
{
  uint16_t dl_src;
  uint16_t dl_dst;
  uint16_t msg_len;

} dnp3_packet_info_t;

static const char* dnp3_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
  if (filter == CONV_FT_SRC_ADDRESS) {
    if (conv->src_address.type == AT_NUMERIC)
      return "dnp3.src";
  }

  if (filter == CONV_FT_DST_ADDRESS) {
    if (conv->dst_address.type == AT_NUMERIC)
      return "dnp3.dst";
  }

  if (filter == CONV_FT_ANY_ADDRESS) {
    if (conv->src_address.type == AT_NUMERIC && conv->dst_address.type == AT_NUMERIC)
      return "dnp3.addr";
  }

  return CONV_FILTER_INVALID;
}

static ct_dissector_info_t dnp3_ct_dissector_info = { &dnp3_conv_get_filter_type };

static const char* dnp3_get_filter_type(endpoint_item_t* endpoint, conv_filter_type_e filter)
{
  if (endpoint->myaddress.type == AT_NUMERIC) {
    if (filter == CONV_FT_ANY_ADDRESS)
      return "dnp3.addr";
    else if (filter == CONV_FT_SRC_ADDRESS)
      return "dnp3.src";
    else if (filter == CONV_FT_DST_ADDRESS)
      return "dnp3.dst";
  }

  return CONV_FILTER_INVALID;
}

static et_dissector_info_t  dnp3_dissector_info = { &dnp3_get_filter_type };

static tap_packet_status
dnp3_conversation_packet(void* pct, packet_info* pinfo,
  epan_dissect_t* edt _U_, const void* vip, tap_flags_t flags)
{

  address* src = wmem_new0(pinfo->pool, address);
  address* dst = wmem_new0(pinfo->pool, address);
  conv_hash_t* hash = (conv_hash_t*)pct;
  const dnp3_packet_info_t* dnp3_info = (const dnp3_packet_info_t*)vip;

  hash->flags = flags;

  alloc_address_wmem(pinfo->pool, src, AT_NUMERIC, (int)sizeof(uint16_t), &dnp3_info->dl_src);
  alloc_address_wmem(pinfo->pool, dst, AT_NUMERIC, (int)sizeof(uint16_t), &dnp3_info->dl_dst);

  add_conversation_table_data(hash, src, dst, 0, 0, 1, dnp3_info->msg_len, &pinfo->rel_ts, &pinfo->abs_ts,
    &dnp3_ct_dissector_info, CONVERSATION_DNP3);

  return TAP_PACKET_REDRAW;
}

static tap_packet_status
dnp3_endpoint_packet(void* pit, packet_info* pinfo,
  epan_dissect_t* edt _U_, const void* vip, tap_flags_t flags)
{
  address* src = wmem_new0(pinfo->pool, address);
  address* dst = wmem_new0(pinfo->pool, address);
  conv_hash_t* hash = (conv_hash_t*)pit;
  const dnp3_packet_info_t* dnp3_info = (const dnp3_packet_info_t*)vip;

  hash->flags = flags;

  alloc_address_wmem(pinfo->pool, src, AT_NUMERIC, (int)sizeof(uint16_t), &dnp3_info->dl_src);
  alloc_address_wmem(pinfo->pool, dst, AT_NUMERIC, (int)sizeof(uint16_t), &dnp3_info->dl_src);

  add_endpoint_table_data(hash, src, 0, true, 1, dnp3_info->msg_len, &dnp3_dissector_info, ENDPOINT_NONE);
  add_endpoint_table_data(hash, dst, 0, false, 1, dnp3_info->msg_len, &dnp3_dissector_info, ENDPOINT_NONE);

  return TAP_PACKET_REDRAW;
}

/*****************************************************************/
/*  Application Layer Process Internal Indications (IIN)         */
/*****************************************************************/
static void
dnp3_al_process_iin(tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *al_tree)
{
  uint16_t    al_iin;
  proto_item *tiin;
  static int* const indications[] = {
      &hf_dnp3_al_iin_rst,
      &hf_dnp3_al_iin_dt,
      &hf_dnp3_al_iin_dol,
      &hf_dnp3_al_iin_tsr,
      &hf_dnp3_al_iin_cls3d,
      &hf_dnp3_al_iin_cls2d,
      &hf_dnp3_al_iin_cls1d,
      &hf_dnp3_al_iin_bmsg,
      &hf_dnp3_al_iin_cc,
      &hf_dnp3_al_iin_oae,
      &hf_dnp3_al_iin_ebo,
      &hf_dnp3_al_iin_pioor,
      &hf_dnp3_al_iin_obju,
      &hf_dnp3_al_iin_fcni,
      NULL
  };

  tiin = proto_tree_add_bitmask(al_tree, tvb, offset, hf_dnp3_al_iin, ett_dnp3_al_iin, indications, ENC_BIG_ENDIAN);
  al_iin = tvb_get_ntohs(tvb, offset);

  /* If IIN indicates an abnormal condition, add expert info */
  if ((al_iin & AL_IIN_DT) || (al_iin & AL_IIN_CC) || (al_iin & AL_IIN_OAE) || (al_iin & AL_IIN_EBO) ||
      (al_iin & AL_IIN_PIOOR) || (al_iin & AL_IIN_OBJU) || (al_iin & AL_IIN_FCNI)) {
      expert_add_info(pinfo, tiin, &ei_dnp_iin_abnormal);
  }
}

/**************************************************************/
/* Function to determine Application Layer Object Prefix size */
/* and Point address.                                         */
/**************************************************************/
static int
dnp3_al_obj_procprefix(tvbuff_t *tvb, int offset, uint16_t al_obj, uint8_t al_objq_prefix, uint32_t *al_ptaddr, proto_tree *item_tree)
{
  int         prefixbytes = 0;
  proto_item *prefix_item;
  proto_item *index_item = 0, *type_index_item = 0;

  switch (al_objq_prefix)
  {
    case AL_OBJQL_PREFIX_NI:        /* No Prefix */
      prefixbytes = 0;
      prefix_item = proto_tree_add_uint(item_tree, hf_dnp3_al_point_index, tvb, offset, 0, *al_ptaddr);
      proto_item_set_generated(prefix_item);
      break;
    case AL_OBJQL_PREFIX_1O:
      *al_ptaddr = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_index8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      prefixbytes = 1;
      break;
    case AL_OBJQL_PREFIX_2O:
      *al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_index16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      prefixbytes = 2;
      break;
    case AL_OBJQL_PREFIX_4O:
      *al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_index32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      prefixbytes = 4;
      break;
    case AL_OBJQL_PREFIX_1OS:
      *al_ptaddr = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_size8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      prefixbytes = 1;
      break;
    case AL_OBJQL_PREFIX_2OS:
      *al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_size16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      prefixbytes = 2;
      break;
    case AL_OBJQL_PREFIX_4OS:
      *al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(item_tree, hf_dnp3_al_size32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      prefixbytes = 4;
      break;
  }

  if (al_objq_prefix <= AL_OBJQL_PREFIX_4O) {
    switch (al_obj & 0xff00) {
      case AL_OBJ_BI_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bi_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bi_static_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_BIC_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bi_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bi_event_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_2BI_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_dbi_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_dbi_static_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_2BIC_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_dbi_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_dbi_event_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_CTR_ALL:
      case AL_OBJ_FCTR_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_counter_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_counter_static_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_CTRC_ALL:
      case AL_OBJ_FCTRC_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_counter_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_counter_event_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_BO_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bo_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bo_static_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_BOC_ALL:
      case AL_OBJ_BOE_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bo_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bo_event_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_CTLOP_BLK & 0xff00:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bo_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_bo_cmnd_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_AI_ALL:
      case AL_OBJ_AIF_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ai_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ai_static_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_AIC_ALL:
      case AL_OBJ_AIFC_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ai_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ai_event_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_AO_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ao_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ao_static_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_AO_32OPB & 0xff00:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ao_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ao_cmnd_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_AOC_ALL:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ao_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_ao_event_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_OCT:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_os_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_os_static_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
      case AL_OBJ_OCT_EVT:
        index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_os_index, tvb, offset, prefixbytes, *al_ptaddr);
        type_index_item = proto_tree_add_uint(item_tree, hf_dnp3_al_os_event_index, tvb, offset, prefixbytes, *al_ptaddr);
        break;
    }

    if (al_objq_prefix == AL_OBJQL_PREFIX_NI) {
      proto_item_set_generated(index_item);
      proto_item_set_generated(type_index_item);
    }
  }

  return prefixbytes;
}

/*****************************************************************/
/* Function to add the same string to two separate tree items    */
/*****************************************************************/
static void
dnp3_append_2item_text(proto_item *item1, proto_item *item2, const char *text)
{
  proto_item_append_text(item1, "%s", text);
  proto_item_append_text(item2, "%s", text);
}

/*****************************************************************/
/* Function to Determine Application Layer Point Quality Flags & */
/* add Point Quality Flag Sub-Tree                               */
/*****************************************************************/
static void
dnp3_al_obj_quality(tvbuff_t *tvb, int offset, uint8_t al_ptflags, proto_tree *point_tree, proto_item *point_item, enum QUALITY_TYPE type)
{

  proto_tree *quality_tree;
  proto_item *quality_item;
  int         hf0 = 0, hf1 = 0, hf2 = 0, hf3 = 0, hf4 = 0, hf5 = 0, hf6 = 0, hf7 = 0;

  /* Common code */
  proto_item_append_text(point_item, " (Quality: ");
  quality_tree = proto_tree_add_subtree(point_tree, tvb, offset, 1, ett_dnp3_al_obj_quality, &quality_item, "Quality: ");

  if (al_ptflags & AL_OBJ_BI_FLAG0) {
    dnp3_append_2item_text(point_item, quality_item, "Online");
  }
  else {
    dnp3_append_2item_text(point_item, quality_item, "Offline");
  }
  if (al_ptflags & AL_OBJ_BI_FLAG1) dnp3_append_2item_text(point_item, quality_item, ", Restart");
  if (al_ptflags & AL_OBJ_BI_FLAG2) dnp3_append_2item_text(point_item, quality_item, ", Comm Fail");
  if (al_ptflags & AL_OBJ_BI_FLAG3) dnp3_append_2item_text(point_item, quality_item, ", Remote Force");
  if (al_ptflags & AL_OBJ_BI_FLAG4) dnp3_append_2item_text(point_item, quality_item, ", Local Force");

  switch (type) {
    case BIN_IN: /* Binary Input Quality flags */
    case DBIN_IN: /* 2 bit Binary Input Quality flags */
      if (al_ptflags & AL_OBJ_BI_FLAG5) dnp3_append_2item_text(point_item, quality_item, ", Chatter Filter");

      hf0 = hf_dnp3_al_biq_b0;
      hf1 = hf_dnp3_al_biq_b1;
      hf2 = hf_dnp3_al_biq_b2;
      hf3 = hf_dnp3_al_biq_b3;
      hf4 = hf_dnp3_al_biq_b4;
      hf5 = hf_dnp3_al_biq_b5;
      if (type == BIN_IN) {
        hf6 = hf_dnp3_al_biq_b6;
        hf7 = hf_dnp3_al_biq_b7;
      }
      else /* MUST be DBIN_IN */ {
        hf6 = hf_dnp3_al_2bit;
      }
      break;

    case BIN_OUT: /* Binary Output Quality flags */
      hf0 = hf_dnp3_al_boq_b0;
      hf1 = hf_dnp3_al_boq_b1;
      hf2 = hf_dnp3_al_boq_b2;
      hf3 = hf_dnp3_al_boq_b3;
      hf4 = hf_dnp3_al_boq_b4;
      hf5 = hf_dnp3_al_boq_b5;
      hf6 = hf_dnp3_al_boq_b6;
      hf7 = hf_dnp3_al_boq_b7;
      break;

    case ANA_IN: /* Analog Input Quality flags */
      if (al_ptflags & AL_OBJ_AI_FLAG5) dnp3_append_2item_text(point_item, quality_item, ", Over-Range");
      if (al_ptflags & AL_OBJ_AI_FLAG6) dnp3_append_2item_text(point_item, quality_item, ", Reference Check");

      hf0 = hf_dnp3_al_aiq_b0;
      hf1 = hf_dnp3_al_aiq_b1;
      hf2 = hf_dnp3_al_aiq_b2;
      hf3 = hf_dnp3_al_aiq_b3;
      hf4 = hf_dnp3_al_aiq_b4;
      hf5 = hf_dnp3_al_aiq_b5;
      hf6 = hf_dnp3_al_aiq_b6;
      hf7 = hf_dnp3_al_aiq_b7;
      break;

    case ANA_OUT: /* Analog Output Quality flags */
      hf0 = hf_dnp3_al_aoq_b0;
      hf1 = hf_dnp3_al_aoq_b1;
      hf2 = hf_dnp3_al_aoq_b2;
      hf3 = hf_dnp3_al_aoq_b3;
      hf4 = hf_dnp3_al_aoq_b4;
      hf5 = hf_dnp3_al_aoq_b5;
      hf6 = hf_dnp3_al_aoq_b6;
      hf7 = hf_dnp3_al_aoq_b7;
      break;

    case COUNTER: /* Counter Quality flags */
      if (al_ptflags & AL_OBJ_CTR_FLAG5) dnp3_append_2item_text(point_item, quality_item, ", Roll-over");
      if (al_ptflags & AL_OBJ_CTR_FLAG6) dnp3_append_2item_text(point_item, quality_item, ", Discontinuity");

      hf0 = hf_dnp3_al_ctrq_b0;
      hf1 = hf_dnp3_al_ctrq_b1;
      hf2 = hf_dnp3_al_ctrq_b2;
      hf3 = hf_dnp3_al_ctrq_b3;
      hf4 = hf_dnp3_al_ctrq_b4;
      hf5 = hf_dnp3_al_ctrq_b5;
      hf6 = hf_dnp3_al_ctrq_b6;
      hf7 = hf_dnp3_al_ctrq_b7;
      break;
  }

  if (quality_tree != NULL) {
    if (hf7) {
      proto_tree_add_item(quality_tree, hf7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(quality_tree, hf6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(quality_tree, hf0, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  }
  proto_item_append_text(point_item, ")");
}

static bool
dnp3_al_empty_obj(uint16_t al_obj)
{

  /* return a true if we expect an empty object (default var, class object, etc) */
  switch (al_obj)
  {
    case AL_OBJ_BI_ALL:      /* Binary Input Default Variation (Obj:01, Var:Default) */
    case AL_OBJ_BIC_ALL:     /* Binary Input Change Default Variation (Obj:02, Var:Default) */
    case AL_OBJ_BOC_ALL:     /* Binary Output Event Default Variation (Obj:11, Var:Default) */
    case AL_OBJ_2BI_ALL:     /* Double-bit Input Default Variation (Obj:03, Var:Default) */
    case AL_OBJ_2BIC_ALL:    /* Double-bit Input Change Default Variation (Obj:04, Var:Default) */
    case AL_OBJ_CTR_ALL:     /* Binary Counter Default Variation (Obj:20, Var:Default) */
    case AL_OBJ_CTRC_ALL:    /* Binary Counter Change Default Variation (Obj:22 Var:Default) */
    case AL_OBJ_AI_ALL:      /* Analog Input Default Variation (Obj:30, Var:Default) */
    case AL_OBJ_AIC_ALL:     /* Analog Input Change Default Variation (Obj:32 Var:Default) */
    case AL_OBJ_AIDB_ALL:    /* Analog Input Deadband Default Variation (Obj:34, Var:Default) */
    case AL_OBJ_AOC_ALL:     /* Analog Output Event Default Variation (Obj:42 Var:Default) */
    case AL_OBJ_CLASS0:      /* Class Data Objects */
    case AL_OBJ_CLASS1:
    case AL_OBJ_CLASS2:
    case AL_OBJ_CLASS3:
      return true;
    default:
      return false;
  }
}

/*****************************************************************/
/*  Desc:    Application Layer Process Object Details            */
/*  Returns: New offset pointer into tvb                         */
/*****************************************************************/
static int
dnp3_al_process_object(tvbuff_t *tvb, packet_info *pinfo, int offset,
                       proto_tree *robj_tree, bool header_only,
                       uint16_t *al_objtype, nstime_t *al_cto)
{

  uint8_t     al_objq, al_objq_prefix, al_objq_range, al_oct_len = 0, bitindex;
  uint16_t    al_obj, temp;
  uint32_t    al_ptaddr = 0;
  int         num_items = 0;
  int         orig_offset, rangebytes = 0;
  proto_item *object_item, *range_item;
  proto_tree *object_tree, *qualifier_tree, *range_tree;
  const char   *sec_stat_str;
  orig_offset = offset;

  /* Application Layer Objects in this Message */
  *al_objtype =
  al_obj = tvb_get_ntohs(tvb, offset);

  /* Special handling for Octet string objects as the variation is the length of the string */
  temp = al_obj & 0xFF00;
  if ((temp == AL_OBJ_OCT) || (temp == AL_OBJ_OCT_EVT )) {
    al_oct_len = al_obj & 0xFF;
    al_obj = temp;
  }

  /* Special handling for Aggressive Mode Requests (Obj:120, Var3) and Message Authentication Codes (Obj:120, Var:9)
     objects that occur in read messages and require full dissection */
  if ((al_obj == AL_OBJ_SA_AUTH_AGMRQ) || (al_obj == AL_OBJ_SA_AUTH_MAC)) {
    header_only = false;
  }

  /* Create Data Objects Detail Tree */
  if (AL_OBJ_GROUP(al_obj) == 0x0) {
    object_item = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
                                             "Object(s): %s (0x%04x)",
                                             val_to_str_ext_const(al_obj, &dnp3_al_obj_vals_ext, "Unknown group 0 Variation"),
                                             al_obj);
    if (try_val_to_str_ext(al_obj, &dnp3_al_obj_vals_ext) == NULL) {
      expert_add_info(pinfo, object_item, &ei_dnp3_unknown_group0_variation);
    }
  }
  else if ((AL_OBJ_GROUP(al_obj) == AL_OBJ_GROUP(AL_OBJ_OCT)) || (AL_OBJ_GROUP(al_obj) == AL_OBJ_GROUP(AL_OBJ_OCT_EVT))) {
    /* For octet strings the variation is the length */
    object_item = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
                                             "Object(s): %s (0x%04x), Length: %d",
                                             val_to_str_ext_const(al_obj, &dnp3_al_obj_vals_ext, "Unknown Object\\Variation"),
                                             al_obj, al_oct_len);
  }
  else {
    object_item = proto_tree_add_uint_format(robj_tree, hf_dnp3_al_obj, tvb, offset, 2, al_obj,
                                             "Object(s): %s (0x%04x)",
                                             val_to_str_ext_const(al_obj, &dnp3_al_obj_vals_ext, "Unknown Object\\Variation"),
                                             al_obj);
    if (try_val_to_str_ext(al_obj, &dnp3_al_obj_vals_ext) == NULL) {
      expert_add_info(pinfo, object_item, &ei_dnp3_unknown_object);
    }
  }
  object_tree = proto_item_add_subtree(object_item, ett_dnp3_al_obj);

  offset += 2;

  /* Object Qualifier */
  al_objq = tvb_get_uint8(tvb, offset);
  al_objq_prefix = al_objq & AL_OBJQ_PREFIX;
  al_objq_prefix = al_objq_prefix >> 4;
  al_objq_range = al_objq & AL_OBJQ_RANGE;

  qualifier_tree = proto_tree_add_subtree_format(object_tree, tvb, offset, 1, ett_dnp3_al_obj_qualifier, NULL,
    "Qualifier Field, Prefix: %s, Range: %s",
    val_to_str_ext_const(al_objq_prefix, &dnp3_al_objq_prefix_vals_ext, "Unknown Prefix Type"),
    val_to_str_ext_const(al_objq_range, &dnp3_al_objq_range_vals_ext, "Unknown Range Type"));
  proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_prefix, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(qualifier_tree, hf_dnp3_al_objq_range, tvb, offset, 1, ENC_BIG_ENDIAN);

  offset += 1;

  /* Create (possibly synthesized) number of items and range field tree */
  range_tree = proto_tree_add_subtree(object_tree, tvb, offset, 0, ett_dnp3_al_obj_range, &range_item, "Number of Items: ");

  switch (al_objq_range)
  {
    case AL_OBJQL_RANGE_SSI8:           /* 8-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_uint8(tvb, offset+1) - tvb_get_uint8(tvb, offset) + 1);
      proto_item_set_generated(range_item);
      al_ptaddr = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop8, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 2;
      break;
    case AL_OBJQL_RANGE_SSI16:          /* 16-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_letohs(tvb, offset+2) - tvb_get_letohs(tvb, (offset)) + 1);
      proto_item_set_generated(range_item);
      al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop16, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
      rangebytes = 4;
      break;
    case AL_OBJQL_RANGE_SSI32:          /* 32-bit Start and Stop Indices in Range Field */
      num_items = ( tvb_get_letohl(tvb, offset+4) - tvb_get_letohl(tvb, offset) + 1);
      proto_item_set_generated(range_item);
      al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_start32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_stop32, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
      rangebytes = 8;
      break;
    case AL_OBJQL_RANGE_AA8:            /* 8-bit Absolute Address in Range Field */
      num_items = 1;
      proto_item_set_generated(range_item);
      al_ptaddr = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 1;
      break;
    case AL_OBJQL_RANGE_AA16:           /* 16-bit Absolute Address in Range Field */
      num_items = 1;
      proto_item_set_generated(range_item);
      al_ptaddr = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      rangebytes = 2;
      break;
    case AL_OBJQL_RANGE_AA32:           /* 32-bit Absolute Address in Range Field */
      num_items = 1;
      proto_item_set_generated(range_item);
      al_ptaddr = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_abs32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      rangebytes = 4;
      break;
    case AL_OBJQL_RANGE_SF8:            /* 8-bit Single Field Quantity in Range Field */
      num_items = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 1;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_RANGE_SF16:           /* 16-bit Single Field Quantity in Range Field */
      num_items = tvb_get_letohs(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      rangebytes = 2;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_RANGE_SF32:           /* 32-bit Single Field Quantity in Range Field */
      num_items = tvb_get_letohl(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      rangebytes = 4;
      proto_item_set_len(range_item, rangebytes);
      break;
    case AL_OBJQL_RANGE_FF:            /* 8 bit object count in Range Field */
      num_items = tvb_get_uint8(tvb, offset);
      proto_tree_add_item(range_tree, hf_dnp3_al_range_quant8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      rangebytes = 1;
      proto_item_set_len(range_item, rangebytes);
  }
  if (num_items > 0) {
    proto_item_append_text(object_item, ", %d point%s", num_items, plurality(num_items, "", "s"));
  }
  proto_item_append_text(range_item, "%d", num_items);

  /* A negative number of items is an error */
  if (num_items < 0) {
    proto_item_append_text(range_item, " (bogus)");
    expert_add_info(pinfo, range_item, &ei_dnp_num_items_neg);
    return tvb_captured_length(tvb);
  }

  /* Move offset past any range field */
  offset += rangebytes;

  bitindex = 0; /* Temp variable for cycling through points when object values are encoded into
                   bits; primarily objects 0x0101, 0x0301 & 0x1001 */

  /* Only process the point information for replies or items with point index lists */
  if (!header_only || al_objq_prefix > 0) {
    int item_num;
    int start_offset;

    start_offset = offset;
    for (item_num = 0; item_num < num_items; item_num++)
    {
      proto_item *point_item;
      proto_tree *point_tree;
      unsigned    data_pos;
      int         prefixbytes;

      /* Create Point item and process prefix */
      if (al_objq_prefix <= AL_OBJQL_PREFIX_4O) {
        point_tree = proto_tree_add_subtree(object_tree, tvb, offset, -1, ett_dnp3_al_obj_point, &point_item, "Point Number");
      }
      else {
        point_tree = proto_tree_add_subtree(object_tree, tvb, offset, -1, ett_dnp3_al_obj_point, &point_item, "Object: Size");
      }

      data_pos   = offset;
      prefixbytes = dnp3_al_obj_procprefix(tvb, offset, al_obj, al_objq_prefix, &al_ptaddr, point_tree);

      /* If this is an 'empty' object type as the num_items field is not equal to zero,
         then the packet is potentially malicious */
      if (dnp3_al_empty_obj(al_obj)) {
        proto_item_append_text(range_item, " (bogus)");
        expert_add_info(pinfo, range_item, &ei_dnp3_num_items_invalid);
        num_items = 0;
      }

      proto_item_append_text(point_item, " %u", al_ptaddr);
      proto_item_set_len(point_item, prefixbytes);
      data_pos += prefixbytes;

      if (!header_only || (AL_OBJQL_PREFIX_1OS <= al_objq_prefix && al_objq_prefix <= AL_OBJQL_PREFIX_4OS)) {
        /* Process the object values */
        uint8_t      al_2bit, al_ptflags, al_bi_val, al_tcc_code, al_sa_mac_len;
        int16_t      al_val_int16;
        uint16_t     al_val_uint16, al_ctlobj_stat;
        uint16_t     al_relms, al_filename_len, al_file_ctrl_mode;
        uint16_t     sa_username_len, sa_challengedata_len, sa_updatekey_len;
        int32_t      al_val_int32;
        uint32_t     al_val_uint32, file_data_size;
        nstime_t     al_reltime, al_abstime;
        bool         al_bit;
        float        al_valflt;
        double       al_valdbl;
        const char *ctl_status_str;

        /* Device Attributes (g0) all have a type code, use that rather than the individual variation */
        if (AL_OBJ_GROUP(al_obj) == 0x0) {
          uint32_t data_type;
          uint8_t da_len;

          /* Add and retrieve the data type */
          proto_tree_add_item_ret_uint(point_tree, hf_dnp3_al_datatype, tvb, data_pos, 1, ENC_LITTLE_ENDIAN, &data_type);
          data_pos++;

          /* If a valid data type process it */
          if (try_val_to_str(data_type, dnp3_al_data_type_vals) != NULL) {
            switch(data_type) {
              case AL_DATA_TYPE_NONE:
                break;
              case AL_DATA_TYPE_VSTR:
                da_len = tvb_get_uint8(tvb, data_pos);
                proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
                data_pos++;
                const uint8_t* da_value;
                proto_tree_add_item_ret_string(point_tree, hf_dnp3_al_da_value, tvb, data_pos, da_len, ENC_ASCII|ENC_NA, pinfo->pool, &da_value);
                proto_item_append_text(object_item, ", Value: %s", da_value);
                data_pos += da_len;
                break;
              case AL_DATA_TYPE_UINT:
                da_len = tvb_get_uint8(tvb, data_pos);
                proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
                data_pos++;
                if (da_len == 1) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_uint8, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %u", tvb_get_uint8(tvb, data_pos));
                  data_pos++;
                }
                else if (da_len == 2) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_uint16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %u", tvb_get_letohs(tvb, data_pos));
                  data_pos += 2;
                }
                else if (da_len == 4) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_uint32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %u", tvb_get_letohl(tvb, data_pos));
                  data_pos += 4;
                }
                break;
              case AL_DATA_TYPE_INT:
                da_len = tvb_get_uint8(tvb, data_pos);
                proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
                data_pos++;
                if (da_len == 1) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_int8, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %d", tvb_get_uint8(tvb, data_pos));
                  data_pos++;
                }
                else if (da_len == 2) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_int16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %d", tvb_get_letohs(tvb, data_pos));
                  data_pos += 2;
                }
                else if (da_len == 4) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_int32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %d", tvb_get_letohl(tvb, data_pos));
                  data_pos += 4;
                }
                break;
              case AL_DATA_TYPE_FLT:
                da_len = tvb_get_uint8(tvb, data_pos);
                proto_tree_add_item(point_tree, hf_dnp3_al_da_length, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
                data_pos++;
                if (da_len == 4) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_flt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %g", tvb_get_letohieee_float(tvb, data_pos));
                  data_pos += 4;
                }
                else if (da_len == 8) {
                  proto_tree_add_item(point_tree, hf_dnp3_al_da_dbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                  proto_item_append_text(object_item, ", Value: %g", tvb_get_letohieee_double(tvb, data_pos));
                  data_pos += 8;
                }
                break;
              case AL_DATA_TYPE_OSTR:
                break;
              case AL_DATA_TYPE_BSTR:
                break;
              case AL_DATA_TYPE_TIME:
                break;
              case AL_DATA_TYPE_UNCD:
                break;
              case AL_DATA_TYPE_U8BS8LIST:
                break;
              case AL_DATA_TYPE_U8BS8EXLIST:
                break;
            }
          }
          offset = data_pos;
        }
        else {

          /* All other objects are handled here, by their variations */
          switch (al_obj)
          {

            /* There is nothing to handle for the default variations */
            case AL_OBJ_BI_ALL:      /* Binary Input Default Variation (Obj:01, Var:Default) */
            case AL_OBJ_BIC_ALL:     /* Binary Input Change Default Variation (Obj:02, Var:Default) */
            case AL_OBJ_BOC_ALL:     /* Binary Output Event Default Variation (Obj:11, Var:Default) */
            case AL_OBJ_2BI_ALL:     /* Double-bit Input Default Variation (Obj:03, Var:Default) */
            case AL_OBJ_2BIC_ALL:    /* Double-bit Input Change Default Variation (Obj:04, Var:Default) */
            case AL_OBJ_CTR_ALL:     /* Binary Counter Default Variation (Obj:20, Var:Default) */
            case AL_OBJ_CTRC_ALL:    /* Binary Counter Change Default Variation (Obj:22 Var:Default) */
            case AL_OBJ_AI_ALL:      /* Analog Input Default Variation (Obj:30, Var:Default) */
            case AL_OBJ_AIC_ALL:     /* Analog Input Change Default Variation (Obj:32 Var:Default) */
            case AL_OBJ_AIDB_ALL:    /* Analog Input Deadband Default Variation (Obj:34, Var:Default) */
            case AL_OBJ_AOC_ALL:     /* Analog Output Event Default Variation (Obj:42 Var:Default) */
            case AL_OBJ_CLASS0:      /* Class Data Objects */
            case AL_OBJ_CLASS1:
            case AL_OBJ_CLASS2:
            case AL_OBJ_CLASS3:

              offset = data_pos;
              break;

            /* Bit-based Data objects here */
            case AL_OBJ_BI_1BIT:    /* Single-Bit Binary Input (Obj:01, Var:01) */
            case AL_OBJ_BO:         /* Binary Output (Obj:10, Var:01) */
            case AL_OBJ_CTL_PMASK:  /* Pattern Mask (Obj:12, Var:03) */
            case AL_OBJ_IIN:        /* Internal Indications - IIN (Obj: 80, Var:01) */

              /* Extract the bit from the packed byte */
              al_bi_val = tvb_get_uint8(tvb, data_pos);
              al_bit = (al_bi_val & 1) > 0;
              if (al_obj == AL_OBJ_IIN) {
                /* For an IIN bit, work out the IIN constant value for the bit position to get the name of the bit */
                uint16_t iin_bit = 0;
                if (al_ptaddr < 8) {
                  iin_bit = 0x100 << al_ptaddr;
                }
                else {
                  iin_bit = 1 << (al_ptaddr - 8);
                }
                proto_item_append_text(point_item, " (%s), Value: %u",
                                       val_to_str_const(iin_bit, dnp3_al_iin_vals, "Invalid IIN bit"), al_bit);
              }
              else
              {
                if (al_objq_prefix != AL_OBJQL_PREFIX_NI) {
                  /* Each item has an index prefix, in this case bump
                     the bitindex to force the correct offset adjustment */
                  bitindex = 7;
                }
                else {
                  /* Regular packed bits, get the value at the appropriate bit index */
                  al_bit = (al_bi_val & (1 << bitindex)) > 0;
                }
                proto_item_append_text(point_item, ", Value: %u", al_bit);
              }
              switch(bitindex) {
              case 0:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit0, tvb, data_pos, 1, al_bi_val);
                break;
              case 1:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit1, tvb, data_pos, 1, al_bi_val);
                break;
              case 2:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit2, tvb, data_pos, 1, al_bi_val);
                break;
              case 3:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit3, tvb, data_pos, 1, al_bi_val);
                break;
              case 4:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit4, tvb, data_pos, 1, al_bi_val);
                break;
              case 5:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit5, tvb, data_pos, 1, al_bi_val);
                break;
              case 6:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit6, tvb, data_pos, 1, al_bi_val);
                break;
              case 7:
                proto_tree_add_boolean(point_tree, hf_dnp3_al_bit7, tvb, data_pos, 1, al_bi_val);
                break;

              default:
                break;
              }
              proto_item_set_len(point_item, prefixbytes + 1);

              /* Increment the bit index for next cycle */
              bitindex++;

              /* If we have counted 8 bits or read the last item,
                 reset bit index and move onto the next byte */
              if ((bitindex > 7) || (item_num == (num_items-1)))
              {
                bitindex = 0;
                offset += (prefixbytes + 1);
              }
              break;

            case AL_OBJ_2BI_NF:    /* Double-bit Input No Flags (Obj:03, Var:01) */

              /* Extract the Double-bit from the packed byte */
              al_bi_val = tvb_get_uint8(tvb, offset);
              al_2bit = ((al_bi_val >> (bitindex << 1)) & 3);

              proto_item_append_text(point_item, ", State: %s", val_to_str_ext(al_2bit, &dnp3_al_dbi_vals_ext, "Unknown double bit state (0x%02x)"));
              switch (bitindex)
              {
              case 0:
                proto_tree_add_uint(point_tree, hf_dnp3_al_2bit0, tvb, offset, 1, al_bi_val);
                break;
              case 1:
                proto_tree_add_uint(point_tree, hf_dnp3_al_2bit1, tvb, offset, 1, al_bi_val);
                break;
              case 2:
                proto_tree_add_uint(point_tree, hf_dnp3_al_2bit2, tvb, offset, 1, al_bi_val);
                break;
              case 3:
                proto_tree_add_uint(point_tree, hf_dnp3_al_2bit3, tvb, offset, 1, al_bi_val);
                break;

              default:
                break;
              }
              proto_item_set_len(point_item, prefixbytes + 1);

              /* Increment the bit index for next cycle */
              bitindex++;

              /* If we have counted 4 double bits or read the last item,
                 reset bit index and move onto the next byte */
              if ((bitindex > 3) || (item_num == (num_items-1)))
              {
                bitindex = 0;
                offset += (prefixbytes + 1);
              }
              break;

            case AL_OBJ_BI_STAT:    /* Binary Input With Status (Obj:01, Var:02) */
            case AL_OBJ_BIC_NOTIME: /* Binary Input Change Without Time (Obj:02, Var:01) */
            case AL_OBJ_BO_STAT:    /* Binary Output Status (Obj:10, Var:02) */
            case AL_OBJ_BOC_NOTIME: /* Binary Output Change Without Time (Obj:11, Var:01) */

              /* Get Point Flags */
              al_ptflags = tvb_get_uint8(tvb, data_pos);

              switch (al_obj) {
                case AL_OBJ_BI_STAT:
                case AL_OBJ_BIC_NOTIME:
                  dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
                  break;
                case AL_OBJ_BO_STAT:
                case AL_OBJ_BOC_NOTIME:
                  dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_OUT);
                  break;
              }
              data_pos += 1;

              al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) > 0;
              proto_item_append_text(point_item, ", Value: %u", al_bit);

              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_2BI_STAT:    /* Double-bit Input With Status (Obj:03, Var:02) */
            case AL_OBJ_2BIC_NOTIME: /* Double-bit Input Change Without Time (Obj:04, Var:01) */

              /* Get Point Flags */
              al_ptflags = tvb_get_uint8(tvb, data_pos);
              dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, DBIN_IN);
              data_pos += 1;

              al_2bit = (al_ptflags >> 6) & 3;
              proto_item_append_text(point_item, ", State: %s", val_to_str_ext(al_2bit, &dnp3_al_dbi_vals_ext, "Unknown double bit state (0x%02x)"));
              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_BIC_TIME:   /* Binary Input Change w/ Time (Obj:02, Var:02)  */
            case AL_OBJ_BOC_TIME:   /* Binary Output Change w/ Time (Obj:11, Var:02)  */

              /* Get Point Flags */
              al_ptflags = tvb_get_uint8(tvb, data_pos);
              switch (al_obj) {
                case AL_OBJ_BIC_TIME:
                  dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
                  break;
                case AL_OBJ_BOC_TIME:
                  dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_OUT);
                  break;
              }
              data_pos += 1;

              /* Get timestamp */
              proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
              data_pos += 6;

              al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) >> 7; /* bit shift 1xxxxxxx -> xxxxxxx1 */
              proto_item_append_text(point_item, ", Value: %u, Timestamp: %s",
                                     al_bit, abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_2BIC_TIME:   /* Double-bit Input Change w/ Time (Obj:04, Var:02)  */

              /* Get Point Flags */
              al_ptflags = tvb_get_uint8(tvb, data_pos);
              dnp3_al_obj_quality(tvb, (offset+prefixbytes), al_ptflags, point_tree, point_item, DBIN_IN);
              data_pos += 1;

              /* Get timestamp */
              proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
              data_pos += 6;

              al_2bit = (al_ptflags >> 6) & 3; /* bit shift 11xxxxxx -> 00000011 */
              proto_item_append_text(point_item, ", State: %s, Timestamp: %s",
                                     val_to_str_ext(al_2bit, &dnp3_al_dbi_vals_ext, "Unknown double bit state (0x%02x)"),
                                     abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_BIC_RTIME:   /* Binary Input Change w/ Relative Time (Obj:02, Var:03)  */
            case AL_OBJ_2BIC_RTIME:  /* Double-bit Input Change w/ Relative Time (Obj:04, Var:03)  */

              /* Get Point Flags */
              al_ptflags = tvb_get_uint8(tvb, data_pos);
              if (al_obj == AL_OBJ_BIC_RTIME) {
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, BIN_IN);
              }
              else /* MUST be AL_OBJ_2BIC_RTIME */ {
                dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, DBIN_IN);
              }
              data_pos += 1;

              /* Get relative time in ms, and convert to ns_time */
              al_relms = tvb_get_letohs(tvb, data_pos);
              al_reltime.secs = al_relms / 1000;
              al_reltime.nsecs = (al_relms % 1000) * 1000000;
              /* Now add to CTO time */
              nstime_sum(&al_abstime, al_cto, &al_reltime);
              proto_tree_add_time(point_tree, hf_dnp3_al_rel_timestamp, tvb, data_pos, 2, &al_reltime);
              data_pos += 2;

              switch (al_obj) {
                case AL_OBJ_BIC_RTIME:
                  al_bit = (al_ptflags & AL_OBJ_BI_FLAG7) >> 7; /* bit shift 1xxxxxxx -> xxxxxxx1 */
                  proto_item_append_text(point_item, ", Value: %u, Timestamp: %s",
                                        al_bit, abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
                  break;
                case AL_OBJ_2BIC_RTIME:
                  al_2bit = (al_ptflags >> 6) & 3; /* bit shift 11xxxxxx -> 00000011 */
                  proto_item_append_text(point_item, ", State: %s, Timestamp: %s",
                                         val_to_str_ext(al_2bit, &dnp3_al_dbi_vals_ext, "Unknown double bit state (0x%02x)"),
                                         abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, FALSE));
                  break;
              }
              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_CTLOP_BLK: /* Control Relay Output Block (Obj:12, Var:01) */
            case AL_OBJ_CTL_PCB: /* Pattern Control Block (Obj:12, Var:02) */
            {
              proto_tree  *tcc_tree;

              /* Add a expand/collapse for TCC */
              al_tcc_code = tvb_get_uint8(tvb, data_pos);
              tcc_tree = proto_tree_add_subtree_format(point_tree, tvb, data_pos, 1,
                          ett_dnp3_al_obj_point_tcc, NULL, "Control Code [0x%02x]",al_tcc_code);

              /* Add the Control Code to the Point number list for quick visual reference as to the operation */
              proto_item_append_text(point_item, " [%s]", val_to_str_const((al_tcc_code & AL_OBJCTLC_CODE),
                                                                           dnp3_al_ctlc_code_vals,
                                                                           "Invalid Operation"));

              /* Add Trip/Close qualifier (if applicable) to previously appended quick visual reference */
              proto_item_append_text(point_item, " [%s]", val_to_str_const((al_tcc_code & AL_OBJCTLC_TC) >> 6,
                                                                           dnp3_al_ctlc_tc_vals,
                                                                           "Invalid Qualifier"));



              /* Control Code 'Operation Type' */
              proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_c, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);

              /* Control Code Misc Values */
              proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_m, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);

              /* Control Code 'Trip Close Code' */
              proto_tree_add_item(tcc_tree, hf_dnp3_ctlobj_code_tc, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Get "Count" Field */
              proto_tree_add_item(point_tree, hf_dnp3_al_count, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Get "On Time" Field */
              proto_tree_add_item(point_tree, hf_dnp3_al_on_time, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* Get "Off Time" Field */
              proto_tree_add_item(point_tree, hf_dnp3_al_off_time, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* Get "Control Status" Field */
              proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;
            }

            case AL_OBJ_BOE_NOTIME: /* Binary Command Event (Obj:13, Var:01) */
            case AL_OBJ_BOE_TIME:   /* Binary Command Event with time (Obj:13, Var:02) */
            case AL_OBJ_AOC_32EVNT:   /* 32-bit Analog Command Event (Obj:43, Var:01) */
            case AL_OBJ_AOC_16EVNT:   /* 16-bit Analog Command Event (Obj:43, Var:02) */
            case AL_OBJ_AOC_32EVTT:   /* 32-bit Analog Command Event with time (Obj:43, Var:03) */
            case AL_OBJ_AOC_16EVTT:   /* 16-bit Analog Command Event with time (Obj:43, Var:04) */
            case AL_OBJ_AOC_FLTEVNT:   /* 32-bit Floating Point Analog Command Event (Obj:43, Var:05) */
            case AL_OBJ_AOC_DBLEVNT:   /* 64-bit Floating Point Analog Command Event (Obj:43, Var:06) */
            case AL_OBJ_AOC_FLTEVTT:   /* 32-bit Floating Point Analog Command Event with time (Obj:43, Var:07) */
            case AL_OBJ_AOC_DBLEVTT:   /* 64-bit Floating Point Analog Command Event with time (Obj:43, Var:08) */
            {
              /* Get the status code */
              al_ctlobj_stat = tvb_get_uint8(tvb, data_pos) & AL_OBJCTL_STATUS_MASK;
              ctl_status_str = val_to_str_ext(al_ctlobj_stat, &dnp3_al_ctl_status_vals_ext, "Invalid Status (0x%02x)");
              proto_item_append_text(point_item, " [Status: %s (0x%02x)]", ctl_status_str, al_ctlobj_stat);
              proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);

              /* Get the command value */
              switch(al_obj)
              {
                case AL_OBJ_BOE_NOTIME:
                case AL_OBJ_BOE_TIME:
                  proto_tree_add_item(point_tree, hf_dnp3_bocs_bit, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
                  data_pos += 1;
                  break;
                case AL_OBJ_AOC_32EVNT:
                case AL_OBJ_AOC_32EVTT:
                  data_pos += 1; /* Step past status */
                  al_val_int32 = tvb_get_letohl(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int32);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  break;
                case AL_OBJ_AOC_16EVNT:
                case AL_OBJ_AOC_16EVTT:
                  data_pos += 1; /* Step past status */
                  al_val_int16 = tvb_get_letohs(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int16);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                  data_pos += 2;
                  break;
                case AL_OBJ_AOC_FLTEVNT:
                case AL_OBJ_AOC_FLTEVTT:
                  data_pos += 1; /* Step past status */
                  al_valflt = tvb_get_letohieee_float(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valflt);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;
                case AL_OBJ_AOC_DBLEVNT:
                case AL_OBJ_AOC_DBLEVTT:
                  data_pos += 1; /* Step past status */
                  al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valdbl);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                  data_pos += 8;
                  break;
              }

              /* Get the timestamp */
              switch(al_obj)
              {
                case AL_OBJ_BOE_TIME:   /* Binary Command Event with time (Obj:13, Var:02) */
                case AL_OBJ_AOC_32EVTT:   /* 32-bit Analog Command Event with time (Obj:43, Var:03) */
                case AL_OBJ_AOC_16EVTT:   /* 16-bit Analog Command Event with time (Obj:43, Var:04) */
                case AL_OBJ_AOC_FLTEVTT:   /* 32-bit Floating Point Analog Command Event with time (Obj:43, Var:07) */
                case AL_OBJ_AOC_DBLEVTT:   /* 64-bit Floating Point Analog Command Event with time (Obj:43, Var:08) */
                  proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
                  proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
                  data_pos += 6;
                break;
              }

              proto_item_set_len(point_item, data_pos - offset);
              offset = data_pos;
              break;
            }

            case AL_OBJ_AO_32OPB:   /* 32-Bit Analog Output Block (Obj:41, Var:01) */
            case AL_OBJ_AO_16OPB:   /* 16-Bit Analog Output Block (Obj:41, Var:02) */
            case AL_OBJ_AO_FLTOPB:  /* 32-Bit Floating Point Output Block (Obj:41, Var:03) */
            case AL_OBJ_AO_DBLOPB:  /* 64-Bit Floating Point Output Block (Obj:41, Var:04) */

              switch (al_obj)
              {
                case AL_OBJ_AO_32OPB:
                  al_val_int32 = tvb_get_letohl(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int32);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;
                case AL_OBJ_AO_16OPB:
                  al_val_int16 = tvb_get_letohs(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int16);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                  data_pos += 2;
                  break;
                case AL_OBJ_AO_FLTOPB:
                  al_valflt = tvb_get_letohieee_float(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valflt);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;
                case AL_OBJ_AO_DBLOPB:
                  al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valdbl);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                  data_pos += 8;
                  break;
              }

              /* Get control status */
              al_ctlobj_stat = tvb_get_uint8(tvb, data_pos) & AL_OBJCTL_STATUS_MASK;
              ctl_status_str = val_to_str_ext(al_ctlobj_stat, &dnp3_al_ctl_status_vals_ext, "Invalid Status (0x%02x)");
              proto_item_append_text(point_item, " [Status: %s (0x%02x)]", ctl_status_str, al_ctlobj_stat);
              proto_tree_add_item(point_tree, hf_dnp3_al_ctrlstatus, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_CTR_32:     /* 32-Bit Binary Counter (Obj:20, Var:01) */
            case AL_OBJ_CTR_16:     /* 16-Bit Binary Counter (Obj:20, Var:02) */
            case AL_OBJ_DCTR_32:    /* 32-Bit Binary Delta Counter (Obj:20, Var:03) */
            case AL_OBJ_DCTR_16:    /* 16-Bit Binary Delta Counter (Obj:20, Var:04) */
            case AL_OBJ_CTR_32NF:   /* 32-Bit Binary Counter Without Flag (Obj:20, Var:05) */
            case AL_OBJ_CTR_16NF:   /* 16-Bit Binary Counter Without Flag (Obj:20, Var:06) */
            case AL_OBJ_DCTR_32NF:  /* 32-Bit Binary Delta Counter Without Flag (Obj:20, Var:07) */
            case AL_OBJ_DCTR_16NF:  /* 16-Bit Binary Delta Counter Without Flag (Obj:20, Var:08) */
            case AL_OBJ_FCTR_32:    /* 32-Bit Frozen Counter (Obj:21, Var:01) */
            case AL_OBJ_FCTR_16:    /* 16-Bit Frozen Counter (Obj:21, Var:02) */
            case AL_OBJ_FDCTR_32:   /* 21 03 32-Bit Frozen Delta Counter */
            case AL_OBJ_FDCTR_16:   /* 21 04 16-Bit Frozen Delta Counter */
            case AL_OBJ_FCTR_32T:   /* 32-Bit Frozen Counter w/ Time of Freeze (Obj:21 Var:05 ) */
            case AL_OBJ_FCTR_16T:   /* 16-Bit Frozen Counter w/ Time of Freeze (Obj:21 Var:06) */
            case AL_OBJ_FDCTR_32T:  /* 32-Bit Frozen Delta Counter w/ Time of Freeze (Obj:21 Var:07) */
            case AL_OBJ_FDCTR_16T:  /* 16-Bit Frozen Delta Counter w/ Time of Freeze (Obj:21 Var:08) */
            case AL_OBJ_FCTR_32NF:  /* 32-Bit Frozen Counter Without Flag (Obj:21 Var:09) */
            case AL_OBJ_FCTR_16NF:  /* 16-Bit Frozen Counter Without Flag (Obj:21 Var:10) */
            case AL_OBJ_FDCTR_32NF: /* 32-Bit Frozen Delta Counter Without Flag (Obj:21 Var:11) */
            case AL_OBJ_FDCTR_16NF: /* 16-Bit Frozen Delta Counter Without Flag (Obj:21 Var:12) */
            case AL_OBJ_CTRC_32:    /* 32-Bit Counter Change Event w/o Time (Obj:22, Var:01) */
            case AL_OBJ_CTRC_16:    /* 16-Bit Counter Change Event w/o Time (Obj:22, Var:02) */
            case AL_OBJ_DCTRC_32:   /* 32-Bit Delta Counter Change Event w/o Time (Obj:22, Var:03) */
            case AL_OBJ_DCTRC_16:   /* 16-Bit Delta Counter Change Event w/o Time (Obj:22, Var:04) */
            case AL_OBJ_CTRC_32T:   /* 32-Bit Counter Change Event with Time (Obj:22, Var:05) */
            case AL_OBJ_CTRC_16T:   /* 16-Bit Counter Change Event with Time (Obj:22, Var:06) */
            case AL_OBJ_DCTRC_32T:  /* 32-Bit Delta Counter Change Event with Time (Obj:22, Var:07) */
            case AL_OBJ_DCTRC_16T:  /* 16-Bit Delta Counter Change Event with Time (Obj:22, Var:08) */
            case AL_OBJ_FCTRC_32:   /* 32-Bit Frozen Counter Change Event (Obj:23 Var:01) */
            case AL_OBJ_FCTRC_16:   /* 16-Bit Frozen Counter Change Event (Obj:23 Var:02) */
            case AL_OBJ_FDCTRC_32:  /* 32-Bit Frozen Delta Counter Change Event (Obj:23 Var:03) */
            case AL_OBJ_FDCTRC_16:  /* 16-Bit Frozen Delta Counter Change Event (Obj:23 Var:04) */
            case AL_OBJ_FCTRC_32T:  /* 32-Bit Frozen Counter Change Event w/ Time of Freeze (Obj:23 Var:05) */
            case AL_OBJ_FCTRC_16T:  /* 16-Bit Frozen Counter Change Event w/ Time of Freeze (Obj:23 Var:06) */
            case AL_OBJ_FDCTRC_32T: /* 32-Bit Frozen Delta Counter Change Event w/ Time of Freeze (Obj:23 Var:07) */
            case AL_OBJ_FDCTRC_16T: /* 16-Bit Frozen Delta Counter Change Event w/ Time of Freeze (Obj:23 Var:08) */

              /* Get Point Flags for those types that have them, it's easier to block out those that don't have flags */
              switch (al_obj)
              {
                case AL_OBJ_CTR_32NF:
                case AL_OBJ_CTR_16NF:
                case AL_OBJ_DCTR_32NF:
                case AL_OBJ_DCTR_16NF:
                case AL_OBJ_FCTR_32NF:
                case AL_OBJ_FCTR_16NF:
                case AL_OBJ_FDCTR_32NF:
                case AL_OBJ_FDCTR_16NF:
                  break;

                default:
                  al_ptflags = tvb_get_uint8(tvb, data_pos);
                  dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, COUNTER);
                  data_pos += 1;
                  break;
              }

              /* Get Counter values */
              switch (al_obj)
              {
                case AL_OBJ_CTR_32:
                case AL_OBJ_DCTR_32:
                case AL_OBJ_CTR_32NF:
                case AL_OBJ_DCTR_32NF:
                case AL_OBJ_FCTR_32:
                case AL_OBJ_FDCTR_32:
                case AL_OBJ_FCTR_32T:
                case AL_OBJ_FDCTR_32T:
                case AL_OBJ_FCTR_32NF:
                case AL_OBJ_FDCTR_32NF:
                case AL_OBJ_CTRC_32:
                case AL_OBJ_DCTRC_32:
                case AL_OBJ_CTRC_32T:
                case AL_OBJ_DCTRC_32T:
                case AL_OBJ_FCTRC_32:
                case AL_OBJ_FDCTRC_32:
                case AL_OBJ_FCTRC_32T:
                case AL_OBJ_FDCTRC_32T:

                  al_val_uint32 = tvb_get_letohl(tvb, data_pos);
                  proto_item_append_text(point_item, ", Count: %u", al_val_uint32);
                  proto_tree_add_item(point_tree, hf_dnp3_al_cnt32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;

                case AL_OBJ_CTR_16:
                case AL_OBJ_DCTR_16:
                case AL_OBJ_CTR_16NF:
                case AL_OBJ_DCTR_16NF:
                case AL_OBJ_FCTR_16:
                case AL_OBJ_FDCTR_16:
                case AL_OBJ_FCTR_16T:
                case AL_OBJ_FDCTR_16T:
                case AL_OBJ_FCTR_16NF:
                case AL_OBJ_FDCTR_16NF:
                case AL_OBJ_CTRC_16:
                case AL_OBJ_DCTRC_16:
                case AL_OBJ_CTRC_16T:
                case AL_OBJ_DCTRC_16T:
                case AL_OBJ_FCTRC_16:
                case AL_OBJ_FDCTRC_16:
                case AL_OBJ_FCTRC_16T:
                case AL_OBJ_FDCTRC_16T:

                  al_val_uint16 = tvb_get_letohs(tvb, data_pos);
                  proto_item_append_text(point_item, ", Count: %u", al_val_uint16);
                  proto_tree_add_item(point_tree, hf_dnp3_al_cnt16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                  data_pos += 2;
                  break;
              }

              /* Get the time for those points that have it */
              switch (al_obj)
              {
                case AL_OBJ_FCTR_32T:
                case AL_OBJ_FCTR_16T:
                case AL_OBJ_FDCTR_32T:
                case AL_OBJ_FDCTR_16T:
                case AL_OBJ_CTRC_32T:
                case AL_OBJ_CTRC_16T:
                case AL_OBJ_DCTRC_32T:
                case AL_OBJ_DCTRC_16T:
                case AL_OBJ_FCTRC_32T:
                case AL_OBJ_FCTRC_16T:
                case AL_OBJ_FDCTRC_32T:
                case AL_OBJ_FDCTRC_16T:
                  proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
                  proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
                  data_pos += 6;
                  break;
              }

              proto_item_set_len(point_item, data_pos - offset);
              offset = data_pos;
              break;

            case AL_OBJ_AI_32:        /* 32-Bit Analog Input (Obj:30, Var:01) */
            case AL_OBJ_AI_16:        /* 16-Bit Analog Input (Obj:30, Var:02) */
            case AL_OBJ_AI_32NF:      /* 32-Bit Analog Input Without Flag (Obj:30, Var:03) */
            case AL_OBJ_AI_16NF:      /* 16-Bit Analog Input Without Flag (Obj:30, Var:04) */
            case AL_OBJ_AI_FLT:       /* 32-Bit Floating Point Input (Obj:30, Var:05) */
            case AL_OBJ_AI_DBL:       /* 64-Bit Floating Point Input (Obj:30, Var:06) */
            case AL_OBJ_AIF_32:       /* 32-Bit Frozen Analog Input (Obj:31, Var:01) */
            case AL_OBJ_AIF_16:       /* 16-Bit Frozen Analog Input (Obj:31, Var:02) */
            case AL_OBJ_AIF_32TOF:    /* 32-Bit Frozen Analog Input w/ Time of Freeze (Obj:31, Var:03) */
            case AL_OBJ_AIF_16TOF:    /* 16-Bit Frozen Analog Input w/ Time of Freeze (Obj:31, Var:04) */
            case AL_OBJ_AIF_32NF:     /* 32-Bit Frozen Analog Input Without Flag (Obj:31, Var:05) */
            case AL_OBJ_AIF_16NF:     /* 16-Bit Frozen Analog Input Without Flag (Obj:31, Var:06) */
            case AL_OBJ_AIF_FLT:      /* 32-Bit Frozen Floating Point Input (Obj:31, Var:07) */
            case AL_OBJ_AIF_DBL:      /* 64-Bit Frozen Floating Point Input (Obj:31, Var:08) */
            case AL_OBJ_AIC_32NT:     /* 32-Bit Analog Change Event w/o Time (Obj:32, Var:01) */
            case AL_OBJ_AIC_16NT:     /* 16-Bit Analog Change Event w/o Time (Obj:32, Var:02) */
            case AL_OBJ_AIC_32T:      /* 32-Bit Analog Change Event with Time (Obj:32, Var:03) */
            case AL_OBJ_AIC_16T:      /* 16-Bit Analog Change Event with Time (Obj:32, Var:04) */
            case AL_OBJ_AIC_FLTNT:    /* 32-Bit Floating Point Change Event w/o Time (Obj:32, Var:05) */
            case AL_OBJ_AIC_DBLNT:    /* 64-Bit Floating Point Change Event w/o Time (Obj:32, Var:06) */
            case AL_OBJ_AIC_FLTT:     /* 32-Bit Floating Point Change Event w/ Time (Obj:32, Var:07) */
            case AL_OBJ_AIC_DBLT:     /* 64-Bit Floating Point Change Event w/ Time (Obj:32, Var:08) */
            case AL_OBJ_AIFC_32NT:    /* 32-Bit Frozen Analog Event w/o Time (Obj:33, Var:01) */
            case AL_OBJ_AIFC_16NT:    /* 16-Bit Frozen Analog Event w/o Time (Obj:33, Var:02) */
            case AL_OBJ_AIFC_32T:     /* 32-Bit Frozen Analog Event w/ Time (Obj:33, Var:03) */
            case AL_OBJ_AIFC_16T:     /* 16-Bit Frozen Analog Event w/ Time (Obj:33, Var:04) */
            case AL_OBJ_AIFC_FLTNT:   /* 32-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:05) */
            case AL_OBJ_AIFC_DBLNT:   /* 64-Bit Floating Point Frozen Change Event w/o Time (Obj:33, Var:06) */
            case AL_OBJ_AIFC_FLTT:    /* 32-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:07) */
            case AL_OBJ_AIFC_DBLT:    /* 64-Bit Floating Point Frozen Change Event w/ Time (Obj:33, Var:08) */
            case AL_OBJ_AIDB_16:      /* 16-Bit Analog Input Deadband (Obj:34, Var:01) */
            case AL_OBJ_AIDB_32:      /* 32-Bit Analog Input Deadband (Obj:34, Var:02) */
            case AL_OBJ_AIDB_FLT:     /* 32-Bit Floating Point Analog Input Deadband (Obj:34, Var:03) */

              /* Get Point Flags for those types that have them */
              switch (al_obj)
              {
                case AL_OBJ_AI_32NF:
                case AL_OBJ_AI_16NF:
                case AL_OBJ_AIF_32NF:
                case AL_OBJ_AIF_16NF:
                case AL_OBJ_AIDB_16:
                case AL_OBJ_AIDB_32:
                case AL_OBJ_AIDB_FLT:
                  break;

                default:
                  al_ptflags = tvb_get_uint8(tvb, data_pos);
                  dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, ANA_IN);
                  data_pos += 1;
                  break;
              }

              switch (al_obj)
              {
                case AL_OBJ_AI_32:
                case AL_OBJ_AI_32NF:
                case AL_OBJ_AIF_32:
                case AL_OBJ_AIF_32TOF:
                case AL_OBJ_AIF_32NF:
                case AL_OBJ_AIC_32NT:
                case AL_OBJ_AIC_32T:
                case AL_OBJ_AIFC_32NT:
                case AL_OBJ_AIFC_32T:
                case AL_OBJ_AIDB_32:

                  al_val_int32 = tvb_get_letohl(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int32);
                  proto_tree_add_item(point_tree, hf_dnp3_al_ana32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;

                case AL_OBJ_AI_16:
                case AL_OBJ_AI_16NF:
                case AL_OBJ_AIF_16:
                case AL_OBJ_AIF_16TOF:
                case AL_OBJ_AIF_16NF:
                case AL_OBJ_AIC_16NT:
                case AL_OBJ_AIC_16T:
                case AL_OBJ_AIFC_16NT:
                case AL_OBJ_AIFC_16T:
                case AL_OBJ_AIDB_16:

                  al_val_int16 = tvb_get_letohs(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int16);
                  proto_tree_add_item(point_tree, hf_dnp3_al_ana16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                  data_pos += 2;
                  break;

                case AL_OBJ_AI_FLT:
                case AL_OBJ_AIF_FLT:
                case AL_OBJ_AIC_FLTNT:
                case AL_OBJ_AIC_FLTT:
                case AL_OBJ_AIFC_FLTNT:
                case AL_OBJ_AIFC_FLTT:
                case AL_OBJ_AIDB_FLT:

                  al_valflt = tvb_get_letohieee_float(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valflt);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;

                case AL_OBJ_AI_DBL:
                case AL_OBJ_AIF_DBL:
                case AL_OBJ_AIC_DBLNT:
                case AL_OBJ_AIC_DBLT:
                case AL_OBJ_AIFC_DBLNT:
                case AL_OBJ_AIFC_DBLT:

                  al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valdbl);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anadbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                  data_pos += 8;
                  break;
              }

              /* Get timestamp */
              switch (al_obj)
              {
                case AL_OBJ_AIC_32T:
                case AL_OBJ_AIC_16T:
                case AL_OBJ_AIC_FLTT:
                case AL_OBJ_AIC_DBLT:
                case AL_OBJ_AIFC_32T:
                case AL_OBJ_AIFC_16T:
                case AL_OBJ_AIFC_FLTT:
                case AL_OBJ_AIFC_DBLT:

                  proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
                  proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
                  data_pos += 6;
                  break;

                case AL_OBJ_AIF_32TOF:
                case AL_OBJ_AIF_16TOF:

                  proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
                  proto_item_append_text(point_item, ", Time of Freeze: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
                  data_pos += 6;
                  break;
              }

              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_AO_32:     /* 32-Bit Analog Output Status (Obj:40, Var:01) */
            case AL_OBJ_AO_16:     /* 16-Bit Analog Output Status (Obj:40, Var:02) */
            case AL_OBJ_AO_FLT:    /* 32-Bit Floating Point Output Status (Obj:40, Var:03) */
            case AL_OBJ_AO_DBL:    /* 64-Bit Floating Point Output Status (Obj:40, Var:04) */
            case AL_OBJ_AOC_32NT:  /* 32-Bit Analog Output Event w/o Time (Obj:42, Var:01) */
            case AL_OBJ_AOC_16NT:  /* 16-Bit Analog Output Event w/o Time (Obj:42, Var:02) */
            case AL_OBJ_AOC_32T:   /* 32-Bit Analog Output Event with Time (Obj:42, Var:03) */
            case AL_OBJ_AOC_16T:   /* 16-Bit Analog Output Event with Time (Obj:42, Var:04) */
            case AL_OBJ_AOC_FLTNT: /* 32-Bit Floating Point Output Event w/o Time (Obj:42, Var:05) */
            case AL_OBJ_AOC_DBLNT: /* 64-Bit Floating Point Output Event w/o Time (Obj:42, Var:06) */
            case AL_OBJ_AOC_FLTT:  /* 32-Bit Floating Point Output Event w/ Time (Obj:42, Var:07) */
            case AL_OBJ_AOC_DBLT:  /* 64-Bit Floating Point Output Event w/ Time (Obj:42, Var:08) */

              /* Get Point Flags */
              al_ptflags = tvb_get_uint8(tvb, data_pos);
              dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, ANA_OUT);
              data_pos += 1;

              switch (al_obj)
              {
                case AL_OBJ_AO_32:     /* 32-Bit Analog Output Status (Obj:40, Var:01) */
                case AL_OBJ_AOC_32NT:  /* 32-Bit Analog Output Event w/o Time (Obj:42, Var:01) */
                case AL_OBJ_AOC_32T:   /* 32-Bit Analog Output Event with Time (Obj:42, Var:03) */

                  al_val_int32 = tvb_get_letohl(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int32);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaout32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;

                case AL_OBJ_AO_16:     /* 16-Bit Analog Output Status (Obj:40, Var:02) */
                case AL_OBJ_AOC_16NT:  /* 16-Bit Analog Output Event w/o Time (Obj:42, Var:02) */
                case AL_OBJ_AOC_16T:   /* 16-Bit Analog Output Event with Time (Obj:42, Var:04) */

                  al_val_int16 = tvb_get_letohs(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %d", al_val_int16);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaout16, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
                  data_pos += 2;
                  break;

                case AL_OBJ_AO_FLT:     /* 32-Bit Floating Point Output Status (Obj:40, Var:03) */
                case AL_OBJ_AOC_FLTNT:  /* 32-Bit Floating Point Output Event w/o Time (Obj:42, Var:05) */
                case AL_OBJ_AOC_FLTT:   /* 32-Bit Floating Point Output Event w/ Time (Obj:42, Var:07) */

                  al_valflt = tvb_get_letohieee_float(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valflt);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaoutflt, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
                  data_pos += 4;
                  break;

                case AL_OBJ_AO_DBL:     /* 64-Bit Floating Point Output Status (Obj:40, Var:04) */
                case AL_OBJ_AOC_DBLNT:  /* 64-Bit Floating Point Output Event w/o Time (Obj:42, Var:06) */
                case AL_OBJ_AOC_DBLT:   /* 64-Bit Floating Point Output Event w/ Time (Obj:42, Var:08) */

                  al_valdbl = tvb_get_letohieee_double(tvb, data_pos);
                  proto_item_append_text(point_item, ", Value: %g", al_valdbl);
                  proto_tree_add_item(point_tree, hf_dnp3_al_anaoutdbl, tvb, data_pos, 8, ENC_LITTLE_ENDIAN);
                  data_pos += 8;
                  break;
              }

              /* Get timestamp */
              switch (al_obj)
              {
                case AL_OBJ_AOC_32T:
                case AL_OBJ_AOC_16T:
                case AL_OBJ_AOC_FLTT:
                case AL_OBJ_AOC_DBLT:
                  proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
                  proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
                  data_pos += 6;
                  break;
              }

              proto_item_set_len(point_item, data_pos - offset);
              offset = data_pos;
              break;

            case AL_OBJ_TD:     /* Time and Date (Obj:50, Var:01) */
            case AL_OBJ_TDR:    /* Time and Date at Last Recorded Time (Obj:50, Var:03) */
            case AL_OBJ_TDCTO:  /* Time and Date CTO (Obj:51, Var:01) */
            case AL_OBJ_UTDCTO: /* Unsynchronized Time and Date CTO (Obj:51, Var:02) */

              proto_tree_add_time_item(object_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
              data_pos += 6;
              proto_item_set_len(point_item, data_pos - offset);

              if (al_obj == AL_OBJ_TDCTO) {
                /* Copy the time object to the CTO for any other relative time objects in this response */
                nstime_copy(al_cto, &al_abstime);
              }

              offset = data_pos;
              break;

            case AL_OBJ_TDELAYF: /* Time Delay - Fine (Obj:52, Var:02) */

              proto_tree_add_item(object_tree, hf_dnp3_al_time_delay, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;
              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_FILE_CMD: /* File Control - File Command (Obj:70, Var:03) */
              /* File name offset and length */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_string_offset, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;
              al_filename_len = tvb_get_letohs(tvb, data_pos);
              proto_tree_add_item(point_tree, hf_dnp3_al_file_string_length, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Grab the mode as it determines if some of the following fields are relevant */
              al_file_ctrl_mode = tvb_get_letohs(tvb, data_pos + 16);

              /* Creation Time */
              if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE) {
                proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
              }
              data_pos += 6;

              /* Perms */
              if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE) {
                proto_item *perms_item;
                proto_tree *perms_tree;

                perms_item = proto_tree_add_item(point_tree, hf_dnp3_al_file_perms, tvb, offset, 2, ENC_LITTLE_ENDIAN);

                perms_tree = proto_item_add_subtree(perms_item, ett_dnp3_al_obj_point_perms);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_owner,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_owner, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_owner,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_group,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_group, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_group,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_read_world,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_write_world, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(perms_tree, hf_dnp3_al_file_perms_exec_world,  tvb, offset, 2, ENC_LITTLE_ENDIAN);
              }
              data_pos += 2;

              /* Auth Key */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_auth, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* File Size */
              if (al_file_ctrl_mode == AL_OBJ_FILE_MODE_WRITE || al_file_ctrl_mode == AL_OBJ_FILE_MODE_APPEND) {
                proto_tree_add_item(point_tree, hf_dnp3_al_file_size, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              }
              data_pos += 4; //-V525

              /* Mode */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_mode, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Max Block Size */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_maxblk, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Request ID */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_reqID, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Filename */
              if (al_filename_len > 0) {
                proto_tree_add_item(point_tree, hf_dnp3_al_file_name, tvb, data_pos, al_filename_len, ENC_ASCII);
              }
              data_pos += al_filename_len;
              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_FILE_STAT: /* File Control - File Status (Obj:70, Var:04) */

              /* File Handle */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* File Size */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_size,   tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* Max Block Size */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_maxblk, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Request ID */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_reqID,  tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Status code */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_status, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Optional text */
              file_data_size = al_ptaddr - (data_pos - offset - prefixbytes);
              if ((file_data_size) > 0) {
                proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
                data_pos += file_data_size;
              }

              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_FILE_TRANS: /* File Control - File Transport (Obj:70, Var:05) */

              /* File Handle */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* File block (bits 0 - 30) and last block flag (bit 31) */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_blocknum,  tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(point_tree, hf_dnp3_al_file_lastblock, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* File data */
              file_data_size = al_ptaddr - (data_pos - offset - prefixbytes);
              if ((file_data_size) > 0) {
                proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
                data_pos += file_data_size;
              }

              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_FILE_TRAN_ST: /* File Control Tansport Status (Obj:70, Var:06) */

              /* File Handle */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_handle, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* File block (bits 0 - 30) and last block flag (bit 31) */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_blocknum,  tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              proto_tree_add_item(point_tree, hf_dnp3_al_file_lastblock, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* Status code */
              proto_tree_add_item(point_tree, hf_dnp3_al_file_status, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Optional text */
              file_data_size = al_ptaddr - (data_pos - offset - prefixbytes);
              if ((file_data_size) > 0) {
                proto_tree_add_item(point_tree, hf_dnp3_al_file_data, tvb, data_pos, file_data_size, ENC_NA);
                data_pos += file_data_size;
              }

              proto_item_set_len(point_item, data_pos - offset);

              offset = data_pos;
              break;

            case AL_OBJ_OCT:      /* Octet string */
            case AL_OBJ_OCT_EVT:  /* Octet string event */

              /* read the number of bytes defined by the variation */
              if (al_oct_len > 0) {
                proto_tree_add_item(object_tree, hf_dnp3_al_octet_string, tvb, data_pos, al_oct_len, ENC_NA);
                data_pos += al_oct_len;
                proto_item_set_len(point_item, data_pos - offset);
              }

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_CH:    /* Authentication Challenge (Obj:120, Var:01) */

              /* Challenge Sequence Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_csq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* MAC Algorithm */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_mal, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Reason for Challenge */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_rfc, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Challenge Data */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, (al_ptaddr-8), ENC_NA);
              data_pos += (al_ptaddr-8);

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_RP:    /* Authentication Reply (Obj:120, Var:02) */

              /* Challenge Sequence Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_csq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* MAC Value */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_mac, tvb, data_pos, (al_ptaddr-6), ENC_NA);
              data_pos += (al_ptaddr-6);

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_AGMRQ:    /* Authentication Aggressive Mode Request (Obj:120, Var:03) */

              /* Challenge Sequence Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_csq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_SKSR:    /* Authentication Session Key Status Request (Obj:120, Var:04) */

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_SKS:    /* Authentication Session Key Status (Obj:120, Var:05) */

              /* Key Change Sequence Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_ksq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Key Wrap Algorithm */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_kwa, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Key Status */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_ks, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* MAC Algorithm */
              /* Use the MAC Algorithm to determine the length of the MAC Value */
              temp = tvb_get_uint8(tvb, data_pos);
              switch (temp) {
                  case 1:
                    al_sa_mac_len = 4;
                    break;
                  case 2:
                    al_sa_mac_len = 10;
                    break;
                  case 3:
                  case 5:
                    al_sa_mac_len = 8;
                    break;
                  case 4:
                    al_sa_mac_len = 16;
                    break;
                  case 6:
                    al_sa_mac_len = 12;
                    break;
                  default:
                    al_sa_mac_len = 0;
                    break;
              }
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_mal, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Challenge Data Length */
              al_val_uint16 = tvb_get_letohs(tvb, data_pos);
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_cdl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Challenge Data */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, al_val_uint16, ENC_NA);
              data_pos += al_val_uint16;

              /* MAC Value */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_mac, tvb, data_pos, al_sa_mac_len, ENC_NA);
              data_pos += al_sa_mac_len;

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_SKC:    /* Authentication Session Key Change (Obj:120, Var:06) */

              /* Key Change Sequence Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_ksq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Key Data */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_key, tvb, data_pos, (al_ptaddr-6), ENC_NA);
              data_pos += (al_ptaddr-6);

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_ERR:    /* Authentication Error (Obj:120, Var:07) */

              /* Sequence Number - Can be Challenge or Key Change */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_seq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Association ID */
              proto_tree_add_item(point_tree, hf_dnp3_al_sa_assoc_id, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Error Code */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_err, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* Error Timestamp */
              proto_tree_add_time_item(object_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
              data_pos += 6;

              /* Error Text */
              /* Optional footer for any remaining data */

              offset = data_pos;
              break;


            case AL_OBJ_SA_AUTH_MAC:    /* Authentication Message Authentication Code (Obj:120, Var:09) */
            case AL_OBJ_SA_AUTH_UKCC:   /* Authentication Update Key Change Confirmation (Obj:120, Var:15) */

              /* MAC Value */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_mac, tvb, data_pos, al_ptaddr, ENC_NA);
              data_pos += al_ptaddr;

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_UKCR:    /* Authentication Update Key Change Request (Obj:120, Var:11) */

              /* Key Change Method */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_kcm, tvb, data_pos, 1, ENC_LITTLE_ENDIAN);
              data_pos += 1;

              /* User Name Length */
              sa_username_len = tvb_get_letohs(tvb, data_pos);
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usrnl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Challenge Data Length */
              sa_challengedata_len = tvb_get_letohs(tvb, data_pos);
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_cdl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* User Name */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usrn, tvb, data_pos, sa_username_len, ENC_ASCII);
              data_pos += sa_username_len;

              /* Challenge Data */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, sa_challengedata_len, ENC_NA);
              data_pos += sa_challengedata_len;

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_UKCRP:    /* Authentication Update Key Change Reply (Obj:120, Var:12) */

              /* Sequence Number - Can be Challenge or Key Change */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_seq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Challenge Data Length */
              sa_challengedata_len = tvb_get_letohs(tvb, data_pos);
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_cdl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Challenge Data */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_cd, tvb, data_pos, sa_challengedata_len, ENC_NA);
              data_pos += sa_challengedata_len;

              offset = data_pos;
              break;

            case AL_OBJ_SA_AUTH_UKC:    /* Authentication Update Key Change (Obj:120, Var:13) */

              /* Sequence Number - Can be Challenge or Key Change */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_seq, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              /* User Number */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_usr, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Encrypted Update Key Length */
              sa_updatekey_len = tvb_get_letohs(tvb, data_pos);
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_ukl, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* Encrypted Update Key Data */
              proto_tree_add_item(object_tree, hf_dnp3_al_sa_uk, tvb, data_pos, sa_updatekey_len, ENC_NA);
              data_pos += sa_updatekey_len;

              offset = data_pos;
              break;

            case AL_OBJ_SA_SECSTAT:     /* Security Statistics (Obj:121, Var:01) */
            case AL_OBJ_SA_SECSTATEVT:  /* Security Statistic Event (Obj:122, Var:01) */
            case AL_OBJ_SA_SECSTATEVTT: /* Security Statistic Event w/ Time (Obj:122, Var:02) */

              /* Security Statistic Description */
              sec_stat_str = val_to_str_ext(al_ptaddr, &dnp3_al_sa_secstat_vals_ext, "Unknown statistic (%u)");
              proto_item_append_text(point_item, " %s", sec_stat_str);

              /* Quality Flags */
              al_ptflags = tvb_get_uint8(tvb, data_pos);
              dnp3_al_obj_quality(tvb, data_pos, al_ptflags, point_tree, point_item, COUNTER);
              data_pos += 1;

              /* Association ID */
              al_val_uint16 = tvb_get_letohs(tvb, data_pos);
              proto_item_append_text(point_item, ", Association ID: %u", al_val_uint16);
              proto_tree_add_item(point_tree, hf_dnp3_al_sa_assoc_id, tvb, data_pos, 2, ENC_LITTLE_ENDIAN);
              data_pos += 2;

              /* 32-bit Count Value */
              al_val_uint32 = tvb_get_letohl(tvb, data_pos);
              proto_item_append_text(point_item, ", Count: %u", al_val_uint32);
              proto_tree_add_item(point_tree, hf_dnp3_al_cnt32, tvb, data_pos, 4, ENC_LITTLE_ENDIAN);
              data_pos += 4;

              if (al_obj == AL_OBJ_SA_SECSTATEVTT) {
                proto_tree_add_time_item(point_tree, hf_dnp3_al_timestamp, tvb, data_pos, 6, ENC_TIME_MSECS|ENC_LITTLE_ENDIAN, &al_abstime, NULL, NULL);
                proto_item_append_text(point_item, ", Timestamp: %s", abs_time_to_str(pinfo->pool, &al_abstime, ABSOLUTE_TIME_UTC, false));
                data_pos += 6;
              }

              offset = data_pos;
              break;

            default:             /* In case of unknown object */

              proto_tree_add_item(object_tree, hf_dnp3_unknown_data_chunk, tvb, offset, -1, ENC_NA);
              offset = tvb_captured_length(tvb); /* Finish decoding if unknown object is encountered... */
              break;
          }
        }

        /* And increment the point address, may be overwritten by an index value */
        al_ptaddr++;
      }
      else {
        /* No objects, just prefixes, move past prefix values */
        offset = data_pos;
      }
      if (start_offset > offset) {
        expert_add_info(pinfo, point_item, &ei_dnp_invalid_length);
        offset = tvb_captured_length(tvb); /* Finish decoding if unknown object is encountered... */
      }
    }
  }
  proto_item_set_len(object_item, offset - orig_offset);

  return offset;
}

/*****************************************************************/
/* Application Layer Dissector */
/*****************************************************************/
static int
dissect_dnp3_al(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  uint8_t       al_ctl, al_seq, al_func, al_class = 0, i;
  uint16_t      bytes, obj_type = 0;
  unsigned      data_len = 0, offset = 0;
  proto_item   *ti, *tc;
  proto_tree   *al_tree, *robj_tree;
  const char   *func_code_str, *obj_type_str;
  nstime_t      al_cto;
  static int * const control_flags[] = {
    &hf_dnp3_al_fir,
    &hf_dnp3_al_fin,
    &hf_dnp3_al_con,
    &hf_dnp3_al_uns,
    &hf_dnp3_al_seq,
    NULL
  };

  nstime_set_zero (&al_cto);

  data_len = tvb_captured_length(tvb);

  /* Handle the control byte and function code */
  al_ctl = tvb_get_uint8(tvb, offset);
  al_seq = al_ctl & DNP3_AL_SEQ;
  al_func = tvb_get_uint8(tvb, (offset+1));
  func_code_str = val_to_str_ext(al_func, &dnp3_al_func_vals_ext, "Unknown function (0x%02x)");

  /* Clear out lower layer info */
  col_clear(pinfo->cinfo, COL_INFO);
  col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, func_code_str);
  col_set_fence(pinfo->cinfo, COL_INFO);

  /* format up the text representation */
  al_tree = proto_tree_add_subtree(tree, tvb, offset, data_len, ett_dnp3_al, &ti, "Application Layer: (");
  if (al_ctl & DNP3_AL_FIR)  proto_item_append_text(ti, "FIR, ");
  if (al_ctl & DNP3_AL_FIN)  proto_item_append_text(ti, "FIN, ");
  if (al_ctl & DNP3_AL_CON)  proto_item_append_text(ti, "CON, ");
  if (al_ctl & DNP3_AL_UNS)  proto_item_append_text(ti, "UNS, ");
  proto_item_append_text(ti, "Sequence %u, %s)", al_seq, func_code_str);

  /* Application Layer control byte subtree */
  tc = proto_tree_add_bitmask(al_tree, tvb, offset, hf_dnp3_al_ctl, ett_dnp3_al_ctl, control_flags, ENC_BIG_ENDIAN);
  proto_item_append_text(tc, "(");
  if (al_ctl & DNP3_AL_FIR)  proto_item_append_text(tc, "FIR, ");
  if (al_ctl & DNP3_AL_FIN)  proto_item_append_text(tc, "FIN, ");
  if (al_ctl & DNP3_AL_CON)  proto_item_append_text(tc, "CON, ");
  if (al_ctl & DNP3_AL_UNS)  proto_item_append_text(tc, "UNS, ");
  proto_item_append_text(tc, "Sequence %u)", al_seq);
  offset += 1;

#if 0
  /* If this packet is NOT the final Application Layer Message, exit and continue
     processing the remaining data in the fragment. */
  if (!(al_ctl & DNP3_AL_FIN)) {
    t_robj = proto_tree_add_expert(al_tree, pinfo, &ei_dnp3_buffering_user_data_until_final_frame_is_received, tvb, offset, -1);
    return 1;
  }
#endif

  /* Application Layer Function Code Byte  */
  proto_tree_add_uint_format(al_tree, hf_dnp3_al_func, tvb, offset, 1, al_func,
    "Function Code: %s (0x%02x)", func_code_str, al_func);
  offset += 1;

  switch (al_func)
  {
    case AL_FUNC_CONFIRM:     /* Confirm Function Code 0x00 */

      /* If the application layer data is longer than two bytes in length it may have SA objects appended to it */
      if (data_len > 2) {

        /* Create Confirm Data Objects Tree */
        robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "CONFIRM Data Objects");

        /* Process Data Object Details */
        while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
          offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, true, &obj_type, &al_cto);
        }
      }
      break;

    case AL_FUNC_READ:     /* Read Function Code 0x01 */

      /* Create Read Request Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "READ Request Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, true, &obj_type, &al_cto);

        /* Update class type for each object that was a class read */
        switch(obj_type) {
          case AL_OBJ_CLASS0:
          case AL_OBJ_CLASS1:
          case AL_OBJ_CLASS2:
          case AL_OBJ_CLASS3:
            al_class |= (1 << ((obj_type & 0x0f) - 1));
            break;
          default:
            /* For reads for specific object types, bit-mask out the first byte and add the generic obj description to the column info */
            obj_type_str = val_to_str_ext_const((obj_type & 0xFF00), &dnp3_al_read_obj_vals_ext, "Unknown Object Type");
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, obj_type_str);
            break;
        }

      }

      /* Update the col info if there were class reads */
      if (al_class != 0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Class ");
        for (i = 0; i < 4; i++) {
          if (al_class & (1 << i)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%u", i);
          }
        }
      }

      break;

    case AL_FUNC_WRITE:     /* Write Function Code 0x02 */

      /* Create Write Request Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "WRITE Request Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);

        /* For writes for specific object types, bit-mask out the first byte and add the generic obj description to the column info */
        obj_type_str = val_to_str_ext_const((obj_type & 0xFF00), &dnp3_al_write_obj_vals_ext, "Unknown Object Type");
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, obj_type_str);

      }

      break;

    case AL_FUNC_SELECT:     /* Select Function Code 0x03 */

      /* Create Select Request Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "SELECT Request Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_OPERATE:    /* Operate Function Code 0x04 */
      /* Functionally identical to 'SELECT' Function Code */

      /* Create Operate Request Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "OPERATE Request Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_DIROP:        /* Direct Operate Function Code 0x05 */
    case AL_FUNC_DIROPNACK:    /* Direct Operate No ACK Function Code 0x06 */
      /* Functionally identical to 'SELECT' Function Code */

      /* Create Direct Operate Request Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "DIRECT OPERATE Request Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_FRZ:        /* Immediate Freeze Function Code 0x07 */
    case AL_FUNC_FRZNACK:    /* Immediate Freeze No ACK Function Code 0x08 */
    case AL_FUNC_FRZCLR:     /* Freeze and Clear Function Code 0x09 */
    case AL_FUNC_FRZCLRNACK: /* Freeze and Clear No ACK Function Code 0x0A */

      /* Create Freeze Request Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Freeze Request Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, true, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_ENSPMSG:   /* Enable Spontaneous Messages Function Code 0x14 */

      /* Create Enable Spontaneous Messages Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Enable Spontaneous Msg's Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_DISSPMSG:   /* Disable Spontaneous Messages Function Code 0x15 */

      /* Create Disable Spontaneous Messages Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Disable Spontaneous Msg's Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_DELAYMST:  /* Delay Measurement Function Code 0x17 */

      break;

    case AL_FUNC_OPENFILE:        /* Open File Function Code 0x19 */
    case AL_FUNC_CLOSEFILE:       /* Close File Function Code 0x1A */
    case AL_FUNC_DELETEFILE:      /* Delete File Function Code 0x1B */

      /* Create File Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "File Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_AUTHREQ:     /* Authentication Request Function Code 0x20 */
    case AL_FUNC_AUTHERR:     /* Authentication Error Function Code 0x21 */


      /* Create Authentication Request Data Objects Tree */
      robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "Authentication Request Data Objects");

      /* Process Data Object Details */
      while (offset <= (data_len-2))  {  /* 2 octet object code + CRC32 */
        offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
      }

      break;

    case AL_FUNC_RESPON:   /* Response Function Code 0x81 */
    case AL_FUNC_UNSOLI:   /* Unsolicited Response Function Code 0x82 */
    case AL_FUNC_AUTHRESP: /* Authentication Response Function Code 0x83 */

      /* Application Layer IIN bits req'd if message is a response */
      dnp3_al_process_iin(tvb, pinfo, offset, al_tree);
      offset += 2;

      /* Ensure there is actual data remaining in the message.
         A response will not contain data following the IIN bits,
         if there is none available */
      bytes = tvb_reported_length_remaining(tvb, offset);
      if (bytes > 0)
      {
        /* Create Response Data Objects Tree */
        robj_tree = proto_tree_add_subtree(al_tree, tvb, offset, -1, ett_dnp3_al_objdet, NULL, "RESPONSE Data Objects");

        /* Process Data Object Details */
        while (offset <= (data_len-2)) {  /* 2 octet object code + CRC32 */
          offset = dnp3_al_process_object(tvb, pinfo, offset, robj_tree, false, &obj_type, &al_cto);
        }

        break;
      }

    default:    /* Unknown Function */

      break;
  }

  return 0;
}

/*****************************************************************/
/* Data Link and Transport layer dissector */
/*****************************************************************/
static int
dissect_dnp3_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item  *ti, *tdl, *tc, *hidden_item;
  proto_tree  *dnp3_tree, *dl_tree, *field_tree;
  int          offset = 0, temp_offset = 0;
  bool         dl_prm;
  uint8_t      dl_len, dl_ctl, dl_func;
  const char *func_code_str;
  uint16_t     dl_dst, dl_src, calc_dl_crc;

  /* Make entries in Protocol column and Info column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "DNP 3.0");
  col_clear(pinfo->cinfo, COL_INFO);

  /* Skip "0x0564" header bytes */
  temp_offset += 2;

  dl_len = tvb_get_uint8(tvb, temp_offset);
  temp_offset += 1;

  dl_ctl = tvb_get_uint8(tvb, temp_offset);
  temp_offset += 1;

  dl_dst = tvb_get_letohs(tvb, temp_offset);
  temp_offset += 2;

  dl_src = tvb_get_letohs(tvb, temp_offset);

  dl_func = dl_ctl & DNP3_CTL_FUNC;
  dl_prm = dl_ctl & DNP3_CTL_PRM;
  func_code_str = val_to_str(dl_func, dl_prm ? dnp3_ctl_func_pri_vals : dnp3_ctl_func_sec_vals,
           "Unknown function (0x%02x)");

  /* Make sure source and dest are always in the info column. This might not
   * be the first DL segment (PDU) in the frame so add a separator. */
  col_append_sep_fstr(pinfo->cinfo, COL_INFO, "; ", "%u " UTF8_RIGHTWARDS_ARROW " %u", dl_src, dl_dst);
  col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "len=%u, %s", dl_len, func_code_str);

  /* create display subtree for the protocol */
  ti = proto_tree_add_item(tree, proto_dnp3, tvb, offset, -1, ENC_NA);
  dnp3_tree = proto_item_add_subtree(ti, ett_dnp3);

  /* Create Subtree for Data Link Layer */
  dl_tree = proto_tree_add_subtree_format(dnp3_tree, tvb, offset, DNP_HDR_LEN, ett_dnp3_dl, &tdl,
        "Data Link Layer, Len: %u, From: %u, To: %u, ", dl_len, dl_src, dl_dst);
  if (dl_prm) {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tdl, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tdl, "PRM, ");
    if (dl_ctl & DNP3_CTL_FCB) proto_item_append_text(tdl, "FCB, ");
    if (dl_ctl & DNP3_CTL_FCV) proto_item_append_text(tdl, "FCV, ");
  }
  else {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tdl, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tdl, "PRM, ");
    if (dl_ctl & DNP3_CTL_RES) proto_item_append_text(tdl, "RES, ");
    if (dl_ctl & DNP3_CTL_DFC) proto_item_append_text(tdl, "DFC, ");
  }
  proto_item_append_text(tdl, "%s", func_code_str);

  /* start bytes */
  proto_tree_add_item(dl_tree, hf_dnp3_start, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  /* add length field */
  proto_tree_add_item(dl_tree, hf_dnp3_len, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* Add Control Byte Subtree */
  tc = proto_tree_add_uint_format_value(dl_tree, hf_dnp3_ctl, tvb, offset, 1, dl_ctl,
          "0x%02x (", dl_ctl);
  /* Add Text to Control Byte Subtree Header */
  if (dl_prm) {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tc, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tc, "PRM, ");
    if (dl_ctl & DNP3_CTL_FCB) proto_item_append_text(tc, "FCB, ");
    if (dl_ctl & DNP3_CTL_FCV) proto_item_append_text(tc, "FCV, ");
  }
  else {
    if (dl_ctl & DNP3_CTL_DIR) proto_item_append_text(tc, "DIR, ");
    if (dl_ctl & DNP3_CTL_PRM) proto_item_append_text(tc, "PRM, ");
    if (dl_ctl & DNP3_CTL_RES) proto_item_append_text(tc, "RES, ");
    if (dl_ctl & DNP3_CTL_DFC) proto_item_append_text(tc, "DFC, ");
  }
  proto_item_append_text(tc, "%s)", func_code_str );
  field_tree = proto_item_add_subtree(tc, ett_dnp3_dl_ctl);

  /* Add Control Byte Subtree Items */
  if (dl_prm) {
    proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_fcb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_fcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_prifunc, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
  else {
    proto_tree_add_item(field_tree, hf_dnp3_ctl_dir, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_dfc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(field_tree, hf_dnp3_ctl_secfunc, tvb, offset, 1, ENC_BIG_ENDIAN);
  }
    offset += 1;

  /* add destination and source addresses */
  /* XXX - We could create AT_NUMERIC (or a newly registered address type)
   * addressses from these, either just for a conversation table or even
   * to set pinfo->src / dst. */
  proto_tree_add_item(dl_tree, hf_dnp3_dst, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  hidden_item = proto_tree_add_item(dl_tree, hf_dnp3_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_item_set_hidden(hidden_item);
  offset += 2;
  proto_tree_add_item(dl_tree, hf_dnp3_src, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  hidden_item = proto_tree_add_item(dl_tree, hf_dnp3_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
  proto_item_set_hidden(hidden_item);
  offset += 2;

  dnp3_packet_info_t* dnp3_info = wmem_new0(pinfo->pool, dnp3_packet_info_t);
  dnp3_info->dl_src = dl_src;
  dnp3_info->dl_dst = dl_dst;
  dnp3_info->msg_len = dl_len;

  tap_queue_packet(dnp3_tap, pinfo, dnp3_info);

  /* and header CRC */
  calc_dl_crc = calculateCRCtvb(tvb, 0, DNP_HDR_LEN - 2);
  proto_tree_add_checksum(dl_tree, tvb, offset, hf_dnp3_data_hdr_crc,
                          hf_dnp3_data_hdr_crc_status, &ei_dnp3_data_hdr_crc_incorrect,
                          pinfo, calc_dl_crc, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
  offset += 2;

  /* If the DataLink function is 'Request Link Status' or 'Status of Link',
     or 'Reset Link' we don't expect any Transport or Application Layer Data
     NOTE: This code should probably check what DOES have TR or AL data */
  if ((dl_func != DL_FUNC_LINK_STAT) && (dl_func != DL_FUNC_STAT_LINK) &&
      (dl_func != DL_FUNC_RESET_LINK) && (dl_func != DL_FUNC_ACK)) //-V560 (both codes are the same value but semantically different)
  {
    proto_tree *data_tree;
    proto_item *data_ti;
    uint8_t     tr_ctl, tr_seq;
    bool        tr_fir, tr_fin;
    uint8_t    *al_buffer, *al_buffer_ptr;
    uint8_t     data_len;
    int         data_start = offset;
    int         tl_offset;
    bool        crc_OK = false;
    tvbuff_t   *next_tvb = NULL;
    unsigned    i;
    uint32_t    ext_seq;
    static int * const transport_flags[] = {
      &hf_dnp3_tr_fin,
      &hf_dnp3_tr_fir,
      &hf_dnp3_tr_seq,
      NULL
    };

    /* get the transport layer byte */
    tr_ctl = tvb_get_uint8(tvb, offset);
    tr_seq = tr_ctl & DNP3_TR_SEQ;
    tr_fir = tr_ctl & DNP3_TR_FIR;
    tr_fin = tr_ctl & DNP3_TR_FIN;

    if (!PINFO_FD_VISITED(pinfo)) {
      /* create a unidirectional conversation. Use the addresses (IP currently)
       * as the reassembly functions use that anyway, and the DNP3.0 DL
       * addresses but intentionally NOT the TCP or UDP ports. */
      conversation_element_t* conv_key = wmem_alloc_array(pinfo->pool, conversation_element_t, 5);
      conv_key[0].type = CE_ADDRESS;
      copy_address_shallow(&(conv_key[0].addr_val), &pinfo->src);
      conv_key[1].type = CE_ADDRESS;
      copy_address_shallow(&(conv_key[1].addr_val), &pinfo->dst);
      conv_key[2].type = CE_UINT;
      conv_key[2].port_val = dl_src;
      conv_key[3].type = CE_UINT;
      conv_key[3].uint_val = dl_dst;
      conv_key[4].type = CE_CONVERSATION_TYPE;
      conv_key[4].conversation_type_val = CONVERSATION_DNP3;
      conversation_t* conv = find_conversation_full(pinfo->num, conv_key);
      uint32_t prev;
      if (conv) {
        prev = GPOINTER_TO_UINT(conversation_get_proto_data(conv, proto_dnp3));
      } else {
        prev = tr_seq;
        conv = conversation_new_full(pinfo->num, conv_key);
      }
      ext_seq = calculate_extended_seqno(prev, tr_seq, tr_fir);
      /* The only thing we store right now is the 32 bit extended sequence
       * number, so we don't need a conversation_data type. */
      conversation_add_proto_data(conv, proto_dnp3, GUINT_TO_POINTER(ext_seq));
      p_add_proto_data(wmem_file_scope(), pinfo, proto_dnp3, tr_seq, GUINT_TO_POINTER(ext_seq));
    } else {
      ext_seq = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo, proto_dnp3, tr_seq));
    }

    /* Add Transport Layer Tree */
    tc = proto_tree_add_bitmask(dnp3_tree, tvb, offset, hf_dnp3_tr_ctl, ett_dnp3_tr_ctl, transport_flags, ENC_BIG_ENDIAN);
    proto_item_append_text(tc, "(");
    if (tr_fir) proto_item_append_text(tc, "FIR, ");
    if (tr_fin) proto_item_append_text(tc, "FIN, ");
    proto_item_append_text(tc, "Sequence %u)", tr_seq);

    /* Add data chunk tree */
    data_tree = proto_tree_add_subtree(dnp3_tree, tvb, offset, -1, ett_dnp3_dl_data, &data_ti, "Data Chunks");

    /* extract the application layer data, validating the CRCs */

    /* XXX - check for dl_len <= 5 */
    data_len = dl_len - 5;
    al_buffer = (uint8_t *)wmem_alloc(pinfo->pool, data_len);
    al_buffer_ptr = al_buffer;
    i = 0;
    tl_offset = 1;  /* skip the initial transport layer byte when assembling chunks for the application layer tvb */
    while (data_len > 0)
    {
      uint8_t       chk_size;
      const uint8_t *chk_ptr;
      proto_tree   *chk_tree;
      proto_item   *chk_len_ti;
      uint16_t      calc_crc, act_crc;

      chk_size = MIN(data_len, AL_MAX_CHUNK_SIZE);
      chk_ptr  = tvb_get_ptr(tvb, offset, chk_size);
      memcpy(al_buffer_ptr, chk_ptr + tl_offset, chk_size - tl_offset);
      al_buffer_ptr += chk_size - tl_offset;

      chk_tree = proto_tree_add_subtree_format(data_tree, tvb, offset, chk_size + 2, ett_dnp3_dl_chunk, NULL, "Data Chunk: %u", i);
      proto_tree_add_item(chk_tree, hf_dnp3_data_chunk, tvb, offset, chk_size, ENC_NA);
      chk_len_ti = proto_tree_add_uint(chk_tree, hf_dnp3_data_chunk_len, tvb, offset, 0, chk_size);
      proto_item_set_generated(chk_len_ti);

      offset  += chk_size;

      calc_crc = calculateCRC(chk_ptr, chk_size);
      proto_tree_add_checksum(chk_tree, tvb, offset, hf_dnp3_data_chunk_crc,
                              hf_dnp3_data_chunk_crc_status, &ei_dnp3_data_chunk_crc_incorrect,
                              pinfo, calc_crc, ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
      act_crc  = tvb_get_letohs(tvb, offset);
      offset  += 2;
      crc_OK   = calc_crc == act_crc;
      if (!crc_OK)
      {
        /* Don't trust the rest of the data, get out of here */
        break;
      }
      data_len -= chk_size;
      i++;
      tl_offset = 0;  /* copy all the data in the rest of the chunks */
    }
    proto_item_set_len(data_ti, offset - data_start);

    /* if crc OK, set up new tvb */
    if (crc_OK)
    {
      tvbuff_t *al_tvb;
      bool      save_fragmented;

      al_tvb = tvb_new_child_real_data(tvb, al_buffer, (unsigned) (al_buffer_ptr-al_buffer), (int) (al_buffer_ptr-al_buffer));

      /* Check for fragmented packet */
      save_fragmented = pinfo->fragmented;

      /* Reassemble AL fragments */
      static unsigned al_max_fragments = 60; /* In practice 9 - 2048 (AL) / 249 (AL Fragment) */
      fragment_head *frag_al = NULL;
      pinfo->fragmented = true;
      if (!pinfo->fd->visited)
      {
        frag_al = fragment_add_seq_single(&al_reassembly_table,
            al_tvb, 0, pinfo, ext_seq, NULL,
            tvb_reported_length(al_tvb), /* As this is a constructed tvb, all of it is ok */
            tr_fir, tr_fin,
            al_max_fragments);
      }
      else
      {
        frag_al = fragment_get_reassembled_id(&al_reassembly_table, pinfo, ext_seq);
      }

      if (frag_al)
      {
        /* Check the FIN bit because the DNP3 dissector is only called once
         * and so the curr_layer_num check in processed_reassembled_data
         * does not help for multiple messages in one frame. */
        if (tr_fin) {
          next_tvb = process_reassembled_data(al_tvb, 0, pinfo,
            "Reassembled DNP 3.0 Application Layer message", frag_al, &dnp3_frag_items,
            NULL, dnp3_tree);
        }
        if (next_tvb) {
          /* next_tvb should be non-NULL if this is a FIN and we reassembled,
           * but check for bugs caused by non-standard fragmentation methods
           * (#20336).  */
          /* As a complete AL message will have cleared the info column,
             make sure source and dest are always in the info column */
          //col_append_fstr(pinfo->cinfo, COL_INFO, "from %u to %u", dl_src, dl_dst);
          //col_set_fence(pinfo->cinfo, COL_INFO);
          dissect_dnp3_al(next_tvb, pinfo, dnp3_tree);
        }
        else
        {
          proto_tree_add_uint(dnp3_tree, hf_dnp3_fragment_reassembled_in, tvb, 0, 0,
            frag_al->reassembled_in);
          /* Lock any column info set by the DL and TL */
          col_set_fence(pinfo->cinfo, COL_INFO);
          col_append_fstr(pinfo->cinfo, COL_INFO,
              " (Application Layer fragment %u, reassembled in packet %u)",
              tr_seq, frag_al->reassembled_in);
          proto_tree_add_item(dnp3_tree, hf_al_frag_data, al_tvb, 0, -1, ENC_NA);
        }
      }
      else
      {
        col_append_fstr(pinfo->cinfo, COL_INFO,
            " (Application Layer Unreassembled fragment %u)",
            tr_seq);
        proto_tree_add_item(dnp3_tree, hf_al_frag_data, al_tvb, 0, -1, ENC_NA);
      }

      pinfo->fragmented = save_fragmented;
    }
    else
    {
      /* CRC error - throw away the data. */
      wmem_free(pinfo->pool, al_buffer);
      next_tvb = NULL;
    }
  }

  /* Set the length of the message */
  proto_item_set_len(ti, offset);
  return offset;
}

static bool
check_dnp3_header(tvbuff_t *tvb, bool dnp3_heuristics)
{
  /* Assume the CRC will be bad */
  bool goodCRC = false;

  /* How big is the actual buffer */
  int length = tvb_captured_length(tvb);

  /* Calculate the header CRC if the bytes are available */
  if (length >= DNP_HDR_LEN) {
    uint16_t calc_crc = calculateCRCtvb(tvb, 0, DNP_HDR_LEN - 2);
    goodCRC = (calc_crc == tvb_get_letohs(tvb, 8));
  }

  /* For a heuristic match we must have at least a header, beginning with 0x0564
     and a valid header CRC */
  if (dnp3_heuristics) {
    if ( !goodCRC || (tvb_get_ntohs(tvb, 0) != 0x0564)) {
      return false;
    }
  }
  else {
    /* For a non-heuristic match, at least the first byte is 0x05 and if available
       the second byte is 64 and if available the CRC is valid */
    if (tvb_get_uint8(tvb, 0) != 0x05) {
      return false;
    }
    if ((length > 1) && (tvb_get_uint8(tvb, 1) != 0x64)) {
      return false;
    }
    if ((length >= DNP_HDR_LEN) && !goodCRC) {
      return false;
    }
  }
  return true;
}

static unsigned
get_dnp3_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                     int offset, void *data _U_)
{
  uint16_t message_len;  /* need 16 bits as total can exceed 255 */
  uint16_t data_crc;     /* No. of user data CRC bytes */

  message_len = tvb_get_uint8(tvb, offset + 2);

  /* Add in 2 bytes for header start octets,
            1 byte for len itself,
            2 bytes for header CRC
            data CRC bytes (2 bytes per 16 bytes of data
  */

  data_crc = (uint16_t)(ceil((message_len - 5) / 16.0)) * 2;
  message_len += 2 + 1 + 2 + data_crc;
  return message_len;
}

static int
dissect_dnp3_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  if (!check_dnp3_header(tvb, false)) {
    return 0;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, true, DNP_HDR_LEN,
                   get_dnp3_message_len, dissect_dnp3_message, data);

  return tvb_captured_length(tvb);
}

static bool
dissect_dnp3_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  if (!check_dnp3_header(tvb, true)) {
    return false;
  }

  tcp_dissect_pdus(tvb, pinfo, tree, true, DNP_HDR_LEN,
                   get_dnp3_message_len, dissect_dnp3_message, data);

  return true;
}

static bool
dnp3_udp_check_header(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    return check_dnp3_header(tvb, false);
}

static bool
dnp3_udp_check_header_heur(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{
    return check_dnp3_header(tvb, true);
}

static int
dissect_dnp3_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  return udp_dissect_pdus(tvb, pinfo, tree, DNP_HDR_LEN, dnp3_udp_check_header,
                   get_dnp3_message_len, dissect_dnp3_message, data);
}

static bool
dissect_dnp3_udp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  return (udp_dissect_pdus(tvb, pinfo, tree, DNP_HDR_LEN, dnp3_udp_check_header_heur,
                   get_dnp3_message_len, dissect_dnp3_message, data) != 0);

}

/* Register the protocol with Wireshark */

void
proto_register_dnp3(void)
{

/* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_dnp3_start,
      { "Start Bytes", "dnp3.start",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_len,
      { "Length", "dnp3.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Frame Data Length", HFILL }
    },

    { &hf_dnp3_ctl,
      { "Control", "dnp3.ctl",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Frame Control Byte", HFILL }
    },

    { &hf_dnp3_ctl_prifunc,
      { "Control Function Code", "dnp3.ctl.prifunc",
        FT_UINT8, BASE_DEC, VALS(dnp3_ctl_func_pri_vals), DNP3_CTL_FUNC,
        "Frame Control Function Code", HFILL }
    },

    { &hf_dnp3_ctl_secfunc,
      { "Control Function Code", "dnp3.ctl.secfunc",
        FT_UINT8, BASE_DEC, VALS(dnp3_ctl_func_sec_vals), DNP3_CTL_FUNC,
        "Frame Control Function Code", HFILL }
    },

    { &hf_dnp3_ctlobj_code_c,
      { "Operation Type", "dnp3.ctl.op",
        FT_UINT8, BASE_DEC, VALS(dnp3_al_ctlc_code_vals), AL_OBJCTLC_CODE,
        "Control Code, Operation Type", HFILL }
    },

    { &hf_dnp3_ctlobj_code_m,
      { "Queue / Clear Field", "dnp3.ctl.clr",
        FT_UINT8, BASE_DEC, VALS(dnp3_al_ctlc_misc_vals), AL_OBJCTLC_MISC,
        "Control Code, Clear Field", HFILL }
    },

    { &hf_dnp3_ctlobj_code_tc,
      { "Trip Control Code", "dnp3.ctl.trip",
        FT_UINT8, BASE_DEC, VALS(dnp3_al_ctlc_tc_vals), AL_OBJCTLC_TC,
        "Control Code, Trip Close Control", HFILL }
    },

    { &hf_dnp3_ctl_dir,
      { "Direction", "dnp3.ctl.dir",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_DIR,
        NULL, HFILL }
    },

    { &hf_dnp3_ctl_prm,
      { "Primary", "dnp3.ctl.prm",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_PRM,
        NULL, HFILL }
    },

    { &hf_dnp3_ctl_fcb,
      { "Frame Count Bit", "dnp3.ctl.fcb",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_FCB,
        NULL, HFILL }
    },

    { &hf_dnp3_ctl_fcv,
      { "Frame Count Valid", "dnp3.ctl.fcv",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_FCV,
        NULL, HFILL }
    },

    { &hf_dnp3_ctl_dfc,
      { "Data Flow Control", "dnp3.ctl.dfc",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_CTL_DFC,
        NULL, HFILL }
    },

    { &hf_dnp3_dst,
      { "Destination", "dnp3.dst",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Destination Address", HFILL }
    },

    { &hf_dnp3_src,
      { "Source", "dnp3.src",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Source Address", HFILL }
    },

    { &hf_dnp3_addr,
      { "Address", "dnp3.addr",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Source or Destination Address", HFILL }
    },

    { &hf_dnp3_data_hdr_crc,
      { "Data Link Header checksum", "dnp3.hdr.CRC",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_data_hdr_crc_status,
        { "Data Link Header Checksum Status", "dnp.hdr.CRC.status",
        FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_tr_ctl,
      { "Transport Control", "dnp3.tr.ctl",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Transport Layer Control Byte", HFILL }
    },

    { &hf_dnp3_tr_fin,
      { "Final", "dnp3.tr.fin",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_TR_FIN,
        NULL, HFILL }
    },

    { &hf_dnp3_tr_fir,
      { "First", "dnp3.tr.fir",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_TR_FIR,
        NULL, HFILL }
    },

    { &hf_dnp3_tr_seq,
      { "Sequence", "dnp3.tr.seq",
        FT_UINT8, BASE_DEC, NULL, DNP3_TR_SEQ,
        "Frame Sequence Number", HFILL }
    },

    { &hf_dnp3_data_chunk,
      { "Data Chunk", "dnp.data_chunk",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_data_chunk_len,
      { "Data Chunk length", "dnp.data_chunk_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_data_chunk_crc,
      { "Data Chunk checksum", "dnp.data_chunk.CRC",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_data_chunk_crc_status,
        { "Data Chunk Checksum Status", "dnp.data_chunk.CRC.status",
        FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_al_ctl,
      { "Application Control", "dnp3.al.ctl",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "Application Layer Control Byte", HFILL }
    },

    { &hf_dnp3_al_fir,
      { "First", "dnp3.al.fir",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_FIR,
        NULL, HFILL }
    },

    { &hf_dnp3_al_fin,
      { "Final", "dnp3.al.fin",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_FIN,
        NULL, HFILL }
    },

    { &hf_dnp3_al_con,
      { "Confirm", "dnp3.al.con",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_CON,
        NULL, HFILL }
    },

    { &hf_dnp3_al_uns,
      { "Unsolicited", "dnp3.al.uns",
        FT_BOOLEAN, 8, TFS(&tfs_set_notset), DNP3_AL_UNS,
        NULL, HFILL }
    },

    { &hf_dnp3_al_seq,
      { "Sequence", "dnp3.al.seq",
        FT_UINT8, BASE_DEC, NULL, DNP3_AL_SEQ,
        "Frame Sequence Number", HFILL }
    },

    { &hf_dnp3_al_func,
      { "Application Layer Function Code", "dnp3.al.func",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_func_vals_ext, DNP3_AL_FUNC,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin,
      { "Internal Indications", "dnp3.al.iin",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "Application Layer IIN", HFILL }
    },

    { &hf_dnp3_al_iin_bmsg,
      { "Broadcast Msg Rx", "dnp3.al.iin.bmsg",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_BMSG,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_cls1d,
      { "Class 1 Data Available", "dnp3.al.iin.cls1d",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS1D,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_cls2d,
      { "Class 2 Data Available", "dnp3.al.iin.cls2d",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS2D,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_cls3d,
      { "Class 3 Data Available", "dnp3.al.iin.cls3d",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CLS3D,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_tsr,
      { "Time Sync Required", "dnp3.al.iin.tsr",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_TSR,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_dol,
      { "Digital Outputs in Local", "dnp3.al.iin.dol",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_DOL,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_dt,
      { "Device Trouble", "dnp3.al.iin.dt",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_DT,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_rst,
      { "Device Restart", "dnp3.al.iin.rst",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_RST,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_fcni,
      { "Function Code not implemented", "dnp3.al.iin.fcni",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_FCNI,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_obju,
      { "Requested Objects Unknown", "dnp3.al.iin.obju",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_OBJU,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_pioor,
      { "Parameters Invalid or Out of Range", "dnp3.al.iin.pioor",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_PIOOR,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_ebo,
      { "Event Buffer Overflow", "dnp3.al.iin.ebo",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_EBO,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_oae,
      { "Operation Already Executing", "dnp3.al.iin.oae",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_OAE,
        NULL, HFILL }
    },

    { &hf_dnp3_al_iin_cc,
      { "Configuration Corrupt", "dnp3.al.iin.cc",
        FT_BOOLEAN, 16, TFS(&tfs_set_notset), AL_IIN_CC,
        NULL, HFILL }
    },

    { &hf_dnp3_al_obj,
      { "Object", "dnp3.al.obj",
        FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dnp3_al_obj_vals_ext, 0x0,
        "Application Layer Object", HFILL }
    },

    { &hf_dnp3_al_objq_prefix,
      { "Prefix Code", "dnp3.al.objq.prefix",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_objq_prefix_vals_ext, AL_OBJQ_PREFIX,
        "Object Prefix Code", HFILL }
    },

    { &hf_dnp3_al_objq_range,
      { "Range Code", "dnp3.al.objq.range",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_objq_range_vals_ext, AL_OBJQ_RANGE,
        "Object Range Specifier Code", HFILL }
    },

    { &hf_dnp3_al_range_start8,
      { "Start (8 bit)", "dnp3.al.range.start",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Object Start Index", HFILL }
    },

    { &hf_dnp3_al_range_stop8,
      { "Stop (8 bit)", "dnp3.al.range.stop",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Object Stop Index", HFILL }
    },

    { &hf_dnp3_al_range_start16,
      { "Start (16 bit)", "dnp3.al.range.start",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Object Start Index", HFILL }
    },

    { &hf_dnp3_al_range_stop16,
      { "Stop (16 bit)", "dnp3.al.range.stop",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Object Stop Index", HFILL }
    },

    { &hf_dnp3_al_range_start32,
      { "Start (32 bit)", "dnp3.al.range.start",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Object Start Index", HFILL }
    },

    { &hf_dnp3_al_range_stop32,
      { "Stop (32 bit)", "dnp3.al.range.stop",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Object Stop Index", HFILL }
    },

    { &hf_dnp3_al_range_abs8,
      { "Address (8 bit)", "dnp3.al.range.abs",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Object Absolute Address", HFILL }
    },

    { &hf_dnp3_al_range_abs16,
      { "Address (16 bit)", "dnp3.al.range.abs",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Object Absolute Address", HFILL }
    },

    { &hf_dnp3_al_range_abs32,
      { "Address (32 bit)", "dnp3.al.range.abs",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Object Absolute Address", HFILL }
    },

    { &hf_dnp3_al_range_quant8,
      { "Quantity (8 bit)", "dnp3.al.range.quantity",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Object Quantity", HFILL }
    },

    { &hf_dnp3_al_range_quant16,
      { "Quantity (16 bit)", "dnp3.al.range.quantity",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Object Quantity", HFILL }
    },

    { &hf_dnp3_al_range_quant32,
      { "Quantity (32 bit)", "dnp3.al.range.quantity",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Object Quantity", HFILL }
    },

    { &hf_dnp3_al_index8,
      { "Index (8 bit)", "dnp3.al.index",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Object Index", HFILL }
    },

    { &hf_dnp3_al_index16,
      { "Index (16 bit)", "dnp3.al.index",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "Object Index", HFILL }
    },

    { &hf_dnp3_al_index32,
      { "Index (32 bit)", "dnp3.al.index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Object Index", HFILL }
    },

#if 0
    { &hf_dnp3_al_ptnum,
      { "Object Point Number", "dnp3.al.ptnum",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
#endif

    { &hf_dnp3_al_size8,
      { "Size (8 bit)", "dnp3.al.size",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          "Object Size", HFILL }
    },

    { &hf_dnp3_al_size16,
      { "Size (16 bit)", "dnp3.al.size",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Object Size", HFILL }
    },

    { &hf_dnp3_al_size32,
      { "Size (32 bit)", "dnp3.al.size",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Object Size", HFILL }
    },

    { &hf_dnp3_bocs_bit,
      { "Commanded State", "dnp3.al.bocs",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80,
          "Binary Output Commanded state", HFILL }
    },

    { &hf_dnp3_al_bit,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x1,
          "Digital Value (1 bit)", HFILL }
    },

    { &hf_dnp3_al_bit0,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
          "Digital Value (1 bit)", HFILL }
    },
    { &hf_dnp3_al_bit1,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x02,
          "Digital Value (1 bit)", HFILL }
    },
    { &hf_dnp3_al_bit2,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x04,
          "Digital Value (1 bit)", HFILL }
    },
    { &hf_dnp3_al_bit3,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x08,
          "Digital Value (1 bit)", HFILL }
    },
    { &hf_dnp3_al_bit4,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x10,
          "Digital Value (1 bit)", HFILL }
    },
    { &hf_dnp3_al_bit5,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x20,
          "Digital Value (1 bit)", HFILL }
    },
    { &hf_dnp3_al_bit6,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x40,
          "Digital Value (1 bit)", HFILL }
    },
    { &hf_dnp3_al_bit7,
      { "Value (bit)", "dnp3.al.bit",
          FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x80,
          "Digital Value (1 bit)", HFILL }
    },

    { &hf_dnp3_al_2bit,
      { "Value (Double-bit)", "dnp3.al.2bit",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_dbi_vals_ext, AL_OBJ_DBI_MASK,
          "Digital Value (Double-bit)", HFILL }
    },

    { &hf_dnp3_al_2bit0,
      { "Value (Double-bit)", "dnp3.al.2bit",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_dbi_vals_ext, 0x03,
          "Digital Value (Double-bit)", HFILL }
    },

    { &hf_dnp3_al_2bit1,
      { "Value (Double-bit)", "dnp3.al.2bit",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_dbi_vals_ext, 0x0c,
          "Digital Value (Double-bit)", HFILL }
    },

    { &hf_dnp3_al_2bit2,
      { "Value (Double-bit)", "dnp3.al.2bit",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_dbi_vals_ext, 0x30,
          "Digital Value (Double-bit)", HFILL }
    },
    { &hf_dnp3_al_2bit3,
      { "Value (Double-bit)", "dnp3.al.2bit",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_dbi_vals_ext, 0xc0,
          "Digital Value (Double-bit)", HFILL }
    },

    { &hf_dnp3_al_ana16,
      { "Value (16 bit)", "dnp3.al.ana.int",
          FT_INT16, BASE_DEC, NULL, 0x0,
          "Analog Value (16 bit)", HFILL }
    },

    { &hf_dnp3_al_ana32,
      { "Value (32 bit)", "dnp3.al.ana.int",
          FT_INT32, BASE_DEC, NULL, 0x0,
          "Analog Value (32 bit)", HFILL }
    },

    { &hf_dnp3_al_anaflt,
      { "Value (float)", "dnp3.al.ana.float",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          "Analog Value (float)", HFILL }
    },

    { &hf_dnp3_al_anadbl,
      { "Value (double)", "dnp3.al.ana.double",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          "Analog Value (double)", HFILL }
    },

    { &hf_dnp3_al_anaout16,
      { "Output Value (16 bit)", "dnp3.al.anaout.int",
          FT_INT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_anaout32,
      { "Output Value (32 bit)", "dnp3.al.anaout.int",
          FT_INT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_anaoutflt,
      { "Output Value (float)", "dnp3.al.anaout.float",
          FT_FLOAT, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_anaoutdbl,
      { "Output (double)", "dnp3.al.anaout.double",
          FT_DOUBLE, BASE_NONE, NULL, 0x0,
          "Output Value (double)", HFILL }
    },

    { &hf_dnp3_al_cnt16,
      { "Counter (16 bit)", "dnp3.al.cnt",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Counter Value (16 bit)", HFILL }
    },

    { &hf_dnp3_al_cnt32,
      { "Counter (32 bit)", "dnp3.al.cnt",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Counter Value (32 bit)", HFILL }
    },

    { &hf_dnp3_al_ctrlstatus,
      { "Control Status", "dnp3.al.ctrlstatus",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_ctl_status_vals_ext, AL_OBJCTL_STATUS_MASK,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_mode,
      { "File Control Mode", "dnp3.al.file.mode",
          FT_UINT16, BASE_DEC, VALS(dnp3_al_file_mode_vals), 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_auth,
      { "File Authentication Key", "dnp3.al.file.auth",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_size,
      { "File Size", "dnp3.al.file.size",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_maxblk,
      { "File Max Block Size", "dnp3.al.file.maxblock",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_reqID,
      { "File Request Identifier", "dnp3.al.file.reqID",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_status,
      { "File Control Status", "dnp3.al.file.status",
          FT_UINT8, BASE_DEC|BASE_EXT_STRING, &dnp3_al_file_status_vals_ext, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_handle,
      { "File Handle", "dnp3.al.file.handle",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_blocknum,
      { "File Block Number", "dnp3.al.file.blocknum",
          FT_UINT32, BASE_HEX, NULL, 0x7fffffff,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_lastblock,
      { "File Last Block", "dnp3.al.file.lastblock",
          FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x80000000,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_data,
      { "File Data", "dnp3.al.file.data",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b0,
      { "Online", "dnp3.al.biq.b0",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b1,
      { "Restart", "dnp3.al.biq.b1",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG1,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b2,
      { "Comm Fail", "dnp3.al.biq.b2",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG2,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b3,
      { "Remote Force", "dnp3.al.biq.b3",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG3,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b4,
      { "Local Force", "dnp3.al.biq.b4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG4,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b5,
      { "Chatter Filter", "dnp3.al.biq.b5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG5,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b6,
      { "Reserved", "dnp3.al.biq.b6",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG6,
          NULL, HFILL }
    },

    { &hf_dnp3_al_biq_b7,
      { "Point Value", "dnp3.al.biq.b7",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BI_FLAG7,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b0,
      { "Online", "dnp3.al.boq.b0",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b1,
      { "Restart", "dnp3.al.boq.b1",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG1,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b2,
      { "Comm Fail", "dnp3.al.boq.b2",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG2,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b3,
      { "Remote Force", "dnp3.al.boq.b3",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG3,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b4,
      { "Local Force", "dnp3.al.boq.b4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG4,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b5,
      { "Reserved", "dnp3.al.boq.b5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG5,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b6,
      { "Reserved", "dnp3.al.boq.b6",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG6,
          NULL, HFILL }
    },

    { &hf_dnp3_al_boq_b7,
      { "Point Value", "dnp3.al.boq.b7",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_BO_FLAG7,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b0,
      { "Online", "dnp3.al.ctrq.b0",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b1,
      { "Restart", "dnp3.al.ctrq.b1",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG1,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b2,
      { "Comm Fail", "dnp3.al.ctrq.b2",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG2,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b3,
      { "Remote Force", "dnp3.al.ctrq.b3",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG3,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b4,
      { "Local Force", "dnp3.al.ctrq.b4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG4,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b5,
      { "Roll-Over", "dnp3.al.ctrq.b5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG5,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b6,
      { "Discontinuity", "dnp3.al.ctrq.b6",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG6,
          NULL, HFILL }
    },

    { &hf_dnp3_al_ctrq_b7,
      { "Reserved", "dnp3.al.ctrq.b7",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_CTR_FLAG7,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b0,
      { "Online", "dnp3.al.aiq.b0",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b1,
      { "Restart", "dnp3.al.aiq.b1",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG1,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b2,
      { "Comm Fail", "dnp3.al.aiq.b2",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG2,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b3,
      { "Remote Force", "dnp3.al.aiq.b3",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG3,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b4,
      { "Local Force", "dnp3.al.aiq.b4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG4,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b5,
      { "Over-Range", "dnp3.al.aiq.b5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG5,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b6,
      { "Reference Check", "dnp3.al.aiq.b6",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG6,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aiq_b7,
      { "Reserved", "dnp3.al.aiq.b7",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AI_FLAG7,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b0,
      { "Online", "dnp3.al.aoq.b0",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b1,
      { "Restart", "dnp3.al.aoq.b1",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG1,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b2,
      { "Comm Fail", "dnp3.al.aoq.b2",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG2,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b3,
      { "Remote Force", "dnp3.al.aoq.b3",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG3,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b4,
      { "Local Force", "dnp3.al.aoq.b4",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG4,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b5,
      { "Reserved", "dnp3.al.aoq.b5",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG5,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b6,
      { "Reserved", "dnp3.al.aoq.b6",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG6,
          NULL, HFILL }
    },

    { &hf_dnp3_al_aoq_b7,
      { "Reserved", "dnp3.al.aoq.b7",
          FT_BOOLEAN, 8, TFS(&tfs_set_notset), AL_OBJ_AO_FLAG7,
          NULL, HFILL }
    },

    { &hf_dnp3_al_timestamp,
      { "Timestamp", "dnp3.al.timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0,
          "Object Timestamp", HFILL }
    },

    { &hf_dnp3_al_file_perms,
      { "Permissions", "dnp3.al.file.perms",
          FT_UINT16, BASE_OCT, NULL, 0x0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_read_owner,
      { "Read permission for owner", "dnp3.al.file.perms.read_owner",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0400,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_write_owner,
      { "Write permission for owner", "dnp3.al.file.perms.write_owner",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0200,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_exec_owner,
      { "Execute permission for owner", "dnp3.al.file.perms.exec_owner",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0100,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_read_group,
      { "Read permission for group", "dnp3.al.file.perms.read_group",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 040,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_write_group,
      { "Write permission for group", "dnp3.al.file.perms.write_group",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 020,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_exec_group,
      { "Execute permission for group", "dnp3.al.file.perms.exec_group",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 010,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_read_world,
      { "Read permission for world", "dnp3.al.file.perms.read_world",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 04,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_write_world,
      { "Write permission for world", "dnp3.al.file.perms.write_world",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 02,
          NULL, HFILL }
    },

    { &hf_dnp3_al_file_perms_exec_world,
      { "Execute permission for world", "dnp3.al.file.perms.exec_world",
          FT_BOOLEAN, 16, TFS(&tfs_yes_no), 01,
          NULL, HFILL }
    },

    { &hf_dnp3_al_rel_timestamp,
      { "Relative Timestamp", "dnp3.al.reltimestamp",
          FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
          "Object Relative Timestamp", HFILL }
    },

    { &hf_dnp3_al_datatype,
      { "Data Type", "dnp3.al.datatype",
          FT_UINT8, BASE_HEX, VALS(dnp3_al_data_type_vals), 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_length,
      { "Device Attribute Length", "dnp3.al.da.length",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_uint8,
      { "Device Attribute 8-Bit Unsigned Integer Value", "dnp3.al.da.uint8",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_uint16,
      { "Device Attribute 16-Bit Unsigned Integer Value", "dnp3.al.da.uint16",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_uint32,
      { "Device Attribute 32-Bit Unsigned Integer Value", "dnp3.al.da.uint32",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_int8,
      { "Device Attribute 8-Bit Integer Value", "dnp3.al.da.int8",
          FT_INT8, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_int16,
      { "Device Attribute 16-Bit Integer Value", "dnp3.al.da.int16",
          FT_INT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_int32,
      { "Device Attribute 32-Bit Integer Value", "dnp3.al.da.int32",
          FT_INT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_flt,
      { "Device Attribute Float Value", "dnp3.al.da.float",
          FT_FLOAT, BASE_NONE, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_da_dbl,
      { "Device Attribute Double Value", "dnp3.al.da.double",
          FT_DOUBLE, BASE_NONE, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_assoc_id,
      { "Association ID" , "dnp3.al.sa.assoc_id",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_cd,
      {"Challenge Data", "dnp3.al.sa.cd",
          FT_BYTES, BASE_NONE, NULL, 0x00,
          NULL, HFILL }},

    { &hf_dnp3_al_sa_cdl,
      { "Challenge Data Length", "dnp3.al.sa.cdl",
          FT_UINT16, BASE_HEX, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_csq,
      { "Challenge Sequence Number" , "dnp3.al.sa.csq",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_err,
      { "Error Code", "dnp3.al.sa.err",
          FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_err_vals), 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_kcm,
      { "Key Change Method", "dnp3.al.sa.kcm",
          FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_kcm_vals), 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_key,
      {"Key Data", "dnp3.al.sa.key",
          FT_BYTES, BASE_NONE, NULL, 0x00,
          NULL, HFILL }},

    { &hf_dnp3_al_sa_ks,
      { "Key Status", "dnp3.al.sa.kw",
          FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_ks_vals), 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_ksq,
      { "Key Change Sequence Number" , "dnp3.al.sa.ksq",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_kwa,
      { "Key Wrap Algorithm", "dnp3.al.sa.kwa",
          FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_kwa_vals), 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_mac,
      {"MAC Value", "dnp3.al.sa.mac",
          FT_BYTES, BASE_NONE, NULL, 0x00,
          NULL, HFILL }},

    { &hf_dnp3_al_sa_mal,
      { "MAC Algorithm", "dnp3.al.sa.mal",
          FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_mal_vals), 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_rfc,
      { "Reason for Challenge", "dnp3.al.sa.rfc",
          FT_UINT8, BASE_HEX, VALS(dnp3_al_sa_rfc_vals), 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_seq,
      { "Sequence Number" , "dnp3.al.sa.seq",
          FT_UINT32, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_uk,
      {"Encrypted Update Key Data", "dnp3.al.sa.uk",
          FT_BYTES, BASE_NONE, NULL, 0x00,
          NULL, HFILL }},

    { &hf_dnp3_al_sa_ukl,
      { "Encrypted Update Key Length", "dnp3.al.sa.ukl",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_usr,
      { "User Number" , "dnp3.al.sa.usr",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_dnp3_al_sa_usrn,
      { "User Name", "dnp3.al.sa.usrn",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL }},

    { &hf_dnp3_al_sa_usrnl,
      { "User name Length", "dnp3.al.sa.usrnl",
          FT_UINT16, BASE_DEC, NULL, 0,
          NULL, HFILL }
    },

    { &hf_al_frag_data,
      {"DNP3.0 AL Fragment Data", "dnp3.al.frag_data",
          FT_BYTES, BASE_NONE, NULL, 0x00,
          "DNP 3.0 Application Layer Fragment Data", HFILL }},

    { &hf_dnp3_fragment,
      { "DNP 3.0 AL Fragment", "dnp3.al.fragment",
          FT_FRAMENUM, BASE_NONE, NULL, 0x0,
          "DNP 3.0 Application Layer Fragment", HFILL }
    },

    { &hf_dnp3_fragments,
      { "DNP 3.0 AL Fragments", "dnp3.al.fragments",
          FT_NONE, BASE_NONE, NULL, 0x0,
          "DNP 3.0 Application Layer Fragments", HFILL }
    },

    { &hf_dnp3_fragment_overlap,
      { "Fragment overlap", "dnp3.al.fragment.overlap",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Fragment overlaps with other fragments", HFILL }
    },

    { &hf_dnp3_fragment_overlap_conflict,
      { "Conflicting data in fragment overlap", "dnp3.al.fragment.overlap.conflict",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Overlapping fragments contained conflicting data", HFILL }
    },

    { &hf_dnp3_fragment_multiple_tails,
      { "Multiple tail fragments found", "dnp3.al.fragment.multipletails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Several tails were found when defragmenting the packet", HFILL }
    },

    { &hf_dnp3_fragment_too_long_fragment,
      { "Fragment too long", "dnp3.al.fragment.toolongfragment",
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,
          "Fragment contained data past end of packet", HFILL }
    },

    { &hf_dnp3_fragment_error,
      { "Defragmentation error", "dnp3.al.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "Defragmentation error due to illegal fragments", HFILL }
    },

    { &hf_dnp3_fragment_count,
      { "Fragment count", "dnp3.al.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },

    { &hf_dnp3_fragment_reassembled_in,
      { "Reassembled PDU In Frame", "dnp3.al.fragment.reassembled_in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "This PDU is reassembled in this frame", HFILL }
    },

    { &hf_dnp3_fragment_reassembled_length,
      { "Reassembled DNP length", "dnp3.al.fragment.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The total length of the reassembled payload", HFILL }
    },
    { &hf_dnp3_al_bi_index, { "Binary Input Index", "dnp3.al.bi.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_bi_static_index, { "Binary Input Static Index", "dnp3.al.bi.static.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_bi_event_index, { "Binary Input Event Index", "dnp3.al.bi.event.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_dbi_index, { "Double-Bit Input Index", "dnp3.al.dbi.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_dbi_static_index, { "Double-Bit Input Static Index", "dnp3.al.dbi.static.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_dbi_event_index, { "Double-Bit Input Event Index", "dnp3.al.dbi.event.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_bo_index, { "Binary Output Index", "dnp3.al.bo.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_bo_static_index, { "Binary Output Static Index", "dnp3.al.bo.static.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_bo_event_index, { "Binary Output Event Index", "dnp3.al.bo.event.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_bo_cmnd_index, { "Binary Output Command Index", "dnp3.al.bo.cmnd.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_counter_index, { "Counter Index", "dnp3.al.counter.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_counter_static_index, { "Counter Static Index", "dnp3.al.counter.static.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_counter_event_index, { "Counter Input Event Index", "dnp3.al.counter.event.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_ai_index, { "Analog Input Index", "dnp3.al.ai.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_ai_static_index, { "Analog Input Static Index", "dnp3.al.ai.static.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_ai_event_index, { "Analog Input Event Index", "dnp3.al.ai.event.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_ao_index, { "Analog Output Index", "dnp3.al.ao.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_ao_static_index, { "Analog Output Static Index", "dnp3.al.ao.static.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_ao_event_index, { "Analog Output Event Index", "dnp3.al.ao.event.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_ao_cmnd_index, { "Analog Output Command Index", "dnp3.al.ao.cmnd.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_os_index, { "Octet String Index", "dnp3.al.os.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_os_static_index, { "Octet String Static Index", "dnp3.al.os.static.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_os_event_index, { "Octet String Event Index", "dnp3.al.os.event.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    /* Generated from convert_proto_tree_add_text.pl */
    { &hf_dnp3_al_point_index, { "Point Index", "dnp3.al.point_index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_da_value, { "Value", "dnp3.al.da.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_count, { "Count", "dnp3.al.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_on_time, { "On Time", "dnp3.al.on_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_off_time, { "Off Time", "dnp3.al.off_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_time_delay, { "Time Delay", "dnp3.al.time_delay", FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0, NULL, HFILL }},
    { &hf_dnp3_al_file_string_offset, { "File String Offset", "dnp3.al.file_string_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_file_string_length, { "File String Length", "dnp3.al.file_string_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_file_name, { "File Name", "dnp3.al.file_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_al_octet_string, { "Octet String", "dnp3.al.octet_string", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dnp3_unknown_data_chunk, { "Unknown Data Chunk", "dnp3.al.unknown_data_chunk", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

  };

/* Setup protocol subtree array */
  static int *ett[] = {
    &ett_dnp3,
    &ett_dnp3_dl,
    &ett_dnp3_dl_ctl,
    &ett_dnp3_tr_ctl,
    &ett_dnp3_dl_data,
    &ett_dnp3_dl_chunk,
    &ett_dnp3_al,
    &ett_dnp3_al_ctl,
    &ett_dnp3_al_obj_point_tcc,
    &ett_dnp3_al_iin,
    &ett_dnp3_al_obj,
    &ett_dnp3_al_obj_qualifier,
    &ett_dnp3_al_obj_range,
    &ett_dnp3_al_objdet,
    &ett_dnp3_al_obj_quality,
    &ett_dnp3_al_obj_point,
    &ett_dnp3_al_obj_point_perms,
    &ett_dnp3_fragment,
    &ett_dnp3_fragments
  };
  static ei_register_info ei[] = {
     { &ei_dnp_num_items_neg, { "dnp3.num_items_neg", PI_MALFORMED, PI_ERROR, "Negative number of items", EXPFILL }},
     { &ei_dnp_invalid_length, { "dnp3.invalid_length", PI_MALFORMED, PI_ERROR, "Invalid length", EXPFILL }},
     { &ei_dnp_iin_abnormal, { "dnp3.iin_abnormal", PI_PROTOCOL, PI_WARN, "IIN Abnormality", EXPFILL }},
     { &ei_dnp3_data_hdr_crc_incorrect, { "dnp3.hdr.CRC.incorrect", PI_CHECKSUM, PI_WARN, "Data Link Header Checksum incorrect", EXPFILL }},
     { &ei_dnp3_data_chunk_crc_incorrect, { "dnp3.data_chunk.CRC.incorrect", PI_CHECKSUM, PI_WARN, "Data Chunk Checksum incorrect", EXPFILL }},
     { &ei_dnp3_unknown_object, { "dnp3.unknown_object", PI_PROTOCOL, PI_WARN, "Unknown Object\\Variation", EXPFILL }},
     { &ei_dnp3_unknown_group0_variation, { "dnp3.unknown_group0_variation", PI_PROTOCOL, PI_WARN, "Unknown Group 0 Variation", EXPFILL }},
     { &ei_dnp3_num_items_invalid, { "dnp3.num_items_invalid", PI_MALFORMED, PI_ERROR, "Number of items is invalid for normally empty object. Potentially malicious packet", EXPFILL }},
      /* Generated from convert_proto_tree_add_text.pl */
#if 0
      { &ei_dnp3_buffering_user_data_until_final_frame_is_received, { "dnp3.buffering_user_data_until_final_frame_is_received", PI_PROTOCOL, PI_WARN, "Buffering User Data Until Final Frame is Received..", EXPFILL }},
#endif
    };

  module_t *dnp3_module;
  expert_module_t* expert_dnp3;

  reassembly_table_register(&al_reassembly_table,
                        &addresses_reassembly_table_functions);

/* Register the protocol name and description */
  proto_dnp3 = proto_register_protocol("Distributed Network Protocol 3.0", "DNP 3.0", "dnp3");

/* Register the dissector so it may be used as a User DLT payload protocol */
  dnp3_tcp_handle = register_dissector("dnp3.tcp", dissect_dnp3_tcp, proto_dnp3);
  dnp3_udp_handle = register_dissector("dnp3.udp", dissect_dnp3_udp, proto_dnp3);

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_dnp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dnp3 = expert_register_protocol(proto_dnp3);
  expert_register_field_array(expert_dnp3, ei, array_length(ei));

  dnp3_module = prefs_register_protocol(proto_dnp3, NULL);
  prefs_register_obsolete_preference(dnp3_module, "heuristics");
  prefs_register_bool_preference(dnp3_module, "desegment",
    "Reassemble DNP3 messages spanning multiple TCP segments",
    "Whether the DNP3 dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &dnp3_desegment);

  /* Register tap */
  dnp3_tap = register_tap("dnp3");

  register_conversation_table(proto_dnp3, true, dnp3_conversation_packet, dnp3_endpoint_packet);
}

void
proto_reg_handoff_dnp3(void)
{
  /* register as heuristic dissector for both TCP and UDP */
  heur_dissector_add("tcp", dissect_dnp3_tcp_heur, "DNP 3.0 over TCP", "dnp3_tcp", proto_dnp3, HEURISTIC_DISABLE);
  heur_dissector_add("udp", dissect_dnp3_udp_heur, "DNP 3.0 over UDP", "dnp3_udp", proto_dnp3, HEURISTIC_DISABLE);

  dissector_add_uint_with_preference("tcp.port", TCP_PORT_DNP, dnp3_tcp_handle);
  dissector_add_uint_with_preference("udp.port", UDP_PORT_DNP, dnp3_udp_handle);
  dissector_add_for_decode_as("rtacser.data", dnp3_udp_handle);

  ssl_dissector_add(TCP_PORT_DNP_TLS, dnp3_tcp_handle);
}

/*
 * Editor modelines
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

