/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pcap.c                                                              */
/* asn2wrs.py -q -L -p pcap -c ./pcap.cnf -s ./packet-pcap-template -D . -O ../.. PCAP-CommonDataTypes.asn PCAP-Constants.asn PCAP-Containers.asn PCAP-IEs.asn PCAP-PDU-Contents.asn PCAP-PDU-Descriptions.asn */

/* packet-pcap.c
 * Routines for UTRAN Iupc interface Positioning Calculation Application Part (PCAP) packet dissection
 *
 * Copyright 2008, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Based on the RANAP dissector
 *
 * References: ETSI TS 125 453 V17.0.0 (2022-04)
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/array.h>

#include <epan/strutil.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-sccp.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iupc interface Positioning Calculation Application Part (PCAP)"
#define PSNAME "PCAP"
#define PFNAME "pcap"

#define MAX_SSN 254

void proto_register_pcap(void);
void proto_reg_handoff_pcap(void);

#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfErrors                  256
#define maxSat                         16
#define maxSatAlmanac                  32
#define maxNrOfLevels                  256
#define maxNrOfPoints                  15
#define maxNrOfExpInfo                 32
#define maxNrOfMeasNCell               32
#define maxNrOfMeasurements            16
#define maxNrOfSets                    3
#define maxRateMatching                256
#define maxNrOfTFs                     32
#define maxTTI_count                   4
#define maxTS_1                        13
#define maxCCTrCH                      8
#define maxTF                          32
#define maxTFC                         1024
#define maxPRACH                       16
#define maxTrCH                        32
#define maxTGPS                        6
#define maxNoOfMeasurements            16
#define maxCellMeas                    32
#define maxNrOfEDPCCH_PO_QUANTSTEPs    8
#define maxNrOfRefETFCI_PO_QUANTSTEPs  8
#define maxNrOfRefETFCIs               8
#define maxSet                         9
#define maxGANSSSat                    64
#define maxSgnType                     8
#define maxGANSS                       8
#define maxGANSSSet                    9
#define maxGANSSSatAlmanac             36
#define maxGANSSClockMod               4
#define maxGANSS_1                     7
#define maxNrOfIRATMeasurements        16
#define maxReportedGERANCells          6
#define maxIonGridInfo                 320
#define maxAddPos                      8
#define maxBeacons                     64
#define maxBTs                         32
#define maxWLANs                       64
#define maxNrOfULTSs                   15
#define maxNrOfDPCHs                   240

typedef enum _ProcedureCode_enum {
  id_PositionCalculation =   1,
  id_InformationExchangeInitiation =   2,
  id_InformationReporting =   3,
  id_InformationExchangeTermination =   4,
  id_InformationExchangeFailure =   5,
  id_ErrorIndication =   6,
  id_privateMessage =   7,
  id_PositionParameterModification =   8,
  id_PositionInitiation =   9,
  id_PositionActivation =  10,
  id_Abort     =  11,
  id_PositionPeriodicReport =  12,
  id_PositionPeriodicResult =  13,
  id_PositionPeriodicTermination =  14
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   1,
  id_CriticalityDiagnostics =   2,
  id_GPS_UTRAN_TRU =   3,
  id_InformationExchangeID =   4,
  id_InformationExchangeObjectType_InfEx_Rprt =   5,
  id_InformationExchangeObjectType_InfEx_Rqst =   6,
  id_InformationExchangeObjectType_InfEx_Rsp =   7,
  id_InformationReportCharacteristics =   8,
  id_InformationType =   9,
  id_GPS_MeasuredResultsList =  10,
  id_MethodType =  11,
  id_RefPosition_InfEx_Rqst =  12,
  id_RefPosition_InfEx_Rsp =  13,
  id_RefPosition_Inf_Rprt =  14,
  id_RequestedDataValue =  15,
  id_RequestedDataValueInformation =  16,
  id_TransactionID =  17,
  id_UE_PositionEstimate =  18,
  id_Unknown_19 =  19,
  id_CellId_MeasuredResultsSets =  20,
  id_Unknown_21 =  21,
  id_OTDOA_MeasurementGroup =  22,
  id_AccuracyFulfilmentIndicator =  23,
  id_HorizontalAccuracyCode =  24,
  id_VerticalAccuracyCode =  25,
  id_UTDOA_Group =  26,
  id_Unknown_27 =  27,
  id_RequestType =  28,
  id_UE_PositioningCapability =  29,
  id_UC_id     =  30,
  id_ResponseTime =  31,
  id_PositioningPriority =  32,
  id_ClientType =  33,
  id_PositioningMethod =  34,
  id_UTDOAPositioning =  35,
  id_GPSPositioning =  36,
  id_OTDOAAssistanceData =  37,
  id_Positioning_ResponseTime =  38,
  id_EnvironmentCharacterisation =  39,
  id_PositionData =  40,
  id_IncludeVelocity =  41,
  id_VelocityEstimate =  42,
  id_rxTimingDeviation768Info =  43,
  id_UC_ID_InfEx_Rqst =  44,
  id_UE_PositionEstimateInfo =  45,
  id_UTRAN_GPSReferenceTime =  46,
  id_UTRAN_GPSReferenceTimeResult =  47,
  id_UTRAN_GPS_DriftRate =  48,
  id_OTDOA_AddMeasuredResultsInfo =  49,
  id_GPS_ReferenceLocation =  50,
  id_OTDOA_MeasuredResultsSets =  51,
  id_rxTimingDeviation384extInfo =  55,
  id_ExtendedRoundTripTime =  56,
  id_PeriodicPosCalcInfo =  57,
  id_PeriodicLocationInfo =  58,
  id_AmountOfReporting =  59,
  id_MeasInstructionsUsed =  60,
  id_RRCstateChange =  61,
  id_PeriodicTerminationCause =  62,
  id_MeasurementValidity =  63,
  id_roundTripTimeInfoWithType1 =  64,
  id_Unknown_65 =  65,
  id_CellIDPositioning =  66,
  id_AddMeasurementInfo =  67,
  id_Extended_RNC_ID =  68,
  id_GANSS_CommonAssistanceData =  69,
  id_GANSS_GenericAssistanceDataList =  70,
  id_GANSS_MeasuredResultsList =  71,
  id_GANSS_UTRAN_TRU =  72,
  id_GANSSPositioning =  73,
  id_GANSS_PositioningDataSet =  74,
  id_GNSS_PositioningMethod =  75,
  id_NetworkAssistedGANSSSuport =  76,
  id_TUTRANGANSSMeasurementValueInfo =  77,
  id_AdditionalGPSAssistDataRequired =  78,
  id_AdditionalGanssAssistDataRequired =  79,
  id_angleOfArrivalLCR =  80,
  id_extendedTimingAdvanceLCR =  81,
  id_additionalMeasurementInforLCR =  82,
  id_timingAdvanceLCR_R7 =  83,
  id_rxTimingDeviationLCR =  84,
  id_GPSReferenceTimeUncertainty =  85,
  id_GANSS_AddIonoModelReq =  86,
  id_GANSS_EarthOrientParaReq =  87,
  id_GANSS_Additional_Ionospheric_Model =  88,
  id_GANSS_Earth_Orientation_Parameters =  89,
  id_GANSS_Additional_Time_Models =  90,
  id_GANSS_Additional_Navigation_Models =  91,
  id_GANSS_Additional_UTC_Models =  92,
  id_GANSS_Auxiliary_Information =  93,
  id_GANSS_SBAS_ID =  94,
  id_GANSS_SBAS_IDs =  95,
  id_GANSS_Signal_IDs =  96,
  id_supportGANSSNonNativeADchoices =  97,
  id_PositionDataUEbased =  98,
  id_ganssCodePhaseAmbiguityExt =  99,
  id_ganssIntegerCodePhaseExt = 100,
  id_GANSScarrierPhaseRequested = 101,
  id_GANSSMultiFreqMeasRequested = 102,
  id_ganssReq_AddIonosphericModel = 103,
  id_ganssReq_EarthOrientPara = 104,
  id_ganssAddNavigationModel_req = 105,
  id_ganssAddUTCModel_req = 106,
  id_ganssAuxInfo_req = 107,
  id_GANSS_AlmanacModelChoice = 108,
  id_GANSS_alm_keplerianNAVAlmanac = 109,
  id_GANSS_alm_keplerianReducedAlmanac = 110,
  id_GANSS_alm_keplerianMidiAlmanac = 111,
  id_GANSS_alm_keplerianGLONASS = 112,
  id_GANSS_alm_ecefSBASAlmanac = 113,
  id_UTRAN_GANSSReferenceTimeResult = 114,
  id_GANSS_Reference_Time_Only = 115,
  id_GANSS_AddADchoices = 116,
  id_OTDOA_ReferenceCellInfo = 117,
  id_DGNSS_ValidityPeriod = 118,
  id_AzimuthAndElevationLSB = 119,
  id_completeAlmanacProvided = 120,
  id_GPS_Week_Cycle = 121,
  id_GANSS_Day_Cycle = 122,
  id_ganss_Delta_T = 123,
  id_requestedCellIDGERANMeasurements = 124,
  id_CellId_IRATMeasuredResultsSets = 125,
  id_Unknown_126 = 126,
  id_Unknown_127 = 127,
  id_IMSI      = 128,
  id_IMEI      = 129,
  id_GANSS_alm_keplerianBDSAlmanac = 130,
  id_BDS_Ionospheric_Grid_Model = 131,
  id_DBDS_Correction_Information = 132,
  id_BDSIonosphericGridModel = 133,
  id_DBDSCorrection = 134,
  id_Confidence = 135,
  id_ExtraDopplerInfoExtension = 136,
  id_GANSS_Confidence = 137,
  id_GANSS_ExtraDopplerExtension = 138,
  id_Additional_PositioningDataSet = 139,
  id_Additional_PositioningMethod = 140,
  id_AddPos_MeasuredResults = 141,
  id_AddPosSupport = 142
} ProtocolIE_ID_enum;

static dissector_handle_t pcap_handle;

/* Initialize the protocol and registered fields */
static int proto_pcap;

static int hf_pcap_AccuracyFulfilmentIndicator_PDU;  /* AccuracyFulfilmentIndicator */
static int hf_pcap_AddPos_MeasuredResults_PDU;    /* AddPos_MeasuredResults */
static int hf_pcap_Cause_PDU;                     /* Cause */
static int hf_pcap_CellId_MeasuredResultsSets_PDU;  /* CellId_MeasuredResultsSets */
static int hf_pcap_RoundTripTimeInfoWithType1_PDU;  /* RoundTripTimeInfoWithType1 */
static int hf_pcap_ExtendedTimingAdvanceLCR_PDU;  /* ExtendedTimingAdvanceLCR */
static int hf_pcap_RxTimingDeviation768Info_PDU;  /* RxTimingDeviation768Info */
static int hf_pcap_RxTimingDeviation384extInfo_PDU;  /* RxTimingDeviation384extInfo */
static int hf_pcap_AddMeasurementInfo_PDU;        /* AddMeasurementInfo */
static int hf_pcap_AngleOfArrivalLCR_PDU;         /* AngleOfArrivalLCR */
static int hf_pcap_CellId_IRATMeasuredResultsSets_PDU;  /* CellId_IRATMeasuredResultsSets */
static int hf_pcap_CellIDPositioning_PDU;         /* CellIDPositioning */
static int hf_pcap_RequestedCellIDGERANMeasurements_PDU;  /* RequestedCellIDGERANMeasurements */
static int hf_pcap_ClientType_PDU;                /* ClientType */
static int hf_pcap_CriticalityDiagnostics_PDU;    /* CriticalityDiagnostics */
static int hf_pcap_DGNSS_ValidityPeriod_PDU;      /* DGNSS_ValidityPeriod */
static int hf_pcap_IMEI_PDU;                      /* IMEI */
static int hf_pcap_IMSI_PDU;                      /* IMSI */
static int hf_pcap_UE_PositionEstimate_PDU;       /* UE_PositionEstimate */
static int hf_pcap_UE_PositionEstimateInfo_PDU;   /* UE_PositionEstimateInfo */
static int hf_pcap_GANSS_Reference_Time_Only_PDU;  /* GANSS_Reference_Time_Only */
static int hf_pcap_PositionDataUEbased_PDU;       /* PositionDataUEbased */
static int hf_pcap_PositionData_PDU;              /* PositionData */
static int hf_pcap_GANSS_PositioningDataSet_PDU;  /* GANSS_PositioningDataSet */
static int hf_pcap_Additional_PositioningDataSet_PDU;  /* Additional_PositioningDataSet */
static int hf_pcap_ExtraDopplerInfoExtension_PDU;  /* ExtraDopplerInfoExtension */
static int hf_pcap_AzimuthAndElevationLSB_PDU;    /* AzimuthAndElevationLSB */
static int hf_pcap_Confidence_PDU;                /* Confidence */
static int hf_pcap_GANSS_Additional_Ionospheric_Model_PDU;  /* GANSS_Additional_Ionospheric_Model */
static int hf_pcap_GANSS_Additional_Navigation_Models_PDU;  /* GANSS_Additional_Navigation_Models */
static int hf_pcap_GANSS_Additional_Time_Models_PDU;  /* GANSS_Additional_Time_Models */
static int hf_pcap_GANSS_Additional_UTC_Models_PDU;  /* GANSS_Additional_UTC_Models */
static int hf_pcap_GANSS_ALM_BDSKeplericanset_PDU;  /* GANSS_ALM_BDSKeplericanset */
static int hf_pcap_GANSS_ALM_ECEFsbasAlmanacSet_PDU;  /* GANSS_ALM_ECEFsbasAlmanacSet */
static int hf_pcap_GANSS_ALM_GlonassAlmanacSet_PDU;  /* GANSS_ALM_GlonassAlmanacSet */
static int hf_pcap_GANSS_ALM_MidiAlmanacSet_PDU;  /* GANSS_ALM_MidiAlmanacSet */
static int hf_pcap_GANSS_ALM_NAVKeplerianSet_PDU;  /* GANSS_ALM_NAVKeplerianSet */
static int hf_pcap_GANSS_ALM_ReducedKeplerianSet_PDU;  /* GANSS_ALM_ReducedKeplerianSet */
static int hf_pcap_GANSS_Auxiliary_Information_PDU;  /* GANSS_Auxiliary_Information */
static int hf_pcap_GANSS_CommonAssistanceData_PDU;  /* GANSS_CommonAssistanceData */
static int hf_pcap_GANSS_Earth_Orientation_Parameters_PDU;  /* GANSS_Earth_Orientation_Parameters */
static int hf_pcap_GANSS_ExtraDopplerExtension_PDU;  /* GANSS_ExtraDopplerExtension */
static int hf_pcap_GANSS_GenericAssistanceDataList_PDU;  /* GANSS_GenericAssistanceDataList */
static int hf_pcap_BDS_Ionospheric_Grid_Model_PDU;  /* BDS_Ionospheric_Grid_Model */
static int hf_pcap_DBDS_Correction_Information_PDU;  /* DBDS_Correction_Information */
static int hf_pcap_GanssCodePhaseAmbiguityExt_PDU;  /* GanssCodePhaseAmbiguityExt */
static int hf_pcap_GanssIntegerCodePhaseExt_PDU;  /* GanssIntegerCodePhaseExt */
static int hf_pcap_GANSS_MeasuredResultsList_PDU;  /* GANSS_MeasuredResultsList */
static int hf_pcap_GANSS_Day_Cycle_PDU;           /* GANSS_Day_Cycle */
static int hf_pcap_GANSS_Delta_T_PDU;             /* GANSS_Delta_T */
static int hf_pcap_GANSS_UTRAN_TRU_PDU;           /* GANSS_UTRAN_TRU */
static int hf_pcap_CompleteAlmanacProvided_PDU;   /* CompleteAlmanacProvided */
static int hf_pcap_MeasuredResultsList_PDU;       /* MeasuredResultsList */
static int hf_pcap_GPS_ReferenceLocation_PDU;     /* GPS_ReferenceLocation */
static int hf_pcap_GPS_Week_Cycle_PDU;            /* GPS_Week_Cycle */
static int hf_pcap_UTRAN_GPS_DriftRate_PDU;       /* UTRAN_GPS_DriftRate */
static int hf_pcap_GPSReferenceTimeUncertainty_PDU;  /* GPSReferenceTimeUncertainty */
static int hf_pcap_GPS_UTRAN_TRU_PDU;             /* GPS_UTRAN_TRU */
static int hf_pcap_AdditionalGPSAssistDataRequired_PDU;  /* AdditionalGPSAssistDataRequired */
static int hf_pcap_AdditionalGanssAssistDataRequired_PDU;  /* AdditionalGanssAssistDataRequired */
static int hf_pcap_GANSSReq_AddIonosphericModel_PDU;  /* GANSSReq_AddIonosphericModel */
static int hf_pcap_GANSSReq_EarthOrientPara_PDU;  /* GANSSReq_EarthOrientPara */
static int hf_pcap_BDSIonosphericGridModel_PDU;   /* BDSIonosphericGridModel */
static int hf_pcap_DBDSCorrection_PDU;            /* DBDSCorrection */
static int hf_pcap_GANSS_AddNavigationModel_Req_PDU;  /* GANSS_AddNavigationModel_Req */
static int hf_pcap_GANSS_AddUTCModel_Req_PDU;     /* GANSS_AddUTCModel_Req */
static int hf_pcap_GANSS_AuxInfo_req_PDU;         /* GANSS_AuxInfo_req */
static int hf_pcap_GANSS_AddADchoices_PDU;        /* GANSS_AddADchoices */
static int hf_pcap_InformationExchangeID_PDU;     /* InformationExchangeID */
static int hf_pcap_InformationReportCharacteristics_PDU;  /* InformationReportCharacteristics */
static int hf_pcap_InformationType_PDU;           /* InformationType */
static int hf_pcap_GANSS_AddIonoModelReq_PDU;     /* GANSS_AddIonoModelReq */
static int hf_pcap_GANSS_EarthOrientParaReq_PDU;  /* GANSS_EarthOrientParaReq */
static int hf_pcap_GANSS_SBAS_ID_PDU;             /* GANSS_SBAS_ID */
static int hf_pcap_MeasInstructionsUsed_PDU;      /* MeasInstructionsUsed */
static int hf_pcap_OTDOA_MeasurementGroup_PDU;    /* OTDOA_MeasurementGroup */
static int hf_pcap_OTDOA_ReferenceCellInfoSAS_centric_PDU;  /* OTDOA_ReferenceCellInfoSAS_centric */
static int hf_pcap_OTDOA_MeasuredResultsSets_PDU;  /* OTDOA_MeasuredResultsSets */
static int hf_pcap_OTDOA_AddMeasuredResultsInfo_PDU;  /* OTDOA_AddMeasuredResultsInfo */
static int hf_pcap_UC_ID_PDU;                     /* UC_ID */
static int hf_pcap_Extended_RNC_ID_PDU;           /* Extended_RNC_ID */
static int hf_pcap_AdditionalMeasurementInforLCR_PDU;  /* AdditionalMeasurementInforLCR */
static int hf_pcap_PeriodicPosCalcInfo_PDU;       /* PeriodicPosCalcInfo */
static int hf_pcap_PeriodicLocationInfo_PDU;      /* PeriodicLocationInfo */
static int hf_pcap_PeriodicTerminationCause_PDU;  /* PeriodicTerminationCause */
static int hf_pcap_PositioningMethod_PDU;         /* PositioningMethod */
static int hf_pcap_GNSS_PositioningMethod_PDU;    /* GNSS_PositioningMethod */
static int hf_pcap_Additional_PositioningMethod_PDU;  /* Additional_PositioningMethod */
static int hf_pcap_PositioningPriority_PDU;       /* PositioningPriority */
static int hf_pcap_RRCstateChange_PDU;            /* RRCstateChange */
static int hf_pcap_RequestType_PDU;               /* RequestType */
static int hf_pcap_ResponseTime_PDU;              /* ResponseTime */
static int hf_pcap_HorizontalAccuracyCode_PDU;    /* HorizontalAccuracyCode */
static int hf_pcap_UE_PositioningCapability_PDU;  /* UE_PositioningCapability */
static int hf_pcap_NetworkAssistedGANSSSupport_PDU;  /* NetworkAssistedGANSSSupport */
static int hf_pcap_AddPosSupport_PDU;             /* AddPosSupport */
static int hf_pcap_GANSS_SBAS_IDs_PDU;            /* GANSS_SBAS_IDs */
static int hf_pcap_GANSS_Signal_IDs_PDU;          /* GANSS_Signal_IDs */
static int hf_pcap_SupportGANSSNonNativeADchoices_PDU;  /* SupportGANSSNonNativeADchoices */
static int hf_pcap_UTDOAPositioning_PDU;          /* UTDOAPositioning */
static int hf_pcap_EnvironmentCharacterisation_PDU;  /* EnvironmentCharacterisation */
static int hf_pcap_GPSPositioning_PDU;            /* GPSPositioning */
static int hf_pcap_GANSSPositioning_PDU;          /* GANSSPositioning */
static int hf_pcap_GANSScarrierPhaseRequested_PDU;  /* GANSScarrierPhaseRequested */
static int hf_pcap_GANSSMultiFreqMeasRequested_PDU;  /* GANSSMultiFreqMeasRequested */
static int hf_pcap_OTDOAAssistanceData_PDU;       /* OTDOAAssistanceData */
static int hf_pcap_VerticalAccuracyCode_PDU;      /* VerticalAccuracyCode */
static int hf_pcap_UTDOA_Group_PDU;               /* UTDOA_Group */
static int hf_pcap_Positioning_ResponseTime_PDU;  /* Positioning_ResponseTime */
static int hf_pcap_AmountOfReporting_PDU;         /* AmountOfReporting */
static int hf_pcap_IncludeVelocity_PDU;           /* IncludeVelocity */
static int hf_pcap_VelocityEstimate_PDU;          /* VelocityEstimate */
static int hf_pcap_UTRAN_GPSReferenceTime_PDU;    /* UTRAN_GPSReferenceTime */
static int hf_pcap_UTRAN_GANSSReferenceTimeResult_PDU;  /* UTRAN_GANSSReferenceTimeResult */
static int hf_pcap_PositionCalculationRequest_PDU;  /* PositionCalculationRequest */
static int hf_pcap_PositionCalculationResponse_PDU;  /* PositionCalculationResponse */
static int hf_pcap_PositionCalculationFailure_PDU;  /* PositionCalculationFailure */
static int hf_pcap_InformationExchangeInitiationRequest_PDU;  /* InformationExchangeInitiationRequest */
static int hf_pcap_InformationExchangeObjectType_InfEx_Rqst_PDU;  /* InformationExchangeObjectType_InfEx_Rqst */
static int hf_pcap_UC_ID_InfEx_Rqst_PDU;          /* UC_ID_InfEx_Rqst */
static int hf_pcap_InformationExchangeInitiationResponse_PDU;  /* InformationExchangeInitiationResponse */
static int hf_pcap_InformationExchangeObjectType_InfEx_Rsp_PDU;  /* InformationExchangeObjectType_InfEx_Rsp */
static int hf_pcap_InformationExchangeInitiationFailure_PDU;  /* InformationExchangeInitiationFailure */
static int hf_pcap_PositionInitiationRequest_PDU;  /* PositionInitiationRequest */
static int hf_pcap_PositionInitiationResponse_PDU;  /* PositionInitiationResponse */
static int hf_pcap_PositionInitiationFailure_PDU;  /* PositionInitiationFailure */
static int hf_pcap_PositionActivationRequest_PDU;  /* PositionActivationRequest */
static int hf_pcap_PositionActivationResponse_PDU;  /* PositionActivationResponse */
static int hf_pcap_PositionActivationFailure_PDU;  /* PositionActivationFailure */
static int hf_pcap_InformationReport_PDU;         /* InformationReport */
static int hf_pcap_InformationExchangeObjectType_InfEx_Rprt_PDU;  /* InformationExchangeObjectType_InfEx_Rprt */
static int hf_pcap_InformationExchangeTerminationRequest_PDU;  /* InformationExchangeTerminationRequest */
static int hf_pcap_InformationExchangeFailureIndication_PDU;  /* InformationExchangeFailureIndication */
static int hf_pcap_ErrorIndication_PDU;           /* ErrorIndication */
static int hf_pcap_PositionParameterModification_PDU;  /* PositionParameterModification */
static int hf_pcap_PrivateMessage_PDU;            /* PrivateMessage */
static int hf_pcap_Abort_PDU;                     /* Abort */
static int hf_pcap_PositionPeriodicReport_PDU;    /* PositionPeriodicReport */
static int hf_pcap_PositionPeriodicResult_PDU;    /* PositionPeriodicResult */
static int hf_pcap_PositionPeriodicTermination_PDU;  /* PositionPeriodicTermination */
static int hf_pcap_PCAP_PDU_PDU;                  /* PCAP_PDU */
static int hf_pcap_local;                         /* INTEGER_0_65535 */
static int hf_pcap_global;                        /* OBJECT_IDENTIFIER */
static int hf_pcap_shortTID;                      /* INTEGER_0_127 */
static int hf_pcap_longTID;                       /* INTEGER_0_32767 */
static int hf_pcap_ProtocolIE_Container_item;     /* ProtocolIE_Field */
static int hf_pcap_id;                            /* ProtocolIE_ID */
static int hf_pcap_criticality;                   /* Criticality */
static int hf_pcap_ie_field_value;                /* T_ie_field_value */
static int hf_pcap_ProtocolExtensionContainer_item;  /* ProtocolExtensionField */
static int hf_pcap_ext_id;                        /* ProtocolIE_ID */
static int hf_pcap_extensionValue;                /* T_extensionValue */
static int hf_pcap_PrivateIE_Container_item;      /* PrivateIE_Field */
static int hf_pcap_private_id;                    /* PrivateIE_ID */
static int hf_pcap_private_value;                 /* T_private_value */
static int hf_pcap_AddPos_MeasuredResults_item;   /* AddPos_MeasuredResults_Element */
static int hf_pcap_timestamp;                     /* UTCTime */
static int hf_pcap_type;                          /* T_type */
static int hf_pcap_barometricPressure;            /* T_barometricPressure */
static int hf_pcap_uncompensatedBarometricPressure;  /* BaroMeasurement */
static int hf_pcap_iE_Extensions;                 /* ProtocolExtensionContainer */
static int hf_pcap_wlan;                          /* T_wlan */
static int hf_pcap_wlanMeasurementList;           /* WLANMeasurementList */
static int hf_pcap_bt;                            /* T_bt */
static int hf_pcap_btMeasurementList;             /* BTMeasurementList */
static int hf_pcap_mbs;                           /* T_mbs */
static int hf_pcap_mbsMeasurementList;            /* MBSMeasurementList */
static int hf_pcap_WLANMeasurementList_item;      /* WLANMeasurementList_Element */
static int hf_pcap_wlanBSSID;                     /* OCTET_STRING_SIZE_6 */
static int hf_pcap_wlanSSID;                      /* OCTET_STRING_SIZE_1_32 */
static int hf_pcap_wlanRSSI;                      /* INTEGER_M127_128 */
static int hf_pcap_wlanRTTvalue;                  /* INTEGER_0_16777215 */
static int hf_pcap_wlanRTTunits;                  /* T_wlanRTTunits */
static int hf_pcap_wlanRTTaccuracy;               /* INTEGER_0_255 */
static int hf_pcap_wlanAPChannelFrequency;        /* INTEGER_0_256 */
static int hf_pcap_wlanServingFlag;               /* BOOLEAN */
static int hf_pcap_BTMeasurementList_item;        /* BTMeasurementList_Element */
static int hf_pcap_btADDR;                        /* OCTET_STRING_SIZE_6 */
static int hf_pcap_btRSSI;                        /* INTEGER_M127_128 */
static int hf_pcap_MBSMeasurementList_item;       /* MBSMeasurementList_Element */
static int hf_pcap_transmitterID;                 /* INTEGER_0_32767 */
static int hf_pcap_codephase;                     /* INTEGER_0_2097151 */
static int hf_pcap_codephaseRMS;                  /* INTEGER_0_63 */
static int hf_pcap_gpsAlmanacAndSatelliteHealth;  /* GPS_AlmanacAndSatelliteHealth */
static int hf_pcap_satMask;                       /* BIT_STRING_SIZE_1_32 */
static int hf_pcap_lsbTOW;                        /* BIT_STRING_SIZE_8 */
static int hf_pcap_radioNetwork;                  /* CauseRadioNetwork */
static int hf_pcap_transport;                     /* CauseTransport */
static int hf_pcap_protocol;                      /* CauseProtocol */
static int hf_pcap_misc;                          /* CauseMisc */
static int hf_pcap_CellId_MeasuredResultsSets_item;  /* CellId_MeasuredResultsInfoList */
static int hf_pcap_CellId_MeasuredResultsInfoList_item;  /* CellId_MeasuredResultsInfo */
static int hf_pcap_uC_ID;                         /* UC_ID */
static int hf_pcap_uTRANAccessPointPositionAltitude;  /* UTRANAccessPointPositionAltitude */
static int hf_pcap_ue_PositionEstimate;           /* UE_PositionEstimate */
static int hf_pcap_roundTripTimeInfo;             /* RoundTripTimeInfo */
static int hf_pcap_rxTimingDeviationInfo;         /* RxTimingDeviationInfo */
static int hf_pcap_rxTimingDeviationLCRInfo;      /* RxTimingDeviationLCRInfo */
static int hf_pcap_pathloss;                      /* Pathloss */
static int hf_pcap_ue_RxTxTimeDifferenceType2;    /* UE_RxTxTimeDifferenceType2 */
static int hf_pcap_ue_PositioningMeasQuality;     /* UE_PositioningMeasQuality */
static int hf_pcap_roundTripTime;                 /* RoundTripTime */
static int hf_pcap_ue_RxTxTimeDifferenceType1;    /* UE_RxTxTimeDifferenceType1 */
static int hf_pcap_extendedRoundTripTime;         /* ExtendedRoundTripTime */
static int hf_pcap_stdResolution;                 /* BIT_STRING_SIZE_2 */
static int hf_pcap_numberOfMeasurements;          /* BIT_STRING_SIZE_3 */
static int hf_pcap_stdOfMeasurements;             /* BIT_STRING_SIZE_5 */
static int hf_pcap_geographicalCoordinates;       /* GeographicalCoordinates */
static int hf_pcap_ga_AltitudeAndDirection;       /* GA_AltitudeAndDirection */
static int hf_pcap_rxTimingDeviation;             /* RxTimingDeviation */
static int hf_pcap_timingAdvance;                 /* TimingAdvance */
static int hf_pcap_rxTimingDeviationLCR;          /* RxTimingDeviationLCR */
static int hf_pcap_timingAdvanceLCR;              /* TimingAdvanceLCR */
static int hf_pcap_rxTimingDeviation768;          /* RxTimingDeviation768 */
static int hf_pcap_timingAdvance768;              /* TimingAdvance768 */
static int hf_pcap_rxTimingDeviation384ext;       /* RxTimingDeviation384ext */
static int hf_pcap_timingAdvance384ext;           /* TimingAdvance384ext */
static int hf_pcap_cpich_RSCP;                    /* CPICH_RSCP */
static int hf_pcap_cpich_EcNo;                    /* CPICH_EcNo */
static int hf_pcap_aOA_LCR;                       /* AOA_LCR */
static int hf_pcap_aOA_LCR_Accuracy_Class;        /* AOA_LCR_Accuracy_Class */
static int hf_pcap_CellId_IRATMeasuredResultsSets_item;  /* CellId_IRATMeasuredResultsInfoList */
static int hf_pcap_gERAN_MeasuredResultsInfoList;  /* GERAN_MeasuredResultsInfoList */
static int hf_pcap_iE_Extenstions;                /* ProtocolExtensionContainer */
static int hf_pcap_GERAN_MeasuredResultsInfoList_item;  /* GERAN_MeasuredResultsInfo */
static int hf_pcap_gERANCellID;                   /* GERANCellGlobalID */
static int hf_pcap_gERANPhysicalCellID;           /* GERANPhysicalCellID */
static int hf_pcap_gSM_RSSI;                      /* GSM_RSSI */
static int hf_pcap_plmn_Identity;                 /* PLMN_Identity */
static int hf_pcap_locationAreaCode;              /* BIT_STRING_SIZE_16 */
static int hf_pcap_cellIdentity;                  /* BIT_STRING_SIZE_16 */
static int hf_pcap_bsic;                          /* GSM_BSIC */
static int hf_pcap_arfcn;                         /* GSM_BCCH_ARFCN */
static int hf_pcap_networkColourCode;             /* BIT_STRING_SIZE_3 */
static int hf_pcap_baseStationColourCode;         /* BIT_STRING_SIZE_3 */
static int hf_pcap_requestedCellIDMeasurements;   /* RequestedCellIDMeasurements */
static int hf_pcap_fdd;                           /* T_fdd */
static int hf_pcap_roundTripTimeInfoWanted;       /* BOOLEAN */
static int hf_pcap_pathlossWanted;                /* BOOLEAN */
static int hf_pcap_roundTripTimeInfoWithType1Wanted;  /* BOOLEAN */
static int hf_pcap_cpichRSCPWanted;               /* BOOLEAN */
static int hf_pcap_cpicEcNoWanted;                /* BOOLEAN */
static int hf_pcap_tdd;                           /* T_tdd */
static int hf_pcap_rxTimingDeviationInfoWanted;   /* BOOLEAN */
static int hf_pcap_rxTimingDeviationLCRInfoWanted;  /* BOOLEAN */
static int hf_pcap_rxTimingDeviation768InfoWanted;  /* BOOLEAN */
static int hf_pcap_rxTimingDeviation384extInfoWanted;  /* BOOLEAN */
static int hf_pcap_angleOfArrivalLCRWanted;       /* BOOLEAN */
static int hf_pcap_timingAdvanceLCRWanted;        /* BOOLEAN */
static int hf_pcap_rSSIMeasurementsWanted;        /* BOOLEAN */
static int hf_pcap_procedureCode;                 /* ProcedureCode */
static int hf_pcap_triggeringMessage;             /* TriggeringMessage */
static int hf_pcap_procedureCriticality;          /* Criticality */
static int hf_pcap_transactionID;                 /* TransactionID */
static int hf_pcap_iEsCriticalityDiagnostics;     /* CriticalityDiagnostics_IE_List */
static int hf_pcap_CriticalityDiagnostics_IE_List_item;  /* CriticalityDiagnostics_IE_List_item */
static int hf_pcap_iECriticality;                 /* Criticality */
static int hf_pcap_iE_ID;                         /* ProtocolIE_ID */
static int hf_pcap_repetitionNumber;              /* CriticalityDiagnosticsRepetition */
static int hf_pcap_messageStructure;              /* MessageStructure */
static int hf_pcap_typeOfError;                   /* TypeOfError */
static int hf_pcap_gps_TOW_sec;                   /* INTEGER_0_604799 */
static int hf_pcap_statusHealth;                  /* DiffCorrectionStatus */
static int hf_pcap_dgps_CorrectionSatInfoList;    /* DGPS_CorrectionSatInfoList */
static int hf_pcap_DGPS_CorrectionSatInfoList_item;  /* DGPS_CorrectionSatInfo */
static int hf_pcap_satID;                         /* INTEGER_0_63 */
static int hf_pcap_iode;                          /* INTEGER_0_255 */
static int hf_pcap_udre;                          /* UDRE */
static int hf_pcap_prc;                           /* PRC */
static int hf_pcap_rrc;                           /* RRC */
static int hf_pcap_udreGrowthRate;                /* UDREGrowthRate */
static int hf_pcap_udreValidityTime;              /* UDREValidityTime */
static int hf_pcap_point;                         /* GA_Point */
static int hf_pcap_pointWithUnCertainty;          /* GA_PointWithUnCertainty */
static int hf_pcap_polygon;                       /* GA_Polygon */
static int hf_pcap_pointWithUncertaintyEllipse;   /* GA_PointWithUnCertaintyEllipse */
static int hf_pcap_pointWithAltitude;             /* GA_PointWithAltitude */
static int hf_pcap_pointWithAltitudeAndUncertaintyEllipsoid;  /* GA_PointWithAltitudeAndUncertaintyEllipsoid */
static int hf_pcap_ellipsoidArc;                  /* GA_EllipsoidArc */
static int hf_pcap_latitudeSign;                  /* T_latitudeSign */
static int hf_pcap_latitude;                      /* INTEGER_0_8388607 */
static int hf_pcap_longitude;                     /* INTEGER_M8388608_8388607 */
static int hf_pcap_directionOfAltitude;           /* T_directionOfAltitude */
static int hf_pcap_altitude;                      /* INTEGER_0_32767 */
static int hf_pcap_innerRadius;                   /* INTEGER_0_65535 */
static int hf_pcap_uncertaintyRadius;             /* INTEGER_0_127 */
static int hf_pcap_offsetAngle;                   /* INTEGER_0_179 */
static int hf_pcap_includedAngle;                 /* INTEGER_0_179 */
static int hf_pcap_confidence;                    /* INTEGER_0_100 */
static int hf_pcap_altitudeAndDirection;          /* GA_AltitudeAndDirection */
static int hf_pcap_uncertaintyEllipse;            /* GA_UncertaintyEllipse */
static int hf_pcap_uncertaintyAltitude;           /* INTEGER_0_127 */
static int hf_pcap_uncertaintyCode;               /* INTEGER_0_127 */
static int hf_pcap_GA_Polygon_item;               /* GA_Polygon_item */
static int hf_pcap_uncertaintySemi_major;         /* INTEGER_0_127 */
static int hf_pcap_uncertaintySemi_minor;         /* INTEGER_0_127 */
static int hf_pcap_orientationOfMajorAxis;        /* INTEGER_0_89 */
static int hf_pcap_referenceTimeChoice;           /* ReferenceTimeChoice */
static int hf_pcap_ue_positionEstimate;           /* UE_PositionEstimate */
static int hf_pcap_utran_GPSReferenceTimeResult;  /* UTRAN_GPSReferenceTimeResult */
static int hf_pcap_gps_ReferenceTimeOnly;         /* INTEGER_0_604799999_ */
static int hf_pcap_cell_Timing;                   /* Cell_Timing */
static int hf_pcap_extension_ReferenceTimeChoice;  /* Extension_ReferenceTimeChoice */
static int hf_pcap_sfn;                           /* INTEGER_0_4095 */
static int hf_pcap_ganssTODmsec;                  /* INTEGER_0_3599999 */
static int hf_pcap_ganssTimeID;                   /* GANSSID */
static int hf_pcap_positionData;                  /* BIT_STRING_SIZE_16 */
static int hf_pcap_positioningDataDiscriminator;  /* PositioningDataDiscriminator */
static int hf_pcap_positioningDataSet;            /* PositioningDataSet */
static int hf_pcap_GANSS_PositioningDataSet_item;  /* GANSS_PositioningMethodAndUsage */
static int hf_pcap_PositioningDataSet_item;       /* PositioningMethodAndUsage */
static int hf_pcap_Additional_PositioningDataSet_item;  /* Additional_PositioningMethodAndUsage */
static int hf_pcap_gps_TOW_1msec;                 /* INTEGER_0_604799999 */
static int hf_pcap_satelliteInformationList;      /* AcquisitionSatInfoList */
static int hf_pcap_AcquisitionSatInfoList_item;   /* AcquisitionSatInfo */
static int hf_pcap_doppler0thOrder;               /* INTEGER_M2048_2047 */
static int hf_pcap_extraDopplerInfo;              /* ExtraDopplerInfo */
static int hf_pcap_codePhase;                     /* INTEGER_0_1022 */
static int hf_pcap_integerCodePhase;              /* INTEGER_0_19 */
static int hf_pcap_gps_BitNumber;                 /* INTEGER_0_3 */
static int hf_pcap_codePhaseSearchWindow;         /* CodePhaseSearchWindow */
static int hf_pcap_azimuthAndElevation;           /* AzimuthAndElevation */
static int hf_pcap_doppler1stOrder;               /* INTEGER_M42_21 */
static int hf_pcap_dopplerUncertainty;            /* DopplerUncertainty */
static int hf_pcap_dopplerUncertaintyExtension;   /* DopplerUncertaintyExtension */
static int hf_pcap_azimuth;                       /* INTEGER_0_31 */
static int hf_pcap_elevation;                     /* INTEGER_0_7 */
static int hf_pcap_azimuthLSB;                    /* INTEGER_0_15 */
static int hf_pcap_elevationLSB;                  /* INTEGER_0_15 */
static int hf_pcap_AuxInfoGANSS_ID1_item;         /* AuxInfoGANSS_ID1_element */
static int hf_pcap_svID;                          /* INTEGER_0_63 */
static int hf_pcap_signalsAvailable;              /* BIT_STRING_SIZE_8 */
static int hf_pcap_ie_Extensions;                 /* ProtocolExtensionContainer */
static int hf_pcap_AuxInfoGANSS_ID3_item;         /* AuxInfoGANSS_ID3_element */
static int hf_pcap_channelNumber;                 /* INTEGER_M7_13 */
static int hf_pcap_cnavToc;                       /* BIT_STRING_SIZE_11 */
static int hf_pcap_cnavTop;                       /* BIT_STRING_SIZE_11 */
static int hf_pcap_cnavURA0;                      /* BIT_STRING_SIZE_5 */
static int hf_pcap_cnavURA1;                      /* BIT_STRING_SIZE_3 */
static int hf_pcap_cnavURA2;                      /* BIT_STRING_SIZE_3 */
static int hf_pcap_cnavAf2;                       /* BIT_STRING_SIZE_10 */
static int hf_pcap_cnavAf1;                       /* BIT_STRING_SIZE_20 */
static int hf_pcap_cnavAf0;                       /* BIT_STRING_SIZE_26 */
static int hf_pcap_cnavTgd;                       /* BIT_STRING_SIZE_13 */
static int hf_pcap_cnavISCl1cp;                   /* BIT_STRING_SIZE_13 */
static int hf_pcap_cnavISCl1cd;                   /* BIT_STRING_SIZE_13 */
static int hf_pcap_cnavISCl1ca;                   /* BIT_STRING_SIZE_13 */
static int hf_pcap_cnavISCl2c;                    /* BIT_STRING_SIZE_13 */
static int hf_pcap_cnavISCl5i5;                   /* BIT_STRING_SIZE_13 */
static int hf_pcap_cnavISCl5q5;                   /* BIT_STRING_SIZE_13 */
static int hf_pcap_b1;                            /* BIT_STRING_SIZE_11 */
static int hf_pcap_b2;                            /* BIT_STRING_SIZE_10 */
static int hf_pcap_dGANSS_ReferenceTime;          /* INTEGER_0_119 */
static int hf_pcap_dGANSS_Information;            /* DGANSS_Information */
static int hf_pcap_DGANSS_Information_item;       /* DGANSS_InformationItem */
static int hf_pcap_gANSS_SignalId;                /* GANSS_SignalID */
static int hf_pcap_gANSS_StatusHealth;            /* GANSS_StatusHealth */
static int hf_pcap_dGANSS_SignalInformation;      /* DGANSS_SignalInformation */
static int hf_pcap_DGANSS_SignalInformation_item;  /* DGANSS_SignalInformationItem */
static int hf_pcap_satId;                         /* INTEGER_0_63 */
static int hf_pcap_gANSS_iod;                     /* BIT_STRING_SIZE_10 */
static int hf_pcap_ganss_prc;                     /* INTEGER_M2047_2047 */
static int hf_pcap_ganss_rrc;                     /* INTEGER_M127_127 */
static int hf_pcap_navClockModel;                 /* NAVclockModel */
static int hf_pcap_cnavClockModel;                /* CNAVclockModel */
static int hf_pcap_glonassClockModel;             /* GLONASSclockModel */
static int hf_pcap_sbasClockModel;                /* SBASclockModel */
static int hf_pcap_bDSClockModel;                 /* BDSClockModel */
static int hf_pcap_navKeplerianSet;               /* NavModel_NAVKeplerianSet */
static int hf_pcap_cnavKeplerianSet;              /* NavModel_CNAVKeplerianSet */
static int hf_pcap_glonassECEF;                   /* NavModel_GLONASSecef */
static int hf_pcap_sbasECEF;                      /* NavModel_SBASecef */
static int hf_pcap_bDSKeplerianSet;               /* NavModel_BDSKeplerianSet */
static int hf_pcap_dataID;                        /* BIT_STRING_SIZE_2 */
static int hf_pcap_alpha_beta_parameters;         /* GPS_Ionospheric_Model */
static int hf_pcap_non_broadcastIndication;       /* T_non_broadcastIndication */
static int hf_pcap_ganssSatInfoNavList;           /* Ganss_Sat_Info_AddNavList */
static int hf_pcap_GANSS_Additional_Time_Models_item;  /* GANSS_Time_Model */
static int hf_pcap_utcModel1;                     /* UTCmodelSet1 */
static int hf_pcap_utcModel2;                     /* UTCmodelSet2 */
static int hf_pcap_utcModel3;                     /* UTCmodelSet3 */
static int hf_pcap_utcModel4;                     /* UTCmodelSet4 */
static int hf_pcap_satellite_Information_BDS_KP_List;  /* Satellite_Information_BDS_KP_List */
static int hf_pcap_Satellite_Information_BDS_KP_List_item;  /* Satellite_Information_BDS_KP_Item */
static int hf_pcap_sVID_BDS;                      /* INTEGER_0_63 */
static int hf_pcap_tOA_BDS;                       /* BIT_STRING_SIZE_8 */
static int hf_pcap_a21_BDS;                       /* BIT_STRING_SIZE_24 */
static int hf_pcap_e_BDS;                         /* BIT_STRING_SIZE_17 */
static int hf_pcap_omg_lower_BDS;                 /* BIT_STRING_SIZE_24 */
static int hf_pcap_m0_BDS;                        /* BIT_STRING_SIZE_24 */
static int hf_pcap_omg_0_BDS;                     /* BIT_STRING_SIZE_24 */
static int hf_pcap_omg_upper_BDS;                 /* BIT_STRING_SIZE_17 */
static int hf_pcap_delta_i_BDS;                   /* BIT_STRING_SIZE_16 */
static int hf_pcap_a0_BDS;                        /* BIT_STRING_SIZE_11 */
static int hf_pcap_a1_BDS;                        /* BIT_STRING_SIZE_11 */
static int hf_pcap_hea_BDS;                       /* BIT_STRING_SIZE_9 */
static int hf_pcap_sat_info_SBASecefList;         /* GANSS_SAT_Info_Almanac_SBASecefList */
static int hf_pcap_sat_info_GLOkpList;            /* GANSS_SAT_Info_Almanac_GLOkpList */
static int hf_pcap_t_oa;                          /* INTEGER_0_255 */
static int hf_pcap_sat_info_MIDIkpList;           /* GANSS_SAT_Info_Almanac_MIDIkpList */
static int hf_pcap_sat_info_NAVkpList;            /* GANSS_SAT_Info_Almanac_NAVkpList */
static int hf_pcap_sat_info_REDkpList;            /* GANSS_SAT_Info_Almanac_REDkpList */
static int hf_pcap_weekNumber;                    /* INTEGER_0_255 */
static int hf_pcap_gANSS_AlmanacModel;            /* GANSS_AlmanacModel */
static int hf_pcap_gANSS_keplerianParameters;     /* GANSS_KeplerianParametersAlm */
static int hf_pcap_extension_GANSS_AlmanacModel;  /* Extension_GANSS_AlmanacModel */
static int hf_pcap_ganssID1;                      /* AuxInfoGANSS_ID1 */
static int hf_pcap_ganssID3;                      /* AuxInfoGANSS_ID3 */
static int hf_pcap_elevation_01;                  /* INTEGER_0_75 */
static int hf_pcap_GANSS_Clock_Model_item;        /* GANSS_SatelliteClockModelItem */
static int hf_pcap_ganss_Reference_Time;          /* GANSS_Reference_Time */
static int hf_pcap_ganss_Ionospheric_Model;       /* GANSS_Ionospheric_Model */
static int hf_pcap_ganss_Reference_Location;      /* GANSS_Reference_Location */
static int hf_pcap_ganssTod;                      /* INTEGER_0_59_ */
static int hf_pcap_dataBitAssistancelist;         /* GANSS_DataBitAssistanceList */
static int hf_pcap_GANSS_DataBitAssistanceList_item;  /* GANSS_DataBitAssistanceItem */
static int hf_pcap_dataBitAssistanceSgnList;      /* GANSS_DataBitAssistanceSgnList */
static int hf_pcap_GANSS_DataBitAssistanceSgnList_item;  /* GANSS_DataBitAssistanceSgnItem */
static int hf_pcap_ganss_SignalId;                /* GANSS_SignalID */
static int hf_pcap_ganssDataBits;                 /* BIT_STRING_SIZE_1_1024 */
static int hf_pcap_teop;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_pmX;                           /* BIT_STRING_SIZE_21 */
static int hf_pcap_pmXdot;                        /* BIT_STRING_SIZE_15 */
static int hf_pcap_pmY;                           /* BIT_STRING_SIZE_21 */
static int hf_pcap_pmYdot;                        /* BIT_STRING_SIZE_15 */
static int hf_pcap_deltaUT1;                      /* BIT_STRING_SIZE_31 */
static int hf_pcap_deltaUT1dot;                   /* BIT_STRING_SIZE_19 */
static int hf_pcap_dopplerFirstOrder;             /* INTEGER_M42_21 */
static int hf_pcap_dopplerUncertainty_01;         /* T_dopplerUncertainty */
static int hf_pcap_dopplerUncertaintyExtension_01;  /* T_dopplerUncertaintyExtension */
static int hf_pcap_GANSS_GenericAssistanceDataList_item;  /* GANSSGenericAssistanceData */
static int hf_pcap_ganssId;                       /* GANSSID */
static int hf_pcap_ganss_Real_Time_Integrity;     /* GANSS_Real_Time_Integrity */
static int hf_pcap_ganss_DataBitAssistance;       /* GANSS_Data_Bit_Assistance */
static int hf_pcap_dganss_Corrections;            /* DGANSS_Corrections */
static int hf_pcap_ganss_AlmanacAndSatelliteHealth;  /* GANSS_AlmanacAndSatelliteHealth */
static int hf_pcap_ganss_ReferenceMeasurementInfo;  /* GANSS_ReferenceMeasurementInfo */
static int hf_pcap_ganss_UTC_Model;               /* GANSS_UTC_Model */
static int hf_pcap_ganss_Time_Model;              /* GANSS_Time_Model */
static int hf_pcap_ganss_Navigation_Model;        /* GANSS_Navigation_Model */
static int hf_pcap_bDS_Reference_Time;            /* BDS_Reference_Time */
static int hf_pcap_bDS_Ionospheric_Grid_Information;  /* BDS_Ionospheric_Grid_Information */
static int hf_pcap_BDS_Ionospheric_Grid_Information_item;  /* BDS_Ionospheric_Grid_Information_item */
static int hf_pcap_iGP_number_BDS;                /* INTEGER_1_320 */
static int hf_pcap_vertical_Delay_BDS;            /* BIT_STRING_SIZE_9 */
static int hf_pcap_gIVEI_BDS;                     /* BIT_STRING_SIZE_4 */
static int hf_pcap_dBDS_Information;              /* DBDS_Information */
static int hf_pcap_DBDS_Information_item;         /* DBDS_Information_item */
static int hf_pcap_dBDS_Signal_ID;                /* GANSSID */
static int hf_pcap_dGANSS_Signal_Information;     /* DGANSS_Signal_Information */
static int hf_pcap_DGANSS_Signal_Information_item;  /* DGANSS_Signal_Information_item */
static int hf_pcap_sat_ID_BDS;                    /* INTEGER_0_63 */
static int hf_pcap_uDREI_BDS;                     /* INTEGER_0_15 */
static int hf_pcap_rURAI_BDS;                     /* INTEGER_0_15 */
static int hf_pcap_delta_t_BDS;                   /* BIT_STRING_SIZE_13 */
static int hf_pcap_GANSS_GenericMeasurementInfo_item;  /* GANSS_GenericMeasurementInfo_item */
static int hf_pcap_ganssMeasurementSignalList;    /* GANSSMeasurementSignalList */
static int hf_pcap_ganss_ID;                      /* INTEGER_0_7 */
static int hf_pcap_GANSSMeasurementSignalList_item;  /* GANSSMeasurementSignalList_item */
static int hf_pcap_ganssSignalId;                 /* GANSS_SignalID */
static int hf_pcap_ganssCodePhaseAmbiguity;       /* INTEGER_0_31 */
static int hf_pcap_ganssMeasurementParameters;    /* GANSS_MeasurementParameters */
static int hf_pcap_ganssCodePhaseAmbiguity_ext;   /* INTEGER_32_127 */
static int hf_pcap_alpha_zero_ionos;              /* BIT_STRING_SIZE_11 */
static int hf_pcap_alpha_one_ionos;               /* BIT_STRING_SIZE_11 */
static int hf_pcap_alpha_two_ionos;               /* BIT_STRING_SIZE_14 */
static int hf_pcap_gANSS_IonosphereRegionalStormFlags;  /* GANSS_IonosphereRegionalStormFlags */
static int hf_pcap_storm_flag_one;                /* BOOLEAN */
static int hf_pcap_storm_flag_two;                /* BOOLEAN */
static int hf_pcap_storm_flag_three;              /* BOOLEAN */
static int hf_pcap_storm_flag_four;               /* BOOLEAN */
static int hf_pcap_storm_flag_five;               /* BOOLEAN */
static int hf_pcap_t_oa_01;                       /* INTEGER_0_1023 */
static int hf_pcap_iod_a;                         /* INTEGER_0_15 */
static int hf_pcap_gANSS_SatelliteInformationKP;  /* GANSS_SatelliteInformationKP */
static int hf_pcap_toe_nav;                       /* BIT_STRING_SIZE_14 */
static int hf_pcap_ganss_omega_nav;               /* BIT_STRING_SIZE_32 */
static int hf_pcap_delta_n_nav;                   /* BIT_STRING_SIZE_16 */
static int hf_pcap_m_zero_nav;                    /* BIT_STRING_SIZE_32 */
static int hf_pcap_omegadot_nav;                  /* BIT_STRING_SIZE_24 */
static int hf_pcap_ganss_e_nav;                   /* BIT_STRING_SIZE_32 */
static int hf_pcap_idot_nav;                      /* BIT_STRING_SIZE_14 */
static int hf_pcap_a_sqrt_nav;                    /* BIT_STRING_SIZE_32 */
static int hf_pcap_i_zero_nav;                    /* BIT_STRING_SIZE_32 */
static int hf_pcap_omega_zero_nav;                /* BIT_STRING_SIZE_32 */
static int hf_pcap_c_rs_nav;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_c_is_nav;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_c_us_nav;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_c_rc_nav;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_c_ic_nav;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_c_uc_nav;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_GANSS_MeasurementParameters_item;  /* GANSS_MeasurementParametersItem */
static int hf_pcap_cToNzero;                      /* INTEGER_0_63 */
static int hf_pcap_multipathIndicator;            /* T_multipathIndicator */
static int hf_pcap_carrierQualityIndication;      /* BIT_STRING_SIZE_2 */
static int hf_pcap_ganssCodePhase;                /* INTEGER_0_2097151 */
static int hf_pcap_ganssIntegerCodePhase;         /* INTEGER_0_63 */
static int hf_pcap_codePhaseRmsError;             /* INTEGER_0_63 */
static int hf_pcap_doppler;                       /* INTEGER_M32768_32767 */
static int hf_pcap_adr;                           /* INTEGER_0_33554431 */
static int hf_pcap_ganssIntegerCodePhase_ext;     /* INTEGER_64_127 */
static int hf_pcap_GANSS_MeasuredResultsList_item;  /* GANSS_MeasuredResults */
static int hf_pcap_referenceTime;                 /* T_referenceTime */
static int hf_pcap_utranReferenceTime;            /* UTRAN_GANSSReferenceTimeUL */
static int hf_pcap_ganssReferenceTimeOnly;        /* GANSS_ReferenceTimeOnly */
static int hf_pcap_ganssGenericMeasurementInfo;   /* GANSS_GenericMeasurementInfo */
static int hf_pcap_non_broadcastIndication_01;    /* T_non_broadcastIndication_01 */
static int hf_pcap_ganssSatInfoNav;               /* GANSS_Sat_Info_Nav */
static int hf_pcap_gANSS_keplerianParameters_01;  /* GANSS_KeplerianParametersOrb */
static int hf_pcap_GANSS_Real_Time_Integrity_item;  /* GANSS_RealTimeInformationItem */
static int hf_pcap_bad_ganss_satId;               /* INTEGER_0_63 */
static int hf_pcap_bad_ganss_signalId;            /* BIT_STRING_SIZE_8 */
static int hf_pcap_satelliteInformation;          /* GANSS_SatelliteInformation */
static int hf_pcap_ganssDay;                      /* INTEGER_0_8191 */
static int hf_pcap_ganssTod_01;                   /* INTEGER_0_86399 */
static int hf_pcap_ganssTodUncertainty;           /* INTEGER_0_127 */
static int hf_pcap_ganssTimeId;                   /* GANSSID */
static int hf_pcap_utran_ganssreferenceTime;      /* UTRAN_GANSSReferenceTimeDL */
static int hf_pcap_tutran_ganss_driftRate;        /* TUTRAN_GANSS_DriftRate */
static int hf_pcap_gANSS_tod;                     /* INTEGER_0_3599999 */
static int hf_pcap_gANSS_timeId;                  /* GANSSID */
static int hf_pcap_gANSS_TimeUncertainty;         /* INTEGER_0_127 */
static int hf_pcap_t_oc;                          /* BIT_STRING_SIZE_14 */
static int hf_pcap_a_i2;                          /* BIT_STRING_SIZE_6 */
static int hf_pcap_a_i1;                          /* BIT_STRING_SIZE_21 */
static int hf_pcap_a_i0;                          /* BIT_STRING_SIZE_31 */
static int hf_pcap_t_gd;                          /* BIT_STRING_SIZE_10 */
static int hf_pcap_sisa;                          /* BIT_STRING_SIZE_8 */
static int hf_pcap_model_id;                      /* INTEGER_0_3 */
static int hf_pcap_GANSS_SatelliteInformation_item;  /* GANSS_SatelliteInformationItem */
static int hf_pcap_ganssSatId;                    /* INTEGER_0_63 */
static int hf_pcap_dopplerZeroOrder;              /* INTEGER_M2048_2047 */
static int hf_pcap_extraDoppler;                  /* GANSS_ExtraDoppler */
static int hf_pcap_codePhase_01;                  /* INTEGER_0_1023 */
static int hf_pcap_integerCodePhase_01;           /* INTEGER_0_127 */
static int hf_pcap_codePhaseSearchWindow_01;      /* INTEGER_0_31 */
static int hf_pcap_azimuthAndElevation_01;        /* GANSS_AzimuthAndElevation */
static int hf_pcap_GANSS_SatelliteInformationKP_item;  /* GANSS_SatelliteInformationKPItem */
static int hf_pcap_ganss_e_alm;                   /* BIT_STRING_SIZE_11 */
static int hf_pcap_ganss_delta_I_alm;             /* BIT_STRING_SIZE_11 */
static int hf_pcap_ganss_omegadot_alm;            /* BIT_STRING_SIZE_11 */
static int hf_pcap_ganss_svStatusINAV_alm;        /* BIT_STRING_SIZE_4 */
static int hf_pcap_ganss_svStatusFNAV_alm;        /* BIT_STRING_SIZE_2 */
static int hf_pcap_ganss_delta_a_sqrt_alm;        /* BIT_STRING_SIZE_13 */
static int hf_pcap_ganss_omegazero_alm;           /* BIT_STRING_SIZE_16 */
static int hf_pcap_ganss_m_zero_alm;              /* BIT_STRING_SIZE_16 */
static int hf_pcap_ganss_omega_alm;               /* BIT_STRING_SIZE_16 */
static int hf_pcap_ganss_af_zero_alm;             /* BIT_STRING_SIZE_16 */
static int hf_pcap_ganss_af_one_alm;              /* BIT_STRING_SIZE_13 */
static int hf_pcap_GANSS_SAT_Info_Almanac_GLOkpList_item;  /* GANSS_SAT_Info_Almanac_GLOkp */
static int hf_pcap_gloAlmNA;                      /* BIT_STRING_SIZE_11 */
static int hf_pcap_gloAlmnA;                      /* BIT_STRING_SIZE_5 */
static int hf_pcap_gloAlmHA;                      /* BIT_STRING_SIZE_5 */
static int hf_pcap_gloAlmLambdaA;                 /* BIT_STRING_SIZE_21 */
static int hf_pcap_gloAlmTlambdaA;                /* BIT_STRING_SIZE_21 */
static int hf_pcap_gloAlmDeltaIA;                 /* BIT_STRING_SIZE_18 */
static int hf_pcap_gloAkmDeltaTA;                 /* BIT_STRING_SIZE_22 */
static int hf_pcap_gloAlmDeltaTdotA;              /* BIT_STRING_SIZE_7 */
static int hf_pcap_gloAlmEpsilonA;                /* BIT_STRING_SIZE_15 */
static int hf_pcap_gloAlmOmegaA;                  /* BIT_STRING_SIZE_16 */
static int hf_pcap_gloAlmTauA;                    /* BIT_STRING_SIZE_10 */
static int hf_pcap_gloAlmCA;                      /* BIT_STRING_SIZE_1 */
static int hf_pcap_gloAlmMA;                      /* BIT_STRING_SIZE_2 */
static int hf_pcap_GANSS_SAT_Info_Almanac_MIDIkpList_item;  /* GANSS_SAT_Info_Almanac_MIDIkp */
static int hf_pcap_midiAlmE;                      /* BIT_STRING_SIZE_11 */
static int hf_pcap_midiAlmDeltaI;                 /* BIT_STRING_SIZE_11 */
static int hf_pcap_midiAlmOmegaDot;               /* BIT_STRING_SIZE_11 */
static int hf_pcap_midiAlmSqrtA;                  /* BIT_STRING_SIZE_17 */
static int hf_pcap_midiAlmOmega0;                 /* BIT_STRING_SIZE_16 */
static int hf_pcap_midiAlmOmega;                  /* BIT_STRING_SIZE_16 */
static int hf_pcap_midiAlmMo;                     /* BIT_STRING_SIZE_16 */
static int hf_pcap_midiAlmaf0;                    /* BIT_STRING_SIZE_11 */
static int hf_pcap_midiAlmaf1;                    /* BIT_STRING_SIZE_10 */
static int hf_pcap_midiAlmL1Health;               /* BIT_STRING_SIZE_1 */
static int hf_pcap_midiAlmL2Health;               /* BIT_STRING_SIZE_1 */
static int hf_pcap_midiAlmL5Health;               /* BIT_STRING_SIZE_1 */
static int hf_pcap_GANSS_SAT_Info_Almanac_NAVkpList_item;  /* GANSS_SAT_Info_Almanac_NAVkp */
static int hf_pcap_navAlmE;                       /* BIT_STRING_SIZE_16 */
static int hf_pcap_navAlmDeltaI;                  /* BIT_STRING_SIZE_16 */
static int hf_pcap_navAlmOMEGADOT;                /* BIT_STRING_SIZE_16 */
static int hf_pcap_navAlmSVHealth;                /* BIT_STRING_SIZE_8 */
static int hf_pcap_navAlmSqrtA;                   /* BIT_STRING_SIZE_24 */
static int hf_pcap_navAlmOMEGAo;                  /* BIT_STRING_SIZE_24 */
static int hf_pcap_navAlmOmega;                   /* BIT_STRING_SIZE_24 */
static int hf_pcap_navAlmMo;                      /* BIT_STRING_SIZE_24 */
static int hf_pcap_navAlmaf0;                     /* BIT_STRING_SIZE_11 */
static int hf_pcap_navAlmaf1;                     /* BIT_STRING_SIZE_11 */
static int hf_pcap_GANSS_SAT_Info_Almanac_REDkpList_item;  /* GANSS_SAT_Info_Almanac_REDkp */
static int hf_pcap_redAlmDeltaA;                  /* BIT_STRING_SIZE_8 */
static int hf_pcap_redAlmOmega0;                  /* BIT_STRING_SIZE_7 */
static int hf_pcap_redAlmPhi0;                    /* BIT_STRING_SIZE_7 */
static int hf_pcap_redAlmL1Health;                /* BIT_STRING_SIZE_1 */
static int hf_pcap_redAlmL2Health;                /* BIT_STRING_SIZE_1 */
static int hf_pcap_redAlmL5Health;                /* BIT_STRING_SIZE_1 */
static int hf_pcap_GANSS_SAT_Info_Almanac_SBASecefList_item;  /* GANSS_SAT_Info_Almanac_SBASecef */
static int hf_pcap_sbasAlmDataID;                 /* BIT_STRING_SIZE_2 */
static int hf_pcap_sbasAlmHealth;                 /* BIT_STRING_SIZE_8 */
static int hf_pcap_sbasAlmXg;                     /* BIT_STRING_SIZE_15 */
static int hf_pcap_sbasAlmYg;                     /* BIT_STRING_SIZE_15 */
static int hf_pcap_sbasAlmZg;                     /* BIT_STRING_SIZE_9 */
static int hf_pcap_sbasAlmXgdot;                  /* BIT_STRING_SIZE_3 */
static int hf_pcap_sbasAlmYgDot;                  /* BIT_STRING_SIZE_3 */
static int hf_pcap_sbasAlmZgDot;                  /* BIT_STRING_SIZE_4 */
static int hf_pcap_sbasAlmTo;                     /* BIT_STRING_SIZE_11 */
static int hf_pcap_Ganss_Sat_Info_AddNavList_item;  /* Ganss_Sat_Info_AddNavList_item */
static int hf_pcap_svHealth;                      /* BIT_STRING_SIZE_6 */
static int hf_pcap_iod;                           /* BIT_STRING_SIZE_11 */
static int hf_pcap_ganssAddClockModels;           /* GANSS_AddClockModels */
static int hf_pcap_ganssAddOrbitModels;           /* GANSS_AddOrbitModels */
static int hf_pcap_GANSS_Sat_Info_Nav_item;       /* GANSS_Sat_Info_Nav_item */
static int hf_pcap_svHealth_01;                   /* BIT_STRING_SIZE_9 */
static int hf_pcap_iod_01;                        /* BIT_STRING_SIZE_10 */
static int hf_pcap_ganssClockModel;               /* GANSS_Clock_Model */
static int hf_pcap_ganssOrbitModel;               /* GANSS_Orbit_Model */
static int hf_pcap_ganssSignalID;                 /* INTEGER_0_3_ */
static int hf_pcap_ganss_time_model_refTime;      /* INTEGER_0_37799 */
static int hf_pcap_ganss_t_a0;                    /* INTEGER_M2147483648_2147483647 */
static int hf_pcap_ganss_t_a1;                    /* INTEGER_M8388608_8388607 */
static int hf_pcap_ganss_t_a2;                    /* INTEGER_M64_63 */
static int hf_pcap_gnss_to_id;                    /* T_gnss_to_id */
static int hf_pcap_ganss_wk_number;               /* INTEGER_0_8191 */
static int hf_pcap_gANSS_UTRAN_TimeRelationshipUncertainty;  /* GANSS_UTRAN_TimeRelationshipUncertainty */
static int hf_pcap_a_one_utc;                     /* BIT_STRING_SIZE_24 */
static int hf_pcap_a_zero_utc;                    /* BIT_STRING_SIZE_32 */
static int hf_pcap_t_ot_utc;                      /* BIT_STRING_SIZE_8 */
static int hf_pcap_w_n_t_utc;                     /* BIT_STRING_SIZE_8 */
static int hf_pcap_delta_t_ls_utc;                /* BIT_STRING_SIZE_8 */
static int hf_pcap_w_n_lsf_utc;                   /* BIT_STRING_SIZE_8 */
static int hf_pcap_dn_utc;                        /* BIT_STRING_SIZE_8 */
static int hf_pcap_delta_t_lsf_utc;               /* BIT_STRING_SIZE_8 */
static int hf_pcap_gloTau;                        /* BIT_STRING_SIZE_22 */
static int hf_pcap_gloGamma;                      /* BIT_STRING_SIZE_11 */
static int hf_pcap_gloDeltaTau;                   /* BIT_STRING_SIZE_5 */
static int hf_pcap_navToc;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navaf2;                        /* BIT_STRING_SIZE_8 */
static int hf_pcap_navaf1;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navaf0;                        /* BIT_STRING_SIZE_22 */
static int hf_pcap_navTgd;                        /* BIT_STRING_SIZE_8 */
static int hf_pcap_cnavURAindex;                  /* BIT_STRING_SIZE_5 */
static int hf_pcap_cnavDeltaA;                    /* BIT_STRING_SIZE_26 */
static int hf_pcap_cnavAdot;                      /* BIT_STRING_SIZE_25 */
static int hf_pcap_cnavDeltaNo;                   /* BIT_STRING_SIZE_17 */
static int hf_pcap_cnavDeltaNoDot;                /* BIT_STRING_SIZE_23 */
static int hf_pcap_cnavMo;                        /* BIT_STRING_SIZE_33 */
static int hf_pcap_cnavE;                         /* BIT_STRING_SIZE_33 */
static int hf_pcap_cnavOmega;                     /* BIT_STRING_SIZE_33 */
static int hf_pcap_cnavOMEGA0;                    /* BIT_STRING_SIZE_33 */
static int hf_pcap_cnavDeltaOmegaDot;             /* BIT_STRING_SIZE_17 */
static int hf_pcap_cnavIo;                        /* BIT_STRING_SIZE_33 */
static int hf_pcap_cnavIoDot;                     /* BIT_STRING_SIZE_15 */
static int hf_pcap_cnavCis;                       /* BIT_STRING_SIZE_16 */
static int hf_pcap_cnavCic;                       /* BIT_STRING_SIZE_16 */
static int hf_pcap_cnavCrs;                       /* BIT_STRING_SIZE_24 */
static int hf_pcap_cnavCrc;                       /* BIT_STRING_SIZE_24 */
static int hf_pcap_cnavCus;                       /* BIT_STRING_SIZE_21 */
static int hf_pcap_cnavCuc;                       /* BIT_STRING_SIZE_21 */
static int hf_pcap_gloEn;                         /* BIT_STRING_SIZE_5 */
static int hf_pcap_gloP1;                         /* BIT_STRING_SIZE_2 */
static int hf_pcap_gloP2;                         /* BIT_STRING_SIZE_1 */
static int hf_pcap_gloM;                          /* BIT_STRING_SIZE_2 */
static int hf_pcap_gloX;                          /* BIT_STRING_SIZE_27 */
static int hf_pcap_gloXdot;                       /* BIT_STRING_SIZE_24 */
static int hf_pcap_gloXdotdot;                    /* BIT_STRING_SIZE_5 */
static int hf_pcap_gloY;                          /* BIT_STRING_SIZE_27 */
static int hf_pcap_gloYdot;                       /* BIT_STRING_SIZE_24 */
static int hf_pcap_gloYdotdot;                    /* BIT_STRING_SIZE_5 */
static int hf_pcap_gloZ;                          /* BIT_STRING_SIZE_27 */
static int hf_pcap_gloZdot;                       /* BIT_STRING_SIZE_24 */
static int hf_pcap_gloZdotdot;                    /* BIT_STRING_SIZE_5 */
static int hf_pcap_navURA;                        /* BIT_STRING_SIZE_4 */
static int hf_pcap_navFitFlag;                    /* BIT_STRING_SIZE_1 */
static int hf_pcap_navToe;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navOmega;                      /* BIT_STRING_SIZE_32 */
static int hf_pcap_navDeltaN;                     /* BIT_STRING_SIZE_16 */
static int hf_pcap_navM0;                         /* BIT_STRING_SIZE_32 */
static int hf_pcap_navOmegaADot;                  /* BIT_STRING_SIZE_24 */
static int hf_pcap_navE;                          /* BIT_STRING_SIZE_32 */
static int hf_pcap_navIDot;                       /* BIT_STRING_SIZE_14 */
static int hf_pcap_navAPowerHalf;                 /* BIT_STRING_SIZE_32 */
static int hf_pcap_navI0;                         /* BIT_STRING_SIZE_32 */
static int hf_pcap_navOmegaA0;                    /* BIT_STRING_SIZE_32 */
static int hf_pcap_navCrs;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navCis;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navCus;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navCrc;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navCic;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_navCuc;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_sbasTo;                        /* BIT_STRING_SIZE_13 */
static int hf_pcap_sbasAccuracy;                  /* BIT_STRING_SIZE_4 */
static int hf_pcap_sbasXg;                        /* BIT_STRING_SIZE_30 */
static int hf_pcap_sbasYg;                        /* BIT_STRING_SIZE_30 */
static int hf_pcap_sbasZg;                        /* BIT_STRING_SIZE_25 */
static int hf_pcap_sbasXgDot;                     /* BIT_STRING_SIZE_17 */
static int hf_pcap_sbasYgDot;                     /* BIT_STRING_SIZE_17 */
static int hf_pcap_sbasZgDot;                     /* BIT_STRING_SIZE_18 */
static int hf_pcap_sbasXgDotDot;                  /* BIT_STRING_SIZE_10 */
static int hf_pcap_sbagYgDotDot;                  /* BIT_STRING_SIZE_10 */
static int hf_pcap_sbasZgDotDot;                  /* BIT_STRING_SIZE_10 */
static int hf_pcap_uRAIndex_BDS;                  /* BIT_STRING_SIZE_4 */
static int hf_pcap_tOA_BDS_01;                    /* BIT_STRING_SIZE_17 */
static int hf_pcap_a1_2_BDS;                      /* BIT_STRING_SIZE_32 */
static int hf_pcap_e_BDS_01;                      /* BIT_STRING_SIZE_32 */
static int hf_pcap_oMG_BDS;                       /* BIT_STRING_SIZE_32 */
static int hf_pcap_dLTn_BDS;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_m0_BDS_01;                     /* BIT_STRING_SIZE_32 */
static int hf_pcap_oMG0_BDS;                      /* BIT_STRING_SIZE_32 */
static int hf_pcap_oMGdot_BDS;                    /* BIT_STRING_SIZE_24 */
static int hf_pcap_i0_BDS;                        /* BIT_STRING_SIZE_32 */
static int hf_pcap_iDOT_BDS;                      /* BIT_STRING_SIZE_14 */
static int hf_pcap_cuc_BDS;                       /* BIT_STRING_SIZE_18 */
static int hf_pcap_cus_BDS;                       /* BIT_STRING_SIZE_18 */
static int hf_pcap_crc_BDS;                       /* BIT_STRING_SIZE_18 */
static int hf_pcap_crs_BDS;                       /* BIT_STRING_SIZE_18 */
static int hf_pcap_cic_BDS;                       /* BIT_STRING_SIZE_18 */
static int hf_pcap_cis_BDS;                       /* BIT_STRING_SIZE_18 */
static int hf_pcap_aODE_BDS;                      /* BIT_STRING_SIZE_5 */
static int hf_pcap_sbasAgfo;                      /* BIT_STRING_SIZE_12 */
static int hf_pcap_sbasAgf1;                      /* BIT_STRING_SIZE_8 */
static int hf_pcap_toc_BDS;                       /* BIT_STRING_SIZE_17 */
static int hf_pcap_a0_BDS_01;                     /* BIT_STRING_SIZE_24 */
static int hf_pcap_a1_BDS_01;                     /* BIT_STRING_SIZE_22 */
static int hf_pcap_a2_BDS;                        /* BIT_STRING_SIZE_11 */
static int hf_pcap_tGD1_BDS;                      /* BIT_STRING_SIZE_10 */
static int hf_pcap_aODC_BDS;                      /* BIT_STRING_SIZE_5 */
static int hf_pcap_utcA0;                         /* BIT_STRING_SIZE_16 */
static int hf_pcap_utcA1;                         /* BIT_STRING_SIZE_13 */
static int hf_pcap_utcA2;                         /* BIT_STRING_SIZE_7 */
static int hf_pcap_utcDeltaTls;                   /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcTot;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_utcWNot;                       /* BIT_STRING_SIZE_13 */
static int hf_pcap_utcWNlsf;                      /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcDN;                         /* BIT_STRING_SIZE_4 */
static int hf_pcap_utcDeltaTlsf;                  /* BIT_STRING_SIZE_8 */
static int hf_pcap_nA;                            /* BIT_STRING_SIZE_11 */
static int hf_pcap_tauC;                          /* BIT_STRING_SIZE_32 */
static int hf_pcap_deltaUT1_01;                   /* DeltaUT1 */
static int hf_pcap_kp;                            /* BIT_STRING_SIZE_2 */
static int hf_pcap_utcA1wnt;                      /* BIT_STRING_SIZE_24 */
static int hf_pcap_utcA0wnt;                      /* BIT_STRING_SIZE_32 */
static int hf_pcap_utcTot_01;                     /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcWNt;                        /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcDN_01;                      /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcStandardID;                 /* BIT_STRING_SIZE_3 */
static int hf_pcap_utca0_BDS;                     /* BIT_STRING_SIZE_32 */
static int hf_pcap_utca1_BDS;                     /* BIT_STRING_SIZE_24 */
static int hf_pcap_utcDeltatLS_BDS;               /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcWNlsf_BDS;                  /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcDN_BDS;                     /* BIT_STRING_SIZE_8 */
static int hf_pcap_utcDeltaTlsf_BDS;              /* BIT_STRING_SIZE_8 */
static int hf_pcap_utran_GANSSTimingOfCellFrames;  /* INTEGER_0_3999999 */
static int hf_pcap_referenceSfn;                  /* INTEGER_0_4095 */
static int hf_pcap_ue_GANSSTimingOfCellFrames;    /* INTEGER_0_345599999999 */
static int hf_pcap_gANSS_TimeId;                  /* GANSSID */
static int hf_pcap_wn_a;                          /* BIT_STRING_SIZE_8 */
static int hf_pcap_almanacSatInfoList;            /* AlmanacSatInfoList */
static int hf_pcap_svGlobalHealth;                /* BIT_STRING_SIZE_364 */
static int hf_pcap_AlmanacSatInfoList_item;       /* AlmanacSatInfo */
static int hf_pcap_e;                             /* BIT_STRING_SIZE_16 */
static int hf_pcap_almanacSatInfo_t_oa;           /* BIT_STRING_SIZE_8 */
static int hf_pcap_deltaI;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_omegaDot;                      /* BIT_STRING_SIZE_16 */
static int hf_pcap_satHealth;                     /* BIT_STRING_SIZE_8 */
static int hf_pcap_a_Sqrt;                        /* BIT_STRING_SIZE_24 */
static int hf_pcap_omega0;                        /* BIT_STRING_SIZE_24 */
static int hf_pcap_m0;                            /* BIT_STRING_SIZE_24 */
static int hf_pcap_omega;                         /* BIT_STRING_SIZE_24 */
static int hf_pcap_af0;                           /* BIT_STRING_SIZE_11 */
static int hf_pcap_af1;                           /* BIT_STRING_SIZE_11 */
static int hf_pcap_codeOnL2;                      /* BIT_STRING_SIZE_2 */
static int hf_pcap_uraIndex;                      /* BIT_STRING_SIZE_4 */
static int hf_pcap_satHealth_01;                  /* BIT_STRING_SIZE_6 */
static int hf_pcap_iodc;                          /* BIT_STRING_SIZE_10 */
static int hf_pcap_l2Pflag;                       /* BIT_STRING_SIZE_1 */
static int hf_pcap_sf1Revd;                       /* SubFrame1Reserved */
static int hf_pcap_t_GD;                          /* BIT_STRING_SIZE_8 */
static int hf_pcap_t_oc_01;                       /* BIT_STRING_SIZE_16 */
static int hf_pcap_af2;                           /* BIT_STRING_SIZE_8 */
static int hf_pcap_af1_01;                        /* BIT_STRING_SIZE_16 */
static int hf_pcap_af0_01;                        /* BIT_STRING_SIZE_22 */
static int hf_pcap_c_rs;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_delta_n;                       /* BIT_STRING_SIZE_16 */
static int hf_pcap_m0_01;                         /* BIT_STRING_SIZE_32 */
static int hf_pcap_c_uc;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_e_01;                          /* BIT_STRING_SIZE_32 */
static int hf_pcap_c_us;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_a_Sqrt_01;                     /* BIT_STRING_SIZE_32 */
static int hf_pcap_t_oe;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_fitInterval;                   /* BIT_STRING_SIZE_1 */
static int hf_pcap_aodo;                          /* BIT_STRING_SIZE_5 */
static int hf_pcap_c_ic;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_omega0_01;                     /* BIT_STRING_SIZE_32 */
static int hf_pcap_c_is;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_i0;                            /* BIT_STRING_SIZE_32 */
static int hf_pcap_c_rc;                          /* BIT_STRING_SIZE_16 */
static int hf_pcap_omega_01;                      /* BIT_STRING_SIZE_32 */
static int hf_pcap_omegaDot_01;                   /* BIT_STRING_SIZE_24 */
static int hf_pcap_iDot;                          /* BIT_STRING_SIZE_14 */
static int hf_pcap_reserved1;                     /* BIT_STRING_SIZE_23 */
static int hf_pcap_reserved2;                     /* BIT_STRING_SIZE_24 */
static int hf_pcap_reserved3;                     /* BIT_STRING_SIZE_24 */
static int hf_pcap_reserved4;                     /* BIT_STRING_SIZE_16 */
static int hf_pcap_alfa0;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_alfa1;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_alfa2;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_alfa3;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_beta0;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_beta1;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_beta2;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_beta3;                         /* BIT_STRING_SIZE_8 */
static int hf_pcap_MeasuredResultsList_item;      /* GPS_MeasuredResults */
static int hf_pcap_gps_MeasurementParamList;      /* GPS_MeasurementParamList */
static int hf_pcap_GPS_MeasurementParamList_item;  /* GPS_MeasurementParam */
static int hf_pcap_satelliteID;                   /* INTEGER_0_63 */
static int hf_pcap_c_N0;                          /* INTEGER_0_63 */
static int hf_pcap_doppler_01;                    /* INTEGER_M32768_32768 */
static int hf_pcap_wholeGPS_Chips;                /* INTEGER_0_1022 */
static int hf_pcap_fractionalGPS_Chips;           /* INTEGER_0_1023 */
static int hf_pcap_multipathIndicator_01;         /* MultipathIndicator */
static int hf_pcap_pseudorangeRMS_Error;          /* INTEGER_0_63 */
static int hf_pcap_GPS_NavigationModel_item;      /* NavigationModelSatInfo */
static int hf_pcap_satelliteStatus;               /* SatelliteStatus */
static int hf_pcap_gps_clockAndEphemerisParms;    /* GPS_ClockAndEphemerisParameters */
static int hf_pcap_badSatellites;                 /* BadSatList */
static int hf_pcap_noBadSatellites;               /* NoBadSatellites */
static int hf_pcap_BadSatList_item;               /* INTEGER_0_63 */
static int hf_pcap_gps_Week;                      /* INTEGER_0_1023 */
static int hf_pcap_gps_TOW_AssistList;            /* GPS_TOW_AssistList */
static int hf_pcap_GPS_TOW_AssistList_item;       /* GPS_TOW_Assist */
static int hf_pcap_tlm_Message;                   /* BIT_STRING_SIZE_14 */
static int hf_pcap_antiSpoof;                     /* BOOLEAN */
static int hf_pcap_alert;                         /* BOOLEAN */
static int hf_pcap_tlm_Reserved;                  /* BIT_STRING_SIZE_2 */
static int hf_pcap_gps_RefTimeUNC;                /* INTEGER_0_127 */
static int hf_pcap_a1;                            /* BIT_STRING_SIZE_24 */
static int hf_pcap_a0;                            /* BIT_STRING_SIZE_32 */
static int hf_pcap_t_ot;                          /* BIT_STRING_SIZE_8 */
static int hf_pcap_delta_t_LS;                    /* BIT_STRING_SIZE_8 */
static int hf_pcap_wn_t;                          /* BIT_STRING_SIZE_8 */
static int hf_pcap_wn_lsf;                        /* BIT_STRING_SIZE_8 */
static int hf_pcap_dn;                            /* BIT_STRING_SIZE_8 */
static int hf_pcap_delta_t_LSF;                   /* BIT_STRING_SIZE_8 */
static int hf_pcap_almanacRequest;                /* BOOLEAN */
static int hf_pcap_utcModelRequest;               /* BOOLEAN */
static int hf_pcap_ionosphericModelRequest;       /* BOOLEAN */
static int hf_pcap_navigationModelRequest;        /* BOOLEAN */
static int hf_pcap_dgpsCorrectionsRequest;        /* BOOLEAN */
static int hf_pcap_referenceLocationRequest;      /* BOOLEAN */
static int hf_pcap_referenceTimeRequest;          /* BOOLEAN */
static int hf_pcap_aquisitionAssistanceRequest;   /* BOOLEAN */
static int hf_pcap_realTimeIntegrityRequest;      /* BOOLEAN */
static int hf_pcap_navModelAddDataRequest;        /* NavModelAdditionalData */
static int hf_pcap_ganssReferenceTime;            /* BOOLEAN */
static int hf_pcap_ganssreferenceLocation;        /* BOOLEAN */
static int hf_pcap_ganssIonosphericModel;         /* BOOLEAN */
static int hf_pcap_ganssRequestedGenericAssistanceDataList;  /* GanssRequestedGenericAssistanceDataList */
static int hf_pcap_ganss_add_iono_mode_req;       /* BIT_STRING_SIZE_2 */
static int hf_pcap_GanssRequestedGenericAssistanceDataList_item;  /* GanssReqGenericData */
static int hf_pcap_ganssRealTimeIntegrity;        /* BOOLEAN */
static int hf_pcap_ganssDifferentialCorrection;   /* DGANSS_Sig_Id_Req */
static int hf_pcap_ganssAlmanac;                  /* BOOLEAN */
static int hf_pcap_ganssNavigationModel;          /* BOOLEAN */
static int hf_pcap_ganssTimeModelGnssGnss;        /* BIT_STRING_SIZE_9 */
static int hf_pcap_ganssReferenceMeasurementInfo;  /* BOOLEAN */
static int hf_pcap_ganssDataBits_01;              /* GanssDataBits */
static int hf_pcap_ganssUTCModel;                 /* BOOLEAN */
static int hf_pcap_ganssNavigationModelAdditionalData;  /* NavigationModelGANSS */
static int hf_pcap_dGANSSSignalBDS;               /* BIT_STRING_SIZE_8 */
static int hf_pcap_orbitModelID;                  /* INTEGER_0_7 */
static int hf_pcap_clockModelID;                  /* INTEGER_0_7 */
static int hf_pcap_utcModelID;                    /* INTEGER_0_7 */
static int hf_pcap_almanacModelID;                /* INTEGER_0_7 */
static int hf_pcap_dataBitAssistancelist_01;      /* ReqDataBitAssistanceList */
static int hf_pcap_reqDataBitAssistanceList_ganssSignalID;  /* BIT_STRING_SIZE_8 */
static int hf_pcap_ganssDataBitInterval;          /* INTEGER_0_15 */
static int hf_pcap_ganssSatelliteInfo;            /* T_ganssSatelliteInfo */
static int hf_pcap_ganssSatelliteInfo_item;       /* INTEGER_0_63 */
static int hf_pcap_type_01;                       /* InformationReportCharacteristicsType */
static int hf_pcap_periodicity;                   /* InformationReportPeriodicity */
static int hf_pcap_min;                           /* INTEGER_1_60_ */
static int hf_pcap_hour;                          /* INTEGER_1_24_ */
static int hf_pcap_implicitInformation;           /* MethodType */
static int hf_pcap_explicitInformation;           /* ExplicitInformationList */
static int hf_pcap_ExplicitInformationList_item;  /* ExplicitInformation */
static int hf_pcap_almanacAndSatelliteHealth;     /* AlmanacAndSatelliteHealth */
static int hf_pcap_utcModel;                      /* UtcModel */
static int hf_pcap_ionosphericModel;              /* IonosphericModel */
static int hf_pcap_navigationModel;               /* NavigationModel */
static int hf_pcap_dgpsCorrections;               /* DgpsCorrections */
static int hf_pcap_referenceTime_01;              /* ReferenceTime */
static int hf_pcap_acquisitionAssistance;         /* AcquisitionAssistance */
static int hf_pcap_realTimeIntegrity;             /* RealTimeIntegrity */
static int hf_pcap_almanacAndSatelliteHealthSIB;  /* AlmanacAndSatelliteHealthSIB_InfoType */
static int hf_pcap_referenceLocation;             /* ReferenceLocation */
static int hf_pcap_ganss_Common_DataReq;          /* GANSSCommonDataReq */
static int hf_pcap_ganss_Generic_DataList;        /* GANSSGenericDataList */
static int hf_pcap_transmissionGanssTimeIndicator;  /* TransmissionGanssTimeIndicator */
static int hf_pcap_dganss_sig_id_req;             /* DGANSS_Sig_Id_Req */
static int hf_pcap_ganss_ReferenceTime;           /* T_ganss_ReferenceTime */
static int hf_pcap_ganss_IonosphericModel;        /* T_ganss_IonosphericModel */
static int hf_pcap_ganss_ReferenceLocation;       /* T_ganss_ReferenceLocation */
static int hf_pcap_eopReq;                        /* T_eopReq */
static int hf_pcap_GANSSGenericDataList_item;     /* GANSSGenericDataReq */
static int hf_pcap_ganssID;                       /* GANSSID */
static int hf_pcap_ganss_realTimeIntegrity;       /* Ganss_realTimeIntegrityReq */
static int hf_pcap_ganss_dataBitAssistance;       /* GanssDataBits */
static int hf_pcap_dganssCorrections;             /* DganssCorrectionsReq */
static int hf_pcap_ganss_almanacAndSatelliteHealth;  /* Ganss_almanacAndSatelliteHealthReq */
static int hf_pcap_ganss_referenceMeasurementInfo;  /* Ganss_referenceMeasurementInfoReq */
static int hf_pcap_ganss_utcModel;                /* Ganss_utcModelReq */
static int hf_pcap_ganss_TimeModel_Gnss_Gnss;     /* Ganss_TimeModel_Gnss_Gnss */
static int hf_pcap_navigationModel_01;            /* NavigationModelGANSS */
static int hf_pcap_ganss_AddNavModelsReq;         /* AddNavigationModelsGANSS */
static int hf_pcap_ganss_AddUtcModelsReq;         /* GANSS_AddUtcModelsReq */
static int hf_pcap_ganss_AuxInfoReq;              /* GANSS_AuxInfoReq */
static int hf_pcap_ganss_SBAS_ID;                 /* GANSS_SBAS_ID */
static int hf_pcap_dBDS_Corrections;              /* DBDS_Corrections */
static int hf_pcap_bDS_Ionospheric_Grid_Model_Request;  /* BDS_Ionospheric_Grid_Model_Request */
static int hf_pcap_ganssWeek;                     /* INTEGER_0_4095 */
static int hf_pcap_ganssTOE;                      /* INTEGER_0_167 */
static int hf_pcap_t_toe_limit;                   /* INTEGER_0_10 */
static int hf_pcap_addSatRelatedDataListGANSS;    /* AddSatelliteRelatedDataListGANSS */
static int hf_pcap_AddSatelliteRelatedDataListGANSS_item;  /* AddSatelliteRelatedDataGANSS */
static int hf_pcap_dGANSS_Signal;                 /* BIT_STRING_SIZE_8 */
static int hf_pcap_ganssTimeModelGnssGnssExt;     /* BIT_STRING_SIZE_9 */
static int hf_pcap_transmissionTOWIndicator;      /* TransmissionTOWIndicator */
static int hf_pcap_navModelAdditionalData;        /* NavModelAdditionalData */
static int hf_pcap_gps_TOE;                       /* INTEGER_0_167 */
static int hf_pcap_t_TOE_limit;                   /* INTEGER_0_10 */
static int hf_pcap_satRelatedDataList;            /* SatelliteRelatedDataList */
static int hf_pcap_SatelliteRelatedDataList_item;  /* SatelliteRelatedData */
static int hf_pcap_satRelatedDataListGANSS;       /* SatelliteRelatedDataListGANSS */
static int hf_pcap_SatelliteRelatedDataListGANSS_item;  /* SatelliteRelatedDataGANSS */
static int hf_pcap_MessageStructure_item;         /* MessageStructure_item */
static int hf_pcap_repetitionNumber_01;           /* MessageStructureRepetition */
static int hf_pcap_measurementValidity;           /* MeasurementValidity */
static int hf_pcap_ue_State;                      /* T_ue_State */
static int hf_pcap_otdoa_ReferenceCellInfo;       /* OTDOA_ReferenceCellInfo */
static int hf_pcap_otdoa_NeighbourCellInfoList;   /* OTDOA_NeighbourCellInfoList */
static int hf_pcap_otdoa_MeasuredResultsSets;     /* OTDOA_MeasuredResultsSets */
static int hf_pcap_tUTRANGPSMeasurementValueInfo;  /* TUTRANGPSMeasurementValueInfo */
static int hf_pcap_OTDOA_NeighbourCellInfoList_item;  /* OTDOA_NeighbourCellInfo */
static int hf_pcap_relativeTimingDifferenceInfo;  /* RelativeTimingDifferenceInfo */
static int hf_pcap_OTDOA_MeasuredResultsSets_item;  /* OTDOA_MeasuredResultsInfoList */
static int hf_pcap_OTDOA_MeasuredResultsInfoList_item;  /* OTDOA_MeasuredResultsInfo */
static int hf_pcap_ue_SFNSFNTimeDifferenceType2Info;  /* UE_SFNSFNTimeDifferenceType2Info */
static int hf_pcap_primaryCPICH_Info;             /* PrimaryScramblingCode */
static int hf_pcap_ue_SFNSFNTimeDifferenceType2;  /* INTEGER_0_40961 */
static int hf_pcap_measurementDelay;              /* INTEGER_0_65535 */
static int hf_pcap_rNC_ID;                        /* INTEGER_0_4095 */
static int hf_pcap_c_ID;                          /* INTEGER_0_65535 */
static int hf_pcap_sFNSFNMeasurementValueInfo;    /* SFNSFNMeasurementValueInfo */
static int hf_pcap_tUTRANGANSSMeasurementValueInfo;  /* TUTRANGANSSMeasurementValueInfo */
static int hf_pcap_sFNSFNValue;                   /* SFNSFNValue */
static int hf_pcap_sFNSFNQuality;                 /* SFNSFNQuality */
static int hf_pcap_sFNSFNDriftRate;               /* SFNSFNDriftRate */
static int hf_pcap_sFNSFNDriftRateQuality;        /* SFNSFNDriftRateQuality */
static int hf_pcap_sFN;                           /* SFN */
static int hf_pcap_tUTRANGPS;                     /* TUTRANGPS */
static int hf_pcap_tUTRANGPSQuality;              /* TUTRANGPSQuality */
static int hf_pcap_tUTRANGPSDriftRate;            /* TUTRANGPSDriftRate */
static int hf_pcap_tUTRANGPSDriftRateQuality;     /* TUTRANGPSDriftRateQuality */
static int hf_pcap_ms_part;                       /* INTEGER_0_16383 */
static int hf_pcap_ls_part;                       /* INTEGER_0_4294967295 */
static int hf_pcap_tUTRANGANSS;                   /* TUTRANGANSS */
static int hf_pcap_tUTRANGANSSQuality;            /* INTEGER_0_255 */
static int hf_pcap_tUTRANGANSSDriftRate;          /* INTEGER_M50_50 */
static int hf_pcap_tUTRANGANSSDriftRateQuality;   /* INTEGER_0_50 */
static int hf_pcap_timingAdvanceLCR_R7;           /* TimingAdvanceLCR_R7 */
static int hf_pcap_angleOfArrivalLCR;             /* AngleOfArrivalLCR */
static int hf_pcap_referenceNumber;               /* INTEGER_0_32767_ */
static int hf_pcap_amountOutstandingRequests;     /* INTEGER_1_8639999_ */
static int hf_pcap_reportingInterval;             /* INTEGER_1_8639999_ */
static int hf_pcap_reportingAmount;               /* INTEGER_1_8639999_ */
static int hf_pcap_additionalMethodType;          /* AdditionalMethodType */
static int hf_pcap_selectedPositionMethod;        /* SelectedPositionMethod */
static int hf_pcap_new_ue_State;                  /* T_new_ue_State */
static int hf_pcap_gps_UTC_Model;                 /* GPS_UTC_Model */
static int hf_pcap_gps_Ionospheric_Model;         /* GPS_Ionospheric_Model */
static int hf_pcap_gps_NavigationModel;           /* GPS_NavigationModel */
static int hf_pcap_dgpsCorrections_01;            /* DGPSCorrections */
static int hf_pcap_referenceTime_02;              /* GPS_ReferenceTime */
static int hf_pcap_gps_AcquisitionAssistance;     /* GPS_AcquisitionAssistance */
static int hf_pcap_gps_RealTime_Integrity;        /* GPS_RealTimeIntegrity */
static int hf_pcap_almanacAndSatelliteHealthSIB_01;  /* AlmanacAndSatelliteHealthSIB */
static int hf_pcap_gps_Transmission_TOW;          /* GPS_Transmission_TOW */
static int hf_pcap_informationAvailable;          /* InformationAvailable */
static int hf_pcap_informationNotAvailable;       /* InformationNotAvailable */
static int hf_pcap_requestedDataValue;            /* RequestedDataValue */
static int hf_pcap_event;                         /* RequestTypeEvent */
static int hf_pcap_reportArea;                    /* RequestTypeReportArea */
static int hf_pcap_horizontalaccuracyCode;        /* RequestTypeAccuracyCode */
static int hf_pcap_standAloneLocationMethodsSupported;  /* BOOLEAN */
static int hf_pcap_ueBasedOTDOASupported;         /* BOOLEAN */
static int hf_pcap_networkAssistedGPSSupport;     /* NetworkAssistedGPSSuport */
static int hf_pcap_supportGPSTimingOfCellFrame;   /* BOOLEAN */
static int hf_pcap_supportForIPDL;                /* BOOLEAN */
static int hf_pcap_supportForRxTxTimeDiff;        /* BOOLEAN */
static int hf_pcap_supportForUEAGPSinCellPCH;     /* BOOLEAN */
static int hf_pcap_supportForSFNSFNTimeDiff;      /* BOOLEAN */
static int hf_pcap_NetworkAssistedGANSSSupport_item;  /* NetworkAssistedGANSSSupport_item */
static int hf_pcap_ganssMode;                     /* T_ganssMode */
static int hf_pcap_networkAssistedGANSSSupport_item_ganssSignalID;  /* GANSS_SignalID */
static int hf_pcap_supportGANSSTimingOfCellFrame;  /* BOOLEAN */
static int hf_pcap_supportGANSSCarrierPhaseMeasurement;  /* BOOLEAN */
static int hf_pcap_AddPosSupport_item;            /* AddPosSupport_Element */
static int hf_pcap_addPosID;                      /* T_addPosID */
static int hf_pcap_addPosMode;                    /* T_addPosMode */
static int hf_pcap_ganss_sbas_ids;                /* BIT_STRING_SIZE_8 */
static int hf_pcap_ganss_signal_ids;              /* BIT_STRING_SIZE_8 */
static int hf_pcap_utdoa_BitCount;                /* UTDOA_BitCount */
static int hf_pcap_utdoa_timeInterval;            /* UTDOA_TimeInterval */
static int hf_pcap_gpsPositioningInstructions;    /* GPSPositioningInstructions */
static int hf_pcap_horizontalAccuracyCode;        /* HorizontalAccuracyCode */
static int hf_pcap_verticalAccuracyCode;          /* VerticalAccuracyCode */
static int hf_pcap_gpsTimingOfCellWanted;         /* BOOLEAN */
static int hf_pcap_additionalAssistanceDataRequest;  /* BOOLEAN */
static int hf_pcap_ganssPositioningInstructions;  /* GANSS_PositioningInstructions */
static int hf_pcap_ganssTimingOfCellWanted;       /* BIT_STRING_SIZE_8 */
static int hf_pcap_gANSS_PositioningInstructions_additionalAssistanceDataRequest;  /* BIT_STRING_SIZE_8 */
static int hf_pcap_uE_Positioning_OTDOA_AssistanceData;  /* UE_Positioning_OTDOA_AssistanceData */
static int hf_pcap_ue_positioning_OTDOA_ReferenceCellInfo;  /* UE_Positioning_OTDOA_ReferenceCellInfo */
static int hf_pcap_ue_positioning_OTDOA_NeighbourCellList;  /* UE_Positioning_OTDOA_NeighbourCellList */
static int hf_pcap_sfn_01;                        /* SFN */
static int hf_pcap_modeSpecificInfo;              /* T_modeSpecificInfo */
static int hf_pcap_fdd_01;                        /* T_fdd_01 */
static int hf_pcap_tdd_01;                        /* T_tdd_01 */
static int hf_pcap_cellParameterID;               /* CellParameterID */
static int hf_pcap_frequencyInfo;                 /* FrequencyInfo */
static int hf_pcap_positioningMode;               /* T_positioningMode */
static int hf_pcap_ueBased;                       /* T_ueBased */
static int hf_pcap_cellPosition;                  /* ReferenceCellPosition */
static int hf_pcap_roundTripTime_01;              /* INTEGER_0_32766 */
static int hf_pcap_ueAssisted;                    /* T_ueAssisted */
static int hf_pcap_ue_positioning_IPDL_Paremeters;  /* UE_Positioning_IPDL_Parameters */
static int hf_pcap_ellipsoidPoint;                /* GeographicalCoordinates */
static int hf_pcap_ellipsoidPointWithAltitude;    /* GA_PointWithAltitude */
static int hf_pcap_modeSpecificInfo_01;           /* T_modeSpecificInfo_01 */
static int hf_pcap_fdd_02;                        /* T_fdd_02 */
static int hf_pcap_ip_Spacing;                    /* IP_Spacing */
static int hf_pcap_ip_Length;                     /* IP_Length */
static int hf_pcap_ip_Offset;                     /* INTEGER_0_9 */
static int hf_pcap_seed;                          /* INTEGER_0_63 */
static int hf_pcap_tdd_02;                        /* T_tdd_02 */
static int hf_pcap_burstModeParameters;           /* BurstModeParameters */
static int hf_pcap_burstStart;                    /* INTEGER_0_15 */
static int hf_pcap_burstLength;                   /* INTEGER_10_25 */
static int hf_pcap_burstFreq;                     /* INTEGER_1_16 */
static int hf_pcap_UE_Positioning_OTDOA_NeighbourCellList_item;  /* UE_Positioning_OTDOA_NeighbourCellInfo */
static int hf_pcap_modeSpecificInfo_02;           /* T_modeSpecificInfo_02 */
static int hf_pcap_fdd_03;                        /* T_fdd_03 */
static int hf_pcap_tdd_03;                        /* T_tdd_03 */
static int hf_pcap_sfn_SFN_RelTimeDifference;     /* SFN_SFN_RelTimeDifference1 */
static int hf_pcap_sfn_Offset_Validity;           /* SFN_Offset_Validity */
static int hf_pcap_sfn_SFN_Drift;                 /* SFN_SFN_Drift */
static int hf_pcap_searchWindowSize;              /* OTDOA_SearchWindowSize */
static int hf_pcap_positioningMode_01;            /* T_positioningMode_01 */
static int hf_pcap_ueBased_01;                    /* T_ueBased_01 */
static int hf_pcap_relativeNorth;                 /* INTEGER_M20000_20000 */
static int hf_pcap_relativeEast;                  /* INTEGER_M20000_20000 */
static int hf_pcap_relativeAltitude;              /* INTEGER_M4000_4000 */
static int hf_pcap_fineSFN_SFN;                   /* FineSFNSFN */
static int hf_pcap_ueAssisted_01;                 /* T_ueAssisted_01 */
static int hf_pcap_sfn_Offset;                    /* INTEGER_0_4095 */
static int hf_pcap_sfn_sfn_Reltimedifference;     /* INTEGER_0_38399 */
static int hf_pcap_uTDOA_ChannelSettings;         /* UTDOA_RRCState */
static int hf_pcap_modeSpecificInfo_03;           /* T_modeSpecificInfo_03 */
static int hf_pcap_fdd_04;                        /* FrequencyInfoFDD */
static int hf_pcap_tdd_04;                        /* FrequencyInfoTDD */
static int hf_pcap_uarfcn_UL;                     /* UARFCN */
static int hf_pcap_uarfcn_DL;                     /* UARFCN */
static int hf_pcap_uarfcn;                        /* UARFCN */
static int hf_pcap_uTDOA_CELLDCH;                 /* UTDOA_CELLDCH */
static int hf_pcap_uTDOA_CELLFACH;                /* UTDOA_CELLFACH */
static int hf_pcap_uL_DPCHInfo;                   /* UL_DPCHInfo */
static int hf_pcap_compressedModeAssistanceData;  /* Compressed_Mode_Assistance_Data */
static int hf_pcap_dCH_Information;               /* DCH_Information */
static int hf_pcap_e_DPCH_Information;            /* E_DPCH_Information */
static int hf_pcap_fdd_05;                        /* T_fdd_04 */
static int hf_pcap_scramblingCodeType;            /* ScramblingCodeType */
static int hf_pcap_scramblingCode;                /* UL_ScramblingCode */
static int hf_pcap_tfci_Existence;                /* BOOLEAN */
static int hf_pcap_numberOfFBI_Bits;              /* NumberOfFBI_Bits */
static int hf_pcap_tdd_05;                        /* T_tdd_04 */
static int hf_pcap_tFCI_Coding;                   /* TFCI_Coding */
static int hf_pcap_punctureLimit;                 /* PuncturingLimit */
static int hf_pcap_repetitionPeriod;              /* RepetitionPeriod */
static int hf_pcap_repetitionLength;              /* RepetitionLength */
static int hf_pcap_tdd_DPCHOffset;                /* TDD_DPCHOffset */
static int hf_pcap_uL_Timeslot_Information;       /* UL_Timeslot_Information */
static int hf_pcap_frameOffset;                   /* FrameOffset */
static int hf_pcap_specialBurstScheduling;        /* SpecialBurstScheduling */
static int hf_pcap_dl_information;                /* DL_InformationFDD */
static int hf_pcap_ul_information;                /* UL_InformationFDD */
static int hf_pcap_primaryScramblingCode;         /* PrimaryScramblingCode */
static int hf_pcap_chipOffset;                    /* ChipOffset */
static int hf_pcap_transmissionGapPatternSequenceInfo;  /* Transmission_Gap_Pattern_Sequence_Information */
static int hf_pcap_activePatternSequenceInfo;     /* Active_Pattern_Sequence_Information */
static int hf_pcap_cFN;                           /* CFN */
static int hf_pcap_Transmission_Gap_Pattern_Sequence_Information_item;  /* Transmission_Gap_Pattern_Sequence_Information_item */
static int hf_pcap_tGPSID;                        /* TGPSID */
static int hf_pcap_tGSN;                          /* TGSN */
static int hf_pcap_tGL1;                          /* GapLength */
static int hf_pcap_tGL2;                          /* GapLength */
static int hf_pcap_tGD;                           /* TGD */
static int hf_pcap_tGPL1;                         /* GapDuration */
static int hf_pcap_uplink_Compressed_Mode_Method;  /* Uplink_Compressed_Mode_Method */
static int hf_pcap_cMConfigurationChangeCFN;      /* CFN */
static int hf_pcap_transmission_Gap_Pattern_Sequence_Status;  /* Transmission_Gap_Pattern_Sequence_Status_List */
static int hf_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item;  /* Transmission_Gap_Pattern_Sequence_Status_List_item */
static int hf_pcap_tGPRC;                         /* TGPRC */
static int hf_pcap_tGCFN;                         /* CFN */
static int hf_pcap_tFCS;                          /* TFCS */
static int hf_pcap_trChInfo;                      /* TrChInfoList */
static int hf_pcap_TrChInfoList_item;             /* UL_TrCHInfo */
static int hf_pcap_uL_TrCHtype;                   /* UL_TrCHType */
static int hf_pcap_tfs;                           /* TransportFormatSet */
static int hf_pcap_maxSet_E_DPDCHs;               /* Max_Set_E_DPDCHs */
static int hf_pcap_ul_PunctureLimit;              /* PuncturingLimit */
static int hf_pcap_e_TFCS_Information;            /* E_TFCS_Information */
static int hf_pcap_e_TTI;                         /* E_TTI */
static int hf_pcap_e_DPCCH_PO;                    /* E_DPCCH_PO */
static int hf_pcap_e_DCH_TFCS_Index;              /* E_DCH_TFCS_Index */
static int hf_pcap_reference_E_TFCI_Information;  /* Reference_E_TFCI_Information */
static int hf_pcap_Reference_E_TFCI_Information_item;  /* Reference_E_TFCI_Information_Item */
static int hf_pcap_reference_E_TFCI;              /* E_TFCI */
static int hf_pcap_reference_E_TFCI_PO;           /* Reference_E_TFCI_PO */
static int hf_pcap_initialOffset;                 /* INTEGER_0_255 */
static int hf_pcap_noinitialOffset;               /* INTEGER_0_63 */
static int hf_pcap_UL_Timeslot_Information_item;  /* UL_Timeslot_InformationItem */
static int hf_pcap_timeSlot;                      /* TimeSlot */
static int hf_pcap_midambleShiftAndBurstType;     /* MidambleShiftAndBurstType */
static int hf_pcap_tFCI_Presence;                 /* BOOLEAN */
static int hf_pcap_uL_Code_InformationList;       /* TDD_UL_Code_Information */
static int hf_pcap_type1;                         /* T_type1 */
static int hf_pcap_midambleConfigurationBurstType1And3;  /* MidambleConfigurationBurstType1And3 */
static int hf_pcap_midambleAllocationMode;        /* T_midambleAllocationMode */
static int hf_pcap_defaultMidamble;               /* NULL */
static int hf_pcap_commonMidamble;                /* NULL */
static int hf_pcap_ueSpecificMidamble;            /* MidambleShiftLong */
static int hf_pcap_type2;                         /* T_type2 */
static int hf_pcap_midambleConfigurationBurstType2;  /* MidambleConfigurationBurstType2 */
static int hf_pcap_midambleAllocationMode_01;     /* T_midambleAllocationMode_01 */
static int hf_pcap_ueSpecificMidamble_01;         /* MidambleShiftShort */
static int hf_pcap_type3;                         /* T_type3 */
static int hf_pcap_midambleAllocationMode_02;     /* T_midambleAllocationMode_02 */
static int hf_pcap_TDD_UL_Code_Information_item;  /* TDD_UL_Code_InformationItem */
static int hf_pcap_tdd_ChannelisationCode;        /* TDD_ChannelisationCode */
static int hf_pcap_pRACHparameters;               /* PRACHparameters */
static int hf_pcap_cRNTI;                         /* C_RNTI */
static int hf_pcap_uschParameters;                /* UschParameters */
static int hf_pcap_PRACHparameters_item;          /* PRACH_ChannelInfo */
static int hf_pcap_pRACH_Info;                    /* PRACH_Info */
static int hf_pcap_tFS;                           /* TransportFormatSet */
static int hf_pcap_fdd_06;                        /* T_fdd_05 */
static int hf_pcap_availableSignatures;           /* AvailableSignatures */
static int hf_pcap_availableSF;                   /* SF_PRACH */
static int hf_pcap_preambleScramblingCodeWordNumber;  /* PreambleScramblingCodeWordNumber */
static int hf_pcap_puncturingLimit;               /* PuncturingLimit */
static int hf_pcap_availableSubChannelNumbers;    /* AvailableSubChannelNumbers */
static int hf_pcap_tdd_06;                        /* T_tdd_05 */
static int hf_pcap_maxPRACH_MidambleShifts;       /* MaxPRACH_MidambleShifts */
static int hf_pcap_pRACH_Midamble;                /* PRACH_Midamble */
static int hf_pcap_dynamicPart;                   /* TransportFormatSet_DynamicPartList */
static int hf_pcap_semi_staticPart;               /* TransportFormatSet_Semi_staticPart */
static int hf_pcap_TransportFormatSet_DynamicPartList_item;  /* TransportFormatSet_DynamicPartList_item */
static int hf_pcap_rlc_Size;                      /* RLC_Size */
static int hf_pcap_numberOfTbsTTIList;            /* SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo */
static int hf_pcap_numberOfTbsTTIList_item;       /* TbsTTIInfo */
static int hf_pcap_tTIInfo;                       /* TransportFormatSet_TransmissionTimeIntervalDynamic */
static int hf_pcap_numberOfTbs;                   /* TransportFormatSet_NrOfTransportBlocks */
static int hf_pcap_transmissionTimeInterval;      /* TransportFormatSet_TransmissionTimeIntervalSemiStatic */
static int hf_pcap_channelCoding;                 /* TransportFormatSet_ChannelCodingType */
static int hf_pcap_codingRate;                    /* TransportFormatSet_CodingRate */
static int hf_pcap_rateMatchingAttribute;         /* TransportFormatSet_RateMatchingAttribute */
static int hf_pcap_cRC_Size;                      /* TransportFormatSet_CRC_Size */
static int hf_pcap_TFCS_item;                     /* CTFC */
static int hf_pcap_ctfc2Bit;                      /* T_ctfc2Bit */
static int hf_pcap_ctfc2Bit_item;                 /* INTEGER_0_3 */
static int hf_pcap_ctfc4Bit;                      /* T_ctfc4Bit */
static int hf_pcap_ctfc4Bit_item;                 /* INTEGER_0_15 */
static int hf_pcap_ctfc6Bit;                      /* T_ctfc6Bit */
static int hf_pcap_ctfc6Bit_item;                 /* INTEGER_0_63 */
static int hf_pcap_ctfc8Bit;                      /* T_ctfc8Bit */
static int hf_pcap_ctfc8Bit_item;                 /* INTEGER_0_255 */
static int hf_pcap_ctfc12Bit;                     /* T_ctfc12Bit */
static int hf_pcap_ctfc12Bit_item;                /* INTEGER_0_4095 */
static int hf_pcap_ctfc16Bit;                     /* T_ctfc16Bit */
static int hf_pcap_ctfc16Bit_item;                /* INTEGER_0_65535 */
static int hf_pcap_ctfc24Bit;                     /* T_ctfc24Bit */
static int hf_pcap_ctfc24Bit_item;                /* INTEGER_0_16777215 */
static int hf_pcap_uSCH_SchedulingOffset;         /* USCH_SchedulingOffset */
static int hf_pcap_horizontalVelocity;            /* HorizontalVelocity */
static int hf_pcap_horizontalWithVerticalVelocity;  /* HorizontalWithVerticalVelocity */
static int hf_pcap_horizontalVelocityWithUncertainty;  /* HorizontalVelocityWithUncertainty */
static int hf_pcap_horizontalWithVerticalVelocityAndUncertainty;  /* HorizontalWithVerticalVelocityAndUncertainty */
static int hf_pcap_horizontalSpeedAndBearing;     /* HorizontalSpeedAndBearing */
static int hf_pcap_verticalVelocity;              /* VerticalVelocity */
static int hf_pcap_uncertaintySpeed;              /* INTEGER_0_255 */
static int hf_pcap_horizontalUncertaintySpeed;    /* INTEGER_0_255 */
static int hf_pcap_verticalUncertaintySpeed;      /* INTEGER_0_255 */
static int hf_pcap_bearing;                       /* INTEGER_0_359 */
static int hf_pcap_horizontalSpeed;               /* INTEGER_0_2047 */
static int hf_pcap_verticalSpeed;                 /* INTEGER_0_255 */
static int hf_pcap_verticalSpeedDirection;        /* VerticalSpeedDirection */
static int hf_pcap_utran_GPSTimingOfCell;         /* INTEGER_0_2322431999999_ */
static int hf_pcap_ue_GPSTimingOfCell;            /* INTEGER_0_37158911999999_ */
static int hf_pcap_ue_GANSSTimingOfCell;          /* INTEGER_0_345599999999_ */
static int hf_pcap_ganss_Time_ID;                 /* GANSSID */
static int hf_pcap_protocolIEs;                   /* ProtocolIE_Container */
static int hf_pcap_protocolExtensions;            /* ProtocolExtensionContainer */
static int hf_pcap_referencePosition;             /* RefPosition_InfEx_Rqst */
static int hf_pcap_extension_InformationExchangeObjectType_InfEx_Rqst;  /* Extension_InformationExchangeObjectType_InfEx_Rqst */
static int hf_pcap_referencePositionEstimate;     /* UE_PositionEstimate */
static int hf_pcap_referenceUC_ID;                /* UC_ID */
static int hf_pcap_referencePosition_01;          /* RefPosition_InfEx_Rsp */
static int hf_pcap_referencePosition_02;          /* RefPosition_InfEx_Rprt */
static int hf_pcap_requestedDataValueInformation;  /* RequestedDataValueInformation */
static int hf_pcap_privateIEs;                    /* PrivateIE_Container */
static int hf_pcap_initiatingMessage;             /* InitiatingMessage */
static int hf_pcap_successfulOutcome;             /* SuccessfulOutcome */
static int hf_pcap_unsuccessfulOutcome;           /* UnsuccessfulOutcome */
static int hf_pcap_outcome;                       /* Outcome */
static int hf_pcap_initiatingMessagevalue;        /* InitiatingMessage_value */
static int hf_pcap_successfulOutcome_value;       /* SuccessfulOutcome_value */
static int hf_pcap_unsuccessfulOutcome_value;     /* UnsuccessfulOutcome_value */
static int hf_pcap_outcome_value;                 /* Outcome_value */
/* named bits */
static int hf_pcap_AvailableSignatures_signature15;
static int hf_pcap_AvailableSignatures_signature14;
static int hf_pcap_AvailableSignatures_signature13;
static int hf_pcap_AvailableSignatures_signature12;
static int hf_pcap_AvailableSignatures_signature11;
static int hf_pcap_AvailableSignatures_signature10;
static int hf_pcap_AvailableSignatures_signature9;
static int hf_pcap_AvailableSignatures_signature8;
static int hf_pcap_AvailableSignatures_signature7;
static int hf_pcap_AvailableSignatures_signature6;
static int hf_pcap_AvailableSignatures_signature5;
static int hf_pcap_AvailableSignatures_signature4;
static int hf_pcap_AvailableSignatures_signature3;
static int hf_pcap_AvailableSignatures_signature2;
static int hf_pcap_AvailableSignatures_signature1;
static int hf_pcap_AvailableSignatures_signature0;
static int hf_pcap_AvailableSubChannelNumbers_subCh11;
static int hf_pcap_AvailableSubChannelNumbers_subCh10;
static int hf_pcap_AvailableSubChannelNumbers_subCh9;
static int hf_pcap_AvailableSubChannelNumbers_subCh8;
static int hf_pcap_AvailableSubChannelNumbers_subCh7;
static int hf_pcap_AvailableSubChannelNumbers_subCh6;
static int hf_pcap_AvailableSubChannelNumbers_subCh5;
static int hf_pcap_AvailableSubChannelNumbers_subCh4;
static int hf_pcap_AvailableSubChannelNumbers_subCh3;
static int hf_pcap_AvailableSubChannelNumbers_subCh2;
static int hf_pcap_AvailableSubChannelNumbers_subCh1;
static int hf_pcap_AvailableSubChannelNumbers_subCh0;

/* Initialize the subtree pointers */
static int ett_pcap;

static int ett_pcap_PrivateIE_ID;
static int ett_pcap_TransactionID;
static int ett_pcap_ProtocolIE_Container;
static int ett_pcap_ProtocolIE_Field;
static int ett_pcap_ProtocolExtensionContainer;
static int ett_pcap_ProtocolExtensionField;
static int ett_pcap_PrivateIE_Container;
static int ett_pcap_PrivateIE_Field;
static int ett_pcap_AddPos_MeasuredResults;
static int ett_pcap_AddPos_MeasuredResults_Element;
static int ett_pcap_T_type;
static int ett_pcap_T_barometricPressure;
static int ett_pcap_T_wlan;
static int ett_pcap_T_bt;
static int ett_pcap_T_mbs;
static int ett_pcap_WLANMeasurementList;
static int ett_pcap_WLANMeasurementList_Element;
static int ett_pcap_BTMeasurementList;
static int ett_pcap_BTMeasurementList_Element;
static int ett_pcap_MBSMeasurementList;
static int ett_pcap_MBSMeasurementList_Element;
static int ett_pcap_AlmanacAndSatelliteHealthSIB;
static int ett_pcap_Cause;
static int ett_pcap_CellId_MeasuredResultsSets;
static int ett_pcap_CellId_MeasuredResultsInfoList;
static int ett_pcap_CellId_MeasuredResultsInfo;
static int ett_pcap_RoundTripTimeInfo;
static int ett_pcap_RoundTripTimeInfoWithType1;
static int ett_pcap_UE_PositioningMeasQuality;
static int ett_pcap_UTRANAccessPointPositionAltitude;
static int ett_pcap_RxTimingDeviationInfo;
static int ett_pcap_RxTimingDeviationLCRInfo;
static int ett_pcap_RxTimingDeviation768Info;
static int ett_pcap_RxTimingDeviation384extInfo;
static int ett_pcap_AddMeasurementInfo;
static int ett_pcap_AngleOfArrivalLCR;
static int ett_pcap_CellId_IRATMeasuredResultsSets;
static int ett_pcap_CellId_IRATMeasuredResultsInfoList;
static int ett_pcap_GERAN_MeasuredResultsInfoList;
static int ett_pcap_GERAN_MeasuredResultsInfo;
static int ett_pcap_GERANCellGlobalID;
static int ett_pcap_GERANPhysicalCellID;
static int ett_pcap_GSM_BSIC;
static int ett_pcap_CellIDPositioning;
static int ett_pcap_RequestedCellIDMeasurements;
static int ett_pcap_T_fdd;
static int ett_pcap_T_tdd;
static int ett_pcap_RequestedCellIDGERANMeasurements;
static int ett_pcap_CriticalityDiagnostics;
static int ett_pcap_CriticalityDiagnostics_IE_List;
static int ett_pcap_CriticalityDiagnostics_IE_List_item;
static int ett_pcap_DGPSCorrections;
static int ett_pcap_DGPS_CorrectionSatInfoList;
static int ett_pcap_DGPS_CorrectionSatInfo;
static int ett_pcap_DGNSS_ValidityPeriod;
static int ett_pcap_UE_PositionEstimate;
static int ett_pcap_GeographicalCoordinates;
static int ett_pcap_GA_AltitudeAndDirection;
static int ett_pcap_GA_EllipsoidArc;
static int ett_pcap_GA_Point;
static int ett_pcap_GA_PointWithAltitude;
static int ett_pcap_GA_PointWithAltitudeAndUncertaintyEllipsoid;
static int ett_pcap_GA_PointWithUnCertainty;
static int ett_pcap_GA_PointWithUnCertaintyEllipse;
static int ett_pcap_GA_Polygon;
static int ett_pcap_GA_Polygon_item;
static int ett_pcap_GA_UncertaintyEllipse;
static int ett_pcap_UE_PositionEstimateInfo;
static int ett_pcap_ReferenceTimeChoice;
static int ett_pcap_Cell_Timing;
static int ett_pcap_GANSS_Reference_Time_Only;
static int ett_pcap_PositionDataUEbased;
static int ett_pcap_PositionData;
static int ett_pcap_GANSS_PositioningDataSet;
static int ett_pcap_PositioningDataSet;
static int ett_pcap_Additional_PositioningDataSet;
static int ett_pcap_GPS_AcquisitionAssistance;
static int ett_pcap_AcquisitionSatInfoList;
static int ett_pcap_AcquisitionSatInfo;
static int ett_pcap_ExtraDopplerInfo;
static int ett_pcap_ExtraDopplerInfoExtension;
static int ett_pcap_AzimuthAndElevation;
static int ett_pcap_AzimuthAndElevationLSB;
static int ett_pcap_AuxInfoGANSS_ID1;
static int ett_pcap_AuxInfoGANSS_ID1_element;
static int ett_pcap_AuxInfoGANSS_ID3;
static int ett_pcap_AuxInfoGANSS_ID3_element;
static int ett_pcap_CNAVclockModel;
static int ett_pcap_DeltaUT1;
static int ett_pcap_DGANSS_Corrections;
static int ett_pcap_DGANSS_Information;
static int ett_pcap_DGANSS_InformationItem;
static int ett_pcap_DGANSS_SignalInformation;
static int ett_pcap_DGANSS_SignalInformationItem;
static int ett_pcap_GANSS_AddClockModels;
static int ett_pcap_GANSS_AddOrbitModels;
static int ett_pcap_GANSS_Additional_Ionospheric_Model;
static int ett_pcap_GANSS_Additional_Navigation_Models;
static int ett_pcap_GANSS_Additional_Time_Models;
static int ett_pcap_GANSS_Additional_UTC_Models;
static int ett_pcap_GANSS_ALM_BDSKeplericanset;
static int ett_pcap_Satellite_Information_BDS_KP_List;
static int ett_pcap_Satellite_Information_BDS_KP_Item;
static int ett_pcap_GANSS_ALM_ECEFsbasAlmanacSet;
static int ett_pcap_GANSS_ALM_GlonassAlmanacSet;
static int ett_pcap_GANSS_ALM_MidiAlmanacSet;
static int ett_pcap_GANSS_ALM_NAVKeplerianSet;
static int ett_pcap_GANSS_ALM_ReducedKeplerianSet;
static int ett_pcap_GANSS_AlmanacAndSatelliteHealth;
static int ett_pcap_GANSS_AlmanacModel;
static int ett_pcap_GANSS_Auxiliary_Information;
static int ett_pcap_GANSS_AzimuthAndElevation;
static int ett_pcap_GANSS_Clock_Model;
static int ett_pcap_GANSS_CommonAssistanceData;
static int ett_pcap_GANSS_Data_Bit_Assistance;
static int ett_pcap_GANSS_DataBitAssistanceList;
static int ett_pcap_GANSS_DataBitAssistanceItem;
static int ett_pcap_GANSS_DataBitAssistanceSgnList;
static int ett_pcap_GANSS_DataBitAssistanceSgnItem;
static int ett_pcap_GANSS_Earth_Orientation_Parameters;
static int ett_pcap_GANSS_ExtraDoppler;
static int ett_pcap_GANSS_ExtraDopplerExtension;
static int ett_pcap_GANSS_GenericAssistanceDataList;
static int ett_pcap_GANSSGenericAssistanceData;
static int ett_pcap_BDS_Ionospheric_Grid_Model;
static int ett_pcap_BDS_Ionospheric_Grid_Information;
static int ett_pcap_BDS_Ionospheric_Grid_Information_item;
static int ett_pcap_DBDS_Correction_Information;
static int ett_pcap_DBDS_Information;
static int ett_pcap_DBDS_Information_item;
static int ett_pcap_DGANSS_Signal_Information;
static int ett_pcap_DGANSS_Signal_Information_item;
static int ett_pcap_GANSS_GenericMeasurementInfo;
static int ett_pcap_GANSS_GenericMeasurementInfo_item;
static int ett_pcap_GANSSID;
static int ett_pcap_GANSSMeasurementSignalList;
static int ett_pcap_GANSSMeasurementSignalList_item;
static int ett_pcap_GanssCodePhaseAmbiguityExt;
static int ett_pcap_GANSS_Ionospheric_Model;
static int ett_pcap_GANSS_IonosphereRegionalStormFlags;
static int ett_pcap_GANSS_KeplerianParametersAlm;
static int ett_pcap_GANSS_KeplerianParametersOrb;
static int ett_pcap_GANSS_MeasurementParameters;
static int ett_pcap_GANSS_MeasurementParametersItem;
static int ett_pcap_GanssIntegerCodePhaseExt;
static int ett_pcap_GANSS_MeasuredResultsList;
static int ett_pcap_GANSS_MeasuredResults;
static int ett_pcap_T_referenceTime;
static int ett_pcap_GANSS_Navigation_Model;
static int ett_pcap_GANSS_Orbit_Model;
static int ett_pcap_GANSS_Real_Time_Integrity;
static int ett_pcap_GANSS_RealTimeInformationItem;
static int ett_pcap_GANSS_Reference_Location;
static int ett_pcap_GANSS_ReferenceMeasurementInfo;
static int ett_pcap_GANSS_Reference_Time;
static int ett_pcap_GANSS_ReferenceTimeOnly;
static int ett_pcap_GANSS_SatelliteClockModelItem;
static int ett_pcap_GANSS_SatelliteInformation;
static int ett_pcap_GANSS_SatelliteInformationItem;
static int ett_pcap_GANSS_SatelliteInformationKP;
static int ett_pcap_GANSS_SatelliteInformationKPItem;
static int ett_pcap_GANSS_SAT_Info_Almanac_GLOkpList;
static int ett_pcap_GANSS_SAT_Info_Almanac_GLOkp;
static int ett_pcap_GANSS_SAT_Info_Almanac_MIDIkpList;
static int ett_pcap_GANSS_SAT_Info_Almanac_MIDIkp;
static int ett_pcap_GANSS_SAT_Info_Almanac_NAVkpList;
static int ett_pcap_GANSS_SAT_Info_Almanac_NAVkp;
static int ett_pcap_GANSS_SAT_Info_Almanac_REDkpList;
static int ett_pcap_GANSS_SAT_Info_Almanac_REDkp;
static int ett_pcap_GANSS_SAT_Info_Almanac_SBASecefList;
static int ett_pcap_GANSS_SAT_Info_Almanac_SBASecef;
static int ett_pcap_Ganss_Sat_Info_AddNavList;
static int ett_pcap_Ganss_Sat_Info_AddNavList_item;
static int ett_pcap_GANSS_Sat_Info_Nav;
static int ett_pcap_GANSS_Sat_Info_Nav_item;
static int ett_pcap_GANSS_SignalID;
static int ett_pcap_GANSS_Time_Model;
static int ett_pcap_GANSS_UTRAN_TRU;
static int ett_pcap_GANSS_UTC_Model;
static int ett_pcap_GLONASSclockModel;
static int ett_pcap_NAVclockModel;
static int ett_pcap_NavModel_CNAVKeplerianSet;
static int ett_pcap_NavModel_GLONASSecef;
static int ett_pcap_NavModel_NAVKeplerianSet;
static int ett_pcap_NavModel_SBASecef;
static int ett_pcap_NavModel_BDSKeplerianSet;
static int ett_pcap_SBASclockModel;
static int ett_pcap_BDSClockModel;
static int ett_pcap_UTCmodelSet1;
static int ett_pcap_UTCmodelSet2;
static int ett_pcap_UTCmodelSet3;
static int ett_pcap_UTCmodelSet4;
static int ett_pcap_UTRAN_GANSSReferenceTimeDL;
static int ett_pcap_UTRAN_GANSSReferenceTimeUL;
static int ett_pcap_GPS_AlmanacAndSatelliteHealth;
static int ett_pcap_AlmanacSatInfoList;
static int ett_pcap_AlmanacSatInfo;
static int ett_pcap_GPS_ClockAndEphemerisParameters;
static int ett_pcap_SubFrame1Reserved;
static int ett_pcap_GPS_Ionospheric_Model;
static int ett_pcap_MeasuredResultsList;
static int ett_pcap_GPS_MeasuredResults;
static int ett_pcap_GPS_MeasurementParamList;
static int ett_pcap_GPS_MeasurementParam;
static int ett_pcap_GPS_NavigationModel;
static int ett_pcap_NavigationModelSatInfo;
static int ett_pcap_GPS_RealTimeIntegrity;
static int ett_pcap_BadSatList;
static int ett_pcap_GPS_ReferenceLocation;
static int ett_pcap_GPS_ReferenceTime;
static int ett_pcap_GPS_TOW_AssistList;
static int ett_pcap_GPS_TOW_Assist;
static int ett_pcap_GPSReferenceTimeUncertainty;
static int ett_pcap_GPS_UTC_Model;
static int ett_pcap_AdditionalGPSAssistDataRequired;
static int ett_pcap_AdditionalGanssAssistDataRequired;
static int ett_pcap_GANSSReq_AddIonosphericModel;
static int ett_pcap_GanssRequestedGenericAssistanceDataList;
static int ett_pcap_GanssReqGenericData;
static int ett_pcap_DBDSCorrection;
static int ett_pcap_GANSS_AddADchoices;
static int ett_pcap_GanssDataBits;
static int ett_pcap_ReqDataBitAssistanceList;
static int ett_pcap_T_ganssSatelliteInfo;
static int ett_pcap_InformationReportCharacteristics;
static int ett_pcap_InformationReportPeriodicity;
static int ett_pcap_InformationType;
static int ett_pcap_ExplicitInformationList;
static int ett_pcap_ExplicitInformation;
static int ett_pcap_DganssCorrectionsReq;
static int ett_pcap_Ganss_almanacAndSatelliteHealthReq;
static int ett_pcap_GANSSCommonDataReq;
static int ett_pcap_GANSS_AddIonoModelReq;
static int ett_pcap_GANSS_EarthOrientParaReq;
static int ett_pcap_GANSSGenericDataList;
static int ett_pcap_GANSSGenericDataReq;
static int ett_pcap_AddNavigationModelsGANSS;
static int ett_pcap_AddSatelliteRelatedDataListGANSS;
static int ett_pcap_AddSatelliteRelatedDataGANSS;
static int ett_pcap_DBDS_Corrections;
static int ett_pcap_GANSS_AddUtcModelsReq;
static int ett_pcap_GANSS_AuxInfoReq;
static int ett_pcap_Ganss_utcModelReq;
static int ett_pcap_Ganss_realTimeIntegrityReq;
static int ett_pcap_Ganss_referenceMeasurementInfoReq;
static int ett_pcap_Ganss_TimeModel_Gnss_Gnss;
static int ett_pcap_UtcModel;
static int ett_pcap_IonosphericModel;
static int ett_pcap_NavigationModel;
static int ett_pcap_NavModelAdditionalData;
static int ett_pcap_SatelliteRelatedDataList;
static int ett_pcap_SatelliteRelatedData;
static int ett_pcap_NavigationModelGANSS;
static int ett_pcap_SatelliteRelatedDataListGANSS;
static int ett_pcap_SatelliteRelatedDataGANSS;
static int ett_pcap_AlmanacAndSatelliteHealthSIB_InfoType;
static int ett_pcap_MessageStructure;
static int ett_pcap_MessageStructure_item;
static int ett_pcap_MeasInstructionsUsed;
static int ett_pcap_MeasurementValidity;
static int ett_pcap_OTDOA_MeasurementGroup;
static int ett_pcap_OTDOA_ReferenceCellInfo;
static int ett_pcap_OTDOA_ReferenceCellInfoSAS_centric;
static int ett_pcap_OTDOA_NeighbourCellInfoList;
static int ett_pcap_OTDOA_NeighbourCellInfo;
static int ett_pcap_OTDOA_MeasuredResultsSets;
static int ett_pcap_OTDOA_MeasuredResultsInfoList;
static int ett_pcap_OTDOA_MeasuredResultsInfo;
static int ett_pcap_OTDOA_AddMeasuredResultsInfo;
static int ett_pcap_UE_SFNSFNTimeDifferenceType2Info;
static int ett_pcap_UC_ID;
static int ett_pcap_RelativeTimingDifferenceInfo;
static int ett_pcap_SFNSFNMeasurementValueInfo;
static int ett_pcap_TUTRANGPSMeasurementValueInfo;
static int ett_pcap_TUTRANGPS;
static int ett_pcap_TUTRANGANSSMeasurementValueInfo;
static int ett_pcap_TUTRANGANSS;
static int ett_pcap_AdditionalMeasurementInforLCR;
static int ett_pcap_PeriodicPosCalcInfo;
static int ett_pcap_PeriodicLocationInfo;
static int ett_pcap_PositioningMethod;
static int ett_pcap_RRCstateChange;
static int ett_pcap_RequestedDataValue;
static int ett_pcap_RequestedDataValueInformation;
static int ett_pcap_InformationAvailable;
static int ett_pcap_RequestType;
static int ett_pcap_UE_PositioningCapability;
static int ett_pcap_NetworkAssistedGANSSSupport;
static int ett_pcap_NetworkAssistedGANSSSupport_item;
static int ett_pcap_AddPosSupport;
static int ett_pcap_AddPosSupport_Element;
static int ett_pcap_GANSS_SBAS_IDs;
static int ett_pcap_GANSS_Signal_IDs;
static int ett_pcap_UTDOAPositioning;
static int ett_pcap_GPSPositioning;
static int ett_pcap_GPSPositioningInstructions;
static int ett_pcap_GANSSPositioning;
static int ett_pcap_GANSS_PositioningInstructions;
static int ett_pcap_OTDOAAssistanceData;
static int ett_pcap_UE_Positioning_OTDOA_AssistanceData;
static int ett_pcap_UE_Positioning_OTDOA_ReferenceCellInfo;
static int ett_pcap_T_modeSpecificInfo;
static int ett_pcap_T_fdd_01;
static int ett_pcap_T_tdd_01;
static int ett_pcap_T_positioningMode;
static int ett_pcap_T_ueBased;
static int ett_pcap_T_ueAssisted;
static int ett_pcap_ReferenceCellPosition;
static int ett_pcap_UE_Positioning_IPDL_Parameters;
static int ett_pcap_T_modeSpecificInfo_01;
static int ett_pcap_T_fdd_02;
static int ett_pcap_T_tdd_02;
static int ett_pcap_BurstModeParameters;
static int ett_pcap_UE_Positioning_OTDOA_NeighbourCellList;
static int ett_pcap_UE_Positioning_OTDOA_NeighbourCellInfo;
static int ett_pcap_T_modeSpecificInfo_02;
static int ett_pcap_T_fdd_03;
static int ett_pcap_T_tdd_03;
static int ett_pcap_T_positioningMode_01;
static int ett_pcap_T_ueBased_01;
static int ett_pcap_T_ueAssisted_01;
static int ett_pcap_SFN_SFN_RelTimeDifference1;
static int ett_pcap_UTDOA_Group;
static int ett_pcap_FrequencyInfo;
static int ett_pcap_T_modeSpecificInfo_03;
static int ett_pcap_FrequencyInfoFDD;
static int ett_pcap_FrequencyInfoTDD;
static int ett_pcap_UTDOA_RRCState;
static int ett_pcap_UTDOA_CELLDCH;
static int ett_pcap_UL_DPCHInfo;
static int ett_pcap_T_fdd_04;
static int ett_pcap_T_tdd_04;
static int ett_pcap_Compressed_Mode_Assistance_Data;
static int ett_pcap_DL_InformationFDD;
static int ett_pcap_UL_InformationFDD;
static int ett_pcap_Transmission_Gap_Pattern_Sequence_Information;
static int ett_pcap_Transmission_Gap_Pattern_Sequence_Information_item;
static int ett_pcap_Active_Pattern_Sequence_Information;
static int ett_pcap_Transmission_Gap_Pattern_Sequence_Status_List;
static int ett_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item;
static int ett_pcap_DCH_Information;
static int ett_pcap_TrChInfoList;
static int ett_pcap_UL_TrCHInfo;
static int ett_pcap_E_DPCH_Information;
static int ett_pcap_E_TFCS_Information;
static int ett_pcap_Reference_E_TFCI_Information;
static int ett_pcap_Reference_E_TFCI_Information_Item;
static int ett_pcap_TDD_DPCHOffset;
static int ett_pcap_UL_Timeslot_Information;
static int ett_pcap_UL_Timeslot_InformationItem;
static int ett_pcap_MidambleShiftAndBurstType;
static int ett_pcap_T_type1;
static int ett_pcap_T_midambleAllocationMode;
static int ett_pcap_T_type2;
static int ett_pcap_T_midambleAllocationMode_01;
static int ett_pcap_T_type3;
static int ett_pcap_T_midambleAllocationMode_02;
static int ett_pcap_TDD_UL_Code_Information;
static int ett_pcap_TDD_UL_Code_InformationItem;
static int ett_pcap_UTDOA_CELLFACH;
static int ett_pcap_PRACHparameters;
static int ett_pcap_PRACH_ChannelInfo;
static int ett_pcap_PRACH_Info;
static int ett_pcap_T_fdd_05;
static int ett_pcap_T_tdd_05;
static int ett_pcap_AvailableSignatures;
static int ett_pcap_AvailableSubChannelNumbers;
static int ett_pcap_TransportFormatSet;
static int ett_pcap_TransportFormatSet_DynamicPartList;
static int ett_pcap_TransportFormatSet_DynamicPartList_item;
static int ett_pcap_SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo;
static int ett_pcap_TbsTTIInfo;
static int ett_pcap_TransportFormatSet_Semi_staticPart;
static int ett_pcap_TFCS;
static int ett_pcap_CTFC;
static int ett_pcap_T_ctfc2Bit;
static int ett_pcap_T_ctfc4Bit;
static int ett_pcap_T_ctfc6Bit;
static int ett_pcap_T_ctfc8Bit;
static int ett_pcap_T_ctfc12Bit;
static int ett_pcap_T_ctfc16Bit;
static int ett_pcap_T_ctfc24Bit;
static int ett_pcap_UschParameters;
static int ett_pcap_VelocityEstimate;
static int ett_pcap_HorizontalVelocity;
static int ett_pcap_HorizontalWithVerticalVelocity;
static int ett_pcap_HorizontalVelocityWithUncertainty;
static int ett_pcap_HorizontalWithVerticalVelocityAndUncertainty;
static int ett_pcap_HorizontalSpeedAndBearing;
static int ett_pcap_VerticalVelocity;
static int ett_pcap_UTRAN_GPSReferenceTime;
static int ett_pcap_UTRAN_GPSReferenceTimeResult;
static int ett_pcap_UTRAN_GANSSReferenceTimeResult;
static int ett_pcap_PositionCalculationRequest;
static int ett_pcap_PositionCalculationResponse;
static int ett_pcap_PositionCalculationFailure;
static int ett_pcap_InformationExchangeInitiationRequest;
static int ett_pcap_InformationExchangeObjectType_InfEx_Rqst;
static int ett_pcap_RefPosition_InfEx_Rqst;
static int ett_pcap_UC_ID_InfEx_Rqst;
static int ett_pcap_InformationExchangeInitiationResponse;
static int ett_pcap_InformationExchangeObjectType_InfEx_Rsp;
static int ett_pcap_RefPosition_InfEx_Rsp;
static int ett_pcap_InformationExchangeInitiationFailure;
static int ett_pcap_PositionInitiationRequest;
static int ett_pcap_PositionInitiationResponse;
static int ett_pcap_PositionInitiationFailure;
static int ett_pcap_PositionActivationRequest;
static int ett_pcap_PositionActivationResponse;
static int ett_pcap_PositionActivationFailure;
static int ett_pcap_InformationReport;
static int ett_pcap_InformationExchangeObjectType_InfEx_Rprt;
static int ett_pcap_RefPosition_InfEx_Rprt;
static int ett_pcap_InformationExchangeTerminationRequest;
static int ett_pcap_InformationExchangeFailureIndication;
static int ett_pcap_ErrorIndication;
static int ett_pcap_PositionParameterModification;
static int ett_pcap_PrivateMessage;
static int ett_pcap_Abort;
static int ett_pcap_PositionPeriodicReport;
static int ett_pcap_PositionPeriodicResult;
static int ett_pcap_PositionPeriodicTermination;
static int ett_pcap_PCAP_PDU;
static int ett_pcap_InitiatingMessage;
static int ett_pcap_SuccessfulOutcome;
static int ett_pcap_UnsuccessfulOutcome;
static int ett_pcap_Outcome;

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;
/*static uint32_t ProtocolExtensionID;*/

/* Dissector tables */
static dissector_table_t pcap_ies_dissector_table;
static dissector_table_t pcap_ies_p1_dissector_table;
static dissector_table_t pcap_ies_p2_dissector_table;
static dissector_table_t pcap_extension_dissector_table;
static dissector_table_t pcap_proc_imsg_dissector_table;
static dissector_table_t pcap_proc_sout_dissector_table;
static dissector_table_t pcap_proc_uout_dissector_table;
static dissector_table_t pcap_proc_out_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


static const value_string pcap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_pcap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_pcap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string pcap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_pcap_local          , ASN1_NO_EXTENSIONS     , dissect_pcap_INTEGER_0_65535 },
  {   1, &hf_pcap_global         , ASN1_NO_EXTENSIONS     , dissect_pcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string pcap_ProcedureCode_vals[] = {
  { id_PositionCalculation, "id-PositionCalculation" },
  { id_InformationExchangeInitiation, "id-InformationExchangeInitiation" },
  { id_InformationReporting, "id-InformationReporting" },
  { id_InformationExchangeTermination, "id-InformationExchangeTermination" },
  { id_InformationExchangeFailure, "id-InformationExchangeFailure" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { id_PositionParameterModification, "id-PositionParameterModification" },
  { id_PositionInitiation, "id-PositionInitiation" },
  { id_PositionActivation, "id-PositionActivation" },
  { id_Abort, "id-Abort" },
  { id_PositionPeriodicReport, "id-PositionPeriodicReport" },
  { id_PositionPeriodicResult, "id-PositionPeriodicResult" },
  { id_PositionPeriodicTermination, "id-PositionPeriodicTermination" },
  { 0, NULL }
};


static int
dissect_pcap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, false);

    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                val_to_str_const(ProcedureCode, pcap_ProcedureCode_vals,
                                 "unknown message"));
  return offset;
}


static const value_string pcap_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_GPS_UTRAN_TRU, "id-GPS-UTRAN-TRU" },
  { id_InformationExchangeID, "id-InformationExchangeID" },
  { id_InformationExchangeObjectType_InfEx_Rprt, "id-InformationExchangeObjectType-InfEx-Rprt" },
  { id_InformationExchangeObjectType_InfEx_Rqst, "id-InformationExchangeObjectType-InfEx-Rqst" },
  { id_InformationExchangeObjectType_InfEx_Rsp, "id-InformationExchangeObjectType-InfEx-Rsp" },
  { id_InformationReportCharacteristics, "id-InformationReportCharacteristics" },
  { id_InformationType, "id-InformationType" },
  { id_GPS_MeasuredResultsList, "id-GPS-MeasuredResultsList" },
  { id_MethodType, "id-MethodType" },
  { id_RefPosition_InfEx_Rqst, "id-RefPosition-InfEx-Rqst" },
  { id_RefPosition_InfEx_Rsp, "id-RefPosition-InfEx-Rsp" },
  { id_RefPosition_Inf_Rprt, "id-RefPosition-Inf-Rprt" },
  { id_RequestedDataValue, "id-RequestedDataValue" },
  { id_RequestedDataValueInformation, "id-RequestedDataValueInformation" },
  { id_TransactionID, "id-TransactionID" },
  { id_UE_PositionEstimate, "id-UE-PositionEstimate" },
  { id_Unknown_19, "id-Unknown-19" },
  { id_CellId_MeasuredResultsSets, "id-CellId-MeasuredResultsSets" },
  { id_Unknown_21, "id-Unknown-21" },
  { id_OTDOA_MeasurementGroup, "id-OTDOA-MeasurementGroup" },
  { id_AccuracyFulfilmentIndicator, "id-AccuracyFulfilmentIndicator" },
  { id_HorizontalAccuracyCode, "id-HorizontalAccuracyCode" },
  { id_VerticalAccuracyCode, "id-VerticalAccuracyCode" },
  { id_UTDOA_Group, "id-UTDOA-Group" },
  { id_Unknown_27, "id-Unknown-27" },
  { id_RequestType, "id-RequestType" },
  { id_UE_PositioningCapability, "id-UE-PositioningCapability" },
  { id_UC_id, "id-UC-id" },
  { id_ResponseTime, "id-ResponseTime" },
  { id_PositioningPriority, "id-PositioningPriority" },
  { id_ClientType, "id-ClientType" },
  { id_PositioningMethod, "id-PositioningMethod" },
  { id_UTDOAPositioning, "id-UTDOAPositioning" },
  { id_GPSPositioning, "id-GPSPositioning" },
  { id_OTDOAAssistanceData, "id-OTDOAAssistanceData" },
  { id_Positioning_ResponseTime, "id-Positioning-ResponseTime" },
  { id_EnvironmentCharacterisation, "id-EnvironmentCharacterisation" },
  { id_PositionData, "id-PositionData" },
  { id_IncludeVelocity, "id-IncludeVelocity" },
  { id_VelocityEstimate, "id-VelocityEstimate" },
  { id_rxTimingDeviation768Info, "id-rxTimingDeviation768Info" },
  { id_UC_ID_InfEx_Rqst, "id-UC-ID-InfEx-Rqst" },
  { id_UE_PositionEstimateInfo, "id-UE-PositionEstimateInfo" },
  { id_UTRAN_GPSReferenceTime, "id-UTRAN-GPSReferenceTime" },
  { id_UTRAN_GPSReferenceTimeResult, "id-UTRAN-GPSReferenceTimeResult" },
  { id_UTRAN_GPS_DriftRate, "id-UTRAN-GPS-DriftRate" },
  { id_OTDOA_AddMeasuredResultsInfo, "id-OTDOA-AddMeasuredResultsInfo" },
  { id_GPS_ReferenceLocation, "id-GPS-ReferenceLocation" },
  { id_OTDOA_MeasuredResultsSets, "id-OTDOA-MeasuredResultsSets" },
  { id_rxTimingDeviation384extInfo, "id-rxTimingDeviation384extInfo" },
  { id_ExtendedRoundTripTime, "id-ExtendedRoundTripTime" },
  { id_PeriodicPosCalcInfo, "id-PeriodicPosCalcInfo" },
  { id_PeriodicLocationInfo, "id-PeriodicLocationInfo" },
  { id_AmountOfReporting, "id-AmountOfReporting" },
  { id_MeasInstructionsUsed, "id-MeasInstructionsUsed" },
  { id_RRCstateChange, "id-RRCstateChange" },
  { id_PeriodicTerminationCause, "id-PeriodicTerminationCause" },
  { id_MeasurementValidity, "id-MeasurementValidity" },
  { id_roundTripTimeInfoWithType1, "id-roundTripTimeInfoWithType1" },
  { id_Unknown_65, "id-Unknown-65" },
  { id_CellIDPositioning, "id-CellIDPositioning" },
  { id_AddMeasurementInfo, "id-AddMeasurementInfo" },
  { id_Extended_RNC_ID, "id-Extended-RNC-ID" },
  { id_GANSS_CommonAssistanceData, "id-GANSS-CommonAssistanceData" },
  { id_GANSS_GenericAssistanceDataList, "id-GANSS-GenericAssistanceDataList" },
  { id_GANSS_MeasuredResultsList, "id-GANSS-MeasuredResultsList" },
  { id_GANSS_UTRAN_TRU, "id-GANSS-UTRAN-TRU" },
  { id_GANSSPositioning, "id-GANSSPositioning" },
  { id_GANSS_PositioningDataSet, "id-GANSS-PositioningDataSet" },
  { id_GNSS_PositioningMethod, "id-GNSS-PositioningMethod" },
  { id_NetworkAssistedGANSSSuport, "id-NetworkAssistedGANSSSuport" },
  { id_TUTRANGANSSMeasurementValueInfo, "id-TUTRANGANSSMeasurementValueInfo" },
  { id_AdditionalGPSAssistDataRequired, "id-AdditionalGPSAssistDataRequired" },
  { id_AdditionalGanssAssistDataRequired, "id-AdditionalGanssAssistDataRequired" },
  { id_angleOfArrivalLCR, "id-angleOfArrivalLCR" },
  { id_extendedTimingAdvanceLCR, "id-extendedTimingAdvanceLCR" },
  { id_additionalMeasurementInforLCR, "id-additionalMeasurementInforLCR" },
  { id_timingAdvanceLCR_R7, "id-timingAdvanceLCR-R7" },
  { id_rxTimingDeviationLCR, "id-rxTimingDeviationLCR" },
  { id_GPSReferenceTimeUncertainty, "id-GPSReferenceTimeUncertainty" },
  { id_GANSS_AddIonoModelReq, "id-GANSS-AddIonoModelReq" },
  { id_GANSS_EarthOrientParaReq, "id-GANSS-EarthOrientParaReq" },
  { id_GANSS_Additional_Ionospheric_Model, "id-GANSS-Additional-Ionospheric-Model" },
  { id_GANSS_Earth_Orientation_Parameters, "id-GANSS-Earth-Orientation-Parameters" },
  { id_GANSS_Additional_Time_Models, "id-GANSS-Additional-Time-Models" },
  { id_GANSS_Additional_Navigation_Models, "id-GANSS-Additional-Navigation-Models" },
  { id_GANSS_Additional_UTC_Models, "id-GANSS-Additional-UTC-Models" },
  { id_GANSS_Auxiliary_Information, "id-GANSS-Auxiliary-Information" },
  { id_GANSS_SBAS_ID, "id-GANSS-SBAS-ID" },
  { id_GANSS_SBAS_IDs, "id-GANSS-SBAS-IDs" },
  { id_GANSS_Signal_IDs, "id-GANSS-Signal-IDs" },
  { id_supportGANSSNonNativeADchoices, "id-supportGANSSNonNativeADchoices" },
  { id_PositionDataUEbased, "id-PositionDataUEbased" },
  { id_ganssCodePhaseAmbiguityExt, "id-ganssCodePhaseAmbiguityExt" },
  { id_ganssIntegerCodePhaseExt, "id-ganssIntegerCodePhaseExt" },
  { id_GANSScarrierPhaseRequested, "id-GANSScarrierPhaseRequested" },
  { id_GANSSMultiFreqMeasRequested, "id-GANSSMultiFreqMeasRequested" },
  { id_ganssReq_AddIonosphericModel, "id-ganssReq-AddIonosphericModel" },
  { id_ganssReq_EarthOrientPara, "id-ganssReq-EarthOrientPara" },
  { id_ganssAddNavigationModel_req, "id-ganssAddNavigationModel-req" },
  { id_ganssAddUTCModel_req, "id-ganssAddUTCModel-req" },
  { id_ganssAuxInfo_req, "id-ganssAuxInfo-req" },
  { id_GANSS_AlmanacModelChoice, "id-GANSS-AlmanacModelChoice" },
  { id_GANSS_alm_keplerianNAVAlmanac, "id-GANSS-alm-keplerianNAVAlmanac" },
  { id_GANSS_alm_keplerianReducedAlmanac, "id-GANSS-alm-keplerianReducedAlmanac" },
  { id_GANSS_alm_keplerianMidiAlmanac, "id-GANSS-alm-keplerianMidiAlmanac" },
  { id_GANSS_alm_keplerianGLONASS, "id-GANSS-alm-keplerianGLONASS" },
  { id_GANSS_alm_ecefSBASAlmanac, "id-GANSS-alm-ecefSBASAlmanac" },
  { id_UTRAN_GANSSReferenceTimeResult, "id-UTRAN-GANSSReferenceTimeResult" },
  { id_GANSS_Reference_Time_Only, "id-GANSS-Reference-Time-Only" },
  { id_GANSS_AddADchoices, "id-GANSS-AddADchoices" },
  { id_OTDOA_ReferenceCellInfo, "id-OTDOA-ReferenceCellInfo" },
  { id_DGNSS_ValidityPeriod, "id-DGNSS-ValidityPeriod" },
  { id_AzimuthAndElevationLSB, "id-AzimuthAndElevationLSB" },
  { id_completeAlmanacProvided, "id-completeAlmanacProvided" },
  { id_GPS_Week_Cycle, "id-GPS-Week-Cycle" },
  { id_GANSS_Day_Cycle, "id-GANSS-Day-Cycle" },
  { id_ganss_Delta_T, "id-ganss-Delta-T" },
  { id_requestedCellIDGERANMeasurements, "id-requestedCellIDGERANMeasurements" },
  { id_CellId_IRATMeasuredResultsSets, "id-CellId-IRATMeasuredResultsSets" },
  { id_Unknown_126, "id-Unknown-126" },
  { id_Unknown_127, "id-Unknown-127" },
  { id_IMSI, "id-IMSI" },
  { id_IMEI, "id-IMEI" },
  { id_GANSS_alm_keplerianBDSAlmanac, "id-GANSS-alm-keplerianBDSAlmanac" },
  { id_BDS_Ionospheric_Grid_Model, "id-BDS-Ionospheric-Grid-Model" },
  { id_DBDS_Correction_Information, "id-DBDS-Correction-Information" },
  { id_BDSIonosphericGridModel, "id-BDSIonosphericGridModel" },
  { id_DBDSCorrection, "id-DBDSCorrection" },
  { id_Confidence, "id-Confidence" },
  { id_ExtraDopplerInfoExtension, "id-ExtraDopplerInfoExtension" },
  { id_GANSS_Confidence, "id-GANSS-Confidence" },
  { id_GANSS_ExtraDopplerExtension, "id-GANSS-ExtraDopplerExtension" },
  { id_Additional_PositioningDataSet, "id-Additional-PositioningDataSet" },
  { id_Additional_PositioningMethod, "id-Additional-PositioningMethod" },
  { id_AddPos_MeasuredResults, "id-AddPos-MeasuredResults" },
  { id_AddPosSupport, "id-AddPosSupport" },
  { 0, NULL }
};

static value_string_ext pcap_ProtocolIE_ID_vals_ext = VALUE_STRING_EXT_INIT(pcap_ProtocolIE_ID_vals);


static int
dissect_pcap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, false);

  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str_ext(ProtocolIE_ID, &pcap_ProtocolIE_ID_vals_ext, "unknown (%d)"));
  }
  return offset;
}



static int
dissect_pcap_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}


static const value_string pcap_TransactionID_vals[] = {
  {   0, "shortTID" },
  {   1, "longTID" },
  { 0, NULL }
};

static const per_choice_t TransactionID_choice[] = {
  {   0, &hf_pcap_shortTID       , ASN1_NO_EXTENSIONS     , dissect_pcap_INTEGER_0_127 },
  {   1, &hf_pcap_longTID        , ASN1_NO_EXTENSIONS     , dissect_pcap_INTEGER_0_32767 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_TransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_TransactionID, TransactionID_choice,
                                 NULL);

  return offset;
}


static const value_string pcap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  {   3, "outcome" },
  { 0, NULL }
};


static int
dissect_pcap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_pcap_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_ID },
  { &hf_pcap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_pcap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Field },
};

static int
dissect_pcap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_pcap_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pcap_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pcap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_pcap_ext_id         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_ID },
  { &hf_pcap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_pcap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolExtensionField },
};

static int
dissect_pcap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, false);

  return offset;
}



static int
dissect_pcap_T_private_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_pcap_private_id     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_PrivateIE_ID },
  { &hf_pcap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_private_value  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_T_private_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_pcap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_PrivateIE_Field },
};

static int
dissect_pcap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, false);

  return offset;
}


static const value_string pcap_AccuracyFulfilmentIndicator_vals[] = {
  {   0, "requested-Accuracy-Fulfilled" },
  {   1, "requested-Accuracy-Not-Fulfilled" },
  { 0, NULL }
};


static int
dissect_pcap_AccuracyFulfilmentIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_AdditionalMethodType_vals[] = {
  {   0, "ue-assisted" },
  {   1, "ue-based" },
  {   2, "ue-based-preferred-but-ue-assisted-allowed" },
  {   3, "ue-assisted-preferred-but-ue-based-allowed" },
  { 0, NULL }
};


static int
dissect_pcap_AdditionalMethodType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_UTCTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                        NO_BOUND, NO_BOUND, false,
                                        NULL);

  return offset;
}



static int
dissect_pcap_BaroMeasurement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            30000U, 115000U, NULL, false);

  return offset;
}


static const per_sequence_t T_barometricPressure_sequence[] = {
  { &hf_pcap_uncompensatedBarometricPressure, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BaroMeasurement },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_barometricPressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_barometricPressure, T_barometricPressure_sequence);

  return offset;
}



static int
dissect_pcap_OCTET_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, false, NULL);

  return offset;
}



static int
dissect_pcap_OCTET_STRING_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, false, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_M127_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 128U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_16777215(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, false);

  return offset;
}


static const value_string pcap_T_wlanRTTunits_vals[] = {
  {   0, "microseconds" },
  {   1, "hundredsofnanoseconds" },
  {   2, "tensofnanoseconds" },
  {   3, "nanoseconds" },
  {   4, "tenthsofnanosecond" },
  { 0, NULL }
};


static int
dissect_pcap_T_wlanRTTunits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 256U, NULL, false);

  return offset;
}



static int
dissect_pcap_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t WLANMeasurementList_Element_sequence[] = {
  { &hf_pcap_wlanBSSID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_OCTET_STRING_SIZE_6 },
  { &hf_pcap_wlanSSID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_OCTET_STRING_SIZE_1_32 },
  { &hf_pcap_wlanRSSI       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_M127_128 },
  { &hf_pcap_wlanRTTvalue   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_16777215 },
  { &hf_pcap_wlanRTTunits   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_T_wlanRTTunits },
  { &hf_pcap_wlanRTTaccuracy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_wlanAPChannelFrequency, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_256 },
  { &hf_pcap_wlanServingFlag, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BOOLEAN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_WLANMeasurementList_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_WLANMeasurementList_Element, WLANMeasurementList_Element_sequence);

  return offset;
}


static const per_sequence_t WLANMeasurementList_sequence_of[1] = {
  { &hf_pcap_WLANMeasurementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_WLANMeasurementList_Element },
};

static int
dissect_pcap_WLANMeasurementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_WLANMeasurementList, WLANMeasurementList_sequence_of,
                                                  1, maxWLANs, false);

  return offset;
}


static const per_sequence_t T_wlan_sequence[] = {
  { &hf_pcap_wlanMeasurementList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_WLANMeasurementList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_wlan(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_wlan, T_wlan_sequence);

  return offset;
}


static const per_sequence_t BTMeasurementList_Element_sequence[] = {
  { &hf_pcap_btADDR         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_OCTET_STRING_SIZE_6 },
  { &hf_pcap_btRSSI         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_M127_128 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_BTMeasurementList_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_BTMeasurementList_Element, BTMeasurementList_Element_sequence);

  return offset;
}


static const per_sequence_t BTMeasurementList_sequence_of[1] = {
  { &hf_pcap_BTMeasurementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BTMeasurementList_Element },
};

static int
dissect_pcap_BTMeasurementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_BTMeasurementList, BTMeasurementList_sequence_of,
                                                  1, maxBTs, false);

  return offset;
}


static const per_sequence_t T_bt_sequence[] = {
  { &hf_pcap_btMeasurementList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BTMeasurementList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_bt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_bt, T_bt_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_2097151(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2097151U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t MBSMeasurementList_Element_sequence[] = {
  { &hf_pcap_transmitterID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_32767 },
  { &hf_pcap_codephase      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_2097151 },
  { &hf_pcap_codephaseRMS   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_MBSMeasurementList_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_MBSMeasurementList_Element, MBSMeasurementList_Element_sequence);

  return offset;
}


static const per_sequence_t MBSMeasurementList_sequence_of[1] = {
  { &hf_pcap_MBSMeasurementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_MBSMeasurementList_Element },
};

static int
dissect_pcap_MBSMeasurementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_MBSMeasurementList, MBSMeasurementList_sequence_of,
                                                  1, maxBeacons, false);

  return offset;
}


static const per_sequence_t T_mbs_sequence[] = {
  { &hf_pcap_mbsMeasurementList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MBSMeasurementList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_mbs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_mbs, T_mbs_sequence);

  return offset;
}


static const value_string pcap_T_type_vals[] = {
  {   0, "barometricPressure" },
  {   1, "wlan" },
  {   2, "bt" },
  {   3, "mbs" },
  { 0, NULL }
};

static const per_choice_t T_type_choice[] = {
  {   0, &hf_pcap_barometricPressure, ASN1_EXTENSION_ROOT    , dissect_pcap_T_barometricPressure },
  {   1, &hf_pcap_wlan           , ASN1_EXTENSION_ROOT    , dissect_pcap_T_wlan },
  {   2, &hf_pcap_bt             , ASN1_EXTENSION_ROOT    , dissect_pcap_T_bt },
  {   3, &hf_pcap_mbs            , ASN1_EXTENSION_ROOT    , dissect_pcap_T_mbs },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_type, T_type_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AddPos_MeasuredResults_Element_sequence[] = {
  { &hf_pcap_timestamp      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UTCTime },
  { &hf_pcap_type           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_type },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AddPos_MeasuredResults_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AddPos_MeasuredResults_Element, AddPos_MeasuredResults_Element_sequence);

  return offset;
}


static const per_sequence_t AddPos_MeasuredResults_sequence_of[1] = {
  { &hf_pcap_AddPos_MeasuredResults_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_AddPos_MeasuredResults_Element },
};

static int
dissect_pcap_AddPos_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_AddPos_MeasuredResults, AddPos_MeasuredResults_sequence_of,
                                                  1, maxAddPos, false);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     11, 11, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t AlmanacSatInfo_sequence[] = {
  { &hf_pcap_dataID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_e              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_almanacSatInfo_t_oa, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_deltaI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_omegaDot       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_satHealth      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_a_Sqrt         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_omega0         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_m0             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_omega          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_af0            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_af1            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AlmanacSatInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AlmanacSatInfo, AlmanacSatInfo_sequence);

  return offset;
}


static const per_sequence_t AlmanacSatInfoList_sequence_of[1] = {
  { &hf_pcap_AlmanacSatInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_AlmanacSatInfo },
};

static int
dissect_pcap_AlmanacSatInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_AlmanacSatInfoList, AlmanacSatInfoList_sequence_of,
                                                  1, maxSatAlmanac, false);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_364(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     364, 364, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GPS_AlmanacAndSatelliteHealth_sequence[] = {
  { &hf_pcap_wn_a           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_almanacSatInfoList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AlmanacSatInfoList },
  { &hf_pcap_svGlobalHealth , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_364 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_AlmanacAndSatelliteHealth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_AlmanacAndSatelliteHealth, GPS_AlmanacAndSatelliteHealth_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t AlmanacAndSatelliteHealthSIB_sequence[] = {
  { &hf_pcap_gpsAlmanacAndSatelliteHealth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GPS_AlmanacAndSatelliteHealth },
  { &hf_pcap_satMask        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1_32 },
  { &hf_pcap_lsbTOW         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AlmanacAndSatelliteHealthSIB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AlmanacAndSatelliteHealthSIB, AlmanacAndSatelliteHealthSIB_sequence);

  return offset;
}


static const value_string pcap_CauseRadioNetwork_vals[] = {
  {   0, "invalid-reference-information" },
  {   1, "information-temporarily-not-available" },
  {   2, "information-provision-not-supported-for-the-object" },
  {   3, "position-calculation-error-invalid-GPS-measured-results" },
  {   4, "position-calculation-error-invalid-CellID-measured-results" },
  {   5, "position-calculation-error-invalid-OTDOA-measured-results" },
  {   6, "position-calculation-error-AGPS-positioning-method-not-supported" },
  {   7, "position-calculation-error-CellID-positioning-method-not-supported" },
  {   8, "position-calculation-error-OTDOA-positioning-method-not-supported" },
  {   9, "initial-UE-position-estimate-missing" },
  {  10, "position-caclulation-error-invalid-UTDOA-measured-results" },
  {  11, "position-calculation-error-UTDOA-positioning-method-not-supported" },
  {  12, "position-calculation-error-UTDOA-not-supported-UTRAN-cell" },
  {  13, "positioning-method-not-supported" },
  {  14, "loss-of-contact-with-UE" },
  {  15, "sAS-unable-to-perform-UTDOA-positioning-within-response-time" },
  {  16, "location-measurement-failure" },
  {  17, "ue-positioning-error-Not-enough-OTDOA-cells" },
  {  18, "ue-positioning-error-Not-enough-GPS-Satellites" },
  {  19, "ue-positioning-error-Reference-Cell-not-serving-cell" },
  {  20, "ue-positioning-error-Not-Accomplished-GPS-Timing-of-Cell-Frames" },
  {  21, "ue-positioning-error-Undefined-Error" },
  {  22, "position-calculation-error-invalid-Galileo-measured-results" },
  {  23, "position-calculation-error-AGalileo-positioning-method-not-supported" },
  {  24, "ue-positioning-error-Not-enough-Galileo-Satellites" },
  {  25, "ue-positioning-error-Not-Accomplished-Galileo-Timing-of-Cell-Frames" },
  {  26, "ue-positioning-error-Assistance-Data-missing" },
  {  27, "position-calculation-error-invalid-GLONASS-measured-results" },
  {  28, "position-calculation-error-invalid-GANSS-measured-results" },
  {  29, "position-calculation-error-AGANSS-positioning-method-not-supported" },
  {  30, "ue-positioning-error-Not-enough-GANSS-Satellites" },
  {  31, "ue-positioning-error-Not-Accomplished-GANSS-Timing-of-Cell-Frames" },
  {  32, "position-calculation-error-invalid-BDS-measured-results" },
  {  33, "ue-Positioning-Error-Not-enough-BDS-Satellites" },
  {  34, "position-calculation-error-A-BDS-positioning-method-not-supported" },
  { 0, NULL }
};

static value_string_ext pcap_CauseRadioNetwork_vals_ext = VALUE_STRING_EXT_INIT(pcap_CauseRadioNetwork_vals);


static int
dissect_pcap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 31, NULL);

  return offset;
}


static const value_string pcap_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_pcap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "unspecified" },
  {   6, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_pcap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_CauseMisc_vals[] = {
  {   0, "processing-overload" },
  {   1, "hardware-failure" },
  {   2, "o-and-m-intervention" },
  {   3, "unspecified" },
  { 0, NULL }
};


static int
dissect_pcap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_pcap_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_pcap_CauseRadioNetwork },
  {   1, &hf_pcap_transport      , ASN1_EXTENSION_ROOT    , dissect_pcap_CauseTransport },
  {   2, &hf_pcap_protocol       , ASN1_EXTENSION_ROOT    , dissect_pcap_CauseProtocol },
  {   3, &hf_pcap_misc           , ASN1_EXTENSION_ROOT    , dissect_pcap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}


static const per_sequence_t UC_ID_sequence[] = {
  { &hf_pcap_rNC_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_c_ID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_65535 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UC_ID, UC_ID_sequence);

  return offset;
}


static const value_string pcap_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_pcap_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, false);

  return offset;
}


static const per_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_pcap_latitudeSign   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_latitudeSign },
  { &hf_pcap_latitude       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_8388607 },
  { &hf_pcap_longitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M8388608_8388607 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GeographicalCoordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GeographicalCoordinates, GeographicalCoordinates_sequence);

  return offset;
}


static const value_string pcap_T_directionOfAltitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_pcap_T_directionOfAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GA_AltitudeAndDirection_sequence[] = {
  { &hf_pcap_directionOfAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_directionOfAltitude },
  { &hf_pcap_altitude       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_AltitudeAndDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_AltitudeAndDirection, GA_AltitudeAndDirection_sequence);

  return offset;
}


static const per_sequence_t UTRANAccessPointPositionAltitude_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_ga_AltitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GA_AltitudeAndDirection },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTRANAccessPointPositionAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTRANAccessPointPositionAltitude, UTRANAccessPointPositionAltitude_sequence);

  return offset;
}


static const per_sequence_t GA_Point_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_Point(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_Point, GA_Point_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithUnCertainty_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_uncertaintyCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_PointWithUnCertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_PointWithUnCertainty, GA_PointWithUnCertainty_sequence);

  return offset;
}


static const per_sequence_t GA_Polygon_item_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_Polygon_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_Polygon_item, GA_Polygon_item_sequence);

  return offset;
}


static const per_sequence_t GA_Polygon_sequence_of[1] = {
  { &hf_pcap_GA_Polygon_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GA_Polygon_item },
};

static int
dissect_pcap_GA_Polygon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GA_Polygon, GA_Polygon_sequence_of,
                                                  1, maxNrOfPoints, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_89(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 89U, NULL, false);

  return offset;
}


static const per_sequence_t GA_UncertaintyEllipse_sequence[] = {
  { &hf_pcap_uncertaintySemi_major, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_uncertaintySemi_minor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_orientationOfMajorAxis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_89 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_UncertaintyEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_UncertaintyEllipse, GA_UncertaintyEllipse_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}


static const per_sequence_t GA_PointWithUnCertaintyEllipse_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_uncertaintyEllipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GA_UncertaintyEllipse },
  { &hf_pcap_confidence     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_100 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_PointWithUnCertaintyEllipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_PointWithUnCertaintyEllipse, GA_PointWithUnCertaintyEllipse_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithAltitude_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_altitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GA_AltitudeAndDirection },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_PointWithAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_PointWithAltitude, GA_PointWithAltitude_sequence);

  return offset;
}


static const per_sequence_t GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_altitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GA_AltitudeAndDirection },
  { &hf_pcap_uncertaintyEllipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GA_UncertaintyEllipse },
  { &hf_pcap_uncertaintyAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_confidence     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_100 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_PointWithAltitudeAndUncertaintyEllipsoid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_PointWithAltitudeAndUncertaintyEllipsoid, GA_PointWithAltitudeAndUncertaintyEllipsoid_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, false);

  return offset;
}


static const per_sequence_t GA_EllipsoidArc_sequence[] = {
  { &hf_pcap_geographicalCoordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GeographicalCoordinates },
  { &hf_pcap_innerRadius    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_65535 },
  { &hf_pcap_uncertaintyRadius, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_offsetAngle    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_179 },
  { &hf_pcap_includedAngle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_179 },
  { &hf_pcap_confidence     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_100 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GA_EllipsoidArc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GA_EllipsoidArc, GA_EllipsoidArc_sequence);

  return offset;
}


static const value_string pcap_UE_PositionEstimate_vals[] = {
  {   0, "point" },
  {   1, "pointWithUnCertainty" },
  {   2, "polygon" },
  {   3, "pointWithUncertaintyEllipse" },
  {   4, "pointWithAltitude" },
  {   5, "pointWithAltitudeAndUncertaintyEllipsoid" },
  {   6, "ellipsoidArc" },
  { 0, NULL }
};

static const per_choice_t UE_PositionEstimate_choice[] = {
  {   0, &hf_pcap_point          , ASN1_EXTENSION_ROOT    , dissect_pcap_GA_Point },
  {   1, &hf_pcap_pointWithUnCertainty, ASN1_EXTENSION_ROOT    , dissect_pcap_GA_PointWithUnCertainty },
  {   2, &hf_pcap_polygon        , ASN1_EXTENSION_ROOT    , dissect_pcap_GA_Polygon },
  {   3, &hf_pcap_pointWithUncertaintyEllipse, ASN1_EXTENSION_ROOT    , dissect_pcap_GA_PointWithUnCertaintyEllipse },
  {   4, &hf_pcap_pointWithAltitude, ASN1_EXTENSION_ROOT    , dissect_pcap_GA_PointWithAltitude },
  {   5, &hf_pcap_pointWithAltitudeAndUncertaintyEllipsoid, ASN1_EXTENSION_ROOT    , dissect_pcap_GA_PointWithAltitudeAndUncertaintyEllipsoid },
  {   6, &hf_pcap_ellipsoidArc   , ASN1_EXTENSION_ROOT    , dissect_pcap_GA_EllipsoidArc },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_UE_PositionEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_UE_PositionEstimate, UE_PositionEstimate_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_UE_RxTxTimeDifferenceType2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, false);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 3, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     5, 5, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t UE_PositioningMeasQuality_sequence[] = {
  { &hf_pcap_stdResolution  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_numberOfMeasurements, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { &hf_pcap_stdOfMeasurements, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_PositioningMeasQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_PositioningMeasQuality, UE_PositioningMeasQuality_sequence);

  return offset;
}



static int
dissect_pcap_RoundTripTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32766U, NULL, false);

  return offset;
}


static const per_sequence_t RoundTripTimeInfo_sequence[] = {
  { &hf_pcap_ue_RxTxTimeDifferenceType2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_RxTxTimeDifferenceType2 },
  { &hf_pcap_ue_PositioningMeasQuality, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_PositioningMeasQuality },
  { &hf_pcap_roundTripTime  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RoundTripTime },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RoundTripTimeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RoundTripTimeInfo, RoundTripTimeInfo_sequence);

  return offset;
}



static int
dissect_pcap_RxTimingDeviation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, false);

  return offset;
}



static int
dissect_pcap_TimingAdvance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t RxTimingDeviationInfo_sequence[] = {
  { &hf_pcap_rxTimingDeviation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RxTimingDeviation },
  { &hf_pcap_timingAdvance  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TimingAdvance },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RxTimingDeviationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RxTimingDeviationInfo, RxTimingDeviationInfo_sequence);

  return offset;
}



static int
dissect_pcap_RxTimingDeviationLCR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, false);

  return offset;
}



static int
dissect_pcap_TimingAdvanceLCR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, false);

  return offset;
}


static const per_sequence_t RxTimingDeviationLCRInfo_sequence[] = {
  { &hf_pcap_rxTimingDeviationLCR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RxTimingDeviationLCR },
  { &hf_pcap_timingAdvanceLCR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TimingAdvanceLCR },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RxTimingDeviationLCRInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RxTimingDeviationLCRInfo, RxTimingDeviationLCRInfo_sequence);

  return offset;
}



static int
dissect_pcap_Pathloss(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            46U, 158U, NULL, false);

  return offset;
}


static const per_sequence_t CellId_MeasuredResultsInfo_sequence[] = {
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_uTRANAccessPointPositionAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UTRANAccessPointPositionAltitude },
  { &hf_pcap_ue_PositionEstimate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UE_PositionEstimate },
  { &hf_pcap_roundTripTimeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_RoundTripTimeInfo },
  { &hf_pcap_rxTimingDeviationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_RxTimingDeviationInfo },
  { &hf_pcap_rxTimingDeviationLCRInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_RxTimingDeviationLCRInfo },
  { &hf_pcap_pathloss       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Pathloss },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_CellId_MeasuredResultsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_CellId_MeasuredResultsInfo, CellId_MeasuredResultsInfo_sequence);

  return offset;
}


static const per_sequence_t CellId_MeasuredResultsInfoList_sequence_of[1] = {
  { &hf_pcap_CellId_MeasuredResultsInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_CellId_MeasuredResultsInfo },
};

static int
dissect_pcap_CellId_MeasuredResultsInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_CellId_MeasuredResultsInfoList, CellId_MeasuredResultsInfoList_sequence_of,
                                                  1, maxNrOfMeasNCell, false);

  return offset;
}


static const per_sequence_t CellId_MeasuredResultsSets_sequence_of[1] = {
  { &hf_pcap_CellId_MeasuredResultsSets_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_CellId_MeasuredResultsInfoList },
};

static int
dissect_pcap_CellId_MeasuredResultsSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_CellId_MeasuredResultsSets, CellId_MeasuredResultsSets_sequence_of,
                                                  1, maxNrOfMeasurements, false);

  return offset;
}



static int
dissect_pcap_UE_RxTxTimeDifferenceType1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            768U, 1280U, NULL, false);

  return offset;
}



static int
dissect_pcap_ExtendedRoundTripTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            32767U, 103041U, NULL, false);

  return offset;
}


static const per_sequence_t RoundTripTimeInfoWithType1_sequence[] = {
  { &hf_pcap_ue_RxTxTimeDifferenceType1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_RxTxTimeDifferenceType1 },
  { &hf_pcap_roundTripTime  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RoundTripTime },
  { &hf_pcap_extendedRoundTripTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ExtendedRoundTripTime },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RoundTripTimeInfoWithType1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RoundTripTimeInfoWithType1, RoundTripTimeInfoWithType1_sequence);

  return offset;
}



static int
dissect_pcap_ExtendedTimingAdvanceLCR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2048U, 8191U, NULL, false);

  return offset;
}



static int
dissect_pcap_RxTimingDeviation768(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_pcap_TimingAdvance768(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, false);

  return offset;
}


static const per_sequence_t RxTimingDeviation768Info_sequence[] = {
  { &hf_pcap_rxTimingDeviation768, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RxTimingDeviation768 },
  { &hf_pcap_timingAdvance768, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TimingAdvance768 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RxTimingDeviation768Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RxTimingDeviation768Info, RxTimingDeviation768Info_sequence);

  return offset;
}



static int
dissect_pcap_RxTimingDeviation384ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}



static int
dissect_pcap_TimingAdvance384ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t RxTimingDeviation384extInfo_sequence[] = {
  { &hf_pcap_rxTimingDeviation384ext, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RxTimingDeviation384ext },
  { &hf_pcap_timingAdvance384ext, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TimingAdvance384ext },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RxTimingDeviation384extInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RxTimingDeviation384extInfo, RxTimingDeviation384extInfo_sequence);

  return offset;
}



static int
dissect_pcap_CPICH_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -5, 91U, NULL, false);

  return offset;
}



static int
dissect_pcap_CPICH_EcNo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 49U, NULL, false);

  return offset;
}


static const per_sequence_t AddMeasurementInfo_sequence[] = {
  { &hf_pcap_cpich_RSCP     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_CPICH_RSCP },
  { &hf_pcap_cpich_EcNo     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_CPICH_EcNo },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AddMeasurementInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AddMeasurementInfo, AddMeasurementInfo_sequence);

  return offset;
}



static int
dissect_pcap_AOA_LCR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 719U, NULL, false);

  return offset;
}


static const value_string pcap_AOA_LCR_Accuracy_Class_vals[] = {
  {   0, "a" },
  {   1, "b" },
  {   2, "c" },
  {   3, "d" },
  {   4, "e" },
  {   5, "f" },
  {   6, "g" },
  {   7, "h" },
  { 0, NULL }
};


static int
dissect_pcap_AOA_LCR_Accuracy_Class(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t AngleOfArrivalLCR_sequence[] = {
  { &hf_pcap_aOA_LCR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AOA_LCR },
  { &hf_pcap_aOA_LCR_Accuracy_Class, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AOA_LCR_Accuracy_Class },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AngleOfArrivalLCR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AngleOfArrivalLCR, AngleOfArrivalLCR_sequence);

  return offset;
}



static int
dissect_pcap_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}


static const per_sequence_t GERANCellGlobalID_sequence[] = {
  { &hf_pcap_plmn_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PLMN_Identity },
  { &hf_pcap_locationAreaCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_cellIdentity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_iE_Extenstions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GERANCellGlobalID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GERANCellGlobalID, GERANCellGlobalID_sequence);

  return offset;
}


static const per_sequence_t GSM_BSIC_sequence[] = {
  { &hf_pcap_networkColourCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { &hf_pcap_baseStationColourCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GSM_BSIC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GSM_BSIC, GSM_BSIC_sequence);

  return offset;
}



static int
dissect_pcap_GSM_BCCH_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}


static const per_sequence_t GERANPhysicalCellID_sequence[] = {
  { &hf_pcap_bsic           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GSM_BSIC },
  { &hf_pcap_arfcn          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GSM_BCCH_ARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GERANPhysicalCellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GERANPhysicalCellID, GERANPhysicalCellID_sequence);

  return offset;
}



static int
dissect_pcap_GSM_RSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t GERAN_MeasuredResultsInfo_sequence[] = {
  { &hf_pcap_gERANCellID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GERANCellGlobalID },
  { &hf_pcap_gERANPhysicalCellID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GERANPhysicalCellID },
  { &hf_pcap_gSM_RSSI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GSM_RSSI },
  { &hf_pcap_iE_Extenstions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GERAN_MeasuredResultsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GERAN_MeasuredResultsInfo, GERAN_MeasuredResultsInfo_sequence);

  return offset;
}


static const per_sequence_t GERAN_MeasuredResultsInfoList_sequence_of[1] = {
  { &hf_pcap_GERAN_MeasuredResultsInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GERAN_MeasuredResultsInfo },
};

static int
dissect_pcap_GERAN_MeasuredResultsInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GERAN_MeasuredResultsInfoList, GERAN_MeasuredResultsInfoList_sequence_of,
                                                  1, maxReportedGERANCells, false);

  return offset;
}


static const per_sequence_t CellId_IRATMeasuredResultsInfoList_sequence[] = {
  { &hf_pcap_gERAN_MeasuredResultsInfoList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GERAN_MeasuredResultsInfoList },
  { &hf_pcap_iE_Extenstions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_CellId_IRATMeasuredResultsInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_CellId_IRATMeasuredResultsInfoList, CellId_IRATMeasuredResultsInfoList_sequence);

  return offset;
}


static const per_sequence_t CellId_IRATMeasuredResultsSets_sequence_of[1] = {
  { &hf_pcap_CellId_IRATMeasuredResultsSets_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_CellId_IRATMeasuredResultsInfoList },
};

static int
dissect_pcap_CellId_IRATMeasuredResultsSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_CellId_IRATMeasuredResultsSets, CellId_IRATMeasuredResultsSets_sequence_of,
                                                  1, maxNrOfIRATMeasurements, false);

  return offset;
}


static const per_sequence_t T_fdd_sequence[] = {
  { &hf_pcap_roundTripTimeInfoWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_pathlossWanted , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_roundTripTimeInfoWithType1Wanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_cpichRSCPWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_cpicEcNoWanted , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_fdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_fdd, T_fdd_sequence);

  return offset;
}


static const per_sequence_t T_tdd_sequence[] = {
  { &hf_pcap_rxTimingDeviationInfoWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_pathlossWanted , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_rxTimingDeviationLCRInfoWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_rxTimingDeviation768InfoWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_rxTimingDeviation384extInfoWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_angleOfArrivalLCRWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_timingAdvanceLCRWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_tdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_tdd, T_tdd_sequence);

  return offset;
}


static const value_string pcap_RequestedCellIDMeasurements_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t RequestedCellIDMeasurements_choice[] = {
  {   0, &hf_pcap_fdd            , ASN1_EXTENSION_ROOT    , dissect_pcap_T_fdd },
  {   1, &hf_pcap_tdd            , ASN1_EXTENSION_ROOT    , dissect_pcap_T_tdd },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_RequestedCellIDMeasurements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_RequestedCellIDMeasurements, RequestedCellIDMeasurements_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellIDPositioning_sequence[] = {
  { &hf_pcap_requestedCellIDMeasurements, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RequestedCellIDMeasurements },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_CellIDPositioning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_CellIDPositioning, CellIDPositioning_sequence);

  return offset;
}


static const per_sequence_t RequestedCellIDGERANMeasurements_sequence[] = {
  { &hf_pcap_rSSIMeasurementsWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RequestedCellIDGERANMeasurements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RequestedCellIDGERANMeasurements, RequestedCellIDGERANMeasurements_sequence);

  return offset;
}


static const value_string pcap_ClientType_vals[] = {
  {   0, "emergency-services" },
  {   1, "value-added-services" },
  {   2, "plmn-operator-services" },
  {   3, "lawful-intercept-services" },
  {   4, "plmn-operator-broadcast-services" },
  {   5, "plmn-operator-oam" },
  {   6, "plmn-operator-anonymous-statistics" },
  {   7, "plmn-operator-target-ms-service-support" },
  { 0, NULL }
};


static int
dissect_pcap_ClientType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_CriticalityDiagnosticsRepetition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_pcap_MessageStructureRepetition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, false);

  return offset;
}


static const per_sequence_t MessageStructure_item_sequence[] = {
  { &hf_pcap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_ID },
  { &hf_pcap_repetitionNumber_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_MessageStructureRepetition },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_MessageStructure_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_MessageStructure_item, MessageStructure_item_sequence);

  return offset;
}


static const per_sequence_t MessageStructure_sequence_of[1] = {
  { &hf_pcap_MessageStructure_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_MessageStructure_item },
};

static int
dissect_pcap_MessageStructure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_MessageStructure, MessageStructure_sequence_of,
                                                  1, maxNrOfLevels, false);

  return offset;
}


static const value_string pcap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_pcap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_pcap_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_ID },
  { &hf_pcap_repetitionNumber, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_CriticalityDiagnosticsRepetition },
  { &hf_pcap_messageStructure, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_MessageStructure },
  { &hf_pcap_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TypeOfError },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_pcap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_pcap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, false);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_pcap_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProcedureCode },
  { &hf_pcap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TriggeringMessage },
  { &hf_pcap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Criticality },
  { &hf_pcap_transactionID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransactionID },
  { &hf_pcap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_CriticalityDiagnostics_IE_List },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_604799(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 604799U, NULL, false);

  return offset;
}


static const value_string pcap_DiffCorrectionStatus_vals[] = {
  {   0, "udre-1-0" },
  {   1, "udre-0-75" },
  {   2, "udre-0-5" },
  {   3, "udre-0-3" },
  {   4, "udre-0-2" },
  {   5, "udre-0-1" },
  {   6, "noData" },
  {   7, "invalidData" },
  { 0, NULL }
};


static int
dissect_pcap_DiffCorrectionStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}


static const value_string pcap_UDRE_vals[] = {
  {   0, "lessThan1" },
  {   1, "between1-and-4" },
  {   2, "between4-and-8" },
  {   3, "over8" },
  { 0, NULL }
};


static int
dissect_pcap_UDRE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_PRC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2047, 2047U, NULL, false);

  return offset;
}



static int
dissect_pcap_RRC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, false);

  return offset;
}


static const per_sequence_t DGPS_CorrectionSatInfo_sequence[] = {
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_iode           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_udre           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UDRE },
  { &hf_pcap_prc            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PRC },
  { &hf_pcap_rrc            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RRC },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DGPS_CorrectionSatInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DGPS_CorrectionSatInfo, DGPS_CorrectionSatInfo_sequence);

  return offset;
}


static const per_sequence_t DGPS_CorrectionSatInfoList_sequence_of[1] = {
  { &hf_pcap_DGPS_CorrectionSatInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_DGPS_CorrectionSatInfo },
};

static int
dissect_pcap_DGPS_CorrectionSatInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_DGPS_CorrectionSatInfoList, DGPS_CorrectionSatInfoList_sequence_of,
                                                  1, maxSat, false);

  return offset;
}


static const per_sequence_t DGPSCorrections_sequence[] = {
  { &hf_pcap_gps_TOW_sec    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_604799 },
  { &hf_pcap_statusHealth   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DiffCorrectionStatus },
  { &hf_pcap_dgps_CorrectionSatInfoList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DGPS_CorrectionSatInfoList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DGPSCorrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DGPSCorrections, DGPSCorrections_sequence);

  return offset;
}


static const value_string pcap_UDREGrowthRate_vals[] = {
  {   0, "growth-1-point-5" },
  {   1, "growth-2" },
  {   2, "growth-4" },
  {   3, "growth-6" },
  {   4, "growth-8" },
  {   5, "growth-10" },
  {   6, "growth-12" },
  {   7, "growth-16" },
  { 0, NULL }
};


static int
dissect_pcap_UDREGrowthRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}


static const value_string pcap_UDREValidityTime_vals[] = {
  {   0, "val-20sec" },
  {   1, "val-40sec" },
  {   2, "val-80sec" },
  {   3, "val-160sec" },
  {   4, "val-320sec" },
  {   5, "val-640sec" },
  {   6, "val-1280sec" },
  {   7, "val-2560sec" },
  { 0, NULL }
};


static int
dissect_pcap_UDREValidityTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t DGNSS_ValidityPeriod_sequence[] = {
  { &hf_pcap_udreGrowthRate , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UDREGrowthRate },
  { &hf_pcap_udreValidityTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UDREValidityTime },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DGNSS_ValidityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DGNSS_ValidityPeriod, DGNSS_ValidityPeriod_sequence);

  return offset;
}



static int
dissect_pcap_IMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_pcap_IMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, false, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_37158911999999_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(37158911999999), NULL, true);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTimeResult_sequence[] = {
  { &hf_pcap_ue_GPSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_37158911999999_ },
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_sfn            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTRAN_GPSReferenceTimeResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTRAN_GPSReferenceTimeResult, UTRAN_GPSReferenceTimeResult_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_604799999_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 604799999U, NULL, true);

  return offset;
}


static const per_sequence_t Cell_Timing_sequence[] = {
  { &hf_pcap_sfn            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Cell_Timing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Cell_Timing, Cell_Timing_sequence);

  return offset;
}



static int
dissect_pcap_Extension_ReferenceTimeChoice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pcap_ProtocolIE_Single_Container(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pcap_ReferenceTimeChoice_vals[] = {
  {   0, "utran-GPSReferenceTimeResult" },
  {   1, "gps-ReferenceTimeOnly" },
  {   2, "cell-Timing" },
  {   3, "extension-ReferenceTimeChoice" },
  { 0, NULL }
};

static const per_choice_t ReferenceTimeChoice_choice[] = {
  {   0, &hf_pcap_utran_GPSReferenceTimeResult, ASN1_EXTENSION_ROOT    , dissect_pcap_UTRAN_GPSReferenceTimeResult },
  {   1, &hf_pcap_gps_ReferenceTimeOnly, ASN1_EXTENSION_ROOT    , dissect_pcap_INTEGER_0_604799999_ },
  {   2, &hf_pcap_cell_Timing    , ASN1_EXTENSION_ROOT    , dissect_pcap_Cell_Timing },
  {   3, &hf_pcap_extension_ReferenceTimeChoice, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_Extension_ReferenceTimeChoice },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_ReferenceTimeChoice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_ReferenceTimeChoice, ReferenceTimeChoice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UE_PositionEstimateInfo_sequence[] = {
  { &hf_pcap_referenceTimeChoice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ReferenceTimeChoice },
  { &hf_pcap_ue_positionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_PositionEstimate },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_PositionEstimateInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_PositionEstimateInfo, UE_PositionEstimateInfo_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_3599999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3599999U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSID_sequence[] = {
  { &hf_pcap_ganss_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_7 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSSID, GANSSID_sequence);

  return offset;
}


static const per_sequence_t GANSS_Reference_Time_Only_sequence[] = {
  { &hf_pcap_ganssTODmsec   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_3599999 },
  { &hf_pcap_ganssTimeID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Reference_Time_Only(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Reference_Time_Only, GANSS_Reference_Time_Only_sequence);

  return offset;
}


static const per_sequence_t PositionDataUEbased_sequence[] = {
  { &hf_pcap_positionData   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionDataUEbased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionDataUEbased, PositionDataUEbased_sequence);

  return offset;
}



static int
dissect_pcap_PositioningDataDiscriminator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t PositioningDataSet_sequence_of[1] = {
  { &hf_pcap_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_PositioningMethodAndUsage },
};

static int
dissect_pcap_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_PositioningDataSet, PositioningDataSet_sequence_of,
                                                  1, maxSet, false);

  return offset;
}


static const per_sequence_t PositionData_sequence[] = {
  { &hf_pcap_positioningDataDiscriminator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PositioningDataDiscriminator },
  { &hf_pcap_positioningDataSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_PositioningDataSet },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionData, PositionData_sequence);

  return offset;
}



static int
dissect_pcap_GANSS_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t GANSS_PositioningDataSet_sequence_of[1] = {
  { &hf_pcap_GANSS_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_PositioningMethodAndUsage },
};

static int
dissect_pcap_GANSS_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_PositioningDataSet, GANSS_PositioningDataSet_sequence_of,
                                                  1, maxGANSSSet, false);

  return offset;
}



static int
dissect_pcap_Additional_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t Additional_PositioningDataSet_sequence_of[1] = {
  { &hf_pcap_Additional_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Additional_PositioningMethodAndUsage },
};

static int
dissect_pcap_Additional_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_Additional_PositioningDataSet, Additional_PositioningDataSet_sequence_of,
                                                  1, maxAddPos, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_604799999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 604799999U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M2048_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M42_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -42, 21U, NULL, false);

  return offset;
}


static const value_string pcap_DopplerUncertainty_vals[] = {
  {   0, "hz12-5" },
  {   1, "hz25" },
  {   2, "hz50" },
  {   3, "hz100" },
  {   4, "hz200" },
  { 0, NULL }
};


static int
dissect_pcap_DopplerUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ExtraDopplerInfo_sequence[] = {
  { &hf_pcap_doppler1stOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M42_21 },
  { &hf_pcap_dopplerUncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DopplerUncertainty },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_ExtraDopplerInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_ExtraDopplerInfo, ExtraDopplerInfo_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_1022(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1022U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 19U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}


static const value_string pcap_CodePhaseSearchWindow_vals[] = {
  {   0, "w1023" },
  {   1, "w1" },
  {   2, "w2" },
  {   3, "w3" },
  {   4, "w4" },
  {   5, "w6" },
  {   6, "w8" },
  {   7, "w12" },
  {   8, "w16" },
  {   9, "w24" },
  {  10, "w32" },
  {  11, "w48" },
  {  12, "w64" },
  {  13, "w96" },
  {  14, "w128" },
  {  15, "w192" },
  { 0, NULL }
};

static value_string_ext pcap_CodePhaseSearchWindow_vals_ext = VALUE_STRING_EXT_INIT(pcap_CodePhaseSearchWindow_vals);


static int
dissect_pcap_CodePhaseSearchWindow(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, false);

  return offset;
}


static const per_sequence_t AzimuthAndElevation_sequence[] = {
  { &hf_pcap_azimuth        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_31 },
  { &hf_pcap_elevation      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_7 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AzimuthAndElevation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AzimuthAndElevation, AzimuthAndElevation_sequence);

  return offset;
}


static const per_sequence_t AcquisitionSatInfo_sequence[] = {
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_doppler0thOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M2048_2047 },
  { &hf_pcap_extraDopplerInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ExtraDopplerInfo },
  { &hf_pcap_codePhase      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_1022 },
  { &hf_pcap_integerCodePhase, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_19 },
  { &hf_pcap_gps_BitNumber  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_3 },
  { &hf_pcap_codePhaseSearchWindow, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CodePhaseSearchWindow },
  { &hf_pcap_azimuthAndElevation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_AzimuthAndElevation },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AcquisitionSatInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AcquisitionSatInfo, AcquisitionSatInfo_sequence);

  return offset;
}


static const per_sequence_t AcquisitionSatInfoList_sequence_of[1] = {
  { &hf_pcap_AcquisitionSatInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_AcquisitionSatInfo },
};

static int
dissect_pcap_AcquisitionSatInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_AcquisitionSatInfoList, AcquisitionSatInfoList_sequence_of,
                                                  1, maxSat, false);

  return offset;
}


static const per_sequence_t GPS_AcquisitionAssistance_sequence[] = {
  { &hf_pcap_gps_TOW_1msec  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_604799999 },
  { &hf_pcap_satelliteInformationList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AcquisitionSatInfoList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_AcquisitionAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_AcquisitionAssistance, GPS_AcquisitionAssistance_sequence);

  return offset;
}


static const value_string pcap_DopplerUncertaintyExtension_vals[] = {
  {   0, "hz300" },
  {   1, "hz400" },
  {   2, "hz500" },
  {   3, "hz600" },
  {   4, "noInformation" },
  { 0, NULL }
};


static int
dissect_pcap_DopplerUncertaintyExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ExtraDopplerInfoExtension_sequence[] = {
  { &hf_pcap_doppler1stOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M42_21 },
  { &hf_pcap_dopplerUncertaintyExtension, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DopplerUncertaintyExtension },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_ExtraDopplerInfoExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_ExtraDopplerInfoExtension, ExtraDopplerInfoExtension_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const per_sequence_t AzimuthAndElevationLSB_sequence[] = {
  { &hf_pcap_azimuthLSB     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
  { &hf_pcap_elevationLSB   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AzimuthAndElevationLSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AzimuthAndElevationLSB, AzimuthAndElevationLSB_sequence);

  return offset;
}



static int
dissect_pcap_Confidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}


static const per_sequence_t AuxInfoGANSS_ID1_element_sequence[] = {
  { &hf_pcap_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_signalsAvailable, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AuxInfoGANSS_ID1_element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AuxInfoGANSS_ID1_element, AuxInfoGANSS_ID1_element_sequence);

  return offset;
}


static const per_sequence_t AuxInfoGANSS_ID1_sequence_of[1] = {
  { &hf_pcap_AuxInfoGANSS_ID1_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_AuxInfoGANSS_ID1_element },
};

static int
dissect_pcap_AuxInfoGANSS_ID1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_AuxInfoGANSS_ID1, AuxInfoGANSS_ID1_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M7_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -7, 13U, NULL, false);

  return offset;
}


static const per_sequence_t AuxInfoGANSS_ID3_element_sequence[] = {
  { &hf_pcap_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_signalsAvailable, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_channelNumber  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M7_13 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AuxInfoGANSS_ID3_element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AuxInfoGANSS_ID3_element, AuxInfoGANSS_ID3_element_sequence);

  return offset;
}


static const per_sequence_t AuxInfoGANSS_ID3_sequence_of[1] = {
  { &hf_pcap_AuxInfoGANSS_ID3_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_AuxInfoGANSS_ID3_element },
};

static int
dissect_pcap_AuxInfoGANSS_ID3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_AuxInfoGANSS_ID3, AuxInfoGANSS_ID3_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_26(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     26, 26, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     13, 13, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CNAVclockModel_sequence[] = {
  { &hf_pcap_cnavToc        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_cnavTop        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_cnavURA0       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_cnavURA1       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { &hf_pcap_cnavURA2       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { &hf_pcap_cnavAf2        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_cnavAf1        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_20 },
  { &hf_pcap_cnavAf0        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_26 },
  { &hf_pcap_cnavTgd        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_cnavISCl1cp    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_cnavISCl1cd    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_cnavISCl1ca    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_cnavISCl2c     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_cnavISCl5i5    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_cnavISCl5q5    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_CNAVclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_CNAVclockModel, CNAVclockModel_sequence);

  return offset;
}


static const per_sequence_t DeltaUT1_sequence[] = {
  { &hf_pcap_b1             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_b2             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DeltaUT1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DeltaUT1, DeltaUT1_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_119(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 119U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_3_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, true);

  return offset;
}


static const per_sequence_t GANSS_SignalID_sequence[] = {
  { &hf_pcap_ganssSignalID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_3_ },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SignalID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SignalID, GANSS_SignalID_sequence);

  return offset;
}


static const value_string pcap_GANSS_StatusHealth_vals[] = {
  {   0, "udre-scale-1dot0" },
  {   1, "udre-scale-0dot75" },
  {   2, "udre-scale-0dot5" },
  {   3, "udre-scale-0dot3" },
  {   4, "udre-scale-Odot2" },
  {   5, "udre-scale-0dot1" },
  {   6, "no-data" },
  {   7, "invalid-data" },
  { 0, NULL }
};


static int
dissect_pcap_GANSS_StatusHealth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_M2047_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2047, 2047U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M127_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, false);

  return offset;
}


static const per_sequence_t DGANSS_SignalInformationItem_sequence[] = {
  { &hf_pcap_satId          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_gANSS_iod      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_udre           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UDRE },
  { &hf_pcap_ganss_prc      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M2047_2047 },
  { &hf_pcap_ganss_rrc      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M127_127 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DGANSS_SignalInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DGANSS_SignalInformationItem, DGANSS_SignalInformationItem_sequence);

  return offset;
}


static const per_sequence_t DGANSS_SignalInformation_sequence_of[1] = {
  { &hf_pcap_DGANSS_SignalInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_DGANSS_SignalInformationItem },
};

static int
dissect_pcap_DGANSS_SignalInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_DGANSS_SignalInformation, DGANSS_SignalInformation_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t DGANSS_InformationItem_sequence[] = {
  { &hf_pcap_gANSS_SignalId , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_SignalID },
  { &hf_pcap_gANSS_StatusHealth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_StatusHealth },
  { &hf_pcap_dGANSS_SignalInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DGANSS_SignalInformation },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DGANSS_InformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DGANSS_InformationItem, DGANSS_InformationItem_sequence);

  return offset;
}


static const per_sequence_t DGANSS_Information_sequence_of[1] = {
  { &hf_pcap_DGANSS_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_DGANSS_InformationItem },
};

static int
dissect_pcap_DGANSS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_DGANSS_Information, DGANSS_Information_sequence_of,
                                                  1, maxSgnType, false);

  return offset;
}


static const per_sequence_t DGANSS_Corrections_sequence[] = {
  { &hf_pcap_dGANSS_ReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_119 },
  { &hf_pcap_dGANSS_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DGANSS_Information },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DGANSS_Corrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DGANSS_Corrections, DGANSS_Corrections_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 22, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NAVclockModel_sequence[] = {
  { &hf_pcap_navToc         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navaf2         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_navaf1         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navaf0         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_22 },
  { &hf_pcap_navTgd         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NAVclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NAVclockModel, NAVclockModel_sequence);

  return offset;
}


static const per_sequence_t GLONASSclockModel_sequence[] = {
  { &hf_pcap_gloTau         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_22 },
  { &hf_pcap_gloGamma       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_gloDeltaTau    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GLONASSclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GLONASSclockModel, GLONASSclockModel_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     12, 12, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t SBASclockModel_sequence[] = {
  { &hf_pcap_sbasTo         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_sbasAgfo       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_12 },
  { &hf_pcap_sbasAgf1       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_SBASclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_SBASclockModel, SBASclockModel_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     17, 17, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t BDSClockModel_sequence[] = {
  { &hf_pcap_toc_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_a0_BDS_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_a1_BDS_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_22 },
  { &hf_pcap_a2_BDS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_tGD1_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_aODC_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_BDSClockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_BDSClockModel, BDSClockModel_sequence);

  return offset;
}


static const value_string pcap_GANSS_AddClockModels_vals[] = {
  {   0, "navClockModel" },
  {   1, "cnavClockModel" },
  {   2, "glonassClockModel" },
  {   3, "sbasClockModel" },
  {   4, "bDSClockModel" },
  { 0, NULL }
};

static const per_choice_t GANSS_AddClockModels_choice[] = {
  {   0, &hf_pcap_navClockModel  , ASN1_EXTENSION_ROOT    , dissect_pcap_NAVclockModel },
  {   1, &hf_pcap_cnavClockModel , ASN1_EXTENSION_ROOT    , dissect_pcap_CNAVclockModel },
  {   2, &hf_pcap_glonassClockModel, ASN1_EXTENSION_ROOT    , dissect_pcap_GLONASSclockModel },
  {   3, &hf_pcap_sbasClockModel , ASN1_EXTENSION_ROOT    , dissect_pcap_SBASclockModel },
  {   4, &hf_pcap_bDSClockModel  , ASN1_NOT_EXTENSION_ROOT, dissect_pcap_BDSClockModel },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_GANSS_AddClockModels(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_GANSS_AddClockModels, GANSS_AddClockModels_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     14, 14, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NavModel_NAVKeplerianSet_sequence[] = {
  { &hf_pcap_navURA         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_navFitFlag     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_navToe         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navOmega       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_navDeltaN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navM0          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_navOmegaADot   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_navE           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_navIDot        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_navAPowerHalf  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_navI0          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_navOmegaA0     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_navCrs         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navCis         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navCus         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navCrc         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navCic         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navCuc         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavModel_NAVKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavModel_NAVKeplerianSet, NavModel_NAVKeplerianSet_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     25, 25, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     23, 23, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_33(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     33, 33, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     15, 15, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NavModel_CNAVKeplerianSet_sequence[] = {
  { &hf_pcap_cnavTop        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_cnavURAindex   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_cnavDeltaA     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_26 },
  { &hf_pcap_cnavAdot       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_25 },
  { &hf_pcap_cnavDeltaNo    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_cnavDeltaNoDot , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_23 },
  { &hf_pcap_cnavMo         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_33 },
  { &hf_pcap_cnavE          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_33 },
  { &hf_pcap_cnavOmega      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_33 },
  { &hf_pcap_cnavOMEGA0     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_33 },
  { &hf_pcap_cnavDeltaOmegaDot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_cnavIo         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_33 },
  { &hf_pcap_cnavIoDot      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_15 },
  { &hf_pcap_cnavCis        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_cnavCic        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_cnavCrs        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_cnavCrc        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_cnavCus        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_21 },
  { &hf_pcap_cnavCuc        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_21 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavModel_CNAVKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavModel_CNAVKeplerianSet, NavModel_CNAVKeplerianSet_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_27(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     27, 27, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NavModel_GLONASSecef_sequence[] = {
  { &hf_pcap_gloEn          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_gloP1          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_gloP2          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_gloM           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_gloX           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_27 },
  { &hf_pcap_gloXdot        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_gloXdotdot     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_gloY           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_27 },
  { &hf_pcap_gloYdot        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_gloYdotdot     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_gloZ           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_27 },
  { &hf_pcap_gloZdot        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_gloZdotdot     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavModel_GLONASSecef(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavModel_GLONASSecef, NavModel_GLONASSecef_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     30, 30, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NavModel_SBASecef_sequence[] = {
  { &hf_pcap_sbasTo         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_sbasAccuracy   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_sbasXg         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_30 },
  { &hf_pcap_sbasYg         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_30 },
  { &hf_pcap_sbasZg         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_25 },
  { &hf_pcap_sbasXgDot      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_sbasYgDot      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_sbasZgDot      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_sbasXgDotDot   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_sbagYgDotDot   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_sbasZgDotDot   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavModel_SBASecef(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavModel_SBASecef, NavModel_SBASecef_sequence);

  return offset;
}


static const per_sequence_t NavModel_BDSKeplerianSet_sequence[] = {
  { &hf_pcap_uRAIndex_BDS   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_tOA_BDS_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_a1_2_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_e_BDS_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_oMG_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_dLTn_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_m0_BDS_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_oMG0_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_oMGdot_BDS     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_i0_BDS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_iDOT_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_cuc_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_cus_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_crc_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_crs_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_cic_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_cis_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_aODE_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavModel_BDSKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavModel_BDSKeplerianSet, NavModel_BDSKeplerianSet_sequence);

  return offset;
}


static const value_string pcap_GANSS_AddOrbitModels_vals[] = {
  {   0, "navKeplerianSet" },
  {   1, "cnavKeplerianSet" },
  {   2, "glonassECEF" },
  {   3, "sbasECEF" },
  {   4, "bDSKeplerianSet" },
  { 0, NULL }
};

static const per_choice_t GANSS_AddOrbitModels_choice[] = {
  {   0, &hf_pcap_navKeplerianSet, ASN1_EXTENSION_ROOT    , dissect_pcap_NavModel_NAVKeplerianSet },
  {   1, &hf_pcap_cnavKeplerianSet, ASN1_EXTENSION_ROOT    , dissect_pcap_NavModel_CNAVKeplerianSet },
  {   2, &hf_pcap_glonassECEF    , ASN1_EXTENSION_ROOT    , dissect_pcap_NavModel_GLONASSecef },
  {   3, &hf_pcap_sbasECEF       , ASN1_EXTENSION_ROOT    , dissect_pcap_NavModel_SBASecef },
  {   4, &hf_pcap_bDSKeplerianSet, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_NavModel_BDSKeplerianSet },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_GANSS_AddOrbitModels(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_GANSS_AddOrbitModels, GANSS_AddOrbitModels_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GPS_Ionospheric_Model_sequence[] = {
  { &hf_pcap_alfa0          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_alfa1          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_alfa2          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_alfa3          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_beta0          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_beta1          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_beta2          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_beta3          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_Ionospheric_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_Ionospheric_Model, GPS_Ionospheric_Model_sequence);

  return offset;
}


static const per_sequence_t GANSS_Additional_Ionospheric_Model_sequence[] = {
  { &hf_pcap_dataID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_alpha_beta_parameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GPS_Ionospheric_Model },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Additional_Ionospheric_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Additional_Ionospheric_Model, GANSS_Additional_Ionospheric_Model_sequence);

  return offset;
}


static const value_string pcap_T_non_broadcastIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_pcap_T_non_broadcastIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Ganss_Sat_Info_AddNavList_item_sequence[] = {
  { &hf_pcap_satId          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_svHealth       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_6 },
  { &hf_pcap_iod            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_ganssAddClockModels, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_AddClockModels },
  { &hf_pcap_ganssAddOrbitModels, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_AddOrbitModels },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Ganss_Sat_Info_AddNavList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Ganss_Sat_Info_AddNavList_item, Ganss_Sat_Info_AddNavList_item_sequence);

  return offset;
}


static const per_sequence_t Ganss_Sat_Info_AddNavList_sequence_of[1] = {
  { &hf_pcap_Ganss_Sat_Info_AddNavList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Ganss_Sat_Info_AddNavList_item },
};

static int
dissect_pcap_Ganss_Sat_Info_AddNavList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_Ganss_Sat_Info_AddNavList, Ganss_Sat_Info_AddNavList_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GANSS_Additional_Navigation_Models_sequence[] = {
  { &hf_pcap_non_broadcastIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_T_non_broadcastIndication },
  { &hf_pcap_ganssSatInfoNavList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Ganss_Sat_Info_AddNavList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Additional_Navigation_Models(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Additional_Navigation_Models, GANSS_Additional_Navigation_Models_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_37799(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 37799U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M2147483648_2147483647(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            INT32_MIN, 2147483647U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M64_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64, 63U, NULL, false);

  return offset;
}


static const value_string pcap_T_gnss_to_id_vals[] = {
  {   0, "gps" },
  {   1, "galileo" },
  {   2, "qzss" },
  {   3, "glonass" },
  {   4, "bds" },
  { 0, NULL }
};


static int
dissect_pcap_T_gnss_to_id(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 4, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, false);

  return offset;
}


static const per_sequence_t GANSS_Time_Model_sequence[] = {
  { &hf_pcap_ganss_time_model_refTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_37799 },
  { &hf_pcap_ganss_t_a0     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M2147483648_2147483647 },
  { &hf_pcap_ganss_t_a1     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_M8388608_8388607 },
  { &hf_pcap_ganss_t_a2     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_M64_63 },
  { &hf_pcap_gnss_to_id     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_gnss_to_id },
  { &hf_pcap_ganss_wk_number, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_8191 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Time_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Time_Model, GANSS_Time_Model_sequence);

  return offset;
}


static const per_sequence_t GANSS_Additional_Time_Models_sequence_of[1] = {
  { &hf_pcap_GANSS_Additional_Time_Models_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_Time_Model },
};

static int
dissect_pcap_GANSS_Additional_Time_Models(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_Additional_Time_Models, GANSS_Additional_Time_Models_sequence_of,
                                                  1, maxGANSS_1, false);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t UTCmodelSet1_sequence[] = {
  { &hf_pcap_utcA0          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_utcA1          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_utcA2          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_7 },
  { &hf_pcap_utcDeltaTls    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcTot         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_utcWNot        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_utcWNlsf       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcDN          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_utcDeltaTlsf   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTCmodelSet1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTCmodelSet1, UTCmodelSet1_sequence);

  return offset;
}


static const per_sequence_t UTCmodelSet2_sequence[] = {
  { &hf_pcap_nA             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_tauC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_deltaUT1_01    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DeltaUT1 },
  { &hf_pcap_kp             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTCmodelSet2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTCmodelSet2, UTCmodelSet2_sequence);

  return offset;
}


static const per_sequence_t UTCmodelSet3_sequence[] = {
  { &hf_pcap_utcA1wnt       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_utcA0wnt       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_utcTot_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcWNt         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcDeltaTls    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcWNlsf       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcDN_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcDeltaTlsf   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcStandardID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTCmodelSet3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTCmodelSet3, UTCmodelSet3_sequence);

  return offset;
}


static const per_sequence_t UTCmodelSet4_sequence[] = {
  { &hf_pcap_utca0_BDS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_utca1_BDS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_utcDeltatLS_BDS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcWNt         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcDeltaTls    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcWNlsf_BDS   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcDN_BDS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_utcDeltaTlsf_BDS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTCmodelSet4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTCmodelSet4, UTCmodelSet4_sequence);

  return offset;
}


static const value_string pcap_GANSS_Additional_UTC_Models_vals[] = {
  {   0, "utcModel1" },
  {   1, "utcModel2" },
  {   2, "utcModel3" },
  {   3, "utcModel4" },
  { 0, NULL }
};

static const per_choice_t GANSS_Additional_UTC_Models_choice[] = {
  {   0, &hf_pcap_utcModel1      , ASN1_EXTENSION_ROOT    , dissect_pcap_UTCmodelSet1 },
  {   1, &hf_pcap_utcModel2      , ASN1_EXTENSION_ROOT    , dissect_pcap_UTCmodelSet2 },
  {   2, &hf_pcap_utcModel3      , ASN1_EXTENSION_ROOT    , dissect_pcap_UTCmodelSet3 },
  {   3, &hf_pcap_utcModel4      , ASN1_NOT_EXTENSION_ROOT, dissect_pcap_UTCmodelSet4 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_GANSS_Additional_UTC_Models(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_GANSS_Additional_UTC_Models, GANSS_Additional_UTC_Models_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     9, 9, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Satellite_Information_BDS_KP_Item_sequence[] = {
  { &hf_pcap_sVID_BDS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_tOA_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_a21_BDS        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_e_BDS          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_omg_lower_BDS  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_m0_BDS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_omg_0_BDS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_omg_upper_BDS  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_delta_i_BDS    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_a0_BDS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_a1_BDS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_hea_BDS        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_9 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Satellite_Information_BDS_KP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Satellite_Information_BDS_KP_Item, Satellite_Information_BDS_KP_Item_sequence);

  return offset;
}


static const per_sequence_t Satellite_Information_BDS_KP_List_sequence_of[1] = {
  { &hf_pcap_Satellite_Information_BDS_KP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Satellite_Information_BDS_KP_Item },
};

static int
dissect_pcap_Satellite_Information_BDS_KP_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_Satellite_Information_BDS_KP_List, Satellite_Information_BDS_KP_List_sequence_of,
                                                  1, maxGANSSSatAlmanac, false);

  return offset;
}


static const per_sequence_t GANSS_ALM_BDSKeplericanset_sequence[] = {
  { &hf_pcap_satellite_Information_BDS_KP_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Satellite_Information_BDS_KP_List },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ALM_BDSKeplericanset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ALM_BDSKeplericanset, GANSS_ALM_BDSKeplericanset_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_SBASecef_sequence[] = {
  { &hf_pcap_sbasAlmDataID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_sbasAlmHealth  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_sbasAlmXg      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_15 },
  { &hf_pcap_sbasAlmYg      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_15 },
  { &hf_pcap_sbasAlmZg      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_9 },
  { &hf_pcap_sbasAlmXgdot   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { &hf_pcap_sbasAlmYgDot   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_3 },
  { &hf_pcap_sbasAlmZgDot   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_sbasAlmTo      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_SBASecef(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SAT_Info_Almanac_SBASecef, GANSS_SAT_Info_Almanac_SBASecef_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_SBASecefList_sequence_of[1] = {
  { &hf_pcap_GANSS_SAT_Info_Almanac_SBASecefList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_SBASecef },
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_SBASecefList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_SAT_Info_Almanac_SBASecefList, GANSS_SAT_Info_Almanac_SBASecefList_sequence_of,
                                                  1, maxGANSSSatAlmanac, false);

  return offset;
}


static const per_sequence_t GANSS_ALM_ECEFsbasAlmanacSet_sequence[] = {
  { &hf_pcap_sat_info_SBASecefList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_SBASecefList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ALM_ECEFsbasAlmanacSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ALM_ECEFsbasAlmanacSet, GANSS_ALM_ECEFsbasAlmanacSet_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_GLOkp_sequence[] = {
  { &hf_pcap_gloAlmNA       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_gloAlmnA       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_gloAlmHA       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_gloAlmLambdaA  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_21 },
  { &hf_pcap_gloAlmTlambdaA , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_21 },
  { &hf_pcap_gloAlmDeltaIA  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_18 },
  { &hf_pcap_gloAkmDeltaTA  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_22 },
  { &hf_pcap_gloAlmDeltaTdotA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_7 },
  { &hf_pcap_gloAlmEpsilonA , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_15 },
  { &hf_pcap_gloAlmOmegaA   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_gloAlmTauA     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_gloAlmCA       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_gloAlmMA       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_GLOkp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SAT_Info_Almanac_GLOkp, GANSS_SAT_Info_Almanac_GLOkp_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_GLOkpList_sequence_of[1] = {
  { &hf_pcap_GANSS_SAT_Info_Almanac_GLOkpList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_GLOkp },
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_GLOkpList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_SAT_Info_Almanac_GLOkpList, GANSS_SAT_Info_Almanac_GLOkpList_sequence_of,
                                                  1, maxGANSSSatAlmanac, false);

  return offset;
}


static const per_sequence_t GANSS_ALM_GlonassAlmanacSet_sequence[] = {
  { &hf_pcap_sat_info_GLOkpList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_GLOkpList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ALM_GlonassAlmanacSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ALM_GlonassAlmanacSet, GANSS_ALM_GlonassAlmanacSet_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_MIDIkp_sequence[] = {
  { &hf_pcap_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_midiAlmE       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_midiAlmDeltaI  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_midiAlmOmegaDot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_midiAlmSqrtA   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_17 },
  { &hf_pcap_midiAlmOmega0  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_midiAlmOmega   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_midiAlmMo      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_midiAlmaf0     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_midiAlmaf1     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_midiAlmL1Health, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_midiAlmL2Health, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_midiAlmL5Health, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_MIDIkp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SAT_Info_Almanac_MIDIkp, GANSS_SAT_Info_Almanac_MIDIkp_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_MIDIkpList_sequence_of[1] = {
  { &hf_pcap_GANSS_SAT_Info_Almanac_MIDIkpList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_MIDIkp },
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_MIDIkpList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_SAT_Info_Almanac_MIDIkpList, GANSS_SAT_Info_Almanac_MIDIkpList_sequence_of,
                                                  1, maxGANSSSatAlmanac, false);

  return offset;
}


static const per_sequence_t GANSS_ALM_MidiAlmanacSet_sequence[] = {
  { &hf_pcap_t_oa           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_sat_info_MIDIkpList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_MIDIkpList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ALM_MidiAlmanacSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ALM_MidiAlmanacSet, GANSS_ALM_MidiAlmanacSet_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_NAVkp_sequence[] = {
  { &hf_pcap_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_navAlmE        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navAlmDeltaI   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navAlmOMEGADOT , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_navAlmSVHealth , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_navAlmSqrtA    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_navAlmOMEGAo   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_navAlmOmega    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_navAlmMo       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_navAlmaf0      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_navAlmaf1      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_NAVkp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SAT_Info_Almanac_NAVkp, GANSS_SAT_Info_Almanac_NAVkp_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_NAVkpList_sequence_of[1] = {
  { &hf_pcap_GANSS_SAT_Info_Almanac_NAVkpList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_NAVkp },
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_NAVkpList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_SAT_Info_Almanac_NAVkpList, GANSS_SAT_Info_Almanac_NAVkpList_sequence_of,
                                                  1, maxGANSSSatAlmanac, false);

  return offset;
}


static const per_sequence_t GANSS_ALM_NAVKeplerianSet_sequence[] = {
  { &hf_pcap_t_oa           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_sat_info_NAVkpList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_NAVkpList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ALM_NAVKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ALM_NAVKeplerianSet, GANSS_ALM_NAVKeplerianSet_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_REDkp_sequence[] = {
  { &hf_pcap_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_redAlmDeltaA   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_redAlmOmega0   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_7 },
  { &hf_pcap_redAlmPhi0     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_7 },
  { &hf_pcap_redAlmL1Health , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_redAlmL2Health , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_redAlmL5Health , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_REDkp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SAT_Info_Almanac_REDkp, GANSS_SAT_Info_Almanac_REDkp_sequence);

  return offset;
}


static const per_sequence_t GANSS_SAT_Info_Almanac_REDkpList_sequence_of[1] = {
  { &hf_pcap_GANSS_SAT_Info_Almanac_REDkpList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_REDkp },
};

static int
dissect_pcap_GANSS_SAT_Info_Almanac_REDkpList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_SAT_Info_Almanac_REDkpList, GANSS_SAT_Info_Almanac_REDkpList_sequence_of,
                                                  1, maxGANSSSatAlmanac, false);

  return offset;
}


static const per_sequence_t GANSS_ALM_ReducedKeplerianSet_sequence[] = {
  { &hf_pcap_t_oa           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_sat_info_REDkpList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SAT_Info_Almanac_REDkpList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ALM_ReducedKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ALM_ReducedKeplerianSet, GANSS_ALM_ReducedKeplerianSet_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}


static const per_sequence_t GANSS_SatelliteInformationKPItem_sequence[] = {
  { &hf_pcap_satId          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_ganss_e_alm    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_ganss_delta_I_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_ganss_omegadot_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_ganss_svStatusINAV_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_ganss_svStatusFNAV_alm, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_ganss_delta_a_sqrt_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_ganss_omegazero_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_ganss_m_zero_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_ganss_omega_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_ganss_af_zero_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_ganss_af_one_alm, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SatelliteInformationKPItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SatelliteInformationKPItem, GANSS_SatelliteInformationKPItem_sequence);

  return offset;
}


static const per_sequence_t GANSS_SatelliteInformationKP_sequence_of[1] = {
  { &hf_pcap_GANSS_SatelliteInformationKP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SatelliteInformationKPItem },
};

static int
dissect_pcap_GANSS_SatelliteInformationKP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_SatelliteInformationKP, GANSS_SatelliteInformationKP_sequence_of,
                                                  1, maxGANSSSatAlmanac, false);

  return offset;
}


static const per_sequence_t GANSS_KeplerianParametersAlm_sequence[] = {
  { &hf_pcap_t_oa_01        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_1023 },
  { &hf_pcap_iod_a          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
  { &hf_pcap_gANSS_SatelliteInformationKP, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SatelliteInformationKP },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_KeplerianParametersAlm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_KeplerianParametersAlm, GANSS_KeplerianParametersAlm_sequence);

  return offset;
}



static int
dissect_pcap_Extension_GANSS_AlmanacModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pcap_ProtocolIE_Single_Container(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pcap_GANSS_AlmanacModel_vals[] = {
  {   0, "gANSS-keplerianParameters" },
  {   1, "extension-GANSS-AlmanacModel" },
  { 0, NULL }
};

static const per_choice_t GANSS_AlmanacModel_choice[] = {
  {   0, &hf_pcap_gANSS_keplerianParameters, ASN1_EXTENSION_ROOT    , dissect_pcap_GANSS_KeplerianParametersAlm },
  {   1, &hf_pcap_extension_GANSS_AlmanacModel, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_Extension_GANSS_AlmanacModel },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_GANSS_AlmanacModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_GANSS_AlmanacModel, GANSS_AlmanacModel_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GANSS_AlmanacAndSatelliteHealth_sequence[] = {
  { &hf_pcap_weekNumber     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_gANSS_AlmanacModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_AlmanacModel },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_AlmanacAndSatelliteHealth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_AlmanacAndSatelliteHealth, GANSS_AlmanacAndSatelliteHealth_sequence);

  return offset;
}


static const value_string pcap_GANSS_Auxiliary_Information_vals[] = {
  {   0, "ganssID1" },
  {   1, "ganssID3" },
  { 0, NULL }
};

static const per_choice_t GANSS_Auxiliary_Information_choice[] = {
  {   0, &hf_pcap_ganssID1       , ASN1_EXTENSION_ROOT    , dissect_pcap_AuxInfoGANSS_ID1 },
  {   1, &hf_pcap_ganssID3       , ASN1_EXTENSION_ROOT    , dissect_pcap_AuxInfoGANSS_ID3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_GANSS_Auxiliary_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_GANSS_Auxiliary_Information, GANSS_Auxiliary_Information_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_75(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 75U, NULL, false);

  return offset;
}


static const per_sequence_t GANSS_AzimuthAndElevation_sequence[] = {
  { &hf_pcap_azimuth        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_31 },
  { &hf_pcap_elevation_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_75 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_AzimuthAndElevation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_AzimuthAndElevation, GANSS_AzimuthAndElevation_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     31, 31, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSS_SatelliteClockModelItem_sequence[] = {
  { &hf_pcap_t_oc           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_a_i2           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_6 },
  { &hf_pcap_a_i1           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_21 },
  { &hf_pcap_a_i0           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_31 },
  { &hf_pcap_t_gd           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_sisa           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_model_id       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_3 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SatelliteClockModelItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SatelliteClockModelItem, GANSS_SatelliteClockModelItem_sequence);

  return offset;
}


static const per_sequence_t GANSS_Clock_Model_sequence_of[1] = {
  { &hf_pcap_GANSS_Clock_Model_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SatelliteClockModelItem },
};

static int
dissect_pcap_GANSS_Clock_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_Clock_Model, GANSS_Clock_Model_sequence_of,
                                                  1, maxGANSSClockMod, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_86399(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86399U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_3999999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3999999U, NULL, false);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTimeDL_sequence[] = {
  { &hf_pcap_utran_GANSSTimingOfCellFrames, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_3999999 },
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UC_ID },
  { &hf_pcap_referenceSfn   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTRAN_GANSSReferenceTimeDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTRAN_GANSSReferenceTimeDL, UTRAN_GANSSReferenceTimeDL_sequence);

  return offset;
}


static const value_string pcap_TUTRAN_GANSS_DriftRate_vals[] = {
  {   0, "uTRAN-GANSSDrift0" },
  {   1, "uTRAN-GANSSDrift1" },
  {   2, "uTRAN-GANSSDrift2" },
  {   3, "uTRAN-GANSSDrift5" },
  {   4, "uTRAN-GANSSDrift10" },
  {   5, "uTRAN-GANSSDrift15" },
  {   6, "uTRAN-GANSSDrift25" },
  {   7, "uTRAN-GANSSDrift50" },
  {   8, "uTRAN-GANSSDrift-1" },
  {   9, "uTRAN-GANSSDrift-2" },
  {  10, "uTRAN-GANSSDrift-5" },
  {  11, "uTRAN-GANSSDrift-10" },
  {  12, "uTRAN-GANSSDrift-15" },
  {  13, "uTRAN-GANSSDrift-25" },
  {  14, "uTRAN-GANSSDrift-50" },
  { 0, NULL }
};

static value_string_ext pcap_TUTRAN_GANSS_DriftRate_vals_ext = VALUE_STRING_EXT_INIT(pcap_TUTRAN_GANSS_DriftRate_vals);


static int
dissect_pcap_TUTRAN_GANSS_DriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t GANSS_Reference_Time_sequence[] = {
  { &hf_pcap_ganssDay       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_8191 },
  { &hf_pcap_ganssTod_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_86399 },
  { &hf_pcap_ganssTodUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_ganssTimeId    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_utran_ganssreferenceTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UTRAN_GANSSReferenceTimeDL },
  { &hf_pcap_tutran_ganss_driftRate, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TUTRAN_GANSS_DriftRate },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Reference_Time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Reference_Time, GANSS_Reference_Time_sequence);

  return offset;
}


static const per_sequence_t GANSS_IonosphereRegionalStormFlags_sequence[] = {
  { &hf_pcap_storm_flag_one , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_storm_flag_two , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_storm_flag_three, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_storm_flag_four, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_storm_flag_five, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_IonosphereRegionalStormFlags(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_IonosphereRegionalStormFlags, GANSS_IonosphereRegionalStormFlags_sequence);

  return offset;
}


static const per_sequence_t GANSS_Ionospheric_Model_sequence[] = {
  { &hf_pcap_alpha_zero_ionos, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_alpha_one_ionos, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_11 },
  { &hf_pcap_alpha_two_ionos, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_gANSS_IonosphereRegionalStormFlags, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_IonosphereRegionalStormFlags },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Ionospheric_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Ionospheric_Model, GANSS_Ionospheric_Model_sequence);

  return offset;
}


static const per_sequence_t GANSS_Reference_Location_sequence[] = {
  { &hf_pcap_ue_PositionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_PositionEstimate },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Reference_Location(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Reference_Location, GANSS_Reference_Location_sequence);

  return offset;
}


static const per_sequence_t GANSS_CommonAssistanceData_sequence[] = {
  { &hf_pcap_ganss_Reference_Time, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_Reference_Time },
  { &hf_pcap_ganss_Ionospheric_Model, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_Ionospheric_Model },
  { &hf_pcap_ganss_Reference_Location, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_Reference_Location },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_CommonAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_CommonAssistanceData, GANSS_CommonAssistanceData_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_59_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, true);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_1_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1024, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSS_DataBitAssistanceSgnItem_sequence[] = {
  { &hf_pcap_ganss_SignalId , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SignalID },
  { &hf_pcap_ganssDataBits  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1_1024 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_DataBitAssistanceSgnItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_DataBitAssistanceSgnItem, GANSS_DataBitAssistanceSgnItem_sequence);

  return offset;
}


static const per_sequence_t GANSS_DataBitAssistanceSgnList_sequence_of[1] = {
  { &hf_pcap_GANSS_DataBitAssistanceSgnList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_DataBitAssistanceSgnItem },
};

static int
dissect_pcap_GANSS_DataBitAssistanceSgnList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_DataBitAssistanceSgnList, GANSS_DataBitAssistanceSgnList_sequence_of,
                                                  1, maxSgnType, false);

  return offset;
}


static const per_sequence_t GANSS_DataBitAssistanceItem_sequence[] = {
  { &hf_pcap_satId          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_dataBitAssistanceSgnList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_DataBitAssistanceSgnList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_DataBitAssistanceItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_DataBitAssistanceItem, GANSS_DataBitAssistanceItem_sequence);

  return offset;
}


static const per_sequence_t GANSS_DataBitAssistanceList_sequence_of[1] = {
  { &hf_pcap_GANSS_DataBitAssistanceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_DataBitAssistanceItem },
};

static int
dissect_pcap_GANSS_DataBitAssistanceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_DataBitAssistanceList, GANSS_DataBitAssistanceList_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GANSS_Data_Bit_Assistance_sequence[] = {
  { &hf_pcap_ganssTod       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_59_ },
  { &hf_pcap_dataBitAssistancelist, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_DataBitAssistanceList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Data_Bit_Assistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Data_Bit_Assistance, GANSS_Data_Bit_Assistance_sequence);

  return offset;
}



static int
dissect_pcap_BIT_STRING_SIZE_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     19, 19, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSS_Earth_Orientation_Parameters_sequence[] = {
  { &hf_pcap_teop           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_pmX            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_21 },
  { &hf_pcap_pmXdot         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_15 },
  { &hf_pcap_pmY            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_21 },
  { &hf_pcap_pmYdot         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_15 },
  { &hf_pcap_deltaUT1       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_31 },
  { &hf_pcap_deltaUT1dot    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_19 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Earth_Orientation_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Earth_Orientation_Parameters, GANSS_Earth_Orientation_Parameters_sequence);

  return offset;
}


static const value_string pcap_T_dopplerUncertainty_vals[] = {
  {   0, "dH40" },
  {   1, "dH20" },
  {   2, "dH10" },
  {   3, "dH5" },
  {   4, "dH2-5" },
  { 0, NULL }
};


static int
dissect_pcap_T_dopplerUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GANSS_ExtraDoppler_sequence[] = {
  { &hf_pcap_dopplerFirstOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M42_21 },
  { &hf_pcap_dopplerUncertainty_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_dopplerUncertainty },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ExtraDoppler(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ExtraDoppler, GANSS_ExtraDoppler_sequence);

  return offset;
}


static const value_string pcap_T_dopplerUncertaintyExtension_vals[] = {
  {   0, "dH60" },
  {   1, "dH80" },
  {   2, "dH100" },
  {   3, "dH120" },
  {   4, "noInformation" },
  { 0, NULL }
};


static int
dissect_pcap_T_dopplerUncertaintyExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GANSS_ExtraDopplerExtension_sequence[] = {
  { &hf_pcap_dopplerFirstOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M42_21 },
  { &hf_pcap_dopplerUncertaintyExtension_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_dopplerUncertaintyExtension },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ExtraDopplerExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ExtraDopplerExtension, GANSS_ExtraDopplerExtension_sequence);

  return offset;
}


static const per_sequence_t GANSS_RealTimeInformationItem_sequence[] = {
  { &hf_pcap_bad_ganss_satId, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_bad_ganss_signalId, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_RealTimeInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_RealTimeInformationItem, GANSS_RealTimeInformationItem_sequence);

  return offset;
}


static const per_sequence_t GANSS_Real_Time_Integrity_sequence_of[1] = {
  { &hf_pcap_GANSS_Real_Time_Integrity_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_RealTimeInformationItem },
};

static int
dissect_pcap_GANSS_Real_Time_Integrity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_Real_Time_Integrity, GANSS_Real_Time_Integrity_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GANSS_SatelliteInformationItem_sequence[] = {
  { &hf_pcap_ganssSatId     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_dopplerZeroOrder, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M2048_2047 },
  { &hf_pcap_extraDoppler   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_ExtraDoppler },
  { &hf_pcap_codePhase_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_1023 },
  { &hf_pcap_integerCodePhase_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_codePhaseSearchWindow_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_31 },
  { &hf_pcap_azimuthAndElevation_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_AzimuthAndElevation },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SatelliteInformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SatelliteInformationItem, GANSS_SatelliteInformationItem_sequence);

  return offset;
}


static const per_sequence_t GANSS_SatelliteInformation_sequence_of[1] = {
  { &hf_pcap_GANSS_SatelliteInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SatelliteInformationItem },
};

static int
dissect_pcap_GANSS_SatelliteInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_SatelliteInformation, GANSS_SatelliteInformation_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GANSS_ReferenceMeasurementInfo_sequence[] = {
  { &hf_pcap_ganssSignalId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_SignalID },
  { &hf_pcap_satelliteInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_SatelliteInformation },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ReferenceMeasurementInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ReferenceMeasurementInfo, GANSS_ReferenceMeasurementInfo_sequence);

  return offset;
}


static const per_sequence_t GANSS_UTC_Model_sequence[] = {
  { &hf_pcap_a_one_utc      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_a_zero_utc     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_t_ot_utc       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_w_n_t_utc      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_delta_t_ls_utc , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_w_n_lsf_utc    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_dn_utc         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_delta_t_lsf_utc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_UTC_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_UTC_Model, GANSS_UTC_Model_sequence);

  return offset;
}


static const value_string pcap_T_non_broadcastIndication_01_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_pcap_T_non_broadcastIndication_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GANSS_KeplerianParametersOrb_sequence[] = {
  { &hf_pcap_toe_nav        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_ganss_omega_nav, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_delta_n_nav    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_m_zero_nav     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_omegadot_nav   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_ganss_e_nav    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_idot_nav       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_a_sqrt_nav     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_i_zero_nav     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_omega_zero_nav , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_c_rs_nav       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_c_is_nav       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_c_us_nav       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_c_rc_nav       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_c_ic_nav       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_c_uc_nav       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_KeplerianParametersOrb(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_KeplerianParametersOrb, GANSS_KeplerianParametersOrb_sequence);

  return offset;
}


static const value_string pcap_GANSS_Orbit_Model_vals[] = {
  {   0, "gANSS-keplerianParameters" },
  { 0, NULL }
};

static const per_choice_t GANSS_Orbit_Model_choice[] = {
  {   0, &hf_pcap_gANSS_keplerianParameters_01, ASN1_EXTENSION_ROOT    , dissect_pcap_GANSS_KeplerianParametersOrb },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_GANSS_Orbit_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_GANSS_Orbit_Model, GANSS_Orbit_Model_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GANSS_Sat_Info_Nav_item_sequence[] = {
  { &hf_pcap_satId          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_svHealth_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_9 },
  { &hf_pcap_iod_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_ganssClockModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_Clock_Model },
  { &hf_pcap_ganssOrbitModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_Orbit_Model },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Sat_Info_Nav_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Sat_Info_Nav_item, GANSS_Sat_Info_Nav_item_sequence);

  return offset;
}


static const per_sequence_t GANSS_Sat_Info_Nav_sequence_of[1] = {
  { &hf_pcap_GANSS_Sat_Info_Nav_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_Sat_Info_Nav_item },
};

static int
dissect_pcap_GANSS_Sat_Info_Nav(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_Sat_Info_Nav, GANSS_Sat_Info_Nav_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GANSS_Navigation_Model_sequence[] = {
  { &hf_pcap_non_broadcastIndication_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_T_non_broadcastIndication_01 },
  { &hf_pcap_ganssSatInfoNav, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_Sat_Info_Nav },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Navigation_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Navigation_Model, GANSS_Navigation_Model_sequence);

  return offset;
}


static const per_sequence_t GANSSGenericAssistanceData_sequence[] = {
  { &hf_pcap_ganssId        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_ganss_Real_Time_Integrity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_Real_Time_Integrity },
  { &hf_pcap_ganss_DataBitAssistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_Data_Bit_Assistance },
  { &hf_pcap_dganss_Corrections, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DGANSS_Corrections },
  { &hf_pcap_ganss_AlmanacAndSatelliteHealth, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_AlmanacAndSatelliteHealth },
  { &hf_pcap_ganss_ReferenceMeasurementInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_ReferenceMeasurementInfo },
  { &hf_pcap_ganss_UTC_Model, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_UTC_Model },
  { &hf_pcap_ganss_Time_Model, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_Time_Model },
  { &hf_pcap_ganss_Navigation_Model, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_Navigation_Model },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSSGenericAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSSGenericAssistanceData, GANSSGenericAssistanceData_sequence);

  return offset;
}


static const per_sequence_t GANSS_GenericAssistanceDataList_sequence_of[1] = {
  { &hf_pcap_GANSS_GenericAssistanceDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSSGenericAssistanceData },
};

static int
dissect_pcap_GANSS_GenericAssistanceDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_GenericAssistanceDataList, GANSS_GenericAssistanceDataList_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}



static int
dissect_pcap_BDS_Reference_Time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3570U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_1_320(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 320U, NULL, false);

  return offset;
}


static const per_sequence_t BDS_Ionospheric_Grid_Information_item_sequence[] = {
  { &hf_pcap_iGP_number_BDS , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_1_320 },
  { &hf_pcap_vertical_Delay_BDS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_9 },
  { &hf_pcap_gIVEI_BDS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_BDS_Ionospheric_Grid_Information_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_BDS_Ionospheric_Grid_Information_item, BDS_Ionospheric_Grid_Information_item_sequence);

  return offset;
}


static const per_sequence_t BDS_Ionospheric_Grid_Information_sequence_of[1] = {
  { &hf_pcap_BDS_Ionospheric_Grid_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BDS_Ionospheric_Grid_Information_item },
};

static int
dissect_pcap_BDS_Ionospheric_Grid_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_BDS_Ionospheric_Grid_Information, BDS_Ionospheric_Grid_Information_sequence_of,
                                                  1, maxIonGridInfo, false);

  return offset;
}


static const per_sequence_t BDS_Ionospheric_Grid_Model_sequence[] = {
  { &hf_pcap_bDS_Reference_Time, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BDS_Reference_Time },
  { &hf_pcap_bDS_Ionospheric_Grid_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BDS_Ionospheric_Grid_Information },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_BDS_Ionospheric_Grid_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_BDS_Ionospheric_Grid_Model, BDS_Ionospheric_Grid_Model_sequence);

  return offset;
}


static const per_sequence_t DGANSS_Signal_Information_item_sequence[] = {
  { &hf_pcap_sat_ID_BDS     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_uDREI_BDS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
  { &hf_pcap_rURAI_BDS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
  { &hf_pcap_delta_t_BDS    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_13 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DGANSS_Signal_Information_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DGANSS_Signal_Information_item, DGANSS_Signal_Information_item_sequence);

  return offset;
}


static const per_sequence_t DGANSS_Signal_Information_sequence_of[1] = {
  { &hf_pcap_DGANSS_Signal_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_DGANSS_Signal_Information_item },
};

static int
dissect_pcap_DGANSS_Signal_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_DGANSS_Signal_Information, DGANSS_Signal_Information_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t DBDS_Information_item_sequence[] = {
  { &hf_pcap_dBDS_Signal_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_dGANSS_Signal_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DGANSS_Signal_Information },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DBDS_Information_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DBDS_Information_item, DBDS_Information_item_sequence);

  return offset;
}


static const per_sequence_t DBDS_Information_sequence_of[1] = {
  { &hf_pcap_DBDS_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_DBDS_Information_item },
};

static int
dissect_pcap_DBDS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_DBDS_Information, DBDS_Information_sequence_of,
                                                  1, maxSgnType, false);

  return offset;
}


static const per_sequence_t DBDS_Correction_Information_sequence[] = {
  { &hf_pcap_bDS_Reference_Time, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BDS_Reference_Time },
  { &hf_pcap_dBDS_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DBDS_Information },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DBDS_Correction_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DBDS_Correction_Information, DBDS_Correction_Information_sequence);

  return offset;
}


static const value_string pcap_T_multipathIndicator_vals[] = {
  {   0, "nM" },
  {   1, "low" },
  {   2, "medium" },
  {   3, "high" },
  { 0, NULL }
};


static int
dissect_pcap_T_multipathIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_M32768_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_33554431(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 33554431U, NULL, false);

  return offset;
}


static const per_sequence_t GANSS_MeasurementParametersItem_sequence[] = {
  { &hf_pcap_satId          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_cToNzero       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_multipathIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_multipathIndicator },
  { &hf_pcap_carrierQualityIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_ganssCodePhase , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_2097151 },
  { &hf_pcap_ganssIntegerCodePhase, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_codePhaseRmsError, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_doppler        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M32768_32767 },
  { &hf_pcap_adr            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_33554431 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_MeasurementParametersItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_MeasurementParametersItem, GANSS_MeasurementParametersItem_sequence);

  return offset;
}


static const per_sequence_t GANSS_MeasurementParameters_sequence_of[1] = {
  { &hf_pcap_GANSS_MeasurementParameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_MeasurementParametersItem },
};

static int
dissect_pcap_GANSS_MeasurementParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_MeasurementParameters, GANSS_MeasurementParameters_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GANSSMeasurementSignalList_item_sequence[] = {
  { &hf_pcap_ganssSignalId  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_SignalID },
  { &hf_pcap_ganssCodePhaseAmbiguity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_31 },
  { &hf_pcap_ganssMeasurementParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_MeasurementParameters },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSSMeasurementSignalList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSSMeasurementSignalList_item, GANSSMeasurementSignalList_item_sequence);

  return offset;
}


static const per_sequence_t GANSSMeasurementSignalList_sequence_of[1] = {
  { &hf_pcap_GANSSMeasurementSignalList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSSMeasurementSignalList_item },
};

static int
dissect_pcap_GANSSMeasurementSignalList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSSMeasurementSignalList, GANSSMeasurementSignalList_sequence_of,
                                                  1, maxSgnType, false);

  return offset;
}


static const per_sequence_t GANSS_GenericMeasurementInfo_item_sequence[] = {
  { &hf_pcap_ganssId        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_ganssMeasurementSignalList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSSMeasurementSignalList },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_GenericMeasurementInfo_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_GenericMeasurementInfo_item, GANSS_GenericMeasurementInfo_item_sequence);

  return offset;
}


static const per_sequence_t GANSS_GenericMeasurementInfo_sequence_of[1] = {
  { &hf_pcap_GANSS_GenericMeasurementInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_GenericMeasurementInfo_item },
};

static int
dissect_pcap_GANSS_GenericMeasurementInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_GenericMeasurementInfo, GANSS_GenericMeasurementInfo_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}



static int
dissect_pcap_INTEGER_32_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            32U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t GanssCodePhaseAmbiguityExt_sequence[] = {
  { &hf_pcap_ganssCodePhaseAmbiguity_ext, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_32_127 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GanssCodePhaseAmbiguityExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GanssCodePhaseAmbiguityExt, GanssCodePhaseAmbiguityExt_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_64_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            64U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t GanssIntegerCodePhaseExt_sequence[] = {
  { &hf_pcap_ganssIntegerCodePhase_ext, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_64_127 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GanssIntegerCodePhaseExt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GanssIntegerCodePhaseExt, GanssIntegerCodePhaseExt_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_345599999999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(345599999999), NULL, false);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTimeUL_sequence[] = {
  { &hf_pcap_ue_GANSSTimingOfCellFrames, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_345599999999 },
  { &hf_pcap_gANSS_TimeId   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_gANSS_TimeUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_referenceSfn   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTRAN_GANSSReferenceTimeUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTRAN_GANSSReferenceTimeUL, UTRAN_GANSSReferenceTimeUL_sequence);

  return offset;
}


static const per_sequence_t GANSS_ReferenceTimeOnly_sequence[] = {
  { &hf_pcap_gANSS_tod      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_3599999 },
  { &hf_pcap_gANSS_timeId   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_gANSS_TimeUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_ReferenceTimeOnly(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_ReferenceTimeOnly, GANSS_ReferenceTimeOnly_sequence);

  return offset;
}


static const value_string pcap_T_referenceTime_vals[] = {
  {   0, "utranReferenceTime" },
  {   1, "ganssReferenceTimeOnly" },
  { 0, NULL }
};

static const per_choice_t T_referenceTime_choice[] = {
  {   0, &hf_pcap_utranReferenceTime, ASN1_EXTENSION_ROOT    , dissect_pcap_UTRAN_GANSSReferenceTimeUL },
  {   1, &hf_pcap_ganssReferenceTimeOnly, ASN1_EXTENSION_ROOT    , dissect_pcap_GANSS_ReferenceTimeOnly },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_referenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_referenceTime, T_referenceTime_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GANSS_MeasuredResults_sequence[] = {
  { &hf_pcap_referenceTime  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_referenceTime },
  { &hf_pcap_ganssGenericMeasurementInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_GenericMeasurementInfo },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_MeasuredResults, GANSS_MeasuredResults_sequence);

  return offset;
}


static const per_sequence_t GANSS_MeasuredResultsList_sequence_of[1] = {
  { &hf_pcap_GANSS_MeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_MeasuredResults },
};

static int
dissect_pcap_GANSS_MeasuredResultsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSS_MeasuredResultsList, GANSS_MeasuredResultsList_sequence_of,
                                                  1, maxNrOfSets, false);

  return offset;
}



static int
dissect_pcap_GANSS_Day_Cycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_pcap_GANSS_Delta_T(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, false);

  return offset;
}


static const value_string pcap_GANSS_UTRAN_TimeRelationshipUncertainty_vals[] = {
  {   0, "gANSS-UTRAN-TRU-50nano" },
  {   1, "gANSS-UTRAN-TRU-500nano" },
  {   2, "gANSS-UTRAN-TRU-1micro" },
  {   3, "gANSS-UTRAN-TRU-10micro" },
  {   4, "gANSS-UTRAN-TRU-1milli" },
  {   5, "gANSS-UTRAN-TRU-10milli" },
  {   6, "gANSS-UTRAN-TRU-100milli" },
  {   7, "gANSS-UTRAN-TRU-unreliable" },
  { 0, NULL }
};


static int
dissect_pcap_GANSS_UTRAN_TimeRelationshipUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t GANSS_UTRAN_TRU_sequence[] = {
  { &hf_pcap_gANSS_UTRAN_TimeRelationshipUncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_UTRAN_TimeRelationshipUncertainty },
  { &hf_pcap_ganssId        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_UTRAN_TRU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_UTRAN_TRU, GANSS_UTRAN_TRU_sequence);

  return offset;
}



static int
dissect_pcap_CompleteAlmanacProvided(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t SubFrame1Reserved_sequence[] = {
  { &hf_pcap_reserved1      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_23 },
  { &hf_pcap_reserved2      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_reserved3      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_reserved4      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_SubFrame1Reserved(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_SubFrame1Reserved, SubFrame1Reserved_sequence);

  return offset;
}


static const per_sequence_t GPS_ClockAndEphemerisParameters_sequence[] = {
  { &hf_pcap_codeOnL2       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_uraIndex       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_4 },
  { &hf_pcap_satHealth_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_6 },
  { &hf_pcap_iodc           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_l2Pflag        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_sf1Revd        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SubFrame1Reserved },
  { &hf_pcap_t_GD           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_t_oc_01        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_af2            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_af1_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_af0_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_22 },
  { &hf_pcap_c_rs           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_delta_n        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_m0_01          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_c_uc           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_e_01           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_c_us           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_a_Sqrt_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_t_oe           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_fitInterval    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_1 },
  { &hf_pcap_aodo           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_5 },
  { &hf_pcap_c_ic           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_omega0_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_c_is           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_i0             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_c_rc           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_16 },
  { &hf_pcap_omega_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_omegaDot_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_iDot           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_ClockAndEphemerisParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_ClockAndEphemerisParameters, GPS_ClockAndEphemerisParameters_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_M32768_32768(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32768U, NULL, false);

  return offset;
}


static const value_string pcap_MultipathIndicator_vals[] = {
  {   0, "nm" },
  {   1, "low" },
  {   2, "medium" },
  {   3, "high" },
  { 0, NULL }
};


static int
dissect_pcap_MultipathIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GPS_MeasurementParam_sequence[] = {
  { &hf_pcap_satelliteID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_c_N0           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_doppler_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M32768_32768 },
  { &hf_pcap_wholeGPS_Chips , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_1022 },
  { &hf_pcap_fractionalGPS_Chips, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_1023 },
  { &hf_pcap_multipathIndicator_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MultipathIndicator },
  { &hf_pcap_pseudorangeRMS_Error, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_MeasurementParam(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_MeasurementParam, GPS_MeasurementParam_sequence);

  return offset;
}


static const per_sequence_t GPS_MeasurementParamList_sequence_of[1] = {
  { &hf_pcap_GPS_MeasurementParamList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GPS_MeasurementParam },
};

static int
dissect_pcap_GPS_MeasurementParamList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GPS_MeasurementParamList, GPS_MeasurementParamList_sequence_of,
                                                  1, maxSat, false);

  return offset;
}


static const per_sequence_t GPS_MeasuredResults_sequence[] = {
  { &hf_pcap_gps_TOW_1msec  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_604799999 },
  { &hf_pcap_gps_MeasurementParamList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GPS_MeasurementParamList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_MeasuredResults, GPS_MeasuredResults_sequence);

  return offset;
}


static const per_sequence_t MeasuredResultsList_sequence_of[1] = {
  { &hf_pcap_MeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GPS_MeasuredResults },
};

static int
dissect_pcap_MeasuredResultsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_MeasuredResultsList, MeasuredResultsList_sequence_of,
                                                  1, maxNrOfSets, false);

  return offset;
}


static const value_string pcap_SatelliteStatus_vals[] = {
  {   0, "ns-NN" },
  {   1, "es-SN" },
  {   2, "es-NN" },
  {   3, "rev2" },
  {   4, "rev" },
  { 0, NULL }
};


static int
dissect_pcap_SatelliteStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t NavigationModelSatInfo_sequence[] = {
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_satelliteStatus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SatelliteStatus },
  { &hf_pcap_gps_clockAndEphemerisParms, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_ClockAndEphemerisParameters },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavigationModelSatInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavigationModelSatInfo, NavigationModelSatInfo_sequence);

  return offset;
}


static const per_sequence_t GPS_NavigationModel_sequence_of[1] = {
  { &hf_pcap_GPS_NavigationModel_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_NavigationModelSatInfo },
};

static int
dissect_pcap_GPS_NavigationModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GPS_NavigationModel, GPS_NavigationModel_sequence_of,
                                                  1, maxSat, false);

  return offset;
}


static const per_sequence_t BadSatList_sequence_of[1] = {
  { &hf_pcap_BadSatList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
};

static int
dissect_pcap_BadSatList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_BadSatList, BadSatList_sequence_of,
                                                  1, maxSat, false);

  return offset;
}



static int
dissect_pcap_NoBadSatellites(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pcap_GPS_RealTimeIntegrity_vals[] = {
  {   0, "badSatellites" },
  {   1, "noBadSatellites" },
  { 0, NULL }
};

static const per_choice_t GPS_RealTimeIntegrity_choice[] = {
  {   0, &hf_pcap_badSatellites  , ASN1_EXTENSION_ROOT    , dissect_pcap_BadSatList },
  {   1, &hf_pcap_noBadSatellites, ASN1_EXTENSION_ROOT    , dissect_pcap_NoBadSatellites },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_GPS_RealTimeIntegrity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_GPS_RealTimeIntegrity, GPS_RealTimeIntegrity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GPS_ReferenceLocation_sequence[] = {
  { &hf_pcap_ue_PositionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_PositionEstimate },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_ReferenceLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_ReferenceLocation, GPS_ReferenceLocation_sequence);

  return offset;
}


static const per_sequence_t GPS_TOW_Assist_sequence[] = {
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_tlm_Message    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_14 },
  { &hf_pcap_antiSpoof      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_alert          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_tlm_Reserved   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_TOW_Assist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_TOW_Assist, GPS_TOW_Assist_sequence);

  return offset;
}


static const per_sequence_t GPS_TOW_AssistList_sequence_of[1] = {
  { &hf_pcap_GPS_TOW_AssistList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GPS_TOW_Assist },
};

static int
dissect_pcap_GPS_TOW_AssistList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GPS_TOW_AssistList, GPS_TOW_AssistList_sequence_of,
                                                  1, maxSat, false);

  return offset;
}


static const per_sequence_t GPS_ReferenceTime_sequence[] = {
  { &hf_pcap_gps_Week       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_1023 },
  { &hf_pcap_gps_TOW_1msec  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_604799999 },
  { &hf_pcap_gps_TOW_AssistList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_TOW_AssistList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_ReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_ReferenceTime, GPS_ReferenceTime_sequence);

  return offset;
}



static int
dissect_pcap_GPS_Week_Cycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}


static const value_string pcap_UTRAN_GPS_DriftRate_vals[] = {
  {   0, "utran-GPSDrift0" },
  {   1, "utran-GPSDrift1" },
  {   2, "utran-GPSDrift2" },
  {   3, "utran-GPSDrift5" },
  {   4, "utran-GPSDrift10" },
  {   5, "utran-GPSDrift15" },
  {   6, "utran-GPSDrift25" },
  {   7, "utran-GPSDrift50" },
  {   8, "utran-GPSDrift-1" },
  {   9, "utran-GPSDrift-2" },
  {  10, "utran-GPSDrift-5" },
  {  11, "utran-GPSDrift-10" },
  {  12, "utran-GPSDrift-15" },
  {  13, "utran-GPSDrift-25" },
  {  14, "utran-GPSDrift-50" },
  { 0, NULL }
};

static value_string_ext pcap_UTRAN_GPS_DriftRate_vals_ext = VALUE_STRING_EXT_INIT(pcap_UTRAN_GPS_DriftRate_vals);


static int
dissect_pcap_UTRAN_GPS_DriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t GPSReferenceTimeUncertainty_sequence[] = {
  { &hf_pcap_gps_RefTimeUNC , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPSReferenceTimeUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPSReferenceTimeUncertainty, GPSReferenceTimeUncertainty_sequence);

  return offset;
}



static int
dissect_pcap_GPS_Transmission_TOW(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 604799U, NULL, false);

  return offset;
}


static const per_sequence_t GPS_UTC_Model_sequence[] = {
  { &hf_pcap_a1             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_24 },
  { &hf_pcap_a0             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_32 },
  { &hf_pcap_t_ot           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_delta_t_LS     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_wn_t           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_wn_lsf         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_dn             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_delta_t_LSF    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPS_UTC_Model(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPS_UTC_Model, GPS_UTC_Model_sequence);

  return offset;
}


static const value_string pcap_GPS_UTRAN_TRU_vals[] = {
  {   0, "nsec-50" },
  {   1, "nsec-500" },
  {   2, "usec-1" },
  {   3, "usec-10" },
  {   4, "msec-1" },
  {   5, "msec-10" },
  {   6, "msec-100" },
  {   7, "unreliable" },
  { 0, NULL }
};


static int
dissect_pcap_GPS_UTRAN_TRU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_167(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 167U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10U, NULL, false);

  return offset;
}


static const per_sequence_t SatelliteRelatedData_sequence[] = {
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_iode           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_SatelliteRelatedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_SatelliteRelatedData, SatelliteRelatedData_sequence);

  return offset;
}


static const per_sequence_t SatelliteRelatedDataList_sequence_of[1] = {
  { &hf_pcap_SatelliteRelatedDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_SatelliteRelatedData },
};

static int
dissect_pcap_SatelliteRelatedDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_SatelliteRelatedDataList, SatelliteRelatedDataList_sequence_of,
                                                  0, maxSat, false);

  return offset;
}


static const per_sequence_t NavModelAdditionalData_sequence[] = {
  { &hf_pcap_gps_Week       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_1023 },
  { &hf_pcap_gps_TOE        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_167 },
  { &hf_pcap_t_TOE_limit    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_10 },
  { &hf_pcap_satRelatedDataList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SatelliteRelatedDataList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavModelAdditionalData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavModelAdditionalData, NavModelAdditionalData_sequence);

  return offset;
}


static const per_sequence_t AdditionalGPSAssistDataRequired_sequence[] = {
  { &hf_pcap_almanacRequest , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_utcModelRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_ionosphericModelRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_navigationModelRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_dgpsCorrectionsRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_referenceLocationRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_referenceTimeRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_aquisitionAssistanceRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_realTimeIntegrityRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_navModelAddDataRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_NavModelAdditionalData },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AdditionalGPSAssistDataRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AdditionalGPSAssistDataRequired, AdditionalGPSAssistDataRequired_sequence);

  return offset;
}



static int
dissect_pcap_DGANSS_Sig_Id_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t T_ganssSatelliteInfo_sequence_of[1] = {
  { &hf_pcap_ganssSatelliteInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
};

static int
dissect_pcap_T_ganssSatelliteInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ganssSatelliteInfo, T_ganssSatelliteInfo_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t ReqDataBitAssistanceList_sequence[] = {
  { &hf_pcap_reqDataBitAssistanceList_ganssSignalID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_ganssDataBitInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
  { &hf_pcap_ganssSatelliteInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_T_ganssSatelliteInfo },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_ReqDataBitAssistanceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_ReqDataBitAssistanceList, ReqDataBitAssistanceList_sequence);

  return offset;
}


static const per_sequence_t GanssDataBits_sequence[] = {
  { &hf_pcap_ganssTod_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_86399 },
  { &hf_pcap_dataBitAssistancelist_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ReqDataBitAssistanceList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GanssDataBits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GanssDataBits, GanssDataBits_sequence);

  return offset;
}


static const per_sequence_t SatelliteRelatedDataGANSS_sequence[] = {
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_iod_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_SatelliteRelatedDataGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_SatelliteRelatedDataGANSS, SatelliteRelatedDataGANSS_sequence);

  return offset;
}


static const per_sequence_t SatelliteRelatedDataListGANSS_sequence_of[1] = {
  { &hf_pcap_SatelliteRelatedDataListGANSS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_SatelliteRelatedDataGANSS },
};

static int
dissect_pcap_SatelliteRelatedDataListGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_SatelliteRelatedDataListGANSS, SatelliteRelatedDataListGANSS_sequence_of,
                                                  0, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t NavigationModelGANSS_sequence[] = {
  { &hf_pcap_ganssWeek      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_ganssTOE       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_167 },
  { &hf_pcap_t_toe_limit    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_10 },
  { &hf_pcap_satRelatedDataListGANSS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SatelliteRelatedDataListGANSS },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavigationModelGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavigationModelGANSS, NavigationModelGANSS_sequence);

  return offset;
}


static const per_sequence_t GanssReqGenericData_sequence[] = {
  { &hf_pcap_ganssId        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_ganssRealTimeIntegrity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssDifferentialCorrection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DGANSS_Sig_Id_Req },
  { &hf_pcap_ganssAlmanac   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssNavigationModel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssTimeModelGnssGnss, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BIT_STRING_SIZE_9 },
  { &hf_pcap_ganssReferenceMeasurementInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssDataBits_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GanssDataBits },
  { &hf_pcap_ganssUTCModel  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssNavigationModelAdditionalData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_NavigationModelGANSS },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GanssReqGenericData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GanssReqGenericData, GanssReqGenericData_sequence);

  return offset;
}


static const per_sequence_t GanssRequestedGenericAssistanceDataList_sequence_of[1] = {
  { &hf_pcap_GanssRequestedGenericAssistanceDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GanssReqGenericData },
};

static int
dissect_pcap_GanssRequestedGenericAssistanceDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GanssRequestedGenericAssistanceDataList, GanssRequestedGenericAssistanceDataList_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}


static const per_sequence_t AdditionalGanssAssistDataRequired_sequence[] = {
  { &hf_pcap_ganssReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssreferenceLocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssIonosphericModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_ganssRequestedGenericAssistanceDataList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GanssRequestedGenericAssistanceDataList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AdditionalGanssAssistDataRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AdditionalGanssAssistDataRequired, AdditionalGanssAssistDataRequired_sequence);

  return offset;
}


static const per_sequence_t GANSSReq_AddIonosphericModel_sequence[] = {
  { &hf_pcap_ganss_add_iono_mode_req, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSSReq_AddIonosphericModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSSReq_AddIonosphericModel, GANSSReq_AddIonosphericModel_sequence);

  return offset;
}



static int
dissect_pcap_GANSSReq_EarthOrientPara(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_pcap_BDSIonosphericGridModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t DBDSCorrection_sequence[] = {
  { &hf_pcap_dGANSSSignalBDS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DBDSCorrection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DBDSCorrection, DBDSCorrection_sequence);

  return offset;
}



static int
dissect_pcap_GANSS_AddNavigationModel_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_pcap_GANSS_AddUTCModel_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_pcap_GANSS_AuxInfo_req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t GANSS_AddADchoices_sequence[] = {
  { &hf_pcap_orbitModelID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_7 },
  { &hf_pcap_clockModelID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_7 },
  { &hf_pcap_utcModelID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_7 },
  { &hf_pcap_almanacModelID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_7 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_AddADchoices(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_AddADchoices, GANSS_AddADchoices_sequence);

  return offset;
}



static int
dissect_pcap_InformationExchangeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1048575U, NULL, false);

  return offset;
}


static const value_string pcap_InformationReportCharacteristicsType_vals[] = {
  {   0, "onDemand" },
  {   1, "periodic" },
  {   2, "onModification" },
  { 0, NULL }
};


static int
dissect_pcap_InformationReportCharacteristicsType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_1_60_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 60U, NULL, true);

  return offset;
}



static int
dissect_pcap_INTEGER_1_24_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 24U, NULL, true);

  return offset;
}


static const value_string pcap_InformationReportPeriodicity_vals[] = {
  {   0, "min" },
  {   1, "hour" },
  { 0, NULL }
};

static const per_choice_t InformationReportPeriodicity_choice[] = {
  {   0, &hf_pcap_min            , ASN1_EXTENSION_ROOT    , dissect_pcap_INTEGER_1_60_ },
  {   1, &hf_pcap_hour           , ASN1_EXTENSION_ROOT    , dissect_pcap_INTEGER_1_24_ },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_InformationReportPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_InformationReportPeriodicity, InformationReportPeriodicity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InformationReportCharacteristics_sequence[] = {
  { &hf_pcap_type_01        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_InformationReportCharacteristicsType },
  { &hf_pcap_periodicity    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_InformationReportPeriodicity },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationReportCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationReportCharacteristics, InformationReportCharacteristics_sequence);

  return offset;
}


static const value_string pcap_MethodType_vals[] = {
  {   0, "ue-assisted" },
  {   1, "ue-based" },
  { 0, NULL }
};


static int
dissect_pcap_MethodType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_AlmanacAndSatelliteHealth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pcap_TransmissionTOWIndicator_vals[] = {
  {   0, "requested" },
  {   1, "not-Requested" },
  { 0, NULL }
};


static int
dissect_pcap_TransmissionTOWIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t UtcModel_sequence[] = {
  { &hf_pcap_transmissionTOWIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransmissionTOWIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UtcModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UtcModel, UtcModel_sequence);

  return offset;
}


static const per_sequence_t IonosphericModel_sequence[] = {
  { &hf_pcap_transmissionTOWIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransmissionTOWIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_IonosphericModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_IonosphericModel, IonosphericModel_sequence);

  return offset;
}


static const per_sequence_t NavigationModel_sequence[] = {
  { &hf_pcap_transmissionTOWIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransmissionTOWIndicator },
  { &hf_pcap_navModelAdditionalData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_NavModelAdditionalData },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NavigationModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NavigationModel, NavigationModel_sequence);

  return offset;
}



static int
dissect_pcap_DgpsCorrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pcap_ReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pcap_AcquisitionAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pcap_RealTimeIntegrity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t AlmanacAndSatelliteHealthSIB_InfoType_sequence[] = {
  { &hf_pcap_transmissionTOWIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransmissionTOWIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AlmanacAndSatelliteHealthSIB_InfoType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AlmanacAndSatelliteHealthSIB_InfoType, AlmanacAndSatelliteHealthSIB_InfoType_sequence);

  return offset;
}



static int
dissect_pcap_ReferenceLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pcap_T_ganss_ReferenceTime_vals[] = {
  {   0, "requested" },
  {   1, "not-requested" },
  { 0, NULL }
};


static int
dissect_pcap_T_ganss_ReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const value_string pcap_T_ganss_IonosphericModel_vals[] = {
  {   0, "requested" },
  {   1, "not-requested" },
  { 0, NULL }
};


static int
dissect_pcap_T_ganss_IonosphericModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const value_string pcap_T_ganss_ReferenceLocation_vals[] = {
  {   0, "requested" },
  {   1, "not-requested" },
  { 0, NULL }
};


static int
dissect_pcap_T_ganss_ReferenceLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GANSSCommonDataReq_sequence[] = {
  { &hf_pcap_ganss_ReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_T_ganss_ReferenceTime },
  { &hf_pcap_ganss_IonosphericModel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_T_ganss_IonosphericModel },
  { &hf_pcap_ganss_ReferenceLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_T_ganss_ReferenceLocation },
  { &hf_pcap_ie_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSSCommonDataReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSSCommonDataReq, GANSSCommonDataReq_sequence);

  return offset;
}


static const value_string pcap_TransmissionGanssTimeIndicator_vals[] = {
  {   0, "requested" },
  {   1, "not-Requested" },
  { 0, NULL }
};


static int
dissect_pcap_TransmissionGanssTimeIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Ganss_realTimeIntegrityReq_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Ganss_realTimeIntegrityReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Ganss_realTimeIntegrityReq, Ganss_realTimeIntegrityReq_sequence);

  return offset;
}


static const per_sequence_t DganssCorrectionsReq_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_dganss_sig_id_req, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DGANSS_Sig_Id_Req },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DganssCorrectionsReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DganssCorrectionsReq, DganssCorrectionsReq_sequence);

  return offset;
}


static const per_sequence_t Ganss_almanacAndSatelliteHealthReq_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Ganss_almanacAndSatelliteHealthReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Ganss_almanacAndSatelliteHealthReq, Ganss_almanacAndSatelliteHealthReq_sequence);

  return offset;
}


static const per_sequence_t Ganss_referenceMeasurementInfoReq_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Ganss_referenceMeasurementInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Ganss_referenceMeasurementInfoReq, Ganss_referenceMeasurementInfoReq_sequence);

  return offset;
}


static const per_sequence_t Ganss_utcModelReq_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Ganss_utcModelReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Ganss_utcModelReq, Ganss_utcModelReq_sequence);

  return offset;
}


static const per_sequence_t Ganss_TimeModel_Gnss_Gnss_sequence[] = {
  { &hf_pcap_ganssTimeModelGnssGnssExt, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_9 },
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Ganss_TimeModel_Gnss_Gnss(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Ganss_TimeModel_Gnss_Gnss, Ganss_TimeModel_Gnss_Gnss_sequence);

  return offset;
}


static const per_sequence_t AddSatelliteRelatedDataGANSS_sequence[] = {
  { &hf_pcap_satID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { &hf_pcap_iod_01         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_10 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AddSatelliteRelatedDataGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AddSatelliteRelatedDataGANSS, AddSatelliteRelatedDataGANSS_sequence);

  return offset;
}


static const per_sequence_t AddSatelliteRelatedDataListGANSS_sequence_of[1] = {
  { &hf_pcap_AddSatelliteRelatedDataListGANSS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_AddSatelliteRelatedDataGANSS },
};

static int
dissect_pcap_AddSatelliteRelatedDataListGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_AddSatelliteRelatedDataListGANSS, AddSatelliteRelatedDataListGANSS_sequence_of,
                                                  0, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t AddNavigationModelsGANSS_sequence[] = {
  { &hf_pcap_ganssWeek      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_ganssTOE       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_167 },
  { &hf_pcap_t_toe_limit    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_10 },
  { &hf_pcap_addSatRelatedDataListGANSS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AddSatelliteRelatedDataListGANSS },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AddNavigationModelsGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AddNavigationModelsGANSS, AddNavigationModelsGANSS_sequence);

  return offset;
}


static const per_sequence_t GANSS_AddUtcModelsReq_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_AddUtcModelsReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_AddUtcModelsReq, GANSS_AddUtcModelsReq_sequence);

  return offset;
}


static const per_sequence_t GANSS_AuxInfoReq_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_AuxInfoReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_AuxInfoReq, GANSS_AuxInfoReq_sequence);

  return offset;
}


static const value_string pcap_GANSS_SBAS_ID_vals[] = {
  {   0, "waas" },
  {   1, "egnos" },
  {   2, "msas" },
  {   3, "gagan" },
  { 0, NULL }
};


static int
dissect_pcap_GANSS_SBAS_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t DBDS_Corrections_sequence[] = {
  { &hf_pcap_transmissionGanssTimeIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransmissionGanssTimeIndicator },
  { &hf_pcap_dGANSS_Signal  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DBDS_Corrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DBDS_Corrections, DBDS_Corrections_sequence);

  return offset;
}


static const value_string pcap_BDS_Ionospheric_Grid_Model_Request_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_pcap_BDS_Ionospheric_Grid_Model_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t GANSSGenericDataReq_sequence[] = {
  { &hf_pcap_ganssID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_ganss_realTimeIntegrity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Ganss_realTimeIntegrityReq },
  { &hf_pcap_ganss_dataBitAssistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GanssDataBits },
  { &hf_pcap_dganssCorrections, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DganssCorrectionsReq },
  { &hf_pcap_ganss_almanacAndSatelliteHealth, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Ganss_almanacAndSatelliteHealthReq },
  { &hf_pcap_ganss_referenceMeasurementInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Ganss_referenceMeasurementInfoReq },
  { &hf_pcap_ganss_utcModel , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Ganss_utcModelReq },
  { &hf_pcap_ganss_TimeModel_Gnss_Gnss, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Ganss_TimeModel_Gnss_Gnss },
  { &hf_pcap_navigationModel_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_NavigationModelGANSS },
  { &hf_pcap_ganss_AddNavModelsReq, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_pcap_AddNavigationModelsGANSS },
  { &hf_pcap_ganss_AddUtcModelsReq, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_pcap_GANSS_AddUtcModelsReq },
  { &hf_pcap_ganss_AuxInfoReq, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_pcap_GANSS_AuxInfoReq },
  { &hf_pcap_ganss_SBAS_ID  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_pcap_GANSS_SBAS_ID },
  { &hf_pcap_dBDS_Corrections, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_pcap_DBDS_Corrections },
  { &hf_pcap_bDS_Ionospheric_Grid_Model_Request, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_pcap_BDS_Ionospheric_Grid_Model_Request },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSSGenericDataReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSSGenericDataReq, GANSSGenericDataReq_sequence);

  return offset;
}


static const per_sequence_t GANSSGenericDataList_sequence_of[1] = {
  { &hf_pcap_GANSSGenericDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_GANSSGenericDataReq },
};

static int
dissect_pcap_GANSSGenericDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_GANSSGenericDataList, GANSSGenericDataList_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}


static const value_string pcap_ExplicitInformation_vals[] = {
  {   0, "almanacAndSatelliteHealth" },
  {   1, "utcModel" },
  {   2, "ionosphericModel" },
  {   3, "navigationModel" },
  {   4, "dgpsCorrections" },
  {   5, "referenceTime" },
  {   6, "acquisitionAssistance" },
  {   7, "realTimeIntegrity" },
  {   8, "almanacAndSatelliteHealthSIB" },
  {   9, "referenceLocation" },
  {  10, "ganss-Common-DataReq" },
  {  11, "ganss-Generic-DataList" },
  { 0, NULL }
};

static value_string_ext pcap_ExplicitInformation_vals_ext = VALUE_STRING_EXT_INIT(pcap_ExplicitInformation_vals);

static const per_choice_t ExplicitInformation_choice[] = {
  {   0, &hf_pcap_almanacAndSatelliteHealth, ASN1_EXTENSION_ROOT    , dissect_pcap_AlmanacAndSatelliteHealth },
  {   1, &hf_pcap_utcModel       , ASN1_EXTENSION_ROOT    , dissect_pcap_UtcModel },
  {   2, &hf_pcap_ionosphericModel, ASN1_EXTENSION_ROOT    , dissect_pcap_IonosphericModel },
  {   3, &hf_pcap_navigationModel, ASN1_EXTENSION_ROOT    , dissect_pcap_NavigationModel },
  {   4, &hf_pcap_dgpsCorrections, ASN1_EXTENSION_ROOT    , dissect_pcap_DgpsCorrections },
  {   5, &hf_pcap_referenceTime_01, ASN1_EXTENSION_ROOT    , dissect_pcap_ReferenceTime },
  {   6, &hf_pcap_acquisitionAssistance, ASN1_EXTENSION_ROOT    , dissect_pcap_AcquisitionAssistance },
  {   7, &hf_pcap_realTimeIntegrity, ASN1_EXTENSION_ROOT    , dissect_pcap_RealTimeIntegrity },
  {   8, &hf_pcap_almanacAndSatelliteHealthSIB, ASN1_EXTENSION_ROOT    , dissect_pcap_AlmanacAndSatelliteHealthSIB_InfoType },
  {   9, &hf_pcap_referenceLocation, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_ReferenceLocation },
  {  10, &hf_pcap_ganss_Common_DataReq, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_GANSSCommonDataReq },
  {  11, &hf_pcap_ganss_Generic_DataList, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_GANSSGenericDataList },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_ExplicitInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_ExplicitInformation, ExplicitInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ExplicitInformationList_sequence_of[1] = {
  { &hf_pcap_ExplicitInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ExplicitInformation },
};

static int
dissect_pcap_ExplicitInformationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_ExplicitInformationList, ExplicitInformationList_sequence_of,
                                                  1, maxNrOfExpInfo, false);

  return offset;
}


static const value_string pcap_InformationType_vals[] = {
  {   0, "implicitInformation" },
  {   1, "explicitInformation" },
  { 0, NULL }
};

static const per_choice_t InformationType_choice[] = {
  {   0, &hf_pcap_implicitInformation, ASN1_EXTENSION_ROOT    , dissect_pcap_MethodType },
  {   1, &hf_pcap_explicitInformation, ASN1_EXTENSION_ROOT    , dissect_pcap_ExplicitInformationList },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_InformationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_InformationType, InformationType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GANSS_AddIonoModelReq_sequence[] = {
  { &hf_pcap_dataID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_2 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_AddIonoModelReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_AddIonoModelReq, GANSS_AddIonoModelReq_sequence);

  return offset;
}


static const value_string pcap_T_eopReq_vals[] = {
  {   0, "requested" },
  {   1, "not-requested" },
  { 0, NULL }
};


static int
dissect_pcap_T_eopReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GANSS_EarthOrientParaReq_sequence[] = {
  { &hf_pcap_eopReq         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_eopReq },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_EarthOrientParaReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_EarthOrientParaReq, GANSS_EarthOrientParaReq_sequence);

  return offset;
}


static const value_string pcap_T_ue_State_vals[] = {
  {   0, "cell-DCH" },
  {   1, "all-States-Except-Cell-DCH" },
  {   2, "all-States" },
  { 0, NULL }
};


static int
dissect_pcap_T_ue_State(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementValidity_sequence[] = {
  { &hf_pcap_ue_State       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_ue_State },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_MeasurementValidity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_MeasurementValidity, MeasurementValidity_sequence);

  return offset;
}


static const per_sequence_t MeasInstructionsUsed_sequence[] = {
  { &hf_pcap_measurementValidity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MeasurementValidity },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_MeasInstructionsUsed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_MeasInstructionsUsed, MeasInstructionsUsed_sequence);

  return offset;
}



static int
dissect_pcap_SFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t TUTRANGPS_sequence[] = {
  { &hf_pcap_ms_part        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_16383 },
  { &hf_pcap_ls_part        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TUTRANGPS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TUTRANGPS, TUTRANGPS_sequence);

  return offset;
}



static int
dissect_pcap_TUTRANGPSQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_pcap_TUTRANGPSDriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -50, 50U, NULL, false);

  return offset;
}



static int
dissect_pcap_TUTRANGPSDriftRateQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 50U, NULL, false);

  return offset;
}


static const per_sequence_t TUTRANGPSMeasurementValueInfo_sequence[] = {
  { &hf_pcap_sFN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SFN },
  { &hf_pcap_tUTRANGPS      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TUTRANGPS },
  { &hf_pcap_tUTRANGPSQuality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TUTRANGPSQuality },
  { &hf_pcap_tUTRANGPSDriftRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TUTRANGPSDriftRate },
  { &hf_pcap_tUTRANGPSDriftRateQuality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TUTRANGPSDriftRateQuality },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TUTRANGPSMeasurementValueInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TUTRANGPSMeasurementValueInfo, TUTRANGPSMeasurementValueInfo_sequence);

  return offset;
}


static const per_sequence_t OTDOA_ReferenceCellInfo_sequence[] = {
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_uTRANAccessPointPositionAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UTRANAccessPointPositionAltitude },
  { &hf_pcap_tUTRANGPSMeasurementValueInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TUTRANGPSMeasurementValueInfo },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_OTDOA_ReferenceCellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_OTDOA_ReferenceCellInfo, OTDOA_ReferenceCellInfo_sequence);

  return offset;
}



static int
dissect_pcap_SFNSFNValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 614399U, NULL, false);

  return offset;
}



static int
dissect_pcap_SFNSFNQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_pcap_SFNSFNDriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -100, 100U, NULL, false);

  return offset;
}



static int
dissect_pcap_SFNSFNDriftRateQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}


static const per_sequence_t SFNSFNMeasurementValueInfo_sequence[] = {
  { &hf_pcap_sFNSFNValue    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SFNSFNValue },
  { &hf_pcap_sFNSFNQuality  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_SFNSFNQuality },
  { &hf_pcap_sFNSFNDriftRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SFNSFNDriftRate },
  { &hf_pcap_sFNSFNDriftRateQuality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_SFNSFNDriftRateQuality },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_SFNSFNMeasurementValueInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_SFNSFNMeasurementValueInfo, SFNSFNMeasurementValueInfo_sequence);

  return offset;
}


static const per_sequence_t TUTRANGANSS_sequence[] = {
  { &hf_pcap_ms_part        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_16383 },
  { &hf_pcap_ls_part        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TUTRANGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TUTRANGANSS, TUTRANGANSS_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_M50_50(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -50, 50U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_50(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 50U, NULL, false);

  return offset;
}


static const per_sequence_t TUTRANGANSSMeasurementValueInfo_sequence[] = {
  { &hf_pcap_ganssID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_sFN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SFN },
  { &hf_pcap_tUTRANGANSS    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TUTRANGANSS },
  { &hf_pcap_tUTRANGANSSQuality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_tUTRANGANSSDriftRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_M50_50 },
  { &hf_pcap_tUTRANGANSSDriftRateQuality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_50 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TUTRANGANSSMeasurementValueInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TUTRANGANSSMeasurementValueInfo, TUTRANGANSSMeasurementValueInfo_sequence);

  return offset;
}


static const value_string pcap_RelativeTimingDifferenceInfo_vals[] = {
  {   0, "sFNSFNMeasurementValueInfo" },
  {   1, "tUTRANGPSMeasurementValueInfo" },
  {   2, "tUTRANGANSSMeasurementValueInfo" },
  { 0, NULL }
};

static const per_choice_t RelativeTimingDifferenceInfo_choice[] = {
  {   0, &hf_pcap_sFNSFNMeasurementValueInfo, ASN1_EXTENSION_ROOT    , dissect_pcap_SFNSFNMeasurementValueInfo },
  {   1, &hf_pcap_tUTRANGPSMeasurementValueInfo, ASN1_EXTENSION_ROOT    , dissect_pcap_TUTRANGPSMeasurementValueInfo },
  {   2, &hf_pcap_tUTRANGANSSMeasurementValueInfo, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_TUTRANGANSSMeasurementValueInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_RelativeTimingDifferenceInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_RelativeTimingDifferenceInfo, RelativeTimingDifferenceInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OTDOA_NeighbourCellInfo_sequence[] = {
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_uTRANAccessPointPositionAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UTRANAccessPointPositionAltitude },
  { &hf_pcap_relativeTimingDifferenceInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RelativeTimingDifferenceInfo },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_OTDOA_NeighbourCellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_OTDOA_NeighbourCellInfo, OTDOA_NeighbourCellInfo_sequence);

  return offset;
}


static const per_sequence_t OTDOA_NeighbourCellInfoList_sequence_of[1] = {
  { &hf_pcap_OTDOA_NeighbourCellInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_OTDOA_NeighbourCellInfo },
};

static int
dissect_pcap_OTDOA_NeighbourCellInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_OTDOA_NeighbourCellInfoList, OTDOA_NeighbourCellInfoList_sequence_of,
                                                  1, maxNrOfMeasNCell, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_40961(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 40961U, NULL, false);

  return offset;
}


static const per_sequence_t UE_SFNSFNTimeDifferenceType2Info_sequence[] = {
  { &hf_pcap_ue_SFNSFNTimeDifferenceType2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_40961 },
  { &hf_pcap_ue_PositioningMeasQuality, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_PositioningMeasQuality },
  { &hf_pcap_measurementDelay, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_65535 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_SFNSFNTimeDifferenceType2Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_SFNSFNTimeDifferenceType2Info, UE_SFNSFNTimeDifferenceType2Info_sequence);

  return offset;
}


static const per_sequence_t OTDOA_MeasuredResultsInfo_sequence[] = {
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_ue_SFNSFNTimeDifferenceType2Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_SFNSFNTimeDifferenceType2Info },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_OTDOA_MeasuredResultsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_OTDOA_MeasuredResultsInfo, OTDOA_MeasuredResultsInfo_sequence);

  return offset;
}


static const per_sequence_t OTDOA_MeasuredResultsInfoList_sequence_of[1] = {
  { &hf_pcap_OTDOA_MeasuredResultsInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_OTDOA_MeasuredResultsInfo },
};

static int
dissect_pcap_OTDOA_MeasuredResultsInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_OTDOA_MeasuredResultsInfoList, OTDOA_MeasuredResultsInfoList_sequence_of,
                                                  1, maxNrOfMeasNCell, false);

  return offset;
}


static const per_sequence_t OTDOA_MeasuredResultsSets_sequence_of[1] = {
  { &hf_pcap_OTDOA_MeasuredResultsSets_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_OTDOA_MeasuredResultsInfoList },
};

static int
dissect_pcap_OTDOA_MeasuredResultsSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_OTDOA_MeasuredResultsSets, OTDOA_MeasuredResultsSets_sequence_of,
                                                  1, maxNrOfMeasurements, false);

  return offset;
}


static const per_sequence_t OTDOA_MeasurementGroup_sequence[] = {
  { &hf_pcap_otdoa_ReferenceCellInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_OTDOA_ReferenceCellInfo },
  { &hf_pcap_otdoa_NeighbourCellInfoList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_OTDOA_NeighbourCellInfoList },
  { &hf_pcap_otdoa_MeasuredResultsSets, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_OTDOA_MeasuredResultsSets },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_OTDOA_MeasurementGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_OTDOA_MeasurementGroup, OTDOA_MeasurementGroup_sequence);

  return offset;
}


static const per_sequence_t OTDOA_ReferenceCellInfoSAS_centric_sequence[] = {
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_OTDOA_ReferenceCellInfoSAS_centric(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_OTDOA_ReferenceCellInfoSAS_centric, OTDOA_ReferenceCellInfoSAS_centric_sequence);

  return offset;
}



static int
dissect_pcap_PrimaryScramblingCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, false);

  return offset;
}


static const per_sequence_t OTDOA_AddMeasuredResultsInfo_sequence[] = {
  { &hf_pcap_primaryCPICH_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PrimaryScramblingCode },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_OTDOA_AddMeasuredResultsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_OTDOA_AddMeasuredResultsInfo, OTDOA_AddMeasuredResultsInfo_sequence);

  return offset;
}



static int
dissect_pcap_Extended_RNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            4096U, 65535U, NULL, false);

  return offset;
}



static int
dissect_pcap_TimingAdvanceLCR_R7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, false);

  return offset;
}


static const per_sequence_t AdditionalMeasurementInforLCR_sequence[] = {
  { &hf_pcap_timingAdvanceLCR_R7, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TimingAdvanceLCR_R7 },
  { &hf_pcap_rxTimingDeviationLCR, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RxTimingDeviationLCR },
  { &hf_pcap_angleOfArrivalLCR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_AngleOfArrivalLCR },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AdditionalMeasurementInforLCR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AdditionalMeasurementInforLCR, AdditionalMeasurementInforLCR_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_32767_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, true);

  return offset;
}



static int
dissect_pcap_INTEGER_1_8639999_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8639999U, NULL, true);

  return offset;
}


static const per_sequence_t PeriodicPosCalcInfo_sequence[] = {
  { &hf_pcap_referenceNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_32767_ },
  { &hf_pcap_amountOutstandingRequests, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_1_8639999_ },
  { &hf_pcap_reportingInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_1_8639999_ },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PeriodicPosCalcInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PeriodicPosCalcInfo, PeriodicPosCalcInfo_sequence);

  return offset;
}


static const per_sequence_t PeriodicLocationInfo_sequence[] = {
  { &hf_pcap_reportingAmount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_1_8639999_ },
  { &hf_pcap_reportingInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_1_8639999_ },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PeriodicLocationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PeriodicLocationInfo, PeriodicLocationInfo_sequence);

  return offset;
}


static const value_string pcap_PeriodicTerminationCause_vals[] = {
  {   0, "rrc-state-transition" },
  {   1, "cancelled-by-srnc" },
  {   2, "cancelled-by-sas" },
  {   3, "undefined" },
  { 0, NULL }
};


static int
dissect_pcap_PeriodicTerminationCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_SelectedPositionMethod_vals[] = {
  {   0, "oTDOA" },
  {   1, "gPS" },
  {   2, "oTDOA-or-GPS" },
  {   3, "cell-id" },
  {   4, "uTDOA" },
  {   5, "gNSS" },
  {   6, "oTDOA-or-GNSS" },
  {   7, "gPS-and-AddPos" },
  {   8, "oTDOA-or-GPS-and-AddPos" },
  { 0, NULL }
};


static int
dissect_pcap_SelectedPositionMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 4, NULL);

  return offset;
}


static const per_sequence_t PositioningMethod_sequence[] = {
  { &hf_pcap_additionalMethodType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AdditionalMethodType },
  { &hf_pcap_selectedPositionMethod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SelectedPositionMethod },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositioningMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositioningMethod, PositioningMethod_sequence);

  return offset;
}



static int
dissect_pcap_GNSS_PositioningMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     9, 9, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_Additional_PositioningMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string pcap_PositioningPriority_vals[] = {
  {   0, "high-priority" },
  {   1, "normal-priority" },
  { 0, NULL }
};


static int
dissect_pcap_PositioningPriority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_T_new_ue_State_vals[] = {
  {   0, "cell-DCH" },
  {   1, "cell-FACH" },
  {   2, "cell-PCH" },
  {   3, "ura-PCH" },
  { 0, NULL }
};


static int
dissect_pcap_T_new_ue_State(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RRCstateChange_sequence[] = {
  { &hf_pcap_new_ue_State   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_new_ue_State },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RRCstateChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RRCstateChange, RRCstateChange_sequence);

  return offset;
}


static const per_sequence_t RequestedDataValue_sequence[] = {
  { &hf_pcap_gpsAlmanacAndSatelliteHealth, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_AlmanacAndSatelliteHealth },
  { &hf_pcap_gps_UTC_Model  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_UTC_Model },
  { &hf_pcap_gps_Ionospheric_Model, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_Ionospheric_Model },
  { &hf_pcap_gps_NavigationModel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_NavigationModel },
  { &hf_pcap_dgpsCorrections_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DGPSCorrections },
  { &hf_pcap_referenceTime_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_ReferenceTime },
  { &hf_pcap_gps_AcquisitionAssistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_AcquisitionAssistance },
  { &hf_pcap_gps_RealTime_Integrity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_RealTimeIntegrity },
  { &hf_pcap_almanacAndSatelliteHealthSIB_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_AlmanacAndSatelliteHealthSIB },
  { &hf_pcap_gps_Transmission_TOW, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GPS_Transmission_TOW },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RequestedDataValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RequestedDataValue, RequestedDataValue_sequence);

  return offset;
}


static const per_sequence_t InformationAvailable_sequence[] = {
  { &hf_pcap_requestedDataValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RequestedDataValue },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationAvailable(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationAvailable, InformationAvailable_sequence);

  return offset;
}



static int
dissect_pcap_InformationNotAvailable(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pcap_RequestedDataValueInformation_vals[] = {
  {   0, "informationAvailable" },
  {   1, "informationNotAvailable" },
  { 0, NULL }
};

static const per_choice_t RequestedDataValueInformation_choice[] = {
  {   0, &hf_pcap_informationAvailable, ASN1_NO_EXTENSIONS     , dissect_pcap_InformationAvailable },
  {   1, &hf_pcap_informationNotAvailable, ASN1_NO_EXTENSIONS     , dissect_pcap_InformationNotAvailable },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_RequestedDataValueInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_RequestedDataValueInformation, RequestedDataValueInformation_choice,
                                 NULL);

  return offset;
}


static const value_string pcap_RequestTypeEvent_vals[] = {
  {   0, "stop-change-of-service-area" },
  {   1, "direct" },
  {   2, "change-of-service-area" },
  {   3, "stop-direct" },
  {   4, "periodic" },
  {   5, "stop-periodic" },
  { 0, NULL }
};


static int
dissect_pcap_RequestTypeEvent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 2, NULL);

  return offset;
}


static const value_string pcap_RequestTypeReportArea_vals[] = {
  {   0, "service-area" },
  {   1, "geographical-area" },
  { 0, NULL }
};


static int
dissect_pcap_RequestTypeReportArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_RequestTypeAccuracyCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t RequestType_sequence[] = {
  { &hf_pcap_event          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RequestTypeEvent },
  { &hf_pcap_reportArea     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RequestTypeReportArea },
  { &hf_pcap_horizontalaccuracyCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_RequestTypeAccuracyCode },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RequestType, RequestType_sequence);

  return offset;
}


static const value_string pcap_ResponseTime_vals[] = {
  {   0, "low-delay" },
  {   1, "delay-tolerant" },
  { 0, NULL }
};


static int
dissect_pcap_ResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_HorizontalAccuracyCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const value_string pcap_NetworkAssistedGPSSuport_vals[] = {
  {   0, "network-based" },
  {   1, "ue-based" },
  {   2, "both" },
  {   3, "none" },
  { 0, NULL }
};


static int
dissect_pcap_NetworkAssistedGPSSuport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UE_PositioningCapability_sequence[] = {
  { &hf_pcap_standAloneLocationMethodsSupported, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_ueBasedOTDOASupported, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_networkAssistedGPSSupport, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_NetworkAssistedGPSSuport },
  { &hf_pcap_supportGPSTimingOfCellFrame, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_supportForIPDL , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_supportForRxTxTimeDiff, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_supportForUEAGPSinCellPCH, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_supportForSFNSFNTimeDiff, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_PositioningCapability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_PositioningCapability, UE_PositioningCapability_sequence);

  return offset;
}


static const value_string pcap_T_ganssMode_vals[] = {
  {   0, "networkBased" },
  {   1, "ue-Based" },
  {   2, "both" },
  {   3, "none" },
  { 0, NULL }
};


static int
dissect_pcap_T_ganssMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t NetworkAssistedGANSSSupport_item_sequence[] = {
  { &hf_pcap_ganssID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_ganssMode      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_ganssMode },
  { &hf_pcap_networkAssistedGANSSSupport_item_ganssSignalID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSS_SignalID },
  { &hf_pcap_supportGANSSTimingOfCellFrame, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_supportGANSSCarrierPhaseMeasurement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_NetworkAssistedGANSSSupport_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_NetworkAssistedGANSSSupport_item, NetworkAssistedGANSSSupport_item_sequence);

  return offset;
}


static const per_sequence_t NetworkAssistedGANSSSupport_sequence_of[1] = {
  { &hf_pcap_NetworkAssistedGANSSSupport_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_NetworkAssistedGANSSSupport_item },
};

static int
dissect_pcap_NetworkAssistedGANSSSupport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_NetworkAssistedGANSSSupport, NetworkAssistedGANSSSupport_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}


static const value_string pcap_T_addPosID_vals[] = {
  {   0, "barometricPressure" },
  {   1, "wLAN" },
  {   2, "bluetooth" },
  {   3, "mBS" },
  { 0, NULL }
};


static int
dissect_pcap_T_addPosID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_T_addPosMode_vals[] = {
  {   0, "standalone" },
  {   1, "ue-assisted" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_pcap_T_addPosMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t AddPosSupport_Element_sequence[] = {
  { &hf_pcap_addPosID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_addPosID },
  { &hf_pcap_addPosMode     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_addPosMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_AddPosSupport_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_AddPosSupport_Element, AddPosSupport_Element_sequence);

  return offset;
}


static const per_sequence_t AddPosSupport_sequence_of[1] = {
  { &hf_pcap_AddPosSupport_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_AddPosSupport_Element },
};

static int
dissect_pcap_AddPosSupport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_AddPosSupport, AddPosSupport_sequence_of,
                                                  1, maxAddPos, false);

  return offset;
}


static const per_sequence_t GANSS_SBAS_IDs_sequence[] = {
  { &hf_pcap_ganss_sbas_ids , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_SBAS_IDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_SBAS_IDs, GANSS_SBAS_IDs_sequence);

  return offset;
}


static const per_sequence_t GANSS_Signal_IDs_sequence[] = {
  { &hf_pcap_ganss_signal_ids, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_Signal_IDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_Signal_IDs, GANSS_Signal_IDs_sequence);

  return offset;
}



static int
dissect_pcap_SupportGANSSNonNativeADchoices(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_pcap_UTDOA_BitCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 5000U, NULL, false);

  return offset;
}



static int
dissect_pcap_UTDOA_TimeInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3000U, NULL, false);

  return offset;
}


static const per_sequence_t UTDOAPositioning_sequence[] = {
  { &hf_pcap_utdoa_BitCount , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UTDOA_BitCount },
  { &hf_pcap_utdoa_timeInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UTDOA_TimeInterval },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTDOAPositioning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTDOAPositioning, UTDOAPositioning_sequence);

  return offset;
}


static const value_string pcap_EnvironmentCharacterisation_vals[] = {
  {   0, "heavyMultipathandNLOSconditions" },
  {   1, "noOrLightMultipathAndUsuallyLOSconditions" },
  {   2, "notDefinedOrMixedEnvironment" },
  { 0, NULL }
};


static int
dissect_pcap_EnvironmentCharacterisation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_VerticalAccuracyCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t GPSPositioningInstructions_sequence[] = {
  { &hf_pcap_horizontalAccuracyCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_HorizontalAccuracyCode },
  { &hf_pcap_verticalAccuracyCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_VerticalAccuracyCode },
  { &hf_pcap_gpsTimingOfCellWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_additionalAssistanceDataRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPSPositioningInstructions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPSPositioningInstructions, GPSPositioningInstructions_sequence);

  return offset;
}


static const per_sequence_t GPSPositioning_sequence[] = {
  { &hf_pcap_gpsPositioningInstructions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GPSPositioningInstructions },
  { &hf_pcap_requestedDataValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_RequestedDataValue },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GPSPositioning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GPSPositioning, GPSPositioning_sequence);

  return offset;
}


static const per_sequence_t GANSS_PositioningInstructions_sequence[] = {
  { &hf_pcap_horizontalAccuracyCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_HorizontalAccuracyCode },
  { &hf_pcap_verticalAccuracyCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_VerticalAccuracyCode },
  { &hf_pcap_ganssTimingOfCellWanted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_gANSS_PositioningInstructions_additionalAssistanceDataRequest, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BIT_STRING_SIZE_8 },
  { &hf_pcap_measurementValidity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_MeasurementValidity },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSS_PositioningInstructions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSS_PositioningInstructions, GANSS_PositioningInstructions_sequence);

  return offset;
}


static const per_sequence_t GANSSPositioning_sequence[] = {
  { &hf_pcap_ganssPositioningInstructions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GANSS_PositioningInstructions },
  { &hf_pcap_requestedDataValue, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_RequestedDataValue },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_GANSSPositioning(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_GANSSPositioning, GANSSPositioning_sequence);

  return offset;
}



static int
dissect_pcap_GANSScarrierPhaseRequested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_GANSSMultiFreqMeasRequested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t T_fdd_01_sequence[] = {
  { &hf_pcap_primaryCPICH_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PrimaryScramblingCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_fdd_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_fdd_01, T_fdd_01_sequence);

  return offset;
}



static int
dissect_pcap_CellParameterID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, true);

  return offset;
}


static const per_sequence_t T_tdd_01_sequence[] = {
  { &hf_pcap_cellParameterID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CellParameterID },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_tdd_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_tdd_01, T_tdd_01_sequence);

  return offset;
}


static const value_string pcap_T_modeSpecificInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_choice[] = {
  {   0, &hf_pcap_fdd_01         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_fdd_01 },
  {   1, &hf_pcap_tdd_01         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_tdd_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_modeSpecificInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_modeSpecificInfo, T_modeSpecificInfo_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_UARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}


static const per_sequence_t FrequencyInfoFDD_sequence[] = {
  { &hf_pcap_uarfcn_UL      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UARFCN },
  { &hf_pcap_uarfcn_DL      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UARFCN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_FrequencyInfoFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_FrequencyInfoFDD, FrequencyInfoFDD_sequence);

  return offset;
}


static const per_sequence_t FrequencyInfoTDD_sequence[] = {
  { &hf_pcap_uarfcn         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UARFCN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_FrequencyInfoTDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_FrequencyInfoTDD, FrequencyInfoTDD_sequence);

  return offset;
}


static const value_string pcap_T_modeSpecificInfo_03_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_03_choice[] = {
  {   0, &hf_pcap_fdd_04         , ASN1_EXTENSION_ROOT    , dissect_pcap_FrequencyInfoFDD },
  {   1, &hf_pcap_tdd_04         , ASN1_EXTENSION_ROOT    , dissect_pcap_FrequencyInfoTDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_modeSpecificInfo_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_modeSpecificInfo_03, T_modeSpecificInfo_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t FrequencyInfo_sequence[] = {
  { &hf_pcap_modeSpecificInfo_03, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_modeSpecificInfo_03 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_FrequencyInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_FrequencyInfo, FrequencyInfo_sequence);

  return offset;
}


static const value_string pcap_ReferenceCellPosition_vals[] = {
  {   0, "ellipsoidPoint" },
  {   1, "ellipsoidPointWithAltitude" },
  { 0, NULL }
};

static const per_choice_t ReferenceCellPosition_choice[] = {
  {   0, &hf_pcap_ellipsoidPoint , ASN1_EXTENSION_ROOT    , dissect_pcap_GeographicalCoordinates },
  {   1, &hf_pcap_ellipsoidPointWithAltitude, ASN1_EXTENSION_ROOT    , dissect_pcap_GA_PointWithAltitude },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_ReferenceCellPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_ReferenceCellPosition, ReferenceCellPosition_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_32766(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32766U, NULL, false);

  return offset;
}


static const per_sequence_t T_ueBased_sequence[] = {
  { &hf_pcap_cellPosition   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ReferenceCellPosition },
  { &hf_pcap_roundTripTime_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_32766 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_ueBased(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_ueBased, T_ueBased_sequence);

  return offset;
}


static const per_sequence_t T_ueAssisted_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_pcap_T_ueAssisted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_ueAssisted, T_ueAssisted_sequence);

  return offset;
}


static const value_string pcap_T_positioningMode_vals[] = {
  {   0, "ueBased" },
  {   1, "ueAssisted" },
  { 0, NULL }
};

static const per_choice_t T_positioningMode_choice[] = {
  {   0, &hf_pcap_ueBased        , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ueBased },
  {   1, &hf_pcap_ueAssisted     , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ueAssisted },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_positioningMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_positioningMode, T_positioningMode_choice,
                                 NULL);

  return offset;
}


static const value_string pcap_IP_Spacing_vals[] = {
  {   0, "e5" },
  {   1, "e7" },
  {   2, "e10" },
  {   3, "e15" },
  {   4, "e20" },
  {   5, "e30" },
  {   6, "e40" },
  {   7, "e50" },
  { 0, NULL }
};


static int
dissect_pcap_IP_Spacing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_IP_Length_vals[] = {
  {   0, "ipl5" },
  {   1, "ipl10" },
  { 0, NULL }
};


static int
dissect_pcap_IP_Length(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, false);

  return offset;
}


static const per_sequence_t T_fdd_02_sequence[] = {
  { &hf_pcap_ip_Spacing     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_IP_Spacing },
  { &hf_pcap_ip_Length      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_IP_Length },
  { &hf_pcap_ip_Offset      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_9 },
  { &hf_pcap_seed           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_fdd_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_fdd_02, T_fdd_02_sequence);

  return offset;
}


static const per_sequence_t T_tdd_02_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_pcap_T_tdd_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_tdd_02, T_tdd_02_sequence);

  return offset;
}


static const value_string pcap_T_modeSpecificInfo_01_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_01_choice[] = {
  {   0, &hf_pcap_fdd_02         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_fdd_02 },
  {   1, &hf_pcap_tdd_02         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_tdd_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_modeSpecificInfo_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_modeSpecificInfo_01, T_modeSpecificInfo_01_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_10_25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            10U, 25U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, false);

  return offset;
}


static const per_sequence_t BurstModeParameters_sequence[] = {
  { &hf_pcap_burstStart     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
  { &hf_pcap_burstLength    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_10_25 },
  { &hf_pcap_burstFreq      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_1_16 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_BurstModeParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_BurstModeParameters, BurstModeParameters_sequence);

  return offset;
}


static const per_sequence_t UE_Positioning_IPDL_Parameters_sequence[] = {
  { &hf_pcap_modeSpecificInfo_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_modeSpecificInfo_01 },
  { &hf_pcap_burstModeParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_BurstModeParameters },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_Positioning_IPDL_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_Positioning_IPDL_Parameters, UE_Positioning_IPDL_Parameters_sequence);

  return offset;
}


static const per_sequence_t UE_Positioning_OTDOA_ReferenceCellInfo_sequence[] = {
  { &hf_pcap_sfn_01         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_SFN },
  { &hf_pcap_modeSpecificInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_modeSpecificInfo },
  { &hf_pcap_frequencyInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_FrequencyInfo },
  { &hf_pcap_positioningMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_positioningMode },
  { &hf_pcap_ue_positioning_IPDL_Paremeters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UE_Positioning_IPDL_Parameters },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_Positioning_OTDOA_ReferenceCellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_Positioning_OTDOA_ReferenceCellInfo, UE_Positioning_OTDOA_ReferenceCellInfo_sequence);

  return offset;
}


static const per_sequence_t T_fdd_03_sequence[] = {
  { &hf_pcap_primaryCPICH_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PrimaryScramblingCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_fdd_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_fdd_03, T_fdd_03_sequence);

  return offset;
}


static const per_sequence_t T_tdd_03_sequence[] = {
  { &hf_pcap_cellParameterID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CellParameterID },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_tdd_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_tdd_03, T_tdd_03_sequence);

  return offset;
}


static const value_string pcap_T_modeSpecificInfo_02_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_02_choice[] = {
  {   0, &hf_pcap_fdd_03         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_fdd_03 },
  {   1, &hf_pcap_tdd_03         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_tdd_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_modeSpecificInfo_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_modeSpecificInfo_02, T_modeSpecificInfo_02_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_38399(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 38399U, NULL, false);

  return offset;
}


static const per_sequence_t SFN_SFN_RelTimeDifference1_sequence[] = {
  { &hf_pcap_sfn_Offset     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_sfn_sfn_Reltimedifference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_38399 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_SFN_SFN_RelTimeDifference1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_SFN_SFN_RelTimeDifference1, SFN_SFN_RelTimeDifference1_sequence);

  return offset;
}


static const value_string pcap_SFN_Offset_Validity_vals[] = {
  {   0, "false" },
  { 0, NULL }
};


static int
dissect_pcap_SFN_Offset_Validity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}


static const value_string pcap_SFN_SFN_Drift_vals[] = {
  {   0, "sfnsfndrift0" },
  {   1, "sfnsfndrift1" },
  {   2, "sfnsfndrift2" },
  {   3, "sfnsfndrift3" },
  {   4, "sfnsfndrift4" },
  {   5, "sfnsfndrift5" },
  {   6, "sfnsfndrift8" },
  {   7, "sfnsfndrift10" },
  {   8, "sfnsfndrift15" },
  {   9, "sfnsfndrift25" },
  {  10, "sfnsfndrift35" },
  {  11, "sfnsfndrift50" },
  {  12, "sfnsfndrift65" },
  {  13, "sfnsfndrift80" },
  {  14, "sfnsfndrift100" },
  {  15, "sfnsfndrift-1" },
  {  16, "sfnsfndrift-2" },
  {  17, "sfnsfndrift-3" },
  {  18, "sfnsfndrift-4" },
  {  19, "sfnsfndrift-5" },
  {  20, "sfnsfndrift-8" },
  {  21, "sfnsfndrift-10" },
  {  22, "sfnsfndrift-15" },
  {  23, "sfnsfndrift-25" },
  {  24, "sfnsfndrift-35" },
  {  25, "sfnsfndrift-50" },
  {  26, "sfnsfndrift-65" },
  {  27, "sfnsfndrift-80" },
  {  28, "sfnsfndrift-100" },
  { 0, NULL }
};

static value_string_ext pcap_SFN_SFN_Drift_vals_ext = VALUE_STRING_EXT_INIT(pcap_SFN_SFN_Drift_vals);


static int
dissect_pcap_SFN_SFN_Drift(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     29, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_OTDOA_SearchWindowSize_vals[] = {
  {   0, "c20" },
  {   1, "c40" },
  {   2, "c80" },
  {   3, "c160" },
  {   4, "c320" },
  {   5, "c640" },
  {   6, "c1280" },
  {   7, "moreThan1280" },
  { 0, NULL }
};


static int
dissect_pcap_OTDOA_SearchWindowSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_M20000_20000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -20000, 20000U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_M4000_4000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4000, 4000U, NULL, false);

  return offset;
}



static int
dissect_pcap_FineSFNSFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const per_sequence_t T_ueBased_01_sequence[] = {
  { &hf_pcap_relativeNorth  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_M20000_20000 },
  { &hf_pcap_relativeEast   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_M20000_20000 },
  { &hf_pcap_relativeAltitude, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_M4000_4000 },
  { &hf_pcap_fineSFN_SFN    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_FineSFNSFN },
  { &hf_pcap_roundTripTime_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_32766 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_ueBased_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_ueBased_01, T_ueBased_01_sequence);

  return offset;
}


static const per_sequence_t T_ueAssisted_01_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_pcap_T_ueAssisted_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_ueAssisted_01, T_ueAssisted_01_sequence);

  return offset;
}


static const value_string pcap_T_positioningMode_01_vals[] = {
  {   0, "ueBased" },
  {   1, "ueAssisted" },
  { 0, NULL }
};

static const per_choice_t T_positioningMode_01_choice[] = {
  {   0, &hf_pcap_ueBased_01     , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ueBased_01 },
  {   1, &hf_pcap_ueAssisted_01  , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ueAssisted_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_positioningMode_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_positioningMode_01, T_positioningMode_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UE_Positioning_OTDOA_NeighbourCellInfo_sequence[] = {
  { &hf_pcap_modeSpecificInfo_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_modeSpecificInfo_02 },
  { &hf_pcap_frequencyInfo  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_FrequencyInfo },
  { &hf_pcap_ue_positioning_IPDL_Paremeters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UE_Positioning_IPDL_Parameters },
  { &hf_pcap_sfn_SFN_RelTimeDifference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SFN_SFN_RelTimeDifference1 },
  { &hf_pcap_sfn_Offset_Validity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_SFN_Offset_Validity },
  { &hf_pcap_sfn_SFN_Drift  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_SFN_SFN_Drift },
  { &hf_pcap_searchWindowSize, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_OTDOA_SearchWindowSize },
  { &hf_pcap_positioningMode_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_positioningMode_01 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_Positioning_OTDOA_NeighbourCellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_Positioning_OTDOA_NeighbourCellInfo, UE_Positioning_OTDOA_NeighbourCellInfo_sequence);

  return offset;
}


static const per_sequence_t UE_Positioning_OTDOA_NeighbourCellList_sequence_of[1] = {
  { &hf_pcap_UE_Positioning_OTDOA_NeighbourCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_UE_Positioning_OTDOA_NeighbourCellInfo },
};

static int
dissect_pcap_UE_Positioning_OTDOA_NeighbourCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_UE_Positioning_OTDOA_NeighbourCellList, UE_Positioning_OTDOA_NeighbourCellList_sequence_of,
                                                  1, maxCellMeas, false);

  return offset;
}


static const per_sequence_t UE_Positioning_OTDOA_AssistanceData_sequence[] = {
  { &hf_pcap_ue_positioning_OTDOA_ReferenceCellInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UE_Positioning_OTDOA_ReferenceCellInfo },
  { &hf_pcap_ue_positioning_OTDOA_NeighbourCellList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UE_Positioning_OTDOA_NeighbourCellList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UE_Positioning_OTDOA_AssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UE_Positioning_OTDOA_AssistanceData, UE_Positioning_OTDOA_AssistanceData_sequence);

  return offset;
}


static const per_sequence_t OTDOAAssistanceData_sequence[] = {
  { &hf_pcap_uE_Positioning_OTDOA_AssistanceData, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_Positioning_OTDOA_AssistanceData },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_OTDOAAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_OTDOAAssistanceData, OTDOAAssistanceData_sequence);

  return offset;
}


static const value_string pcap_ScramblingCodeType_vals[] = {
  {   0, "shortSC" },
  {   1, "longSC" },
  { 0, NULL }
};


static int
dissect_pcap_ScramblingCodeType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_UL_ScramblingCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, false);

  return offset;
}



static int
dissect_pcap_NumberOfFBI_Bits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2U, NULL, false);

  return offset;
}


static const per_sequence_t T_fdd_04_sequence[] = {
  { &hf_pcap_scramblingCodeType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ScramblingCodeType },
  { &hf_pcap_scramblingCode , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UL_ScramblingCode },
  { &hf_pcap_tfci_Existence , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_numberOfFBI_Bits, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_NumberOfFBI_Bits },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_fdd_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_fdd_04, T_fdd_04_sequence);

  return offset;
}


static const value_string pcap_TFCI_Coding_vals[] = {
  {   0, "v4" },
  {   1, "v8" },
  {   2, "v16" },
  {   3, "v32" },
  { 0, NULL }
};


static int
dissect_pcap_TFCI_Coding(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_PuncturingLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const value_string pcap_RepetitionPeriod_vals[] = {
  {   0, "v1" },
  {   1, "v2" },
  {   2, "v4" },
  {   3, "v8" },
  {   4, "v16" },
  {   5, "v32" },
  {   6, "v64" },
  { 0, NULL }
};


static int
dissect_pcap_RepetitionPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_RepetitionLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 63U, NULL, false);

  return offset;
}


static const value_string pcap_TDD_DPCHOffset_vals[] = {
  {   0, "initialOffset" },
  {   1, "noinitialOffset" },
  { 0, NULL }
};

static const per_choice_t TDD_DPCHOffset_choice[] = {
  {   0, &hf_pcap_initialOffset  , ASN1_NO_EXTENSIONS     , dissect_pcap_INTEGER_0_255 },
  {   1, &hf_pcap_noinitialOffset, ASN1_NO_EXTENSIONS     , dissect_pcap_INTEGER_0_63 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_TDD_DPCHOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_TDD_DPCHOffset, TDD_DPCHOffset_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_TimeSlot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14U, NULL, false);

  return offset;
}


static const value_string pcap_MidambleConfigurationBurstType1And3_vals[] = {
  {   0, "v4" },
  {   1, "v8" },
  {   2, "v16" },
  { 0, NULL }
};


static int
dissect_pcap_MidambleConfigurationBurstType1And3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pcap_MidambleShiftLong(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const value_string pcap_T_midambleAllocationMode_vals[] = {
  {   0, "defaultMidamble" },
  {   1, "commonMidamble" },
  {   2, "ueSpecificMidamble" },
  { 0, NULL }
};

static const per_choice_t T_midambleAllocationMode_choice[] = {
  {   0, &hf_pcap_defaultMidamble, ASN1_EXTENSION_ROOT    , dissect_pcap_NULL },
  {   1, &hf_pcap_commonMidamble , ASN1_EXTENSION_ROOT    , dissect_pcap_NULL },
  {   2, &hf_pcap_ueSpecificMidamble, ASN1_EXTENSION_ROOT    , dissect_pcap_MidambleShiftLong },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_midambleAllocationMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_midambleAllocationMode, T_midambleAllocationMode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type1_sequence[] = {
  { &hf_pcap_midambleConfigurationBurstType1And3, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MidambleConfigurationBurstType1And3 },
  { &hf_pcap_midambleAllocationMode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_midambleAllocationMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_type1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_type1, T_type1_sequence);

  return offset;
}


static const value_string pcap_MidambleConfigurationBurstType2_vals[] = {
  {   0, "v3" },
  {   1, "v6" },
  { 0, NULL }
};


static int
dissect_pcap_MidambleConfigurationBurstType2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_MidambleShiftShort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 5U, NULL, false);

  return offset;
}


static const value_string pcap_T_midambleAllocationMode_01_vals[] = {
  {   0, "defaultMidamble" },
  {   1, "commonMidamble" },
  {   2, "ueSpecificMidamble" },
  { 0, NULL }
};

static const per_choice_t T_midambleAllocationMode_01_choice[] = {
  {   0, &hf_pcap_defaultMidamble, ASN1_EXTENSION_ROOT    , dissect_pcap_NULL },
  {   1, &hf_pcap_commonMidamble , ASN1_EXTENSION_ROOT    , dissect_pcap_NULL },
  {   2, &hf_pcap_ueSpecificMidamble_01, ASN1_EXTENSION_ROOT    , dissect_pcap_MidambleShiftShort },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_midambleAllocationMode_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_midambleAllocationMode_01, T_midambleAllocationMode_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type2_sequence[] = {
  { &hf_pcap_midambleConfigurationBurstType2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MidambleConfigurationBurstType2 },
  { &hf_pcap_midambleAllocationMode_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_midambleAllocationMode_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_type2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_type2, T_type2_sequence);

  return offset;
}


static const value_string pcap_T_midambleAllocationMode_02_vals[] = {
  {   0, "defaultMidamble" },
  {   1, "ueSpecificMidamble" },
  { 0, NULL }
};

static const per_choice_t T_midambleAllocationMode_02_choice[] = {
  {   0, &hf_pcap_defaultMidamble, ASN1_EXTENSION_ROOT    , dissect_pcap_NULL },
  {   1, &hf_pcap_ueSpecificMidamble, ASN1_EXTENSION_ROOT    , dissect_pcap_MidambleShiftLong },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_T_midambleAllocationMode_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_T_midambleAllocationMode_02, T_midambleAllocationMode_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_type3_sequence[] = {
  { &hf_pcap_midambleConfigurationBurstType1And3, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MidambleConfigurationBurstType1And3 },
  { &hf_pcap_midambleAllocationMode_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_T_midambleAllocationMode_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_type3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_type3, T_type3_sequence);

  return offset;
}


static const value_string pcap_MidambleShiftAndBurstType_vals[] = {
  {   0, "type1" },
  {   1, "type2" },
  {   2, "type3" },
  { 0, NULL }
};

static const per_choice_t MidambleShiftAndBurstType_choice[] = {
  {   0, &hf_pcap_type1          , ASN1_EXTENSION_ROOT    , dissect_pcap_T_type1 },
  {   1, &hf_pcap_type2          , ASN1_EXTENSION_ROOT    , dissect_pcap_T_type2 },
  {   2, &hf_pcap_type3          , ASN1_EXTENSION_ROOT    , dissect_pcap_T_type3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_MidambleShiftAndBurstType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_MidambleShiftAndBurstType, MidambleShiftAndBurstType_choice,
                                 NULL);

  return offset;
}


static const value_string pcap_TDD_ChannelisationCode_vals[] = {
  {   0, "chCode1div1" },
  {   1, "chCode2div1" },
  {   2, "chCode2div2" },
  {   3, "chCode4div1" },
  {   4, "chCode4div2" },
  {   5, "chCode4div3" },
  {   6, "chCode4div4" },
  {   7, "chCode8div1" },
  {   8, "chCode8div2" },
  {   9, "chCode8div3" },
  {  10, "chCode8div4" },
  {  11, "chCode8div5" },
  {  12, "chCode8div6" },
  {  13, "chCode8div7" },
  {  14, "chCode8div8" },
  {  15, "chCode16div1" },
  {  16, "chCode16div2" },
  {  17, "chCode16div3" },
  {  18, "chCode16div4" },
  {  19, "chCode16div5" },
  {  20, "chCode16div6" },
  {  21, "chCode16div7" },
  {  22, "chCode16div8" },
  {  23, "chCode16div9" },
  {  24, "chCode16div10" },
  {  25, "chCode16div11" },
  {  26, "chCode16div12" },
  {  27, "chCode16div13" },
  {  28, "chCode16div14" },
  {  29, "chCode16div15" },
  {  30, "chCode16div16" },
  { 0, NULL }
};

static value_string_ext pcap_TDD_ChannelisationCode_vals_ext = VALUE_STRING_EXT_INIT(pcap_TDD_ChannelisationCode_vals);


static int
dissect_pcap_TDD_ChannelisationCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     31, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TDD_UL_Code_InformationItem_sequence[] = {
  { &hf_pcap_tdd_ChannelisationCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TDD_ChannelisationCode },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TDD_UL_Code_InformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TDD_UL_Code_InformationItem, TDD_UL_Code_InformationItem_sequence);

  return offset;
}


static const per_sequence_t TDD_UL_Code_Information_sequence_of[1] = {
  { &hf_pcap_TDD_UL_Code_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_TDD_UL_Code_InformationItem },
};

static int
dissect_pcap_TDD_UL_Code_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_TDD_UL_Code_Information, TDD_UL_Code_Information_sequence_of,
                                                  1, maxNrOfDPCHs, false);

  return offset;
}


static const per_sequence_t UL_Timeslot_InformationItem_sequence[] = {
  { &hf_pcap_timeSlot       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TimeSlot },
  { &hf_pcap_midambleShiftAndBurstType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MidambleShiftAndBurstType },
  { &hf_pcap_tFCI_Presence  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_BOOLEAN },
  { &hf_pcap_uL_Code_InformationList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TDD_UL_Code_Information },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UL_Timeslot_InformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UL_Timeslot_InformationItem, UL_Timeslot_InformationItem_sequence);

  return offset;
}


static const per_sequence_t UL_Timeslot_Information_sequence_of[1] = {
  { &hf_pcap_UL_Timeslot_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_UL_Timeslot_InformationItem },
};

static int
dissect_pcap_UL_Timeslot_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_UL_Timeslot_Information, UL_Timeslot_Information_sequence_of,
                                                  1, maxNrOfULTSs, false);

  return offset;
}



static int
dissect_pcap_FrameOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_pcap_SpecialBurstScheduling(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, false);

  return offset;
}


static const per_sequence_t T_tdd_04_sequence[] = {
  { &hf_pcap_cellParameterID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CellParameterID },
  { &hf_pcap_tFCI_Coding    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TFCI_Coding },
  { &hf_pcap_punctureLimit  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PuncturingLimit },
  { &hf_pcap_repetitionPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RepetitionPeriod },
  { &hf_pcap_repetitionLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RepetitionLength },
  { &hf_pcap_tdd_DPCHOffset , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TDD_DPCHOffset },
  { &hf_pcap_uL_Timeslot_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UL_Timeslot_Information },
  { &hf_pcap_frameOffset    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_FrameOffset },
  { &hf_pcap_specialBurstScheduling, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SpecialBurstScheduling },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_tdd_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_tdd_04, T_tdd_04_sequence);

  return offset;
}


static const value_string pcap_UL_DPCHInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t UL_DPCHInfo_choice[] = {
  {   0, &hf_pcap_fdd_05         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_fdd_04 },
  {   1, &hf_pcap_tdd_05         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_tdd_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_UL_DPCHInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_UL_DPCHInfo, UL_DPCHInfo_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_ChipOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 38399U, NULL, false);

  return offset;
}


static const per_sequence_t DL_InformationFDD_sequence[] = {
  { &hf_pcap_primaryScramblingCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PrimaryScramblingCode },
  { &hf_pcap_chipOffset     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ChipOffset },
  { &hf_pcap_frameOffset    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_FrameOffset },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DL_InformationFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DL_InformationFDD, DL_InformationFDD_sequence);

  return offset;
}



static int
dissect_pcap_TGPSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxTGPS, NULL, false);

  return offset;
}



static int
dissect_pcap_TGSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14U, NULL, false);

  return offset;
}



static int
dissect_pcap_GapLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 14U, NULL, false);

  return offset;
}



static int
dissect_pcap_TGD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 269U, NULL, false);

  return offset;
}



static int
dissect_pcap_GapDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 144U, NULL, true);

  return offset;
}


static const value_string pcap_Uplink_Compressed_Mode_Method_vals[] = {
  {   0, "sFdiv2" },
  {   1, "higher-layer-scheduling" },
  { 0, NULL }
};


static int
dissect_pcap_Uplink_Compressed_Mode_Method(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Transmission_Gap_Pattern_Sequence_Information_item_sequence[] = {
  { &hf_pcap_tGPSID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TGPSID },
  { &hf_pcap_tGSN           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TGSN },
  { &hf_pcap_tGL1           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GapLength },
  { &hf_pcap_tGL2           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GapLength },
  { &hf_pcap_tGD            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TGD },
  { &hf_pcap_tGPL1          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_GapDuration },
  { &hf_pcap_uplink_Compressed_Mode_Method, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Uplink_Compressed_Mode_Method },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Transmission_Gap_Pattern_Sequence_Information_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Transmission_Gap_Pattern_Sequence_Information_item, Transmission_Gap_Pattern_Sequence_Information_item_sequence);

  return offset;
}


static const per_sequence_t Transmission_Gap_Pattern_Sequence_Information_sequence_of[1] = {
  { &hf_pcap_Transmission_Gap_Pattern_Sequence_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Transmission_Gap_Pattern_Sequence_Information_item },
};

static int
dissect_pcap_Transmission_Gap_Pattern_Sequence_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_Transmission_Gap_Pattern_Sequence_Information, Transmission_Gap_Pattern_Sequence_Information_sequence_of,
                                                  1, maxTGPS, false);

  return offset;
}



static int
dissect_pcap_CFN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_pcap_TGPRC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, false);

  return offset;
}


static const per_sequence_t Transmission_Gap_Pattern_Sequence_Status_List_item_sequence[] = {
  { &hf_pcap_tGPSID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TGPSID },
  { &hf_pcap_tGPRC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TGPRC },
  { &hf_pcap_tGCFN          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CFN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item, Transmission_Gap_Pattern_Sequence_Status_List_item_sequence);

  return offset;
}


static const per_sequence_t Transmission_Gap_Pattern_Sequence_Status_List_sequence_of[1] = {
  { &hf_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item },
};

static int
dissect_pcap_Transmission_Gap_Pattern_Sequence_Status_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_Transmission_Gap_Pattern_Sequence_Status_List, Transmission_Gap_Pattern_Sequence_Status_List_sequence_of,
                                                  1, maxTGPS, false);

  return offset;
}


static const per_sequence_t Active_Pattern_Sequence_Information_sequence[] = {
  { &hf_pcap_cMConfigurationChangeCFN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CFN },
  { &hf_pcap_transmission_Gap_Pattern_Sequence_Status, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Transmission_Gap_Pattern_Sequence_Status_List },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Active_Pattern_Sequence_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Active_Pattern_Sequence_Information, Active_Pattern_Sequence_Information_sequence);

  return offset;
}


static const per_sequence_t UL_InformationFDD_sequence[] = {
  { &hf_pcap_transmissionGapPatternSequenceInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Transmission_Gap_Pattern_Sequence_Information },
  { &hf_pcap_activePatternSequenceInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Active_Pattern_Sequence_Information },
  { &hf_pcap_cFN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CFN },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UL_InformationFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UL_InformationFDD, UL_InformationFDD_sequence);

  return offset;
}


static const per_sequence_t Compressed_Mode_Assistance_Data_sequence[] = {
  { &hf_pcap_dl_information , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_DL_InformationFDD },
  { &hf_pcap_ul_information , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UL_InformationFDD },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Compressed_Mode_Assistance_Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Compressed_Mode_Assistance_Data, Compressed_Mode_Assistance_Data_sequence);

  return offset;
}


static const per_sequence_t T_ctfc2Bit_sequence_of[1] = {
  { &hf_pcap_ctfc2Bit_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_3 },
};

static int
dissect_pcap_T_ctfc2Bit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ctfc2Bit, T_ctfc2Bit_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const per_sequence_t T_ctfc4Bit_sequence_of[1] = {
  { &hf_pcap_ctfc4Bit_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_15 },
};

static int
dissect_pcap_T_ctfc4Bit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ctfc4Bit, T_ctfc4Bit_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const per_sequence_t T_ctfc6Bit_sequence_of[1] = {
  { &hf_pcap_ctfc6Bit_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_63 },
};

static int
dissect_pcap_T_ctfc6Bit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ctfc6Bit, T_ctfc6Bit_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const per_sequence_t T_ctfc8Bit_sequence_of[1] = {
  { &hf_pcap_ctfc8Bit_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
};

static int
dissect_pcap_T_ctfc8Bit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ctfc8Bit, T_ctfc8Bit_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const per_sequence_t T_ctfc12Bit_sequence_of[1] = {
  { &hf_pcap_ctfc12Bit_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
};

static int
dissect_pcap_T_ctfc12Bit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ctfc12Bit, T_ctfc12Bit_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const per_sequence_t T_ctfc16Bit_sequence_of[1] = {
  { &hf_pcap_ctfc16Bit_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_65535 },
};

static int
dissect_pcap_T_ctfc16Bit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ctfc16Bit, T_ctfc16Bit_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const per_sequence_t T_ctfc24Bit_sequence_of[1] = {
  { &hf_pcap_ctfc24Bit_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_16777215 },
};

static int
dissect_pcap_T_ctfc24Bit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_T_ctfc24Bit, T_ctfc24Bit_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const value_string pcap_CTFC_vals[] = {
  {   0, "ctfc2Bit" },
  {   1, "ctfc4Bit" },
  {   2, "ctfc6Bit" },
  {   3, "ctfc8Bit" },
  {   4, "ctfc12Bit" },
  {   5, "ctfc16Bit" },
  {   6, "ctfc24Bit" },
  { 0, NULL }
};

static const per_choice_t CTFC_choice[] = {
  {   0, &hf_pcap_ctfc2Bit       , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ctfc2Bit },
  {   1, &hf_pcap_ctfc4Bit       , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ctfc4Bit },
  {   2, &hf_pcap_ctfc6Bit       , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ctfc6Bit },
  {   3, &hf_pcap_ctfc8Bit       , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ctfc8Bit },
  {   4, &hf_pcap_ctfc12Bit      , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ctfc12Bit },
  {   5, &hf_pcap_ctfc16Bit      , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ctfc16Bit },
  {   6, &hf_pcap_ctfc24Bit      , ASN1_EXTENSION_ROOT    , dissect_pcap_T_ctfc24Bit },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_CTFC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_CTFC, CTFC_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TFCS_sequence_of[1] = {
  { &hf_pcap_TFCS_item      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_CTFC },
};

static int
dissect_pcap_TFCS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_TFCS, TFCS_sequence_of,
                                                  1, maxTFC, false);

  return offset;
}


static const value_string pcap_UL_TrCHType_vals[] = {
  {   0, "dch" },
  {   1, "usch" },
  { 0, NULL }
};


static int
dissect_pcap_UL_TrCHType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_RLC_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            129U, 5055U, NULL, false);

  return offset;
}


static const value_string pcap_TransportFormatSet_TransmissionTimeIntervalDynamic_vals[] = {
  {   0, "msec-10" },
  {   1, "msec-20" },
  {   2, "msec-40" },
  {   3, "msec-80" },
  {   4, "dynamic" },
  { 0, NULL }
};


static int
dissect_pcap_TransportFormatSet_TransmissionTimeIntervalDynamic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_TransportFormatSet_NrOfTransportBlocks(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 512U, NULL, false);

  return offset;
}


static const per_sequence_t TbsTTIInfo_sequence[] = {
  { &hf_pcap_tTIInfo        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransportFormatSet_TransmissionTimeIntervalDynamic },
  { &hf_pcap_numberOfTbs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_NrOfTransportBlocks },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TbsTTIInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TbsTTIInfo, TbsTTIInfo_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo_sequence_of[1] = {
  { &hf_pcap_numberOfTbsTTIList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_TbsTTIInfo },
};

static int
dissect_pcap_SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo, SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo_sequence_of,
                                                  1, maxNrOfTFs, false);

  return offset;
}


static const per_sequence_t TransportFormatSet_DynamicPartList_item_sequence[] = {
  { &hf_pcap_rlc_Size       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RLC_Size },
  { &hf_pcap_numberOfTbsTTIList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TransportFormatSet_DynamicPartList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TransportFormatSet_DynamicPartList_item, TransportFormatSet_DynamicPartList_item_sequence);

  return offset;
}


static const per_sequence_t TransportFormatSet_DynamicPartList_sequence_of[1] = {
  { &hf_pcap_TransportFormatSet_DynamicPartList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_DynamicPartList_item },
};

static int
dissect_pcap_TransportFormatSet_DynamicPartList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_TransportFormatSet_DynamicPartList, TransportFormatSet_DynamicPartList_sequence_of,
                                                  1, maxNrOfTFs, false);

  return offset;
}


static const value_string pcap_TransportFormatSet_TransmissionTimeIntervalSemiStatic_vals[] = {
  {   0, "msec-5" },
  {   1, "msec-10" },
  {   2, "msec-20" },
  {   3, "msec-40" },
  {   4, "msec-80" },
  {   5, "dynamic" },
  { 0, NULL }
};


static int
dissect_pcap_TransportFormatSet_TransmissionTimeIntervalSemiStatic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_TransportFormatSet_ChannelCodingType_vals[] = {
  {   0, "no-codingTDD" },
  {   1, "convolutional-coding" },
  {   2, "turbo-coding" },
  { 0, NULL }
};


static int
dissect_pcap_TransportFormatSet_ChannelCodingType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_TransportFormatSet_CodingRate_vals[] = {
  {   0, "half" },
  {   1, "third" },
  { 0, NULL }
};


static int
dissect_pcap_TransportFormatSet_CodingRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_TransportFormatSet_RateMatchingAttribute(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxRateMatching, NULL, false);

  return offset;
}


static const value_string pcap_TransportFormatSet_CRC_Size_vals[] = {
  {   0, "v0" },
  {   1, "v8" },
  {   2, "v12" },
  {   3, "v16" },
  {   4, "v24" },
  { 0, NULL }
};


static int
dissect_pcap_TransportFormatSet_CRC_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TransportFormatSet_Semi_staticPart_sequence[] = {
  { &hf_pcap_transmissionTimeInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_TransmissionTimeIntervalSemiStatic },
  { &hf_pcap_channelCoding  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_ChannelCodingType },
  { &hf_pcap_codingRate     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_TransportFormatSet_CodingRate },
  { &hf_pcap_rateMatchingAttribute, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_RateMatchingAttribute },
  { &hf_pcap_cRC_Size       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_CRC_Size },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TransportFormatSet_Semi_staticPart(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TransportFormatSet_Semi_staticPart, TransportFormatSet_Semi_staticPart_sequence);

  return offset;
}


static const per_sequence_t TransportFormatSet_sequence[] = {
  { &hf_pcap_dynamicPart    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_DynamicPartList },
  { &hf_pcap_semi_staticPart, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet_Semi_staticPart },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_TransportFormatSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_TransportFormatSet, TransportFormatSet_sequence);

  return offset;
}


static const per_sequence_t UL_TrCHInfo_sequence[] = {
  { &hf_pcap_uL_TrCHtype    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UL_TrCHType },
  { &hf_pcap_tfs            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UL_TrCHInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UL_TrCHInfo, UL_TrCHInfo_sequence);

  return offset;
}


static const per_sequence_t TrChInfoList_sequence_of[1] = {
  { &hf_pcap_TrChInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_UL_TrCHInfo },
};

static int
dissect_pcap_TrChInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_TrChInfoList, TrChInfoList_sequence_of,
                                                  1, maxTrCH, false);

  return offset;
}


static const per_sequence_t DCH_Information_sequence[] = {
  { &hf_pcap_tFCS           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TFCS },
  { &hf_pcap_trChInfo       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TrChInfoList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_DCH_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_DCH_Information, DCH_Information_sequence);

  return offset;
}


static const value_string pcap_Max_Set_E_DPDCHs_vals[] = {
  {   0, "vN64" },
  {   1, "vN32" },
  {   2, "vN16" },
  {   3, "vN8" },
  {   4, "v2xN4" },
  {   5, "v2xN2" },
  {   6, "v2xN2plus2xN4" },
  { 0, NULL }
};


static int
dissect_pcap_Max_Set_E_DPDCHs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_E_DCH_TFCS_Index(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4U, NULL, true);

  return offset;
}



static int
dissect_pcap_E_TFCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_pcap_Reference_E_TFCI_PO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrOfRefETFCI_PO_QUANTSTEPs, NULL, false);

  return offset;
}


static const per_sequence_t Reference_E_TFCI_Information_Item_sequence[] = {
  { &hf_pcap_reference_E_TFCI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_E_TFCI },
  { &hf_pcap_reference_E_TFCI_PO, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Reference_E_TFCI_PO },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Reference_E_TFCI_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Reference_E_TFCI_Information_Item, Reference_E_TFCI_Information_Item_sequence);

  return offset;
}


static const per_sequence_t Reference_E_TFCI_Information_sequence_of[1] = {
  { &hf_pcap_Reference_E_TFCI_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Reference_E_TFCI_Information_Item },
};

static int
dissect_pcap_Reference_E_TFCI_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_Reference_E_TFCI_Information, Reference_E_TFCI_Information_sequence_of,
                                                  1, maxNrOfRefETFCIs, false);

  return offset;
}


static const per_sequence_t E_TFCS_Information_sequence[] = {
  { &hf_pcap_e_DCH_TFCS_Index, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_E_DCH_TFCS_Index },
  { &hf_pcap_reference_E_TFCI_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Reference_E_TFCI_Information },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_E_TFCS_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_E_TFCS_Information, E_TFCS_Information_sequence);

  return offset;
}


static const value_string pcap_E_TTI_vals[] = {
  {   0, "e-TTI-2ms" },
  {   1, "e-TTI-10ms" },
  { 0, NULL }
};


static int
dissect_pcap_E_TTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_E_DPCCH_PO(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNrOfEDPCCH_PO_QUANTSTEPs, NULL, false);

  return offset;
}


static const per_sequence_t E_DPCH_Information_sequence[] = {
  { &hf_pcap_maxSet_E_DPDCHs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_Max_Set_E_DPDCHs },
  { &hf_pcap_ul_PunctureLimit, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PuncturingLimit },
  { &hf_pcap_e_TFCS_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_E_TFCS_Information },
  { &hf_pcap_e_TTI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_E_TTI },
  { &hf_pcap_e_DPCCH_PO     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_E_DPCCH_PO },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_E_DPCH_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_E_DPCH_Information, E_DPCH_Information_sequence);

  return offset;
}


static const per_sequence_t UTDOA_CELLDCH_sequence[] = {
  { &hf_pcap_uL_DPCHInfo    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UL_DPCHInfo },
  { &hf_pcap_compressedModeAssistanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_Compressed_Mode_Assistance_Data },
  { &hf_pcap_dCH_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_DCH_Information },
  { &hf_pcap_e_DPCH_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_E_DPCH_Information },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTDOA_CELLDCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTDOA_CELLDCH, UTDOA_CELLDCH_sequence);

  return offset;
}


static int * const AvailableSignatures_bits[] = {
  &hf_pcap_AvailableSignatures_signature15,
  &hf_pcap_AvailableSignatures_signature14,
  &hf_pcap_AvailableSignatures_signature13,
  &hf_pcap_AvailableSignatures_signature12,
  &hf_pcap_AvailableSignatures_signature11,
  &hf_pcap_AvailableSignatures_signature10,
  &hf_pcap_AvailableSignatures_signature9,
  &hf_pcap_AvailableSignatures_signature8,
  &hf_pcap_AvailableSignatures_signature7,
  &hf_pcap_AvailableSignatures_signature6,
  &hf_pcap_AvailableSignatures_signature5,
  &hf_pcap_AvailableSignatures_signature4,
  &hf_pcap_AvailableSignatures_signature3,
  &hf_pcap_AvailableSignatures_signature2,
  &hf_pcap_AvailableSignatures_signature1,
  &hf_pcap_AvailableSignatures_signature0,
  NULL
};

static int
dissect_pcap_AvailableSignatures(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, AvailableSignatures_bits, 16, NULL, NULL);

  return offset;
}


static const value_string pcap_SF_PRACH_vals[] = {
  {   0, "sfpr32" },
  {   1, "sfpr64" },
  {   2, "sfpr128" },
  {   3, "sfpr256" },
  { 0, NULL }
};


static int
dissect_pcap_SF_PRACH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_pcap_PreambleScramblingCodeWordNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static int * const AvailableSubChannelNumbers_bits[] = {
  &hf_pcap_AvailableSubChannelNumbers_subCh11,
  &hf_pcap_AvailableSubChannelNumbers_subCh10,
  &hf_pcap_AvailableSubChannelNumbers_subCh9,
  &hf_pcap_AvailableSubChannelNumbers_subCh8,
  &hf_pcap_AvailableSubChannelNumbers_subCh7,
  &hf_pcap_AvailableSubChannelNumbers_subCh6,
  &hf_pcap_AvailableSubChannelNumbers_subCh5,
  &hf_pcap_AvailableSubChannelNumbers_subCh4,
  &hf_pcap_AvailableSubChannelNumbers_subCh3,
  &hf_pcap_AvailableSubChannelNumbers_subCh2,
  &hf_pcap_AvailableSubChannelNumbers_subCh1,
  &hf_pcap_AvailableSubChannelNumbers_subCh0,
  NULL
};

static int
dissect_pcap_AvailableSubChannelNumbers(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     12, 12, false, AvailableSubChannelNumbers_bits, 12, NULL, NULL);

  return offset;
}


static const per_sequence_t T_fdd_05_sequence[] = {
  { &hf_pcap_availableSignatures, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AvailableSignatures },
  { &hf_pcap_availableSF    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_SF_PRACH },
  { &hf_pcap_preambleScramblingCodeWordNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PreambleScramblingCodeWordNumber },
  { &hf_pcap_puncturingLimit, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PuncturingLimit },
  { &hf_pcap_availableSubChannelNumbers, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_AvailableSubChannelNumbers },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_fdd_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_fdd_05, T_fdd_05_sequence);

  return offset;
}


static const value_string pcap_MaxPRACH_MidambleShifts_vals[] = {
  {   0, "shift4" },
  {   1, "shift8" },
  { 0, NULL }
};


static int
dissect_pcap_MaxPRACH_MidambleShifts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_PRACH_Midamble_vals[] = {
  {   0, "inverted" },
  {   1, "direct" },
  { 0, NULL }
};


static int
dissect_pcap_PRACH_Midamble(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t T_tdd_05_sequence[] = {
  { &hf_pcap_timeSlot       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TimeSlot },
  { &hf_pcap_tdd_ChannelisationCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TDD_ChannelisationCode },
  { &hf_pcap_maxPRACH_MidambleShifts, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_MaxPRACH_MidambleShifts },
  { &hf_pcap_pRACH_Midamble , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PRACH_Midamble },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_T_tdd_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_T_tdd_05, T_tdd_05_sequence);

  return offset;
}


static const value_string pcap_PRACH_Info_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t PRACH_Info_choice[] = {
  {   0, &hf_pcap_fdd_06         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_fdd_05 },
  {   1, &hf_pcap_tdd_06         , ASN1_EXTENSION_ROOT    , dissect_pcap_T_tdd_05 },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_PRACH_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_PRACH_Info, PRACH_Info_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PRACH_ChannelInfo_sequence[] = {
  { &hf_pcap_pRACH_Info     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PRACH_Info },
  { &hf_pcap_tFS            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TransportFormatSet },
  { &hf_pcap_tFCS           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TFCS },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PRACH_ChannelInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PRACH_ChannelInfo, PRACH_ChannelInfo_sequence);

  return offset;
}


static const per_sequence_t PRACHparameters_sequence_of[1] = {
  { &hf_pcap_PRACHparameters_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_PRACH_ChannelInfo },
};

static int
dissect_pcap_PRACHparameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_pcap_PRACHparameters, PRACHparameters_sequence_of,
                                                  1, maxPRACH, false);

  return offset;
}



static int
dissect_pcap_C_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_pcap_USCH_SchedulingOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t UschParameters_sequence[] = {
  { &hf_pcap_cellParameterID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_CellParameterID },
  { &hf_pcap_tFCI_Coding    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TFCI_Coding },
  { &hf_pcap_punctureLimit  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PuncturingLimit },
  { &hf_pcap_repetitionPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RepetitionPeriod },
  { &hf_pcap_uSCH_SchedulingOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_USCH_SchedulingOffset },
  { &hf_pcap_uL_Timeslot_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UL_Timeslot_Information },
  { &hf_pcap_tFCS           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TFCS },
  { &hf_pcap_trChInfo       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_TrChInfoList },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UschParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UschParameters, UschParameters_sequence);

  return offset;
}


static const per_sequence_t UTDOA_CELLFACH_sequence[] = {
  { &hf_pcap_pRACHparameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PRACHparameters },
  { &hf_pcap_cRNTI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_C_RNTI },
  { &hf_pcap_uschParameters , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UschParameters },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTDOA_CELLFACH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTDOA_CELLFACH, UTDOA_CELLFACH_sequence);

  return offset;
}


static const value_string pcap_UTDOA_RRCState_vals[] = {
  {   0, "uTDOA-CELLDCH" },
  {   1, "uTDOA-CELLFACH" },
  { 0, NULL }
};

static const per_choice_t UTDOA_RRCState_choice[] = {
  {   0, &hf_pcap_uTDOA_CELLDCH  , ASN1_EXTENSION_ROOT    , dissect_pcap_UTDOA_CELLDCH },
  {   1, &hf_pcap_uTDOA_CELLFACH , ASN1_EXTENSION_ROOT    , dissect_pcap_UTDOA_CELLFACH },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_UTDOA_RRCState(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_UTDOA_RRCState, UTDOA_RRCState_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UTDOA_Group_sequence[] = {
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_frequencyInfo  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_FrequencyInfo },
  { &hf_pcap_uTDOA_ChannelSettings, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UTDOA_RRCState },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTDOA_Group(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTDOA_Group, UTDOA_Group_sequence);

  return offset;
}


static const value_string pcap_Positioning_ResponseTime_vals[] = {
  {   0, "ms250" },
  {   1, "ms500" },
  {   2, "s1" },
  {   3, "s2" },
  {   4, "s3" },
  {   5, "s4" },
  {   6, "s6" },
  {   7, "s8" },
  {   8, "s12" },
  {   9, "s16" },
  {  10, "s20" },
  {  11, "s24" },
  {  12, "s28" },
  {  13, "s32" },
  {  14, "s64" },
  { 0, NULL }
};


static int
dissect_pcap_Positioning_ResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_AmountOfReporting_vals[] = {
  {   0, "ra2" },
  {   1, "ra4" },
  {   2, "ra8" },
  {   3, "ra16" },
  {   4, "ra32" },
  {   5, "ra64" },
  {   6, "ra-Infinity" },
  { 0, NULL }
};


static int
dissect_pcap_AmountOfReporting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string pcap_IncludeVelocity_vals[] = {
  {   0, "requested" },
  { 0, NULL }
};


static int
dissect_pcap_IncludeVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_359(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 359U, NULL, false);

  return offset;
}



static int
dissect_pcap_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, false);

  return offset;
}


static const per_sequence_t HorizontalSpeedAndBearing_sequence[] = {
  { &hf_pcap_bearing        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_359 },
  { &hf_pcap_horizontalSpeed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_HorizontalSpeedAndBearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_HorizontalSpeedAndBearing, HorizontalSpeedAndBearing_sequence);

  return offset;
}


static const per_sequence_t HorizontalVelocity_sequence[] = {
  { &hf_pcap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_HorizontalSpeedAndBearing },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_HorizontalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_HorizontalVelocity, HorizontalVelocity_sequence);

  return offset;
}


static const value_string pcap_VerticalSpeedDirection_vals[] = {
  {   0, "upward" },
  {   1, "downward" },
  { 0, NULL }
};


static int
dissect_pcap_VerticalSpeedDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t VerticalVelocity_sequence[] = {
  { &hf_pcap_verticalSpeed  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_verticalSpeedDirection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_VerticalSpeedDirection },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_VerticalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_VerticalVelocity, VerticalVelocity_sequence);

  return offset;
}


static const per_sequence_t HorizontalWithVerticalVelocity_sequence[] = {
  { &hf_pcap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_HorizontalSpeedAndBearing },
  { &hf_pcap_verticalVelocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_VerticalVelocity },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_HorizontalWithVerticalVelocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_HorizontalWithVerticalVelocity, HorizontalWithVerticalVelocity_sequence);

  return offset;
}


static const per_sequence_t HorizontalVelocityWithUncertainty_sequence[] = {
  { &hf_pcap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_HorizontalSpeedAndBearing },
  { &hf_pcap_uncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_HorizontalVelocityWithUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_HorizontalVelocityWithUncertainty, HorizontalVelocityWithUncertainty_sequence);

  return offset;
}


static const per_sequence_t HorizontalWithVerticalVelocityAndUncertainty_sequence[] = {
  { &hf_pcap_horizontalSpeedAndBearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_HorizontalSpeedAndBearing },
  { &hf_pcap_verticalVelocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_VerticalVelocity },
  { &hf_pcap_horizontalUncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_verticalUncertaintySpeed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_255 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_HorizontalWithVerticalVelocityAndUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_HorizontalWithVerticalVelocityAndUncertainty, HorizontalWithVerticalVelocityAndUncertainty_sequence);

  return offset;
}


static const value_string pcap_VelocityEstimate_vals[] = {
  {   0, "horizontalVelocity" },
  {   1, "horizontalWithVerticalVelocity" },
  {   2, "horizontalVelocityWithUncertainty" },
  {   3, "horizontalWithVerticalVelocityAndUncertainty" },
  { 0, NULL }
};

static const per_choice_t VelocityEstimate_choice[] = {
  {   0, &hf_pcap_horizontalVelocity, ASN1_EXTENSION_ROOT    , dissect_pcap_HorizontalVelocity },
  {   1, &hf_pcap_horizontalWithVerticalVelocity, ASN1_EXTENSION_ROOT    , dissect_pcap_HorizontalWithVerticalVelocity },
  {   2, &hf_pcap_horizontalVelocityWithUncertainty, ASN1_EXTENSION_ROOT    , dissect_pcap_HorizontalVelocityWithUncertainty },
  {   3, &hf_pcap_horizontalWithVerticalVelocityAndUncertainty, ASN1_EXTENSION_ROOT    , dissect_pcap_HorizontalWithVerticalVelocityAndUncertainty },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_VelocityEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_VelocityEstimate, VelocityEstimate_choice,
                                 NULL);

  return offset;
}



static int
dissect_pcap_INTEGER_0_2322431999999_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(2322431999999), NULL, true);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTime_sequence[] = {
  { &hf_pcap_utran_GPSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_2322431999999_ },
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_UC_ID },
  { &hf_pcap_sfn            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTRAN_GPSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTRAN_GPSReferenceTime, UTRAN_GPSReferenceTime_sequence);

  return offset;
}



static int
dissect_pcap_INTEGER_0_345599999999_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(345599999999), NULL, true);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTimeResult_sequence[] = {
  { &hf_pcap_ue_GANSSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_345599999999_ },
  { &hf_pcap_ganss_Time_ID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_GANSSID },
  { &hf_pcap_ganssTodUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_INTEGER_0_127 },
  { &hf_pcap_uC_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_sfn            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_INTEGER_0_4095 },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UTRAN_GANSSReferenceTimeResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UTRAN_GANSSReferenceTimeResult, UTRAN_GANSSReferenceTimeResult_sequence);

  return offset;
}


static const per_sequence_t PositionCalculationRequest_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionCalculationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionCalculationRequest, PositionCalculationRequest_sequence);

  return offset;
}


static const per_sequence_t PositionCalculationResponse_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionCalculationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionCalculationResponse, PositionCalculationResponse_sequence);

  return offset;
}


static const per_sequence_t PositionCalculationFailure_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionCalculationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionCalculationFailure, PositionCalculationFailure_sequence);

  return offset;
}


static const per_sequence_t InformationExchangeInitiationRequest_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationExchangeInitiationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationExchangeInitiationRequest, InformationExchangeInitiationRequest_sequence);

  return offset;
}


static const per_sequence_t RefPosition_InfEx_Rqst_sequence[] = {
  { &hf_pcap_referencePositionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UE_PositionEstimate },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RefPosition_InfEx_Rqst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RefPosition_InfEx_Rqst, RefPosition_InfEx_Rqst_sequence);

  return offset;
}



static int
dissect_pcap_Extension_InformationExchangeObjectType_InfEx_Rqst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pcap_ProtocolIE_Single_Container(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string pcap_InformationExchangeObjectType_InfEx_Rqst_vals[] = {
  {   0, "referencePosition" },
  {   1, "extension-InformationExchangeObjectType-InfEx-Rqst" },
  { 0, NULL }
};

static const per_choice_t InformationExchangeObjectType_InfEx_Rqst_choice[] = {
  {   0, &hf_pcap_referencePosition, ASN1_EXTENSION_ROOT    , dissect_pcap_RefPosition_InfEx_Rqst },
  {   1, &hf_pcap_extension_InformationExchangeObjectType_InfEx_Rqst, ASN1_NOT_EXTENSION_ROOT, dissect_pcap_Extension_InformationExchangeObjectType_InfEx_Rqst },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_InformationExchangeObjectType_InfEx_Rqst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_InformationExchangeObjectType_InfEx_Rqst, InformationExchangeObjectType_InfEx_Rqst_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UC_ID_InfEx_Rqst_sequence[] = {
  { &hf_pcap_referenceUC_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_UC_ID },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UC_ID_InfEx_Rqst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UC_ID_InfEx_Rqst, UC_ID_InfEx_Rqst_sequence);

  return offset;
}


static const per_sequence_t InformationExchangeInitiationResponse_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationExchangeInitiationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationExchangeInitiationResponse, InformationExchangeInitiationResponse_sequence);

  return offset;
}


static const per_sequence_t RefPosition_InfEx_Rsp_sequence[] = {
  { &hf_pcap_requestedDataValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RequestedDataValue },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RefPosition_InfEx_Rsp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RefPosition_InfEx_Rsp, RefPosition_InfEx_Rsp_sequence);

  return offset;
}


static const value_string pcap_InformationExchangeObjectType_InfEx_Rsp_vals[] = {
  {   0, "referencePosition" },
  { 0, NULL }
};

static const per_choice_t InformationExchangeObjectType_InfEx_Rsp_choice[] = {
  {   0, &hf_pcap_referencePosition_01, ASN1_EXTENSION_ROOT    , dissect_pcap_RefPosition_InfEx_Rsp },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_InformationExchangeObjectType_InfEx_Rsp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_InformationExchangeObjectType_InfEx_Rsp, InformationExchangeObjectType_InfEx_Rsp_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InformationExchangeInitiationFailure_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationExchangeInitiationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationExchangeInitiationFailure, InformationExchangeInitiationFailure_sequence);

  return offset;
}


static const per_sequence_t PositionInitiationRequest_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionInitiationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionInitiationRequest, PositionInitiationRequest_sequence);

  return offset;
}


static const per_sequence_t PositionInitiationResponse_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionInitiationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionInitiationResponse, PositionInitiationResponse_sequence);

  return offset;
}


static const per_sequence_t PositionInitiationFailure_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionInitiationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionInitiationFailure, PositionInitiationFailure_sequence);

  return offset;
}


static const per_sequence_t PositionActivationRequest_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionActivationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionActivationRequest, PositionActivationRequest_sequence);

  return offset;
}


static const per_sequence_t PositionActivationResponse_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionActivationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionActivationResponse, PositionActivationResponse_sequence);

  return offset;
}


static const per_sequence_t PositionActivationFailure_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionActivationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionActivationFailure, PositionActivationFailure_sequence);

  return offset;
}


static const per_sequence_t InformationReport_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationReport, InformationReport_sequence);

  return offset;
}


static const per_sequence_t RefPosition_InfEx_Rprt_sequence[] = {
  { &hf_pcap_requestedDataValueInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_RequestedDataValueInformation },
  { &hf_pcap_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_RefPosition_InfEx_Rprt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_RefPosition_InfEx_Rprt, RefPosition_InfEx_Rprt_sequence);

  return offset;
}


static const value_string pcap_InformationExchangeObjectType_InfEx_Rprt_vals[] = {
  {   0, "referencePosition" },
  { 0, NULL }
};

static const per_choice_t InformationExchangeObjectType_InfEx_Rprt_choice[] = {
  {   0, &hf_pcap_referencePosition_02, ASN1_EXTENSION_ROOT    , dissect_pcap_RefPosition_InfEx_Rprt },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_InformationExchangeObjectType_InfEx_Rprt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_InformationExchangeObjectType_InfEx_Rprt, InformationExchangeObjectType_InfEx_Rprt_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InformationExchangeTerminationRequest_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationExchangeTerminationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationExchangeTerminationRequest, InformationExchangeTerminationRequest_sequence);

  return offset;
}


static const per_sequence_t InformationExchangeFailureIndication_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InformationExchangeFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InformationExchangeFailureIndication, InformationExchangeFailureIndication_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t PositionParameterModification_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionParameterModification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionParameterModification, PositionParameterModification_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_pcap_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t Abort_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Abort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Abort, Abort_sequence);

  return offset;
}


static const per_sequence_t PositionPeriodicReport_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionPeriodicReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionPeriodicReport, PositionPeriodicReport_sequence);

  return offset;
}


static const per_sequence_t PositionPeriodicResult_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionPeriodicResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionPeriodicResult, PositionPeriodicResult_sequence);

  return offset;
}


static const per_sequence_t PositionPeriodicTermination_sequence[] = {
  { &hf_pcap_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pcap_ProtocolIE_Container },
  { &hf_pcap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pcap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_PositionPeriodicTermination(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_PositionPeriodicTermination, PositionPeriodicTermination_sequence);

  return offset;
}



static int
dissect_pcap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_pcap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProcedureCode },
  { &hf_pcap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_transactionID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_TransactionID },
  { &hf_pcap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_pcap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_pcap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProcedureCode },
  { &hf_pcap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_transactionID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_TransactionID },
  { &hf_pcap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_pcap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_pcap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProcedureCode },
  { &hf_pcap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_transactionID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_TransactionID },
  { &hf_pcap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_pcap_Outcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_OutcomeValue);

  return offset;
}


static const per_sequence_t Outcome_sequence[] = {
  { &hf_pcap_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_ProcedureCode },
  { &hf_pcap_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Criticality },
  { &hf_pcap_transactionID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_TransactionID },
  { &hf_pcap_outcome_value  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pcap_Outcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_pcap_Outcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_pcap_Outcome, Outcome_sequence);

  return offset;
}


static const value_string pcap_PCAP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  {   3, "outcome" },
  { 0, NULL }
};

static const per_choice_t PCAP_PDU_choice[] = {
  {   0, &hf_pcap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_pcap_InitiatingMessage },
  {   1, &hf_pcap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_pcap_SuccessfulOutcome },
  {   2, &hf_pcap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_pcap_UnsuccessfulOutcome },
  {   3, &hf_pcap_outcome        , ASN1_EXTENSION_ROOT    , dissect_pcap_Outcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_pcap_PCAP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_pcap_PCAP_PDU, PCAP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AccuracyFulfilmentIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AccuracyFulfilmentIndicator(tvb, offset, &asn1_ctx, tree, hf_pcap_AccuracyFulfilmentIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AddPos_MeasuredResults_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AddPos_MeasuredResults(tvb, offset, &asn1_ctx, tree, hf_pcap_AddPos_MeasuredResults_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_Cause(tvb, offset, &asn1_ctx, tree, hf_pcap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellId_MeasuredResultsSets_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_CellId_MeasuredResultsSets(tvb, offset, &asn1_ctx, tree, hf_pcap_CellId_MeasuredResultsSets_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RoundTripTimeInfoWithType1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_RoundTripTimeInfoWithType1(tvb, offset, &asn1_ctx, tree, hf_pcap_RoundTripTimeInfoWithType1_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedTimingAdvanceLCR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_ExtendedTimingAdvanceLCR(tvb, offset, &asn1_ctx, tree, hf_pcap_ExtendedTimingAdvanceLCR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RxTimingDeviation768Info_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_RxTimingDeviation768Info(tvb, offset, &asn1_ctx, tree, hf_pcap_RxTimingDeviation768Info_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RxTimingDeviation384extInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_RxTimingDeviation384extInfo(tvb, offset, &asn1_ctx, tree, hf_pcap_RxTimingDeviation384extInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AddMeasurementInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AddMeasurementInfo(tvb, offset, &asn1_ctx, tree, hf_pcap_AddMeasurementInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AngleOfArrivalLCR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AngleOfArrivalLCR(tvb, offset, &asn1_ctx, tree, hf_pcap_AngleOfArrivalLCR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellId_IRATMeasuredResultsSets_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_CellId_IRATMeasuredResultsSets(tvb, offset, &asn1_ctx, tree, hf_pcap_CellId_IRATMeasuredResultsSets_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellIDPositioning_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_CellIDPositioning(tvb, offset, &asn1_ctx, tree, hf_pcap_CellIDPositioning_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedCellIDGERANMeasurements_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_RequestedCellIDGERANMeasurements(tvb, offset, &asn1_ctx, tree, hf_pcap_RequestedCellIDGERANMeasurements_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ClientType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_ClientType(tvb, offset, &asn1_ctx, tree, hf_pcap_ClientType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_pcap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DGNSS_ValidityPeriod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_DGNSS_ValidityPeriod(tvb, offset, &asn1_ctx, tree, hf_pcap_DGNSS_ValidityPeriod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMEI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_IMEI(tvb, offset, &asn1_ctx, tree, hf_pcap_IMEI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMSI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_IMSI(tvb, offset, &asn1_ctx, tree, hf_pcap_IMSI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_PositionEstimate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UE_PositionEstimate(tvb, offset, &asn1_ctx, tree, hf_pcap_UE_PositionEstimate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_PositionEstimateInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UE_PositionEstimateInfo(tvb, offset, &asn1_ctx, tree, hf_pcap_UE_PositionEstimateInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Reference_Time_Only_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Reference_Time_Only(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Reference_Time_Only_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionDataUEbased_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionDataUEbased(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionDataUEbased_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionData(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_PositioningDataSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_PositioningDataSet(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_PositioningDataSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Additional_PositioningDataSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_Additional_PositioningDataSet(tvb, offset, &asn1_ctx, tree, hf_pcap_Additional_PositioningDataSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtraDopplerInfoExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_ExtraDopplerInfoExtension(tvb, offset, &asn1_ctx, tree, hf_pcap_ExtraDopplerInfoExtension_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AzimuthAndElevationLSB_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AzimuthAndElevationLSB(tvb, offset, &asn1_ctx, tree, hf_pcap_AzimuthAndElevationLSB_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Confidence_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_Confidence(tvb, offset, &asn1_ctx, tree, hf_pcap_Confidence_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Additional_Ionospheric_Model_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Additional_Ionospheric_Model(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Additional_Ionospheric_Model_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Additional_Navigation_Models_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Additional_Navigation_Models(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Additional_Navigation_Models_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Additional_Time_Models_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Additional_Time_Models(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Additional_Time_Models_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Additional_UTC_Models_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Additional_UTC_Models(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Additional_UTC_Models_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_ALM_BDSKeplericanset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_ALM_BDSKeplericanset(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_ALM_BDSKeplericanset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_ALM_ECEFsbasAlmanacSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_ALM_ECEFsbasAlmanacSet(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_ALM_ECEFsbasAlmanacSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_ALM_GlonassAlmanacSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_ALM_GlonassAlmanacSet(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_ALM_GlonassAlmanacSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_ALM_MidiAlmanacSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_ALM_MidiAlmanacSet(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_ALM_MidiAlmanacSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_ALM_NAVKeplerianSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_ALM_NAVKeplerianSet(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_ALM_NAVKeplerianSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_ALM_ReducedKeplerianSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_ALM_ReducedKeplerianSet(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_ALM_ReducedKeplerianSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Auxiliary_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Auxiliary_Information(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Auxiliary_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_CommonAssistanceData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_CommonAssistanceData(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_CommonAssistanceData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Earth_Orientation_Parameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Earth_Orientation_Parameters(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Earth_Orientation_Parameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_ExtraDopplerExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_ExtraDopplerExtension(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_ExtraDopplerExtension_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_GenericAssistanceDataList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_GenericAssistanceDataList(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_GenericAssistanceDataList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BDS_Ionospheric_Grid_Model_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_BDS_Ionospheric_Grid_Model(tvb, offset, &asn1_ctx, tree, hf_pcap_BDS_Ionospheric_Grid_Model_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DBDS_Correction_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_DBDS_Correction_Information(tvb, offset, &asn1_ctx, tree, hf_pcap_DBDS_Correction_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GanssCodePhaseAmbiguityExt_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GanssCodePhaseAmbiguityExt(tvb, offset, &asn1_ctx, tree, hf_pcap_GanssCodePhaseAmbiguityExt_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GanssIntegerCodePhaseExt_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GanssIntegerCodePhaseExt(tvb, offset, &asn1_ctx, tree, hf_pcap_GanssIntegerCodePhaseExt_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_MeasuredResultsList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_MeasuredResultsList(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_MeasuredResultsList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Day_Cycle_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Day_Cycle(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Day_Cycle_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Delta_T_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Delta_T(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Delta_T_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_UTRAN_TRU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_UTRAN_TRU(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_UTRAN_TRU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CompleteAlmanacProvided_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_CompleteAlmanacProvided(tvb, offset, &asn1_ctx, tree, hf_pcap_CompleteAlmanacProvided_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasuredResultsList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_MeasuredResultsList(tvb, offset, &asn1_ctx, tree, hf_pcap_MeasuredResultsList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GPS_ReferenceLocation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GPS_ReferenceLocation(tvb, offset, &asn1_ctx, tree, hf_pcap_GPS_ReferenceLocation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GPS_Week_Cycle_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GPS_Week_Cycle(tvb, offset, &asn1_ctx, tree, hf_pcap_GPS_Week_Cycle_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTRAN_GPS_DriftRate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UTRAN_GPS_DriftRate(tvb, offset, &asn1_ctx, tree, hf_pcap_UTRAN_GPS_DriftRate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GPSReferenceTimeUncertainty_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GPSReferenceTimeUncertainty(tvb, offset, &asn1_ctx, tree, hf_pcap_GPSReferenceTimeUncertainty_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GPS_UTRAN_TRU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GPS_UTRAN_TRU(tvb, offset, &asn1_ctx, tree, hf_pcap_GPS_UTRAN_TRU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AdditionalGPSAssistDataRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AdditionalGPSAssistDataRequired(tvb, offset, &asn1_ctx, tree, hf_pcap_AdditionalGPSAssistDataRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AdditionalGanssAssistDataRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AdditionalGanssAssistDataRequired(tvb, offset, &asn1_ctx, tree, hf_pcap_AdditionalGanssAssistDataRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSSReq_AddIonosphericModel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSSReq_AddIonosphericModel(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSSReq_AddIonosphericModel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSSReq_EarthOrientPara_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSSReq_EarthOrientPara(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSSReq_EarthOrientPara_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BDSIonosphericGridModel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_BDSIonosphericGridModel(tvb, offset, &asn1_ctx, tree, hf_pcap_BDSIonosphericGridModel_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DBDSCorrection_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_DBDSCorrection(tvb, offset, &asn1_ctx, tree, hf_pcap_DBDSCorrection_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_AddNavigationModel_Req_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_AddNavigationModel_Req(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_AddNavigationModel_Req_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_AddUTCModel_Req_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_AddUTCModel_Req(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_AddUTCModel_Req_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_AuxInfo_req_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_AuxInfo_req(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_AuxInfo_req_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_AddADchoices_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_AddADchoices(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_AddADchoices_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeID(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationReportCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationReportCharacteristics(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationReportCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationType(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_AddIonoModelReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_AddIonoModelReq(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_AddIonoModelReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_EarthOrientParaReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_EarthOrientParaReq(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_EarthOrientParaReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_SBAS_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_SBAS_ID(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_SBAS_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasInstructionsUsed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_MeasInstructionsUsed(tvb, offset, &asn1_ctx, tree, hf_pcap_MeasInstructionsUsed_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_MeasurementGroup_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_OTDOA_MeasurementGroup(tvb, offset, &asn1_ctx, tree, hf_pcap_OTDOA_MeasurementGroup_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_ReferenceCellInfoSAS_centric_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_OTDOA_ReferenceCellInfoSAS_centric(tvb, offset, &asn1_ctx, tree, hf_pcap_OTDOA_ReferenceCellInfoSAS_centric_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_MeasuredResultsSets_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_OTDOA_MeasuredResultsSets(tvb, offset, &asn1_ctx, tree, hf_pcap_OTDOA_MeasuredResultsSets_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_AddMeasuredResultsInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_OTDOA_AddMeasuredResultsInfo(tvb, offset, &asn1_ctx, tree, hf_pcap_OTDOA_AddMeasuredResultsInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UC_ID(tvb, offset, &asn1_ctx, tree, hf_pcap_UC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Extended_RNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_Extended_RNC_ID(tvb, offset, &asn1_ctx, tree, hf_pcap_Extended_RNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AdditionalMeasurementInforLCR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AdditionalMeasurementInforLCR(tvb, offset, &asn1_ctx, tree, hf_pcap_AdditionalMeasurementInforLCR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PeriodicPosCalcInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PeriodicPosCalcInfo(tvb, offset, &asn1_ctx, tree, hf_pcap_PeriodicPosCalcInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PeriodicLocationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PeriodicLocationInfo(tvb, offset, &asn1_ctx, tree, hf_pcap_PeriodicLocationInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PeriodicTerminationCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PeriodicTerminationCause(tvb, offset, &asn1_ctx, tree, hf_pcap_PeriodicTerminationCause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningMethod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositioningMethod(tvb, offset, &asn1_ctx, tree, hf_pcap_PositioningMethod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GNSS_PositioningMethod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GNSS_PositioningMethod(tvb, offset, &asn1_ctx, tree, hf_pcap_GNSS_PositioningMethod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Additional_PositioningMethod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_Additional_PositioningMethod(tvb, offset, &asn1_ctx, tree, hf_pcap_Additional_PositioningMethod_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningPriority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositioningPriority(tvb, offset, &asn1_ctx, tree, hf_pcap_PositioningPriority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RRCstateChange_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_RRCstateChange(tvb, offset, &asn1_ctx, tree, hf_pcap_RRCstateChange_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_RequestType(tvb, offset, &asn1_ctx, tree, hf_pcap_RequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResponseTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_ResponseTime(tvb, offset, &asn1_ctx, tree, hf_pcap_ResponseTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HorizontalAccuracyCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_HorizontalAccuracyCode(tvb, offset, &asn1_ctx, tree, hf_pcap_HorizontalAccuracyCode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_PositioningCapability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UE_PositioningCapability(tvb, offset, &asn1_ctx, tree, hf_pcap_UE_PositioningCapability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NetworkAssistedGANSSSupport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_NetworkAssistedGANSSSupport(tvb, offset, &asn1_ctx, tree, hf_pcap_NetworkAssistedGANSSSupport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AddPosSupport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AddPosSupport(tvb, offset, &asn1_ctx, tree, hf_pcap_AddPosSupport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_SBAS_IDs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_SBAS_IDs(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_SBAS_IDs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSS_Signal_IDs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSS_Signal_IDs(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSS_Signal_IDs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SupportGANSSNonNativeADchoices_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_SupportGANSSNonNativeADchoices(tvb, offset, &asn1_ctx, tree, hf_pcap_SupportGANSSNonNativeADchoices_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTDOAPositioning_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UTDOAPositioning(tvb, offset, &asn1_ctx, tree, hf_pcap_UTDOAPositioning_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_EnvironmentCharacterisation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_EnvironmentCharacterisation(tvb, offset, &asn1_ctx, tree, hf_pcap_EnvironmentCharacterisation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GPSPositioning_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GPSPositioning(tvb, offset, &asn1_ctx, tree, hf_pcap_GPSPositioning_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSSPositioning_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSSPositioning(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSSPositioning_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSScarrierPhaseRequested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSScarrierPhaseRequested(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSScarrierPhaseRequested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GANSSMultiFreqMeasRequested_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_GANSSMultiFreqMeasRequested(tvb, offset, &asn1_ctx, tree, hf_pcap_GANSSMultiFreqMeasRequested_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAAssistanceData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_OTDOAAssistanceData(tvb, offset, &asn1_ctx, tree, hf_pcap_OTDOAAssistanceData_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VerticalAccuracyCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_VerticalAccuracyCode(tvb, offset, &asn1_ctx, tree, hf_pcap_VerticalAccuracyCode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTDOA_Group_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UTDOA_Group(tvb, offset, &asn1_ctx, tree, hf_pcap_UTDOA_Group_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Positioning_ResponseTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_Positioning_ResponseTime(tvb, offset, &asn1_ctx, tree, hf_pcap_Positioning_ResponseTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AmountOfReporting_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_AmountOfReporting(tvb, offset, &asn1_ctx, tree, hf_pcap_AmountOfReporting_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IncludeVelocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_IncludeVelocity(tvb, offset, &asn1_ctx, tree, hf_pcap_IncludeVelocity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_VelocityEstimate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_VelocityEstimate(tvb, offset, &asn1_ctx, tree, hf_pcap_VelocityEstimate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTRAN_GPSReferenceTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UTRAN_GPSReferenceTime(tvb, offset, &asn1_ctx, tree, hf_pcap_UTRAN_GPSReferenceTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTRAN_GANSSReferenceTimeResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UTRAN_GANSSReferenceTimeResult(tvb, offset, &asn1_ctx, tree, hf_pcap_UTRAN_GANSSReferenceTimeResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionCalculationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionCalculationRequest(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionCalculationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionCalculationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionCalculationResponse(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionCalculationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionCalculationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionCalculationFailure(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionCalculationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeInitiationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeInitiationRequest(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeInitiationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeObjectType_InfEx_Rqst_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeObjectType_InfEx_Rqst(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeObjectType_InfEx_Rqst_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UC_ID_InfEx_Rqst_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_UC_ID_InfEx_Rqst(tvb, offset, &asn1_ctx, tree, hf_pcap_UC_ID_InfEx_Rqst_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeInitiationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeInitiationResponse(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeInitiationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeObjectType_InfEx_Rsp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeObjectType_InfEx_Rsp(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeObjectType_InfEx_Rsp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeInitiationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeInitiationFailure(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeInitiationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionInitiationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionInitiationRequest(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionInitiationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionInitiationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionInitiationResponse(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionInitiationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionInitiationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionInitiationFailure(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionInitiationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionActivationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionActivationRequest(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionActivationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionActivationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionActivationResponse(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionActivationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionActivationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionActivationFailure(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionActivationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationReport(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeObjectType_InfEx_Rprt_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeObjectType_InfEx_Rprt(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeObjectType_InfEx_Rprt_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeTerminationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeTerminationRequest(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeTerminationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InformationExchangeFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_InformationExchangeFailureIndication(tvb, offset, &asn1_ctx, tree, hf_pcap_InformationExchangeFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_pcap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionParameterModification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionParameterModification(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionParameterModification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_pcap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Abort_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_Abort(tvb, offset, &asn1_ctx, tree, hf_pcap_Abort_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionPeriodicReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionPeriodicReport(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionPeriodicReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionPeriodicResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionPeriodicResult(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionPeriodicResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositionPeriodicTermination_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PositionPeriodicTermination(tvb, offset, &asn1_ctx, tree, hf_pcap_PositionPeriodicTermination_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PCAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_pcap_PCAP_PDU(tvb, offset, &asn1_ctx, tree, hf_pcap_PCAP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(pcap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(pcap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(pcap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(pcap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(pcap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_OutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(pcap_proc_out_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int
dissect_pcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item	*pcap_item = NULL;
	proto_tree	*pcap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCAP");

	/* create the pcap protocol tree */
	pcap_item = proto_tree_add_item(tree, proto_pcap, tvb, 0, -1, ENC_NA);
	pcap_tree = proto_item_add_subtree(pcap_item, ett_pcap);

	dissect_PCAP_PDU_PDU(tvb, pinfo, pcap_tree, NULL);
	return tvb_captured_length(tvb);
}

/*--- proto_reg_handoff_pcap ---------------------------------------*/
void
proto_reg_handoff_pcap(void)
{
  dissector_add_uint("pcap.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GPS_UTRAN_TRU, create_dissector_handle(dissect_GPS_UTRAN_TRU_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_InformationExchangeID, create_dissector_handle(dissect_InformationExchangeID_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_InformationExchangeObjectType_InfEx_Rprt, create_dissector_handle(dissect_InformationExchangeObjectType_InfEx_Rprt_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_InformationExchangeObjectType_InfEx_Rqst, create_dissector_handle(dissect_InformationExchangeObjectType_InfEx_Rqst_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_InformationExchangeObjectType_InfEx_Rsp, create_dissector_handle(dissect_InformationExchangeObjectType_InfEx_Rsp_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_InformationReportCharacteristics, create_dissector_handle(dissect_InformationReportCharacteristics_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_InformationType, create_dissector_handle(dissect_InformationType_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GPS_MeasuredResultsList, create_dissector_handle(dissect_MeasuredResultsList_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UE_PositionEstimate, create_dissector_handle(dissect_UE_PositionEstimate_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_CellId_MeasuredResultsSets, create_dissector_handle(dissect_CellId_MeasuredResultsSets_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_OTDOA_MeasurementGroup, create_dissector_handle(dissect_OTDOA_MeasurementGroup_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_AccuracyFulfilmentIndicator, create_dissector_handle(dissect_AccuracyFulfilmentIndicator_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_HorizontalAccuracyCode, create_dissector_handle(dissect_HorizontalAccuracyCode_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_VerticalAccuracyCode, create_dissector_handle(dissect_VerticalAccuracyCode_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UTDOA_Group, create_dissector_handle(dissect_UTDOA_Group_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_RequestType, create_dissector_handle(dissect_RequestType_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UE_PositioningCapability, create_dissector_handle(dissect_UE_PositioningCapability_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UC_id, create_dissector_handle(dissect_UC_ID_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_ResponseTime, create_dissector_handle(dissect_ResponseTime_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_PositioningPriority, create_dissector_handle(dissect_PositioningPriority_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_ClientType, create_dissector_handle(dissect_ClientType_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_PositioningMethod, create_dissector_handle(dissect_PositioningMethod_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UTDOAPositioning, create_dissector_handle(dissect_UTDOAPositioning_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GPSPositioning, create_dissector_handle(dissect_GPSPositioning_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_OTDOAAssistanceData, create_dissector_handle(dissect_OTDOAAssistanceData_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_Positioning_ResponseTime, create_dissector_handle(dissect_Positioning_ResponseTime_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_EnvironmentCharacterisation, create_dissector_handle(dissect_EnvironmentCharacterisation_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_PositionData, create_dissector_handle(dissect_PositionData_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_VelocityEstimate, create_dissector_handle(dissect_VelocityEstimate_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UC_ID_InfEx_Rqst, create_dissector_handle(dissect_UC_ID_InfEx_Rqst_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UE_PositionEstimateInfo, create_dissector_handle(dissect_UE_PositionEstimateInfo_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_OTDOA_MeasuredResultsSets, create_dissector_handle(dissect_OTDOA_MeasuredResultsSets_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_PeriodicPosCalcInfo, create_dissector_handle(dissect_PeriodicPosCalcInfo_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_PeriodicTerminationCause, create_dissector_handle(dissect_PeriodicTerminationCause_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GANSS_alm_keplerianBDSAlmanac, create_dissector_handle(dissect_GANSS_ALM_BDSKeplericanset_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_CellId_MeasuredResultsSets, create_dissector_handle(dissect_CellId_MeasuredResultsSets_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_OTDOA_MeasurementGroup, create_dissector_handle(dissect_OTDOA_MeasurementGroup_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_HorizontalAccuracyCode, create_dissector_handle(dissect_HorizontalAccuracyCode_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_VerticalAccuracyCode, create_dissector_handle(dissect_VerticalAccuracyCode_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_UTDOA_Group, create_dissector_handle(dissect_UTDOA_Group_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_Positioning_ResponseTime, create_dissector_handle(dissect_Positioning_ResponseTime_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_IncludeVelocity, create_dissector_handle(dissect_IncludeVelocity_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_PeriodicPosCalcInfo, create_dissector_handle(dissect_PeriodicPosCalcInfo_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_AmountOfReporting, create_dissector_handle(dissect_AmountOfReporting_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_PeriodicLocationInfo, create_dissector_handle(dissect_PeriodicLocationInfo_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_MeasInstructionsUsed, create_dissector_handle(dissect_MeasInstructionsUsed_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_CellIDPositioning, create_dissector_handle(dissect_CellIDPositioning_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSSPositioning, create_dissector_handle(dissect_GANSSPositioning_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_RRCstateChange, create_dissector_handle(dissect_RRCstateChange_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_MeasuredResultsList, create_dissector_handle(dissect_GANSS_MeasuredResultsList_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_UTRAN_TRU, create_dissector_handle(dissect_GANSS_UTRAN_TRU_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_AdditionalGPSAssistDataRequired, create_dissector_handle(dissect_AdditionalGPSAssistDataRequired_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_AdditionalGanssAssistDataRequired, create_dissector_handle(dissect_AdditionalGanssAssistDataRequired_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_rxTimingDeviation768Info, create_dissector_handle(dissect_RxTimingDeviation768Info_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_rxTimingDeviation384extInfo, create_dissector_handle(dissect_RxTimingDeviation384extInfo_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_roundTripTimeInfoWithType1, create_dissector_handle(dissect_RoundTripTimeInfoWithType1_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_AddMeasurementInfo, create_dissector_handle(dissect_AddMeasurementInfo_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_angleOfArrivalLCR, create_dissector_handle(dissect_AngleOfArrivalLCR_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_extendedTimingAdvanceLCR, create_dissector_handle(dissect_ExtendedTimingAdvanceLCR_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_PositioningDataSet, create_dissector_handle(dissect_GANSS_PositioningDataSet_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_CommonAssistanceData, create_dissector_handle(dissect_GANSS_CommonAssistanceData_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_GenericAssistanceDataList, create_dissector_handle(dissect_GANSS_GenericAssistanceDataList_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GPS_ReferenceLocation, create_dissector_handle(dissect_GPS_ReferenceLocation_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_UTRAN_GPS_DriftRate, create_dissector_handle(dissect_UTRAN_GPS_DriftRate_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GPSReferenceTimeUncertainty, create_dissector_handle(dissect_GPSReferenceTimeUncertainty_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_OTDOA_AddMeasuredResultsInfo, create_dissector_handle(dissect_OTDOA_AddMeasuredResultsInfo_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_Extended_RNC_ID, create_dissector_handle(dissect_Extended_RNC_ID_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_additionalMeasurementInforLCR, create_dissector_handle(dissect_AdditionalMeasurementInforLCR_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GNSS_PositioningMethod, create_dissector_handle(dissect_GNSS_PositioningMethod_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_NetworkAssistedGANSSSuport, create_dissector_handle(dissect_NetworkAssistedGANSSSupport_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_UTRAN_GPSReferenceTime, create_dissector_handle(dissect_UTRAN_GPSReferenceTime_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_AddIonoModelReq, create_dissector_handle(dissect_GANSS_AddIonoModelReq_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_EarthOrientParaReq, create_dissector_handle(dissect_GANSS_EarthOrientParaReq_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Additional_Ionospheric_Model, create_dissector_handle(dissect_GANSS_Additional_Ionospheric_Model_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Earth_Orientation_Parameters, create_dissector_handle(dissect_GANSS_Earth_Orientation_Parameters_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Additional_Time_Models, create_dissector_handle(dissect_GANSS_Additional_Time_Models_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Additional_Navigation_Models, create_dissector_handle(dissect_GANSS_Additional_Navigation_Models_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Additional_UTC_Models, create_dissector_handle(dissect_GANSS_Additional_UTC_Models_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Auxiliary_Information, create_dissector_handle(dissect_GANSS_Auxiliary_Information_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_SBAS_ID, create_dissector_handle(dissect_GANSS_SBAS_ID_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_SBAS_IDs, create_dissector_handle(dissect_GANSS_SBAS_IDs_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Signal_IDs, create_dissector_handle(dissect_GANSS_Signal_IDs_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GANSS_alm_keplerianNAVAlmanac, create_dissector_handle(dissect_GANSS_ALM_NAVKeplerianSet_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GANSS_alm_keplerianReducedAlmanac, create_dissector_handle(dissect_GANSS_ALM_ReducedKeplerianSet_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GANSS_alm_keplerianMidiAlmanac, create_dissector_handle(dissect_GANSS_ALM_MidiAlmanacSet_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GANSS_alm_keplerianGLONASS, create_dissector_handle(dissect_GANSS_ALM_GlonassAlmanacSet_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GANSS_alm_ecefSBASAlmanac, create_dissector_handle(dissect_GANSS_ALM_ECEFsbasAlmanacSet_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_UTRAN_GANSSReferenceTimeResult, create_dissector_handle(dissect_UTRAN_GANSSReferenceTimeResult_PDU, proto_pcap));
  dissector_add_uint("pcap.ies", id_GANSS_Reference_Time_Only, create_dissector_handle(dissect_GANSS_Reference_Time_Only_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_AddADchoices, create_dissector_handle(dissect_GANSS_AddADchoices_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_supportGANSSNonNativeADchoices, create_dissector_handle(dissect_SupportGANSSNonNativeADchoices_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_PositionDataUEbased, create_dissector_handle(dissect_PositionDataUEbased_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganssCodePhaseAmbiguityExt, create_dissector_handle(dissect_GanssCodePhaseAmbiguityExt_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganssIntegerCodePhaseExt, create_dissector_handle(dissect_GanssIntegerCodePhaseExt_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSScarrierPhaseRequested, create_dissector_handle(dissect_GANSScarrierPhaseRequested_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSSMultiFreqMeasRequested, create_dissector_handle(dissect_GANSSMultiFreqMeasRequested_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganssReq_AddIonosphericModel, create_dissector_handle(dissect_GANSSReq_AddIonosphericModel_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganssReq_EarthOrientPara, create_dissector_handle(dissect_GANSSReq_EarthOrientPara_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganssAddNavigationModel_req, create_dissector_handle(dissect_GANSS_AddNavigationModel_Req_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganssAddUTCModel_req, create_dissector_handle(dissect_GANSS_AddUTCModel_Req_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganssAuxInfo_req, create_dissector_handle(dissect_GANSS_AuxInfo_req_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_OTDOA_ReferenceCellInfo, create_dissector_handle(dissect_OTDOA_ReferenceCellInfoSAS_centric_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_DGNSS_ValidityPeriod, create_dissector_handle(dissect_DGNSS_ValidityPeriod_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_AzimuthAndElevationLSB, create_dissector_handle(dissect_AzimuthAndElevationLSB_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_completeAlmanacProvided, create_dissector_handle(dissect_CompleteAlmanacProvided_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GPS_Week_Cycle, create_dissector_handle(dissect_GPS_Week_Cycle_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Day_Cycle, create_dissector_handle(dissect_GANSS_Day_Cycle_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ganss_Delta_T, create_dissector_handle(dissect_GANSS_Delta_T_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_requestedCellIDGERANMeasurements, create_dissector_handle(dissect_RequestedCellIDGERANMeasurements_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_CellId_IRATMeasuredResultsSets, create_dissector_handle(dissect_CellId_IRATMeasuredResultsSets_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_IMSI, create_dissector_handle(dissect_IMSI_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_IMEI, create_dissector_handle(dissect_IMEI_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_BDS_Ionospheric_Grid_Model, create_dissector_handle(dissect_BDS_Ionospheric_Grid_Model_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_DBDS_Correction_Information, create_dissector_handle(dissect_DBDS_Correction_Information_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_BDSIonosphericGridModel, create_dissector_handle(dissect_BDSIonosphericGridModel_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_DBDSCorrection, create_dissector_handle(dissect_DBDSCorrection_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_Confidence, create_dissector_handle(dissect_Confidence_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_ExtraDopplerInfoExtension, create_dissector_handle(dissect_ExtraDopplerInfoExtension_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_Confidence, create_dissector_handle(dissect_Confidence_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_GANSS_ExtraDopplerExtension, create_dissector_handle(dissect_GANSS_ExtraDopplerExtension_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_Additional_PositioningDataSet, create_dissector_handle(dissect_Additional_PositioningDataSet_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_Additional_PositioningMethod, create_dissector_handle(dissect_Additional_PositioningMethod_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_AddPos_MeasuredResults, create_dissector_handle(dissect_AddPos_MeasuredResults_PDU, proto_pcap));
  dissector_add_uint("pcap.extension", id_AddPosSupport, create_dissector_handle(dissect_AddPosSupport_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_PositionCalculation, create_dissector_handle(dissect_PositionCalculationRequest_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.sout", id_PositionCalculation, create_dissector_handle(dissect_PositionCalculationResponse_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.uout", id_PositionCalculation, create_dissector_handle(dissect_PositionCalculationFailure_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_InformationExchangeInitiation, create_dissector_handle(dissect_InformationExchangeInitiationRequest_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.sout", id_InformationExchangeInitiation, create_dissector_handle(dissect_InformationExchangeInitiationResponse_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.uout", id_InformationExchangeInitiation, create_dissector_handle(dissect_InformationExchangeInitiationFailure_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_PositionInitiation, create_dissector_handle(dissect_PositionInitiationRequest_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.sout", id_PositionInitiation, create_dissector_handle(dissect_PositionInitiationResponse_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.uout", id_PositionInitiation, create_dissector_handle(dissect_PositionInitiationFailure_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_PositionActivation, create_dissector_handle(dissect_PositionActivationRequest_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.sout", id_PositionActivation, create_dissector_handle(dissect_PositionActivationResponse_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.uout", id_PositionActivation, create_dissector_handle(dissect_PositionActivationFailure_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_InformationReporting, create_dissector_handle(dissect_InformationReport_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_InformationExchangeTermination, create_dissector_handle(dissect_InformationExchangeTerminationRequest_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_InformationExchangeFailure, create_dissector_handle(dissect_InformationExchangeFailureIndication_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_ErrorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_PositionParameterModification, create_dissector_handle(dissect_PositionParameterModification_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_Abort, create_dissector_handle(dissect_Abort_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_PositionPeriodicReport, create_dissector_handle(dissect_PositionPeriodicReport_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_PositionPeriodicResult, create_dissector_handle(dissect_PositionPeriodicResult_PDU, proto_pcap));
  dissector_add_uint("pcap.proc.imsg", id_PositionPeriodicTermination, create_dissector_handle(dissect_PositionPeriodicTermination_PDU, proto_pcap));

    dissector_add_for_decode_as_with_preference("sccp.ssn", pcap_handle);
}

/*--- proto_register_pcap -------------------------------------------*/
void proto_register_pcap(void) {

  /* List of fields */

  static hf_register_info hf[] = {

    { &hf_pcap_AccuracyFulfilmentIndicator_PDU,
      { "AccuracyFulfilmentIndicator", "pcap.AccuracyFulfilmentIndicator",
        FT_UINT32, BASE_DEC, VALS(pcap_AccuracyFulfilmentIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_AddPos_MeasuredResults_PDU,
      { "AddPos-MeasuredResults", "pcap.AddPos_MeasuredResults",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Cause_PDU,
      { "Cause", "pcap.Cause",
        FT_UINT32, BASE_DEC, VALS(pcap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_CellId_MeasuredResultsSets_PDU,
      { "CellId-MeasuredResultsSets", "pcap.CellId_MeasuredResultsSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_RoundTripTimeInfoWithType1_PDU,
      { "RoundTripTimeInfoWithType1", "pcap.RoundTripTimeInfoWithType1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ExtendedTimingAdvanceLCR_PDU,
      { "ExtendedTimingAdvanceLCR", "pcap.ExtendedTimingAdvanceLCR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_RxTimingDeviation768Info_PDU,
      { "RxTimingDeviation768Info", "pcap.RxTimingDeviation768Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_RxTimingDeviation384extInfo_PDU,
      { "RxTimingDeviation384extInfo", "pcap.RxTimingDeviation384extInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_AddMeasurementInfo_PDU,
      { "AddMeasurementInfo", "pcap.AddMeasurementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_AngleOfArrivalLCR_PDU,
      { "AngleOfArrivalLCR", "pcap.AngleOfArrivalLCR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_CellId_IRATMeasuredResultsSets_PDU,
      { "CellId-IRATMeasuredResultsSets", "pcap.CellId_IRATMeasuredResultsSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_CellIDPositioning_PDU,
      { "CellIDPositioning", "pcap.CellIDPositioning_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_RequestedCellIDGERANMeasurements_PDU,
      { "RequestedCellIDGERANMeasurements", "pcap.RequestedCellIDGERANMeasurements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ClientType_PDU,
      { "ClientType", "pcap.ClientType",
        FT_UINT32, BASE_DEC, VALS(pcap_ClientType_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "pcap.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DGNSS_ValidityPeriod_PDU,
      { "DGNSS-ValidityPeriod", "pcap.DGNSS_ValidityPeriod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_IMEI_PDU,
      { "IMEI", "pcap.IMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_IMSI_PDU,
      { "IMSI", "pcap.IMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_UE_PositionEstimate_PDU,
      { "UE-PositionEstimate", "pcap.UE_PositionEstimate",
        FT_UINT32, BASE_DEC, VALS(pcap_UE_PositionEstimate_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_UE_PositionEstimateInfo_PDU,
      { "UE-PositionEstimateInfo", "pcap.UE_PositionEstimateInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Reference_Time_Only_PDU,
      { "GANSS-Reference-Time-Only", "pcap.GANSS_Reference_Time_Only_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionDataUEbased_PDU,
      { "PositionDataUEbased", "pcap.PositionDataUEbased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionData_PDU,
      { "PositionData", "pcap.PositionData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_PositioningDataSet_PDU,
      { "GANSS-PositioningDataSet", "pcap.GANSS_PositioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Additional_PositioningDataSet_PDU,
      { "Additional-PositioningDataSet", "pcap.Additional_PositioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ExtraDopplerInfoExtension_PDU,
      { "ExtraDopplerInfoExtension", "pcap.ExtraDopplerInfoExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_AzimuthAndElevationLSB_PDU,
      { "AzimuthAndElevationLSB", "pcap.AzimuthAndElevationLSB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Confidence_PDU,
      { "Confidence", "pcap.Confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Additional_Ionospheric_Model_PDU,
      { "GANSS-Additional-Ionospheric-Model", "pcap.GANSS_Additional_Ionospheric_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Additional_Navigation_Models_PDU,
      { "GANSS-Additional-Navigation-Models", "pcap.GANSS_Additional_Navigation_Models_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Additional_Time_Models_PDU,
      { "GANSS-Additional-Time-Models", "pcap.GANSS_Additional_Time_Models",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Additional_UTC_Models_PDU,
      { "GANSS-Additional-UTC-Models", "pcap.GANSS_Additional_UTC_Models",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_Additional_UTC_Models_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_ALM_BDSKeplericanset_PDU,
      { "GANSS-ALM-BDSKeplericanset", "pcap.GANSS_ALM_BDSKeplericanset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_ALM_ECEFsbasAlmanacSet_PDU,
      { "GANSS-ALM-ECEFsbasAlmanacSet", "pcap.GANSS_ALM_ECEFsbasAlmanacSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_ALM_GlonassAlmanacSet_PDU,
      { "GANSS-ALM-GlonassAlmanacSet", "pcap.GANSS_ALM_GlonassAlmanacSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_ALM_MidiAlmanacSet_PDU,
      { "GANSS-ALM-MidiAlmanacSet", "pcap.GANSS_ALM_MidiAlmanacSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_ALM_NAVKeplerianSet_PDU,
      { "GANSS-ALM-NAVKeplerianSet", "pcap.GANSS_ALM_NAVKeplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_ALM_ReducedKeplerianSet_PDU,
      { "GANSS-ALM-ReducedKeplerianSet", "pcap.GANSS_ALM_ReducedKeplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Auxiliary_Information_PDU,
      { "GANSS-Auxiliary-Information", "pcap.GANSS_Auxiliary_Information",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_Auxiliary_Information_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_CommonAssistanceData_PDU,
      { "GANSS-CommonAssistanceData", "pcap.GANSS_CommonAssistanceData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Earth_Orientation_Parameters_PDU,
      { "GANSS-Earth-Orientation-Parameters", "pcap.GANSS_Earth_Orientation_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_ExtraDopplerExtension_PDU,
      { "GANSS-ExtraDopplerExtension", "pcap.GANSS_ExtraDopplerExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_GenericAssistanceDataList_PDU,
      { "GANSS-GenericAssistanceDataList", "pcap.GANSS_GenericAssistanceDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_BDS_Ionospheric_Grid_Model_PDU,
      { "BDS-Ionospheric-Grid-Model", "pcap.BDS_Ionospheric_Grid_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DBDS_Correction_Information_PDU,
      { "DBDS-Correction-Information", "pcap.DBDS_Correction_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GanssCodePhaseAmbiguityExt_PDU,
      { "GanssCodePhaseAmbiguityExt", "pcap.GanssCodePhaseAmbiguityExt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GanssIntegerCodePhaseExt_PDU,
      { "GanssIntegerCodePhaseExt", "pcap.GanssIntegerCodePhaseExt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_MeasuredResultsList_PDU,
      { "GANSS-MeasuredResultsList", "pcap.GANSS_MeasuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Day_Cycle_PDU,
      { "GANSS-Day-Cycle", "pcap.GANSS_Day_Cycle",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Delta_T_PDU,
      { "GANSS-Delta-T", "pcap.GANSS_Delta_T",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_UTRAN_TRU_PDU,
      { "GANSS-UTRAN-TRU", "pcap.GANSS_UTRAN_TRU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_CompleteAlmanacProvided_PDU,
      { "CompleteAlmanacProvided", "pcap.CompleteAlmanacProvided",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_MeasuredResultsList_PDU,
      { "MeasuredResultsList", "pcap.MeasuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GPS_ReferenceLocation_PDU,
      { "GPS-ReferenceLocation", "pcap.GPS_ReferenceLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GPS_Week_Cycle_PDU,
      { "GPS-Week-Cycle", "pcap.GPS_Week_Cycle",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_UTRAN_GPS_DriftRate_PDU,
      { "UTRAN-GPS-DriftRate", "pcap.UTRAN_GPS_DriftRate",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_UTRAN_GPS_DriftRate_vals_ext, 0,
        NULL, HFILL }},
    { &hf_pcap_GPSReferenceTimeUncertainty_PDU,
      { "GPSReferenceTimeUncertainty", "pcap.GPSReferenceTimeUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GPS_UTRAN_TRU_PDU,
      { "GPS-UTRAN-TRU", "pcap.GPS_UTRAN_TRU",
        FT_UINT32, BASE_DEC, VALS(pcap_GPS_UTRAN_TRU_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_AdditionalGPSAssistDataRequired_PDU,
      { "AdditionalGPSAssistDataRequired", "pcap.AdditionalGPSAssistDataRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_AdditionalGanssAssistDataRequired_PDU,
      { "AdditionalGanssAssistDataRequired", "pcap.AdditionalGanssAssistDataRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSSReq_AddIonosphericModel_PDU,
      { "GANSSReq-AddIonosphericModel", "pcap.GANSSReq_AddIonosphericModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSSReq_EarthOrientPara_PDU,
      { "GANSSReq-EarthOrientPara", "pcap.GANSSReq_EarthOrientPara",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_BDSIonosphericGridModel_PDU,
      { "BDSIonosphericGridModel", "pcap.BDSIonosphericGridModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DBDSCorrection_PDU,
      { "DBDSCorrection", "pcap.DBDSCorrection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_AddNavigationModel_Req_PDU,
      { "GANSS-AddNavigationModel-Req", "pcap.GANSS_AddNavigationModel_Req",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_AddUTCModel_Req_PDU,
      { "GANSS-AddUTCModel-Req", "pcap.GANSS_AddUTCModel_Req",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_AuxInfo_req_PDU,
      { "GANSS-AuxInfo-req", "pcap.GANSS_AuxInfo_req",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_AddADchoices_PDU,
      { "GANSS-AddADchoices", "pcap.GANSS_AddADchoices_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeID_PDU,
      { "InformationExchangeID", "pcap.InformationExchangeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationReportCharacteristics_PDU,
      { "InformationReportCharacteristics", "pcap.InformationReportCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationType_PDU,
      { "InformationType", "pcap.InformationType",
        FT_UINT32, BASE_DEC, VALS(pcap_InformationType_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_AddIonoModelReq_PDU,
      { "GANSS-AddIonoModelReq", "pcap.GANSS_AddIonoModelReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_EarthOrientParaReq_PDU,
      { "GANSS-EarthOrientParaReq", "pcap.GANSS_EarthOrientParaReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_SBAS_ID_PDU,
      { "GANSS-SBAS-ID", "pcap.GANSS_SBAS_ID",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_SBAS_ID_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_MeasInstructionsUsed_PDU,
      { "MeasInstructionsUsed", "pcap.MeasInstructionsUsed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOA_MeasurementGroup_PDU,
      { "OTDOA-MeasurementGroup", "pcap.OTDOA_MeasurementGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOA_ReferenceCellInfoSAS_centric_PDU,
      { "OTDOA-ReferenceCellInfoSAS-centric", "pcap.OTDOA_ReferenceCellInfoSAS_centric_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOA_MeasuredResultsSets_PDU,
      { "OTDOA-MeasuredResultsSets", "pcap.OTDOA_MeasuredResultsSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOA_AddMeasuredResultsInfo_PDU,
      { "OTDOA-AddMeasuredResultsInfo", "pcap.OTDOA_AddMeasuredResultsInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_UC_ID_PDU,
      { "UC-ID", "pcap.UC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Extended_RNC_ID_PDU,
      { "Extended-RNC-ID", "pcap.Extended_RNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_AdditionalMeasurementInforLCR_PDU,
      { "AdditionalMeasurementInforLCR", "pcap.AdditionalMeasurementInforLCR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PeriodicPosCalcInfo_PDU,
      { "PeriodicPosCalcInfo", "pcap.PeriodicPosCalcInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PeriodicLocationInfo_PDU,
      { "PeriodicLocationInfo", "pcap.PeriodicLocationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PeriodicTerminationCause_PDU,
      { "PeriodicTerminationCause", "pcap.PeriodicTerminationCause",
        FT_UINT32, BASE_DEC, VALS(pcap_PeriodicTerminationCause_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_PositioningMethod_PDU,
      { "PositioningMethod", "pcap.PositioningMethod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GNSS_PositioningMethod_PDU,
      { "GNSS-PositioningMethod", "pcap.GNSS_PositioningMethod",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Additional_PositioningMethod_PDU,
      { "Additional-PositioningMethod", "pcap.Additional_PositioningMethod",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositioningPriority_PDU,
      { "PositioningPriority", "pcap.PositioningPriority",
        FT_UINT32, BASE_DEC, VALS(pcap_PositioningPriority_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_RRCstateChange_PDU,
      { "RRCstateChange", "pcap.RRCstateChange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_RequestType_PDU,
      { "RequestType", "pcap.RequestType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ResponseTime_PDU,
      { "ResponseTime", "pcap.ResponseTime",
        FT_UINT32, BASE_DEC, VALS(pcap_ResponseTime_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_HorizontalAccuracyCode_PDU,
      { "HorizontalAccuracyCode", "pcap.HorizontalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_UE_PositioningCapability_PDU,
      { "UE-PositioningCapability", "pcap.UE_PositioningCapability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_NetworkAssistedGANSSSupport_PDU,
      { "NetworkAssistedGANSSSupport", "pcap.NetworkAssistedGANSSSupport",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_AddPosSupport_PDU,
      { "AddPosSupport", "pcap.AddPosSupport",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_SBAS_IDs_PDU,
      { "GANSS-SBAS-IDs", "pcap.GANSS_SBAS_IDs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_Signal_IDs_PDU,
      { "GANSS-Signal-IDs", "pcap.GANSS_Signal_IDs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_SupportGANSSNonNativeADchoices_PDU,
      { "SupportGANSSNonNativeADchoices", "pcap.SupportGANSSNonNativeADchoices",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_UTDOAPositioning_PDU,
      { "UTDOAPositioning", "pcap.UTDOAPositioning_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_EnvironmentCharacterisation_PDU,
      { "EnvironmentCharacterisation", "pcap.EnvironmentCharacterisation",
        FT_UINT32, BASE_DEC, VALS(pcap_EnvironmentCharacterisation_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_GPSPositioning_PDU,
      { "GPSPositioning", "pcap.GPSPositioning_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSSPositioning_PDU,
      { "GANSSPositioning", "pcap.GANSSPositioning_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSScarrierPhaseRequested_PDU,
      { "GANSScarrierPhaseRequested", "pcap.GANSScarrierPhaseRequested",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSSMultiFreqMeasRequested_PDU,
      { "GANSSMultiFreqMeasRequested", "pcap.GANSSMultiFreqMeasRequested",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOAAssistanceData_PDU,
      { "OTDOAAssistanceData", "pcap.OTDOAAssistanceData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_VerticalAccuracyCode_PDU,
      { "VerticalAccuracyCode", "pcap.VerticalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_UTDOA_Group_PDU,
      { "UTDOA-Group", "pcap.UTDOA_Group_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Positioning_ResponseTime_PDU,
      { "Positioning-ResponseTime", "pcap.Positioning_ResponseTime",
        FT_UINT32, BASE_DEC, VALS(pcap_Positioning_ResponseTime_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_AmountOfReporting_PDU,
      { "AmountOfReporting", "pcap.AmountOfReporting",
        FT_UINT32, BASE_DEC, VALS(pcap_AmountOfReporting_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_IncludeVelocity_PDU,
      { "IncludeVelocity", "pcap.IncludeVelocity",
        FT_UINT32, BASE_DEC, VALS(pcap_IncludeVelocity_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_VelocityEstimate_PDU,
      { "VelocityEstimate", "pcap.VelocityEstimate",
        FT_UINT32, BASE_DEC, VALS(pcap_VelocityEstimate_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_UTRAN_GPSReferenceTime_PDU,
      { "UTRAN-GPSReferenceTime", "pcap.UTRAN_GPSReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_UTRAN_GANSSReferenceTimeResult_PDU,
      { "UTRAN-GANSSReferenceTimeResult", "pcap.UTRAN_GANSSReferenceTimeResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionCalculationRequest_PDU,
      { "PositionCalculationRequest", "pcap.PositionCalculationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionCalculationResponse_PDU,
      { "PositionCalculationResponse", "pcap.PositionCalculationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionCalculationFailure_PDU,
      { "PositionCalculationFailure", "pcap.PositionCalculationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeInitiationRequest_PDU,
      { "InformationExchangeInitiationRequest", "pcap.InformationExchangeInitiationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeObjectType_InfEx_Rqst_PDU,
      { "InformationExchangeObjectType-InfEx-Rqst", "pcap.InformationExchangeObjectType_InfEx_Rqst",
        FT_UINT32, BASE_DEC, VALS(pcap_InformationExchangeObjectType_InfEx_Rqst_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_UC_ID_InfEx_Rqst_PDU,
      { "UC-ID-InfEx-Rqst", "pcap.UC_ID_InfEx_Rqst_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeInitiationResponse_PDU,
      { "InformationExchangeInitiationResponse", "pcap.InformationExchangeInitiationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeObjectType_InfEx_Rsp_PDU,
      { "InformationExchangeObjectType-InfEx-Rsp", "pcap.InformationExchangeObjectType_InfEx_Rsp",
        FT_UINT32, BASE_DEC, VALS(pcap_InformationExchangeObjectType_InfEx_Rsp_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeInitiationFailure_PDU,
      { "InformationExchangeInitiationFailure", "pcap.InformationExchangeInitiationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionInitiationRequest_PDU,
      { "PositionInitiationRequest", "pcap.PositionInitiationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionInitiationResponse_PDU,
      { "PositionInitiationResponse", "pcap.PositionInitiationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionInitiationFailure_PDU,
      { "PositionInitiationFailure", "pcap.PositionInitiationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionActivationRequest_PDU,
      { "PositionActivationRequest", "pcap.PositionActivationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionActivationResponse_PDU,
      { "PositionActivationResponse", "pcap.PositionActivationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionActivationFailure_PDU,
      { "PositionActivationFailure", "pcap.PositionActivationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationReport_PDU,
      { "InformationReport", "pcap.InformationReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeObjectType_InfEx_Rprt_PDU,
      { "InformationExchangeObjectType-InfEx-Rprt", "pcap.InformationExchangeObjectType_InfEx_Rprt",
        FT_UINT32, BASE_DEC, VALS(pcap_InformationExchangeObjectType_InfEx_Rprt_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeTerminationRequest_PDU,
      { "InformationExchangeTerminationRequest", "pcap.InformationExchangeTerminationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_InformationExchangeFailureIndication_PDU,
      { "InformationExchangeFailureIndication", "pcap.InformationExchangeFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ErrorIndication_PDU,
      { "ErrorIndication", "pcap.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionParameterModification_PDU,
      { "PositionParameterModification", "pcap.PositionParameterModification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PrivateMessage_PDU,
      { "PrivateMessage", "pcap.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Abort_PDU,
      { "Abort", "pcap.Abort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionPeriodicReport_PDU,
      { "PositionPeriodicReport", "pcap.PositionPeriodicReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionPeriodicResult_PDU,
      { "PositionPeriodicResult", "pcap.PositionPeriodicResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositionPeriodicTermination_PDU,
      { "PositionPeriodicTermination", "pcap.PositionPeriodicTermination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PCAP_PDU_PDU,
      { "PCAP-PDU", "pcap.PCAP_PDU",
        FT_UINT32, BASE_DEC, VALS(pcap_PCAP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_local,
      { "local", "pcap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_pcap_global,
      { "global", "pcap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pcap_shortTID,
      { "shortTID", "pcap.shortTID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_longTID,
      { "longTID", "pcap.longTID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_pcap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "pcap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_id,
      { "id", "pcap.id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_pcap_criticality,
      { "criticality", "pcap.criticality",
        FT_UINT32, BASE_DEC, VALS(pcap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ie_field_value,
      { "value", "pcap.ie_field_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_pcap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "pcap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ext_id,
      { "id", "pcap.ext_id",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_pcap_extensionValue,
      { "extensionValue", "pcap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PrivateIE_Container_item,
      { "PrivateIE-Field", "pcap.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_private_id,
      { "id", "pcap.private_id",
        FT_UINT32, BASE_DEC, VALS(pcap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_pcap_private_value,
      { "value", "pcap.private_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_private_value", HFILL }},
    { &hf_pcap_AddPos_MeasuredResults_item,
      { "AddPos-MeasuredResults-Element", "pcap.AddPos_MeasuredResults_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_timestamp,
      { "timestamp", "pcap.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_pcap_type,
      { "type", "pcap.type",
        FT_UINT32, BASE_DEC, VALS(pcap_T_type_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_barometricPressure,
      { "barometricPressure", "pcap.barometricPressure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uncompensatedBarometricPressure,
      { "uncompensatedBarometricPressure", "pcap.uncompensatedBarometricPressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BaroMeasurement", HFILL }},
    { &hf_pcap_iE_Extensions,
      { "iE-Extensions", "pcap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_pcap_wlan,
      { "wlan", "pcap.wlan_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_wlanMeasurementList,
      { "wlanMeasurementList", "pcap.wlanMeasurementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_bt,
      { "bt", "pcap.bt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_btMeasurementList,
      { "btMeasurementList", "pcap.btMeasurementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_mbs,
      { "mbs", "pcap.mbs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_mbsMeasurementList,
      { "mbsMeasurementList", "pcap.mbsMeasurementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_WLANMeasurementList_item,
      { "WLANMeasurementList-Element", "pcap.WLANMeasurementList_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_wlanBSSID,
      { "wlanBSSID", "pcap.wlanBSSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_pcap_wlanSSID,
      { "wlanSSID", "pcap.wlanSSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_32", HFILL }},
    { &hf_pcap_wlanRSSI,
      { "wlanRSSI", "pcap.wlanRSSI",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_pcap_wlanRTTvalue,
      { "wlanRTTvalue", "pcap.wlanRTTvalue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_pcap_wlanRTTunits,
      { "wlanRTTunits", "pcap.wlanRTTunits",
        FT_UINT32, BASE_DEC, VALS(pcap_T_wlanRTTunits_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_wlanRTTaccuracy,
      { "wlanRTTaccuracy", "pcap.wlanRTTaccuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_wlanAPChannelFrequency,
      { "wlanAPChannelFrequency", "pcap.wlanAPChannelFrequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_256", HFILL }},
    { &hf_pcap_wlanServingFlag,
      { "wlanServingFlag", "pcap.wlanServingFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_BTMeasurementList_item,
      { "BTMeasurementList-Element", "pcap.BTMeasurementList_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_btADDR,
      { "btADDR", "pcap.btADDR",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_pcap_btRSSI,
      { "btRSSI", "pcap.btRSSI",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_pcap_MBSMeasurementList_item,
      { "MBSMeasurementList-Element", "pcap.MBSMeasurementList_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_transmitterID,
      { "transmitterID", "pcap.transmitterID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_pcap_codephase,
      { "codephase", "pcap.codephase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2097151", HFILL }},
    { &hf_pcap_codephaseRMS,
      { "codephaseRMS", "pcap.codephaseRMS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_gpsAlmanacAndSatelliteHealth,
      { "gpsAlmanacAndSatelliteHealth", "pcap.gpsAlmanacAndSatelliteHealth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPS_AlmanacAndSatelliteHealth", HFILL }},
    { &hf_pcap_satMask,
      { "satMask", "pcap.satMask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_32", HFILL }},
    { &hf_pcap_lsbTOW,
      { "lsbTOW", "pcap.lsbTOW",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_radioNetwork,
      { "radioNetwork", "pcap.radioNetwork",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_CauseRadioNetwork_vals_ext, 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_pcap_transport,
      { "transport", "pcap.transport",
        FT_UINT32, BASE_DEC, VALS(pcap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_pcap_protocol,
      { "protocol", "pcap.protocol",
        FT_UINT32, BASE_DEC, VALS(pcap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_pcap_misc,
      { "misc", "pcap.misc",
        FT_UINT32, BASE_DEC, VALS(pcap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_pcap_CellId_MeasuredResultsSets_item,
      { "CellId-MeasuredResultsInfoList", "pcap.CellId_MeasuredResultsInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_CellId_MeasuredResultsInfoList_item,
      { "CellId-MeasuredResultsInfo", "pcap.CellId_MeasuredResultsInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uC_ID,
      { "uC-ID", "pcap.uC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uTRANAccessPointPositionAltitude,
      { "uTRANAccessPointPositionAltitude", "pcap.uTRANAccessPointPositionAltitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_PositionEstimate,
      { "ue-PositionEstimate", "pcap.ue_PositionEstimate",
        FT_UINT32, BASE_DEC, VALS(pcap_UE_PositionEstimate_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_roundTripTimeInfo,
      { "roundTripTimeInfo", "pcap.roundTripTimeInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rxTimingDeviationInfo,
      { "rxTimingDeviationInfo", "pcap.rxTimingDeviationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rxTimingDeviationLCRInfo,
      { "rxTimingDeviationLCRInfo", "pcap.rxTimingDeviationLCRInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_pathloss,
      { "pathloss", "pcap.pathloss",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_RxTxTimeDifferenceType2,
      { "ue-RxTxTimeDifferenceType2", "pcap.ue_RxTxTimeDifferenceType2",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_PositioningMeasQuality,
      { "ue-PositioningMeasQuality", "pcap.ue_PositioningMeasQuality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_roundTripTime,
      { "roundTripTime", "pcap.roundTripTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_RxTxTimeDifferenceType1,
      { "ue-RxTxTimeDifferenceType1", "pcap.ue_RxTxTimeDifferenceType1",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_extendedRoundTripTime,
      { "extendedRoundTripTime", "pcap.extendedRoundTripTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_stdResolution,
      { "stdResolution", "pcap.stdResolution",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_numberOfMeasurements,
      { "numberOfMeasurements", "pcap.numberOfMeasurements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_stdOfMeasurements,
      { "stdOfMeasurements", "pcap.stdOfMeasurements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_geographicalCoordinates,
      { "geographicalCoordinates", "pcap.geographicalCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ga_AltitudeAndDirection,
      { "ga-AltitudeAndDirection", "pcap.ga_AltitudeAndDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rxTimingDeviation,
      { "rxTimingDeviation", "pcap.rxTimingDeviation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_timingAdvance,
      { "timingAdvance", "pcap.timingAdvance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rxTimingDeviationLCR,
      { "rxTimingDeviationLCR", "pcap.rxTimingDeviationLCR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_timingAdvanceLCR,
      { "timingAdvanceLCR", "pcap.timingAdvanceLCR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rxTimingDeviation768,
      { "rxTimingDeviation768", "pcap.rxTimingDeviation768",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_timingAdvance768,
      { "timingAdvance768", "pcap.timingAdvance768",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rxTimingDeviation384ext,
      { "rxTimingDeviation384ext", "pcap.rxTimingDeviation384ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_timingAdvance384ext,
      { "timingAdvance384ext", "pcap.timingAdvance384ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_cpich_RSCP,
      { "cpich-RSCP", "pcap.cpich_RSCP",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_cpich_EcNo,
      { "cpich-EcNo", "pcap.cpich_EcNo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_aOA_LCR,
      { "aOA-LCR", "pcap.aOA_LCR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_aOA_LCR_Accuracy_Class,
      { "aOA-LCR-Accuracy-Class", "pcap.aOA_LCR_Accuracy_Class",
        FT_UINT32, BASE_DEC, VALS(pcap_AOA_LCR_Accuracy_Class_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_CellId_IRATMeasuredResultsSets_item,
      { "CellId-IRATMeasuredResultsInfoList", "pcap.CellId_IRATMeasuredResultsInfoList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gERAN_MeasuredResultsInfoList,
      { "gERAN-MeasuredResultsInfoList", "pcap.gERAN_MeasuredResultsInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_iE_Extenstions,
      { "iE-Extenstions", "pcap.iE_Extenstions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_pcap_GERAN_MeasuredResultsInfoList_item,
      { "GERAN-MeasuredResultsInfo", "pcap.GERAN_MeasuredResultsInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gERANCellID,
      { "gERANCellID", "pcap.gERANCellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GERANCellGlobalID", HFILL }},
    { &hf_pcap_gERANPhysicalCellID,
      { "gERANPhysicalCellID", "pcap.gERANPhysicalCellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gSM_RSSI,
      { "gSM-RSSI", "pcap.gSM_RSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_plmn_Identity,
      { "plmn-Identity", "pcap.plmn_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_locationAreaCode,
      { "locationAreaCode", "pcap.locationAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_cellIdentity,
      { "cellIdentity", "pcap.cellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_bsic,
      { "bsic", "pcap.bsic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSM_BSIC", HFILL }},
    { &hf_pcap_arfcn,
      { "arfcn", "pcap.arfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GSM_BCCH_ARFCN", HFILL }},
    { &hf_pcap_networkColourCode,
      { "networkColourCode", "pcap.networkColourCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_baseStationColourCode,
      { "baseStationColourCode", "pcap.baseStationColourCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_requestedCellIDMeasurements,
      { "requestedCellIDMeasurements", "pcap.requestedCellIDMeasurements",
        FT_UINT32, BASE_DEC, VALS(pcap_RequestedCellIDMeasurements_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_fdd,
      { "fdd", "pcap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_roundTripTimeInfoWanted,
      { "roundTripTimeInfoWanted", "pcap.roundTripTimeInfoWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_pathlossWanted,
      { "pathlossWanted", "pcap.pathlossWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_roundTripTimeInfoWithType1Wanted,
      { "roundTripTimeInfoWithType1Wanted", "pcap.roundTripTimeInfoWithType1Wanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_cpichRSCPWanted,
      { "cpichRSCPWanted", "pcap.cpichRSCPWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_cpicEcNoWanted,
      { "cpicEcNoWanted", "pcap.cpicEcNoWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_tdd,
      { "tdd", "pcap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rxTimingDeviationInfoWanted,
      { "rxTimingDeviationInfoWanted", "pcap.rxTimingDeviationInfoWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_rxTimingDeviationLCRInfoWanted,
      { "rxTimingDeviationLCRInfoWanted", "pcap.rxTimingDeviationLCRInfoWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_rxTimingDeviation768InfoWanted,
      { "rxTimingDeviation768InfoWanted", "pcap.rxTimingDeviation768InfoWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_rxTimingDeviation384extInfoWanted,
      { "rxTimingDeviation384extInfoWanted", "pcap.rxTimingDeviation384extInfoWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_angleOfArrivalLCRWanted,
      { "angleOfArrivalLCRWanted", "pcap.angleOfArrivalLCRWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_timingAdvanceLCRWanted,
      { "timingAdvanceLCRWanted", "pcap.timingAdvanceLCRWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_rSSIMeasurementsWanted,
      { "rSSIMeasurementsWanted", "pcap.rSSIMeasurementsWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_procedureCode,
      { "procedureCode", "pcap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(pcap_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_triggeringMessage,
      { "triggeringMessage", "pcap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(pcap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_procedureCriticality,
      { "procedureCriticality", "pcap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(pcap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_pcap_transactionID,
      { "transactionID", "pcap.transactionID",
        FT_UINT32, BASE_DEC, VALS(pcap_TransactionID_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "pcap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_pcap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "pcap.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_iECriticality,
      { "iECriticality", "pcap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(pcap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_pcap_iE_ID,
      { "iE-ID", "pcap.iE_ID",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_ProtocolIE_ID_vals_ext, 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_pcap_repetitionNumber,
      { "repetitionNumber", "pcap.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnosticsRepetition", HFILL }},
    { &hf_pcap_messageStructure,
      { "messageStructure", "pcap.messageStructure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_typeOfError,
      { "typeOfError", "pcap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(pcap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_gps_TOW_sec,
      { "gps-TOW-sec", "pcap.gps_TOW_sec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_604799", HFILL }},
    { &hf_pcap_statusHealth,
      { "statusHealth", "pcap.statusHealth",
        FT_UINT32, BASE_DEC, VALS(pcap_DiffCorrectionStatus_vals), 0,
        "DiffCorrectionStatus", HFILL }},
    { &hf_pcap_dgps_CorrectionSatInfoList,
      { "dgps-CorrectionSatInfoList", "pcap.dgps_CorrectionSatInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DGPS_CorrectionSatInfoList_item,
      { "DGPS-CorrectionSatInfo", "pcap.DGPS_CorrectionSatInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_satID,
      { "satID", "pcap.satID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_iode,
      { "iode", "pcap.iode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_udre,
      { "udre", "pcap.udre",
        FT_UINT32, BASE_DEC, VALS(pcap_UDRE_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_prc,
      { "prc", "pcap.prc",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rrc,
      { "rrc", "pcap.rrc",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_udreGrowthRate,
      { "udreGrowthRate", "pcap.udreGrowthRate",
        FT_UINT32, BASE_DEC, VALS(pcap_UDREGrowthRate_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_udreValidityTime,
      { "udreValidityTime", "pcap.udreValidityTime",
        FT_UINT32, BASE_DEC, VALS(pcap_UDREValidityTime_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_point,
      { "point", "pcap.point_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_Point", HFILL }},
    { &hf_pcap_pointWithUnCertainty,
      { "pointWithUnCertainty", "pcap.pointWithUnCertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithUnCertainty", HFILL }},
    { &hf_pcap_polygon,
      { "polygon", "pcap.polygon",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA_Polygon", HFILL }},
    { &hf_pcap_pointWithUncertaintyEllipse,
      { "pointWithUncertaintyEllipse", "pcap.pointWithUncertaintyEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithUnCertaintyEllipse", HFILL }},
    { &hf_pcap_pointWithAltitude,
      { "pointWithAltitude", "pcap.pointWithAltitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithAltitude", HFILL }},
    { &hf_pcap_pointWithAltitudeAndUncertaintyEllipsoid,
      { "pointWithAltitudeAndUncertaintyEllipsoid", "pcap.pointWithAltitudeAndUncertaintyEllipsoid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithAltitudeAndUncertaintyEllipsoid", HFILL }},
    { &hf_pcap_ellipsoidArc,
      { "ellipsoidArc", "pcap.ellipsoidArc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_EllipsoidArc", HFILL }},
    { &hf_pcap_latitudeSign,
      { "latitudeSign", "pcap.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(pcap_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_latitude,
      { "latitude", "pcap.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_pcap_longitude,
      { "longitude", "pcap.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_pcap_directionOfAltitude,
      { "directionOfAltitude", "pcap.directionOfAltitude",
        FT_UINT32, BASE_DEC, VALS(pcap_T_directionOfAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_altitude,
      { "altitude", "pcap.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_pcap_innerRadius,
      { "innerRadius", "pcap.innerRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_pcap_uncertaintyRadius,
      { "uncertaintyRadius", "pcap.uncertaintyRadius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_offsetAngle,
      { "offsetAngle", "pcap.offsetAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_pcap_includedAngle,
      { "includedAngle", "pcap.includedAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_pcap_confidence,
      { "confidence", "pcap.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_pcap_altitudeAndDirection,
      { "altitudeAndDirection", "pcap.altitudeAndDirection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_AltitudeAndDirection", HFILL }},
    { &hf_pcap_uncertaintyEllipse,
      { "uncertaintyEllipse", "pcap.uncertaintyEllipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_UncertaintyEllipse", HFILL }},
    { &hf_pcap_uncertaintyAltitude,
      { "uncertaintyAltitude", "pcap.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_uncertaintyCode,
      { "uncertaintyCode", "pcap.uncertaintyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_GA_Polygon_item,
      { "GA-Polygon item", "pcap.GA_Polygon_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uncertaintySemi_major,
      { "uncertaintySemi-major", "pcap.uncertaintySemi_major",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_uncertaintySemi_minor,
      { "uncertaintySemi-minor", "pcap.uncertaintySemi_minor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_orientationOfMajorAxis,
      { "orientationOfMajorAxis", "pcap.orientationOfMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_89", HFILL }},
    { &hf_pcap_referenceTimeChoice,
      { "referenceTimeChoice", "pcap.referenceTimeChoice",
        FT_UINT32, BASE_DEC, VALS(pcap_ReferenceTimeChoice_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ue_positionEstimate,
      { "ue-positionEstimate", "pcap.ue_positionEstimate",
        FT_UINT32, BASE_DEC, VALS(pcap_UE_PositionEstimate_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_utran_GPSReferenceTimeResult,
      { "utran-GPSReferenceTimeResult", "pcap.utran_GPSReferenceTimeResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_ReferenceTimeOnly,
      { "gps-ReferenceTimeOnly", "pcap.gps_ReferenceTimeOnly",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_604799999_", HFILL }},
    { &hf_pcap_cell_Timing,
      { "cell-Timing", "pcap.cell_Timing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_extension_ReferenceTimeChoice,
      { "extension-ReferenceTimeChoice", "pcap.extension_ReferenceTimeChoice_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sfn,
      { "sfn", "pcap.sfn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_pcap_ganssTODmsec,
      { "ganssTODmsec", "pcap.ganssTODmsec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3599999", HFILL }},
    { &hf_pcap_ganssTimeID,
      { "ganssTimeID", "pcap.ganssTimeID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSID", HFILL }},
    { &hf_pcap_positionData,
      { "positionData", "pcap.positionData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_positioningDataDiscriminator,
      { "positioningDataDiscriminator", "pcap.positioningDataDiscriminator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_positioningDataSet,
      { "positioningDataSet", "pcap.positioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_PositioningDataSet_item,
      { "GANSS-PositioningMethodAndUsage", "pcap.GANSS_PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PositioningDataSet_item,
      { "PositioningMethodAndUsage", "pcap.PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Additional_PositioningDataSet_item,
      { "Additional-PositioningMethodAndUsage", "pcap.Additional_PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_TOW_1msec,
      { "gps-TOW-1msec", "pcap.gps_TOW_1msec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_604799999", HFILL }},
    { &hf_pcap_satelliteInformationList,
      { "satelliteInformationList", "pcap.satelliteInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcquisitionSatInfoList", HFILL }},
    { &hf_pcap_AcquisitionSatInfoList_item,
      { "AcquisitionSatInfo", "pcap.AcquisitionSatInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_doppler0thOrder,
      { "doppler0thOrder", "pcap.doppler0thOrder",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2048_2047", HFILL }},
    { &hf_pcap_extraDopplerInfo,
      { "extraDopplerInfo", "pcap.extraDopplerInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_codePhase,
      { "codePhase", "pcap.codePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1022", HFILL }},
    { &hf_pcap_integerCodePhase,
      { "integerCodePhase", "pcap.integerCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_pcap_gps_BitNumber,
      { "gps-BitNumber", "pcap.gps_BitNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_pcap_codePhaseSearchWindow,
      { "codePhaseSearchWindow", "pcap.codePhaseSearchWindow",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_CodePhaseSearchWindow_vals_ext, 0,
        NULL, HFILL }},
    { &hf_pcap_azimuthAndElevation,
      { "azimuthAndElevation", "pcap.azimuthAndElevation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_doppler1stOrder,
      { "doppler1stOrder", "pcap.doppler1stOrder",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M42_21", HFILL }},
    { &hf_pcap_dopplerUncertainty,
      { "dopplerUncertainty", "pcap.dopplerUncertainty",
        FT_UINT32, BASE_DEC, VALS(pcap_DopplerUncertainty_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_dopplerUncertaintyExtension,
      { "dopplerUncertaintyExtension", "pcap.dopplerUncertaintyExtension",
        FT_UINT32, BASE_DEC, VALS(pcap_DopplerUncertaintyExtension_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_azimuth,
      { "azimuth", "pcap.azimuth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_pcap_elevation,
      { "elevation", "pcap.elevation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_pcap_azimuthLSB,
      { "azimuthLSB", "pcap.azimuthLSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_elevationLSB,
      { "elevationLSB", "pcap.elevationLSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_AuxInfoGANSS_ID1_item,
      { "AuxInfoGANSS-ID1-element", "pcap.AuxInfoGANSS_ID1_element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_svID,
      { "svID", "pcap.svID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_signalsAvailable,
      { "signalsAvailable", "pcap.signalsAvailable",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_ie_Extensions,
      { "ie-Extensions", "pcap.ie_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_pcap_AuxInfoGANSS_ID3_item,
      { "AuxInfoGANSS-ID3-element", "pcap.AuxInfoGANSS_ID3_element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_channelNumber,
      { "channelNumber", "pcap.channelNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M7_13", HFILL }},
    { &hf_pcap_cnavToc,
      { "cnavToc", "pcap.cnavToc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_cnavTop,
      { "cnavTop", "pcap.cnavTop",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_cnavURA0,
      { "cnavURA0", "pcap.cnavURA0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_cnavURA1,
      { "cnavURA1", "pcap.cnavURA1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_cnavURA2,
      { "cnavURA2", "pcap.cnavURA2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_cnavAf2,
      { "cnavAf2", "pcap.cnavAf2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_cnavAf1,
      { "cnavAf1", "pcap.cnavAf1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_pcap_cnavAf0,
      { "cnavAf0", "pcap.cnavAf0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_26", HFILL }},
    { &hf_pcap_cnavTgd,
      { "cnavTgd", "pcap.cnavTgd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_cnavISCl1cp,
      { "cnavISCl1cp", "pcap.cnavISCl1cp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_cnavISCl1cd,
      { "cnavISCl1cd", "pcap.cnavISCl1cd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_cnavISCl1ca,
      { "cnavISCl1ca", "pcap.cnavISCl1ca",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_cnavISCl2c,
      { "cnavISCl2c", "pcap.cnavISCl2c",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_cnavISCl5i5,
      { "cnavISCl5i5", "pcap.cnavISCl5i5",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_cnavISCl5q5,
      { "cnavISCl5q5", "pcap.cnavISCl5q5",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_b1,
      { "b1", "pcap.b1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_b2,
      { "b2", "pcap.b2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_dGANSS_ReferenceTime,
      { "dGANSS-ReferenceTime", "pcap.dGANSS_ReferenceTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_119", HFILL }},
    { &hf_pcap_dGANSS_Information,
      { "dGANSS-Information", "pcap.dGANSS_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DGANSS_Information_item,
      { "DGANSS-InformationItem", "pcap.DGANSS_InformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gANSS_SignalId,
      { "gANSS-SignalId", "pcap.gANSS_SignalId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gANSS_StatusHealth,
      { "gANSS-StatusHealth", "pcap.gANSS_StatusHealth",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_StatusHealth_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_dGANSS_SignalInformation,
      { "dGANSS-SignalInformation", "pcap.dGANSS_SignalInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DGANSS_SignalInformation_item,
      { "DGANSS-SignalInformationItem", "pcap.DGANSS_SignalInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_satId,
      { "satId", "pcap.satId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_gANSS_iod,
      { "gANSS-iod", "pcap.gANSS_iod",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_ganss_prc,
      { "ganss-prc", "pcap.ganss_prc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2047_2047", HFILL }},
    { &hf_pcap_ganss_rrc,
      { "ganss-rrc", "pcap.ganss_rrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_127", HFILL }},
    { &hf_pcap_navClockModel,
      { "navClockModel", "pcap.navClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_cnavClockModel,
      { "cnavClockModel", "pcap.cnavClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_glonassClockModel,
      { "glonassClockModel", "pcap.glonassClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sbasClockModel,
      { "sbasClockModel", "pcap.sbasClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_bDSClockModel,
      { "bDSClockModel", "pcap.bDSClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_navKeplerianSet,
      { "navKeplerianSet", "pcap.navKeplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_NAVKeplerianSet", HFILL }},
    { &hf_pcap_cnavKeplerianSet,
      { "cnavKeplerianSet", "pcap.cnavKeplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_CNAVKeplerianSet", HFILL }},
    { &hf_pcap_glonassECEF,
      { "glonassECEF", "pcap.glonassECEF_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_GLONASSecef", HFILL }},
    { &hf_pcap_sbasECEF,
      { "sbasECEF", "pcap.sbasECEF_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_SBASecef", HFILL }},
    { &hf_pcap_bDSKeplerianSet,
      { "bDSKeplerianSet", "pcap.bDSKeplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_BDSKeplerianSet", HFILL }},
    { &hf_pcap_dataID,
      { "dataID", "pcap.dataID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_alpha_beta_parameters,
      { "alpha-beta-parameters", "pcap.alpha_beta_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPS_Ionospheric_Model", HFILL }},
    { &hf_pcap_non_broadcastIndication,
      { "non-broadcastIndication", "pcap.non_broadcastIndication",
        FT_UINT32, BASE_DEC, VALS(pcap_T_non_broadcastIndication_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ganssSatInfoNavList,
      { "ganssSatInfoNavList", "pcap.ganssSatInfoNavList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ganss_Sat_Info_AddNavList", HFILL }},
    { &hf_pcap_GANSS_Additional_Time_Models_item,
      { "GANSS-Time-Model", "pcap.GANSS_Time_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_utcModel1,
      { "utcModel1", "pcap.utcModel1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTCmodelSet1", HFILL }},
    { &hf_pcap_utcModel2,
      { "utcModel2", "pcap.utcModel2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTCmodelSet2", HFILL }},
    { &hf_pcap_utcModel3,
      { "utcModel3", "pcap.utcModel3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTCmodelSet3", HFILL }},
    { &hf_pcap_utcModel4,
      { "utcModel4", "pcap.utcModel4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTCmodelSet4", HFILL }},
    { &hf_pcap_satellite_Information_BDS_KP_List,
      { "satellite-Information-BDS-KP-List", "pcap.satellite_Information_BDS_KP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Satellite_Information_BDS_KP_List_item,
      { "Satellite-Information-BDS-KP-Item", "pcap.Satellite_Information_BDS_KP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sVID_BDS,
      { "sVID-BDS", "pcap.sVID_BDS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_tOA_BDS,
      { "tOA-BDS", "pcap.tOA_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_a21_BDS,
      { "a21-BDS", "pcap.a21_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_e_BDS,
      { "e-BDS", "pcap.e_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_omg_lower_BDS,
      { "omg-lower-BDS", "pcap.omg_lower_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_m0_BDS,
      { "m0-BDS", "pcap.m0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_omg_0_BDS,
      { "omg-0-BDS", "pcap.omg_0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_omg_upper_BDS,
      { "omg-upper-BDS", "pcap.omg_upper_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_delta_i_BDS,
      { "delta-i-BDS", "pcap.delta_i_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_a0_BDS,
      { "a0-BDS", "pcap.a0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_a1_BDS,
      { "a1-BDS", "pcap.a1_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_hea_BDS,
      { "hea-BDS", "pcap.hea_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_pcap_sat_info_SBASecefList,
      { "sat-info-SBASecefList", "pcap.sat_info_SBASecefList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_SAT_Info_Almanac_SBASecefList", HFILL }},
    { &hf_pcap_sat_info_GLOkpList,
      { "sat-info-GLOkpList", "pcap.sat_info_GLOkpList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_SAT_Info_Almanac_GLOkpList", HFILL }},
    { &hf_pcap_t_oa,
      { "t-oa", "pcap.t_oa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_sat_info_MIDIkpList,
      { "sat-info-MIDIkpList", "pcap.sat_info_MIDIkpList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_SAT_Info_Almanac_MIDIkpList", HFILL }},
    { &hf_pcap_sat_info_NAVkpList,
      { "sat-info-NAVkpList", "pcap.sat_info_NAVkpList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_SAT_Info_Almanac_NAVkpList", HFILL }},
    { &hf_pcap_sat_info_REDkpList,
      { "sat-info-REDkpList", "pcap.sat_info_REDkpList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_SAT_Info_Almanac_REDkpList", HFILL }},
    { &hf_pcap_weekNumber,
      { "weekNumber", "pcap.weekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_gANSS_AlmanacModel,
      { "gANSS-AlmanacModel", "pcap.gANSS_AlmanacModel",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_AlmanacModel_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_gANSS_keplerianParameters,
      { "gANSS-keplerianParameters", "pcap.gANSS_keplerianParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_KeplerianParametersAlm", HFILL }},
    { &hf_pcap_extension_GANSS_AlmanacModel,
      { "extension-GANSS-AlmanacModel", "pcap.extension_GANSS_AlmanacModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssID1,
      { "ganssID1", "pcap.ganssID1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuxInfoGANSS_ID1", HFILL }},
    { &hf_pcap_ganssID3,
      { "ganssID3", "pcap.ganssID3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuxInfoGANSS_ID3", HFILL }},
    { &hf_pcap_elevation_01,
      { "elevation", "pcap.elevation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_75", HFILL }},
    { &hf_pcap_GANSS_Clock_Model_item,
      { "GANSS-SatelliteClockModelItem", "pcap.GANSS_SatelliteClockModelItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_Reference_Time,
      { "ganss-Reference-Time", "pcap.ganss_Reference_Time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_Ionospheric_Model,
      { "ganss-Ionospheric-Model", "pcap.ganss_Ionospheric_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_Reference_Location,
      { "ganss-Reference-Location", "pcap.ganss_Reference_Location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssTod,
      { "ganssTod", "pcap.ganssTod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59_", HFILL }},
    { &hf_pcap_dataBitAssistancelist,
      { "dataBitAssistancelist", "pcap.dataBitAssistancelist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_DataBitAssistanceList", HFILL }},
    { &hf_pcap_GANSS_DataBitAssistanceList_item,
      { "GANSS-DataBitAssistanceItem", "pcap.GANSS_DataBitAssistanceItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_dataBitAssistanceSgnList,
      { "dataBitAssistanceSgnList", "pcap.dataBitAssistanceSgnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_DataBitAssistanceSgnList", HFILL }},
    { &hf_pcap_GANSS_DataBitAssistanceSgnList_item,
      { "GANSS-DataBitAssistanceSgnItem", "pcap.GANSS_DataBitAssistanceSgnItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_SignalId,
      { "ganss-SignalId", "pcap.ganss_SignalId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssDataBits,
      { "ganssDataBits", "pcap.ganssDataBits",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1_1024", HFILL }},
    { &hf_pcap_teop,
      { "teop", "pcap.teop",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_pmX,
      { "pmX", "pcap.pmX",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_pcap_pmXdot,
      { "pmXdot", "pcap.pmXdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_15", HFILL }},
    { &hf_pcap_pmY,
      { "pmY", "pcap.pmY",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_pcap_pmYdot,
      { "pmYdot", "pcap.pmYdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_15", HFILL }},
    { &hf_pcap_deltaUT1,
      { "deltaUT1", "pcap.deltaUT1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_31", HFILL }},
    { &hf_pcap_deltaUT1dot,
      { "deltaUT1dot", "pcap.deltaUT1dot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_19", HFILL }},
    { &hf_pcap_dopplerFirstOrder,
      { "dopplerFirstOrder", "pcap.dopplerFirstOrder",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M42_21", HFILL }},
    { &hf_pcap_dopplerUncertainty_01,
      { "dopplerUncertainty", "pcap.dopplerUncertainty",
        FT_UINT32, BASE_DEC, VALS(pcap_T_dopplerUncertainty_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_dopplerUncertaintyExtension_01,
      { "dopplerUncertaintyExtension", "pcap.dopplerUncertaintyExtension",
        FT_UINT32, BASE_DEC, VALS(pcap_T_dopplerUncertaintyExtension_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_GANSS_GenericAssistanceDataList_item,
      { "GANSSGenericAssistanceData", "pcap.GANSSGenericAssistanceData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssId,
      { "ganssId", "pcap.ganssId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_Real_Time_Integrity,
      { "ganss-Real-Time-Integrity", "pcap.ganss_Real_Time_Integrity",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_DataBitAssistance,
      { "ganss-DataBitAssistance", "pcap.ganss_DataBitAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_Data_Bit_Assistance", HFILL }},
    { &hf_pcap_dganss_Corrections,
      { "dganss-Corrections", "pcap.dganss_Corrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_AlmanacAndSatelliteHealth,
      { "ganss-AlmanacAndSatelliteHealth", "pcap.ganss_AlmanacAndSatelliteHealth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_ReferenceMeasurementInfo,
      { "ganss-ReferenceMeasurementInfo", "pcap.ganss_ReferenceMeasurementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_UTC_Model,
      { "ganss-UTC-Model", "pcap.ganss_UTC_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_Time_Model,
      { "ganss-Time-Model", "pcap.ganss_Time_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_Navigation_Model,
      { "ganss-Navigation-Model", "pcap.ganss_Navigation_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_bDS_Reference_Time,
      { "bDS-Reference-Time", "pcap.bDS_Reference_Time",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_bDS_Ionospheric_Grid_Information,
      { "bDS-Ionospheric-Grid-Information", "pcap.bDS_Ionospheric_Grid_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_BDS_Ionospheric_Grid_Information_item,
      { "BDS-Ionospheric-Grid-Information item", "pcap.BDS_Ionospheric_Grid_Information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_iGP_number_BDS,
      { "iGP-number-BDS", "pcap.iGP_number_BDS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_320", HFILL }},
    { &hf_pcap_vertical_Delay_BDS,
      { "vertical-Delay-BDS", "pcap.vertical_Delay_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_pcap_gIVEI_BDS,
      { "gIVEI-BDS", "pcap.gIVEI_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_dBDS_Information,
      { "dBDS-Information", "pcap.dBDS_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DBDS_Information_item,
      { "DBDS-Information item", "pcap.DBDS_Information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_dBDS_Signal_ID,
      { "dBDS-Signal-ID", "pcap.dBDS_Signal_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSID", HFILL }},
    { &hf_pcap_dGANSS_Signal_Information,
      { "dGANSS-Signal-Information", "pcap.dGANSS_Signal_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_DGANSS_Signal_Information_item,
      { "DGANSS-Signal-Information item", "pcap.DGANSS_Signal_Information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sat_ID_BDS,
      { "sat-ID-BDS", "pcap.sat_ID_BDS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_uDREI_BDS,
      { "uDREI-BDS", "pcap.uDREI_BDS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_rURAI_BDS,
      { "rURAI-BDS", "pcap.rURAI_BDS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_delta_t_BDS,
      { "delta-t-BDS", "pcap.delta_t_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_GANSS_GenericMeasurementInfo_item,
      { "GANSS-GenericMeasurementInfo item", "pcap.GANSS_GenericMeasurementInfo_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssMeasurementSignalList,
      { "ganssMeasurementSignalList", "pcap.ganssMeasurementSignalList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_ID,
      { "ganss-ID", "pcap.ganss_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_pcap_GANSSMeasurementSignalList_item,
      { "GANSSMeasurementSignalList item", "pcap.GANSSMeasurementSignalList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssSignalId,
      { "ganssSignalId", "pcap.ganssSignalId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_SignalID", HFILL }},
    { &hf_pcap_ganssCodePhaseAmbiguity,
      { "ganssCodePhaseAmbiguity", "pcap.ganssCodePhaseAmbiguity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_pcap_ganssMeasurementParameters,
      { "ganssMeasurementParameters", "pcap.ganssMeasurementParameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_MeasurementParameters", HFILL }},
    { &hf_pcap_ganssCodePhaseAmbiguity_ext,
      { "ganssCodePhaseAmbiguity-ext", "pcap.ganssCodePhaseAmbiguity_ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_32_127", HFILL }},
    { &hf_pcap_alpha_zero_ionos,
      { "alpha-zero-ionos", "pcap.alpha_zero_ionos",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_alpha_one_ionos,
      { "alpha-one-ionos", "pcap.alpha_one_ionos",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_alpha_two_ionos,
      { "alpha-two-ionos", "pcap.alpha_two_ionos",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_gANSS_IonosphereRegionalStormFlags,
      { "gANSS-IonosphereRegionalStormFlags", "pcap.gANSS_IonosphereRegionalStormFlags_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_storm_flag_one,
      { "storm-flag-one", "pcap.storm_flag_one",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_storm_flag_two,
      { "storm-flag-two", "pcap.storm_flag_two",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_storm_flag_three,
      { "storm-flag-three", "pcap.storm_flag_three",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_storm_flag_four,
      { "storm-flag-four", "pcap.storm_flag_four",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_storm_flag_five,
      { "storm-flag-five", "pcap.storm_flag_five",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_t_oa_01,
      { "t-oa", "pcap.t_oa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_pcap_iod_a,
      { "iod-a", "pcap.iod_a",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_gANSS_SatelliteInformationKP,
      { "gANSS-SatelliteInformationKP", "pcap.gANSS_SatelliteInformationKP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_toe_nav,
      { "toe-nav", "pcap.toe_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_ganss_omega_nav,
      { "ganss-omega-nav", "pcap.ganss_omega_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_delta_n_nav,
      { "delta-n-nav", "pcap.delta_n_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_m_zero_nav,
      { "m-zero-nav", "pcap.m_zero_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_omegadot_nav,
      { "omegadot-nav", "pcap.omegadot_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_ganss_e_nav,
      { "ganss-e-nav", "pcap.ganss_e_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_idot_nav,
      { "idot-nav", "pcap.idot_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_a_sqrt_nav,
      { "a-sqrt-nav", "pcap.a_sqrt_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_i_zero_nav,
      { "i-zero-nav", "pcap.i_zero_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_omega_zero_nav,
      { "omega-zero-nav", "pcap.omega_zero_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_c_rs_nav,
      { "c-rs-nav", "pcap.c_rs_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_c_is_nav,
      { "c-is-nav", "pcap.c_is_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_c_us_nav,
      { "c-us-nav", "pcap.c_us_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_c_rc_nav,
      { "c-rc-nav", "pcap.c_rc_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_c_ic_nav,
      { "c-ic-nav", "pcap.c_ic_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_c_uc_nav,
      { "c-uc-nav", "pcap.c_uc_nav",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_GANSS_MeasurementParameters_item,
      { "GANSS-MeasurementParametersItem", "pcap.GANSS_MeasurementParametersItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_cToNzero,
      { "cToNzero", "pcap.cToNzero",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_multipathIndicator,
      { "multipathIndicator", "pcap.multipathIndicator",
        FT_UINT32, BASE_DEC, VALS(pcap_T_multipathIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_carrierQualityIndication,
      { "carrierQualityIndication", "pcap.carrierQualityIndication",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_ganssCodePhase,
      { "ganssCodePhase", "pcap.ganssCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2097151", HFILL }},
    { &hf_pcap_ganssIntegerCodePhase,
      { "ganssIntegerCodePhase", "pcap.ganssIntegerCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_codePhaseRmsError,
      { "codePhaseRmsError", "pcap.codePhaseRmsError",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_doppler,
      { "doppler", "pcap.doppler",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_pcap_adr,
      { "adr", "pcap.adr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_33554431", HFILL }},
    { &hf_pcap_ganssIntegerCodePhase_ext,
      { "ganssIntegerCodePhase-ext", "pcap.ganssIntegerCodePhase_ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_64_127", HFILL }},
    { &hf_pcap_GANSS_MeasuredResultsList_item,
      { "GANSS-MeasuredResults", "pcap.GANSS_MeasuredResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_referenceTime,
      { "referenceTime", "pcap.referenceTime",
        FT_UINT32, BASE_DEC, VALS(pcap_T_referenceTime_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_utranReferenceTime,
      { "utranReferenceTime", "pcap.utranReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTRAN_GANSSReferenceTimeUL", HFILL }},
    { &hf_pcap_ganssReferenceTimeOnly,
      { "ganssReferenceTimeOnly", "pcap.ganssReferenceTimeOnly_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_ReferenceTimeOnly", HFILL }},
    { &hf_pcap_ganssGenericMeasurementInfo,
      { "ganssGenericMeasurementInfo", "pcap.ganssGenericMeasurementInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_GenericMeasurementInfo", HFILL }},
    { &hf_pcap_non_broadcastIndication_01,
      { "non-broadcastIndication", "pcap.non_broadcastIndication",
        FT_UINT32, BASE_DEC, VALS(pcap_T_non_broadcastIndication_01_vals), 0,
        "T_non_broadcastIndication_01", HFILL }},
    { &hf_pcap_ganssSatInfoNav,
      { "ganssSatInfoNav", "pcap.ganssSatInfoNav",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_Sat_Info_Nav", HFILL }},
    { &hf_pcap_gANSS_keplerianParameters_01,
      { "gANSS-keplerianParameters", "pcap.gANSS_keplerianParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_KeplerianParametersOrb", HFILL }},
    { &hf_pcap_GANSS_Real_Time_Integrity_item,
      { "GANSS-RealTimeInformationItem", "pcap.GANSS_RealTimeInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_bad_ganss_satId,
      { "bad-ganss-satId", "pcap.bad_ganss_satId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_bad_ganss_signalId,
      { "bad-ganss-signalId", "pcap.bad_ganss_signalId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_satelliteInformation,
      { "satelliteInformation", "pcap.satelliteInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_SatelliteInformation", HFILL }},
    { &hf_pcap_ganssDay,
      { "ganssDay", "pcap.ganssDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_pcap_ganssTod_01,
      { "ganssTod", "pcap.ganssTod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_86399", HFILL }},
    { &hf_pcap_ganssTodUncertainty,
      { "ganssTodUncertainty", "pcap.ganssTodUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_ganssTimeId,
      { "ganssTimeId", "pcap.ganssTimeId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSID", HFILL }},
    { &hf_pcap_utran_ganssreferenceTime,
      { "utran-ganssreferenceTime", "pcap.utran_ganssreferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTRAN_GANSSReferenceTimeDL", HFILL }},
    { &hf_pcap_tutran_ganss_driftRate,
      { "tutran-ganss-driftRate", "pcap.tutran_ganss_driftRate",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_TUTRAN_GANSS_DriftRate_vals_ext, 0,
        NULL, HFILL }},
    { &hf_pcap_gANSS_tod,
      { "gANSS-tod", "pcap.gANSS_tod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3599999", HFILL }},
    { &hf_pcap_gANSS_timeId,
      { "gANSS-timeId", "pcap.gANSS_timeId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSID", HFILL }},
    { &hf_pcap_gANSS_TimeUncertainty,
      { "gANSS-TimeUncertainty", "pcap.gANSS_TimeUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_t_oc,
      { "t-oc", "pcap.t_oc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_a_i2,
      { "a-i2", "pcap.a_i2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_pcap_a_i1,
      { "a-i1", "pcap.a_i1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_pcap_a_i0,
      { "a-i0", "pcap.a_i0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_31", HFILL }},
    { &hf_pcap_t_gd,
      { "t-gd", "pcap.t_gd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_sisa,
      { "sisa", "pcap.sisa",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_model_id,
      { "model-id", "pcap.model_id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_pcap_GANSS_SatelliteInformation_item,
      { "GANSS-SatelliteInformationItem", "pcap.GANSS_SatelliteInformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssSatId,
      { "ganssSatId", "pcap.ganssSatId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_dopplerZeroOrder,
      { "dopplerZeroOrder", "pcap.dopplerZeroOrder",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2048_2047", HFILL }},
    { &hf_pcap_extraDoppler,
      { "extraDoppler", "pcap.extraDoppler_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_ExtraDoppler", HFILL }},
    { &hf_pcap_codePhase_01,
      { "codePhase", "pcap.codePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_pcap_integerCodePhase_01,
      { "integerCodePhase", "pcap.integerCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_codePhaseSearchWindow_01,
      { "codePhaseSearchWindow", "pcap.codePhaseSearchWindow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_pcap_azimuthAndElevation_01,
      { "azimuthAndElevation", "pcap.azimuthAndElevation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_AzimuthAndElevation", HFILL }},
    { &hf_pcap_GANSS_SatelliteInformationKP_item,
      { "GANSS-SatelliteInformationKPItem", "pcap.GANSS_SatelliteInformationKPItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_e_alm,
      { "ganss-e-alm", "pcap.ganss_e_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_ganss_delta_I_alm,
      { "ganss-delta-I-alm", "pcap.ganss_delta_I_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_ganss_omegadot_alm,
      { "ganss-omegadot-alm", "pcap.ganss_omegadot_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_ganss_svStatusINAV_alm,
      { "ganss-svStatusINAV-alm", "pcap.ganss_svStatusINAV_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_ganss_svStatusFNAV_alm,
      { "ganss-svStatusFNAV-alm", "pcap.ganss_svStatusFNAV_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_ganss_delta_a_sqrt_alm,
      { "ganss-delta-a-sqrt-alm", "pcap.ganss_delta_a_sqrt_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_ganss_omegazero_alm,
      { "ganss-omegazero-alm", "pcap.ganss_omegazero_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_ganss_m_zero_alm,
      { "ganss-m-zero-alm", "pcap.ganss_m_zero_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_ganss_omega_alm,
      { "ganss-omega-alm", "pcap.ganss_omega_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_ganss_af_zero_alm,
      { "ganss-af-zero-alm", "pcap.ganss_af_zero_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_ganss_af_one_alm,
      { "ganss-af-one-alm", "pcap.ganss_af_one_alm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_GANSS_SAT_Info_Almanac_GLOkpList_item,
      { "GANSS-SAT-Info-Almanac-GLOkp", "pcap.GANSS_SAT_Info_Almanac_GLOkp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gloAlmNA,
      { "gloAlmNA", "pcap.gloAlmNA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_gloAlmnA,
      { "gloAlmnA", "pcap.gloAlmnA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_gloAlmHA,
      { "gloAlmHA", "pcap.gloAlmHA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_gloAlmLambdaA,
      { "gloAlmLambdaA", "pcap.gloAlmLambdaA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_pcap_gloAlmTlambdaA,
      { "gloAlmTlambdaA", "pcap.gloAlmTlambdaA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_pcap_gloAlmDeltaIA,
      { "gloAlmDeltaIA", "pcap.gloAlmDeltaIA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_gloAkmDeltaTA,
      { "gloAkmDeltaTA", "pcap.gloAkmDeltaTA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22", HFILL }},
    { &hf_pcap_gloAlmDeltaTdotA,
      { "gloAlmDeltaTdotA", "pcap.gloAlmDeltaTdotA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_pcap_gloAlmEpsilonA,
      { "gloAlmEpsilonA", "pcap.gloAlmEpsilonA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_15", HFILL }},
    { &hf_pcap_gloAlmOmegaA,
      { "gloAlmOmegaA", "pcap.gloAlmOmegaA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_gloAlmTauA,
      { "gloAlmTauA", "pcap.gloAlmTauA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_gloAlmCA,
      { "gloAlmCA", "pcap.gloAlmCA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_gloAlmMA,
      { "gloAlmMA", "pcap.gloAlmMA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_GANSS_SAT_Info_Almanac_MIDIkpList_item,
      { "GANSS-SAT-Info-Almanac-MIDIkp", "pcap.GANSS_SAT_Info_Almanac_MIDIkp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_midiAlmE,
      { "midiAlmE", "pcap.midiAlmE",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_midiAlmDeltaI,
      { "midiAlmDeltaI", "pcap.midiAlmDeltaI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_midiAlmOmegaDot,
      { "midiAlmOmegaDot", "pcap.midiAlmOmegaDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_midiAlmSqrtA,
      { "midiAlmSqrtA", "pcap.midiAlmSqrtA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_midiAlmOmega0,
      { "midiAlmOmega0", "pcap.midiAlmOmega0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_midiAlmOmega,
      { "midiAlmOmega", "pcap.midiAlmOmega",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_midiAlmMo,
      { "midiAlmMo", "pcap.midiAlmMo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_midiAlmaf0,
      { "midiAlmaf0", "pcap.midiAlmaf0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_midiAlmaf1,
      { "midiAlmaf1", "pcap.midiAlmaf1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_midiAlmL1Health,
      { "midiAlmL1Health", "pcap.midiAlmL1Health",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_midiAlmL2Health,
      { "midiAlmL2Health", "pcap.midiAlmL2Health",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_midiAlmL5Health,
      { "midiAlmL5Health", "pcap.midiAlmL5Health",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_GANSS_SAT_Info_Almanac_NAVkpList_item,
      { "GANSS-SAT-Info-Almanac-NAVkp", "pcap.GANSS_SAT_Info_Almanac_NAVkp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_navAlmE,
      { "navAlmE", "pcap.navAlmE",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navAlmDeltaI,
      { "navAlmDeltaI", "pcap.navAlmDeltaI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navAlmOMEGADOT,
      { "navAlmOMEGADOT", "pcap.navAlmOMEGADOT",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navAlmSVHealth,
      { "navAlmSVHealth", "pcap.navAlmSVHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_navAlmSqrtA,
      { "navAlmSqrtA", "pcap.navAlmSqrtA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_navAlmOMEGAo,
      { "navAlmOMEGAo", "pcap.navAlmOMEGAo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_navAlmOmega,
      { "navAlmOmega", "pcap.navAlmOmega",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_navAlmMo,
      { "navAlmMo", "pcap.navAlmMo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_navAlmaf0,
      { "navAlmaf0", "pcap.navAlmaf0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_navAlmaf1,
      { "navAlmaf1", "pcap.navAlmaf1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_GANSS_SAT_Info_Almanac_REDkpList_item,
      { "GANSS-SAT-Info-Almanac-REDkp", "pcap.GANSS_SAT_Info_Almanac_REDkp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_redAlmDeltaA,
      { "redAlmDeltaA", "pcap.redAlmDeltaA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_redAlmOmega0,
      { "redAlmOmega0", "pcap.redAlmOmega0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_pcap_redAlmPhi0,
      { "redAlmPhi0", "pcap.redAlmPhi0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_pcap_redAlmL1Health,
      { "redAlmL1Health", "pcap.redAlmL1Health",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_redAlmL2Health,
      { "redAlmL2Health", "pcap.redAlmL2Health",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_redAlmL5Health,
      { "redAlmL5Health", "pcap.redAlmL5Health",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_GANSS_SAT_Info_Almanac_SBASecefList_item,
      { "GANSS-SAT-Info-Almanac-SBASecef", "pcap.GANSS_SAT_Info_Almanac_SBASecef_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sbasAlmDataID,
      { "sbasAlmDataID", "pcap.sbasAlmDataID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_sbasAlmHealth,
      { "sbasAlmHealth", "pcap.sbasAlmHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_sbasAlmXg,
      { "sbasAlmXg", "pcap.sbasAlmXg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_15", HFILL }},
    { &hf_pcap_sbasAlmYg,
      { "sbasAlmYg", "pcap.sbasAlmYg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_15", HFILL }},
    { &hf_pcap_sbasAlmZg,
      { "sbasAlmZg", "pcap.sbasAlmZg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_pcap_sbasAlmXgdot,
      { "sbasAlmXgdot", "pcap.sbasAlmXgdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_sbasAlmYgDot,
      { "sbasAlmYgDot", "pcap.sbasAlmYgDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_sbasAlmZgDot,
      { "sbasAlmZgDot", "pcap.sbasAlmZgDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_sbasAlmTo,
      { "sbasAlmTo", "pcap.sbasAlmTo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_Ganss_Sat_Info_AddNavList_item,
      { "Ganss-Sat-Info-AddNavList item", "pcap.Ganss_Sat_Info_AddNavList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_svHealth,
      { "svHealth", "pcap.svHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_pcap_iod,
      { "iod", "pcap.iod",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_ganssAddClockModels,
      { "ganssAddClockModels", "pcap.ganssAddClockModels",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_AddClockModels_vals), 0,
        "GANSS_AddClockModels", HFILL }},
    { &hf_pcap_ganssAddOrbitModels,
      { "ganssAddOrbitModels", "pcap.ganssAddOrbitModels",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_AddOrbitModels_vals), 0,
        "GANSS_AddOrbitModels", HFILL }},
    { &hf_pcap_GANSS_Sat_Info_Nav_item,
      { "GANSS-Sat-Info-Nav item", "pcap.GANSS_Sat_Info_Nav_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_svHealth_01,
      { "svHealth", "pcap.svHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_pcap_iod_01,
      { "iod", "pcap.iod",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_ganssClockModel,
      { "ganssClockModel", "pcap.ganssClockModel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_Clock_Model", HFILL }},
    { &hf_pcap_ganssOrbitModel,
      { "ganssOrbitModel", "pcap.ganssOrbitModel",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_Orbit_Model_vals), 0,
        "GANSS_Orbit_Model", HFILL }},
    { &hf_pcap_ganssSignalID,
      { "ganssSignalID", "pcap.ganssSignalID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_pcap_ganss_time_model_refTime,
      { "ganss-time-model-refTime", "pcap.ganss_time_model_refTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_37799", HFILL }},
    { &hf_pcap_ganss_t_a0,
      { "ganss-t-a0", "pcap.ganss_t_a0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_pcap_ganss_t_a1,
      { "ganss-t-a1", "pcap.ganss_t_a1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_pcap_ganss_t_a2,
      { "ganss-t-a2", "pcap.ganss_t_a2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M64_63", HFILL }},
    { &hf_pcap_gnss_to_id,
      { "gnss-to-id", "pcap.gnss_to_id",
        FT_UINT32, BASE_DEC, VALS(pcap_T_gnss_to_id_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_wk_number,
      { "ganss-wk-number", "pcap.ganss_wk_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_pcap_gANSS_UTRAN_TimeRelationshipUncertainty,
      { "gANSS-UTRAN-TimeRelationshipUncertainty", "pcap.gANSS_UTRAN_TimeRelationshipUncertainty",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_UTRAN_TimeRelationshipUncertainty_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_a_one_utc,
      { "a-one-utc", "pcap.a_one_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_a_zero_utc,
      { "a-zero-utc", "pcap.a_zero_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_t_ot_utc,
      { "t-ot-utc", "pcap.t_ot_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_w_n_t_utc,
      { "w-n-t-utc", "pcap.w_n_t_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_delta_t_ls_utc,
      { "delta-t-ls-utc", "pcap.delta_t_ls_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_w_n_lsf_utc,
      { "w-n-lsf-utc", "pcap.w_n_lsf_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_dn_utc,
      { "dn-utc", "pcap.dn_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_delta_t_lsf_utc,
      { "delta-t-lsf-utc", "pcap.delta_t_lsf_utc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_gloTau,
      { "gloTau", "pcap.gloTau",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22", HFILL }},
    { &hf_pcap_gloGamma,
      { "gloGamma", "pcap.gloGamma",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_gloDeltaTau,
      { "gloDeltaTau", "pcap.gloDeltaTau",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_navToc,
      { "navToc", "pcap.navToc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navaf2,
      { "navaf2", "pcap.navaf2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_navaf1,
      { "navaf1", "pcap.navaf1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navaf0,
      { "navaf0", "pcap.navaf0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22", HFILL }},
    { &hf_pcap_navTgd,
      { "navTgd", "pcap.navTgd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_cnavURAindex,
      { "cnavURAindex", "pcap.cnavURAindex",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_cnavDeltaA,
      { "cnavDeltaA", "pcap.cnavDeltaA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_26", HFILL }},
    { &hf_pcap_cnavAdot,
      { "cnavAdot", "pcap.cnavAdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_25", HFILL }},
    { &hf_pcap_cnavDeltaNo,
      { "cnavDeltaNo", "pcap.cnavDeltaNo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_cnavDeltaNoDot,
      { "cnavDeltaNoDot", "pcap.cnavDeltaNoDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_23", HFILL }},
    { &hf_pcap_cnavMo,
      { "cnavMo", "pcap.cnavMo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_33", HFILL }},
    { &hf_pcap_cnavE,
      { "cnavE", "pcap.cnavE",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_33", HFILL }},
    { &hf_pcap_cnavOmega,
      { "cnavOmega", "pcap.cnavOmega",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_33", HFILL }},
    { &hf_pcap_cnavOMEGA0,
      { "cnavOMEGA0", "pcap.cnavOMEGA0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_33", HFILL }},
    { &hf_pcap_cnavDeltaOmegaDot,
      { "cnavDeltaOmegaDot", "pcap.cnavDeltaOmegaDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_cnavIo,
      { "cnavIo", "pcap.cnavIo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_33", HFILL }},
    { &hf_pcap_cnavIoDot,
      { "cnavIoDot", "pcap.cnavIoDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_15", HFILL }},
    { &hf_pcap_cnavCis,
      { "cnavCis", "pcap.cnavCis",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_cnavCic,
      { "cnavCic", "pcap.cnavCic",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_cnavCrs,
      { "cnavCrs", "pcap.cnavCrs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_cnavCrc,
      { "cnavCrc", "pcap.cnavCrc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_cnavCus,
      { "cnavCus", "pcap.cnavCus",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_pcap_cnavCuc,
      { "cnavCuc", "pcap.cnavCuc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_pcap_gloEn,
      { "gloEn", "pcap.gloEn",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_gloP1,
      { "gloP1", "pcap.gloP1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_gloP2,
      { "gloP2", "pcap.gloP2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_gloM,
      { "gloM", "pcap.gloM",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_gloX,
      { "gloX", "pcap.gloX",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_27", HFILL }},
    { &hf_pcap_gloXdot,
      { "gloXdot", "pcap.gloXdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_gloXdotdot,
      { "gloXdotdot", "pcap.gloXdotdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_gloY,
      { "gloY", "pcap.gloY",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_27", HFILL }},
    { &hf_pcap_gloYdot,
      { "gloYdot", "pcap.gloYdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_gloYdotdot,
      { "gloYdotdot", "pcap.gloYdotdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_gloZ,
      { "gloZ", "pcap.gloZ",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_27", HFILL }},
    { &hf_pcap_gloZdot,
      { "gloZdot", "pcap.gloZdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_gloZdotdot,
      { "gloZdotdot", "pcap.gloZdotdot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_navURA,
      { "navURA", "pcap.navURA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_navFitFlag,
      { "navFitFlag", "pcap.navFitFlag",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_navToe,
      { "navToe", "pcap.navToe",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navOmega,
      { "navOmega", "pcap.navOmega",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_navDeltaN,
      { "navDeltaN", "pcap.navDeltaN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navM0,
      { "navM0", "pcap.navM0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_navOmegaADot,
      { "navOmegaADot", "pcap.navOmegaADot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_navE,
      { "navE", "pcap.navE",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_navIDot,
      { "navIDot", "pcap.navIDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_navAPowerHalf,
      { "navAPowerHalf", "pcap.navAPowerHalf",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_navI0,
      { "navI0", "pcap.navI0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_navOmegaA0,
      { "navOmegaA0", "pcap.navOmegaA0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_navCrs,
      { "navCrs", "pcap.navCrs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navCis,
      { "navCis", "pcap.navCis",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navCus,
      { "navCus", "pcap.navCus",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navCrc,
      { "navCrc", "pcap.navCrc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navCic,
      { "navCic", "pcap.navCic",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_navCuc,
      { "navCuc", "pcap.navCuc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_sbasTo,
      { "sbasTo", "pcap.sbasTo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_sbasAccuracy,
      { "sbasAccuracy", "pcap.sbasAccuracy",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_sbasXg,
      { "sbasXg", "pcap.sbasXg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_30", HFILL }},
    { &hf_pcap_sbasYg,
      { "sbasYg", "pcap.sbasYg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_30", HFILL }},
    { &hf_pcap_sbasZg,
      { "sbasZg", "pcap.sbasZg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_25", HFILL }},
    { &hf_pcap_sbasXgDot,
      { "sbasXgDot", "pcap.sbasXgDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_sbasYgDot,
      { "sbasYgDot", "pcap.sbasYgDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_sbasZgDot,
      { "sbasZgDot", "pcap.sbasZgDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_sbasXgDotDot,
      { "sbasXgDotDot", "pcap.sbasXgDotDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_sbagYgDotDot,
      { "sbagYgDotDot", "pcap.sbagYgDotDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_sbasZgDotDot,
      { "sbasZgDotDot", "pcap.sbasZgDotDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_uRAIndex_BDS,
      { "uRAIndex-BDS", "pcap.uRAIndex_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_tOA_BDS_01,
      { "tOA-BDS", "pcap.tOA_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_a1_2_BDS,
      { "a1-2-BDS", "pcap.a1_2_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_e_BDS_01,
      { "e-BDS", "pcap.e_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_oMG_BDS,
      { "oMG-BDS", "pcap.oMG_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_dLTn_BDS,
      { "dLTn-BDS", "pcap.dLTn_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_m0_BDS_01,
      { "m0-BDS", "pcap.m0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_oMG0_BDS,
      { "oMG0-BDS", "pcap.oMG0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_oMGdot_BDS,
      { "oMGdot-BDS", "pcap.oMGdot_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_i0_BDS,
      { "i0-BDS", "pcap.i0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_iDOT_BDS,
      { "iDOT-BDS", "pcap.iDOT_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_cuc_BDS,
      { "cuc-BDS", "pcap.cuc_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_cus_BDS,
      { "cus-BDS", "pcap.cus_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_crc_BDS,
      { "crc-BDS", "pcap.crc_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_crs_BDS,
      { "crs-BDS", "pcap.crs_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_cic_BDS,
      { "cic-BDS", "pcap.cic_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_cis_BDS,
      { "cis-BDS", "pcap.cis_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_pcap_aODE_BDS,
      { "aODE-BDS", "pcap.aODE_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_sbasAgfo,
      { "sbasAgfo", "pcap.sbasAgfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_12", HFILL }},
    { &hf_pcap_sbasAgf1,
      { "sbasAgf1", "pcap.sbasAgf1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_toc_BDS,
      { "toc-BDS", "pcap.toc_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_17", HFILL }},
    { &hf_pcap_a0_BDS_01,
      { "a0-BDS", "pcap.a0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_a1_BDS_01,
      { "a1-BDS", "pcap.a1_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22", HFILL }},
    { &hf_pcap_a2_BDS,
      { "a2-BDS", "pcap.a2_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_tGD1_BDS,
      { "tGD1-BDS", "pcap.tGD1_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_aODC_BDS,
      { "aODC-BDS", "pcap.aODC_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_utcA0,
      { "utcA0", "pcap.utcA0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_utcA1,
      { "utcA1", "pcap.utcA1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_utcA2,
      { "utcA2", "pcap.utcA2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_7", HFILL }},
    { &hf_pcap_utcDeltaTls,
      { "utcDeltaTls", "pcap.utcDeltaTls",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcTot,
      { "utcTot", "pcap.utcTot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_utcWNot,
      { "utcWNot", "pcap.utcWNot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_13", HFILL }},
    { &hf_pcap_utcWNlsf,
      { "utcWNlsf", "pcap.utcWNlsf",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcDN,
      { "utcDN", "pcap.utcDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_utcDeltaTlsf,
      { "utcDeltaTlsf", "pcap.utcDeltaTlsf",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_nA,
      { "nA", "pcap.nA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_tauC,
      { "tauC", "pcap.tauC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_deltaUT1_01,
      { "deltaUT1", "pcap.deltaUT1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_kp,
      { "kp", "pcap.kp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_utcA1wnt,
      { "utcA1wnt", "pcap.utcA1wnt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_utcA0wnt,
      { "utcA0wnt", "pcap.utcA0wnt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_utcTot_01,
      { "utcTot", "pcap.utcTot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcWNt,
      { "utcWNt", "pcap.utcWNt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcDN_01,
      { "utcDN", "pcap.utcDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcStandardID,
      { "utcStandardID", "pcap.utcStandardID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_pcap_utca0_BDS,
      { "utca0-BDS", "pcap.utca0_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_utca1_BDS,
      { "utca1-BDS", "pcap.utca1_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_utcDeltatLS_BDS,
      { "utcDeltatLS-BDS", "pcap.utcDeltatLS_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcWNlsf_BDS,
      { "utcWNlsf-BDS", "pcap.utcWNlsf_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcDN_BDS,
      { "utcDN-BDS", "pcap.utcDN_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utcDeltaTlsf_BDS,
      { "utcDeltaTlsf-BDS", "pcap.utcDeltaTlsf_BDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utran_GANSSTimingOfCellFrames,
      { "utran-GANSSTimingOfCellFrames", "pcap.utran_GANSSTimingOfCellFrames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3999999", HFILL }},
    { &hf_pcap_referenceSfn,
      { "referenceSfn", "pcap.referenceSfn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_pcap_ue_GANSSTimingOfCellFrames,
      { "ue-GANSSTimingOfCellFrames", "pcap.ue_GANSSTimingOfCellFrames",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_345599999999", HFILL }},
    { &hf_pcap_gANSS_TimeId,
      { "gANSS-TimeId", "pcap.gANSS_TimeId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSID", HFILL }},
    { &hf_pcap_wn_a,
      { "wn-a", "pcap.wn_a",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_almanacSatInfoList,
      { "almanacSatInfoList", "pcap.almanacSatInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_svGlobalHealth,
      { "svGlobalHealth", "pcap.svGlobalHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_364", HFILL }},
    { &hf_pcap_AlmanacSatInfoList_item,
      { "AlmanacSatInfo", "pcap.AlmanacSatInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_e,
      { "e", "pcap.e",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_almanacSatInfo_t_oa,
      { "t-oa", "pcap.almanacSatInfo.t-oa",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_deltaI,
      { "deltaI", "pcap.deltaI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_omegaDot,
      { "omegaDot", "pcap.omegaDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_satHealth,
      { "satHealth", "pcap.satHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_a_Sqrt,
      { "a-Sqrt", "pcap.a_Sqrt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_omega0,
      { "omega0", "pcap.omega0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_m0,
      { "m0", "pcap.m0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_omega,
      { "omega", "pcap.omega",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_af0,
      { "af0", "pcap.af0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_af1,
      { "af1", "pcap.af1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_pcap_codeOnL2,
      { "codeOnL2", "pcap.codeOnL2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_uraIndex,
      { "uraIndex", "pcap.uraIndex",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_pcap_satHealth_01,
      { "satHealth", "pcap.satHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_pcap_iodc,
      { "iodc", "pcap.iodc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_pcap_l2Pflag,
      { "l2Pflag", "pcap.l2Pflag",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_sf1Revd,
      { "sf1Revd", "pcap.sf1Revd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubFrame1Reserved", HFILL }},
    { &hf_pcap_t_GD,
      { "t-GD", "pcap.t_GD",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_t_oc_01,
      { "t-oc", "pcap.t_oc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_af2,
      { "af2", "pcap.af2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_af1_01,
      { "af1", "pcap.af1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_af0_01,
      { "af0", "pcap.af0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22", HFILL }},
    { &hf_pcap_c_rs,
      { "c-rs", "pcap.c_rs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_delta_n,
      { "delta-n", "pcap.delta_n",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_m0_01,
      { "m0", "pcap.m0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_c_uc,
      { "c-uc", "pcap.c_uc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_e_01,
      { "e", "pcap.e",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_c_us,
      { "c-us", "pcap.c_us",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_a_Sqrt_01,
      { "a-Sqrt", "pcap.a_Sqrt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_t_oe,
      { "t-oe", "pcap.t_oe",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_fitInterval,
      { "fitInterval", "pcap.fitInterval",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_pcap_aodo,
      { "aodo", "pcap.aodo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_pcap_c_ic,
      { "c-ic", "pcap.c_ic",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_omega0_01,
      { "omega0", "pcap.omega0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_c_is,
      { "c-is", "pcap.c_is",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_i0,
      { "i0", "pcap.i0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_c_rc,
      { "c-rc", "pcap.c_rc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_omega_01,
      { "omega", "pcap.omega",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_omegaDot_01,
      { "omegaDot", "pcap.omegaDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_iDot,
      { "iDot", "pcap.iDot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_reserved1,
      { "reserved1", "pcap.reserved1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_23", HFILL }},
    { &hf_pcap_reserved2,
      { "reserved2", "pcap.reserved2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_reserved3,
      { "reserved3", "pcap.reserved3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_reserved4,
      { "reserved4", "pcap.reserved4",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_pcap_alfa0,
      { "alfa0", "pcap.alfa0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_alfa1,
      { "alfa1", "pcap.alfa1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_alfa2,
      { "alfa2", "pcap.alfa2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_alfa3,
      { "alfa3", "pcap.alfa3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_beta0,
      { "beta0", "pcap.beta0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_beta1,
      { "beta1", "pcap.beta1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_beta2,
      { "beta2", "pcap.beta2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_beta3,
      { "beta3", "pcap.beta3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_MeasuredResultsList_item,
      { "GPS-MeasuredResults", "pcap.GPS_MeasuredResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_MeasurementParamList,
      { "gps-MeasurementParamList", "pcap.gps_MeasurementParamList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GPS_MeasurementParamList_item,
      { "GPS-MeasurementParam", "pcap.GPS_MeasurementParam_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_satelliteID,
      { "satelliteID", "pcap.satelliteID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_c_N0,
      { "c-N0", "pcap.c_N0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_doppler_01,
      { "doppler", "pcap.doppler",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32768", HFILL }},
    { &hf_pcap_wholeGPS_Chips,
      { "wholeGPS-Chips", "pcap.wholeGPS_Chips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1022", HFILL }},
    { &hf_pcap_fractionalGPS_Chips,
      { "fractionalGPS-Chips", "pcap.fractionalGPS_Chips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_pcap_multipathIndicator_01,
      { "multipathIndicator", "pcap.multipathIndicator",
        FT_UINT32, BASE_DEC, VALS(pcap_MultipathIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_pseudorangeRMS_Error,
      { "pseudorangeRMS-Error", "pcap.pseudorangeRMS_Error",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_GPS_NavigationModel_item,
      { "NavigationModelSatInfo", "pcap.NavigationModelSatInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_satelliteStatus,
      { "satelliteStatus", "pcap.satelliteStatus",
        FT_UINT32, BASE_DEC, VALS(pcap_SatelliteStatus_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_gps_clockAndEphemerisParms,
      { "gps-clockAndEphemerisParms", "pcap.gps_clockAndEphemerisParms_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPS_ClockAndEphemerisParameters", HFILL }},
    { &hf_pcap_badSatellites,
      { "badSatellites", "pcap.badSatellites",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BadSatList", HFILL }},
    { &hf_pcap_noBadSatellites,
      { "noBadSatellites", "pcap.noBadSatellites_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_BadSatList_item,
      { "BadSatList item", "pcap.BadSatList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_gps_Week,
      { "gps-Week", "pcap.gps_Week",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_pcap_gps_TOW_AssistList,
      { "gps-TOW-AssistList", "pcap.gps_TOW_AssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_GPS_TOW_AssistList_item,
      { "GPS-TOW-Assist", "pcap.GPS_TOW_Assist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tlm_Message,
      { "tlm-Message", "pcap.tlm_Message",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_14", HFILL }},
    { &hf_pcap_antiSpoof,
      { "antiSpoof", "pcap.antiSpoof",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_alert,
      { "alert", "pcap.alert",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_tlm_Reserved,
      { "tlm-Reserved", "pcap.tlm_Reserved",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_gps_RefTimeUNC,
      { "gps-RefTimeUNC", "pcap.gps_RefTimeUNC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_pcap_a1,
      { "a1", "pcap.a1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_pcap_a0,
      { "a0", "pcap.a0",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_pcap_t_ot,
      { "t-ot", "pcap.t_ot",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_delta_t_LS,
      { "delta-t-LS", "pcap.delta_t_LS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_wn_t,
      { "wn-t", "pcap.wn_t",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_wn_lsf,
      { "wn-lsf", "pcap.wn_lsf",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_dn,
      { "dn", "pcap.dn",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_delta_t_LSF,
      { "delta-t-LSF", "pcap.delta_t_LSF",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_almanacRequest,
      { "almanacRequest", "pcap.almanacRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_utcModelRequest,
      { "utcModelRequest", "pcap.utcModelRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ionosphericModelRequest,
      { "ionosphericModelRequest", "pcap.ionosphericModelRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_navigationModelRequest,
      { "navigationModelRequest", "pcap.navigationModelRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_dgpsCorrectionsRequest,
      { "dgpsCorrectionsRequest", "pcap.dgpsCorrectionsRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_referenceLocationRequest,
      { "referenceLocationRequest", "pcap.referenceLocationRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_referenceTimeRequest,
      { "referenceTimeRequest", "pcap.referenceTimeRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_aquisitionAssistanceRequest,
      { "aquisitionAssistanceRequest", "pcap.aquisitionAssistanceRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_realTimeIntegrityRequest,
      { "realTimeIntegrityRequest", "pcap.realTimeIntegrityRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_navModelAddDataRequest,
      { "navModelAddDataRequest", "pcap.navModelAddDataRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModelAdditionalData", HFILL }},
    { &hf_pcap_ganssReferenceTime,
      { "ganssReferenceTime", "pcap.ganssReferenceTime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssreferenceLocation,
      { "ganssreferenceLocation", "pcap.ganssreferenceLocation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssIonosphericModel,
      { "ganssIonosphericModel", "pcap.ganssIonosphericModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssRequestedGenericAssistanceDataList,
      { "ganssRequestedGenericAssistanceDataList", "pcap.ganssRequestedGenericAssistanceDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_add_iono_mode_req,
      { "ganss-add-iono-mode-req", "pcap.ganss_add_iono_mode_req",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_pcap_GanssRequestedGenericAssistanceDataList_item,
      { "GanssReqGenericData", "pcap.GanssReqGenericData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssRealTimeIntegrity,
      { "ganssRealTimeIntegrity", "pcap.ganssRealTimeIntegrity",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssDifferentialCorrection,
      { "ganssDifferentialCorrection", "pcap.ganssDifferentialCorrection",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DGANSS_Sig_Id_Req", HFILL }},
    { &hf_pcap_ganssAlmanac,
      { "ganssAlmanac", "pcap.ganssAlmanac",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssNavigationModel,
      { "ganssNavigationModel", "pcap.ganssNavigationModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssTimeModelGnssGnss,
      { "ganssTimeModelGnssGnss", "pcap.ganssTimeModelGnssGnss",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_pcap_ganssReferenceMeasurementInfo,
      { "ganssReferenceMeasurementInfo", "pcap.ganssReferenceMeasurementInfo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssDataBits_01,
      { "ganssDataBits", "pcap.ganssDataBits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssUTCModel,
      { "ganssUTCModel", "pcap.ganssUTCModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssNavigationModelAdditionalData,
      { "ganssNavigationModelAdditionalData", "pcap.ganssNavigationModelAdditionalData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavigationModelGANSS", HFILL }},
    { &hf_pcap_dGANSSSignalBDS,
      { "dGANSSSignalBDS", "pcap.dGANSSSignalBDS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_orbitModelID,
      { "orbitModelID", "pcap.orbitModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_pcap_clockModelID,
      { "clockModelID", "pcap.clockModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_pcap_utcModelID,
      { "utcModelID", "pcap.utcModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_pcap_almanacModelID,
      { "almanacModelID", "pcap.almanacModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_pcap_dataBitAssistancelist_01,
      { "dataBitAssistancelist", "pcap.dataBitAssistancelist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReqDataBitAssistanceList", HFILL }},
    { &hf_pcap_reqDataBitAssistanceList_ganssSignalID,
      { "ganssSignalID", "pcap.reqDataBitAssistanceList.ganssSignalID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_ganssDataBitInterval,
      { "ganssDataBitInterval", "pcap.ganssDataBitInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_ganssSatelliteInfo,
      { "ganssSatelliteInfo", "pcap.ganssSatelliteInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssSatelliteInfo_item,
      { "ganssSatelliteInfo item", "pcap.ganssSatelliteInfo_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_type_01,
      { "type", "pcap.type",
        FT_UINT32, BASE_DEC, VALS(pcap_InformationReportCharacteristicsType_vals), 0,
        "InformationReportCharacteristicsType", HFILL }},
    { &hf_pcap_periodicity,
      { "periodicity", "pcap.periodicity",
        FT_UINT32, BASE_DEC, VALS(pcap_InformationReportPeriodicity_vals), 0,
        "InformationReportPeriodicity", HFILL }},
    { &hf_pcap_min,
      { "min", "pcap.min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_60_", HFILL }},
    { &hf_pcap_hour,
      { "hour", "pcap.hour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_24_", HFILL }},
    { &hf_pcap_implicitInformation,
      { "implicitInformation", "pcap.implicitInformation",
        FT_UINT32, BASE_DEC, VALS(pcap_MethodType_vals), 0,
        "MethodType", HFILL }},
    { &hf_pcap_explicitInformation,
      { "explicitInformation", "pcap.explicitInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExplicitInformationList", HFILL }},
    { &hf_pcap_ExplicitInformationList_item,
      { "ExplicitInformation", "pcap.ExplicitInformation",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_ExplicitInformation_vals_ext, 0,
        NULL, HFILL }},
    { &hf_pcap_almanacAndSatelliteHealth,
      { "almanacAndSatelliteHealth", "pcap.almanacAndSatelliteHealth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_utcModel,
      { "utcModel", "pcap.utcModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ionosphericModel,
      { "ionosphericModel", "pcap.ionosphericModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_navigationModel,
      { "navigationModel", "pcap.navigationModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_dgpsCorrections,
      { "dgpsCorrections", "pcap.dgpsCorrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_referenceTime_01,
      { "referenceTime", "pcap.referenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_acquisitionAssistance,
      { "acquisitionAssistance", "pcap.acquisitionAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_realTimeIntegrity,
      { "realTimeIntegrity", "pcap.realTimeIntegrity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_almanacAndSatelliteHealthSIB,
      { "almanacAndSatelliteHealthSIB", "pcap.almanacAndSatelliteHealthSIB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlmanacAndSatelliteHealthSIB_InfoType", HFILL }},
    { &hf_pcap_referenceLocation,
      { "referenceLocation", "pcap.referenceLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_Common_DataReq,
      { "ganss-Common-DataReq", "pcap.ganss_Common_DataReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSCommonDataReq", HFILL }},
    { &hf_pcap_ganss_Generic_DataList,
      { "ganss-Generic-DataList", "pcap.ganss_Generic_DataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSSGenericDataList", HFILL }},
    { &hf_pcap_transmissionGanssTimeIndicator,
      { "transmissionGanssTimeIndicator", "pcap.transmissionGanssTimeIndicator",
        FT_UINT32, BASE_DEC, VALS(pcap_TransmissionGanssTimeIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_dganss_sig_id_req,
      { "dganss-sig-id-req", "pcap.dganss_sig_id_req",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_ReferenceTime,
      { "ganss-ReferenceTime", "pcap.ganss_ReferenceTime",
        FT_UINT32, BASE_DEC, VALS(pcap_T_ganss_ReferenceTime_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_IonosphericModel,
      { "ganss-IonosphericModel", "pcap.ganss_IonosphericModel",
        FT_UINT32, BASE_DEC, VALS(pcap_T_ganss_IonosphericModel_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_ReferenceLocation,
      { "ganss-ReferenceLocation", "pcap.ganss_ReferenceLocation",
        FT_UINT32, BASE_DEC, VALS(pcap_T_ganss_ReferenceLocation_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_eopReq,
      { "eopReq", "pcap.eopReq",
        FT_UINT32, BASE_DEC, VALS(pcap_T_eopReq_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_GANSSGenericDataList_item,
      { "GANSSGenericDataReq", "pcap.GANSSGenericDataReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssID,
      { "ganssID", "pcap.ganssID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_realTimeIntegrity,
      { "ganss-realTimeIntegrity", "pcap.ganss_realTimeIntegrity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ganss_realTimeIntegrityReq", HFILL }},
    { &hf_pcap_ganss_dataBitAssistance,
      { "ganss-dataBitAssistance", "pcap.ganss_dataBitAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GanssDataBits", HFILL }},
    { &hf_pcap_dganssCorrections,
      { "dganssCorrections", "pcap.dganssCorrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DganssCorrectionsReq", HFILL }},
    { &hf_pcap_ganss_almanacAndSatelliteHealth,
      { "ganss-almanacAndSatelliteHealth", "pcap.ganss_almanacAndSatelliteHealth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ganss_almanacAndSatelliteHealthReq", HFILL }},
    { &hf_pcap_ganss_referenceMeasurementInfo,
      { "ganss-referenceMeasurementInfo", "pcap.ganss_referenceMeasurementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ganss_referenceMeasurementInfoReq", HFILL }},
    { &hf_pcap_ganss_utcModel,
      { "ganss-utcModel", "pcap.ganss_utcModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ganss_utcModelReq", HFILL }},
    { &hf_pcap_ganss_TimeModel_Gnss_Gnss,
      { "ganss-TimeModel-Gnss-Gnss", "pcap.ganss_TimeModel_Gnss_Gnss_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_navigationModel_01,
      { "navigationModel", "pcap.navigationModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavigationModelGANSS", HFILL }},
    { &hf_pcap_ganss_AddNavModelsReq,
      { "ganss-AddNavModelsReq", "pcap.ganss_AddNavModelsReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddNavigationModelsGANSS", HFILL }},
    { &hf_pcap_ganss_AddUtcModelsReq,
      { "ganss-AddUtcModelsReq", "pcap.ganss_AddUtcModelsReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_AuxInfoReq,
      { "ganss-AuxInfoReq", "pcap.ganss_AuxInfoReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_SBAS_ID,
      { "ganss-SBAS-ID", "pcap.ganss_SBAS_ID",
        FT_UINT32, BASE_DEC, VALS(pcap_GANSS_SBAS_ID_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_dBDS_Corrections,
      { "dBDS-Corrections", "pcap.dBDS_Corrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_bDS_Ionospheric_Grid_Model_Request,
      { "bDS-Ionospheric-Grid-Model-Request", "pcap.bDS_Ionospheric_Grid_Model_Request",
        FT_UINT32, BASE_DEC, VALS(pcap_BDS_Ionospheric_Grid_Model_Request_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ganssWeek,
      { "ganssWeek", "pcap.ganssWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_pcap_ganssTOE,
      { "ganssTOE", "pcap.ganssTOE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_167", HFILL }},
    { &hf_pcap_t_toe_limit,
      { "t-toe-limit", "pcap.t_toe_limit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_10", HFILL }},
    { &hf_pcap_addSatRelatedDataListGANSS,
      { "addSatRelatedDataListGANSS", "pcap.addSatRelatedDataListGANSS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddSatelliteRelatedDataListGANSS", HFILL }},
    { &hf_pcap_AddSatelliteRelatedDataListGANSS_item,
      { "AddSatelliteRelatedDataGANSS", "pcap.AddSatelliteRelatedDataGANSS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_dGANSS_Signal,
      { "dGANSS-Signal", "pcap.dGANSS_Signal",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_ganssTimeModelGnssGnssExt,
      { "ganssTimeModelGnssGnssExt", "pcap.ganssTimeModelGnssGnssExt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_pcap_transmissionTOWIndicator,
      { "transmissionTOWIndicator", "pcap.transmissionTOWIndicator",
        FT_UINT32, BASE_DEC, VALS(pcap_TransmissionTOWIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_navModelAdditionalData,
      { "navModelAdditionalData", "pcap.navModelAdditionalData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_TOE,
      { "gps-TOE", "pcap.gps_TOE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_167", HFILL }},
    { &hf_pcap_t_TOE_limit,
      { "t-TOE-limit", "pcap.t_TOE_limit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_10", HFILL }},
    { &hf_pcap_satRelatedDataList,
      { "satRelatedDataList", "pcap.satRelatedDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatelliteRelatedDataList", HFILL }},
    { &hf_pcap_SatelliteRelatedDataList_item,
      { "SatelliteRelatedData", "pcap.SatelliteRelatedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_satRelatedDataListGANSS,
      { "satRelatedDataListGANSS", "pcap.satRelatedDataListGANSS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatelliteRelatedDataListGANSS", HFILL }},
    { &hf_pcap_SatelliteRelatedDataListGANSS_item,
      { "SatelliteRelatedDataGANSS", "pcap.SatelliteRelatedDataGANSS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_MessageStructure_item,
      { "MessageStructure item", "pcap.MessageStructure_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_repetitionNumber_01,
      { "repetitionNumber", "pcap.repetitionNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageStructureRepetition", HFILL }},
    { &hf_pcap_measurementValidity,
      { "measurementValidity", "pcap.measurementValidity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_State,
      { "ue-State", "pcap.ue_State",
        FT_UINT32, BASE_DEC, VALS(pcap_T_ue_State_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_otdoa_ReferenceCellInfo,
      { "otdoa-ReferenceCellInfo", "pcap.otdoa_ReferenceCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_otdoa_NeighbourCellInfoList,
      { "otdoa-NeighbourCellInfoList", "pcap.otdoa_NeighbourCellInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_otdoa_MeasuredResultsSets,
      { "otdoa-MeasuredResultsSets", "pcap.otdoa_MeasuredResultsSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tUTRANGPSMeasurementValueInfo,
      { "tUTRANGPSMeasurementValueInfo", "pcap.tUTRANGPSMeasurementValueInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOA_NeighbourCellInfoList_item,
      { "OTDOA-NeighbourCellInfo", "pcap.OTDOA_NeighbourCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_relativeTimingDifferenceInfo,
      { "relativeTimingDifferenceInfo", "pcap.relativeTimingDifferenceInfo",
        FT_UINT32, BASE_DEC, VALS(pcap_RelativeTimingDifferenceInfo_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOA_MeasuredResultsSets_item,
      { "OTDOA-MeasuredResultsInfoList", "pcap.OTDOA_MeasuredResultsInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_OTDOA_MeasuredResultsInfoList_item,
      { "OTDOA-MeasuredResultsInfo", "pcap.OTDOA_MeasuredResultsInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_SFNSFNTimeDifferenceType2Info,
      { "ue-SFNSFNTimeDifferenceType2Info", "pcap.ue_SFNSFNTimeDifferenceType2Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_primaryCPICH_Info,
      { "primaryCPICH-Info", "pcap.primaryCPICH_Info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrimaryScramblingCode", HFILL }},
    { &hf_pcap_ue_SFNSFNTimeDifferenceType2,
      { "ue-SFNSFNTimeDifferenceType2", "pcap.ue_SFNSFNTimeDifferenceType2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_40961", HFILL }},
    { &hf_pcap_measurementDelay,
      { "measurementDelay", "pcap.measurementDelay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_pcap_rNC_ID,
      { "rNC-ID", "pcap.rNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_pcap_c_ID,
      { "c-ID", "pcap.c_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_pcap_sFNSFNMeasurementValueInfo,
      { "sFNSFNMeasurementValueInfo", "pcap.sFNSFNMeasurementValueInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tUTRANGANSSMeasurementValueInfo,
      { "tUTRANGANSSMeasurementValueInfo", "pcap.tUTRANGANSSMeasurementValueInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sFNSFNValue,
      { "sFNSFNValue", "pcap.sFNSFNValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sFNSFNQuality,
      { "sFNSFNQuality", "pcap.sFNSFNQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sFNSFNDriftRate,
      { "sFNSFNDriftRate", "pcap.sFNSFNDriftRate",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sFNSFNDriftRateQuality,
      { "sFNSFNDriftRateQuality", "pcap.sFNSFNDriftRateQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sFN,
      { "sFN", "pcap.sFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tUTRANGPS,
      { "tUTRANGPS", "pcap.tUTRANGPS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tUTRANGPSQuality,
      { "tUTRANGPSQuality", "pcap.tUTRANGPSQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tUTRANGPSDriftRate,
      { "tUTRANGPSDriftRate", "pcap.tUTRANGPSDriftRate",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tUTRANGPSDriftRateQuality,
      { "tUTRANGPSDriftRateQuality", "pcap.tUTRANGPSDriftRateQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ms_part,
      { "ms-part", "pcap.ms_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_pcap_ls_part,
      { "ls-part", "pcap.ls_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_pcap_tUTRANGANSS,
      { "tUTRANGANSS", "pcap.tUTRANGANSS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tUTRANGANSSQuality,
      { "tUTRANGANSSQuality", "pcap.tUTRANGANSSQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_tUTRANGANSSDriftRate,
      { "tUTRANGANSSDriftRate", "pcap.tUTRANGANSSDriftRate",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M50_50", HFILL }},
    { &hf_pcap_tUTRANGANSSDriftRateQuality,
      { "tUTRANGANSSDriftRateQuality", "pcap.tUTRANGANSSDriftRateQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_50", HFILL }},
    { &hf_pcap_timingAdvanceLCR_R7,
      { "timingAdvanceLCR-R7", "pcap.timingAdvanceLCR_R7",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_angleOfArrivalLCR,
      { "angleOfArrivalLCR", "pcap.angleOfArrivalLCR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_referenceNumber,
      { "referenceNumber", "pcap.referenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767_", HFILL }},
    { &hf_pcap_amountOutstandingRequests,
      { "amountOutstandingRequests", "pcap.amountOutstandingRequests",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999_", HFILL }},
    { &hf_pcap_reportingInterval,
      { "reportingInterval", "pcap.reportingInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999_", HFILL }},
    { &hf_pcap_reportingAmount,
      { "reportingAmount", "pcap.reportingAmount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999_", HFILL }},
    { &hf_pcap_additionalMethodType,
      { "additionalMethodType", "pcap.additionalMethodType",
        FT_UINT32, BASE_DEC, VALS(pcap_AdditionalMethodType_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_selectedPositionMethod,
      { "selectedPositionMethod", "pcap.selectedPositionMethod",
        FT_UINT32, BASE_DEC, VALS(pcap_SelectedPositionMethod_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_new_ue_State,
      { "new-ue-State", "pcap.new_ue_State",
        FT_UINT32, BASE_DEC, VALS(pcap_T_new_ue_State_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_gps_UTC_Model,
      { "gps-UTC-Model", "pcap.gps_UTC_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_Ionospheric_Model,
      { "gps-Ionospheric-Model", "pcap.gps_Ionospheric_Model_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_NavigationModel,
      { "gps-NavigationModel", "pcap.gps_NavigationModel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_dgpsCorrections_01,
      { "dgpsCorrections", "pcap.dgpsCorrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_referenceTime_02,
      { "referenceTime", "pcap.referenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPS_ReferenceTime", HFILL }},
    { &hf_pcap_gps_AcquisitionAssistance,
      { "gps-AcquisitionAssistance", "pcap.gps_AcquisitionAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_RealTime_Integrity,
      { "gps-RealTime-Integrity", "pcap.gps_RealTime_Integrity",
        FT_UINT32, BASE_DEC, VALS(pcap_GPS_RealTimeIntegrity_vals), 0,
        "GPS_RealTimeIntegrity", HFILL }},
    { &hf_pcap_almanacAndSatelliteHealthSIB_01,
      { "almanacAndSatelliteHealthSIB", "pcap.almanacAndSatelliteHealthSIB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gps_Transmission_TOW,
      { "gps-Transmission-TOW", "pcap.gps_Transmission_TOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_informationAvailable,
      { "informationAvailable", "pcap.informationAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_informationNotAvailable,
      { "informationNotAvailable", "pcap.informationNotAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_requestedDataValue,
      { "requestedDataValue", "pcap.requestedDataValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_event,
      { "event", "pcap.event",
        FT_UINT32, BASE_DEC, VALS(pcap_RequestTypeEvent_vals), 0,
        "RequestTypeEvent", HFILL }},
    { &hf_pcap_reportArea,
      { "reportArea", "pcap.reportArea",
        FT_UINT32, BASE_DEC, VALS(pcap_RequestTypeReportArea_vals), 0,
        "RequestTypeReportArea", HFILL }},
    { &hf_pcap_horizontalaccuracyCode,
      { "horizontalaccuracyCode", "pcap.horizontalaccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestTypeAccuracyCode", HFILL }},
    { &hf_pcap_standAloneLocationMethodsSupported,
      { "standAloneLocationMethodsSupported", "pcap.standAloneLocationMethodsSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ueBasedOTDOASupported,
      { "ueBasedOTDOASupported", "pcap.ueBasedOTDOASupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_networkAssistedGPSSupport,
      { "networkAssistedGPSSupport", "pcap.networkAssistedGPSSupport",
        FT_UINT32, BASE_DEC, VALS(pcap_NetworkAssistedGPSSuport_vals), 0,
        "NetworkAssistedGPSSuport", HFILL }},
    { &hf_pcap_supportGPSTimingOfCellFrame,
      { "supportGPSTimingOfCellFrame", "pcap.supportGPSTimingOfCellFrame",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_supportForIPDL,
      { "supportForIPDL", "pcap.supportForIPDL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_supportForRxTxTimeDiff,
      { "supportForRxTxTimeDiff", "pcap.supportForRxTxTimeDiff",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_supportForUEAGPSinCellPCH,
      { "supportForUEAGPSinCellPCH", "pcap.supportForUEAGPSinCellPCH",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_supportForSFNSFNTimeDiff,
      { "supportForSFNSFNTimeDiff", "pcap.supportForSFNSFNTimeDiff",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_NetworkAssistedGANSSSupport_item,
      { "NetworkAssistedGANSSSupport item", "pcap.NetworkAssistedGANSSSupport_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ganssMode,
      { "ganssMode", "pcap.ganssMode",
        FT_UINT32, BASE_DEC, VALS(pcap_T_ganssMode_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_networkAssistedGANSSSupport_item_ganssSignalID,
      { "ganssSignalID", "pcap.networkAssistedGANSSSupport.item.ganssSignalID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_SignalID", HFILL }},
    { &hf_pcap_supportGANSSTimingOfCellFrame,
      { "supportGANSSTimingOfCellFrame", "pcap.supportGANSSTimingOfCellFrame",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_supportGANSSCarrierPhaseMeasurement,
      { "supportGANSSCarrierPhaseMeasurement", "pcap.supportGANSSCarrierPhaseMeasurement",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_AddPosSupport_item,
      { "AddPosSupport-Element", "pcap.AddPosSupport_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_addPosID,
      { "addPosID", "pcap.addPosID",
        FT_UINT32, BASE_DEC, VALS(pcap_T_addPosID_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_addPosMode,
      { "addPosMode", "pcap.addPosMode",
        FT_UINT32, BASE_DEC, VALS(pcap_T_addPosMode_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ganss_sbas_ids,
      { "ganss-sbas-ids", "pcap.ganss_sbas_ids",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_ganss_signal_ids,
      { "ganss-signal-ids", "pcap.ganss_signal_ids",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_utdoa_BitCount,
      { "utdoa-BitCount", "pcap.utdoa_BitCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_utdoa_timeInterval,
      { "utdoa-timeInterval", "pcap.utdoa_timeInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gpsPositioningInstructions,
      { "gpsPositioningInstructions", "pcap.gpsPositioningInstructions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_horizontalAccuracyCode,
      { "horizontalAccuracyCode", "pcap.horizontalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_verticalAccuracyCode,
      { "verticalAccuracyCode", "pcap.verticalAccuracyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_gpsTimingOfCellWanted,
      { "gpsTimingOfCellWanted", "pcap.gpsTimingOfCellWanted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_additionalAssistanceDataRequest,
      { "additionalAssistanceDataRequest", "pcap.additionalAssistanceDataRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_ganssPositioningInstructions,
      { "ganssPositioningInstructions", "pcap.ganssPositioningInstructions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSS_PositioningInstructions", HFILL }},
    { &hf_pcap_ganssTimingOfCellWanted,
      { "ganssTimingOfCellWanted", "pcap.ganssTimingOfCellWanted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_gANSS_PositioningInstructions_additionalAssistanceDataRequest,
      { "additionalAssistanceDataRequest", "pcap.gANSS-PositioningInstructions.additionalAssistanceDataRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_pcap_uE_Positioning_OTDOA_AssistanceData,
      { "uE-Positioning-OTDOA-AssistanceData", "pcap.uE_Positioning_OTDOA_AssistanceData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_positioning_OTDOA_ReferenceCellInfo,
      { "ue-positioning-OTDOA-ReferenceCellInfo", "pcap.ue_positioning_OTDOA_ReferenceCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_positioning_OTDOA_NeighbourCellList,
      { "ue-positioning-OTDOA-NeighbourCellList", "pcap.ue_positioning_OTDOA_NeighbourCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_sfn_01,
      { "sfn", "pcap.sfn",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_modeSpecificInfo,
      { "modeSpecificInfo", "pcap.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(pcap_T_modeSpecificInfo_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_fdd_01,
      { "fdd", "pcap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_01", HFILL }},
    { &hf_pcap_tdd_01,
      { "tdd", "pcap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_01", HFILL }},
    { &hf_pcap_cellParameterID,
      { "cellParameterID", "pcap.cellParameterID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_frequencyInfo,
      { "frequencyInfo", "pcap.frequencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_positioningMode,
      { "positioningMode", "pcap.positioningMode",
        FT_UINT32, BASE_DEC, VALS(pcap_T_positioningMode_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ueBased,
      { "ueBased", "pcap.ueBased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_cellPosition,
      { "cellPosition", "pcap.cellPosition",
        FT_UINT32, BASE_DEC, VALS(pcap_ReferenceCellPosition_vals), 0,
        "ReferenceCellPosition", HFILL }},
    { &hf_pcap_roundTripTime_01,
      { "roundTripTime", "pcap.roundTripTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32766", HFILL }},
    { &hf_pcap_ueAssisted,
      { "ueAssisted", "pcap.ueAssisted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ue_positioning_IPDL_Paremeters,
      { "ue-positioning-IPDL-Paremeters", "pcap.ue_positioning_IPDL_Paremeters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UE_Positioning_IPDL_Parameters", HFILL }},
    { &hf_pcap_ellipsoidPoint,
      { "ellipsoidPoint", "pcap.ellipsoidPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalCoordinates", HFILL }},
    { &hf_pcap_ellipsoidPointWithAltitude,
      { "ellipsoidPointWithAltitude", "pcap.ellipsoidPointWithAltitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithAltitude", HFILL }},
    { &hf_pcap_modeSpecificInfo_01,
      { "modeSpecificInfo", "pcap.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(pcap_T_modeSpecificInfo_01_vals), 0,
        "T_modeSpecificInfo_01", HFILL }},
    { &hf_pcap_fdd_02,
      { "fdd", "pcap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_02", HFILL }},
    { &hf_pcap_ip_Spacing,
      { "ip-Spacing", "pcap.ip_Spacing",
        FT_UINT32, BASE_DEC, VALS(pcap_IP_Spacing_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ip_Length,
      { "ip-Length", "pcap.ip_Length",
        FT_UINT32, BASE_DEC, VALS(pcap_IP_Length_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ip_Offset,
      { "ip-Offset", "pcap.ip_Offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_pcap_seed,
      { "seed", "pcap.seed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_tdd_02,
      { "tdd", "pcap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_02", HFILL }},
    { &hf_pcap_burstModeParameters,
      { "burstModeParameters", "pcap.burstModeParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_burstStart,
      { "burstStart", "pcap.burstStart",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_burstLength,
      { "burstLength", "pcap.burstLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_10_25", HFILL }},
    { &hf_pcap_burstFreq,
      { "burstFreq", "pcap.burstFreq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_pcap_UE_Positioning_OTDOA_NeighbourCellList_item,
      { "UE-Positioning-OTDOA-NeighbourCellInfo", "pcap.UE_Positioning_OTDOA_NeighbourCellInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_modeSpecificInfo_02,
      { "modeSpecificInfo", "pcap.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(pcap_T_modeSpecificInfo_02_vals), 0,
        "T_modeSpecificInfo_02", HFILL }},
    { &hf_pcap_fdd_03,
      { "fdd", "pcap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_03", HFILL }},
    { &hf_pcap_tdd_03,
      { "tdd", "pcap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_03", HFILL }},
    { &hf_pcap_sfn_SFN_RelTimeDifference,
      { "sfn-SFN-RelTimeDifference", "pcap.sfn_SFN_RelTimeDifference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SFN_SFN_RelTimeDifference1", HFILL }},
    { &hf_pcap_sfn_Offset_Validity,
      { "sfn-Offset-Validity", "pcap.sfn_Offset_Validity",
        FT_UINT32, BASE_DEC, VALS(pcap_SFN_Offset_Validity_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_sfn_SFN_Drift,
      { "sfn-SFN-Drift", "pcap.sfn_SFN_Drift",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_SFN_SFN_Drift_vals_ext, 0,
        NULL, HFILL }},
    { &hf_pcap_searchWindowSize,
      { "searchWindowSize", "pcap.searchWindowSize",
        FT_UINT32, BASE_DEC, VALS(pcap_OTDOA_SearchWindowSize_vals), 0,
        "OTDOA_SearchWindowSize", HFILL }},
    { &hf_pcap_positioningMode_01,
      { "positioningMode", "pcap.positioningMode",
        FT_UINT32, BASE_DEC, VALS(pcap_T_positioningMode_01_vals), 0,
        "T_positioningMode_01", HFILL }},
    { &hf_pcap_ueBased_01,
      { "ueBased", "pcap.ueBased_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ueBased_01", HFILL }},
    { &hf_pcap_relativeNorth,
      { "relativeNorth", "pcap.relativeNorth",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M20000_20000", HFILL }},
    { &hf_pcap_relativeEast,
      { "relativeEast", "pcap.relativeEast",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M20000_20000", HFILL }},
    { &hf_pcap_relativeAltitude,
      { "relativeAltitude", "pcap.relativeAltitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4000_4000", HFILL }},
    { &hf_pcap_fineSFN_SFN,
      { "fineSFN-SFN", "pcap.fineSFN_SFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FineSFNSFN", HFILL }},
    { &hf_pcap_ueAssisted_01,
      { "ueAssisted", "pcap.ueAssisted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ueAssisted_01", HFILL }},
    { &hf_pcap_sfn_Offset,
      { "sfn-Offset", "pcap.sfn_Offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_pcap_sfn_sfn_Reltimedifference,
      { "sfn-sfn-Reltimedifference", "pcap.sfn_sfn_Reltimedifference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_38399", HFILL }},
    { &hf_pcap_uTDOA_ChannelSettings,
      { "uTDOA-ChannelSettings", "pcap.uTDOA_ChannelSettings",
        FT_UINT32, BASE_DEC, VALS(pcap_UTDOA_RRCState_vals), 0,
        "UTDOA_RRCState", HFILL }},
    { &hf_pcap_modeSpecificInfo_03,
      { "modeSpecificInfo", "pcap.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(pcap_T_modeSpecificInfo_03_vals), 0,
        "T_modeSpecificInfo_03", HFILL }},
    { &hf_pcap_fdd_04,
      { "fdd", "pcap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfoFDD", HFILL }},
    { &hf_pcap_tdd_04,
      { "tdd", "pcap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfoTDD", HFILL }},
    { &hf_pcap_uarfcn_UL,
      { "uarfcn-UL", "pcap.uarfcn_UL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_pcap_uarfcn_DL,
      { "uarfcn-DL", "pcap.uarfcn_DL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_pcap_uarfcn,
      { "uarfcn", "pcap.uarfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uTDOA_CELLDCH,
      { "uTDOA-CELLDCH", "pcap.uTDOA_CELLDCH_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uTDOA_CELLFACH,
      { "uTDOA-CELLFACH", "pcap.uTDOA_CELLFACH_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uL_DPCHInfo,
      { "uL-DPCHInfo", "pcap.uL_DPCHInfo",
        FT_UINT32, BASE_DEC, VALS(pcap_UL_DPCHInfo_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_compressedModeAssistanceData,
      { "compressedModeAssistanceData", "pcap.compressedModeAssistanceData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Compressed_Mode_Assistance_Data", HFILL }},
    { &hf_pcap_dCH_Information,
      { "dCH-Information", "pcap.dCH_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_e_DPCH_Information,
      { "e-DPCH-Information", "pcap.e_DPCH_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_fdd_05,
      { "fdd", "pcap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_04", HFILL }},
    { &hf_pcap_scramblingCodeType,
      { "scramblingCodeType", "pcap.scramblingCodeType",
        FT_UINT32, BASE_DEC, VALS(pcap_ScramblingCodeType_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_scramblingCode,
      { "scramblingCode", "pcap.scramblingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UL_ScramblingCode", HFILL }},
    { &hf_pcap_tfci_Existence,
      { "tfci-Existence", "pcap.tfci_Existence",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_numberOfFBI_Bits,
      { "numberOfFBI-Bits", "pcap.numberOfFBI_Bits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tdd_05,
      { "tdd", "pcap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_04", HFILL }},
    { &hf_pcap_tFCI_Coding,
      { "tFCI-Coding", "pcap.tFCI_Coding",
        FT_UINT32, BASE_DEC, VALS(pcap_TFCI_Coding_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_punctureLimit,
      { "punctureLimit", "pcap.punctureLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PuncturingLimit", HFILL }},
    { &hf_pcap_repetitionPeriod,
      { "repetitionPeriod", "pcap.repetitionPeriod",
        FT_UINT32, BASE_DEC, VALS(pcap_RepetitionPeriod_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_repetitionLength,
      { "repetitionLength", "pcap.repetitionLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tdd_DPCHOffset,
      { "tdd-DPCHOffset", "pcap.tdd_DPCHOffset",
        FT_UINT32, BASE_DEC, VALS(pcap_TDD_DPCHOffset_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_uL_Timeslot_Information,
      { "uL-Timeslot-Information", "pcap.uL_Timeslot_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_frameOffset,
      { "frameOffset", "pcap.frameOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_specialBurstScheduling,
      { "specialBurstScheduling", "pcap.specialBurstScheduling",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_dl_information,
      { "dl-information", "pcap.dl_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DL_InformationFDD", HFILL }},
    { &hf_pcap_ul_information,
      { "ul-information", "pcap.ul_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL_InformationFDD", HFILL }},
    { &hf_pcap_primaryScramblingCode,
      { "primaryScramblingCode", "pcap.primaryScramblingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_chipOffset,
      { "chipOffset", "pcap.chipOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_transmissionGapPatternSequenceInfo,
      { "transmissionGapPatternSequenceInfo", "pcap.transmissionGapPatternSequenceInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Transmission_Gap_Pattern_Sequence_Information", HFILL }},
    { &hf_pcap_activePatternSequenceInfo,
      { "activePatternSequenceInfo", "pcap.activePatternSequenceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Active_Pattern_Sequence_Information", HFILL }},
    { &hf_pcap_cFN,
      { "cFN", "pcap.cFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Transmission_Gap_Pattern_Sequence_Information_item,
      { "Transmission-Gap-Pattern-Sequence-Information item", "pcap.Transmission_Gap_Pattern_Sequence_Information_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tGPSID,
      { "tGPSID", "pcap.tGPSID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tGSN,
      { "tGSN", "pcap.tGSN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tGL1,
      { "tGL1", "pcap.tGL1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GapLength", HFILL }},
    { &hf_pcap_tGL2,
      { "tGL2", "pcap.tGL2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GapLength", HFILL }},
    { &hf_pcap_tGD,
      { "tGD", "pcap.tGD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tGPL1,
      { "tGPL1", "pcap.tGPL1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GapDuration", HFILL }},
    { &hf_pcap_uplink_Compressed_Mode_Method,
      { "uplink-Compressed-Mode-Method", "pcap.uplink_Compressed_Mode_Method",
        FT_UINT32, BASE_DEC, VALS(pcap_Uplink_Compressed_Mode_Method_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_cMConfigurationChangeCFN,
      { "cMConfigurationChangeCFN", "pcap.cMConfigurationChangeCFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CFN", HFILL }},
    { &hf_pcap_transmission_Gap_Pattern_Sequence_Status,
      { "transmission-Gap-Pattern-Sequence-Status", "pcap.transmission_Gap_Pattern_Sequence_Status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Transmission_Gap_Pattern_Sequence_Status_List", HFILL }},
    { &hf_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item,
      { "Transmission-Gap-Pattern-Sequence-Status-List item", "pcap.Transmission_Gap_Pattern_Sequence_Status_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tGPRC,
      { "tGPRC", "pcap.tGPRC",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tGCFN,
      { "tGCFN", "pcap.tGCFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CFN", HFILL }},
    { &hf_pcap_tFCS,
      { "tFCS", "pcap.tFCS",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_trChInfo,
      { "trChInfo", "pcap.trChInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrChInfoList", HFILL }},
    { &hf_pcap_TrChInfoList_item,
      { "UL-TrCHInfo", "pcap.UL_TrCHInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uL_TrCHtype,
      { "uL-TrCHtype", "pcap.uL_TrCHtype",
        FT_UINT32, BASE_DEC, VALS(pcap_UL_TrCHType_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_tfs,
      { "tfs", "pcap.tfs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportFormatSet", HFILL }},
    { &hf_pcap_maxSet_E_DPDCHs,
      { "maxSet-E-DPDCHs", "pcap.maxSet_E_DPDCHs",
        FT_UINT32, BASE_DEC, VALS(pcap_Max_Set_E_DPDCHs_vals), 0,
        "Max_Set_E_DPDCHs", HFILL }},
    { &hf_pcap_ul_PunctureLimit,
      { "ul-PunctureLimit", "pcap.ul_PunctureLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PuncturingLimit", HFILL }},
    { &hf_pcap_e_TFCS_Information,
      { "e-TFCS-Information", "pcap.e_TFCS_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_e_TTI,
      { "e-TTI", "pcap.e_TTI",
        FT_UINT32, BASE_DEC, VALS(pcap_E_TTI_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_e_DPCCH_PO,
      { "e-DPCCH-PO", "pcap.e_DPCCH_PO",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_e_DCH_TFCS_Index,
      { "e-DCH-TFCS-Index", "pcap.e_DCH_TFCS_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_reference_E_TFCI_Information,
      { "reference-E-TFCI-Information", "pcap.reference_E_TFCI_Information",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_Reference_E_TFCI_Information_item,
      { "Reference-E-TFCI-Information-Item", "pcap.Reference_E_TFCI_Information_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_reference_E_TFCI,
      { "reference-E-TFCI", "pcap.reference_E_TFCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "E_TFCI", HFILL }},
    { &hf_pcap_reference_E_TFCI_PO,
      { "reference-E-TFCI-PO", "pcap.reference_E_TFCI_PO",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_initialOffset,
      { "initialOffset", "pcap.initialOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_noinitialOffset,
      { "noinitialOffset", "pcap.noinitialOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_UL_Timeslot_Information_item,
      { "UL-Timeslot-InformationItem", "pcap.UL_Timeslot_InformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_timeSlot,
      { "timeSlot", "pcap.timeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_midambleShiftAndBurstType,
      { "midambleShiftAndBurstType", "pcap.midambleShiftAndBurstType",
        FT_UINT32, BASE_DEC, VALS(pcap_MidambleShiftAndBurstType_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_tFCI_Presence,
      { "tFCI-Presence", "pcap.tFCI_Presence",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pcap_uL_Code_InformationList,
      { "uL-Code-InformationList", "pcap.uL_Code_InformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TDD_UL_Code_Information", HFILL }},
    { &hf_pcap_type1,
      { "type1", "pcap.type1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_midambleConfigurationBurstType1And3,
      { "midambleConfigurationBurstType1And3", "pcap.midambleConfigurationBurstType1And3",
        FT_UINT32, BASE_DEC, VALS(pcap_MidambleConfigurationBurstType1And3_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_midambleAllocationMode,
      { "midambleAllocationMode", "pcap.midambleAllocationMode",
        FT_UINT32, BASE_DEC, VALS(pcap_T_midambleAllocationMode_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_defaultMidamble,
      { "defaultMidamble", "pcap.defaultMidamble_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_commonMidamble,
      { "commonMidamble", "pcap.commonMidamble_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ueSpecificMidamble,
      { "ueSpecificMidamble", "pcap.ueSpecificMidamble",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MidambleShiftLong", HFILL }},
    { &hf_pcap_type2,
      { "type2", "pcap.type2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_midambleConfigurationBurstType2,
      { "midambleConfigurationBurstType2", "pcap.midambleConfigurationBurstType2",
        FT_UINT32, BASE_DEC, VALS(pcap_MidambleConfigurationBurstType2_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_midambleAllocationMode_01,
      { "midambleAllocationMode", "pcap.midambleAllocationMode",
        FT_UINT32, BASE_DEC, VALS(pcap_T_midambleAllocationMode_01_vals), 0,
        "T_midambleAllocationMode_01", HFILL }},
    { &hf_pcap_ueSpecificMidamble_01,
      { "ueSpecificMidamble", "pcap.ueSpecificMidamble",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MidambleShiftShort", HFILL }},
    { &hf_pcap_type3,
      { "type3", "pcap.type3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_midambleAllocationMode_02,
      { "midambleAllocationMode", "pcap.midambleAllocationMode",
        FT_UINT32, BASE_DEC, VALS(pcap_T_midambleAllocationMode_02_vals), 0,
        "T_midambleAllocationMode_02", HFILL }},
    { &hf_pcap_TDD_UL_Code_Information_item,
      { "TDD-UL-Code-InformationItem", "pcap.TDD_UL_Code_InformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tdd_ChannelisationCode,
      { "tdd-ChannelisationCode", "pcap.tdd_ChannelisationCode",
        FT_UINT32, BASE_DEC|BASE_EXT_STRING, &pcap_TDD_ChannelisationCode_vals_ext, 0,
        NULL, HFILL }},
    { &hf_pcap_pRACHparameters,
      { "pRACHparameters", "pcap.pRACHparameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_cRNTI,
      { "cRNTI", "pcap.cRNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "C_RNTI", HFILL }},
    { &hf_pcap_uschParameters,
      { "uschParameters", "pcap.uschParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_PRACHparameters_item,
      { "PRACH-ChannelInfo", "pcap.PRACH_ChannelInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_pRACH_Info,
      { "pRACH-Info", "pcap.pRACH_Info",
        FT_UINT32, BASE_DEC, VALS(pcap_PRACH_Info_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_tFS,
      { "tFS", "pcap.tFS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportFormatSet", HFILL }},
    { &hf_pcap_fdd_06,
      { "fdd", "pcap.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_05", HFILL }},
    { &hf_pcap_availableSignatures,
      { "availableSignatures", "pcap.availableSignatures",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_availableSF,
      { "availableSF", "pcap.availableSF",
        FT_UINT32, BASE_DEC, VALS(pcap_SF_PRACH_vals), 0,
        "SF_PRACH", HFILL }},
    { &hf_pcap_preambleScramblingCodeWordNumber,
      { "preambleScramblingCodeWordNumber", "pcap.preambleScramblingCodeWordNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_puncturingLimit,
      { "puncturingLimit", "pcap.puncturingLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_availableSubChannelNumbers,
      { "availableSubChannelNumbers", "pcap.availableSubChannelNumbers",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tdd_06,
      { "tdd", "pcap.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_05", HFILL }},
    { &hf_pcap_maxPRACH_MidambleShifts,
      { "maxPRACH-MidambleShifts", "pcap.maxPRACH_MidambleShifts",
        FT_UINT32, BASE_DEC, VALS(pcap_MaxPRACH_MidambleShifts_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_pRACH_Midamble,
      { "pRACH-Midamble", "pcap.pRACH_Midamble",
        FT_UINT32, BASE_DEC, VALS(pcap_PRACH_Midamble_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_dynamicPart,
      { "dynamicPart", "pcap.dynamicPart",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransportFormatSet_DynamicPartList", HFILL }},
    { &hf_pcap_semi_staticPart,
      { "semi-staticPart", "pcap.semi_staticPart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportFormatSet_Semi_staticPart", HFILL }},
    { &hf_pcap_TransportFormatSet_DynamicPartList_item,
      { "TransportFormatSet-DynamicPartList item", "pcap.TransportFormatSet_DynamicPartList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_rlc_Size,
      { "rlc-Size", "pcap.rlc_Size",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_numberOfTbsTTIList,
      { "numberOfTbsTTIList", "pcap.numberOfTbsTTIList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo", HFILL }},
    { &hf_pcap_numberOfTbsTTIList_item,
      { "TbsTTIInfo", "pcap.TbsTTIInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_tTIInfo,
      { "tTIInfo", "pcap.tTIInfo",
        FT_UINT32, BASE_DEC, VALS(pcap_TransportFormatSet_TransmissionTimeIntervalDynamic_vals), 0,
        "TransportFormatSet_TransmissionTimeIntervalDynamic", HFILL }},
    { &hf_pcap_numberOfTbs,
      { "numberOfTbs", "pcap.numberOfTbs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransportFormatSet_NrOfTransportBlocks", HFILL }},
    { &hf_pcap_transmissionTimeInterval,
      { "transmissionTimeInterval", "pcap.transmissionTimeInterval",
        FT_UINT32, BASE_DEC, VALS(pcap_TransportFormatSet_TransmissionTimeIntervalSemiStatic_vals), 0,
        "TransportFormatSet_TransmissionTimeIntervalSemiStatic", HFILL }},
    { &hf_pcap_channelCoding,
      { "channelCoding", "pcap.channelCoding",
        FT_UINT32, BASE_DEC, VALS(pcap_TransportFormatSet_ChannelCodingType_vals), 0,
        "TransportFormatSet_ChannelCodingType", HFILL }},
    { &hf_pcap_codingRate,
      { "codingRate", "pcap.codingRate",
        FT_UINT32, BASE_DEC, VALS(pcap_TransportFormatSet_CodingRate_vals), 0,
        "TransportFormatSet_CodingRate", HFILL }},
    { &hf_pcap_rateMatchingAttribute,
      { "rateMatchingAttribute", "pcap.rateMatchingAttribute",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransportFormatSet_RateMatchingAttribute", HFILL }},
    { &hf_pcap_cRC_Size,
      { "cRC-Size", "pcap.cRC_Size",
        FT_UINT32, BASE_DEC, VALS(pcap_TransportFormatSet_CRC_Size_vals), 0,
        "TransportFormatSet_CRC_Size", HFILL }},
    { &hf_pcap_TFCS_item,
      { "CTFC", "pcap.CTFC",
        FT_UINT32, BASE_DEC, VALS(pcap_CTFC_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc2Bit,
      { "ctfc2Bit", "pcap.ctfc2Bit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc2Bit_item,
      { "ctfc2Bit item", "pcap.ctfc2Bit_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_pcap_ctfc4Bit,
      { "ctfc4Bit", "pcap.ctfc4Bit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc4Bit_item,
      { "ctfc4Bit item", "pcap.ctfc4Bit_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_pcap_ctfc6Bit,
      { "ctfc6Bit", "pcap.ctfc6Bit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc6Bit_item,
      { "ctfc6Bit item", "pcap.ctfc6Bit_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_pcap_ctfc8Bit,
      { "ctfc8Bit", "pcap.ctfc8Bit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc8Bit_item,
      { "ctfc8Bit item", "pcap.ctfc8Bit_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_ctfc12Bit,
      { "ctfc12Bit", "pcap.ctfc12Bit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc12Bit_item,
      { "ctfc12Bit item", "pcap.ctfc12Bit_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_pcap_ctfc16Bit,
      { "ctfc16Bit", "pcap.ctfc16Bit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc16Bit_item,
      { "ctfc16Bit item", "pcap.ctfc16Bit_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_pcap_ctfc24Bit,
      { "ctfc24Bit", "pcap.ctfc24Bit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_ctfc24Bit_item,
      { "ctfc24Bit item", "pcap.ctfc24Bit_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_pcap_uSCH_SchedulingOffset,
      { "uSCH-SchedulingOffset", "pcap.uSCH_SchedulingOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_horizontalVelocity,
      { "horizontalVelocity", "pcap.horizontalVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_horizontalWithVerticalVelocity,
      { "horizontalWithVerticalVelocity", "pcap.horizontalWithVerticalVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_horizontalVelocityWithUncertainty,
      { "horizontalVelocityWithUncertainty", "pcap.horizontalVelocityWithUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_horizontalWithVerticalVelocityAndUncertainty,
      { "horizontalWithVerticalVelocityAndUncertainty", "pcap.horizontalWithVerticalVelocityAndUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_horizontalSpeedAndBearing,
      { "horizontalSpeedAndBearing", "pcap.horizontalSpeedAndBearing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_verticalVelocity,
      { "verticalVelocity", "pcap.verticalVelocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_uncertaintySpeed,
      { "uncertaintySpeed", "pcap.uncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_horizontalUncertaintySpeed,
      { "horizontalUncertaintySpeed", "pcap.horizontalUncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_verticalUncertaintySpeed,
      { "verticalUncertaintySpeed", "pcap.verticalUncertaintySpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_bearing,
      { "bearing", "pcap.bearing",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_pcap_horizontalSpeed,
      { "horizontalSpeed", "pcap.horizontalSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_pcap_verticalSpeed,
      { "verticalSpeed", "pcap.verticalSpeed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_pcap_verticalSpeedDirection,
      { "verticalSpeedDirection", "pcap.verticalSpeedDirection",
        FT_UINT32, BASE_DEC, VALS(pcap_VerticalSpeedDirection_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_utran_GPSTimingOfCell,
      { "utran-GPSTimingOfCell", "pcap.utran_GPSTimingOfCell",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_2322431999999_", HFILL }},
    { &hf_pcap_ue_GPSTimingOfCell,
      { "ue-GPSTimingOfCell", "pcap.ue_GPSTimingOfCell",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_37158911999999_", HFILL }},
    { &hf_pcap_ue_GANSSTimingOfCell,
      { "ue-GANSSTimingOfCell", "pcap.ue_GANSSTimingOfCell",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_345599999999_", HFILL }},
    { &hf_pcap_ganss_Time_ID,
      { "ganss-Time-ID", "pcap.ganss_Time_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSID", HFILL }},
    { &hf_pcap_protocolIEs,
      { "protocolIEs", "pcap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_pcap_protocolExtensions,
      { "protocolExtensions", "pcap.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_pcap_referencePosition,
      { "referencePosition", "pcap.referencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RefPosition_InfEx_Rqst", HFILL }},
    { &hf_pcap_extension_InformationExchangeObjectType_InfEx_Rqst,
      { "extension-InformationExchangeObjectType-InfEx-Rqst", "pcap.extension_InformationExchangeObjectType_InfEx_Rqst_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_referencePositionEstimate,
      { "referencePositionEstimate", "pcap.referencePositionEstimate",
        FT_UINT32, BASE_DEC, VALS(pcap_UE_PositionEstimate_vals), 0,
        "UE_PositionEstimate", HFILL }},
    { &hf_pcap_referenceUC_ID,
      { "referenceUC-ID", "pcap.referenceUC_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UC_ID", HFILL }},
    { &hf_pcap_referencePosition_01,
      { "referencePosition", "pcap.referencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RefPosition_InfEx_Rsp", HFILL }},
    { &hf_pcap_referencePosition_02,
      { "referencePosition", "pcap.referencePosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RefPosition_InfEx_Rprt", HFILL }},
    { &hf_pcap_requestedDataValueInformation,
      { "requestedDataValueInformation", "pcap.requestedDataValueInformation",
        FT_UINT32, BASE_DEC, VALS(pcap_RequestedDataValueInformation_vals), 0,
        NULL, HFILL }},
    { &hf_pcap_privateIEs,
      { "privateIEs", "pcap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_pcap_initiatingMessage,
      { "initiatingMessage", "pcap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_successfulOutcome,
      { "successfulOutcome", "pcap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "pcap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_outcome,
      { "outcome", "pcap.outcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pcap_initiatingMessagevalue,
      { "value", "pcap.initiatingMessagevalue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_pcap_successfulOutcome_value,
      { "value", "pcap.successfulOutcome_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_pcap_unsuccessfulOutcome_value,
      { "value", "pcap.unsuccessfulOutcome_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
    { &hf_pcap_outcome_value,
      { "value", "pcap.outcome_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Outcome_value", HFILL }},
    { &hf_pcap_AvailableSignatures_signature15,
      { "signature15", "pcap.AvailableSignatures.signature15",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature14,
      { "signature14", "pcap.AvailableSignatures.signature14",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature13,
      { "signature13", "pcap.AvailableSignatures.signature13",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature12,
      { "signature12", "pcap.AvailableSignatures.signature12",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature11,
      { "signature11", "pcap.AvailableSignatures.signature11",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature10,
      { "signature10", "pcap.AvailableSignatures.signature10",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature9,
      { "signature9", "pcap.AvailableSignatures.signature9",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature8,
      { "signature8", "pcap.AvailableSignatures.signature8",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature7,
      { "signature7", "pcap.AvailableSignatures.signature7",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature6,
      { "signature6", "pcap.AvailableSignatures.signature6",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature5,
      { "signature5", "pcap.AvailableSignatures.signature5",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature4,
      { "signature4", "pcap.AvailableSignatures.signature4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature3,
      { "signature3", "pcap.AvailableSignatures.signature3",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature2,
      { "signature2", "pcap.AvailableSignatures.signature2",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature1,
      { "signature1", "pcap.AvailableSignatures.signature1",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_pcap_AvailableSignatures_signature0,
      { "signature0", "pcap.AvailableSignatures.signature0",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh11,
      { "subCh11", "pcap.AvailableSubChannelNumbers.subCh11",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh10,
      { "subCh10", "pcap.AvailableSubChannelNumbers.subCh10",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh9,
      { "subCh9", "pcap.AvailableSubChannelNumbers.subCh9",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh8,
      { "subCh8", "pcap.AvailableSubChannelNumbers.subCh8",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh7,
      { "subCh7", "pcap.AvailableSubChannelNumbers.subCh7",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh6,
      { "subCh6", "pcap.AvailableSubChannelNumbers.subCh6",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh5,
      { "subCh5", "pcap.AvailableSubChannelNumbers.subCh5",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh4,
      { "subCh4", "pcap.AvailableSubChannelNumbers.subCh4",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh3,
      { "subCh3", "pcap.AvailableSubChannelNumbers.subCh3",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh2,
      { "subCh2", "pcap.AvailableSubChannelNumbers.subCh2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh1,
      { "subCh1", "pcap.AvailableSubChannelNumbers.subCh1",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pcap_AvailableSubChannelNumbers_subCh0,
      { "subCh0", "pcap.AvailableSubChannelNumbers.subCh0",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
		  &ett_pcap,
    &ett_pcap_PrivateIE_ID,
    &ett_pcap_TransactionID,
    &ett_pcap_ProtocolIE_Container,
    &ett_pcap_ProtocolIE_Field,
    &ett_pcap_ProtocolExtensionContainer,
    &ett_pcap_ProtocolExtensionField,
    &ett_pcap_PrivateIE_Container,
    &ett_pcap_PrivateIE_Field,
    &ett_pcap_AddPos_MeasuredResults,
    &ett_pcap_AddPos_MeasuredResults_Element,
    &ett_pcap_T_type,
    &ett_pcap_T_barometricPressure,
    &ett_pcap_T_wlan,
    &ett_pcap_T_bt,
    &ett_pcap_T_mbs,
    &ett_pcap_WLANMeasurementList,
    &ett_pcap_WLANMeasurementList_Element,
    &ett_pcap_BTMeasurementList,
    &ett_pcap_BTMeasurementList_Element,
    &ett_pcap_MBSMeasurementList,
    &ett_pcap_MBSMeasurementList_Element,
    &ett_pcap_AlmanacAndSatelliteHealthSIB,
    &ett_pcap_Cause,
    &ett_pcap_CellId_MeasuredResultsSets,
    &ett_pcap_CellId_MeasuredResultsInfoList,
    &ett_pcap_CellId_MeasuredResultsInfo,
    &ett_pcap_RoundTripTimeInfo,
    &ett_pcap_RoundTripTimeInfoWithType1,
    &ett_pcap_UE_PositioningMeasQuality,
    &ett_pcap_UTRANAccessPointPositionAltitude,
    &ett_pcap_RxTimingDeviationInfo,
    &ett_pcap_RxTimingDeviationLCRInfo,
    &ett_pcap_RxTimingDeviation768Info,
    &ett_pcap_RxTimingDeviation384extInfo,
    &ett_pcap_AddMeasurementInfo,
    &ett_pcap_AngleOfArrivalLCR,
    &ett_pcap_CellId_IRATMeasuredResultsSets,
    &ett_pcap_CellId_IRATMeasuredResultsInfoList,
    &ett_pcap_GERAN_MeasuredResultsInfoList,
    &ett_pcap_GERAN_MeasuredResultsInfo,
    &ett_pcap_GERANCellGlobalID,
    &ett_pcap_GERANPhysicalCellID,
    &ett_pcap_GSM_BSIC,
    &ett_pcap_CellIDPositioning,
    &ett_pcap_RequestedCellIDMeasurements,
    &ett_pcap_T_fdd,
    &ett_pcap_T_tdd,
    &ett_pcap_RequestedCellIDGERANMeasurements,
    &ett_pcap_CriticalityDiagnostics,
    &ett_pcap_CriticalityDiagnostics_IE_List,
    &ett_pcap_CriticalityDiagnostics_IE_List_item,
    &ett_pcap_DGPSCorrections,
    &ett_pcap_DGPS_CorrectionSatInfoList,
    &ett_pcap_DGPS_CorrectionSatInfo,
    &ett_pcap_DGNSS_ValidityPeriod,
    &ett_pcap_UE_PositionEstimate,
    &ett_pcap_GeographicalCoordinates,
    &ett_pcap_GA_AltitudeAndDirection,
    &ett_pcap_GA_EllipsoidArc,
    &ett_pcap_GA_Point,
    &ett_pcap_GA_PointWithAltitude,
    &ett_pcap_GA_PointWithAltitudeAndUncertaintyEllipsoid,
    &ett_pcap_GA_PointWithUnCertainty,
    &ett_pcap_GA_PointWithUnCertaintyEllipse,
    &ett_pcap_GA_Polygon,
    &ett_pcap_GA_Polygon_item,
    &ett_pcap_GA_UncertaintyEllipse,
    &ett_pcap_UE_PositionEstimateInfo,
    &ett_pcap_ReferenceTimeChoice,
    &ett_pcap_Cell_Timing,
    &ett_pcap_GANSS_Reference_Time_Only,
    &ett_pcap_PositionDataUEbased,
    &ett_pcap_PositionData,
    &ett_pcap_GANSS_PositioningDataSet,
    &ett_pcap_PositioningDataSet,
    &ett_pcap_Additional_PositioningDataSet,
    &ett_pcap_GPS_AcquisitionAssistance,
    &ett_pcap_AcquisitionSatInfoList,
    &ett_pcap_AcquisitionSatInfo,
    &ett_pcap_ExtraDopplerInfo,
    &ett_pcap_ExtraDopplerInfoExtension,
    &ett_pcap_AzimuthAndElevation,
    &ett_pcap_AzimuthAndElevationLSB,
    &ett_pcap_AuxInfoGANSS_ID1,
    &ett_pcap_AuxInfoGANSS_ID1_element,
    &ett_pcap_AuxInfoGANSS_ID3,
    &ett_pcap_AuxInfoGANSS_ID3_element,
    &ett_pcap_CNAVclockModel,
    &ett_pcap_DeltaUT1,
    &ett_pcap_DGANSS_Corrections,
    &ett_pcap_DGANSS_Information,
    &ett_pcap_DGANSS_InformationItem,
    &ett_pcap_DGANSS_SignalInformation,
    &ett_pcap_DGANSS_SignalInformationItem,
    &ett_pcap_GANSS_AddClockModels,
    &ett_pcap_GANSS_AddOrbitModels,
    &ett_pcap_GANSS_Additional_Ionospheric_Model,
    &ett_pcap_GANSS_Additional_Navigation_Models,
    &ett_pcap_GANSS_Additional_Time_Models,
    &ett_pcap_GANSS_Additional_UTC_Models,
    &ett_pcap_GANSS_ALM_BDSKeplericanset,
    &ett_pcap_Satellite_Information_BDS_KP_List,
    &ett_pcap_Satellite_Information_BDS_KP_Item,
    &ett_pcap_GANSS_ALM_ECEFsbasAlmanacSet,
    &ett_pcap_GANSS_ALM_GlonassAlmanacSet,
    &ett_pcap_GANSS_ALM_MidiAlmanacSet,
    &ett_pcap_GANSS_ALM_NAVKeplerianSet,
    &ett_pcap_GANSS_ALM_ReducedKeplerianSet,
    &ett_pcap_GANSS_AlmanacAndSatelliteHealth,
    &ett_pcap_GANSS_AlmanacModel,
    &ett_pcap_GANSS_Auxiliary_Information,
    &ett_pcap_GANSS_AzimuthAndElevation,
    &ett_pcap_GANSS_Clock_Model,
    &ett_pcap_GANSS_CommonAssistanceData,
    &ett_pcap_GANSS_Data_Bit_Assistance,
    &ett_pcap_GANSS_DataBitAssistanceList,
    &ett_pcap_GANSS_DataBitAssistanceItem,
    &ett_pcap_GANSS_DataBitAssistanceSgnList,
    &ett_pcap_GANSS_DataBitAssistanceSgnItem,
    &ett_pcap_GANSS_Earth_Orientation_Parameters,
    &ett_pcap_GANSS_ExtraDoppler,
    &ett_pcap_GANSS_ExtraDopplerExtension,
    &ett_pcap_GANSS_GenericAssistanceDataList,
    &ett_pcap_GANSSGenericAssistanceData,
    &ett_pcap_BDS_Ionospheric_Grid_Model,
    &ett_pcap_BDS_Ionospheric_Grid_Information,
    &ett_pcap_BDS_Ionospheric_Grid_Information_item,
    &ett_pcap_DBDS_Correction_Information,
    &ett_pcap_DBDS_Information,
    &ett_pcap_DBDS_Information_item,
    &ett_pcap_DGANSS_Signal_Information,
    &ett_pcap_DGANSS_Signal_Information_item,
    &ett_pcap_GANSS_GenericMeasurementInfo,
    &ett_pcap_GANSS_GenericMeasurementInfo_item,
    &ett_pcap_GANSSID,
    &ett_pcap_GANSSMeasurementSignalList,
    &ett_pcap_GANSSMeasurementSignalList_item,
    &ett_pcap_GanssCodePhaseAmbiguityExt,
    &ett_pcap_GANSS_Ionospheric_Model,
    &ett_pcap_GANSS_IonosphereRegionalStormFlags,
    &ett_pcap_GANSS_KeplerianParametersAlm,
    &ett_pcap_GANSS_KeplerianParametersOrb,
    &ett_pcap_GANSS_MeasurementParameters,
    &ett_pcap_GANSS_MeasurementParametersItem,
    &ett_pcap_GanssIntegerCodePhaseExt,
    &ett_pcap_GANSS_MeasuredResultsList,
    &ett_pcap_GANSS_MeasuredResults,
    &ett_pcap_T_referenceTime,
    &ett_pcap_GANSS_Navigation_Model,
    &ett_pcap_GANSS_Orbit_Model,
    &ett_pcap_GANSS_Real_Time_Integrity,
    &ett_pcap_GANSS_RealTimeInformationItem,
    &ett_pcap_GANSS_Reference_Location,
    &ett_pcap_GANSS_ReferenceMeasurementInfo,
    &ett_pcap_GANSS_Reference_Time,
    &ett_pcap_GANSS_ReferenceTimeOnly,
    &ett_pcap_GANSS_SatelliteClockModelItem,
    &ett_pcap_GANSS_SatelliteInformation,
    &ett_pcap_GANSS_SatelliteInformationItem,
    &ett_pcap_GANSS_SatelliteInformationKP,
    &ett_pcap_GANSS_SatelliteInformationKPItem,
    &ett_pcap_GANSS_SAT_Info_Almanac_GLOkpList,
    &ett_pcap_GANSS_SAT_Info_Almanac_GLOkp,
    &ett_pcap_GANSS_SAT_Info_Almanac_MIDIkpList,
    &ett_pcap_GANSS_SAT_Info_Almanac_MIDIkp,
    &ett_pcap_GANSS_SAT_Info_Almanac_NAVkpList,
    &ett_pcap_GANSS_SAT_Info_Almanac_NAVkp,
    &ett_pcap_GANSS_SAT_Info_Almanac_REDkpList,
    &ett_pcap_GANSS_SAT_Info_Almanac_REDkp,
    &ett_pcap_GANSS_SAT_Info_Almanac_SBASecefList,
    &ett_pcap_GANSS_SAT_Info_Almanac_SBASecef,
    &ett_pcap_Ganss_Sat_Info_AddNavList,
    &ett_pcap_Ganss_Sat_Info_AddNavList_item,
    &ett_pcap_GANSS_Sat_Info_Nav,
    &ett_pcap_GANSS_Sat_Info_Nav_item,
    &ett_pcap_GANSS_SignalID,
    &ett_pcap_GANSS_Time_Model,
    &ett_pcap_GANSS_UTRAN_TRU,
    &ett_pcap_GANSS_UTC_Model,
    &ett_pcap_GLONASSclockModel,
    &ett_pcap_NAVclockModel,
    &ett_pcap_NavModel_CNAVKeplerianSet,
    &ett_pcap_NavModel_GLONASSecef,
    &ett_pcap_NavModel_NAVKeplerianSet,
    &ett_pcap_NavModel_SBASecef,
    &ett_pcap_NavModel_BDSKeplerianSet,
    &ett_pcap_SBASclockModel,
    &ett_pcap_BDSClockModel,
    &ett_pcap_UTCmodelSet1,
    &ett_pcap_UTCmodelSet2,
    &ett_pcap_UTCmodelSet3,
    &ett_pcap_UTCmodelSet4,
    &ett_pcap_UTRAN_GANSSReferenceTimeDL,
    &ett_pcap_UTRAN_GANSSReferenceTimeUL,
    &ett_pcap_GPS_AlmanacAndSatelliteHealth,
    &ett_pcap_AlmanacSatInfoList,
    &ett_pcap_AlmanacSatInfo,
    &ett_pcap_GPS_ClockAndEphemerisParameters,
    &ett_pcap_SubFrame1Reserved,
    &ett_pcap_GPS_Ionospheric_Model,
    &ett_pcap_MeasuredResultsList,
    &ett_pcap_GPS_MeasuredResults,
    &ett_pcap_GPS_MeasurementParamList,
    &ett_pcap_GPS_MeasurementParam,
    &ett_pcap_GPS_NavigationModel,
    &ett_pcap_NavigationModelSatInfo,
    &ett_pcap_GPS_RealTimeIntegrity,
    &ett_pcap_BadSatList,
    &ett_pcap_GPS_ReferenceLocation,
    &ett_pcap_GPS_ReferenceTime,
    &ett_pcap_GPS_TOW_AssistList,
    &ett_pcap_GPS_TOW_Assist,
    &ett_pcap_GPSReferenceTimeUncertainty,
    &ett_pcap_GPS_UTC_Model,
    &ett_pcap_AdditionalGPSAssistDataRequired,
    &ett_pcap_AdditionalGanssAssistDataRequired,
    &ett_pcap_GANSSReq_AddIonosphericModel,
    &ett_pcap_GanssRequestedGenericAssistanceDataList,
    &ett_pcap_GanssReqGenericData,
    &ett_pcap_DBDSCorrection,
    &ett_pcap_GANSS_AddADchoices,
    &ett_pcap_GanssDataBits,
    &ett_pcap_ReqDataBitAssistanceList,
    &ett_pcap_T_ganssSatelliteInfo,
    &ett_pcap_InformationReportCharacteristics,
    &ett_pcap_InformationReportPeriodicity,
    &ett_pcap_InformationType,
    &ett_pcap_ExplicitInformationList,
    &ett_pcap_ExplicitInformation,
    &ett_pcap_DganssCorrectionsReq,
    &ett_pcap_Ganss_almanacAndSatelliteHealthReq,
    &ett_pcap_GANSSCommonDataReq,
    &ett_pcap_GANSS_AddIonoModelReq,
    &ett_pcap_GANSS_EarthOrientParaReq,
    &ett_pcap_GANSSGenericDataList,
    &ett_pcap_GANSSGenericDataReq,
    &ett_pcap_AddNavigationModelsGANSS,
    &ett_pcap_AddSatelliteRelatedDataListGANSS,
    &ett_pcap_AddSatelliteRelatedDataGANSS,
    &ett_pcap_DBDS_Corrections,
    &ett_pcap_GANSS_AddUtcModelsReq,
    &ett_pcap_GANSS_AuxInfoReq,
    &ett_pcap_Ganss_utcModelReq,
    &ett_pcap_Ganss_realTimeIntegrityReq,
    &ett_pcap_Ganss_referenceMeasurementInfoReq,
    &ett_pcap_Ganss_TimeModel_Gnss_Gnss,
    &ett_pcap_UtcModel,
    &ett_pcap_IonosphericModel,
    &ett_pcap_NavigationModel,
    &ett_pcap_NavModelAdditionalData,
    &ett_pcap_SatelliteRelatedDataList,
    &ett_pcap_SatelliteRelatedData,
    &ett_pcap_NavigationModelGANSS,
    &ett_pcap_SatelliteRelatedDataListGANSS,
    &ett_pcap_SatelliteRelatedDataGANSS,
    &ett_pcap_AlmanacAndSatelliteHealthSIB_InfoType,
    &ett_pcap_MessageStructure,
    &ett_pcap_MessageStructure_item,
    &ett_pcap_MeasInstructionsUsed,
    &ett_pcap_MeasurementValidity,
    &ett_pcap_OTDOA_MeasurementGroup,
    &ett_pcap_OTDOA_ReferenceCellInfo,
    &ett_pcap_OTDOA_ReferenceCellInfoSAS_centric,
    &ett_pcap_OTDOA_NeighbourCellInfoList,
    &ett_pcap_OTDOA_NeighbourCellInfo,
    &ett_pcap_OTDOA_MeasuredResultsSets,
    &ett_pcap_OTDOA_MeasuredResultsInfoList,
    &ett_pcap_OTDOA_MeasuredResultsInfo,
    &ett_pcap_OTDOA_AddMeasuredResultsInfo,
    &ett_pcap_UE_SFNSFNTimeDifferenceType2Info,
    &ett_pcap_UC_ID,
    &ett_pcap_RelativeTimingDifferenceInfo,
    &ett_pcap_SFNSFNMeasurementValueInfo,
    &ett_pcap_TUTRANGPSMeasurementValueInfo,
    &ett_pcap_TUTRANGPS,
    &ett_pcap_TUTRANGANSSMeasurementValueInfo,
    &ett_pcap_TUTRANGANSS,
    &ett_pcap_AdditionalMeasurementInforLCR,
    &ett_pcap_PeriodicPosCalcInfo,
    &ett_pcap_PeriodicLocationInfo,
    &ett_pcap_PositioningMethod,
    &ett_pcap_RRCstateChange,
    &ett_pcap_RequestedDataValue,
    &ett_pcap_RequestedDataValueInformation,
    &ett_pcap_InformationAvailable,
    &ett_pcap_RequestType,
    &ett_pcap_UE_PositioningCapability,
    &ett_pcap_NetworkAssistedGANSSSupport,
    &ett_pcap_NetworkAssistedGANSSSupport_item,
    &ett_pcap_AddPosSupport,
    &ett_pcap_AddPosSupport_Element,
    &ett_pcap_GANSS_SBAS_IDs,
    &ett_pcap_GANSS_Signal_IDs,
    &ett_pcap_UTDOAPositioning,
    &ett_pcap_GPSPositioning,
    &ett_pcap_GPSPositioningInstructions,
    &ett_pcap_GANSSPositioning,
    &ett_pcap_GANSS_PositioningInstructions,
    &ett_pcap_OTDOAAssistanceData,
    &ett_pcap_UE_Positioning_OTDOA_AssistanceData,
    &ett_pcap_UE_Positioning_OTDOA_ReferenceCellInfo,
    &ett_pcap_T_modeSpecificInfo,
    &ett_pcap_T_fdd_01,
    &ett_pcap_T_tdd_01,
    &ett_pcap_T_positioningMode,
    &ett_pcap_T_ueBased,
    &ett_pcap_T_ueAssisted,
    &ett_pcap_ReferenceCellPosition,
    &ett_pcap_UE_Positioning_IPDL_Parameters,
    &ett_pcap_T_modeSpecificInfo_01,
    &ett_pcap_T_fdd_02,
    &ett_pcap_T_tdd_02,
    &ett_pcap_BurstModeParameters,
    &ett_pcap_UE_Positioning_OTDOA_NeighbourCellList,
    &ett_pcap_UE_Positioning_OTDOA_NeighbourCellInfo,
    &ett_pcap_T_modeSpecificInfo_02,
    &ett_pcap_T_fdd_03,
    &ett_pcap_T_tdd_03,
    &ett_pcap_T_positioningMode_01,
    &ett_pcap_T_ueBased_01,
    &ett_pcap_T_ueAssisted_01,
    &ett_pcap_SFN_SFN_RelTimeDifference1,
    &ett_pcap_UTDOA_Group,
    &ett_pcap_FrequencyInfo,
    &ett_pcap_T_modeSpecificInfo_03,
    &ett_pcap_FrequencyInfoFDD,
    &ett_pcap_FrequencyInfoTDD,
    &ett_pcap_UTDOA_RRCState,
    &ett_pcap_UTDOA_CELLDCH,
    &ett_pcap_UL_DPCHInfo,
    &ett_pcap_T_fdd_04,
    &ett_pcap_T_tdd_04,
    &ett_pcap_Compressed_Mode_Assistance_Data,
    &ett_pcap_DL_InformationFDD,
    &ett_pcap_UL_InformationFDD,
    &ett_pcap_Transmission_Gap_Pattern_Sequence_Information,
    &ett_pcap_Transmission_Gap_Pattern_Sequence_Information_item,
    &ett_pcap_Active_Pattern_Sequence_Information,
    &ett_pcap_Transmission_Gap_Pattern_Sequence_Status_List,
    &ett_pcap_Transmission_Gap_Pattern_Sequence_Status_List_item,
    &ett_pcap_DCH_Information,
    &ett_pcap_TrChInfoList,
    &ett_pcap_UL_TrCHInfo,
    &ett_pcap_E_DPCH_Information,
    &ett_pcap_E_TFCS_Information,
    &ett_pcap_Reference_E_TFCI_Information,
    &ett_pcap_Reference_E_TFCI_Information_Item,
    &ett_pcap_TDD_DPCHOffset,
    &ett_pcap_UL_Timeslot_Information,
    &ett_pcap_UL_Timeslot_InformationItem,
    &ett_pcap_MidambleShiftAndBurstType,
    &ett_pcap_T_type1,
    &ett_pcap_T_midambleAllocationMode,
    &ett_pcap_T_type2,
    &ett_pcap_T_midambleAllocationMode_01,
    &ett_pcap_T_type3,
    &ett_pcap_T_midambleAllocationMode_02,
    &ett_pcap_TDD_UL_Code_Information,
    &ett_pcap_TDD_UL_Code_InformationItem,
    &ett_pcap_UTDOA_CELLFACH,
    &ett_pcap_PRACHparameters,
    &ett_pcap_PRACH_ChannelInfo,
    &ett_pcap_PRACH_Info,
    &ett_pcap_T_fdd_05,
    &ett_pcap_T_tdd_05,
    &ett_pcap_AvailableSignatures,
    &ett_pcap_AvailableSubChannelNumbers,
    &ett_pcap_TransportFormatSet,
    &ett_pcap_TransportFormatSet_DynamicPartList,
    &ett_pcap_TransportFormatSet_DynamicPartList_item,
    &ett_pcap_SEQUENCE_SIZE_1_maxNrOfTFs_OF_TbsTTIInfo,
    &ett_pcap_TbsTTIInfo,
    &ett_pcap_TransportFormatSet_Semi_staticPart,
    &ett_pcap_TFCS,
    &ett_pcap_CTFC,
    &ett_pcap_T_ctfc2Bit,
    &ett_pcap_T_ctfc4Bit,
    &ett_pcap_T_ctfc6Bit,
    &ett_pcap_T_ctfc8Bit,
    &ett_pcap_T_ctfc12Bit,
    &ett_pcap_T_ctfc16Bit,
    &ett_pcap_T_ctfc24Bit,
    &ett_pcap_UschParameters,
    &ett_pcap_VelocityEstimate,
    &ett_pcap_HorizontalVelocity,
    &ett_pcap_HorizontalWithVerticalVelocity,
    &ett_pcap_HorizontalVelocityWithUncertainty,
    &ett_pcap_HorizontalWithVerticalVelocityAndUncertainty,
    &ett_pcap_HorizontalSpeedAndBearing,
    &ett_pcap_VerticalVelocity,
    &ett_pcap_UTRAN_GPSReferenceTime,
    &ett_pcap_UTRAN_GPSReferenceTimeResult,
    &ett_pcap_UTRAN_GANSSReferenceTimeResult,
    &ett_pcap_PositionCalculationRequest,
    &ett_pcap_PositionCalculationResponse,
    &ett_pcap_PositionCalculationFailure,
    &ett_pcap_InformationExchangeInitiationRequest,
    &ett_pcap_InformationExchangeObjectType_InfEx_Rqst,
    &ett_pcap_RefPosition_InfEx_Rqst,
    &ett_pcap_UC_ID_InfEx_Rqst,
    &ett_pcap_InformationExchangeInitiationResponse,
    &ett_pcap_InformationExchangeObjectType_InfEx_Rsp,
    &ett_pcap_RefPosition_InfEx_Rsp,
    &ett_pcap_InformationExchangeInitiationFailure,
    &ett_pcap_PositionInitiationRequest,
    &ett_pcap_PositionInitiationResponse,
    &ett_pcap_PositionInitiationFailure,
    &ett_pcap_PositionActivationRequest,
    &ett_pcap_PositionActivationResponse,
    &ett_pcap_PositionActivationFailure,
    &ett_pcap_InformationReport,
    &ett_pcap_InformationExchangeObjectType_InfEx_Rprt,
    &ett_pcap_RefPosition_InfEx_Rprt,
    &ett_pcap_InformationExchangeTerminationRequest,
    &ett_pcap_InformationExchangeFailureIndication,
    &ett_pcap_ErrorIndication,
    &ett_pcap_PositionParameterModification,
    &ett_pcap_PrivateMessage,
    &ett_pcap_Abort,
    &ett_pcap_PositionPeriodicReport,
    &ett_pcap_PositionPeriodicResult,
    &ett_pcap_PositionPeriodicTermination,
    &ett_pcap_PCAP_PDU,
    &ett_pcap_InitiatingMessage,
    &ett_pcap_SuccessfulOutcome,
    &ett_pcap_UnsuccessfulOutcome,
    &ett_pcap_Outcome,
  };

  /* module_t *pcap_module; */

  /* Register protocol */
  proto_pcap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_pcap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* pcap_module = prefs_register_protocol(proto_pcap, NULL); */

  /* Register dissector */
  pcap_handle = register_dissector("pcap", dissect_pcap, proto_pcap);

  /* Register dissector tables */
  pcap_ies_dissector_table = register_dissector_table("pcap.ies", "PCAP-PROTOCOL-IES", proto_pcap, FT_UINT32, BASE_DEC);
  pcap_ies_p1_dissector_table = register_dissector_table("pcap.ies.pair.first", "PCAP-PROTOCOL-IES-PAIR FirstValue", proto_pcap, FT_UINT32, BASE_DEC);
  pcap_ies_p2_dissector_table = register_dissector_table("pcap.ies.pair.second", "PCAP-PROTOCOL-IES-PAIR SecondValue", proto_pcap, FT_UINT32, BASE_DEC);
  pcap_extension_dissector_table = register_dissector_table("pcap.extension", "PCAP-PROTOCOL-EXTENSION", proto_pcap, FT_UINT32, BASE_DEC);
  pcap_proc_imsg_dissector_table = register_dissector_table("pcap.proc.imsg", "PCAP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_pcap, FT_UINT32, BASE_DEC);
  pcap_proc_sout_dissector_table = register_dissector_table("pcap.proc.sout", "PCAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_pcap, FT_UINT32, BASE_DEC);
  pcap_proc_uout_dissector_table = register_dissector_table("pcap.proc.uout", "PCAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_pcap, FT_UINT32, BASE_DEC);
  pcap_proc_out_dissector_table = register_dissector_table("pcap.proc.out", "PCAP-ELEMENTARY-PROCEDURE Outcome", proto_pcap, FT_UINT32, BASE_DEC);


}




