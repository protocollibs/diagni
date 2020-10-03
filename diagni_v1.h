
#ifndef _INCL_DIAM_CORE_HEADER
#define _INCL_DIAM_CORE_HEADER

#define LOG_LEVEL_CRITICAL      1
#define LOG_LEVEL_ERROR         2
#define LOG_LEVEL_WARNING       3
#define LOG_LEVEL_INFO          4
#define LOG_LEVEL_NORMAL        4
#define LOG_LEVEL_DEBUG         5

#define APP_DEBUG( fd, ...)      \
	Log( fd, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, __VA_ARGS__);

#define APP_INFO( fd, ...)      \
	Log( fd, LOG_LEVEL_INFO, __FUNCTION__, __LINE__, __VA_ARGS__);

#define APP_WARNING( fd, ...)      \
	Log( fd, LOG_LEVEL_WARNING, __FUNCTION__, __LINE__, __VA_ARGS__);
	
#define APP_ERROR( fd, ...)      \
	Log( fd, LOG_LEVEL_ERROR, __FUNCTION__, __LINE__, __VA_ARGS__);
	
#define APP_CRITICAL(fd, ...)      \
	Log( fd, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, __VA_ARGS__);			

int LOGCAT( int iLogCatId, unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...);
	
int APP_LOG( unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...);


int GetLoggerFD();


#define OCTET_STRING 1
#define SIGNED_32 2
#define SIGNED_64 3
#define UNSIGNED_32 4
#define UNSIGNED_64 5
#define FLOAT_32 6
#define FLOAT_64 7
#define GROUPED 8
#define ADDRESS 9

typedef struct Queue Queue;
typedef struct AvpFlags AvpFlags;
typedef struct CmdFlags CmdFlags;
typedef struct DiamMessage DiamMessage;
typedef struct DiamAvp DiamAvp;

typedef struct DiamStringTiny
{
	unsigned char Value[49];
	int Length;
} iDiamStringTiny;

typedef struct DiamString
{
	unsigned char Value[249];
	int Length;
} iDiamString;

typedef struct DiamAddress
{
	iDiamStringTiny Address;
	int AddressType;
} iDiamAddress;

typedef struct VendorSpecificApplicationId
{
	unsigned int iVendorId; 
	unsigned int iAuthApplicationId; 
	unsigned int iAcctApplicationId;
} iVendorSpecificApplicationId;

typedef struct MemoryRecord
{
	struct MemoryRecord* PoolNext;
	int PoolIndex;
	int isReleased;
	
	//void * Data;
	uint8_t * Data;
} iMemoryRecord;

typedef struct MessagePtr
{
	void *HeadPtr;
	void *CurrPtr;
	//uint8_t * HeadPtr;
	//uint8_t * CurrPtr;	
	long int Count;
	
	pthread_mutex_t Lock;
} iMessagePtr;

typedef struct MessagePool
{
	struct MessagePtr *FreePool;
	struct MessagePtr *BusyPool;
	int PoolSize;
	pthread_mutex_t Lock;
} iMessagePool;



typedef struct TCPServerInfo
{
	int iPort;
	void (*recvCallBack)(void*);
	void *Queue;
	void * oHostConfigData;
} iTCPServerInfo;

typedef struct TCPClientInfo
{
	pthread_mutex_t ReadLock;
	struct sockaddr_in clientAddr;
	int isActive;
	int fd;
	int iPort;
	iTCPServerInfo *TCPServerInfo;
	
	int hasPendingBeffer;
	char PendingBuffer[2048];
	int PendingBefferLength;

	/*Pool Management*/
	int isReleased;
	struct TCPClientInfo* PoolNext;
	int PoolIndex;	
} iTCPClientInfo;

typedef struct TCPRingBuffer
{
	/*Fields Here*/
	char cBuffer[999999];
	int iLength;
	iTCPClientInfo *TCPClientInfo;

	/*Pool Management*/
	int isReleased;
	struct TCPRingBuffer* PoolNext;
	int PoolIndex;
} iTCPRingBuffer;

typedef struct ExecutionTime
{
	struct timeval before;
	struct timeval after;
	struct timeval lapsed;
} iExecTime; 

typedef struct PeerInfoList
{
	void* Peers[40];
	int PeerServerCount;	
} iPeerInfoList;

void addVendorSpecificApplicationId( struct DiamMessage * diamMessage, unsigned int iVendorId, unsigned int iAuthApplicationId);
void addVendorSpecificApplicationId2( struct DiamMessage * diamMessage, unsigned int iVendorId, unsigned int iAuthApplicationId, unsigned int iAcctApplicationId);
void addVendorSpecificApplicationId3( struct DiamMessage * diamMessage, iVendorSpecificApplicationId * oVendorSpecificApplicationId);

void helper_setDiamStringTiny( iDiamStringTiny *oDiamString, char *sValue, int iLen);

void __initStartTime( iExecTime *oExecTime);
void __initEndTime( iExecTime *oExecTime);

void * lib_malloc( size_t size);
void lib_malloc2( size_t size, void** dataPtr);
void init_iMessagePool( iMessagePool ** oMessagePool);

struct MemoryRecord * __getRecord(long index);
struct MemoryRecord *__allocateMemory( int blockId);
int __registerMemoryBlock( int iMemorySize, int initCount, int incrCount, char *name);
void __initalizeMemory();

void setTimeOutHandler( int (*ptrHandler)( long lRecordId));
void __clearTimeOut( long lRecordId);
void __setTimeOut( long lRecordId, int timeInSeconds);

int getVendorId(struct DiamAvp *dmAvp);

int initPCounter(char *name, char *ipAddress, int port);
void incrementResponse( int iPCounterId);
void incrementRequest( int iPCounterId);
void setActive( int iPCounterId, int isActive);

void setAvpDataTypePreHandler( int (*ptrHandler)( int iAvpCode));
void setInteger32AVP( struct DiamAvp *dmAvp, int iAvpCode, int iInteger32, int iVendorId, int iMandatory);
void setUnsigned32AVP( struct DiamAvp *dmAvp, int iAvpCode, unsigned int uiUnsigned32, int iVendorId, int iMandatory);

void getNewSessionId(char *sSessionId);

void initDiamRequest(struct DiamMessage * diamMessage, int iProxyable, int iCmdCode, int iAppId);

void createDiamAvp(struct DiamAvp * dmAvp, struct DiamMessage * diamMessage);

void createDiamChildAvp(struct DiamAvp * dmAvp, struct DiamAvp * dmParentAvp);

#define AVP_CalledStationId 30

#define AVP_CallingStationId 31

#define AVP_AcctInterimInterval 85

#define AVP_AccountingRealtimeRequired 483

#define AVP_AcctMultiSessionId 50

#define AVP_AccountingRecordNumber 485

#define AVP_AccountingRecordType 480

#define AVP_AccountingSessionId 44

#define AVP_AccountingSubSessionId 287

#define AVP_AcctApplicationId 259

#define AVP_AuthApplicationId 258

#define AVP_AuthRequestType 274

#define AVP_AuthorizationLifetime 291

#define AVP_AuthGracePeriod 276

#define AVP_AuthSessionState 277

#define AVP_ReAuthRequestType 285

#define AVP_Class 25

#define AVP_DestinationHost 293

#define AVP_DestinationRealm 283

#define AVP_DisconnectCause 273

#define AVP_E2ESequenceAVP 300

#define AVP_ErrorMessage 281

#define AVP_ErrorReportingHost 294

#define AVP_EventTimestamp 55

#define AVP_ExperimentalResult 297

#define AVP_ExperimentalResultCode 298

#define AVP_FailedAVP 279

#define AVP_FirmwareRevision 267

#define AVP_HostIPAddress 257

#define AVP_InbandSecurityId 299

#define AVP_MultiRoundTimeOut 272

#define AVP_OriginHost 264

#define AVP_OriginRealm 296

#define AVP_OriginStateId 278

#define AVP_ProductName 269

#define AVP_ProxyHost 280

#define AVP_ProxyInfo 284

#define AVP_ProxyState 33

#define AVP_RedirectHost 292

#define AVP_RedirectHostUsage 261

#define AVP_RedirectMaxCacheTime 262

#define AVP_ResultCode 268

#define AVP_RouteRecord 282

#define AVP_SessionId 263

#define AVP_SessionTimeout 27

#define AVP_SessionBinding 270

#define AVP_SessionServerFailover 271

#define AVP_SupportedVendorId 265

#define AVP_TerminationCause 295

#define AVP_UserName 1

#define AVP_VendorId 266

#define AVP_VendorSpecificApplicationId 260

#define AVP_CCCorrelationId 411

#define AVP_CCInputOctets 412

#define AVP_CCMoney 413

#define AVP_CCOutputOctets 414

#define AVP_CCRequestNumber 415

#define AVP_CCRequestType 416

#define AVP_CCServiceSpecificUnits 417

#define AVP_CCSessionFailover 418

#define AVP_CCSubSessionId 419

#define AVP_CCTime 420

#define AVP_CCTotalOctets 421

#define AVP_CCUnitType 454

#define AVP_CheckBalanceResult 422

#define AVP_CostInformation 423

#define AVP_CostUnit 424

#define AVP_CreditControl 426

#define AVP_CreditControlFailureHandling 427

#define AVP_CurrencyCode 425

#define AVP_DirectDebitingFailureHandling 428

#define AVP_Exponent 429

#define AVP_FinalUnitAction 449

#define AVP_FinalUnitIndication 430

#define AVP_GrantedServiceUnit 431

#define AVP_GSUPoolIdentifier 453

#define AVP_GSUPoolReference 457

#define AVP_MultipleServicesCreditControl 456

#define AVP_MultipleServicesIndicator 455

#define AVP_RatingGroup 432

#define AVP_RedirectAddressType 433

#define AVP_RedirectServer 434

#define AVP_RedirectServerAddress 435

#define AVP_RequestedAction 436

#define AVP_RequestedServiceUnit 437

#define AVP_RestrictionFilterRule 438

#define AVP_ServiceContextId 461

#define AVP_ServiceIdentifier 439

#define AVP_ServiceParameterInfo 440

#define AVP_ServiceParameterType 441

#define AVP_ServiceParameterValue 442

#define AVP_SubscriptionId 443

#define AVP_SubscriptionIdData 444

#define AVP_SubscriptionIdType 450

#define AVP_TariffChangeUsage 452

#define AVP_TariffTimeChange 451

#define AVP_UnitValue 445

#define AVP_UsedServiceUnit 446

#define AVP_UserEquipmentInfo 458

#define AVP_UserEquipmentInfoType 459

#define AVP_UserEquipmentInfoValue 460

#define AVP_ValueDigits 447

#define AVP_ValidityTime 448

#define AVP_TGPPChargingCharacteristics 13

#define AVP_TGPPChargingId 2

#define AVP_TGPPGGSNMCCMNC 9

#define AVP_TGPPIMSI 1

#define AVP_TGPPIMSIMCCMNC 8

#define AVP_TGPPMSTimeZone 23

#define AVP_TGPPNSAPI 10

#define AVP_TGPPPDPType 3

#define AVP_TGPPRATType 21

#define AVP_TGPPSelectionMode 12

#define AVP_TGPPSessionStopIndicator 11

#define AVP_TGPPSGSNMCCMNC 18

#define AVP_TGPPUserLocationInfo 22

#define AVP_TGPP2BSID 5535

#define AVP_AccessNetworkChargingIdentifierValue 503

#define AVP_AccessNetworkInformation 1263

#define AVP_AccumulatedCost 2052

#define AVP_Adaptations 1217

#define AVP_AdditionalContentInformation 1207

#define AVP_AdditionalTypeInformation 1205

#define AVP_AddressData 897

#define AVP_AddressDomain 898

#define AVP_AddresseeType 1208

#define AVP_AddressType 899

#define AVP_AFChargingIdentifier 505

#define AVP_AFCorrelationInformation 1276

#define AVP_AllocationRetentionPriority 1034

#define AVP_AlternateChargedPartyAddress 1280

#define AVP_AoCCostInformation 2053

#define AVP_AoCInformation 2054

#define AVP_AoCRequestType 2055

#define AVP_Applicationprovidedcalledpartyaddress 837

#define AVP_ApplicationServer 836

#define AVP_ApplicationServerID 2101

#define AVP_ApplicationServerInformation 850

#define AVP_ApplicationServiceType 2102

#define AVP_ApplicationSessionID 2103

#define AVP_ApplicID 1218

#define AVP_AssociatedPartyAddress 2035

#define AVP_AssociatedURI 856

#define AVP_AuthorizedQoS 849

#define AVP_AuxApplicInfo 1219

#define AVP_BaseTimeInterval 1265

#define AVP_BearerService 854

#define AVP_CalledAssertedIdentity 1250

#define AVP_CalledPartyAddress 832

#define AVP_CallingPartyAddress 831

#define AVP_CarrierSelectRoutingInformation 2023

#define AVP_CauseCode 861

#define AVP_CGAddress 846

#define AVP_ChangeCondition 2037

#define AVP_ChangeTime 2038

#define AVP_ChargedParty 857

#define AVP_ChargingRuleBaseName 1004

#define AVP_ClassIdentifier 1214

#define AVP_ClientAddress 2018

#define AVP_CNIPMulticastDistribution 921

#define AVP_ContentClass 1220

#define AVP_ContentDisposition 828

#define AVP_ContentID 2116

#define AVP_ContentProviderID 2117

#define AVP_ContentLength 827

#define AVP_ContentSize 1206

#define AVP_ContentType 826

#define AVP_CurrentTariff 2056

#define AVP_DataCodingScheme 2001

#define AVP_DCDInformation 2115

#define AVP_DeferredLocationEventType 1230

#define AVP_DeliveryReportRequested 1216

#define AVP_DeliveryStatus 2104

#define AVP_DestinationInterface 2002

#define AVP_Diagnostics 2039

#define AVP_DomainName 1200

#define AVP_DRMContent 1221

#define AVP_DynamicAddressFlag 2051

#define AVP_EarlyMediaDescription 1272

#define AVP_Envelope 1266

#define AVP_EnvelopeEndTime 1267

#define AVP_EnvelopeReporting 1268

#define AVP_EnvelopeStartTime 1269

#define AVP_Event 825

#define AVP_EventChargingTimeStamp 1258

#define AVP_EventType 823

#define AVP_Expires 888

#define AVP_FileRepairSupported 1224

#define AVP_Flows 510

#define AVP_GGSNAddress 847

#define AVP_GuaranteedBitrateUL 1026

#define AVP_IMInformation 2110

#define AVP_IMSChargingIdentifier 841

#define AVP_IMSCommunicationServiceIdentifier 1281

#define AVP_IMSInformation 876

#define AVP_IncomingTrunkGroupId 852

#define AVP_IncrementalCost 2062

#define AVP_InterfaceId 2003

#define AVP_InterfacePort 2004

#define AVP_InterfaceText 2005

#define AVP_InterfaceType 2006

#define AVP_InterOperatorIdentifier 838

#define AVP_LCSClientDialedByMS 1233

#define AVP_LCSClientExternalID 1234

#define AVP_LCSClientId 1232

#define AVP_LCSClientName 1231

#define AVP_LCSClientType 1241

#define AVP_LCSDataCodingScheme 1236

#define AVP_LCSFormatIndicator 1237

#define AVP_LCSInformation 878

#define AVP_LCSNameString 1238

#define AVP_LCSRequestorId 1239

#define AVP_LCSRequestorIdString 1240

#define AVP_LocalSequenceNumber 2063

#define AVP_LocationEstimate 1242

#define AVP_LocationEstimateType 1243

#define AVP_LocationType 1244

#define AVP_LowBalanceIndication 2020

#define AVP_MandatoryCapability 604

#define AVP_MaxRequestedBandwidthDL 515

#define AVP_MaxRequestedBandwidthUL 516

#define AVP_MBMS2G3GIndicator 907

#define AVP_MBMSInformation 880

#define AVP_MBMSServiceArea 903

#define AVP_MBMSServiceType 906

#define AVP_MBMSSessionIdentity 908

#define AVP_MBMSUserServiceType 1225

#define AVP_MediaInitiatorFlag 882

#define AVP_MediaInitiatorParty 1288

#define AVP_MessageBody 889

#define AVP_MessageClass 1213

#define AVP_MessageID 1210

#define AVP_MessageSize 1212

#define AVP_MessageType 1211

#define AVP_MMBoxStorageRequested 1248

#define AVP_MMContentType 1203

#define AVP_MMSInformation 877

#define AVP_MMTelInformation 2030

#define AVP_MSISDN 701

#define AVP_NextTariff 2057

#define AVP_NodeFunctionality 862

#define AVP_NodeId 2064

#define AVP_NumberOfDiversions 2034

#define AVP_NumberOfMessagesSent 2019

#define AVP_NumberOfMessagesSuccessfullyExploded 2111

#define AVP_NumberOfMessagesSuccessfullySent 2112

#define AVP_NumberOfParticipants 885

#define AVP_NumberOfReceivedTalkBursts 1282

#define AVP_NumberOfTalkBursts 1283

#define AVP_NumberPortabilityRoutingInformation 2024

#define AVP_OfflineCharging 1278

#define AVP_OptionalCapability 605

#define AVP_OriginatingIOI 839

#define AVP_OriginatorSCCPAddress 2008

#define AVP_Originator 864

#define AVP_OriginatorAddress 886

#define AVP_OriginatorReceivedAddress 2027

#define AVP_OriginatorInterface 2009

#define AVP_OutgoingTrunkGroupId 853

#define AVP_ParticipantAccessPriority 1259

#define AVP_ParticipantActionType 2049

#define AVP_ParticipantGroup 1260

#define AVP_ParticipantsInvolved 887

#define AVP_PDGAddress 895

#define AVP_PDGChargingId 896

#define AVP_PDNConnectionID 2050

#define AVP_PDPAddress 1227

#define AVP_PDPContextType 1247

#define AVP_PoCChangeCondition 1261

#define AVP_PoCChangeTime 1262

#define AVP_PoCControllingAddress 858

#define AVP_PoCEventType 2025

#define AVP_PoCGroupName 859

#define AVP_PoCInformation 879

#define AVP_PoCServerRole 883

#define AVP_PoCSessionId 1229

#define AVP_PoCSessionInitiationtype 1277

#define AVP_PoCSessionType 884

#define AVP_PoCUserRole 1252

#define AVP_PoCUserRoleIDs 1253

#define AVP_PoCUserRoleinfoUnits 1254

#define AVP_PositioningData 1245

#define AVP_Priority 1209

#define AVP_PriorityLevel 1046

#define AVP_PSAppendFreeFormatData 867

#define AVP_PSFreeFormatData 866

#define AVP_PSFurnishChargingInformation 865

#define AVP_PSInformation 874

#define AVP_QoSInformation 1016

#define AVP_QoSClassIdentifier 1028

#define AVP_QuotaConsumptionTime 881

#define AVP_QuotaHoldingTime 871

#define AVP_RAI 909

#define AVP_RateElement 2058

#define AVP_ReadReplyReportRequested 1222

#define AVP_ReceivedTalkBurstTime 1284

#define AVP_ReceivedTalkBurstVolume 1285

#define AVP_RecipientAddress 1201

#define AVP_RecipientInfo 2026

#define AVP_RecipientReceivedAddress 2028

#define AVP_RecipientSCCPAddress 2010

#define AVP_RefundInformation 2022

#define AVP_RemainingBalance 2021

#define AVP_ReplyApplicID 1223

#define AVP_ReplyPathRequested 2011

#define AVP_ReportingReason 872

#define AVP_RequestedPartyAddress 1251

#define AVP_RequiredMBMSBearerCapabilities 901

#define AVP_RoleofNode 829

#define AVP_ScaleFactor 2059

#define AVP_SDPAnswerTimestamp 1275

#define AVP_SDPMediaComponent 843

#define AVP_SDPMediaDescription 845

#define AVP_SDPMediaName 844

#define AVP_SDPOfferTimestamp 1274

#define AVP_SDPSessionDescription 842

#define AVP_SDPTimeStamps 1273

#define AVP_SDPType 2036

#define AVP_ServedPartyIPAddress 848

#define AVP_ServerCapabilities 603

#define AVP_ServerName 602

#define AVP_ServiceDataContainer 2040

#define AVP_ServiceGenericInformation 1256

#define AVP_ServiceId 855

#define AVP_ServiceInformation 873

#define AVP_ServiceMode 2032

#define AVP_ServiceSpecificData 863

#define AVP_ServiceSpecificInfo 1249

#define AVP_ServiceSpecificType 1257

#define AVP_ServingNodeType 2047

#define AVP_ServiceType 2031

#define AVP_SessionPriority 650

#define AVP_SGSNAddress 1228

#define AVP_SGWChange 2065

#define AVP_SIPMethod 824

#define AVP_SIPRequestTimestamp 834

#define AVP_SIPResponseTimestamp 835

#define AVP_SMDischargeTime 2012

#define AVP_SMMessageType 2007

#define AVP_SMProtocolID 2013

#define AVP_SMSCAddress 2017

#define AVP_SMSInformation 2000

#define AVP_SMSNode 2016

#define AVP_SMServiceType 2029

#define AVP_SMStatus 2014

#define AVP_SMUserDataHeader 2015

#define AVP_StartTime 2041

#define AVP_StopTime 2042

#define AVP_SubmissionTime 1202

#define AVP_SubscriberRole 2033

#define AVP_SupplementaryService 2048

#define AVP_TalkBurstExchange 1255

#define AVP_TalkBurstTime 1286

#define AVP_TalkBurstVolume 1287

#define AVP_TariffInformation 2060

#define AVP_TerminalInformation 1401

#define AVP_TerminatingIOI 840

#define AVP_TimeFirstUsage 2043

#define AVP_TimeLastUsage 2044

#define AVP_TimeQuotaMechanism 1270

#define AVP_TimeQuotaThreshold 868

#define AVP_TimeQuotaType 1271

#define AVP_TimeStamps 833

#define AVP_TimeUsage 2045

#define AVP_TMGI 900

#define AVP_TokenText 1215

#define AVP_TotalNumberOfMessagesExploded 2113

#define AVP_TotalNumberOfMessagesSent 2114

#define AVP_TrafficDataVolumes 2046

#define AVP_Trigger 1264

#define AVP_TriggerType 870

#define AVP_TrunkGroupId 851

#define AVP_TypeNumber 1204

#define AVP_UnitCost 2061

#define AVP_UnitQuotaThreshold 1226

#define AVP_UserData 606

#define AVP_UserParticipatingType 1279

#define AVP_UserSessionId 830

#define AVP_VASId 1102

#define AVP_VASPId 1101

#define AVP_VolumeQuotaThreshold 869

#define AVP_WAGAddress 890

#define AVP_WAGPLMNId 891

#define AVP_WLANInformation 875

#define AVP_WLANRadioContainer 892

#define AVP_WLANSessionId 1246

#define AVP_WLANTechnology 893

#define AVP_WLANUELocalIPAddress 894

//============================Member Functions============================

/**
* AVP Code : 921
* Data Type : OctetString
*/
void addCNIPMulticastDistributionAVP( struct DiamMessage *dmMessage, char *sCNIPMulticastDistribution, int iVendorId, int iMandatory, int iLength);

void setCNIPMulticastDistributionAVP( struct DiamAvp *dmAvp, char *sCNIPMulticastDistribution, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2116
* Data Type : OctetString
*/
void addContentIDAVP( struct DiamMessage *dmMessage, char *sContentID, int iVendorId, int iMandatory, int iLength);

void setContentIDAVP( struct DiamAvp *dmAvp, char *sContentID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2117
* Data Type : OctetString
*/
void addContentProviderIDAVP( struct DiamMessage *dmMessage, char *sContentProviderID, int iVendorId, int iMandatory, int iLength);

void setContentProviderIDAVP( struct DiamAvp *dmAvp, char *sContentProviderID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2115
* Data Type : OctetString
*/
void addDCDInformationAVP( struct DiamMessage *dmMessage, char *sDCDInformation, int iVendorId, int iMandatory, int iLength);

void setDCDInformationAVP( struct DiamAvp *dmAvp, char *sDCDInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2104
* Data Type : OctetString
*/
void addDeliveryStatusAVP( struct DiamMessage *dmMessage, char *sDeliveryStatus, int iVendorId, int iMandatory, int iLength);

void setDeliveryStatusAVP( struct DiamAvp *dmAvp, char *sDeliveryStatus, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 510
* Data Type : OctetString
*/
void addFlowsAVP( struct DiamMessage *dmMessage, char *sFlows, int iVendorId, int iMandatory, int iLength);

void setFlowsAVP( struct DiamAvp *dmAvp, char *sFlows, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1026
* Data Type : OctetString
*/
void addGuaranteedBitrateULAVP( struct DiamMessage *dmMessage, char *sGuaranteedBitrateUL, int iVendorId, int iMandatory, int iLength);

void setGuaranteedBitrateULAVP( struct DiamAvp *dmAvp, char *sGuaranteedBitrateUL, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2110
* Data Type : OctetString
*/
void addIMInformationAVP( struct DiamMessage *dmMessage, char *sIMInformation, int iVendorId, int iMandatory, int iLength);

void setIMInformationAVP( struct DiamAvp *dmAvp, char *sIMInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 604
* Data Type : OctetString
*/
void addMandatoryCapabilityAVP( struct DiamMessage *dmMessage, char *sMandatoryCapability, int iVendorId, int iMandatory, int iLength);

void setMandatoryCapabilityAVP( struct DiamAvp *dmAvp, char *sMandatoryCapability, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 515
* Data Type : OctetString
*/
void addMaxRequestedBandwidthDLAVP( struct DiamMessage *dmMessage, char *sMaxRequestedBandwidthDL, int iVendorId, int iMandatory, int iLength);

void setMaxRequestedBandwidthDLAVP( struct DiamAvp *dmAvp, char *sMaxRequestedBandwidthDL, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 516
* Data Type : OctetString
*/
void addMaxRequestedBandwidthULAVP( struct DiamMessage *dmMessage, char *sMaxRequestedBandwidthUL, int iVendorId, int iMandatory, int iLength);

void setMaxRequestedBandwidthULAVP( struct DiamAvp *dmAvp, char *sMaxRequestedBandwidthUL, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 907
* Data Type : OctetString
*/
void addMBMS2G3GIndicatorAVP( struct DiamMessage *dmMessage, char *sMBMS2G3GIndicator, int iVendorId, int iMandatory, int iLength);

void setMBMS2G3GIndicatorAVP( struct DiamAvp *dmAvp, char *sMBMS2G3GIndicator, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 903
* Data Type : OctetString
*/
void addMBMSServiceAreaAVP( struct DiamMessage *dmMessage, char *sMBMSServiceArea, int iVendorId, int iMandatory, int iLength);

void setMBMSServiceAreaAVP( struct DiamAvp *dmAvp, char *sMBMSServiceArea, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 906
* Data Type : OctetString
*/
void addMBMSServiceTypeAVP( struct DiamMessage *dmMessage, char *sMBMSServiceType, int iVendorId, int iMandatory, int iLength);

void setMBMSServiceTypeAVP( struct DiamAvp *dmAvp, char *sMBMSServiceType, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 908
* Data Type : OctetString
*/
void addMBMSSessionIdentityAVP( struct DiamMessage *dmMessage, char *sMBMSSessionIdentity, int iVendorId, int iMandatory, int iLength);

void setMBMSSessionIdentityAVP( struct DiamAvp *dmAvp, char *sMBMSSessionIdentity, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 701
* Data Type : OctetString
*/
void addMSISDNAVP( struct DiamMessage *dmMessage, char *sMSISDN, int iVendorId, int iMandatory, int iLength);

void setMSISDNAVP( struct DiamAvp *dmAvp, char *sMSISDN, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2111
* Data Type : OctetString
*/
void addNumberOfMessagesSuccessfullyExplodedAVP( struct DiamMessage *dmMessage, char *sNumberOfMessagesSuccessfullyExploded, int iVendorId, int iMandatory, int iLength);

void setNumberOfMessagesSuccessfullyExplodedAVP( struct DiamAvp *dmAvp, char *sNumberOfMessagesSuccessfullyExploded, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2112
* Data Type : OctetString
*/
void addNumberOfMessagesSuccessfullySentAVP( struct DiamMessage *dmMessage, char *sNumberOfMessagesSuccessfullySent, int iVendorId, int iMandatory, int iLength);

void setNumberOfMessagesSuccessfullySentAVP( struct DiamAvp *dmAvp, char *sNumberOfMessagesSuccessfullySent, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 605
* Data Type : OctetString
*/
void addOptionalCapabilityAVP( struct DiamMessage *dmMessage, char *sOptionalCapability, int iVendorId, int iMandatory, int iLength);

void setOptionalCapabilityAVP( struct DiamAvp *dmAvp, char *sOptionalCapability, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1046
* Data Type : OctetString
*/
void addPriorityLevelAVP( struct DiamMessage *dmMessage, char *sPriorityLevel, int iVendorId, int iMandatory, int iLength);

void setPriorityLevelAVP( struct DiamAvp *dmAvp, char *sPriorityLevel, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1016
* Data Type : OctetString
*/
void addQoSInformationAVP( struct DiamMessage *dmMessage, char *sQoSInformation, int iVendorId, int iMandatory, int iLength);

void setQoSInformationAVP( struct DiamAvp *dmAvp, char *sQoSInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1028
* Data Type : OctetString
*/
void addQoSClassIdentifierAVP( struct DiamMessage *dmMessage, char *sQoSClassIdentifier, int iVendorId, int iMandatory, int iLength);

void setQoSClassIdentifierAVP( struct DiamAvp *dmAvp, char *sQoSClassIdentifier, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 909
* Data Type : OctetString
*/
void addRAIAVP( struct DiamMessage *dmMessage, char *sRAI, int iVendorId, int iMandatory, int iLength);

void setRAIAVP( struct DiamAvp *dmAvp, char *sRAI, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 901
* Data Type : OctetString
*/
void addRequiredMBMSBearerCapabilitiesAVP( struct DiamMessage *dmMessage, char *sRequiredMBMSBearerCapabilities, int iVendorId, int iMandatory, int iLength);

void setRequiredMBMSBearerCapabilitiesAVP( struct DiamAvp *dmAvp, char *sRequiredMBMSBearerCapabilities, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 603
* Data Type : OctetString
*/
void addServerCapabilitiesAVP( struct DiamMessage *dmMessage, char *sServerCapabilities, int iVendorId, int iMandatory, int iLength);

void setServerCapabilitiesAVP( struct DiamAvp *dmAvp, char *sServerCapabilities, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 602
* Data Type : OctetString
*/
void addServerNameAVP( struct DiamMessage *dmMessage, char *sServerName, int iVendorId, int iMandatory, int iLength);

void setServerNameAVP( struct DiamAvp *dmAvp, char *sServerName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1256
* Data Type : OctetString
*/
void addServiceGenericInformationAVP( struct DiamMessage *dmMessage, char *sServiceGenericInformation, int iVendorId, int iMandatory, int iLength);

void setServiceGenericInformationAVP( struct DiamAvp *dmAvp, char *sServiceGenericInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 650
* Data Type : OctetString
*/
void addSessionPriorityAVP( struct DiamMessage *dmMessage, char *sSessionPriority, int iVendorId, int iMandatory, int iLength);

void setSessionPriorityAVP( struct DiamAvp *dmAvp, char *sSessionPriority, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1401
* Data Type : OctetString
*/
void addTerminalInformationAVP( struct DiamMessage *dmMessage, char *sTerminalInformation, int iVendorId, int iMandatory, int iLength);

void setTerminalInformationAVP( struct DiamAvp *dmAvp, char *sTerminalInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 900
* Data Type : OctetString
*/
void addTMGIAVP( struct DiamMessage *dmMessage, char *sTMGI, int iVendorId, int iMandatory, int iLength);

void setTMGIAVP( struct DiamAvp *dmAvp, char *sTMGI, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2113
* Data Type : OctetString
*/
void addTotalNumberOfMessagesExplodedAVP( struct DiamMessage *dmMessage, char *sTotalNumberOfMessagesExploded, int iVendorId, int iMandatory, int iLength);

void setTotalNumberOfMessagesExplodedAVP( struct DiamAvp *dmAvp, char *sTotalNumberOfMessagesExploded, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2114
* Data Type : OctetString
*/
void addTotalNumberOfMessagesSentAVP( struct DiamMessage *dmMessage, char *sTotalNumberOfMessagesSent, int iVendorId, int iMandatory, int iLength);

void setTotalNumberOfMessagesSentAVP( struct DiamAvp *dmAvp, char *sTotalNumberOfMessagesSent, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 606
* Data Type : OctetString
*/
void addUserDataAVP( struct DiamMessage *dmMessage, char *sUserData, int iVendorId, int iMandatory, int iLength);

void setUserDataAVP( struct DiamAvp *dmAvp, char *sUserData, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1102
* Data Type : OctetString
*/
void addVASIdAVP( struct DiamMessage *dmMessage, char *sVASId, int iVendorId, int iMandatory, int iLength);

void setVASIdAVP( struct DiamAvp *dmAvp, char *sVASId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1101
* Data Type : OctetString
*/
void addVASPIdAVP( struct DiamMessage *dmMessage, char *sVASPId, int iVendorId, int iMandatory, int iLength);

void setVASPIdAVP( struct DiamAvp *dmAvp, char *sVASPId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2060
* Data Type : Grouped
*/
void setTariffInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1270
* Data Type : Grouped
*/
void setTimeQuotaMechanismAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 833
* Data Type : Grouped
*/
void setTimeStampsAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2046
* Data Type : Grouped
*/
void setTrafficDataVolumesAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1264
* Data Type : Grouped
*/
void setTriggerAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 851
* Data Type : Grouped
*/
void setTrunkGroupIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2061
* Data Type : Grouped
*/
void setUnitCostAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 875
* Data Type : Grouped
*/
void setWLANInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 892
* Data Type : Grouped
*/
void setWLANRadioContainerAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 456
* Data Type : Grouped
*/
void setMultipleServicesCreditControlAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 55
* Data Type : Time
*/
void addEventTimestampAVP( struct DiamMessage *dmMessage, char *sEventTimestamp, int iVendorId, int iMandatory, int iLength);

void setEventTimestampAVP( struct DiamAvp *dmAvp, char *sEventTimestamp, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2038
* Data Type : Time
*/
void addChangeTimeAVP( struct DiamMessage *dmMessage, char *sChangeTime, int iVendorId, int iMandatory, int iLength);

void setChangeTimeAVP( struct DiamAvp *dmAvp, char *sChangeTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1267
* Data Type : Time
*/
void addEnvelopeEndTimeAVP( struct DiamMessage *dmMessage, char *sEnvelopeEndTime, int iVendorId, int iMandatory, int iLength);

void setEnvelopeEndTimeAVP( struct DiamAvp *dmAvp, char *sEnvelopeEndTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1269
* Data Type : Time
*/
void addEnvelopeStartTimeAVP( struct DiamMessage *dmMessage, char *sEnvelopeStartTime, int iVendorId, int iMandatory, int iLength);

void setEnvelopeStartTimeAVP( struct DiamAvp *dmAvp, char *sEnvelopeStartTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1258
* Data Type : Time
*/
void addEventChargingTimeStampAVP( struct DiamMessage *dmMessage, char *sEventChargingTimeStamp, int iVendorId, int iMandatory, int iLength);

void setEventChargingTimeStampAVP( struct DiamAvp *dmAvp, char *sEventChargingTimeStamp, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1262
* Data Type : Time
*/
void addPoCChangeTimeAVP( struct DiamMessage *dmMessage, char *sPoCChangeTime, int iVendorId, int iMandatory, int iLength);

void setPoCChangeTimeAVP( struct DiamAvp *dmAvp, char *sPoCChangeTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1275
* Data Type : Time
*/
void addSDPAnswerTimestampAVP( struct DiamMessage *dmMessage, char *sSDPAnswerTimestamp, int iVendorId, int iMandatory, int iLength);

void setSDPAnswerTimestampAVP( struct DiamAvp *dmAvp, char *sSDPAnswerTimestamp, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1274
* Data Type : Time
*/
void addSDPOfferTimestampAVP( struct DiamMessage *dmMessage, char *sSDPOfferTimestamp, int iVendorId, int iMandatory, int iLength);

void setSDPOfferTimestampAVP( struct DiamAvp *dmAvp, char *sSDPOfferTimestamp, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 834
* Data Type : Time
*/
void addSIPRequestTimestampAVP( struct DiamMessage *dmMessage, char *sSIPRequestTimestamp, int iVendorId, int iMandatory, int iLength);

void setSIPRequestTimestampAVP( struct DiamAvp *dmAvp, char *sSIPRequestTimestamp, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 835
* Data Type : Time
*/
void addSIPResponseTimestampAVP( struct DiamMessage *dmMessage, char *sSIPResponseTimestamp, int iVendorId, int iMandatory, int iLength);

void setSIPResponseTimestampAVP( struct DiamAvp *dmAvp, char *sSIPResponseTimestamp, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2012
* Data Type : Time
*/
void addSMDischargeTimeAVP( struct DiamMessage *dmMessage, char *sSMDischargeTime, int iVendorId, int iMandatory, int iLength);

void setSMDischargeTimeAVP( struct DiamAvp *dmAvp, char *sSMDischargeTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2041
* Data Type : Time
*/
void addStartTimeAVP( struct DiamMessage *dmMessage, char *sStartTime, int iVendorId, int iMandatory, int iLength);

void setStartTimeAVP( struct DiamAvp *dmAvp, char *sStartTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2042
* Data Type : Time
*/
void addStopTimeAVP( struct DiamMessage *dmMessage, char *sStopTime, int iVendorId, int iMandatory, int iLength);

void setStopTimeAVP( struct DiamAvp *dmAvp, char *sStopTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1202
* Data Type : Time
*/
void addSubmissionTimeAVP( struct DiamMessage *dmMessage, char *sSubmissionTime, int iVendorId, int iMandatory, int iLength);

void setSubmissionTimeAVP( struct DiamAvp *dmAvp, char *sSubmissionTime, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2043
* Data Type : Time
*/
void addTimeFirstUsageAVP( struct DiamMessage *dmMessage, char *sTimeFirstUsage, int iVendorId, int iMandatory, int iLength);

void setTimeFirstUsageAVP( struct DiamAvp *dmAvp, char *sTimeFirstUsage, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2044
* Data Type : Time
*/
void addTimeLastUsageAVP( struct DiamMessage *dmMessage, char *sTimeLastUsage, int iVendorId, int iMandatory, int iLength);

void setTimeLastUsageAVP( struct DiamAvp *dmAvp, char *sTimeLastUsage, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 257
* Data Type : Address
*/
void addHostIPAddressAVP( struct DiamMessage *dmMessage, char *sHostIPAddress, int iVendorId, int iMandatory);

void setHostIPAddressAVP( struct DiamAvp *dmAvp, char *sHostIPAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 846
* Data Type : Address
*/
void addCGAddressAVP( struct DiamMessage *dmMessage, char *sCGAddress, int iVendorId, int iMandatory);

void setCGAddressAVP( struct DiamAvp *dmAvp, char *sCGAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 2018
* Data Type : Address
*/
void addClientAddressAVP( struct DiamMessage *dmMessage, char *sClientAddress, int iVendorId, int iMandatory);

void setClientAddressAVP( struct DiamAvp *dmAvp, char *sClientAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 847
* Data Type : Address
*/
void addGGSNAddressAVP( struct DiamMessage *dmMessage, char *sGGSNAddress, int iVendorId, int iMandatory);

void setGGSNAddressAVP( struct DiamAvp *dmAvp, char *sGGSNAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 2008
* Data Type : Address
*/
void addOriginatorSCCPAddressAVP( struct DiamMessage *dmMessage, char *sOriginatorSCCPAddress, int iVendorId, int iMandatory);

void setOriginatorSCCPAddressAVP( struct DiamAvp *dmAvp, char *sOriginatorSCCPAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 895
* Data Type : Address
*/
void addPDGAddressAVP( struct DiamMessage *dmMessage, char *sPDGAddress, int iVendorId, int iMandatory);

void setPDGAddressAVP( struct DiamAvp *dmAvp, char *sPDGAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 1227
* Data Type : Address
*/
void addPDPAddressAVP( struct DiamMessage *dmMessage, char *sPDPAddress, int iVendorId, int iMandatory);

void setPDPAddressAVP( struct DiamAvp *dmAvp, char *sPDPAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 2010
* Data Type : Address
*/
void addRecipientSCCPAddressAVP( struct DiamMessage *dmMessage, char *sRecipientSCCPAddress, int iVendorId, int iMandatory);

void setRecipientSCCPAddressAVP( struct DiamAvp *dmAvp, char *sRecipientSCCPAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 848
* Data Type : Address
*/
void addServedPartyIPAddressAVP( struct DiamMessage *dmMessage, char *sServedPartyIPAddress, int iVendorId, int iMandatory);

void setServedPartyIPAddressAVP( struct DiamAvp *dmAvp, char *sServedPartyIPAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 1228
* Data Type : Address
*/
void addSGSNAddressAVP( struct DiamMessage *dmMessage, char *sSGSNAddress, int iVendorId, int iMandatory);

void setSGSNAddressAVP( struct DiamAvp *dmAvp, char *sSGSNAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 2017
* Data Type : Address
*/
void addSMSCAddressAVP( struct DiamMessage *dmMessage, char *sSMSCAddress, int iVendorId, int iMandatory);

void setSMSCAddressAVP( struct DiamAvp *dmAvp, char *sSMSCAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 890
* Data Type : Address
*/
void addWAGAddressAVP( struct DiamMessage *dmMessage, char *sWAGAddress, int iVendorId, int iMandatory);

void setWAGAddressAVP( struct DiamAvp *dmAvp, char *sWAGAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 894
* Data Type : Address
*/
void addWLANUELocalIPAddressAVP( struct DiamMessage *dmMessage, char *sWLANUELocalIPAddress, int iVendorId, int iMandatory);

void setWLANUELocalIPAddressAVP( struct DiamAvp *dmAvp, char *sWLANUELocalIPAddress, int iVendorId, int iMandatory);

/**
* AVP Code : 292
* Data Type : DiamURI
*/
void addRedirectHostAVP( struct DiamMessage *dmMessage, char *sRedirectHost, int iVendorId, int iMandatory, int iLength);

void setRedirectHostAVP( struct DiamAvp *dmAvp, char *sRedirectHost, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 861
* Data Type : Integer32
*/
void addCauseCodeAVP( struct DiamMessage *dmMessage, int iCauseCode, int iVendorId, int iMandatory);

void setCauseCodeAVP( struct DiamAvp *dmAvp, int iCauseCode, int iVendorId, int iMandatory);

/**
* AVP Code : 2037
* Data Type : Integer32
*/
void addChangeConditionAVP( struct DiamMessage *dmMessage, int iChangeCondition, int iVendorId, int iMandatory);

void setChangeConditionAVP( struct DiamAvp *dmAvp, int iChangeCondition, int iVendorId, int iMandatory);

/**
* AVP Code : 2001
* Data Type : Integer32
*/
void addDataCodingSchemeAVP( struct DiamMessage *dmMessage, int iDataCodingScheme, int iVendorId, int iMandatory);

void setDataCodingSchemeAVP( struct DiamAvp *dmAvp, int iDataCodingScheme, int iVendorId, int iMandatory);

/**
* AVP Code : 2039
* Data Type : Integer32
*/
void addDiagnosticsAVP( struct DiamMessage *dmMessage, int iDiagnostics, int iVendorId, int iMandatory);

void setDiagnosticsAVP( struct DiamAvp *dmAvp, int iDiagnostics, int iVendorId, int iMandatory);

/**
* AVP Code : 13
* Data Type : OctetString
*/
void addTGPPChargingCharacteristicsAVP( struct DiamMessage *dmMessage, char *sTGPPChargingCharacteristics, int iVendorId, int iMandatory, int iLength);

void setTGPPChargingCharacteristicsAVP( struct DiamAvp *dmAvp, char *sTGPPChargingCharacteristics, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2
* Data Type : OctetString
*/
void addTGPPChargingIdAVP( struct DiamMessage *dmMessage, char *sTGPPChargingId, int iVendorId, int iMandatory, int iLength);

void setTGPPChargingIdAVP( struct DiamAvp *dmAvp, char *sTGPPChargingId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 9
* Data Type : OctetString
*/
void addTGPPGGSNMCCMNCAVP( struct DiamMessage *dmMessage, char *sTGPPGGSNMCCMNC, int iVendorId, int iMandatory, int iLength);

void setTGPPGGSNMCCMNCAVP( struct DiamAvp *dmAvp, char *sTGPPGGSNMCCMNC, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 8
* Data Type : OctetString
*/
void addTGPPIMSIMCCMNCAVP( struct DiamMessage *dmMessage, char *sTGPPIMSIMCCMNC, int iVendorId, int iMandatory, int iLength);

void setTGPPIMSIMCCMNCAVP( struct DiamAvp *dmAvp, char *sTGPPIMSIMCCMNC, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 23
* Data Type : OctetString
*/
void addTGPPMSTimeZoneAVP( struct DiamMessage *dmMessage, char *sTGPPMSTimeZone, int iVendorId, int iMandatory, int iLength);

void setTGPPMSTimeZoneAVP( struct DiamAvp *dmAvp, char *sTGPPMSTimeZone, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 10
* Data Type : OctetString
*/
void addTGPPNSAPIAVP( struct DiamMessage *dmMessage, char *sTGPPNSAPI, int iVendorId, int iMandatory, int iLength);

void setTGPPNSAPIAVP( struct DiamAvp *dmAvp, char *sTGPPNSAPI, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 3
* Data Type : OctetString
*/
void addTGPPPDPTypeAVP( struct DiamMessage *dmMessage, char *sTGPPPDPType, int iVendorId, int iMandatory, int iLength);

void setTGPPPDPTypeAVP( struct DiamAvp *dmAvp, char *sTGPPPDPType, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 21
* Data Type : OctetString
*/
void addTGPPRATTypeAVP( struct DiamMessage *dmMessage, char *sTGPPRATType, int iVendorId, int iMandatory, int iLength);

void setTGPPRATTypeAVP( struct DiamAvp *dmAvp, char *sTGPPRATType, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 12
* Data Type : OctetString
*/
void addTGPPSelectionModeAVP( struct DiamMessage *dmMessage, char *sTGPPSelectionMode, int iVendorId, int iMandatory, int iLength);

void setTGPPSelectionModeAVP( struct DiamAvp *dmAvp, char *sTGPPSelectionMode, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 11
* Data Type : OctetString
*/
void addTGPPSessionStopIndicatorAVP( struct DiamMessage *dmMessage, char *sTGPPSessionStopIndicator, int iVendorId, int iMandatory, int iLength);

void setTGPPSessionStopIndicatorAVP( struct DiamAvp *dmAvp, char *sTGPPSessionStopIndicator, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 18
* Data Type : OctetString
*/
void addTGPPSGSNMCCMNCAVP( struct DiamMessage *dmMessage, char *sTGPPSGSNMCCMNC, int iVendorId, int iMandatory, int iLength);

void setTGPPSGSNMCCMNCAVP( struct DiamAvp *dmAvp, char *sTGPPSGSNMCCMNC, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 22
* Data Type : OctetString
*/
void addTGPPUserLocationInfoAVP( struct DiamMessage *dmMessage, char *sTGPPUserLocationInfo, int iVendorId, int iMandatory, int iLength);

void setTGPPUserLocationInfoAVP( struct DiamAvp *dmAvp, char *sTGPPUserLocationInfo, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 5535
* Data Type : OctetString
*/
void addTGPP2BSIDAVP( struct DiamMessage *dmMessage, char *sTGPP2BSID, int iVendorId, int iMandatory, int iLength);

void setTGPP2BSIDAVP( struct DiamAvp *dmAvp, char *sTGPP2BSID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 503
* Data Type : OctetString
*/
void addAccessNetworkChargingIdentifierValueAVP( struct DiamMessage *dmMessage, char *sAccessNetworkChargingIdentifierValue, int iVendorId, int iMandatory, int iLength);

void setAccessNetworkChargingIdentifierValueAVP( struct DiamAvp *dmAvp, char *sAccessNetworkChargingIdentifierValue, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 505
* Data Type : OctetString
*/
void addAFChargingIdentifierAVP( struct DiamMessage *dmMessage, char *sAFChargingIdentifier, int iVendorId, int iMandatory, int iLength);

void setAFChargingIdentifierAVP( struct DiamAvp *dmAvp, char *sAFChargingIdentifier, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1034
* Data Type : OctetString
*/
void addAllocationRetentionPriorityAVP( struct DiamMessage *dmMessage, char *sAllocationRetentionPriority, int iVendorId, int iMandatory, int iLength);

void setAllocationRetentionPriorityAVP( struct DiamAvp *dmAvp, char *sAllocationRetentionPriority, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2101
* Data Type : OctetString
*/
void addApplicationServerIDAVP( struct DiamMessage *dmMessage, char *sApplicationServerID, int iVendorId, int iMandatory, int iLength);

void setApplicationServerIDAVP( struct DiamAvp *dmAvp, char *sApplicationServerID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2102
* Data Type : OctetString
*/
void addApplicationServiceTypeAVP( struct DiamMessage *dmMessage, char *sApplicationServiceType, int iVendorId, int iMandatory, int iLength);

void setApplicationServiceTypeAVP( struct DiamAvp *dmAvp, char *sApplicationServiceType, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2103
* Data Type : OctetString
*/
void addApplicationSessionIDAVP( struct DiamMessage *dmMessage, char *sApplicationSessionID, int iVendorId, int iMandatory, int iLength);

void setApplicationSessionIDAVP( struct DiamAvp *dmAvp, char *sApplicationSessionID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1004
* Data Type : OctetString
*/
void addChargingRuleBaseNameAVP( struct DiamMessage *dmMessage, char *sChargingRuleBaseName, int iVendorId, int iMandatory, int iLength);

void setChargingRuleBaseNameAVP( struct DiamAvp *dmAvp, char *sChargingRuleBaseName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 294
* Data Type : DiameterIdentity
*/
void addErrorReportingHostAVP( struct DiamMessage *dmMessage, char *sErrorReportingHost, int iVendorId, int iMandatory, int iLength);

void setErrorReportingHostAVP( struct DiamAvp *dmAvp, char *sErrorReportingHost, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 264
* Data Type : DiameterIdentity
*/
void addOriginHostAVP( struct DiamMessage *dmMessage, char *sOriginHost, int iVendorId, int iMandatory, int iLength);

void setOriginHostAVP( struct DiamAvp *dmAvp, char *sOriginHost, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 296
* Data Type : DiameterIdentity
*/
void addOriginRealmAVP( struct DiamMessage *dmMessage, char *sOriginRealm, int iVendorId, int iMandatory, int iLength);

void setOriginRealmAVP( struct DiamAvp *dmAvp, char *sOriginRealm, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 280
* Data Type : DiameterIdentity
*/
void addProxyHostAVP( struct DiamMessage *dmMessage, char *sProxyHost, int iVendorId, int iMandatory, int iLength);

void setProxyHostAVP( struct DiamAvp *dmAvp, char *sProxyHost, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 282
* Data Type : DiameterIdentity
*/
void addRouteRecordAVP( struct DiamMessage *dmMessage, char *sRouteRecord, int iVendorId, int iMandatory, int iLength);

void setRouteRecordAVP( struct DiamAvp *dmAvp, char *sRouteRecord, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 300
* Data Type : Grouped
*/
void setE2ESequenceAVPAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 297
* Data Type : Grouped
*/
void setExperimentalResultAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 279
* Data Type : Grouped
*/
void setFailedAVPAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 284
* Data Type : Grouped
*/
void setProxyInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 443
* Data Type : Grouped
*/
void setSubscriptionIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 260
* Data Type : Grouped
*/
void setVendorSpecificApplicationIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 437
* Data Type : Grouped
*/
void setRequestedServiceUnitAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 446
* Data Type : Grouped
*/
void setUsedServiceUnitAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 440
* Data Type : Grouped
*/
void setServiceParameterInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 458
* Data Type : Grouped
*/
void setUserEquipmentInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2052
* Data Type : Grouped
*/
void setAccumulatedCostAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1207
* Data Type : Grouped
*/
void setAdditionalContentInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 898
* Data Type : Grouped
*/
void setAddressDomainAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1276
* Data Type : Grouped
*/
void setAFCorrelationInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2053
* Data Type : Grouped
*/
void setAoCCostInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2054
* Data Type : Grouped
*/
void setAoCInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 850
* Data Type : Grouped
*/
void setApplicationServerInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2056
* Data Type : Grouped
*/
void setCurrentTariffAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2002
* Data Type : Grouped
*/
void setDestinationInterfaceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1272
* Data Type : Grouped
*/
void setEarlyMediaDescriptionAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1266
* Data Type : Grouped
*/
void setEnvelopeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 823
* Data Type : Grouped
*/
void setEventTypeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 876
* Data Type : Grouped
*/
void setIMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2062
* Data Type : Grouped
*/
void setIncrementalCostAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 838
* Data Type : Grouped
*/
void setInterOperatorIdentifierAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1232
* Data Type : Grouped
*/
void setLCSClientIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 878
* Data Type : Grouped
*/
void setLCSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1239
* Data Type : Grouped
*/
void setLCSRequestorIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1244
* Data Type : Grouped
*/
void setLocationTypeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 880
* Data Type : Grouped
*/
void setMBMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 889
* Data Type : Grouped
*/
void setMessageBodyAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1213
* Data Type : Grouped
*/
void setMessageClassAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1203
* Data Type : Grouped
*/
void setMMContentTypeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 877
* Data Type : Grouped
*/
void setMMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2030
* Data Type : Grouped
*/
void setMMTelInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2057
* Data Type : Grouped
*/
void setNextTariffAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1278
* Data Type : Grouped
*/
void setOfflineChargingAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 886
* Data Type : Grouped
*/
void setOriginatorAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2027
* Data Type : Grouped
*/
void setOriginatorReceivedAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2009
* Data Type : Grouped
*/
void setOriginatorInterfaceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1260
* Data Type : Grouped
*/
void setParticipantGroupAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 879
* Data Type : Grouped
*/
void setPoCInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1252
* Data Type : Grouped
*/
void setPoCUserRoleAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 865
* Data Type : Grouped
*/
void setPSFurnishChargingInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 874
* Data Type : Grouped
*/
void setPSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2058
* Data Type : Grouped
*/
void setRateElementAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1201
* Data Type : Grouped
*/
void setRecipientAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2026
* Data Type : Grouped
*/
void setRecipientInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2028
* Data Type : Grouped
*/
void setRecipientReceivedAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2021
* Data Type : Grouped
*/
void setRemainingBalanceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2059
* Data Type : Grouped
*/
void setScaleFactorAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 843
* Data Type : Grouped
*/
void setSDPMediaComponentAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1273
* Data Type : Grouped
*/
void setSDPTimeStampsAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2040
* Data Type : Grouped
*/
void setServiceDataContainerAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 873
* Data Type : Grouped
*/
void setServiceInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1249
* Data Type : Grouped
*/
void setServiceSpecificInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2000
* Data Type : Grouped
*/
void setSMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2048
* Data Type : Grouped
*/
void setSupplementaryServiceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 1255
* Data Type : Grouped
*/
void setTalkBurstExchangeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);

/**
* AVP Code : 2023
* Data Type : UTF8String
*/
void addCarrierSelectRoutingInformationAVP( struct DiamMessage *dmMessage, char *sCarrierSelectRoutingInformation, int iVendorId, int iMandatory, int iLength);

void setCarrierSelectRoutingInformationAVP( struct DiamAvp *dmAvp, char *sCarrierSelectRoutingInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 857
* Data Type : UTF8String
*/
void addChargedPartyAVP( struct DiamMessage *dmMessage, char *sChargedParty, int iVendorId, int iMandatory, int iLength);

void setChargedPartyAVP( struct DiamAvp *dmAvp, char *sChargedParty, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 828
* Data Type : UTF8String
*/
void addContentDispositionAVP( struct DiamMessage *dmMessage, char *sContentDisposition, int iVendorId, int iMandatory, int iLength);

void setContentDispositionAVP( struct DiamAvp *dmAvp, char *sContentDisposition, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 826
* Data Type : UTF8String
*/
void addContentTypeAVP( struct DiamMessage *dmMessage, char *sContentType, int iVendorId, int iMandatory, int iLength);

void setContentTypeAVP( struct DiamAvp *dmAvp, char *sContentType, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1230
* Data Type : UTF8String
*/
void addDeferredLocationEventTypeAVP( struct DiamMessage *dmMessage, char *sDeferredLocationEventType, int iVendorId, int iMandatory, int iLength);

void setDeferredLocationEventTypeAVP( struct DiamAvp *dmAvp, char *sDeferredLocationEventType, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1200
* Data Type : UTF8String
*/
void addDomainNameAVP( struct DiamMessage *dmMessage, char *sDomainName, int iVendorId, int iMandatory, int iLength);

void setDomainNameAVP( struct DiamAvp *dmAvp, char *sDomainName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 825
* Data Type : UTF8String
*/
void addEventAVP( struct DiamMessage *dmMessage, char *sEvent, int iVendorId, int iMandatory, int iLength);

void setEventAVP( struct DiamAvp *dmAvp, char *sEvent, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 841
* Data Type : UTF8String
*/
void addIMSChargingIdentifierAVP( struct DiamMessage *dmMessage, char *sIMSChargingIdentifier, int iVendorId, int iMandatory, int iLength);

void setIMSChargingIdentifierAVP( struct DiamAvp *dmAvp, char *sIMSChargingIdentifier, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1281
* Data Type : UTF8String
*/
void addIMSCommunicationServiceIdentifierAVP( struct DiamMessage *dmMessage, char *sIMSCommunicationServiceIdentifier, int iVendorId, int iMandatory, int iLength);

void setIMSCommunicationServiceIdentifierAVP( struct DiamAvp *dmAvp, char *sIMSCommunicationServiceIdentifier, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 852
* Data Type : UTF8String
*/
void addIncomingTrunkGroupIdAVP( struct DiamMessage *dmMessage, char *sIncomingTrunkGroupId, int iVendorId, int iMandatory, int iLength);

void setIncomingTrunkGroupIdAVP( struct DiamAvp *dmAvp, char *sIncomingTrunkGroupId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2003
* Data Type : UTF8String
*/
void addInterfaceIdAVP( struct DiamMessage *dmMessage, char *sInterfaceId, int iVendorId, int iMandatory, int iLength);

void setInterfaceIdAVP( struct DiamAvp *dmAvp, char *sInterfaceId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2004
* Data Type : UTF8String
*/
void addInterfacePortAVP( struct DiamMessage *dmMessage, char *sInterfacePort, int iVendorId, int iMandatory, int iLength);

void setInterfacePortAVP( struct DiamAvp *dmAvp, char *sInterfacePort, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2005
* Data Type : UTF8String
*/
void addInterfaceTextAVP( struct DiamMessage *dmMessage, char *sInterfaceText, int iVendorId, int iMandatory, int iLength);

void setInterfaceTextAVP( struct DiamAvp *dmAvp, char *sInterfaceText, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1233
* Data Type : UTF8String
*/
void addLCSClientDialedByMSAVP( struct DiamMessage *dmMessage, char *sLCSClientDialedByMS, int iVendorId, int iMandatory, int iLength);

void setLCSClientDialedByMSAVP( struct DiamAvp *dmAvp, char *sLCSClientDialedByMS, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1234
* Data Type : UTF8String
*/
void addLCSClientExternalIDAVP( struct DiamMessage *dmMessage, char *sLCSClientExternalID, int iVendorId, int iMandatory, int iLength);

void setLCSClientExternalIDAVP( struct DiamAvp *dmAvp, char *sLCSClientExternalID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1231
* Data Type : UTF8String
*/
void addLCSClientNameAVP( struct DiamMessage *dmMessage, char *sLCSClientName, int iVendorId, int iMandatory, int iLength);

void setLCSClientNameAVP( struct DiamAvp *dmAvp, char *sLCSClientName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1236
* Data Type : UTF8String
*/
void addLCSDataCodingSchemeAVP( struct DiamMessage *dmMessage, char *sLCSDataCodingScheme, int iVendorId, int iMandatory, int iLength);

void setLCSDataCodingSchemeAVP( struct DiamAvp *dmAvp, char *sLCSDataCodingScheme, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1238
* Data Type : UTF8String
*/
void addLCSNameStringAVP( struct DiamMessage *dmMessage, char *sLCSNameString, int iVendorId, int iMandatory, int iLength);

void setLCSNameStringAVP( struct DiamAvp *dmAvp, char *sLCSNameString, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1240
* Data Type : UTF8String
*/
void addLCSRequestorIdStringAVP( struct DiamMessage *dmMessage, char *sLCSRequestorIdString, int iVendorId, int iMandatory, int iLength);

void setLCSRequestorIdStringAVP( struct DiamAvp *dmAvp, char *sLCSRequestorIdString, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1242
* Data Type : UTF8String
*/
void addLocationEstimateAVP( struct DiamMessage *dmMessage, char *sLocationEstimate, int iVendorId, int iMandatory, int iLength);

void setLocationEstimateAVP( struct DiamAvp *dmAvp, char *sLocationEstimate, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1288
* Data Type : UTF8String
*/
void addMediaInitiatorPartyAVP( struct DiamMessage *dmMessage, char *sMediaInitiatorParty, int iVendorId, int iMandatory, int iLength);

void setMediaInitiatorPartyAVP( struct DiamAvp *dmAvp, char *sMediaInitiatorParty, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1210
* Data Type : UTF8String
*/
void addMessageIDAVP( struct DiamMessage *dmMessage, char *sMessageID, int iVendorId, int iMandatory, int iLength);

void setMessageIDAVP( struct DiamAvp *dmAvp, char *sMessageID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2064
* Data Type : UTF8String
*/
void addNodeIdAVP( struct DiamMessage *dmMessage, char *sNodeId, int iVendorId, int iMandatory, int iLength);

void setNodeIdAVP( struct DiamAvp *dmAvp, char *sNodeId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2024
* Data Type : UTF8String
*/
void addNumberPortabilityRoutingInformationAVP( struct DiamMessage *dmMessage, char *sNumberPortabilityRoutingInformation, int iVendorId, int iMandatory, int iLength);

void setNumberPortabilityRoutingInformationAVP( struct DiamAvp *dmAvp, char *sNumberPortabilityRoutingInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 839
* Data Type : UTF8String
*/
void addOriginatingIOIAVP( struct DiamMessage *dmMessage, char *sOriginatingIOI, int iVendorId, int iMandatory, int iLength);

void setOriginatingIOIAVP( struct DiamAvp *dmAvp, char *sOriginatingIOI, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 853
* Data Type : UTF8String
*/
void addOutgoingTrunkGroupIdAVP( struct DiamMessage *dmMessage, char *sOutgoingTrunkGroupId, int iVendorId, int iMandatory, int iLength);

void setOutgoingTrunkGroupIdAVP( struct DiamAvp *dmAvp, char *sOutgoingTrunkGroupId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 887
* Data Type : UTF8String
*/
void addParticipantsInvolvedAVP( struct DiamMessage *dmMessage, char *sParticipantsInvolved, int iVendorId, int iMandatory, int iLength);

void setParticipantsInvolvedAVP( struct DiamAvp *dmAvp, char *sParticipantsInvolved, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 858
* Data Type : UTF8String
*/
void addPoCControllingAddressAVP( struct DiamMessage *dmMessage, char *sPoCControllingAddress, int iVendorId, int iMandatory, int iLength);

void setPoCControllingAddressAVP( struct DiamAvp *dmAvp, char *sPoCControllingAddress, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 859
* Data Type : UTF8String
*/
void addPoCGroupNameAVP( struct DiamMessage *dmMessage, char *sPoCGroupName, int iVendorId, int iMandatory, int iLength);

void setPoCGroupNameAVP( struct DiamAvp *dmAvp, char *sPoCGroupName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1229
* Data Type : UTF8String
*/
void addPoCSessionIdAVP( struct DiamMessage *dmMessage, char *sPoCSessionId, int iVendorId, int iMandatory, int iLength);

void setPoCSessionIdAVP( struct DiamAvp *dmAvp, char *sPoCSessionId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1253
* Data Type : UTF8String
*/
void addPoCUserRoleIDsAVP( struct DiamMessage *dmMessage, char *sPoCUserRoleIDs, int iVendorId, int iMandatory, int iLength);

void setPoCUserRoleIDsAVP( struct DiamAvp *dmAvp, char *sPoCUserRoleIDs, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1245
* Data Type : UTF8String
*/
void addPositioningDataAVP( struct DiamMessage *dmMessage, char *sPositioningData, int iVendorId, int iMandatory, int iLength);

void setPositioningDataAVP( struct DiamAvp *dmAvp, char *sPositioningData, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1223
* Data Type : UTF8String
*/
void addReplyApplicIDAVP( struct DiamMessage *dmMessage, char *sReplyApplicID, int iVendorId, int iMandatory, int iLength);

void setReplyApplicIDAVP( struct DiamAvp *dmAvp, char *sReplyApplicID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1251
* Data Type : UTF8String
*/
void addRequestedPartyAddressAVP( struct DiamMessage *dmMessage, char *sRequestedPartyAddress, int iVendorId, int iMandatory, int iLength);

void setRequestedPartyAddressAVP( struct DiamAvp *dmAvp, char *sRequestedPartyAddress, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 845
* Data Type : UTF8String
*/
void addSDPMediaDescriptionAVP( struct DiamMessage *dmMessage, char *sSDPMediaDescription, int iVendorId, int iMandatory, int iLength);

void setSDPMediaDescriptionAVP( struct DiamAvp *dmAvp, char *sSDPMediaDescription, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 844
* Data Type : UTF8String
*/
void addSDPMediaNameAVP( struct DiamMessage *dmMessage, char *sSDPMediaName, int iVendorId, int iMandatory, int iLength);

void setSDPMediaNameAVP( struct DiamAvp *dmAvp, char *sSDPMediaName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 842
* Data Type : UTF8String
*/
void addSDPSessionDescriptionAVP( struct DiamMessage *dmMessage, char *sSDPSessionDescription, int iVendorId, int iMandatory, int iLength);

void setSDPSessionDescriptionAVP( struct DiamAvp *dmAvp, char *sSDPSessionDescription, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 855
* Data Type : UTF8String
*/
void addServiceIdAVP( struct DiamMessage *dmMessage, char *sServiceId, int iVendorId, int iMandatory, int iLength);

void setServiceIdAVP( struct DiamAvp *dmAvp, char *sServiceId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 863
* Data Type : UTF8String
*/
void addServiceSpecificDataAVP( struct DiamMessage *dmMessage, char *sServiceSpecificData, int iVendorId, int iMandatory, int iLength);

void setServiceSpecificDataAVP( struct DiamAvp *dmAvp, char *sServiceSpecificData, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 824
* Data Type : UTF8String
*/
void addSIPMethodAVP( struct DiamMessage *dmMessage, char *sSIPMethod, int iVendorId, int iMandatory, int iLength);

void setSIPMethodAVP( struct DiamAvp *dmAvp, char *sSIPMethod, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 840
* Data Type : UTF8String
*/
void addTerminatingIOIAVP( struct DiamMessage *dmMessage, char *sTerminatingIOI, int iVendorId, int iMandatory, int iLength);

void setTerminatingIOIAVP( struct DiamAvp *dmAvp, char *sTerminatingIOI, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1215
* Data Type : UTF8String
*/
void addTokenTextAVP( struct DiamMessage *dmMessage, char *sTokenText, int iVendorId, int iMandatory, int iLength);

void setTokenTextAVP( struct DiamAvp *dmAvp, char *sTokenText, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 830
* Data Type : UTF8String
*/
void addUserSessionIdAVP( struct DiamMessage *dmMessage, char *sUserSessionId, int iVendorId, int iMandatory, int iLength);

void setUserSessionIdAVP( struct DiamAvp *dmAvp, char *sUserSessionId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1246
* Data Type : UTF8String
*/
void addWLANSessionIdAVP( struct DiamMessage *dmMessage, char *sWLANSessionId, int iVendorId, int iMandatory, int iLength);

void setWLANSessionIdAVP( struct DiamAvp *dmAvp, char *sWLANSessionId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 444
* Data Type : UTF8String
*/
void addSubscriptionIdDataAVP( struct DiamMessage *dmMessage, char *sSubscriptionIdData, int iVendorId, int iMandatory, int iLength);

void setSubscriptionIdDataAVP( struct DiamAvp *dmAvp, char *sSubscriptionIdData, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 44
* Data Type : OctetString
*/
void addAccountingSessionIdAVP( struct DiamMessage *dmMessage, char *sAccountingSessionId, int iVendorId, int iMandatory, int iLength);

void setAccountingSessionIdAVP( struct DiamAvp *dmAvp, char *sAccountingSessionId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 25
* Data Type : OctetString
*/
void addClassAVP( struct DiamMessage *dmMessage, char *sClass, int iVendorId, int iMandatory, int iLength);

void setClassAVP( struct DiamAvp *dmAvp, char *sClass, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 33
* Data Type : OctetString
*/
void addProxyStateAVP( struct DiamMessage *dmMessage, char *sProxyState, int iVendorId, int iMandatory, int iLength);

void setProxyStateAVP( struct DiamAvp *dmAvp, char *sProxyState, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 411
* Data Type : OctetString
*/
void addCCCorrelationIdAVP( struct DiamMessage *dmMessage, char *sCCCorrelationId, int iVendorId, int iMandatory, int iLength);

void setCCCorrelationIdAVP( struct DiamAvp *dmAvp, char *sCCCorrelationId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1263
* Data Type : OctetString
*/
void addAccessNetworkInformationAVP( struct DiamMessage *dmMessage, char *sAccessNetworkInformation, int iVendorId, int iMandatory, int iLength);

void setAccessNetworkInformationAVP( struct DiamAvp *dmAvp, char *sAccessNetworkInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 854
* Data Type : OctetString
*/
void addBearerServiceAVP( struct DiamMessage *dmMessage, char *sBearerService, int iVendorId, int iMandatory, int iLength);

void setBearerServiceAVP( struct DiamAvp *dmAvp, char *sBearerService, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 866
* Data Type : OctetString
*/
void addPSFreeFormatDataAVP( struct DiamMessage *dmMessage, char *sPSFreeFormatData, int iVendorId, int iMandatory, int iLength);

void setPSFreeFormatDataAVP( struct DiamAvp *dmAvp, char *sPSFreeFormatData, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2022
* Data Type : OctetString
*/
void addRefundInformationAVP( struct DiamMessage *dmMessage, char *sRefundInformation, int iVendorId, int iMandatory, int iLength);

void setRefundInformationAVP( struct DiamAvp *dmAvp, char *sRefundInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2013
* Data Type : OctetString
*/
void addSMProtocolIDAVP( struct DiamMessage *dmMessage, char *sSMProtocolID, int iVendorId, int iMandatory, int iLength);

void setSMProtocolIDAVP( struct DiamAvp *dmAvp, char *sSMProtocolID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2014
* Data Type : OctetString
*/
void addSMStatusAVP( struct DiamMessage *dmMessage, char *sSMStatus, int iVendorId, int iMandatory, int iLength);

void setSMStatusAVP( struct DiamAvp *dmAvp, char *sSMStatus, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2015
* Data Type : OctetString
*/
void addSMUserDataHeaderAVP( struct DiamMessage *dmMessage, char *sSMUserDataHeader, int iVendorId, int iMandatory, int iLength);

void setSMUserDataHeaderAVP( struct DiamAvp *dmAvp, char *sSMUserDataHeader, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 891
* Data Type : OctetString
*/
void addWAGPLMNIdAVP( struct DiamMessage *dmMessage, char *sWAGPLMNId, int iVendorId, int iMandatory, int iLength);

void setWAGPLMNIdAVP( struct DiamAvp *dmAvp, char *sWAGPLMNId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 421
* Data Type : Unsigned64
*/
void addCCTotalOctetsAVP( struct DiamMessage *dmMessage, unsigned long ulCCTotalOctets, int iVendorId, int iMandatory);

void setCCTotalOctetsAVP( struct DiamAvp *dmAvp, unsigned long ulCCTotalOctets, int iVendorId, int iMandatory);

/**
* AVP Code : 412
* Data Type : Unsigned64
*/
void addCCInputOctetsAVP( struct DiamMessage *dmMessage, unsigned long ulCCInputOctets, int iVendorId, int iMandatory);

void setCCInputOctetsAVP( struct DiamAvp *dmAvp, unsigned long ulCCInputOctets, int iVendorId, int iMandatory);

/**
* AVP Code : 414
* Data Type : Unsigned64
*/
void addCCOutputOctetsAVP( struct DiamMessage *dmMessage, unsigned long ulCCOutputOctets, int iVendorId, int iMandatory);

void setCCOutputOctetsAVP( struct DiamAvp *dmAvp, unsigned long ulCCOutputOctets, int iVendorId, int iMandatory);

/**
* AVP Code : 287
* Data Type : Unsigned64
*/
void addAccountingSubSessionIdAVP( struct DiamMessage *dmMessage, unsigned long ulAccountingSubSessionId, int iVendorId, int iMandatory);

void setAccountingSubSessionIdAVP( struct DiamAvp *dmAvp, unsigned long ulAccountingSubSessionId, int iVendorId, int iMandatory);

/**
* AVP Code : 419
* Data Type : Unsigned64
*/
void addCCSubSessionIdAVP( struct DiamMessage *dmMessage, unsigned long ulCCSubSessionId, int iVendorId, int iMandatory);

void setCCSubSessionIdAVP( struct DiamAvp *dmAvp, unsigned long ulCCSubSessionId, int iVendorId, int iMandatory);

/**
* AVP Code : 293
* Data Type : DiameterIdentity
*/
void addDestinationHostAVP( struct DiamMessage *dmMessage, char *sDestinationHost, int iVendorId, int iMandatory, int iLength);

void setDestinationHostAVP( struct DiamAvp *dmAvp, char *sDestinationHost, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 283
* Data Type : DiameterIdentity
*/
void addDestinationRealmAVP( struct DiamMessage *dmMessage, char *sDestinationRealm, int iVendorId, int iMandatory, int iLength);

void addDestinationRealmSimulated( struct DiamMessage *dmMessage, int iVendorId, int iMandatory);

void setDestinationRealmAVP( struct DiamAvp *dmAvp, char *sDestinationRealm, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2055
* Data Type : Enumerated
*/
void addAoCRequestTypeAVP( struct DiamMessage *dmMessage, int iAoCRequestType, int iVendorId, int iMandatory);

void setAoCRequestTypeAVP( struct DiamAvp *dmAvp, int iAoCRequestType, int iVendorId, int iMandatory);

/**
* AVP Code : 1214
* Data Type : Enumerated
*/
void addClassIdentifierAVP( struct DiamMessage *dmMessage, int iClassIdentifier, int iVendorId, int iMandatory);

void setClassIdentifierAVP( struct DiamAvp *dmAvp, int iClassIdentifier, int iVendorId, int iMandatory);

/**
* AVP Code : 1220
* Data Type : Enumerated
*/
void addContentClassAVP( struct DiamMessage *dmMessage, int iContentClass, int iVendorId, int iMandatory);

void setContentClassAVP( struct DiamAvp *dmAvp, int iContentClass, int iVendorId, int iMandatory);

/**
* AVP Code : 1216
* Data Type : Enumerated
*/
void addDeliveryReportRequestedAVP( struct DiamMessage *dmMessage, int iDeliveryReportRequested, int iVendorId, int iMandatory);

void setDeliveryReportRequestedAVP( struct DiamAvp *dmAvp, int iDeliveryReportRequested, int iVendorId, int iMandatory);

/**
* AVP Code : 1221
* Data Type : Enumerated
*/
void addDRMContentAVP( struct DiamMessage *dmMessage, int iDRMContent, int iVendorId, int iMandatory);

void setDRMContentAVP( struct DiamAvp *dmAvp, int iDRMContent, int iVendorId, int iMandatory);

/**
* AVP Code : 2051
* Data Type : Enumerated
*/
void addDynamicAddressFlagAVP( struct DiamMessage *dmMessage, int iDynamicAddressFlag, int iVendorId, int iMandatory);

void setDynamicAddressFlagAVP( struct DiamAvp *dmAvp, int iDynamicAddressFlag, int iVendorId, int iMandatory);

/**
* AVP Code : 1268
* Data Type : Enumerated
*/
void addEnvelopeReportingAVP( struct DiamMessage *dmMessage, int iEnvelopeReporting, int iVendorId, int iMandatory);

void setEnvelopeReportingAVP( struct DiamAvp *dmAvp, int iEnvelopeReporting, int iVendorId, int iMandatory);

/**
* AVP Code : 1224
* Data Type : Enumerated
*/
void addFileRepairSupportedAVP( struct DiamMessage *dmMessage, int iFileRepairSupported, int iVendorId, int iMandatory);

void setFileRepairSupportedAVP( struct DiamAvp *dmAvp, int iFileRepairSupported, int iVendorId, int iMandatory);

/**
* AVP Code : 2006
* Data Type : Enumerated
*/
void addInterfaceTypeAVP( struct DiamMessage *dmMessage, int iInterfaceType, int iVendorId, int iMandatory);

void setInterfaceTypeAVP( struct DiamAvp *dmAvp, int iInterfaceType, int iVendorId, int iMandatory);

/**
* AVP Code : 1241
* Data Type : Enumerated
*/
void addLCSClientTypeAVP( struct DiamMessage *dmMessage, int iLCSClientType, int iVendorId, int iMandatory);

void setLCSClientTypeAVP( struct DiamAvp *dmAvp, int iLCSClientType, int iVendorId, int iMandatory);

/**
* AVP Code : 1237
* Data Type : Enumerated
*/
void addLCSFormatIndicatorAVP( struct DiamMessage *dmMessage, int iLCSFormatIndicator, int iVendorId, int iMandatory);

void setLCSFormatIndicatorAVP( struct DiamAvp *dmAvp, int iLCSFormatIndicator, int iVendorId, int iMandatory);

/**
* AVP Code : 1243
* Data Type : Enumerated
*/
void addLocationEstimateTypeAVP( struct DiamMessage *dmMessage, int iLocationEstimateType, int iVendorId, int iMandatory);

void setLocationEstimateTypeAVP( struct DiamAvp *dmAvp, int iLocationEstimateType, int iVendorId, int iMandatory);

/**
* AVP Code : 2020
* Data Type : Enumerated
*/
void addLowBalanceIndicationAVP( struct DiamMessage *dmMessage, int iLowBalanceIndication, int iVendorId, int iMandatory);

void setLowBalanceIndicationAVP( struct DiamAvp *dmAvp, int iLowBalanceIndication, int iVendorId, int iMandatory);

/**
* AVP Code : 1225
* Data Type : Enumerated
*/
void addMBMSUserServiceTypeAVP( struct DiamMessage *dmMessage, int iMBMSUserServiceType, int iVendorId, int iMandatory);

void setMBMSUserServiceTypeAVP( struct DiamAvp *dmAvp, int iMBMSUserServiceType, int iVendorId, int iMandatory);

/**
* AVP Code : 882
* Data Type : Enumerated
*/
void addMediaInitiatorFlagAVP( struct DiamMessage *dmMessage, int iMediaInitiatorFlag, int iVendorId, int iMandatory);

void setMediaInitiatorFlagAVP( struct DiamAvp *dmAvp, int iMediaInitiatorFlag, int iVendorId, int iMandatory);

/**
* AVP Code : 1211
* Data Type : Enumerated
*/
void addMessageTypeAVP( struct DiamMessage *dmMessage, int iMessageType, int iVendorId, int iMandatory);

void setMessageTypeAVP( struct DiamAvp *dmAvp, int iMessageType, int iVendorId, int iMandatory);

/**
* AVP Code : 1248
* Data Type : Enumerated
*/
void addMMBoxStorageRequestedAVP( struct DiamMessage *dmMessage, int iMMBoxStorageRequested, int iVendorId, int iMandatory);

void setMMBoxStorageRequestedAVP( struct DiamAvp *dmAvp, int iMMBoxStorageRequested, int iVendorId, int iMandatory);

/**
* AVP Code : 862
* Data Type : Enumerated
*/
void addNodeFunctionalityAVP( struct DiamMessage *dmMessage, int iNodeFunctionality, int iVendorId, int iMandatory);

void setNodeFunctionalityAVP( struct DiamAvp *dmAvp, int iNodeFunctionality, int iVendorId, int iMandatory);

/**
* AVP Code : 864
* Data Type : Enumerated
*/
void addOriginatorAVP( struct DiamMessage *dmMessage, int iOriginator, int iVendorId, int iMandatory);

void setOriginatorAVP( struct DiamAvp *dmAvp, int iOriginator, int iVendorId, int iMandatory);

/**
* AVP Code : 1259
* Data Type : Enumerated
*/
void addParticipantAccessPriorityAVP( struct DiamMessage *dmMessage, int iParticipantAccessPriority, int iVendorId, int iMandatory);

void setParticipantAccessPriorityAVP( struct DiamAvp *dmAvp, int iParticipantAccessPriority, int iVendorId, int iMandatory);

/**
* AVP Code : 2049
* Data Type : Enumerated
*/
void addParticipantActionTypeAVP( struct DiamMessage *dmMessage, int iParticipantActionType, int iVendorId, int iMandatory);

void setParticipantActionTypeAVP( struct DiamAvp *dmAvp, int iParticipantActionType, int iVendorId, int iMandatory);

/**
* AVP Code : 1247
* Data Type : Enumerated
*/
void addPDPContextTypeAVP( struct DiamMessage *dmMessage, int iPDPContextType, int iVendorId, int iMandatory);

void setPDPContextTypeAVP( struct DiamAvp *dmAvp, int iPDPContextType, int iVendorId, int iMandatory);

/**
* AVP Code : 1261
* Data Type : Enumerated
*/
void addPoCChangeConditionAVP( struct DiamMessage *dmMessage, int iPoCChangeCondition, int iVendorId, int iMandatory);

void setPoCChangeConditionAVP( struct DiamAvp *dmAvp, int iPoCChangeCondition, int iVendorId, int iMandatory);

/**
* AVP Code : 2025
* Data Type : Enumerated
*/
void addPoCEventTypeAVP( struct DiamMessage *dmMessage, int iPoCEventType, int iVendorId, int iMandatory);

void setPoCEventTypeAVP( struct DiamAvp *dmAvp, int iPoCEventType, int iVendorId, int iMandatory);

/**
* AVP Code : 883
* Data Type : Enumerated
*/
void addPoCServerRoleAVP( struct DiamMessage *dmMessage, int iPoCServerRole, int iVendorId, int iMandatory);

void setPoCServerRoleAVP( struct DiamAvp *dmAvp, int iPoCServerRole, int iVendorId, int iMandatory);

/**
* AVP Code : 1277
* Data Type : Enumerated
*/
void addPoCSessionInitiationtypeAVP( struct DiamMessage *dmMessage, int iPoCSessionInitiationtype, int iVendorId, int iMandatory);

void setPoCSessionInitiationtypeAVP( struct DiamAvp *dmAvp, int iPoCSessionInitiationtype, int iVendorId, int iMandatory);

/**
* AVP Code : 884
* Data Type : Enumerated
*/
void addPoCSessionTypeAVP( struct DiamMessage *dmMessage, int iPoCSessionType, int iVendorId, int iMandatory);

void setPoCSessionTypeAVP( struct DiamAvp *dmAvp, int iPoCSessionType, int iVendorId, int iMandatory);

/**
* AVP Code : 1254
* Data Type : Enumerated
*/
void addPoCUserRoleinfoUnitsAVP( struct DiamMessage *dmMessage, int iPoCUserRoleinfoUnits, int iVendorId, int iMandatory);

void setPoCUserRoleinfoUnitsAVP( struct DiamAvp *dmAvp, int iPoCUserRoleinfoUnits, int iVendorId, int iMandatory);

/**
* AVP Code : 1209
* Data Type : Enumerated
*/
void addPriorityAVP( struct DiamMessage *dmMessage, int iPriority, int iVendorId, int iMandatory);

void setPriorityAVP( struct DiamAvp *dmAvp, int iPriority, int iVendorId, int iMandatory);

/**
* AVP Code : 867
* Data Type : Enumerated
*/
void addPSAppendFreeFormatDataAVP( struct DiamMessage *dmMessage, int iPSAppendFreeFormatData, int iVendorId, int iMandatory);

void setPSAppendFreeFormatDataAVP( struct DiamAvp *dmAvp, int iPSAppendFreeFormatData, int iVendorId, int iMandatory);

/**
* AVP Code : 1222
* Data Type : Enumerated
*/
void addReadReplyReportRequestedAVP( struct DiamMessage *dmMessage, int iReadReplyReportRequested, int iVendorId, int iMandatory);

void setReadReplyReportRequestedAVP( struct DiamAvp *dmAvp, int iReadReplyReportRequested, int iVendorId, int iMandatory);

/**
* AVP Code : 2011
* Data Type : Enumerated
*/
void addReplyPathRequestedAVP( struct DiamMessage *dmMessage, int iReplyPathRequested, int iVendorId, int iMandatory);

void setReplyPathRequestedAVP( struct DiamAvp *dmAvp, int iReplyPathRequested, int iVendorId, int iMandatory);

/**
* AVP Code : 872
* Data Type : Enumerated
*/
void addReportingReasonAVP( struct DiamMessage *dmMessage, int iReportingReason, int iVendorId, int iMandatory);

void setReportingReasonAVP( struct DiamAvp *dmAvp, int iReportingReason, int iVendorId, int iMandatory);

/**
* AVP Code : 829
* Data Type : Enumerated
*/
void addRoleofNodeAVP( struct DiamMessage *dmMessage, int iRoleofNode, int iVendorId, int iMandatory);

void setRoleofNodeAVP( struct DiamAvp *dmAvp, int iRoleofNode, int iVendorId, int iMandatory);

/**
* AVP Code : 2036
* Data Type : Enumerated
*/
void addSDPTypeAVP( struct DiamMessage *dmMessage, int iSDPType, int iVendorId, int iMandatory);

void setSDPTypeAVP( struct DiamAvp *dmAvp, int iSDPType, int iVendorId, int iMandatory);

/**
* AVP Code : 2047
* Data Type : Enumerated
*/
void addServingNodeTypeAVP( struct DiamMessage *dmMessage, int iServingNodeType, int iVendorId, int iMandatory);

void setServingNodeTypeAVP( struct DiamAvp *dmAvp, int iServingNodeType, int iVendorId, int iMandatory);

/**
* AVP Code : 2065
* Data Type : Enumerated
*/
void addSGWChangeAVP( struct DiamMessage *dmMessage, int iSGWChange, int iVendorId, int iMandatory);

void setSGWChangeAVP( struct DiamAvp *dmAvp, int iSGWChange, int iVendorId, int iMandatory);

/**
* AVP Code : 2007
* Data Type : Enumerated
*/
void addSMMessageTypeAVP( struct DiamMessage *dmMessage, int iSMMessageType, int iVendorId, int iMandatory);

void setSMMessageTypeAVP( struct DiamAvp *dmAvp, int iSMMessageType, int iVendorId, int iMandatory);

/**
* AVP Code : 2016
* Data Type : Enumerated
*/
void addSMSNodeAVP( struct DiamMessage *dmMessage, int iSMSNode, int iVendorId, int iMandatory);

void setSMSNodeAVP( struct DiamAvp *dmAvp, int iSMSNode, int iVendorId, int iMandatory);

/**
* AVP Code : 2029
* Data Type : Enumerated
*/
void addSMServiceTypeAVP( struct DiamMessage *dmMessage, int iSMServiceType, int iVendorId, int iMandatory);

void setSMServiceTypeAVP( struct DiamAvp *dmAvp, int iSMServiceType, int iVendorId, int iMandatory);

/**
* AVP Code : 2033
* Data Type : Enumerated
*/
void addSubscriberRoleAVP( struct DiamMessage *dmMessage, int iSubscriberRole, int iVendorId, int iMandatory);

void setSubscriberRoleAVP( struct DiamAvp *dmAvp, int iSubscriberRole, int iVendorId, int iMandatory);

/**
* AVP Code : 1271
* Data Type : Enumerated
*/
void addTimeQuotaTypeAVP( struct DiamMessage *dmMessage, int iTimeQuotaType, int iVendorId, int iMandatory);

void setTimeQuotaTypeAVP( struct DiamAvp *dmAvp, int iTimeQuotaType, int iVendorId, int iMandatory);

/**
* AVP Code : 870
* Data Type : Enumerated
*/
void addTriggerTypeAVP( struct DiamMessage *dmMessage, int iTriggerType, int iVendorId, int iMandatory);

void setTriggerTypeAVP( struct DiamAvp *dmAvp, int iTriggerType, int iVendorId, int iMandatory);

/**
* AVP Code : 1204
* Data Type : Enumerated
*/
void addTypeNumberAVP( struct DiamMessage *dmMessage, int iTypeNumber, int iVendorId, int iMandatory);

void setTypeNumberAVP( struct DiamAvp *dmAvp, int iTypeNumber, int iVendorId, int iMandatory);

/**
* AVP Code : 1279
* Data Type : Enumerated
*/
void addUserParticipatingTypeAVP( struct DiamMessage *dmMessage, int iUserParticipatingType, int iVendorId, int iMandatory);

void setUserParticipatingTypeAVP( struct DiamAvp *dmAvp, int iUserParticipatingType, int iVendorId, int iMandatory);

/**
* AVP Code : 50
* Data Type : UTF8String
*/
void addAcctMultiSessionIdAVP( struct DiamMessage *dmMessage, char *sAcctMultiSessionId, int iVendorId, int iMandatory, int iLength);

void setAcctMultiSessionIdAVP( struct DiamAvp *dmAvp, char *sAcctMultiSessionId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 281
* Data Type : UTF8String
*/
void addErrorMessageAVP( struct DiamMessage *dmMessage, char *sErrorMessage, int iVendorId, int iMandatory, int iLength);

void setErrorMessageAVP( struct DiamAvp *dmAvp, char *sErrorMessage, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 269
* Data Type : UTF8String
*/
void addProductNameAVP( struct DiamMessage *dmMessage, char *sProductName, int iVendorId, int iMandatory, int iLength);

void setProductNameAVP( struct DiamAvp *dmAvp, char *sProductName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 263
* Data Type : UTF8String
*/
void addSessionIdAVP( struct DiamMessage *dmMessage, char *sSessionId, int iVendorId, int iMandatory, int iLength);

void setSessionIdAVP( struct DiamAvp *dmAvp, char *sSessionId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1
* Data Type : UTF8String
*/
void addUserNameAVP( struct DiamMessage *dmMessage, char *sUserName, int iVendorId, int iMandatory, int iLength);

void setUserNameAVP( struct DiamAvp *dmAvp, char *sUserName, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 461
* Data Type : UTF8String
*/
void addServiceContextIdAVP( struct DiamMessage *dmMessage, char *sServiceContextId, int iVendorId, int iMandatory, int iLength);

void setServiceContextIdAVP( struct DiamAvp *dmAvp, char *sServiceContextId, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1205
* Data Type : UTF8String
*/
void addAdditionalTypeInformationAVP( struct DiamMessage *dmMessage, char *sAdditionalTypeInformation, int iVendorId, int iMandatory, int iLength);

void setAdditionalTypeInformationAVP( struct DiamAvp *dmAvp, char *sAdditionalTypeInformation, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 897
* Data Type : UTF8String
*/
void addAddressDataAVP( struct DiamMessage *dmMessage, char *sAddressData, int iVendorId, int iMandatory, int iLength);

void setAddressDataAVP( struct DiamAvp *dmAvp, char *sAddressData, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1280
* Data Type : UTF8String
*/
void addAlternateChargedPartyAddressAVP( struct DiamMessage *dmMessage, char *sAlternateChargedPartyAddress, int iVendorId, int iMandatory, int iLength);

void setAlternateChargedPartyAddressAVP( struct DiamAvp *dmAvp, char *sAlternateChargedPartyAddress, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 837
* Data Type : UTF8String
*/
void addApplicationprovidedcalledpartyaddressAVP( struct DiamMessage *dmMessage, char *sApplicationprovidedcalledpartyaddress, int iVendorId, int iMandatory, int iLength);

void setApplicationprovidedcalledpartyaddressAVP( struct DiamAvp *dmAvp, char *sApplicationprovidedcalledpartyaddress, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 836
* Data Type : UTF8String
*/
void addApplicationServerAVP( struct DiamMessage *dmMessage, char *sApplicationServer, int iVendorId, int iMandatory, int iLength);

void setApplicationServerAVP( struct DiamAvp *dmAvp, char *sApplicationServer, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1218
* Data Type : UTF8String
*/
void addApplicIDAVP( struct DiamMessage *dmMessage, char *sApplicID, int iVendorId, int iMandatory, int iLength);

void setApplicIDAVP( struct DiamAvp *dmAvp, char *sApplicID, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 2035
* Data Type : UTF8String
*/
void addAssociatedPartyAddressAVP( struct DiamMessage *dmMessage, char *sAssociatedPartyAddress, int iVendorId, int iMandatory, int iLength);

void setAssociatedPartyAddressAVP( struct DiamAvp *dmAvp, char *sAssociatedPartyAddress, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 856
* Data Type : UTF8String
*/
void addAssociatedURIAVP( struct DiamMessage *dmMessage, char *sAssociatedURI, int iVendorId, int iMandatory, int iLength);

void setAssociatedURIAVP( struct DiamAvp *dmAvp, char *sAssociatedURI, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 849
* Data Type : UTF8String
*/
void addAuthorizedQoSAVP( struct DiamMessage *dmMessage, char *sAuthorizedQoS, int iVendorId, int iMandatory, int iLength);

void setAuthorizedQoSAVP( struct DiamAvp *dmAvp, char *sAuthorizedQoS, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1219
* Data Type : UTF8String
*/
void addAuxApplicInfoAVP( struct DiamMessage *dmMessage, char *sAuxApplicInfo, int iVendorId, int iMandatory, int iLength);

void setAuxApplicInfoAVP( struct DiamAvp *dmAvp, char *sAuxApplicInfo, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 1250
* Data Type : UTF8String
*/
void addCalledAssertedIdentityAVP( struct DiamMessage *dmMessage, char *sCalledAssertedIdentity, int iVendorId, int iMandatory, int iLength);

void setCalledAssertedIdentityAVP( struct DiamAvp *dmAvp, char *sCalledAssertedIdentity, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 832
* Data Type : UTF8String
*/
void addCalledPartyAddressAVP( struct DiamMessage *dmMessage, char *sCalledPartyAddress, int iVendorId, int iMandatory, int iLength);

void setCalledPartyAddressAVP( struct DiamAvp *dmAvp, char *sCalledPartyAddress, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 831
* Data Type : UTF8String
*/
void addCallingPartyAddressAVP( struct DiamMessage *dmMessage, char *sCallingPartyAddress, int iVendorId, int iMandatory, int iLength);

void setCallingPartyAddressAVP( struct DiamAvp *dmAvp, char *sCallingPartyAddress, int iVendorId, int iMandatory, int iLength);

/**
* AVP Code : 432
* Data Type : Unsigned32
*/
void addRatingGroupAVP( struct DiamMessage *dmMessage, unsigned int uiRatingGroup, int iVendorId, int iMandatory);

void setRatingGroupAVP( struct DiamAvp *dmAvp, unsigned int uiRatingGroup, int iVendorId, int iMandatory);

/**
* AVP Code : 420
* Data Type : Unsigned32
*/
void addCCTimeAVP( struct DiamMessage *dmMessage, unsigned int uiCCTime, int iVendorId, int iMandatory);

void setCCTimeAVP( struct DiamAvp *dmAvp, unsigned int uiCCTime, int iVendorId, int iMandatory);

/**
* AVP Code : 85
* Data Type : Unsigned32
*/
void addAcctInterimIntervalAVP( struct DiamMessage *dmMessage, unsigned int uiAcctInterimInterval, int iVendorId, int iMandatory);

void setAcctInterimIntervalAVP( struct DiamAvp *dmAvp, unsigned int uiAcctInterimInterval, int iVendorId, int iMandatory);

/**
* AVP Code : 259
* Data Type : Unsigned32
*/
void addAcctApplicationIdAVP( struct DiamMessage *dmMessage, unsigned int uiAcctApplicationId, int iVendorId, int iMandatory);

void setAcctApplicationIdAVP( struct DiamAvp *dmAvp, unsigned int uiAcctApplicationId, int iVendorId, int iMandatory);

/**
* AVP Code : 258
* Data Type : Unsigned32
*/
void addAuthApplicationIdAVP( struct DiamMessage *dmMessage, unsigned int uiAuthApplicationId, int iVendorId, int iMandatory);

void setAuthApplicationIdAVP( struct DiamAvp *dmAvp, unsigned int uiAuthApplicationId, int iVendorId, int iMandatory);

/**
* AVP Code : 485
* Data Type : Unsigned32
*/
void addAccountingRecordNumberAVP( struct DiamMessage *dmMessage, unsigned int uiAccountingRecordNumber, int iVendorId, int iMandatory);

void setAccountingRecordNumberAVP( struct DiamAvp *dmAvp, unsigned int uiAccountingRecordNumber, int iVendorId, int iMandatory);

/**
* AVP Code : 291
* Data Type : Unsigned32
*/
void addAuthorizationLifetimeAVP( struct DiamMessage *dmMessage, unsigned int uiAuthorizationLifetime, int iVendorId, int iMandatory);

void setAuthorizationLifetimeAVP( struct DiamAvp *dmAvp, unsigned int uiAuthorizationLifetime, int iVendorId, int iMandatory);

/**
* AVP Code : 276
* Data Type : Unsigned32
*/
void addAuthGracePeriodAVP( struct DiamMessage *dmMessage, unsigned int uiAuthGracePeriod, int iVendorId, int iMandatory);

void setAuthGracePeriodAVP( struct DiamAvp *dmAvp, unsigned int uiAuthGracePeriod, int iVendorId, int iMandatory);

/**
* AVP Code : 298
* Data Type : Unsigned32
*/
void addExperimentalResultCodeAVP( struct DiamMessage *dmMessage, unsigned int uiExperimentalResultCode, int iVendorId, int iMandatory);

void setExperimentalResultCodeAVP( struct DiamAvp *dmAvp, unsigned int uiExperimentalResultCode, int iVendorId, int iMandatory);

/**
* AVP Code : 267
* Data Type : Unsigned32
*/
void addFirmwareRevisionAVP( struct DiamMessage *dmMessage, unsigned int uiFirmwareRevision, int iVendorId, int iMandatory);

void setFirmwareRevisionAVP( struct DiamAvp *dmAvp, unsigned int uiFirmwareRevision, int iVendorId, int iMandatory);

/**
* AVP Code : 299
* Data Type : Unsigned32
*/
void addInbandSecurityIdAVP( struct DiamMessage *dmMessage, unsigned int uiInbandSecurityId, int iVendorId, int iMandatory);

void setInbandSecurityIdAVP( struct DiamAvp *dmAvp, unsigned int uiInbandSecurityId, int iVendorId, int iMandatory);

/**
* AVP Code : 272
* Data Type : Unsigned32
*/
void addMultiRoundTimeOutAVP( struct DiamMessage *dmMessage, unsigned int uiMultiRoundTimeOut, int iVendorId, int iMandatory);

void setMultiRoundTimeOutAVP( struct DiamAvp *dmAvp, unsigned int uiMultiRoundTimeOut, int iVendorId, int iMandatory);

/**
* AVP Code : 278
* Data Type : Unsigned32
*/
void addOriginStateIdAVP( struct DiamMessage *dmMessage, unsigned int uiOriginStateId, int iVendorId, int iMandatory);

void setOriginStateIdAVP( struct DiamAvp *dmAvp, unsigned int uiOriginStateId, int iVendorId, int iMandatory);

/**
* AVP Code : 262
* Data Type : Unsigned32
*/
void addRedirectMaxCacheTimeAVP( struct DiamMessage *dmMessage, unsigned int uiRedirectMaxCacheTime, int iVendorId, int iMandatory);

void setRedirectMaxCacheTimeAVP( struct DiamAvp *dmAvp, unsigned int uiRedirectMaxCacheTime, int iVendorId, int iMandatory);

/**
* AVP Code : 268
* Data Type : Unsigned32
*/
void addResultCodeAVP( struct DiamMessage *dmMessage, unsigned int uiResultCode, int iVendorId, int iMandatory);

void setResultCodeAVP( struct DiamAvp *dmAvp, unsigned int uiResultCode, int iVendorId, int iMandatory);

/**
* AVP Code : 27
* Data Type : Unsigned32
*/
void addSessionTimeoutAVP( struct DiamMessage *dmMessage, unsigned int uiSessionTimeout, int iVendorId, int iMandatory);

void setSessionTimeoutAVP( struct DiamAvp *dmAvp, unsigned int uiSessionTimeout, int iVendorId, int iMandatory);

/**
* AVP Code : 270
* Data Type : Unsigned32
*/
void addSessionBindingAVP( struct DiamMessage *dmMessage, unsigned int uiSessionBinding, int iVendorId, int iMandatory);

void setSessionBindingAVP( struct DiamAvp *dmAvp, unsigned int uiSessionBinding, int iVendorId, int iMandatory);

/**
* AVP Code : 265
* Data Type : Unsigned32
*/
void addSupportedVendorIdAVP( struct DiamMessage *dmMessage, unsigned int uiSupportedVendorId, int iVendorId, int iMandatory);

void setSupportedVendorIdAVP( struct DiamAvp *dmAvp, unsigned int uiSupportedVendorId, int iVendorId, int iMandatory);

/**
* AVP Code : 266
* Data Type : Unsigned32
*/
void addVendorIdAVP( struct DiamMessage *dmMessage, unsigned int uiVendorId, int iVendorId, int iMandatory);

void setVendorIdAVP( struct DiamAvp *dmAvp, unsigned int uiVendorId, int iVendorId, int iMandatory);

/**
* AVP Code : 415
* Data Type : Unsigned32
*/
void addCCRequestNumberAVP( struct DiamMessage *dmMessage, unsigned int uiCCRequestNumber, int iVendorId, int iMandatory);

void setCCRequestNumberAVP( struct DiamAvp *dmAvp, unsigned int uiCCRequestNumber, int iVendorId, int iMandatory);

/**
* AVP Code : 439
* Data Type : Unsigned32
*/
void addServiceIdentifierAVP( struct DiamMessage *dmMessage, unsigned int uiServiceIdentifier, int iVendorId, int iMandatory);

void setServiceIdentifierAVP( struct DiamAvp *dmAvp, unsigned int uiServiceIdentifier, int iVendorId, int iMandatory);

/**
* AVP Code : 1265
* Data Type : Unsigned32
*/
void addBaseTimeIntervalAVP( struct DiamMessage *dmMessage, unsigned int uiBaseTimeInterval, int iVendorId, int iMandatory);

void setBaseTimeIntervalAVP( struct DiamAvp *dmAvp, unsigned int uiBaseTimeInterval, int iVendorId, int iMandatory);

/**
* AVP Code : 827
* Data Type : Unsigned32
*/
void addContentLengthAVP( struct DiamMessage *dmMessage, unsigned int uiContentLength, int iVendorId, int iMandatory);

void setContentLengthAVP( struct DiamAvp *dmAvp, unsigned int uiContentLength, int iVendorId, int iMandatory);

/**
* AVP Code : 1206
* Data Type : Unsigned32
*/
void addContentSizeAVP( struct DiamMessage *dmMessage, unsigned int uiContentSize, int iVendorId, int iMandatory);

void setContentSizeAVP( struct DiamAvp *dmAvp, unsigned int uiContentSize, int iVendorId, int iMandatory);

/**
* AVP Code : 888
* Data Type : Unsigned32
*/
void addExpiresAVP( struct DiamMessage *dmMessage, unsigned int uiExpires, int iVendorId, int iMandatory);

void setExpiresAVP( struct DiamAvp *dmAvp, unsigned int uiExpires, int iVendorId, int iMandatory);

/**
* AVP Code : 2063
* Data Type : Unsigned32
*/
void addLocalSequenceNumberAVP( struct DiamMessage *dmMessage, unsigned int uiLocalSequenceNumber, int iVendorId, int iMandatory);

void setLocalSequenceNumberAVP( struct DiamAvp *dmAvp, unsigned int uiLocalSequenceNumber, int iVendorId, int iMandatory);

/**
* AVP Code : 1212
* Data Type : Unsigned32
*/
void addMessageSizeAVP( struct DiamMessage *dmMessage, unsigned int uiMessageSize, int iVendorId, int iMandatory);

void setMessageSizeAVP( struct DiamAvp *dmAvp, unsigned int uiMessageSize, int iVendorId, int iMandatory);

/**
* AVP Code : 2034
* Data Type : Unsigned32
*/
void addNumberOfDiversionsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfDiversions, int iVendorId, int iMandatory);

void setNumberOfDiversionsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfDiversions, int iVendorId, int iMandatory);

/**
* AVP Code : 2019
* Data Type : Unsigned32
*/
void addNumberOfMessagesSentAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfMessagesSent, int iVendorId, int iMandatory);

void setNumberOfMessagesSentAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfMessagesSent, int iVendorId, int iMandatory);

/**
* AVP Code : 885
* Data Type : Unsigned32
*/
void addNumberOfParticipantsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfParticipants, int iVendorId, int iMandatory);

void setNumberOfParticipantsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfParticipants, int iVendorId, int iMandatory);

/**
* AVP Code : 1282
* Data Type : Unsigned32
*/
void addNumberOfReceivedTalkBurstsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfReceivedTalkBursts, int iVendorId, int iMandatory);

void setNumberOfReceivedTalkBurstsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfReceivedTalkBursts, int iVendorId, int iMandatory);

/**
* AVP Code : 1283
* Data Type : Unsigned32
*/
void addNumberOfTalkBurstsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfTalkBursts, int iVendorId, int iMandatory);

void setNumberOfTalkBurstsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfTalkBursts, int iVendorId, int iMandatory);

/**
* AVP Code : 896
* Data Type : Unsigned32
*/
void addPDGChargingIdAVP( struct DiamMessage *dmMessage, unsigned int uiPDGChargingId, int iVendorId, int iMandatory);

void setPDGChargingIdAVP( struct DiamAvp *dmAvp, unsigned int uiPDGChargingId, int iVendorId, int iMandatory);

/**
* AVP Code : 2050
* Data Type : Unsigned32
*/
void addPDNConnectionIDAVP( struct DiamMessage *dmMessage, unsigned int uiPDNConnectionID, int iVendorId, int iMandatory);

void setPDNConnectionIDAVP( struct DiamAvp *dmAvp, unsigned int uiPDNConnectionID, int iVendorId, int iMandatory);

/**
* AVP Code : 881
* Data Type : Unsigned32
*/
void addQuotaConsumptionTimeAVP( struct DiamMessage *dmMessage, unsigned int uiQuotaConsumptionTime, int iVendorId, int iMandatory);

void setQuotaConsumptionTimeAVP( struct DiamAvp *dmAvp, unsigned int uiQuotaConsumptionTime, int iVendorId, int iMandatory);

/**
* AVP Code : 871
* Data Type : Unsigned32
*/
void addQuotaHoldingTimeAVP( struct DiamMessage *dmMessage, unsigned int uiQuotaHoldingTime, int iVendorId, int iMandatory);

void setQuotaHoldingTimeAVP( struct DiamAvp *dmAvp, unsigned int uiQuotaHoldingTime, int iVendorId, int iMandatory);

/**
* AVP Code : 1284
* Data Type : Unsigned32
*/
void addReceivedTalkBurstTimeAVP( struct DiamMessage *dmMessage, unsigned int uiReceivedTalkBurstTime, int iVendorId, int iMandatory);

void setReceivedTalkBurstTimeAVP( struct DiamAvp *dmAvp, unsigned int uiReceivedTalkBurstTime, int iVendorId, int iMandatory);

/**
* AVP Code : 1285
* Data Type : Unsigned32
*/
void addReceivedTalkBurstVolumeAVP( struct DiamMessage *dmMessage, unsigned int uiReceivedTalkBurstVolume, int iVendorId, int iMandatory);

void setReceivedTalkBurstVolumeAVP( struct DiamAvp *dmAvp, unsigned int uiReceivedTalkBurstVolume, int iVendorId, int iMandatory);

/**
* AVP Code : 2032
* Data Type : Unsigned32
*/
void addServiceModeAVP( struct DiamMessage *dmMessage, unsigned int uiServiceMode, int iVendorId, int iMandatory);

void setServiceModeAVP( struct DiamAvp *dmAvp, unsigned int uiServiceMode, int iVendorId, int iMandatory);

/**
* AVP Code : 1257
* Data Type : Unsigned32
*/
void addServiceSpecificTypeAVP( struct DiamMessage *dmMessage, unsigned int uiServiceSpecificType, int iVendorId, int iMandatory);

void setServiceSpecificTypeAVP( struct DiamAvp *dmAvp, unsigned int uiServiceSpecificType, int iVendorId, int iMandatory);

/**
* AVP Code : 2031
* Data Type : Unsigned32
*/
void addServiceTypeAVP( struct DiamMessage *dmMessage, unsigned int uiServiceType, int iVendorId, int iMandatory);

void setServiceTypeAVP( struct DiamAvp *dmAvp, unsigned int uiServiceType, int iVendorId, int iMandatory);

/**
* AVP Code : 1286
* Data Type : Unsigned32
*/
void addTalkBurstTimeAVP( struct DiamMessage *dmMessage, unsigned int uiTalkBurstTime, int iVendorId, int iMandatory);

void setTalkBurstTimeAVP( struct DiamAvp *dmAvp, unsigned int uiTalkBurstTime, int iVendorId, int iMandatory);

/**
* AVP Code : 1287
* Data Type : Unsigned32
*/
void addTalkBurstVolumeAVP( struct DiamMessage *dmMessage, unsigned int uiTalkBurstVolume, int iVendorId, int iMandatory);

void setTalkBurstVolumeAVP( struct DiamAvp *dmAvp, unsigned int uiTalkBurstVolume, int iVendorId, int iMandatory);

/**
* AVP Code : 868
* Data Type : Unsigned32
*/
void addTimeQuotaThresholdAVP( struct DiamMessage *dmMessage, unsigned int uiTimeQuotaThreshold, int iVendorId, int iMandatory);

void setTimeQuotaThresholdAVP( struct DiamAvp *dmAvp, unsigned int uiTimeQuotaThreshold, int iVendorId, int iMandatory);

/**
* AVP Code : 2045
* Data Type : Unsigned32
*/
void addTimeUsageAVP( struct DiamMessage *dmMessage, unsigned int uiTimeUsage, int iVendorId, int iMandatory);

void setTimeUsageAVP( struct DiamAvp *dmAvp, unsigned int uiTimeUsage, int iVendorId, int iMandatory);

/**
* AVP Code : 1226
* Data Type : Unsigned32
*/
void addUnitQuotaThresholdAVP( struct DiamMessage *dmMessage, unsigned int uiUnitQuotaThreshold, int iVendorId, int iMandatory);

void setUnitQuotaThresholdAVP( struct DiamAvp *dmAvp, unsigned int uiUnitQuotaThreshold, int iVendorId, int iMandatory);

/**
* AVP Code : 869
* Data Type : Unsigned32
*/
void addVolumeQuotaThresholdAVP( struct DiamMessage *dmMessage, unsigned int uiVolumeQuotaThreshold, int iVendorId, int iMandatory);

void setVolumeQuotaThresholdAVP( struct DiamAvp *dmAvp, unsigned int uiVolumeQuotaThreshold, int iVendorId, int iMandatory);

/**
* AVP Code : 893
* Data Type : Unsigned32
*/
void addWLANTechnologyAVP( struct DiamMessage *dmMessage, unsigned int uiWLANTechnology, int iVendorId, int iMandatory);

void setWLANTechnologyAVP( struct DiamAvp *dmAvp, unsigned int uiWLANTechnology, int iVendorId, int iMandatory);

/**
* AVP Code : 450
* Data Type : Enumerated
*/
void addSubscriptionIdTypeAVP( struct DiamMessage *dmMessage, int iSubscriptionIdType, int iVendorId, int iMandatory);

void setSubscriptionIdTypeAVP( struct DiamAvp *dmAvp, int iSubscriptionIdType, int iVendorId, int iMandatory);

/**
* AVP Code : 483
* Data Type : Enumerated
*/
void addAccountingRealtimeRequiredAVP( struct DiamMessage *dmMessage, int iAccountingRealtimeRequired, int iVendorId, int iMandatory);

void setAccountingRealtimeRequiredAVP( struct DiamAvp *dmAvp, int iAccountingRealtimeRequired, int iVendorId, int iMandatory);

/**
* AVP Code : 480
* Data Type : Enumerated
*/
void addAccountingRecordTypeAVP( struct DiamMessage *dmMessage, int iAccountingRecordType, int iVendorId, int iMandatory);

void setAccountingRecordTypeAVP( struct DiamAvp *dmAvp, int iAccountingRecordType, int iVendorId, int iMandatory);

/**
* AVP Code : 274
* Data Type : Enumerated
*/
void addAuthRequestTypeAVP( struct DiamMessage *dmMessage, int iAuthRequestType, int iVendorId, int iMandatory);

void setAuthRequestTypeAVP( struct DiamAvp *dmAvp, int iAuthRequestType, int iVendorId, int iMandatory);

/**
* AVP Code : 277
* Data Type : Enumerated
*/
void addAuthSessionStateAVP( struct DiamMessage *dmMessage, int iAuthSessionState, int iVendorId, int iMandatory);

void setAuthSessionStateAVP( struct DiamAvp *dmAvp, int iAuthSessionState, int iVendorId, int iMandatory);

/**
* AVP Code : 285
* Data Type : Enumerated
*/
void addReAuthRequestTypeAVP( struct DiamMessage *dmMessage, int iReAuthRequestType, int iVendorId, int iMandatory);

void setReAuthRequestTypeAVP( struct DiamAvp *dmAvp, int iReAuthRequestType, int iVendorId, int iMandatory);

/**
* AVP Code : 273
* Data Type : Enumerated
*/
void addDisconnectCauseAVP( struct DiamMessage *dmMessage, int iDisconnectCause, int iVendorId, int iMandatory);

void setDisconnectCauseAVP( struct DiamAvp *dmAvp, int iDisconnectCause, int iVendorId, int iMandatory);

/**
* AVP Code : 261
* Data Type : Enumerated
*/
void addRedirectHostUsageAVP( struct DiamMessage *dmMessage, int iRedirectHostUsage, int iVendorId, int iMandatory);

void setRedirectHostUsageAVP( struct DiamAvp *dmAvp, int iRedirectHostUsage, int iVendorId, int iMandatory);

/**
* AVP Code : 271
* Data Type : Enumerated
*/
void addSessionServerFailoverAVP( struct DiamMessage *dmMessage, int iSessionServerFailover, int iVendorId, int iMandatory);

void setSessionServerFailoverAVP( struct DiamAvp *dmAvp, int iSessionServerFailover, int iVendorId, int iMandatory);

/**
* AVP Code : 295
* Data Type : Enumerated
*/
void addTerminationCauseAVP( struct DiamMessage *dmMessage, int iTerminationCause, int iVendorId, int iMandatory);

void setTerminationCauseAVP( struct DiamAvp *dmAvp, int iTerminationCause, int iVendorId, int iMandatory);

/**
* AVP Code : 416
* Data Type : Enumerated
*/
void addCCRequestTypeAVP( struct DiamMessage *dmMessage, int iCCRequestType, int iVendorId, int iMandatory);

void setCCRequestTypeAVP( struct DiamAvp *dmAvp, int iCCRequestType, int iVendorId, int iMandatory);

/**
* AVP Code : 436
* Data Type : Enumerated
*/
void addRequestedActionAVP( struct DiamMessage *dmMessage, int iRequestedAction, int iVendorId, int iMandatory);

void setRequestedActionAVP( struct DiamAvp *dmAvp, int iRequestedAction, int iVendorId, int iMandatory);

/**
* AVP Code : 455
* Data Type : Enumerated
*/
void addMultipleServicesIndicatorAVP( struct DiamMessage *dmMessage, int iMultipleServicesIndicator, int iVendorId, int iMandatory);

void setMultipleServicesIndicatorAVP( struct DiamAvp *dmAvp, int iMultipleServicesIndicator, int iVendorId, int iMandatory);

/**
* AVP Code : 1217
* Data Type : Enumerated
*/
void addAdaptationsAVP( struct DiamMessage *dmMessage, int iAdaptations, int iVendorId, int iMandatory);

void setAdaptationsAVP( struct DiamAvp *dmAvp, int iAdaptations, int iVendorId, int iMandatory);

/**
* AVP Code : 1208
* Data Type : Enumerated
*/
void addAddresseeTypeAVP( struct DiamMessage *dmMessage, int iAddresseeType, int iVendorId, int iMandatory);

void setAddresseeTypeAVP( struct DiamAvp *dmAvp, int iAddresseeType, int iVendorId, int iMandatory);

/**
* AVP Code : 899
* Data Type : Enumerated
*/
void addAddressTypeAVP( struct DiamMessage *dmMessage, int iAddressType, int iVendorId, int iMandatory);

void setAddressTypeAVP( struct DiamAvp *dmAvp, int iAddressType, int iVendorId, int iMandatory);

void __releaseMemory(int blockId, struct MemoryRecord *mRecord);
int isPeerReady( int iPeerThreadIndex);
int sendMessageToPeer(struct DiamMessage *oDiamMessage, int iPeerThreadIndex);
int sendAnswer(struct DiamMessage *oDiamRequestMessage, struct DiamMessage *oDiamRequestAnswer);
int sendCERToPeer(int iPeerThreadIndex);
int sendMessageToClient( struct DiamMessage * oDiamMessage, char * sRealmName, uint32_t iApplicationId);
int sendMessageToClient1( struct DiamMessage * oDiamMessage, char * host, char * sRealmName, uint32_t iApplicationId);
int sendMessageToClientDiameterRoutingAgent( struct DiamMessage* oDiamMessage);

struct DiamMessage* allocateMessage();
struct DiamAvp* allocateDiamAvp();

//void __freeMessage(struct DiamMessage *dmMessage );


//typedef void (*DiamMessageHandler)(struct DiamMessage* dmMsg);
//void setMessageHandler( DiamMessageHandler cbPtr);
void setHandler( int (*ptrHandler)(struct DiamMessage*));

void initDiamAnswer(struct DiamMessage * diamMessageRequest, struct DiamMessage * diamMessageAnswer, int iProxyable);

void hexDump(char* data, int length);
void StartCore( int iWebPort, int initialMemory);

void addSessionId( struct DiamMessage * diamMessage);
void addOriginHost( struct DiamMessage * diamMessage);
void addOriginRealm( struct DiamMessage * diamMessage);
void addOriginStateId( struct DiamMessage * diamMessage);
void addAvp( struct DiamAvp * dmAvpParent, struct DiamAvp * dmAvpChild);

void getCommandInfo(struct DiamMessage* dmMsg, int *iCmdCode, int *iIsRequest, int *iApplicationId, unsigned long *lH2HId, unsigned long *lE2EId);
int getCmdCode(struct DiamMessage* dmMsg);
int isRequest(struct DiamMessage* dmMsg);
int getApplicationId(struct DiamMessage* dmMsg);
int getAvpCode(struct DiamAvp *dmAvp);
int getAvpDataType(int iAvpCode);
int getIsProxyable( struct DiamMessage * dmMsg);
char * getDestinationHost( struct DiamMessage * dmMsg);
void releaseMessage(struct DiamMessage* dmMsg);
void getIPV4Address( char *buffer4Bytes, char *ipAddress);

struct DiamAvp* avpIteratorMoveFirst(struct DiamAvp* dmAvp);
struct DiamAvp* avpIteratorMoveNext(struct DiamAvp* dmAvp);
struct DiamAvp* iteratorMoveFirst(struct DiamMessage* dmMsg);
struct DiamAvp* iteratorMoveNext(struct DiamMessage* dmMsg);
void getIntValue( struct DiamAvp *dmAvp, int *iVal);
void getUnsignedIntValue( struct DiamAvp *dmAvp, unsigned int *uiVal);
void getOctetString( struct DiamAvp *dmAvp, char *cStr, int *iLength);
void getLongValue( struct DiamAvp *dmAvp, long *iVal);
void getULongValue( struct DiamAvp *dmAvp, long *iVal);
void Enquee( void *Data, struct Queue *oQueue);
void Enquee1( void *Data);
void Enquee2( void *Data);
void Enquee3( void *Data);
void *Dequee1();
void *Dequee2();
void *Dequee3();

void InitalizeCore( char* configFileName);
void InitalizeStack( char* configFileName);

void setGroupedAVP( struct DiamMessage *dmMessage, int AvpCode, struct DiamAvp *dmAvp, int iVendorId, int iMandatory);


void addOctetStringAVP( struct DiamMessage *dmMessage, int iAvpCode, char *sOctetString, int iVendorId, int iMandatory, int iLength);
void addUnsigned32AVP( struct DiamMessage *dmMessage, int iAvpCode, unsigned int uiUnsigned32, int iVendorId, int iMandatory);
void addInteger32AVP( struct DiamMessage *dmMessage, int iAvpCode, int iInteger32, int iVendorId, int iMandatory);
void addUnsigned64AVP( struct DiamMessage *dmMessage, int iAvpCode, unsigned long ulUnsigned64, int iVendorId, int iMandatory);
void addAddressAVP( struct DiamMessage *dmMessage, int AvpCode, char *sHostIPAddress, int iVendorId, int iMandatory);

void setOctetStringAVP( struct DiamAvp *dmAvp, int iAvpCode, char *sOctetString, int iVendorId, int iMandatory, int iLength);
void setUnsigned64AVP( struct DiamAvp *dmAvp, int iAvpCode, unsigned long ulUnsigned64, int iVendorId, int iMandatory);
void addNewSessionId( iDiamString *oDiamString);
void helper_setDiamString( iDiamString *oDiamString, char *sValue, int iLen);
void helper_copyDiamString( iDiamString *oDstDiamString, iDiamString *oSrcDiamString);

void setAvpDataTypeHandlerHandler( int (*ptrHandler)( int iAvpCode));

void addDestinationRealm( struct DiamMessage * diamMessage, int iPeerIndex);
void addSubscriptionIdEndUserE164( struct DiamMessage * diamMessage, char *sEndUserE164, int len);
void addSubscriptionIdIMSI( struct DiamMessage * diamMessage, char *sIMSI, int len);

int getDiamString( struct DiamMessage* dmMsg, int iAVPCode, int iIndex, iDiamString * oDiamString);


void addInteger64AVP( struct DiamMessage *dmMessage, int iAvpCode, long lInteger64, int iVendorId, int iMandatory);
void setInteger64AVP( struct DiamAvp *dmAvp, int iAvpCode, long lInteger64, int iVendorId, int iMandatory);
void setAddressAVP( struct DiamAvp *dmAvp, int AvpCode, char *sIPAddress, int iVendorId, int iMandatory);

unsigned int getCCRequestNumber( struct DiamMessage* dmMsg);
int getCCRequestType( struct DiamMessage* dmMsg);
unsigned int getResultCode( struct DiamMessage* dmMsg);
char * getSessionId( struct DiamMessage* dmMsg);

void setObjectTimeOutHandler( int (*ptrHandler)( void* dObj));
int CSV_LOG( char* mLogMessage, ...);

int core_AddLogCat( char *cLogCatName, int iEnable);
void core_wait();

void QueuePool_CreateWithNThreads( void **pQueuePoolObject, void (*ptrCallBackHandler)(void*), int iNoOfThreads);
void QueuePool_CreateWithNThreads2( void **pQueuePoolObject, void (*ptrCallBackHandler)(void*, int), int iNoOfThreads);

int CLog( int id, unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...);

void createRootASTDataPtr(void **rootDataPtr );
void core_addiAcctApplicationId(int iAcctApplicationId);
void core_addiAuthApplicationId(int iAuthApplicationId);
void core_addiVendorSpecificAuthApplicationId( int iVendorId, int iAuthApplicationId);
void core_createE2ETable( int iMaxRows, void **dataPtr);
int core_getNextE2EId( void *dataPtr);
void core_setE2EObject( void *dataPtr, int id, void * objData);
void core_getE2EObject( void *dataPtr, int id, void **objData);
void printMallocStats();
void InitMalloc();
void setCoreOnConfigItemHandler( int (*ptrHandler)( char *, char *, int));

int __addASTItemLock( void *dataPtr, char * Key, void * Data);
void* __getASTItemLock( void * dataPtr, char * Key, int setNull, void **dataOut);

int core_pthread_create( pthread_t *thread, void *(*start_routine) (void *), void *arg);
int core_pthread_create2( void *(*start_routine) (void *), void *arg);
void appLogDiamMessage( struct DiamMessage *oDiamMessage);
void InitMBMalloc( int mbVal, int iMutiply);

int isRetransmitBitSet(struct DiamMessage* dmMsg);
int isErrorBitSet(struct DiamMessage* dmMsg);


typedef uint32_t (*fp_artaddpeer)( char * host, char * realm, uint32_t appId, int fd, int transportType, uint32_t ** userData, void * baseObject, int baseObjectType);
typedef void (*fp_artaddallowedcmdtopeer)( uint32_t id, uint32_t iCmdCode);
typedef void (*fp_artaddnotallowedcmdtopeer)( uint32_t id, uint32_t iCmdCode);
typedef void (*fp_artrempeer)( uint32_t id, uint32_t * userData);
typedef void (*fp_artroutemessage)( int sourceId, void * vdmRd, void * vdmMsg);


void setPeerCloseHandler( fp_artrempeer p);
void setPeerCommandsNotAllowedHandler( fp_artaddnotallowedcmdtopeer p);
void setPeerCommandsAllowedHandler( fp_artaddallowedcmdtopeer p);
void setOnPeerCEASuccess( fp_artaddpeer fp_addPtr);
void setArtMessageHandler( fp_artroutemessage pH);

#endif














