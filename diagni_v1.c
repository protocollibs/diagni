/*
 ============================================================================
 Name        : Diam.c
 Author      : Anil Pashikanti
 Version     : 1050
 Copyright   : Your copyright notice
 Description : System Core and Diameter in C, Ansi-style
 ============================================================================
 */
 
 //08-MAR-2018
 //RingBufferTCPServerImplementation
 
 

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h> 

#if SCTP_SUPPORT
	#include <netinet/sctp.h>
#endif

#include <poll.h>
#include <sys/epoll.h>

//#include "lic.h"

typedef struct StackLicense
{
	char Organization[100];
	char HostName[100];
	int Interfaces[10];
	int TPS;
	time_t Expiry;
	int Rand;
	int NodeType;
} iStackLicense;



void printLicenseInfo( iStackLicense *li);
int IsLicenseExpired(iStackLicense *li);
void encrypt( char *password, int key, int length);
void decrypt( char *password, int key, int length);

int Base64decode_len(const char *bufcoded);
int Base64decode(char *bufplain, const char *bufcoded);
int Base64encode_len(int len);
int Base64encode(char *encoded, const char *string, int len);


void printLicenseInfo( iStackLicense *li)
{
	printf("-------------------------------------------------------------------------------------------------------\n");
	
	printf("Organization[%s]\n", li->Organization);
	printf("HostName[%s]\n", li->HostName);
	printf("TPS[%d]\n", li->TPS);
	printf("Rand[%d]\n", li->Rand);
	struct tm* tm_info;
	char strat_buffer[26];
		
	tm_info = localtime( &li->Expiry);
	strftime( strat_buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);
	
	printf("Expiry[%s]\n", strat_buffer);
		
	int i = 0;
	for( i = 0 ; i < 10; i++)
	{
		if( li->Interfaces[i] != 0)
		{
			printf("%d, Interfaces[%d]\n", (i+1), li->Interfaces[i]);
		}
	}
	
	time_t current_time;
	time( &current_time);
	
	double seconds = difftime( li->Expiry, current_time);
	
	if( seconds < 0)
	{
		printf("License Has Expired\n");		
	}
	else
	{
		printf("License Has the Validity of %f\n", seconds);
	}
	
	printf("-------------------------------------------------------------------------------------------------------\n");	
}

int IsLicenseExpired(iStackLicense *li)
{
	time_t current_time;
	time( &current_time);
		
	if(difftime( li->Expiry, current_time) < 0)
	{
		return 0;
	}
	
	return 1;
}



void encrypt( char *password, int key, int length)
{
    int i;
    for( i = 0; i < length; i++)
    {
        password[i] = password[i] - key;
    }
}



void decrypt( char *password, int key, int length)
{
    int i;
    for( i = 0; i < length; i++)
    {
        password[i] = password[i] + key;
    }
}

static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};


int Base64decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

int Base64decode(char *bufplain, const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
    *(bufout++) =
        (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
    *(bufout++) =
        (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    *(bufout++) = '\0';
    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

static const char basis_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode_len(int len)
{
    return ((len + 2) / 3 * 4) + 1;
}


int Base64encode(char *encoded, const char *string, int len)
{
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    *p++ = basis_64[((string[i] & 0x3) << 4) |
                    ((int) (string[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
                    ((int) (string[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
        *p++ = basis_64[((string[i] & 0x3) << 4)];
        *p++ = '=';
    }
    else {
        *p++ = basis_64[((string[i] & 0x3) << 4) |
                        ((int) (string[i + 1] & 0xF0) >> 4)];
        *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}



#define LOG_MEDIA_LOWER_LIMIT   1
#define LOG_MEDIA_FILE          1
#define LOG_MEDIA_CONSOLE       2
#define LOG_MEDIA_IDE           3
#define LOG_MEDIA_NEW_CONSOLE   4
#define LOG_MEDIA_UPPER_LIMIT   4

#define LOG_LEVEL_LOWER_LIMIT   1
#define LOG_LEVEL_CRITICAL      1
#define LOG_LEVEL_ERROR         2
#define LOG_LEVEL_WARNING       3
#define LOG_LEVEL_INFO          4
#define LOG_LEVEL_NORMAL        4
#define LOG_LEVEL_DEBUG         5
#define LOG_LEVEL_UPPER_LIMIT   5


#define LOGGER_ERR_LEVEL          1
#define LOGGER_ERR_MODE           2
#define LOGGER_ERR_FILE           3
#define LOGGER_ERR_NEW_CONSOLE    4
#define LOGGER_ERR_SEMAPHORE      5
#define LOGGER_ERR_BUFFER         6

#define LOGGER_WAIT_TIME        5000        
#define LOGGER_BUFFER_SIZE    	3000  
#define DATE_STRING_LEN         27
#define PATH_MAX_SIZE           260
#define MODULE_NAME_MAX_SIZE    50
#define LOG_MESSAGE_MAX_SIZE    LOGGER_BUFFER_SIZE - 100

/**
Pending
Timeout and object in queue
Clinet Specific E2EId Implementation
Clinet Specific Sticky Sessions 
Re-Use Disconnected Client Thread.
Web-UI Admin
SCTP
TLS
DTLS
**/

int PERF_LOG( char* mLogMessage, ...);
int CLog( int id, unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...);
int LOGCAT( int iLogCatId, unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...);
int APP_LOG( unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...);

int ____onlyCore = 0;
long globalMxAllocatedMem = 0;
long globalMxCurrPos = 0;

char* globalMxMemory = NULL;

void printMallocStats()
{
	long leftMemory = globalMxAllocatedMem-globalMxCurrPos;
	printf("0, [Bytes] Allocated:%ld Used:%ld left:%ld", globalMxAllocatedMem, globalMxCurrPos, leftMemory);
	
	if( leftMemory > 0)
	{
		printf(" [(%ld MB) Left]", ((leftMemory/1024)/1024));
	}
	
	printf("\n");
}




void * lib_malloc( size_t size)
{
	if( globalMxAllocatedMem > (globalMxCurrPos + size))
	{	
		void *p = globalMxMemory;
	
		globalMxMemory += size;
		globalMxCurrPos += size;

		return p;
	}
	else
	{
		int oneKB = 1024; //bytes
		int oneMB = oneKB * 1024;
		int oneGB = oneMB * 1024;
		int reqGBMem = (128*1024*1024); //128 MB
		//( (oneGB/3) * 1);
	
		globalMxAllocatedMem += reqGBMem;
		globalMxMemory = (char*)calloc( 1, reqGBMem);	
		
		void *p = globalMxMemory;
	
		globalMxMemory += size;
		globalMxCurrPos += size;

		printf("Allocated Memory = %d\n", reqGBMem);
		
		return p;
	}
	
	//printf("1, Allocated:%ld Used:%ld\n", globalMxAllocatedMem, globalMxCurrPos);		
	//printMallocStats();
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "lib_malloc ::::: Memory Exausted in Application ");
	
	//make sure log is printed before Core
	usleep(999999);
	
	return NULL;
}


void lib_malloc2( size_t size, void** dataPtr)
{
	if( globalMxAllocatedMem > (globalMxCurrPos + size))
	{	
		*dataPtr = globalMxMemory;
	
		globalMxMemory += size;
		globalMxCurrPos += size;
		
		return;
	}
	else
	{
		int oneKB = 1024; //bytes
		int oneMB = oneKB * 1024;
		int oneGB = oneMB * 1024;
		int reqGBMem = (128*1024*1024); //128 MB
	
		globalMxAllocatedMem += reqGBMem;
		globalMxMemory = (char*)calloc( 1, reqGBMem);	
		
		*dataPtr = globalMxMemory;
		
		printf("Allocated Memory = %d\n", reqGBMem);
		
		globalMxMemory += size;
		globalMxCurrPos += size;

		return;
	}
	
	printf("2, Allocated:%ld Used:%ld\n", globalMxAllocatedMem, globalMxCurrPos);	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "lib_malloc ::::: Memory Exausted in Application ");
	
	*dataPtr = NULL;
	//make sure log is printed before Core
	usleep(999999);
}


void makeFileName(char *mFileNameBuffer, char * mPath, char * mFilePrefix)
{
	/*
	time_t the_time;
	struct tm *tm_ptr;
	time( &the_time);
	tm_ptr = localtime( &the_time);
	sprintf( mFileNameBuffer, "%s/%s_%02d_%02d_%02d_%02d_%02d_%02d.log", mPath, mFilePrefix, tm_ptr->tm_mday, 
	(tm_ptr->tm_mon + 1), (tm_ptr->tm_year + 1900), tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
	*/
	struct timeval tv;
	struct timezone tzone;
	gettimeofday( &tv, &tzone);
	
	struct tm *timeinfo = gmtime( &tv.tv_sec);
	
	sprintf( mFileNameBuffer, 
		"%s/%s_%02d_%02d_%02d_%02d_%02d_%02d.log",
		mPath, mFilePrefix, 
		timeinfo->tm_mday, 
		(timeinfo->tm_mon) + 1, 
		(timeinfo->tm_year) + 1900, 
		timeinfo->tm_hour, 
		timeinfo->tm_min, 
		timeinfo->tm_sec
	);	
}

void makeIntFileName(char *mFileNameBuffer, char * mPath, char * mFilePrefix, int *iFileIndex)
{
	
	time_t rawtime;
	struct tm * timeinfo;
	struct timeval tval;
	struct timezone tzone;
	time( &rawtime);
	timeinfo = localtime( &rawtime);
	gettimeofday( &tval, &tzone);
	sprintf( mFileNameBuffer, "%s/%s_%02d_%02d_%d_%02d_%02d_%02d_%06lu.log", 
		mPath, mFilePrefix, 
		timeinfo->tm_mday, (timeinfo->tm_mon) + 1, 
		(timeinfo->tm_year) + 1900, timeinfo->tm_hour, 
		timeinfo->tm_min, timeinfo->tm_sec, tval.tv_usec);
	/**/	
	/*
	struct timeval tv;
	struct timezone tzone;
	gettimeofday( &tv, &tzone);
	
	struct tm *timeinfo = gmtime( &tv.tv_sec);
	
	sprintf( mFileNameBuffer, 
		"%s/%s_%02d_%02d_%d_%02d_%02d_%02d_%06lu.log",
		mPath, mFilePrefix, 
		timeinfo->tm_mday, 
		(timeinfo->tm_mon) + 1, 
		(timeinfo->tm_year) + 1900, 
		timeinfo->tm_hour, 
		timeinfo->tm_min, 
		timeinfo->tm_sec, 
		tv.tv_usec);
	*/	
}

void makeTimeStamp(char *datestring)
{
	
	time_t rawtime;
	struct tm * timeinfo;
	struct timeval tval;
	struct timezone tzone;
	time( &rawtime);
	timeinfo = localtime( &rawtime);
	gettimeofday( &tval, &tzone);
	
	sprintf( datestring, 
		"%02d-%02d-%d:%02d:%02d:%02d:%06lu", 
		timeinfo->tm_mday, 
		(timeinfo->tm_mon) + 1, 
		(timeinfo->tm_year) + 1900, 
		timeinfo->tm_hour, 
		timeinfo->tm_min, 
		timeinfo->tm_sec, 
		tval.tv_usec);
		
	datestring[27] = 0;  
	
	/**/
	
	/*
	struct timeval tv;
	struct timezone tzone;
	gettimeofday( &tv, &tzone);
	
	struct tm *timeinfo = gmtime( &tv.tv_sec);
	
	//strftime( datestring, 27, "%Y-%m-%d %H:%M:%S", gm);
	
	sprintf( datestring, 
		"%02d-%02d-%d:%02d:%02d:%02d:%06lu", 
		timeinfo->tm_mday, 
		(timeinfo->tm_mon) + 1, 
		(timeinfo->tm_year) + 1900, 
		timeinfo->tm_hour, 
		timeinfo->tm_min, 
		timeinfo->tm_sec, 
		tv.tv_usec);
		
	datestring[27] = 0;	
	*/
}


void makeTimeStamp2(char *datestring)
{
	struct timeval tv;
	struct timezone tzone;
	gettimeofday( &tv, &tzone);
	
	struct tm *timeinfo = gmtime( &tv.tv_sec);
	
	//strftime( datestring, 27, "%Y-%m-%d %H:%M:%S", gm);
	
	sprintf( datestring, 
		"%02d-%02d-%d:%02d:%02d:%02d:%06lu", 
		timeinfo->tm_mday, 
		(timeinfo->tm_mon) + 1, 
		(timeinfo->tm_year) + 1900, 
		timeinfo->tm_hour, 
		timeinfo->tm_min, 
		timeinfo->tm_sec, 
		tv.tv_usec);
		
	datestring[27] = 0;  
}

//-------------------------------------------------------------------------------------------------------------------------
// AVP Code Constants - Start
//-------------------------------------------------------------------------------------------------------------------------

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

//-------------------------------------------------------------------------------------------------------------------------
// AVP Code Constants - End
//-------------------------------------------------------------------------------------------------------------------------

#define OCTET_STRING 1
#define SIGNED_32 2
#define SIGNED_64 3
#define UNSIGNED_32 4
#define UNSIGNED_64 5
#define FLOAT_32 6
#define FLOAT_64 7
#define GROUPED 8
#define ADDRESS 9

int (*pAppAvpDataTypePerHandler)( int iAvpCode) = NULL;

void setAvpDataTypePreHandler( int (*ptrHandler)( int iAvpCode))
{
	pAppAvpDataTypePerHandler = ptrHandler;
}

//Post Handler
int (*pAppAvpDataTypeHandler)( int iAvpCode) = NULL;

void setAvpDataTypeHandlerHandler( int (*ptrHandler)( int iAvpCode))
{
	pAppAvpDataTypeHandler = ptrHandler;
}

int getAvpDataType( int iAvpCode)
{
	if( pAppAvpDataTypePerHandler > 0)
	{
		int iPreDataType = pAppAvpDataTypePerHandler( iAvpCode);
		if( iPreDataType >= 1)
		{
			return iPreDataType;
		}
	}
	
	switch( iAvpCode)
	{
		case 5535: 		//3GPP2-BSID
		case 1263: 		//Access-Network-Information
		case 908: 		//MBMS-Session-Identity
		case 701: 		//MSISDN
		case 2111: 		//Number-Of-Messages-Successfully-Exploded
		case 2112: 		//Number-Of-Messages-Successfully-Sent
		case 33: 		//Proxy-State
		case 1256: 		//Service-Generic-Information
		case 900: 		//TMGI
		case 2113: 		//Total-Number-Of-Messages-Exploded
		case 2015: 		//SM-User-Data-Header
		case 460: 		//User-Equipment-Info-Value
		case 2114: 		//Total-Number-Of-Messages-Sent
		case 606: 		//User-Data 
		case 2013: 		//SM-Protocol-ID
		case 2014: 		//SM-Status
		case 1020: 		//Bearer-Identifier
		case 903: 		//MBMS-Service-Area
		case 2110: 		//IM-Information
		case 503: 		//Access-Network-Charging-Identifier-Value
		case 505: 		//AF-Charging-Identifier
		case 22: 		//3GPP-User-Location-Info
		case 2101: 		//Application-Server-ID
		case 2102: 		//Application-Service-Type
		case 21: 		//3GPP-RAT-Type
		case 854: 		//Bearer-Service
		case 2103: 		//Application-Session-ID
		case 10: 		//3GPP-NSAPI 
		case 23: 		//3GPP-MS-TimeZone
		case 2: 		//3GPP-Charging-Id 
		case 2116: 		//Content-ID
		case 2117: 		//Content-Provider-ID
		case 2115: 		//DCD-Information
		case 2104: 		//Delivery-Status
		case 891: 		//WAG-PLMN-Id
		case 442: 		//Service-Parameter-Value
		case 1005: 		//Charging-Rule-Name
		case 1054: 		//QoS-Rule-Name
		case 1065: 		//PDN-Connection-ID
		case 2819: 		//RAN-NAS-Release-Cause
		case 2821: 		//Presence-Reporting-Area-Identifier
		case 2820: 		//Presence-Reporting-Area-Elements-List
		case 1056: 		//Security-Parameter-Index
		case 1014: 		//ToS-Traffic-Class
		case 2022: 		//Refund-Information
		case 866: 		//PS-Free-Format-Data
		case 1077: 		//Routing-Rule-Identifier
		case 1096: 		//ADC-Rule-Name
		case 1060: 		//Packet-Filter-Identifier
		case 2802: 		//TDF-Application-Instance-Identifier
		case 411: 		//CC-Correlation-Id
		case 1088: 		//TDF-Application-Identifier
		case 1057: 		//Flow-Label
		case 1066: 		//Monitoring-Key
			return OCTET_STRING;
		case 853: 		//Outgoing-Trunk-Group-Id
		case 2064: 		//Node-Id
		case 1253: 		//PoC-User-Role-IDs
		case 825: 		//Event
		case 839: 		//Originating-IOI
		case 887: 		//Participants-Involved
		case 1246: 		//WLAN-Session-Id
		case 1230: 		//Deferred-Location-Event-Type
		case 13: 		//3GPP-Charging-Characteristics
		case 859: 		//PoC-Group-Name
		case 1236: 		//LCS-Data-Coding-Scheme 
		case 12: 		//3GPP-Selection-Mode
		case 1200: 		//Domain-Name
		case 2024: 		//Number-Portability-Routing-Information
		case 858: 		//PoC-Controlling-Address
		case 8: 		//3GPP-IMSI-MCC-MNC 
		case 18: 		//3GPP-SGSN-MCC-MNC
		case 9: 		//3GPP-GGSN- MCC-MNC 
		case 826: 		//Content-Type
		case 1245: 		//Positioning-Data
		case 830: 		//User-Session-Id
		case 1231: 		//LCS-Client-Name 
		case 1251: 		//Requested-Party-Address
		case 1288: 		//Media-Initiator-Party
		case 845: 		//SDP-Media-Description
		case 844: 		//SDP-Media-Name
		case 842: 		//SDP-Session-Description
		case 855: 		//Service-Id
		case 824: 		//SIP-Method
		case 1238: 		//LCS-Name-String 
		case 1240: 		//LCS-Requestor-Id-String 
		case 1242: 		//Location-Estimate 
		case 1234: 		//LCS-Client-External-ID 
		case 1233: 		//LCS-Client-Dialed-By-MS 
		case 1215: 		//Token-Text
		case 841: 		//IMS-Charging-Identifier
		case 1281: 		//IMS-Communication-Service-Identifier
		case 852: 		//Incoming-Trunk-Group-Id
		case 1210: 		//Message-ID
		case 2003: 		//Interface-Id
		case 2004: 		//Interface-Port
		case 1223: 		//Reply-Applic-ID
		case 2005: 		//Interface-Text
		case 840: 		//Terminating-IOI
		case 1229: 		//PoC-Session-Id
		case 863: 		//Service-Specific-Data
		case 828: 		//Content-Disposition
		case 2817: 		//Default-QoS-Name
		case 1205: 		//Additional-Type-Information
		case 1: 		//User-Name
		case 263: 		//Session-Id
		case 909: 		//RAI
		case 901: 		//Required-MBMS-Bearer-Capabilities
		case 602: 		//Server-Name
		case 461: 		//Service-Context-Id
		case 1102: 		//VAS-Id
		case 444: 		//Subscription-Id-Data
		case 1004: 		//Charging-Rule-Base-Name
		case 435: 		//Redirect-Server-Address
		case 1101: 		//VASP-Id
		case 424: 		//Cost-Unit
		case 1074: 		//QoS-Rule-Base-Name
		case 1095: 		//ADC-Rule-Base-Name
		case 897: 		//Address-Data
		case 837: 		//Application-provided-called-party-address
		case 1219: 		//Aux-Applic-Info
		case 832: 		//Called-Party-Address
		case 831: 		//Calling-Party-Address
		case 1250: 		//Called-Asserted-Identity
		case 849: 		//Authorized-QoS
		case 856: 		//Associated-URI
		case 857: 		//Charged-Party
		case 2035: 		//Associated-Party-Address
		case 1218: 		//Applic-ID
		case 2023: 		//Carrier-Select-Routing-Information
		case 836: 		//Application-Server
			return OCTET_STRING;
		case 1090: 		//TDF-Destination-Realm
		case 1089: 		//TDF-Destination-Host
			return OCTET_STRING;
		case 1059: 		//Packet-Filter-Content
		case 1012: 		//TFT-Filter
		case 1036: 		//Tunnel-Header-Filter
			return OCTET_STRING;
		case 861: 		//Cause-Code
		case 2039: 		//Diagnostics
		case 11: 		//3GPP-Session-Stop-Indicator
		case 2037: 		//Change-Condition
		case 429: 		//Exponent
		case 2001: 		//Data-Coding-Scheme
			return SIGNED_32;
		case 447: 		//Value-Digits
			return SIGNED_64;
		case 1284: 		//Received-Talk-Burst-Time
		case 1285: 		//Received-Talk-Burst-Volume
		case 881: 		//Quota-Consumption-Time
		case 2823: 		//Presence-Reporting-Area-Status
		case 896: 		//PDG-Charging-Id
		case 2050: 		//PDN-Connection-ID
		case 2824: 		//NetLoc-Access-Support
		case 871: 		//Quota-Holding-Time
		case 1082: 		//Credit-Management-Status
		case 2806: 		//UDP-Source-Port
		case 1037: 		//Tunnel-Header-Length
		case 1046: 		//Priority-Level
		case 1010: 		//Precedence
		case 605: 		//Optional-Capability
		case 868: 		//Time-Quota-Threshold
		case 516: 		//Max-Requested-Bandwidth-UL
		case 515: 		//Max-Requested-Bandwidth-DL
		case 1226: 		//Unit-Quota-Threshold
		case 604: 		//Mandatory-Capability
		case 869: 		//Volume-Quota-Threshold
		case 1287: 		//Talk-Burst-Volume
		case 1286: 		//Talk-Burst-Time
		case 1040: 		//APN-Aggregate-Max-Bitrate-DL
		case 1026: 		//Guaranteed-Bitrate-UL
		case 2826: 		//PCSCF-Restoration-Indication
		case 1025: 		//Guaranteed-Bitrate-DL
		case 2032: 		//Service-Mode
		case 2045: 		//Time-Usage
		case 1257: 		//Service-Specific-Type
		case 1041: 		//APN-Aggregate-Max-Bitrate-UL
		case 2031: 		//Service-Type
		case 432: 		//Rating-Group
		case 2019: 		//Number-Of-Messages-Sent
		case 266: 		//Vendor-Id
		case 2034: 		//Number-Of-Diversions
		case 268: 		//Result-Code
		case 262: 		//Redirect-Max-Cache-Time
		case 1265: 		//Base-Time-Interval
		case 278: 		//Origin-State-Id
		case 425: 		//Currency-Code
		case 448: 		//Validity-Time
		case 439: 		//Service-Identifier
		case 441: 		//Service-Parameter-Type
		case 2063: 		//Local-Sequence-Number
		case 453: 		//G-S-U-Pool-Identifier
		case 1212: 		//Message-Size
		case 420: 		//CC-Time
		case 885: 		//Number-Of-Participants
		case 893: 		//WLAN-Technology
		case 1283: 		//Number-Of-Talk-Bursts
		case 415: 		//CC-Request-Number
		case 1206: 		//Content-Size
		case 1282: 		//Number-Of-Received-Talk-Bursts
		case 827: 		//Content-Length
		case 888: 		//Expires
			return UNSIGNED_32;
		case 1043: 		//Rule-Activation-Time
		case 835: 		//SIP-Response-Timestamp
		case 1262: 		//PoC-Change-Time
		case 1258: 		//Event-Charging-TimeStamp
		case 2812: 		//User-Location-Info-Time
		case 1042: 		//Revalidation-Time
		case 1274: 		//SDP-Offer-Timestamp
		case 1267: 		//Envelope-End-Time
		case 1044: 		//Rule-Deactivation-Time
		case 2012: 		//SM-Discharge-Time
		case 1269: 		//Envelope-Start-Time
		case 2043: 		//Time-First-Usage
		case 2810: 		//Monitoring-Time
		case 2044: 		//Time-Last-Usage
		case 834: 		//SIP-Request-Timestamp
		case 2038: 		//Change-Time
		case 1202: 		//Submission-Time
		case 2042: 		//Stop-Time
		case 2041: 		//Start-Time
		case 451: 		//Tariff-Time-Change
		case 1275: 		//SDP-Answer-Timestamp
			return UNSIGNED_32;
		case 419: 		//CC-Sub-Session-Id
		case 421: 		//CC-Total-Octets
		case 414: 		//CC-Output-Octets
		case 417: 		//CC-Service-Specific-Units
		case 412: 		//CC-Input-Octets
			return UNSIGNED_64;
		case 418: 		//CC-Session-Failover
		case 1099: 		//PS-to-CS-Session-Continuity
		case 1217: 		//Adaptations
		case 907: 		//MBMS-2G-3G-Indicator
		case 906: 		//MBMS-Service-Type
		case 261: 		//Redirect-Host-Usage
		case 2809: 		//Mute-Notification
		case 2827: 		//IP-CAN-Session-Charging-Scope
		case 454: 		//CC-Unit-Type
		case 1028: 		//QoS-Class-Identifier
		case 422: 		//Check-Balance-Result
		case 2811: 		//AN-GW-Status
		case 426: 		//Credit-Control
		case 1064: 		//Session-Linking-Indicator
		case 1208: 		//Addressee-Type
		case 899: 		//Address-Type
		case 1268: 		//Envelope-Reporting
		case 1031: 		//Rule-Failure-Code
		case 2051: 		//Dynamic-Address-Flag
		case 1221: 		//DRM-Content
		case 3: 		//3GPP-PDP-Type 
		case 1216: 		//Delivery-Report-Requested
		case 416: 		//CC-Request-Type
		case 1086: 		//Redirect-Support
		case 1220: 		//Content-Class
		case 1214: 		//Class-Identifier
		case 1009: 		//Online
		case 921: 		//CN-IP-Multicast-Distribution
		case 2055: 		//AoC-Request-Type
		case 427: 		//Credit-Control-Failure-Handling
		case 650: 		//Session-Priority
		case 1068: 		//Usage-Monitoring-Level
		case 1007: 		//Metering-Method
		case 436: 		//Requested-Action
		case 1024: 		//Network-Request-Support
		case 1008: 		//Offline
		case 1030: 		//QoS-Upgrade
		case 433: 		//Redirect-Address-Type
		case 1029: 		//QoS-Negotiation 
		case 1062: 		//Packet-Filter-Operation
		case 1072: 		//Packet-Filter-Usage
		case 1045: 		//Session-Release-Cause
		case 455: 		//Multiple-Services-Indicator
		case 1047: 		//Pre-emption-Capability
		case 1048: 		//Pre-emption-Vulnerability
		case 1011: 		//Reporting-Level
		case 1027: 		//IP-CAN-Type
		case 1063: 		//Resource-Allocation-Notification
		case 459: 		//User-Equipment-Info-Type
		case 1070: 		//Usage-Monitoring-Support
		case 452: 		//Tariff-Change-Usage
		case 450: 		//Subscription-Id-Type
		case 1069: 		//Usage-Monitoring-Report
		case 1032: 		//RAT-Type
		case 1023: 		//Bearer-Control-Mode
		case 1021: 		//Bearer-Operation
		case 1000: 		//Bearer-Usage
		case 428: 		//Direct-Debiting-Failure-Handling
		case 1073: 		//Charging-Correlation-Indicator
		case 1071: 		//CSG-Information-Reporting
		case 1006: 		//Event-Trigger
		case 1080: 		//Flow-Direction
		case 449: 		//Final-Unit-Action
		case 1019: 		//PCC-Rule-Status
		case 2033: 		//Subscriber-Role
		case 1271: 		//Time-Quota-Type
		case 1254: 		//PoC-User-Role-info-Units
		case 864: 		//Originator
		case 2007: 		//SM-Message-Type
		case 862: 		//Node-Functionality
		case 1241: 		//LCS-Client-Type 
		case 1243: 		//Location-Estimate-Type 
		case 872: 		//Reporting-Reason
		case 2016: 		//SMS-Node
		case 2047: 		//Serving-Node-Type
		case 1225: 		//MBMS-User-Service-Type
		case 867: 		//PS-Append-Free-Format-Data
		case 1209: 		//Priority
		case 2065: 		//SGW-Change
		case 2029: 		//SM-Service-Type
		case 1237: 		//LCS-Format-Indicator 
		case 1211: 		//Message-Type
		case 2006: 		//Interface-Type
		case 884: 		//PoC-Session-Type
		case 1277: 		//PoC-Session-Initiation-type
		case 883: 		//PoC-Server-Role
		case 1279: 		//User-Participating-Type
		case 2011: 		//Reply-Path-Requested
		case 2036: 		//SDP-Type
		case 2049: 		//Participant-Action-Type
		case 1259: 		//Participant-Access-Priority
		case 2020: 		//Low-Balance-Indication 
		case 882: 		//Media-Initiator-Flag
		case 1224: 		//File-Repair-Supported
		case 1248: 		//MMBox-Storage-Requested
		case 1222: 		//Read-Reply-Report-Requested
		case 829: 		//Role-of-Node
		case 1247: 		//PDP-Context-Type
		case 1204: 		//Type-Number
		case 2025: 		//PoC-Event-Type
		case 870: 		//Trigger-Type
		case 1261: 		//PoC-Change-Condition
			return SIGNED_32;
		case 280: 		//Proxy-Host
		case 282: 		//Route-Record
		case 296: 		//Origin-Realm
		case 264: 		//Origin-Host
			return OCTET_STRING;
		case 1013: 		//TFT-Packet-Filter-Information
		case 431: 		//Granted-Service-Unit
		case 843: 		//SDP-Media-Component
		case 1201: 		//Recipient-Address
		case 1273: 		//SDP-TimeStamps
		case 2059: 		//Scale-Factor
		case 889: 		//Message-Body
		case 456: 		//Multiple-Services-Credit-Control
		case 1078: 		//Routing-Filter
		case 1076: 		//Routing-Rule-Definition
		case 457: 		//G-S-U-Pool-Reference
		case 1081: 		//Routing-Rule-Install
		case 1075: 		//Routing-Rule-Remove
		case 443: 		//Subscription-Id
		case 1213: 		//Message-Class
		case 2021: 		//Remaining-Balance
		case 1016: 		//QoS-Information
		case 2028: 		//Recipient-Received-Address
		case 2026: 		//Recipient-Info
		case 430: 		//Final-Unit-Indication
		case 1038: 		//Tunnel-Information
		case 1097: 		//ADC-Rule-Report
		case 1098: 		//Application-Detection-Information
		case 2818: 		//Conditional-APN-Aggregate-Max-Bitrate
		case 2816: 		//Default-QoS-Information
		case 1252: 		//PoC-User-Role
		case 2825: 		//Fixed-User-Location-Info
		case 879: 		//PoC-Information
		case 2822: 		//Presence-Reporting-Area-Information
		case 1085: 		//Redirect-Information
		case 1278: 		//Offline-Charging
		case 1087: 		//TDF-Information
		case 1260: 		//Participant-Group
		case 413: 		//CC-Money
		case 2009: 		//Originator-Interface
		case 1093: 		//ADC-Rule-Remove
		case 423: 		//Cost-Information
		case 1092: 		//ADC-Rule-Install
		case 2058: 		//Rate-Element
		case 1203: 		//MM-Content-Type
		case 1067: 		//Usage-Monitoring-Information
		case 877: 		//MMS-Information
		case 874: 		//PS-Information
		case 865: 		//PS-Furnish-Charging-Information
		case 2030: 		//MMTel-Information
		case 1051: 		//QoS-Rule-Install
		case 1052: 		//QoS-Rule-Remove
		case 1053: 		//QoS-Rule-Definition
		case 1055: 		//QoS-Rule-Report
		case 898: 		//Address-Domain
		case 2057: 		//Next-Tariff
		case 1094: 		//ADC-Rule-Definition
		case 2027: 		//Originator-Received-Address
		case 1061: 		//Packet-Filter-Information
		case 892: 		//WLAN-Radio-Container
		case 510: 		//Flows
		case 833: 		//Time-Stamps
		case 2062: 		//Incremental-Cost
		case 1207: 		//Additional-Content-Information
		case 1270: 		//Time-Quota-Mechanism
		case 2052: 		//Accumulated-Cost
		case 2060: 		//Tariff-Information
		case 260: 		//Vendor-Specific-Application-Id
		case 838: 		//Inter-Operator-Identifier
		case 1232: 		//LCS-Client-Id 
		case 1255: 		//Talk-Burst-Exchange
		case 2048: 		//Supplementary-Service
		case 284: 		//Proxy-Info
		case 603: 		//Server-Capabilities
		case 1276: 		//AF-Correlation-Information
		case 2053: 		//AoC-Cost-Information
		case 875: 		//WLAN-Information
		case 1266: 		//Envelope
		case 1272: 		//Early-Media-Description
		case 823: 		//Event-Type
		case 2002: 		//Destination-Interface
		case 2056: 		//Current-Tariff
		case 2061: 		//Unit-Cost
		case 851: 		//Trunk-Group-Id
		case 1034: 		//Allocation-Retention-Priority
		case 1264: 		//Trigger
		case 2046: 		//Traffic-Data-Volumes
		case 850: 		//Application-Server-Information
		case 886: 		//Originator-Address 
		case 876: 		//IMS-Information
		case 2054: 		//AoC-Information
		case 1235: 		//LCS-Client-Name 
		case 1401: 		//Terminal-Information
		case 2000: 		//SMS-Information
		case 1003: 		//Charging-Rule-Definition
		case 1244: 		//Location-Type 
		case 440: 		//Service-Parameter-Info
		case 1249: 		//Service-Specific-Info
		case 1018: 		//Charging-Rule-Report
		case 878: 		//LCS-Information
		case 1039: 		//CoA-Information
		case 1049: 		//Default-EPS-Bearer-QoS
		case 2040: 		//Service-Data-Container
		case 1033: 		//Event-Report-Indication
		case 1002: 		//Charging-Rule-Remove
		case 1001: 		//Charging-Rule-Install
		case 458: 		//User-Equipment-Info
		case 446: 		//Used-Service-Unit
		case 873: 		//Service-Information
		case 445: 		//Unit-Value
		case 434: 		//Redirect-Server
		case 1058: 		//Flow-Information
		case 437: 		//Requested-Service-Unit
		case 1022: 		//Access-Network-Charging-Identifier-Gx
		case 880: 		//MBMS-Information
		case 1239: 		//LCS-Requestor-Id 
			return GROUPED;
		case 890: 		//WAG-Address
		case 848: 		//Served-Party-IP-Address
		case 1050: 		//AN-GW-Address
		case 1091: 		//TDF-IP-Address
		case 2805: 		//UE-Local-IP-Address
		case 894: 		//WLAN-UE-Local-IPAddress
		case 2804: 		//HeNB-Local-IP-Address
		case 895: 		//PDG-Address
		case 1227: 		//PDP-Address
		case 2017: 		//SMSC-Address
		case 1228: 		//SGSN-Address
		case 2010: 		//Recipient-SCCP-Address
		case 1035: 		//CoA-IP-Address
		case 847: 		//GGSN-Address
		case 846: 		//CG-Address
		case 1079: 		//Routing-IP-Address
		case 2018: 		//Client-Address
		case 2008: 		//Originator-SCCP-Address
			return OCTET_STRING;
		case 438: 		//Restriction-Filter-Rule
			return OCTET_STRING;
		case 292: 		//Redirect-Host
			return OCTET_STRING;
		case 1280: 		//Alternate-Charged-Party-Address
			return OCTET_STRING;
		case 2067: 		//SGW-Address
		case 496: 		//Token-Rate
		case 497: 		//Bucket-Depth
		case 498: 		//Peak-Traffic-Rate
		case 502: 		//Bandwidth
		case 1655: 		//Measurement-Period-UMTS
		case 1656: 		//Measurement-Period-LTE
		case 1658: 		//Collection-Period-RRM-UMTS
		case 1657: 		//Collection-Period-RRM-LTE
			return OCTET_STRING;
		case 358: 		//Unassigned
		case 352: 		//Unassigned
		case 353: 		//Unassigned
		case 354: 		//Unassigned
		case 362: 		//Unassigned
		case 361: 		//Unassigned
		case 360: 		//Unassigned
		case 355: 		//Unassigned
		case 356: 		//Unassigned
		case 359: 		//Unassigned
		case 357: 		//Unassigned
		case 351: 		//Unassigned
		case 349: 		//Unassigned
		case 340: 		//Not defined in .xml
		case 341: 		//Not defined in .xml
		case 342: 		//Not defined in .xml
		case 343: 		//Not defined in .xml
		case 344: 		//Not defined in .xml
		case 345: 		//Not defined in .xml
		case 346: 		//Not defined in .xml
		case 350: 		//Unassigned
		case 347: 		//Not defined in .xml
		case 348: 		//Not defined in .xml
		case 363: 		//Not defined in .xml
		case 364: 		//Not defined in .xml
		case 379: 		//Not defined in .xml
		case 380: 		//Not defined in .xml
		case 381: 		//Not defined in .xml
		case 382: 		//Not defined in .xml
		case 383: 		//Not defined in .xml
		case 384: 		//Not defined in .xml
		case 385: 		//Not defined in .xml
		case 386: 		//Not defined in .xml
		case 387: 		//Not defined in .xml
		case 388: 		//Not defined in .xml
		case 389: 		//Not defined in .xml
		case 390: 		//Not defined in .xml
		case 378: 		//Not defined in .xml
		case 377: 		//Not defined in .xml
		case 365: 		//Not defined in .xml
		case 366: 		//Not defined in .xml
		case 367: 		//Not defined in .xml
		case 368: 		//Not defined in .xml
		case 369: 		//Not defined in .xml
		case 370: 		//Not defined in .xml
		case 371: 		//Not defined in .xml
		case 372: 		//Not defined in .xml
		case 373: 		//Not defined in .xml
		case 374: 		//Not defined in .xml
		case 375: 		//Not defined in .xml
		case 376: 		//Not defined in .xml
		case 391: 		//Not defined in .xml
		case 339: 		//Not defined in .xml
		case 242: 		//Reserved
		case 286: 		//Unassigned
		case 288: 		//Unallocated
		case 289: 		//Unallocated
		case 290: 		//Unallocated
		case 301: 		//Unallocated
		case 302: 		//Unallocated
		case 303: 		//Unallocated
		case 304: 		//Unallocated
		case 305: 		//Unallocated
		case 306: 		//Unallocated
		case 307: 		//Unallocated
		case 308: 		//Unallocated
		case 256: 		//Unassigned
		case 255: 		//Reserved
		case 243: 		//Reserved
		case 244: 		//Reserved
		case 245: 		//Reserved
		case 246: 		//Reserved
		case 247: 		//Reserved
		case 248: 		//Reserved
		case 249: 		//Reserved
		case 250: 		//Reserved
		case 251: 		//Reserved
		case 252: 		//Reserved
		case 253: 		//Reserved
		case 254: 		//Reserved
		case 309: 		//Unallocated
		case 310: 		//Unallocated
		case 326: 		//Not defined in .xml
		case 327: 		//Not defined in .xml
		case 328: 		//Not defined in .xml
		case 329: 		//Not defined in .xml
		case 330: 		//Not defined in .xml
		case 331: 		//Not defined in .xml
		case 332: 		//Not defined in .xml
		case 333: 		//Not defined in .xml
		case 334: 		//Not defined in .xml
		case 335: 		//Not defined in .xml
		case 336: 		//Not defined in .xml
		case 337: 		//Not defined in .xml
		case 325: 		//Not defined in .xml
		case 324: 		//Not defined in .xml
		case 311: 		//Unallocated
		case 312: 		//Unallocated
		case 313: 		//Unallocated
		case 314: 		//Unallocated
		case 315: 		//Unallocated
		case 316: 		//Unallocated
		case 317: 		//Unallocated
		case 318: 		//3GPP-AAA-Server-Name
		case 320: 		//Not defined in .xml
		case 321: 		//Not defined in .xml
		case 322: 		//Not defined in .xml
		case 323: 		//Not defined in .xml
		case 338: 		//Not defined in .xml
		case 646: 		//Record-Route
		case 927: 		//MBMS-GW-UDP-Port
		case 1136: 		//Policy-Counter-Id
		case 1407: 		//Visited-PLMN-Id
		case 1411: 		//Re-Synchronization-Info
		case 1433: 		//STN-SR
		case 1446: 		//Regional-Subscription-Zone-Code
		case 1447: 		//RAND
		case 1448: 		//XRES
		case 1449: 		//AUTN
		case 1450: 		//KASME
		case 1453: 		//Kc
		case 926: 		//MBMS-BMSC-SSM-UDP-Port
		case 925: 		//MBMS-GW-SSM-IPv6-Address
		case 920: 		//MBMS-Flow-Identifier
		case 702: 		//User-Data
		case 704: 		//Service-Indication
		case 711: 		//DSAI-Tag
		case 904: 		//MBMS-Session-Duration
		case 910: 		//Additional-MBMS-Trace-Info
		case 911: 		//MBMS-Time-To-Data-Transfer
		case 912: 		//MBMS-Session-Repetition-Number
		case 916: 		//MBMS-GGSN-Address
		case 917: 		//MBMS-GGSN-IPv6-Address
		case 918: 		//MBMS-BMSC-SSM-IP-Address
		case 919: 		//MBMS-BMSC-SSM-IPv6-Address
		case 1454: 		//SRES
		case 1459: 		//Trace-Reference
		case 1603: 		//Tracking-Area-Identity
		case 1604: 		//Cell-Global-Identity
		case 1605: 		//Routing-Area-Identity
		case 1606: 		//Location-Area-Identity
		case 1607: 		//Service-Area-Identity
		case 1608: 		//Geographical-Information
		case 1609: 		//Geodetic-Information
		case 1620: 		//Ext-PDP-Type
		case 1643: 		//A-MSISDN
		case 1645: 		//MME-Number-for-MT-SMS
		case 1659: 		//Positioning-Method
		case 1602: 		//E-UTRAN-Cell-Global-Identity
		case 1506: 		//MIP-FA-RK
		case 1489: 		//SGSN-Number
		case 1463: 		//Trace-NE-Type-List
		case 1464: 		//Trace-Interface-List
		case 1465: 		//Trace-Event-List
		case 1466: 		//OMC-Id
		case 1470: 		//PDP-Type
		case 1471: 		//TGPP2-MEID
		case 1474: 		//GMLC-Address
		case 1476: 		//SS-Code
		case 1477: 		//SS-Status
		case 1480: 		//Client-Identity
		case 1487: 		//TS-Code
		case 1660: 		//Measurement-Quantity
		case 645: 		//To-SIP-Header
		case 392: 		//Not defined in .xml
		case 410: 		//Unassigned
		case 462: 		//EAP-Payload
		case 463: 		//EAP-Reissued-Payload
		case 464: 		//EAP-Master-Session-Key
		case 466: 		//Unassigned
		case 467: 		//Unassigned
		case 468: 		//Unassigned
		case 469: 		//Unassigned
		case 470: 		//Unassigned
		case 471: 		//Unassigned
		case 472: 		//Unassigned
		case 409: 		//Unassigned
		case 406: 		//UICC-Key-Material
		case 405: 		//ME-Key-Material
		case 393: 		//Not defined in .xml
		case 394: 		//Unassigned
		case 395: 		//Unassigned
		case 396: 		//Unassigned
		case 397: 		//Unassigned
		case 398: 		//Unassigned
		case 399: 		//Unassigned
		case 400: 		//GBA-UserSecSettings
		case 401: 		//Transaction-Identifier
		case 402: 		//NAF-Hostname
		case 403: 		//GAA-Service-Identifier
		case 473: 		//Unassigned
		case 474: 		//Unassigned
		case 492: 		//Not defined in .xml
		case 493: 		//Not defined in .xml
		case 494: 		//Not defined in .xml
		case 525: 		//Service-URN
		case 528: 		//MPS-Identifier
		case 609: 		//Service-Parameter-Value
		case 625: 		//Confidentiality-Key
		case 626: 		//Integrity-Key
		case 640: 		//Path
		case 641: 		//Contact
		case 643: 		//Call-ID-SIP-Header
		case 491: 		//Not defined in .xml
		case 490: 		//Not defined in .xml
		case 489: 		//Not defined in .xml
		case 475: 		//Unassigned
		case 476: 		//Unassigned
		case 477: 		//Unassigned
		case 478: 		//Unassigned
		case 479: 		//Unassigned
		case 481: 		//Unassigned
		case 482: 		//Unassigned
		case 484: 		//Unassigned
		case 486: 		//Not defined in .xml
		case 487: 		//Not defined in .xml
		case 488: 		//Not defined in .xml
		case 644: 		//From-SIP-Header
		case 241: 		//Reserved
		case 146: 		//Unassigned
		case 157: 		//Unassigned
		case 158: 		//Unassigned
		case 159: 		//Unassigned
		case 160: 		//Unassigned
		case 161: 		//Unassigned
		case 162: 		//Unassigned
		case 163: 		//Unassigned
		case 164: 		//Unassigned
		case 156: 		//Unassigned
		case 155: 		//Unassigned
		case 147: 		//Unassigned
		case 148: 		//Unassigned
		case 149: 		//Unassigned
		case 150: 		//Unassigned
		case 151: 		//Unassigned
		case 152: 		//Unassigned
		case 153: 		//Unassigned
		case 154: 		//Unassigned
		case 165: 		//Unassigned
		case 166: 		//Unassigned
		case 167: 		//Unassigned
		case 178: 		//Unassigned
		case 179: 		//Unassigned
		case 180: 		//Unassigned
		case 181: 		//Unassigned
		case 182: 		//Unassigned
		case 183: 		//Unassigned
		case 184: 		//Unassigned
		case 185: 		//Unassigned
		case 177: 		//Unassigned
		case 176: 		//Unassigned
		case 168: 		//Unassigned
		case 169: 		//Unassigned
		case 170: 		//Unassigned
		case 171: 		//Unassigned
		case 172: 		//Unassigned
		case 173: 		//Unassigned
		case 174: 		//Unassigned
		case 175: 		//Unassigned
		case 186: 		//Unassigned
		case 84: 		//ARAP-Challenge-Response
		case 32: 		//NAS-Identifier
		case 34: 		//Login-LAT-Service
		case 82: 		//Tunnel-Assignment-Id
		case 35: 		//Login-LAT-Node
		case 81: 		//Tunnel-Private-Group-Id
		case 36: 		//Login-LAT-Group
		case 39: 		//Framed-AppleTalk-Zone
		case 44: 		//Acct-Session-Id
		case 88: 		//Framed-Pool
		case 196: 		//Experimental-Use
		case 93: 		//Unassigned
		case 94: 		//Originating-Line-Info
		case 95: 		//NAS-IPv6-Address
		case 25: 		//Class
		case 97: 		//Framed-IPv6-Prefix
		case 98: 		//Login-IPv6-Host
		case 24: 		//State
		case 100: 		//Framed-IPv6-Pool
		case 80: 		//Signature
		case 50: 		//Accounting-Multi-Session-Id
		case 123: 		//Delegated-IPv6-Prefix
		case 137: 		//PKM-SS-Cert
		case 138: 		//PKM-CA-Cert
		case 139: 		//PKM-Config-Settings
		case 140: 		//PKM-Cryptosuite-List
		case 141: 		//PPKM-SAID
		case 142: 		//PKM-SA-Descriptor
		case 143: 		//PKM-Auth-Key
		case 144: 		//Unassigned
		case 78: 		//Configuration-Token
		case 132: 		//Requested-Location-Info
		case 79: 		//EAP-Message
		case 125: 		//MIP6-Home-Link-Prefix
		case 126: 		//Operator-Name
		case 127: 		//Location-Information
		case 128: 		//Location-Data
		case 129: 		//Basic-Location-Policy-Rules
		case 130: 		//Extended-Location-Policy-Rules
		case 131: 		//Location-Capable
		case 145: 		//Unassigned
		case 233: 		//Implementation-Specific
		case 237: 		//Implementation-Specific
		case 238: 		//Implementation-Specific
		case 70: 		//ARAP-Password
		case 225: 		//Implementation-Specific
		case 239: 		//Implementation-Specific
		case 224: 		//Implementation-Specific
		case 223: 		//Experimental-Use
		case 222: 		//Experimental-Use
		case 71: 		//ARAP-Features
		case 56: 		//Egress-VLANID
		case 0: 		//Dummy
		case 240: 		//Implementation-Specific
		case 74: 		//ARAP-Security-Data
		case 221: 		//Experimental-Use
		case 236: 		//Implementation-Specific
		case 17: 		//Unassigned
		case 235: 		//Implementation-Specific
		case 230: 		//Implementation-Specific
		case 229: 		//Implementation-Specific
		case 228: 		//Implementation-Specific
		case 227: 		//Implementation-Specific
		case 226: 		//Implementation-Specific
		case 231: 		//Implementation-Specific
		case 68: 		//Acct-Tunnel-Connection-ID
		case 63: 		//Login-LAT-Port
		case 232: 		//Implementation-Specific
		case 60: 		//CHAP-Challenge
		case 59: 		//User-Priority-Table
		case 4: 		//NAS-IP-Address
		case 69: 		//Tunnel-Password
		case 234: 		//Implementation-Specific
		case 220: 		//Experimental-Use
		case 219: 		//Experimental-Use
		case 187: 		//Unassigned
		case 203: 		//Experimental-Use
		case 202: 		//Experimental-Use
		case 201: 		//Experimental-Use
		case 200: 		//Experimental-Use
		case 199: 		//Experimental-Use
		case 197: 		//Experimental-Use
		case 54: 		//Unassigned
		case 195: 		//Experimental-Use
		case 194: 		//Experimental-Use
		case 193: 		//Experimental-Use
		case 192: 		//Experimental-Use
		case 191: 		//Unassigned
		case 190: 		//Unassigned
		case 189: 		//Unassigned
		case 188: 		//Unassigned
		case 198: 		//Experimental-Use
		case 204: 		//Experimental-Use
		case 205: 		//Experimental-Use
		case 213: 		//Experimental-Use
		case 215: 		//Experimental-Use
		case 212: 		//Experimental-Use
		case 211: 		//Experimental-Use
		case 210: 		//Experimental-Use
		case 209: 		//Experimental-Use
		case 216: 		//Experimental-Use
		case 218: 		//Experimental-Use
		case 217: 		//Experimental-Use
		case 206: 		//Experimental-Use
		case 207: 		//Experimental-Use
		case 208: 		//Experimental-Use
		case 214: 		//Experimental-Use
		case 131145: 		//ACL-Name
		case 131202: 		//Domain-Group-Name
		case 5113: 		//NSN-Token-Value
		case 5105: 		//Session-Start-Indicator
		case 131117: 		//Confirm-Token
		case 131103: 		//Owner-Name
		case 131127: 		//Accounting-Customer-String
		case 3104: 		//SCS-Identity
		case 3004: 		//Payload
		case 131140: 		//Billing-Plan-Name
		case 2403: 		//MSC-Number
		case 131153: 		//VRF-Name
		case 131256: 		//User-Agent
		case 2600: 		//Reserved
		case 131151: 		//Content-Name
		case 2517: 		//ECGI
		case 2516: 		//EUTRAN-Positioning-Data
		case 2515: 		//Velocity-Estimate
		case 3100: 		//IP-SM-GW-Number
		case 131243: 		//Service-Group-Name
		case 2300: 		//Reserved
		case 131089: 		//Policy-Map-Name
		case 131088: 		//Biling-Policy-Name
		case 2109: 		//Reserved
		case 131087: 		//Service-Name
		case 2108: 		//Reserved
		case 2107: 		//Reserved
		case 2106: 		//Reserved
		case 131109: 		//Refund-policy
		case 2304: 		//CUG-Information
		case 131194: 		//TCP-SYN
		case 2100: 		//Reserved
		case 2105: 		//Reserved
		case 131102: 		//Owner-Id
		case 131099: 		//Confirm-Token
			return OCTET_STRING;
		case 131220: 		//Header-Field-Name
		case 2511: 		//LCS-Codeword
		case 131221: 		//Header-Class-Name
		case 2601: 		//IMS-Application-Reference-Identifier
		case 2902: 		//Policy-Counter-Status
		case 5112: 		//Nokia-URI
		case 5106: 		//Rulebase-Id
		case 131236: 		//Cisco-QoS-Profile-Name
		case 3111: 		//External-Identifier
		case 131229: 		//Header-Item-String
		case 131092: 		//Attribute-String
		case 9010: 		//3GPP2-BSID
		case 131215: 		//Header-Group-Name
		case 131091: 		//Match-String
		case 2903: 		//Policy-Counter-Status-Report
		case 2901: 		//Policy-Counter-Identifier
		case 131214: 		//Class-Map-Name
		case 2320: 		//Outgoing-Session-Id
		case 2306: 		//Tariff-XML
		case 2321: 		//Initial-IMS-Charging-Identifier
		case 131219: 		//Header-Insert-Name
		case 514: 		//ETSI-Digest-URI
		case 30: 		//Called-Station-Id
		case 513: 		//ETSI-Digest-Username
		case 87: 		//NAS-Port-Id
		case 512: 		//ETSI-Digest-Auth-Param
		case 511: 		//ETSI-Digest-HA1
		case 504: 		//ETSI-Digest-Realm
		case 517: 		//ETSI-Digest-Nonce-Count
		case 520: 		//ETSI-Digest-Nextnonce
		case 506: 		//ETSI-Digest-Domain
		case 1504: 		//ANID
		case 31: 		//Calling-Station-Id
		case 508: 		//ETSI-Digest-Stale
		case 509: 		//ETSI-Digest-Algorithm
		case 518: 		//ETSI-Digest-Method
		case 519: 		//ETSI-Digest-Entity-Body-Hash
		case 1114: 		//Service-Key
		case 1115: 		//Billing-Information
		case 1427: 		//APN-OI-Replacement
		case 634: 		//Wildcarded-PSI
		case 636: 		//Wildcarded-IMPU
		case 1117: 		//Status-Code
		case 1118: 		//Status-Text
		case 1402: 		//IMEI
		case 1403: 		//Software-Version
		case 1404: 		//QoS-Subscribed
		case 1109: 		//Routeing-Address
		case 1108: 		//Recipient-Address
		case 1104: 		//Sender-Address
		case 521: 		//ETSI-Digest-Response-Auth
		case 524: 		//Codec-Data AVP
		case 67: 		//Tunnel-Server-Endpoint
		case 905: 		//Alternative-APN
		case 66: 		//Acct-Tunnel-Client-Endpoint
		case 554: 		//Subscription-Id-Data
		case 913: 		//MBMS-Required-QoS
		case 1146: 		//Customer-Id
		case 1444: 		//User-Id
		case 58: 		//Egress-VLAN-Name
		case 77: 		//Connect-Info
		case 269: 		//Product-Name
		case 118: 		//Digest-AKA-Auts
		case 117: 		//Digest-Auth-Param
		case 116: 		//Digest-Opaque
		case 114: 		//Digest-Nonce-Count
		case 113: 		//Digest-Digest-CNonce
		case 20: 		//Callback-Id
		case 112: 		//Digest-Entity-Body-Hash
		case 111: 		//Digest-Algorithm
		case 119: 		//Digest-Domain
		case 89: 		//CUI
		case 281: 		//Error-Message
		case 1642: 		//Time-Zone
		case 105: 		//Digest-Nonce
		case 19: 		//Callback-Number
		case 135: 		//Management-Policy-Id
		case 122: 		//SIP-AOR
		case 121: 		//Digest-HA1
		case 120: 		//Digest-Stale
		case 110: 		//Digest-Qop
		case 109: 		//Digest-URI
		case 90: 		//Tunnel-Client-Auth-Id
		case 92: 		//NAS-Filter-Rule
		case 115: 		//Digest-Username
		case 99: 		//Framed-IPv6-Route
		case 91: 		//Tunnel-Server-Auth-Id
		case 102: 		//EAP-Key-Name
		case 104: 		//Digest-Realm
		case 108: 		//Digest-Method
		case 107: 		//Digest-Nextnonce
		case 106: 		//Digest-Response-Auth
		case 103: 		//Digest-Response
			return OCTET_STRING;
		case 6:			//3GPP-SGSN-Address	
		case 14: 		//Login-IP-Host
		case 924: 		//MBMS-GW-SSM-IP-Address
		case 257: 		//Host-IP-Address
		case 1621: 		//Ext-PDP-Address
		case 1452: 		//Trace-Collection-Entity
		case 131137: 		//Nexthop
		case 2307: 		//MBMS-GW-Address
		case 131083: 		//Nexthop-Uplink
		case 131084: 		//Nexthop-Downlink
		case 131146: 		//Destination-IP-Address
		case 131147: 		//Destination-Mask
		case 131211: 		//Nexthop-Media
		case 131138: 		//Nexthop-Reverse
			return OCTET_STRING;
		case 3101: 		//IP-SM-GW-Name
		case 2408: 		//MME-Realm
		case 2402: 		//MME-Name
		case 293: 		//Destination-Host
		case 283: 		//Destination-Realm
		case 275: 		//Alternate-Peer
		case 294: 		//Error-Reporting-Host
			return OCTET_STRING;
		case 1017: 		//TFT-Filter
		case 507: 		//Flow-Description
			return OCTET_STRING;
		case 53: 		//Acct-Output-Gigawords
		case 52: 		//Acct-Input-Gigawords
		case 291: 		//Authorization-Lifetime
		case 616: 		//Exponent
		case 48: 		//Acct-Output-Packets
		case 533: 		//Port-End
		case 532: 		//Port-Start
		case 530: 		//Port
		case 1662: 		//Event-Threshold-Event-1I
		case 1661: 		//Event-Threshold-Event-1F
		case 136: 		//Management-Privilege-Level
		case 47: 		//Acct-Input-Packets
		case 101: 		//Error-Cause
		case 285: 		//Re-Auth-Request-Type			
		case 274: 		//Auth-Request-Type		
			return SIGNED_32;
		case 265: 		//Supported-Vendor-Id
			return UNSIGNED_32;
		case 258: 		//Auth-Application-Id
		case 259: 		//Acct-Application-Id
			return UNSIGNED_32;
		case 1635: 		//PUR-Flags
		case 1630: 		//Event-Threshold-RSRQ
		case 1137: 		//Policy-Counter-Value
		case 1639: 		//UVR-Flags
		case 1629: 		//Event-Threshold-RSRP
		case 1638: 		//CLR-Flags
		case 1405: 		//ULR-Flags
		case 29: 		//Termination-Action
		case 62: 		//Port-Limit
		case 5: 		//NAS-Port
		case 1640: 		//UVA-Flags
		case 1083: 		//Max-Supported-Bandwidth-DL
		case 1084: 		//Max-Supported-Bandwidth-UL
		case 1107: 		//Sequence-Number
		case 1654: 		//Subscription-Data-Flags
		case 16: 		//Login-TCP-Port
		case 28: 		//Idle-Timeout
		case 38: 		//Framed-AppleTalk-Network
		case 1406: 		//ULA-Flags
		case 51: 		//Acct-Link-Count
		case 27: 		//Session-Timeout
		case 49: 		//Acct-Terminate-Cause
		case 46: 		//Acct-Session-Time
		case 1490: 		//IDR-Flags
		case 26: 		//Vendor-Specific
		case 43: 		//Acct-Output-Octets
		case 42: 		//Acct-Input-Octets
		case 41: 		//Acct-Delay-Time
		case 40: 		//Acct-Status-Type
		case 1616: 		//MPS-Priority
		case 37: 		//Framed-AppleTalk-Link
		case 1611: 		//Age-Of-Location-Information
		case 1484: 		//ServiceTypeIdentity
		case 1443: 		//NOR-Flags
		case 1507: 		//MIP-FA-RK-SPI
		case 1441: 		//IDA-Flags
		case 1410: 		//Number-Of-Requested-Vectors
		case 1626: 		//Reporting-Trigger
		case 1412: 		//Immediate-Response-Preferred
		case 1418: 		//HPLMN-ODB
		case 1419: 		//Item-Number
		case 1442: 		//PUA-Flags
		case 1421: 		//DSR-Flags
		case 1422: 		//DSA-Flags
		case 1423: 		//Context-Identifier
		case 1425: 		//Operator-Determined-Barring
		case 1426: 		//Access-Restriction-Data
		case 1625: 		//List-Of-Measurements
		case 1437: 		//CSG-Id
		case 1440: 		//RAT-Frequency-Selection-Priority-ID
		case 1619: 		//Subscribed-Periodic-RAU-TAU-Timer
		case 75: 		//Password-Retry
		case 713: 		//Requested-Nodes
		case 629: 		//Feature-List-ID
		case 630: 		//Feature-List
		case 298: 		//Experimental-Result-Code
		case 83: 		//Tunnel-Preference
		case 1015: 		//PDP-Session-operation
		case 608: 		//Service-Parameter-Type
		case 637: 		//UAR-Flags
		case 299: 		//Inband-Security-Id
		case 500: 		//Maximum-Packet-Size
		case 499: 		//Minimum-Policed-Unit
		case 319: 		//Maximum-Number-Accesses
		case 85: 		//Acct-Interim-Interval
		case 86: 		//Acct-Tunnel-Packets-Lost
		case 485: 		//Accounting-Record-Number
		case 73: 		//ARAP-Security
		case 483: 		//Accounting-Realtime-Required
		case 611: 		//Unit-Type
		case 601: 		//Final-Unit-Indication
		case 615: 		//Requested-Action
		case 719: 		//UDR-Flags
		case 614: 		//Check-Balance-Result
		case 272: 		//Multi-Round-Time-Out
		case 271: 		//Session-Server-Failover
		case 270: 		//Session-Binding
		case 267: 		//Firmware-Revision
		case 600: 		//Abnormal-Termination-Reason
		case 627: 		//User-Data-Request-Type(Obsolete)
		case 522: 		//RS-Bandwidth
		case 277: 		//Auth-Session-State
		case 544: 		//Currency-Code
		case 555: 		//Subscription-Id-Type
		case 716: 		//Sequence-Number
		case 276: 		//Auth-Grace-Period
		case 131209: 		//Dual-Reauthorization-Threshold
		case 131177: 		//Rate-Limit-Action
		case 131201: 		//Priority
		case 131178: 		//DSCP
		case 131208: 		//Dual-Passthrough-Quota
		case 131207: 		//Dual-Billing-Basis
		case 131114: 		//Meter-Initial
		case 131206: 		//Domain-Group-Activation
		case 131113: 		//Meter-Increment
		case 131111: 		//Meter-Include-Imap
		case 131108: 		//Maximum-Timeout
		case 131107: 		//Initial-Timeout
		case 131105: 		//Online-Reauthorization-Threshold
		case 131096: 		//CDR-Time-Threshold
		case 131196: 		//Interleaved
		case 131198: 		//Relative-URL
		case 131234: 		//User-Idle-Pod
		case 131192: 		//Cisco-Event-Trigger-Type
		case 131228: 		//Header-Item
		case 131190: 		//Max-Burst-Size
		case 131189: 		//Policy-Preload-Error-Code
		case 131098: 		//Append-URL
		case 131199: 		//Mining
		case 131100: 		//Service-Class
		case 131101: 		//Service-Idle-Time
		case 131200: 		//User-Default
		case 131118: 		//Weight
		case 131104: 		//Online-Passthrough-Quota
		case 131095: 		//CDR-Volume-Threshold
		case 131119: 		//User-Idle-Timer
		case 131120: 		//Policy-Preload-Req-Type
		case 131213: 		//Quota-Consumption-Time
		case 131154: 		//VLAN-Id
		case 131169: 		//Cisco-Flow-Status
		case 131144: 		//ACL-Number
		case 131168: 		//Policy-Map-Replace
		case 131165: 		//Policy-Map-Type
		case 131164: 		//Flow-Status-Policy-Mismatch
		case 131148: 		//Protocol-ID
		case 131149: 		//Start-of-Port-Range
		case 131150: 		//End-of-Port-Range
		case 131163: 		//Content-Scope
		case 131162: 		//Service-Rating-Group
		case 131159: 		//Last-Packet-Timestanp
		case 131158: 		//First-Packet-Timestanp
		case 131222: 		//Header-Class-Mode
		case 131224: 		//Radius-Attribute-Type
		case 131212: 		//Nexthop-Override
		case 131121: 		//Policy-Preload-Object-Type
		case 131210: 		//Virtual-Online
		case 131122: 		//Policy-Preload-Status
		case 131123: 		//Charging-Rule-Trigger-Type
		case 131174: 		//Max-Bandwidth
		case 131125: 		//Service-Reporting-Level
		case 131128: 		//L7-Parse-Length
		case 131226: 		//Radius-Vsa-Subattribute-Type
		case 131131: 		//CDR-Generation-Delay
		case 131225: 		//Radius-Vsa-Vendor-Id
		case 131133: 		//Replicate-Session-Delay
		case 131134: 		//Content-Pending-Timer
		case 131135: 		//Operation-Status
		case 131136: 		//Subscriber-IP-Source
		case 131157: 		//Duration
		case 2514: 		//Age-Of-Location-Estimate
		case 3109: 		//HSS-Cause
		case 131262: 		//Aggr-Prefix-Len
		case 3110: 		//SIR-Flags
		case 2606: 		//PDP-Address-Prefix-Length
		case 2315: 		//Preferred-AoC-Currency
		case 131110: 		//Meter-Exclude
		case 2404: 		//LCS-Capabilities-Sets
		case 131249: 		//Accel
		case 3010: 		//Application-Port-Identifier
		case 131257: 		//Service-Life-Time
		case 3007: 		//Reference-Number
		case 2520: 		//LCS-Service-Type-ID
		case 2503: 		//LCS-Priority
		case 2505: 		//Horizontal-Accuracy
		case 131251: 		//Cisco-Request-Usage-Type
		case 2506: 		//Vertical-Accuracy
		case 2510: 		//Supported-GAD-Shapes
		case 5109: 		//Quota-Consumption-Time
		case 5110: 		//Quota-Holding-Time
		case 2202: 		//Subsession-Id
		case 131115: 		//Meter-Minimum
		case 131264: 		//Service-Identifier-Hi
		case 131080: 		//Volume-Threshold
		case 131081: 		//Time-Threshold
		case 131082: 		//Content-Idle-Timer
		case 131085: 		//L7-Parse-Protocol-Type
		case 131235: 		//Domain-Group-Clear
		case 131093: 		//Online-Billing-Basis
		case 131094: 		//Service-Activation
		case 5101: 		//Nokia-IMS-Media-Component-Id
		case 2302: 		//SIP-Response-Timestamp-Fraction
		case 131242: 		//Header-Item-Encryption
		case 2301: 		//SIP-Request-Timestamp-Fraction
		case 131263: 		//Service-Identifier-Lo
			return UNSIGNED_32;
		case 2309: 		//Account-Expiration
		case 5103: 		//Time-Of-First-Usage
		case 5104: 		//Time-Of-Last-Usage
		case 55: 		//Event-Timestamp
		case 610: 		//Event-Timestamp
		case 1494: 		//Last-UE-Activity-Time
		case 1439: 		//Expiration-Date
		case 408: 		//BootstrapInfoCreationTime
		case 709: 		//Expiry-Time
		case 404: 		//Key-ExpiryTime
			return UNSIGNED_32;
		case 287: 		//Accounting-Sub-Session-Id
		case 124: 		//MIP6-Feature-Vector
		case 929: 		//MBMS-Data-Transfer-Start
		case 96: 		//Framed-Interface-Id
		case 930: 		//MBMS-Data-Transfer-Stop
		case 617: 		//Value-Digits
		case 465: 		//Accounting-EAP-Auth-Method
		case 131258: 		//Volume-Threshold-64
		case 131155: 		//Volume-Usage
			return UNSIGNED_64;
		case 2509: 		//Response-Time
		case 2512: 		//LCS-Privacy-Check
		case 2513: 		//Accuracy-Fulfilment-Indicator
		case 2308: 		//IMSI-Unauthenticated-Flag
		case 2518: 		//Location-Event
		case 2317: 		//CSG-Access-Mode
		case 2508: 		//Velocity-Requested
		case 2310: 		//AoC-Format
		case 2303: 		//Online-Charging-Flag
		case 2312: 		//AoC-Service-Obligatory-Type
		case 2500: 		//Location-Type
		case 2313: 		//AoC-Service-Type
		case 2203: 		//Subsession-Operation
		case 2204: 		//Multiple-BBERF-Action
		case 2118: 		//Charge-Reason-Code
		case 2318: 		//CSG-Membership-Indication
		case 2604: 		//Local-GW-Inserted-Indicator
		case 3200: 		//SM-Delivery-Outcome-T4
		case 3103: 		//Service-ID
		case 3009: 		//Delivery-Outcome
		case 3008: 		//Request-Status
		case 3006: 		//Priority-Indication
		case 3005: 		//Action-Type
		case 2904: 		//SL-Request-Type
		case 2602: 		//Low-Priority-Indicator
		case 2603: 		//IP-Realm-Default-Indicator
		case 3201: 		//Absent-Subscriber-Diagnostic-T4
		case 2605: 		//Transcoder-Inserted-Indicator
		case 2523: 		//LCS-QoS-Class
		case 1478: 		//Notification-To-UE-User
		case 523: 		//SIP-Forking-Indication
		case 1650: 		//Daylight-Saving-Time
		case 1648: 		//SMS-Register-Request
		case 1482: 		//PLMN-Client
		case 1481: 		//GMLC-Restriction
		case 527: 		//Service-Info-Status
		case 1468: 		//Complete-Data-List-Included-Indicator
		case 15: 		//Login-Service
		case 2066: 		//Charging-Characteristics-Selection-Mode
		case 273: 		//Disconnect-Cause
		//case 6: 		//Service-Type
		case 1455: 		//Requesting-Node-Type
		case 1456: 		//PDN-Type
		case 1457: 		//Roaming-Restricted-Due-To-Unsupported-Feature
		case 45: 		//Acct-Authentic
		case 1462: 		//Trace-Depth
		case 1632: 		//Logging-Duration
		case 7: 		//Framed-Protocol
		case 1434: 		//Alert-Reason
		case 295: 		//Termination-Cause
		case 134: 		//Management-Transport-Protection
		case 1623: 		//Job-Type
		case 133: 		//Framed-Management-Protocol
		case 1618: 		//LIPA-Permission
		case 1617: 		//VPLMN-LIPA-Allowed
		case 407: 		//GBA_U-Awareness-Indicator
		case 480: 		//Accounting-Record-Type
		case 1610: 		//Current-Location-Retrieved
		case 1615: 		//UE-SRVCC-Capability
		case 1613: 		//SIPTO-Permission
		case 1627: 		//Report-Interval
		case 1628: 		//Report-Amount
		case 1503: 		//AN-Trusted
		case 1636: 		//Subscribed-VSRVCC
		case 1634: 		//MDT-User-Consent
		case 1633: 		//Relay-Node-Indicator
		case 1491: 		//ICS-Indicator
		case 1492: 		//IMS-Voice-Over-PSSessions-Supported
		case 1493: 		//Homogeneous-Support-of-IMS-Voice-Over-PS-Sessions
		case 1631: 		//Logging-Interval
		case 1499: 		//User-State
		case 1501: 		//Non-3GPP-IP-Access
		case 1502: 		//Non-3GPP-IP-Access-APN
		case 1614: 		//Error-Diagnostic
		case 65: 		//Tunnel-Medium-Type
		case 1110: 		//Originating-Interface
		case 1111: 		//Delivery-Report
		case 1112: 		//Read-Reply
		case 1113: 		//Sender-Visibility
		case 706: 		//Requested-Domain
		case 705: 		//Subs-Req-Type
		case 703: 		//Data-Reference
		case 648: 		//Multiple-Registration-Indication
		case 72: 		//ARAP-Zone-Access
		case 76: 		//Prompt
		case 638: 		//Loose-Route-Indication
		case 1417: 		//Network-Access-Mode
		case 1119: 		//Routeing-Address-Resolution
		case 1420: 		//Cancellation-Type
		case 633: 		//Originating-Request
		case 707: 		//Current-Location
		case 708: 		//Identity-Set
		case 902: 		//MBMS-StartStop-Indication
		case 914: 		//MBMS-Counting-Information
		case 915: 		//MBMS-User-Data-Mode-Indication
		case 64: 		//Tunnel-Type
		case 61: 		//NAS-Port-Type
		case 718: 		//Local-Time-Zone-Indication
		case 922: 		//MBMS-HC-Indicator
		case 923: 		//MBMS-Access-Indicator
		case 717: 		//Pre-paging-Supported
		case 57: 		//Ingress-Filters
		case 714: 		//Serving-Node-Indication
		case 712: 		//One-Time-Notification
		case 1103: 		//Trigger-Event
		case 710: 		//Send-Data-Indication
		case 2068: 		//Dynamic-Address-Flag-Extension
		case 1424: 		//Subscriber-Status
		case 1432: 		//VPLMN-Dynamic-Address-Allowed
		case 928: 		//MBMS-GW-UDP-Port-Indicator
		case 624: 		//User-Data-Already-Available
		case 1438: 		//PDN-GW-Allocation-Type
		case 623: 		//User-Authorization-Type
		case 1445: 		//Equipment-Status
		case 1428: 		//All-APN-Configurations-Included-Indicator
			return SIGNED_32;
		case 619: 		//Primary-Event-Charging-Function-Name
		case 621: 		//Primary-Charging-Collection-Function-Name
		case 620: 		//Secondary-Event-Charging-Function-Name
		case 622: 		//Secondary-Charging-Collection-Function-Name
			return OCTET_STRING;
		case 1472: 		//Specific-APN-Info
		case 1436: 		//CSG-Subscription-Data
		case 1106: 		//Result-Recipient-Address
		case 559: 		//Original-Subscription-Id
		case 612: 		//Unit-Value
		case 300: 		//E2E-Sequence
		case 1473: 		//LCS-Info
		case 553: 		//Subscription-Id
		case 1475: 		//LCS-PrivacyException
		case 1435: 		//AMBR
		case 1624: 		//Area-Scope
		case 531: 		//Port-Range
		case 1622: 		//MDT-Configuration
		case 613: 		//Used-Service-Unit
		case 1100: 		//Served-User-Identity
		case 860: 		//Cause
		case 1458: 		//Trace-Data
		case 1498: 		//SGSN-User-State
		case 607: 		//Service-Parameter-Info
		case 715: 		//Repository-Data-ID
		case 618: 		//Charging-Information
		case 1469: 		//PDP-Context
		case 279: 		//Failed-AVP
		case 631: 		//Supported-Applications
		case 1641: 		//VPLMN-CSG-Subscription-Data
		case 1467: 		//GPRS-Subscription-Data
		case 297: 		//Experimental-Result
		case 1637: 		//Equivalent-PLMN-List
		case 1105: 		//Initial-Recipient-Address
		case 1116: 		//Status
		case 1600: 		//MME-Location-Information
		case 1483: 		//Service-Type
		case 1413: 		//Authentication-Info
		case 1505: 		//Trace-Info
		case 501: 		//TMOD-2
		case 1414: 		//E-UTRAN-Vector
		case 1415: 		//UMTS-Vector
		case 1416: 		//GERAN-Vector
		case 1500: 		//Non-3GPP-User-Data
		case 526: 		//Acceptable-Service-Info
		case 1485: 		//MO-LR
		case 1496: 		//EPS-Location-Information
		case 1495: 		//EPS-User-State
		case 635: 		//SIP-Digest-Authenticate AVP
		case 1486: 		//Teleservice-List
		case 632: 		//Associated-Identities
		case 1488: 		//Call-Barring-Infor-List
		case 1601: 		//SGSN-Location-Information
		case 639: 		//SCSCF-Restoration-Info
		case 1479: 		//External-Client
		case 700: 		//User-Identity
		case 1497: 		//MME-User-State
		case 1134: 		//Charging-Policy-Report
		case 1135: 		//Policy-Counter
		case 651: 		//Identity-with-Emergency-Registration
		case 649: 		//Restoration-Info
		case 1612: 		//Active-APN
		case 1431: 		//EPS-Subscribed-QoS-Profile
		case 1400: 		//Subscription-Data
		case 647: 		//Associated-Registered-Identities
		case 1430: 		//APN-Configuration
		case 642: 		//Subscription-Info
		case 1408: 		//Requested-EUTRAN-Authentication-Info
		case 1409: 		//Requested-UTRAN-GERAN-Authentication-Info
		case 495: 		//TMOD-1
		case 1429: 		//APN-Configuration-Profile
		case 628: 		//Supported-Features
		case 131203: 		//Domain-Group-Definition
		case 131231: 		//Header-Insert-Definition
		case 131204: 		//Domain-Group-Install
		case 131232: 		//Header-Insert-Install
		case 131205: 		//Domain-Group-Remove
		case 131259: 		//Delegated-IP-Install
		case 131244: 		//Service-Group-Definition
		case 131248: 		//Cisco-Report-Usage
		case 131197: 		//Control-URL
		case 131241: 		//Cisco-QoS-Profile-Downlink
		case 131233: 		//Header-Insert-Remove
		case 131239: 		//Cisco-QoS-Profile-Remove
		case 131238: 		//Cisco-QoS-Profile-Install
		case 131237: 		//Cisco-QoS-Profile
		case 131265: 		//Service-Identifier-Range
		case 131230: 		//Header-Items-Encrypted
		case 131240: 		//Cisco-QoS-Profile-Uplink
		case 131191: 		//Failed-Preload-Obj-Name
		case 131223: 		//Header-Class
		case 131218: 		//Header-Group-Remove
		case 131217: 		//Header-Group-Install
		case 131252: 		//Cisco-Request-Charging-Rule-Usage
		case 131250: 		//Cisco-Answer-User-Usage
		case 131255: 		//Cisco-Answer-Service-Group-Usage
		case 131216: 		//Header-Group-Definition
		case 131227: 		//Header-Item-Radius
		case 131247: 		//Service-Group-Event
		case 131260: 		//Delegated-IPv4-Definition
		case 131254: 		//Cisco-Answer-Charging-Rule-Usage
		case 131246: 		//Service-Group-Remove
		case 131261: 		//Delegated-IPv6-Definition
		case 131245: 		//Service-Group-Install
		case 131253: 		//Cisco-Request-Service-Group-Usage
		case 2200: 		//Subsession-Decision-Info
		case 3106: 		//T4-Parameters
		case 3107: 		//Service-Data
		case 3108: 		//T4-Data
		case 5111: 		//Default-Quota
		case 131072: 		//Cisco-Charging-Rule-Definition
		case 131073: 		//Content-Definition
		case 131074: 		//Billing-Policy-Definition
		case 131075: 		//Policy-Map-Definition
		case 131076: 		//Service-Definition
		case 131077: 		//Content-Policy-Map
		case 131079: 		//Billing-Plan-Definition
		case 131086: 		//Service-Status
		case 131090: 		//Policy-Map-Match
		case 131097: 		//Advice-Of-Charge
		case 131106: 		//Online-Reauthorization-Timeout
		case 3105: 		//Service-Parameters
		case 3102: 		//User-Identifier
		case 2201: 		//Subsession-Enforcement-Info
		case 2305: 		//Real-Time-Tariff-Information
		case 2311: 		//AoC-Service
		case 2314: 		//AoC-Subscription-Information
		case 2319: 		//User-CSG-Information
		case 2401: 		//Serving-Node
		case 2406: 		//Additional-Serving-Node
		case 2501: 		//LCS-EPS-Client-Name
		case 2502: 		//LCS-Requestor-Name
		case 2504: 		//LCS-QoS
		case 2521: 		//LCS-Privacy-Check-Non-Session
		case 2522: 		//LCS-Privacy-Check-Session
		case 3001: 		//Device-Action
		case 3002: 		//Device-Notification
		case 3003: 		//Trigger-Data
		case 131112: 		//Metering-Granularity
		case 131078: 		//Service-Info
		case 131116: 		//Verify
		case 131172: 		//QoS-Rate-Limit-DL
		case 131173: 		//QoS-Rate-Limit
		case 131175: 		//Rate-Limit-Conform-Action
		case 131176: 		//Rate-Limit-Exceed-Action
		case 131179: 		//Policy-Map-Install
		case 131180: 		//Policy-Map-Remove
		case 131181: 		//Billing-Policy-Install
		case 131182: 		//Billing-Policy-Remove
		case 131183: 		//Content-Install
		case 131184: 		//Content-Remove
		case 131185: 		//Service-Install
		case 131186: 		//Service-Remove
		case 131187: 		//Billing-Plan-Install
		case 131188: 		//Billing-Plan-Remove
		case 131193: 		//Cisco-Event-Trigger
		case 131171: 		//QoS-Rate-Limit-UL
		case 131170: 		//Service-QoS
		case 131124: 		//Charging-Rule-Event
		case 131126: 		//Accounting
		case 131129: 		//Service-CDR-Threshold
		case 131130: 		//Intermediate-CDR-Threshold
		case 131132: 		//Replicate-Session
		case 131139: 		//Charging-Rule-Event-Trigger
		case 131141: 		//Content-Flow-Description
		case 131142: 		//Content-Flow-Filter
		case 131143: 		//Client-Group-Id
		case 131152: 		//Failed-Preload-Object
		case 131156: 		//Time-Usage
		case 131160: 		//Cisco-Flow-Description
		case 131161: 		//Terminate-Bearer
		case 131166: 		//Policy-Map-Match-Install
		case 131167: 		//Policy-Map-Match-Remove
		case 131195: 		//Cisco-Event
			return GROUPED;
		default:
			if( pAppAvpDataTypeHandler > 0)
				return pAppAvpDataTypeHandler( iAvpCode);
			else
				return OCTET_STRING;
	}
	return -1;
}





//-------------------------------------------------------------------------------------------------------------------------
// Decode Routines - Start
//-------------------------------------------------------------------------------------------------------------------------
#define GetHiByte(w) (((unsigned short)(w) >> 8) & 0xff)
#define GetLoByte(w) ((unsigned short)(w) & 0xff)
#define GetHiWord(l) (((unsigned long)(l) >> 16) & 0xffffL)
#define GetLoWord(l) ((unsigned long)(l) & 0xffffL)

#define PutHiByte(w,b) (unsigned short) (((unsigned short)(b) << 8) | ((unsigned short)(w) & 0x00ff))
#define PutLoByte(w,b) (unsigned short) (((unsigned short)(b) & 0xff) | ((unsigned short)(w) & 0xff00))
#define PutHiWord(l,w) (unsigned long) (((unsigned long)(w) << 16) | ((unsigned long)(l) & (unsigned long)0x0000ffff))
#define PutLoWord(l,w) (unsigned long) (((unsigned long)(w) & 0xffff) | ((unsigned long)(l) & (unsigned long)0xffff0000))


#define TO_HEX(i) (i <= 9 ? '0' + i : 'A' - 10 + i)

void decodeBitVal(int * bVal, char* _nwByte, int iFromIndex, int bitNumber)
{
	*bVal =  (_nwByte[iFromIndex + 0] & (1 << bitNumber)) ? 1 : 0;
}

void decodeIntValueFrom4Bytes(unsigned int * iInt, char* _nwByte, int iFromIndex)
{
	unsigned short nwWord[2];
	unsigned short hoWord[2];
	unsigned int tmpU32;

	tmpU32 = 0;
	nwWord[0] = nwWord[1] = 0;
	hoWord[0] = hoWord[1] = 0;
	nwWord[0] = (unsigned short)PutHiByte(nwWord[0], _nwByte[iFromIndex + 0]);
	nwWord[0] = (unsigned short)PutLoByte(nwWord[0], _nwByte[iFromIndex + 1]);
	hoWord[0] = (unsigned short)((nwWord[0]));
	nwWord[1] = (unsigned short)PutHiByte(nwWord[1], _nwByte[iFromIndex + 2]);
	nwWord[1] = (unsigned short)PutLoByte(nwWord[1], _nwByte[iFromIndex + 3]);
	hoWord[1] = (unsigned short)((nwWord[1]));
	tmpU32 = (unsigned long)PutHiWord(tmpU32, nwWord[0]);
	tmpU32 = (unsigned long)PutLoWord(tmpU32, nwWord[1]);

	*iInt = (unsigned long)((tmpU32));
}

void decodeIntValueFrom3Bytes(unsigned int * iInt, char* nwByte, int iFromIndex)
{
	unsigned short nwWord[2];
	unsigned int tmpU32;

	tmpU32 = 0;
	nwWord[0] = 0;
	nwWord[1] = 0;

	nwWord[0] = ((unsigned short)nwByte[ iFromIndex + 0] & 0x00FF);
	nwWord[1] = ((unsigned short)nwByte[ iFromIndex + 1] & 0x00FF);
	nwWord[1] <<= 8;
	nwWord[1] |= ((unsigned short)nwByte[ iFromIndex + 2] & 0x00FF);


	nwWord[1] = (nwWord[1]);
	tmpU32 = ((unsigned long)nwWord[0] & 0x0000FFFF);
	tmpU32 <<= 16; 
	tmpU32 |= ((unsigned long)nwWord[1] & 0x0000FFFF);

	*iInt = tmpU32;
}

void decodeLongValueFrom3Bytes(unsigned long * iLong, char* nwByte, int iFromIndex)
{
	unsigned short nwWord[2];
	unsigned long tmpU32;

	tmpU32 = 0;
	nwWord[0] = 0;
	nwWord[1] = 0;

	nwWord[0] = ((unsigned short)nwByte[iFromIndex + 0] & 0x00FF);
	nwWord[1] = ((unsigned short)nwByte[iFromIndex + 1] & 0x00FF);
	nwWord[1] <<= 8;
	nwWord[1] |= ((unsigned short)nwByte[iFromIndex + 2] & 0x00FF);


	nwWord[1] = (nwWord[1]);
	tmpU32 = ((unsigned long)nwWord[0] & 0x0000FFFF);
	tmpU32 <<= 16; 
	tmpU32 |= ((unsigned long)nwWord[1] & 0x0000FFFF);

	*iLong = tmpU32;
}

void decodeLongValueFrom4Bytes(unsigned long * iLong, char* _nwByte, int iFromIndex)
{
	unsigned short nwWord[2];
	unsigned short hoWord[2];
	unsigned long tmpU32;

	tmpU32 = 0;
	nwWord[0] = nwWord[1] = 0;
	hoWord[0] = hoWord[1] = 0;
	nwWord[0] = (unsigned short)PutHiByte(nwWord[0], _nwByte[ iFromIndex + 0 ]);
	nwWord[0] = (unsigned short)PutLoByte(nwWord[0], _nwByte[ iFromIndex + 1 ]);
	hoWord[0] = (unsigned short)((nwWord[0]));
	nwWord[1] = (unsigned short)PutHiByte(nwWord[1], _nwByte[ iFromIndex + 2 ]);
	nwWord[1] = (unsigned short)PutLoByte(nwWord[1], _nwByte[ iFromIndex + 3 ]);
	hoWord[1] = (unsigned short)((nwWord[1]));
	tmpU32 = (unsigned long)PutHiWord(tmpU32, nwWord[0]);
	tmpU32 = (unsigned long)PutLoWord(tmpU32, nwWord[1]);

	*iLong = (unsigned long)((tmpU32));
}



unsigned long charToULong(char *a) 
{
	unsigned long n = 0;
  
	n = (((unsigned long)a[0] << 56) & 0xFF00000000000000U)
		| (((unsigned long)a[1] << 48) & 0x00FF000000000000U)
		| (((unsigned long)a[2] << 40) & 0x0000FF0000000000U)
		| (((unsigned long)a[3] << 32) & 0x000000FF00000000U)
		| ((a[4] << 24) & 0x00000000FF000000U)
		| ((a[5] << 16) & 0x0000000000FF0000U)
		| ((a[6] <<  8) & 0x000000000000FF00U)
		| (a[7]        & 0x00000000000000FFU);

	return n;
}

long charToLong(char *a) 
{
	long n = 0;
  
	n = (((long)a[0] << 56) & 0xFF00000000000000U)
		| (((long)a[1] << 48) & 0x00FF000000000000U)
		| (((long)a[2] << 40) & 0x0000FF0000000000U)
		| (((long)a[3] << 32) & 0x000000FF00000000U)
		| ((a[4] << 24) & 0x00000000FF000000U)
		| ((a[5] << 16) & 0x0000000000FF0000U)
		| ((a[6] <<  8) & 0x000000000000FF00U)
		| (a[7]        & 0x00000000000000FFU);

	return n;
}

/*
int64_t charTo64bitNum(char *a) 
{
	int64_t n = 0;
  
	n = (((int64_t)a[0] << 56) & 0xFF00000000000000U)
		| (((int64_t)a[1] << 48) & 0x00FF000000000000U)
		| (((int64_t)a[2] << 40) & 0x0000FF0000000000U)
		| (((int64_t)a[3] << 32) & 0x000000FF00000000U)
		| ((a[4] << 24) & 0x00000000FF000000U)
		| ((a[5] << 16) & 0x0000000000FF0000U)
		| ((a[6] <<  8) & 0x000000000000FF00U)
		| (a[7]        & 0x00000000000000FFU);

	return n;
}
*/

/*
void decodeTo64BitValue(int64_t *int64Number, char *buffer) 
{
	*int64Number =  (((int64_t)buffer[0] << 56) & 0xFF00000000000000U)
					| (((int64_t)buffer[1] << 48) & 0x00FF000000000000U)
					| (((int64_t)buffer[2] << 40) & 0x0000FF0000000000U)
					| (((int64_t)buffer[3] << 32) & 0x000000FF00000000U)
					| ((buffer[4] << 24) & 0x00000000FF000000U)
					| ((buffer[5] << 16) & 0x0000000000FF0000U)
					| ((buffer[6] <<  8) & 0x000000000000FF00U)
					| (buffer[7]        & 0x00000000000000FFU);
}

void decodeToLongBitValue(long long *int64Number, char *buffer) 
{
	*int64Number =  (((long long)buffer[0] << 56) & 0xFF00000000000000U)
					| (((long long)buffer[1] << 48) & 0x00FF000000000000U)
					| (((long long)buffer[2] << 40) & 0x0000FF0000000000U)
					| (((long long)buffer[3] << 32) & 0x000000FF00000000U)
					| ((buffer[4] << 24) & 0x00000000FF000000U)
					| ((buffer[5] << 16) & 0x0000000000FF0000U)
					| ((buffer[6] <<  8) & 0x000000000000FF00U)
					| (buffer[7]        & 0x00000000000000FFU);
}
*/



void encodeInt64ToChar( int64_t num, char *buffer) 
{
	int i;
	for(i = 0; i < 8; i++) {
		buffer[i] = num >> (8-1-i)*8;
	}	
}


void encodeIntTo3Bytes(unsigned int * val, char * data)
{
	unsigned char *bytePtr = (unsigned char*)val;
	const int arrayLength = sizeof(int);

	int i;
	for( i = 1; i < arrayLength; i++)
	{
		data[i-1] = bytePtr[ (arrayLength) - (i+1)];
	}
}


void encodeIntTo3BytesFrm(unsigned int * val, char * data, int iFrom)
{
	unsigned char *bytePtr = (unsigned char*)val;
	const int arrayLength = sizeof(int);

	int i;
	for( i = 1; i < arrayLength; i++)
	{
		data[iFrom + (i-1)] = bytePtr[ (arrayLength) - (i+1)];
	}
}



void encodeLongTo3Bytes(unsigned long * val, char * data)
{
	unsigned char *bytePtr = (unsigned char*)val;
	const int arrayLength = sizeof(unsigned long);

	int i;
	for( i = 1; i < arrayLength; i++)
	{
		data[i-1] = bytePtr[ (arrayLength) - (i+1)];
	}
}


/*
void encodeIntTo4Bytes(int * val, char * data)
{
	unsigned char *bytePtr = (unsigned char*)val;
	const int arrayLength = sizeof(int);

	int i;
	for( i = 0; i < arrayLength; i++)
	{
		data[i] = bytePtr[ (arrayLength) - (i+1)];
	}
}

	unsigned int number = 4054359794;    ;
	unsigned int number2 = htonl(number);
	char numberStr[4];
	memcpy(numberStr, &number2, 4);

	printf("%x %x %x %x\n", numberStr[0], numberStr[1], numberStr[2], numberStr[3]);



*/

/*
void CopyInt(int value, char* buffer)
{
	memcpy(buffer, (void*)value, sizeof(int));
}
*/

void encodeIntTo4Bytes(unsigned int val, char * data, int iFrom)
{
	data[iFrom + 0] = (val >> 24) & 0xFF;
	data[iFrom + 1] = (val >> 16) & 0xFF;
	data[iFrom + 2] = (val >> 8) & 0xFF;
	data[iFrom + 3] = val & 0xFF;
}


void encodeLongTo4Bytes(unsigned long val, char * data, int iFrom)
{
	data[iFrom + 0] = (val >> 24) & 0xFF;
	data[iFrom + 1] = (val >> 16) & 0xFF;
	data[iFrom + 2] = (val >> 8) & 0xFF;
	data[iFrom + 3] = val & 0xFF;
}


void encodeULongTo8Bytes(unsigned long val, char * data, int iFrom)
{
	data[iFrom + 0] = (val >> 56) & 0xFF;
	data[iFrom + 1] = (val >> 48) & 0xFF;
	data[iFrom + 2] = (val >> 40) & 0xFF;
	data[iFrom + 3] = (val >> 32) & 0xFF;
	data[iFrom + 4] = (val >> 24) & 0xFF;
	data[iFrom + 5] = (val >> 16) & 0xFF;
	data[iFrom + 6] = (val >> 8) & 0xFF;
	data[iFrom + 7] = val & 0xFF;
}

void encodeLongTo8Bytes(long val, char * data, int iFrom)
{
	data[iFrom + 0] = (val >> 56) & 0xFF;
	data[iFrom + 1] = (val >> 48) & 0xFF;
	data[iFrom + 2] = (val >> 40) & 0xFF;
	data[iFrom + 3] = (val >> 32) & 0xFF;
	data[iFrom + 4] = (val >> 24) & 0xFF;
	data[iFrom + 5] = (val >> 16) & 0xFF;
	data[iFrom + 6] = (val >> 8) & 0xFF;
	data[iFrom + 7] = val & 0xFF;
}

//-------------------------------------------------------------------------------------------------------------------------
// Decode Routines - End
//-------------------------------------------------------------------------------------------------------------------------
typedef struct ArrayElement
{
    /*Fields Here*/
	void* Data;				


    /*Pool Management*/
    int isReleased;
    struct ArrayElement* PoolNext;
    int PoolIndex;
} iArrayElement;



typedef struct ArrayList
{
    /*Fields Here*/
    void *HeadPtr;
    void *CurrPtr;
    long int Count;

    pthread_mutex_t Lock;                   


    /*Pool Management*/
    int isReleased;
    struct ArrayList* PoolNext;
    int PoolIndex;
} iArrayList;

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

typedef struct CData
{
	char* Data;
	int len;

	int PoolIndex;
	struct CData *PoolNext;
	int isReleased;
} iCData;

typedef struct DiamRawData
{
	struct CData* Header;
	struct CData* PayLoad;
	struct ClientInfo* CliInfo;
	//void * TCPCliInfo;
	void *PeerConfigData;
	int iPeerIndex;
	long int iRequestNo;
	int iDecodeFull;
	int iRoutinError;
	int iErrorCode;
	u_int16_t sinfo_stream;
	

#if SCTP_SUPPORT	
	sctp_assoc_t sinfo_assoc_id;
	struct sctp_sndrcvinfo sinfo;
#endif
	
	//1 - Peer, 2 - Client
	int iRouteMessageTo;
	
	//1 - Peer, 2 - Client[Host], 10 - SCTP Client[Host], 11 - SCTP Peer  
	int iMessageArrivedFrom;	

	struct DiamRawData* PoolNext;
	int PoolIndex;
	int isReleased;
} iDiamRawData;

typedef struct CmdFlags
{
	int Request;
	int Proxyable;
	int Error;
	int Retransmit;
} iCmdFlags;

typedef struct AvpFlags
{
	 int VendorSpecific;
	 int Mandatory;
	 int Protected;
} iAvpFlags;

typedef struct DiamAvp
{
	int AvpCode;
	int AvpLength;
	int Padding;
	int PayLoadLength;
	int HeaderLength;
	int VendorId;
	//int isEncoded;

	//int isGrouped;
	int iDataType;

	int intVal;
	unsigned int usIntVal;
	
	
	//long int64Val;
	//unsigned long usInt64Val;
	
	long int64Val;
	unsigned long usInt64Val;	
	
	
	float fVal;


	struct AvpFlags Flags;
	struct CData* PayLoad;
	//struct CData* AvpPayLoad;

	struct DiamAvp* Head;
	struct DiamAvp* Next;

	struct DiamAvp* GroupHead;
	struct DiamAvp* GroupCurrent;

	int PoolIndex;
	struct DiamAvp* PoolNext;
	int isReleased;
} iDiamAvp;



typedef struct DiamMessage
{
	int CmdCode;
	int Length;
	int AppId;
	unsigned long tempHBHId;
	unsigned long HBHId;
	unsigned long E2EId;
	struct CmdFlags Flags;
	struct DiamAvp* Head;
	struct DiamAvp* Current;
	char DestHost[200];
	char DestRealm[200];
	char SessionId[200];
	unsigned int iResultCode;
	unsigned int iCCReqNo;
	int iCCReqType;

	char ServiceContext[200];
	uint8_t hasServiceContextId;
	uint8_t iLoopDetected;
	
	long long int IMSI;
	long long int MSISDN;
	long long int IMEI;

	struct DiamAvp* PoolNext;
	int PoolIndex;
	struct ClientInfo *ptrClientInfo;
	u_int16_t sinfo_stream;
	
#if SCTP_SUPPORT	
	sctp_assoc_t sinfo_assoc_id;
	struct sctp_sndrcvinfo sinfo;
#endif
	
	int AvpCount;
	//int isEncoded;
	//struct CData* RespPayLoad;
	int isReleased;
} iDiamMessage;


typedef struct DiamRouteMessage
{
	struct DiamMessage *DiamMessagePtr;
	struct DiamRawData *DiamRawDataPtr;	
	
	int isReleased;
	struct DiamRouteMessage* PoolNext;
	int PoolIndex;
} iDiamRouteMessage;

typedef struct StickySessionInfo
{
	int iPeerIndex;
	
	int isReleased;
	struct StickySessionInfo* PoolNext;
	int PoolIndex;
} iStickySessionInfo;

typedef struct SctpStreamBuffer
{
	uint16_t sinfo_stream;
	int PendingBufferLength;
	char sBuffer[5000];
} iSctpStreamBuffer;

typedef struct SupportedVendorApplicationId
{
	unsigned int iAuthApplicationId;
	unsigned int iVendorId;	
} iSupportedVendorApplicationId;

typedef struct ClientInfo
{
	struct sockaddr clientAddr;
	char OriginHost[250];
	char OriginRealm[200];
	int isActive;
	int CloseIt;
	int fd;
	long int ReceivedMessages;
	long int SentMessages;	
	long int RoutingError;
	int RoutingTableIndex;
	
	char ClientHostName[250];
	char ClientHostRealmName[250];
	char ClientIP[30];
	int ClientPort;	
	int isConnected;
	int isCEASuccess;
	int iConnectToClient;
	int AppId;	//Supported Interface
	int iIdleTime;
	int iDWRCount;
	int ClientIndex;
	
	void *Parent;
	void *HostConfig;
	int TransportType;		//0-TCP, 1-SCTP

	unsigned int VendorIds[10];
	int VendorIdsCount;

	unsigned int AuthApplicationIds[10];
	int AuthApplicationIdsCount;

	unsigned int AcctApplicationIds[10];
	int AcctApplicationIdsCount;

	iSupportedVendorApplicationId SupportedVendorApplicationIds[10];
	int SupportedVendorApplicationIdsCount;
	iSctpStreamBuffer SctpStreamBuffer[100];
	
	//v1
	struct ClientInfo * NextClientInfo;
	sem_t sem_lock;
	
	/*Pool Management*/
	int isReleased;
	struct ClientInfo* PoolNext;
	int PoolIndex;
} iClientInfo;


typedef struct PeerInfo
{
	char PeerHostName[250];
	char PeerHostRealmName[250];
	char ClientHostName[250];
	char ClientHostRealmName[250];
	
	int TransportType;		//0 - TCP, 1 -SCTP	
	char PeerIP[30];
	int ClientInfo[10];
	int ClientInfoCount;
	int PeerPort;
	int fd;
	int isConnected;
	int isCEASuccess;
	long iResponseNo;
	int iIdleTime;
	int iDWRCount;	
	int AppId;	//Supported Interface
	int EPI;
	int EPR;
	int EPRPI;	
	
	int HEPI;
	int HEPR;
	int HEPRPI;
	
	int HREPI;
	int HREPR;
	int HREPRPI;
	
	int AEPI;
	int AEPR;
	int AEPRPI;
	
	long MessagesRouted;
} iPeerInfo;


typedef struct WorkerThread
{
	void* Data;
	int Index;
	struct ThreadPool * Parent;
	struct WorkerThread *Next;
	int isFree;
	sem_t sem_lock;
} iWorkerThread;


typedef struct ThreadPool
{
	int ThreadCount;
	int FreeCount;
	iWorkerThread *Head;
	iWorkerThread *Current;
	pthread_mutex_t aquireLock;
} iThreadPool;

typedef struct PeerEndPointRecord
{
	char Realm[200];
	int CurrentIndex;	
	int PeerIndexCount;
	int PeerIndexes[36];
	int RequestNo;
	int AppId;	
} iPeerEndPointRecord;

typedef struct InterfaceEndPoint
{
	char Realm[200];
	char HostName[200];
	char HostRealm[400];
	int AppId;
	int NoOfPeerNodes;
	int CurrentIndex;
	int PeerIndexes[36];
	int RequestNo;
	int EndPointRecordCount;
	struct PeerEndPointRecord EndPointRecord[36];
} iInterfaceEndPoint;


typedef struct RealmInfo
{
	char HostName[200];	
	char  RealmName[200];
	int AppId[10];
	int AppCount;
	struct ClientInfo *clientInfo;
	
	// Local Action -- LOCAL/PROXY/RELAY
	// Node Discovery -- Dynamic/Static
	// Expiration Time -- TTL
} iRealmInfo;

typedef struct MemoryUsage
{
	long int DiamRawDataAllocatedCount;
	long int DiamRawDataReleaseCount;	
	long int DiamMessageAllocatedCount;
	long int DiamMessageReleaseCount;	
	long int DiamAVPAllocatedCount;
	long int DiamAVPReleaseCount;	
	long int DiamCDataAllocatedCount;
	long int DiamCDataReleaseCount;	
	long int DecodeThreadAllocatedCount;
	long int DecodeThreadReleaseCount;	
	long int DecodeThreadRejectedCount;	
	long int QueueRecordAllocatedCount;	
	long int QueueRecordReleasedCount;	
	long int DiamRoutePoolAllocatedCount;	
	long int DiamRoutePoolReleasedCount;	
	long int SessionBaseRecordAllocatedCount;	
	long int SessionBaseRecordReleasedCount;			
	long int SocketReadCount;
	long int SocketWriteCount;
	long int UnableToDeliverInvalidClientObject;
	long int UnableToDeliverInvalidActiveState;
	long int UnableToDeliverInvalidLength;	
	
	long int c001;
	long int c002;
	long int c003;
	long int c004;
	long int c005;
	long int c006;
	long int c007;
	long int c008;
	long int c009;
	long int c010;
	long int c011;
	long int c012;
	long int c013;
	long int c014;
	long int c015;
	long int c016;
	long int c017;
	long int c018;
	long int c019;
	long int c020;
	long int c021;
	long int c022;
	long int c023;
	long int c024;
	long int c025;
	long int c026;
	long int c027;
	long int c028;
	long int c029;
	long int c030;
	long int c031;
	long int c032;
	long int c033;
	long int c034;
	long int c035;
	long int c036;
	long int c037;
	long int c038;
	long int c039;
	long int c040;
	long int c041;
	long int c042;
	long int c043;
	long int c044;
	long int c045;
	long int c046;
	long int c047;
	long int c048;
	long int c049;
	long int c050;
} iMemoryUsage;




typedef struct QueueRecord
{
	void *Data;
	struct QueueRecord *Next;
	struct QueueRecord *PoolNext;
	int isReleased;
	int PoolIndex;	
} iQueueRecord;

typedef struct Queue
{
	iQueueRecord *Front;
	iQueueRecord *Rear;	
	iQueueRecord *Temp;	
	iQueueRecord *Front1;
	long TotalDequeued;
	long TotalQueued;
	long QueueCount;
	long QueueLimit;		
	int Type;
	pthread_mutex_t Lock;	
	sem_t sem_lock;
} iQueue;


#if DIAMDRA

typedef struct HBHInfo
{
	struct ClientInfo *oClientInfo;
	unsigned int OriginalHBH;
	//unsigned int ETEId;	
	char IsFree;
	//int isLocked;
} iHBHInfo;

#endif


typedef struct LogMessage
{
	int Identity;
	int ILogLevel;
	char Message[400];
} iLogMessage;


typedef struct PCounter
{
	char Name[100];
	char IpAddress[30];
	int Port;
	long iRequest;
	long iResponse;
	int isActive;
	int CTimes;	
	int isConfigured;
} iPCounter;

typedef struct LogConfig
{
	int iHandle;	
	char Prefix[10];
	char Path[500];	
	int iLoggingThreshold;
	int CSVMode;
	int iFileIndex;
	int Enabled;
	pthread_mutex_t Lock;
} iLogConfig;

typedef struct ASTDataPtr
{
	short GenerationId;
	int PtrCharVal;
	void *Data;
	unsigned int Count;
	
	struct ASTDataPtr *Parent;	
	struct ASTDataPtr *Root;
	struct ASTDataPtr *NextItem;
	struct ASTDataPtr *PrevItem;
	struct ASTDataPtr *Current;
	struct ASTDataPtr *PoolNext;

	unsigned char isRoot;	
	int isReleased;
} IASTDataPtr;

typedef struct RootASTDataPtr
{
	int TotalNodes;
	IASTDataPtr *PoolNext;
	
	IASTDataPtr *iASTDataPtr;
	pthread_mutex_t pLock;
} iRootASTDataPtr;


typedef struct IndexASTDataPtr
{
	int TotalNodes;	
	IASTDataPtr *PoolNext;
	
	IASTDataPtr *iASTDataPtr;
	pthread_mutex_t pLock;
} iIndexASTDataPtr;

typedef struct LogCat
{
	int iLogCatId;
	char iLogCatName[100];
	uint8_t Enabled;
} iLogCat;

#define MAX_EPOLL_THREADS					10

//RingBufferTCPServerImplementation [Start]
typedef struct EPollData
{
	int efd;
	pthread_t thread_id;
	int index;
	
	int iWatchCount;
} iEPollData;

typedef struct TCPServerInfo
{
	int iPort;
	void (*recvCallBack)(void*);
	void * Queue;
	void * HostConfigData;
} iTCPServerInfo;


typedef struct TCPClientInfo
{
	struct sockaddr_in clientAddr;
	char OriginRealm[200];	
	int isActive;
	int CloseIt;
	int fd;
	long int ReceivedMessages;
	long int SentMessages;	
	long int RoutingError;
	int RoutingTableIndex;
	
	char ClientHostName[250];
	char ClientHostRealmName[250];
	char ClientIP[30];
	int ClientPort;	
	int isConnected;
	int isCEASuccess;
	int iConnectToClient;
	int AppId;	//Supported Interface
	int iIdleTime;
	int iDWRCount;	
	int ClientIndex;
	
	void *Parent;
	void *HostConfig;
	int TransportType;		//0-TCP	, 1 - SCTP
	unsigned int VendorIds[10];
	int VendorIdsCount;

	unsigned int AuthApplicationIds[10];
	int AuthApplicationIdsCount;

	unsigned int AcctApplicationIds[10];
	int AcctApplicationIdsCount;

	iSupportedVendorApplicationId SupportedVendorApplicationIds[10];
	int SupportedVendorApplicationIdsCount;
	
	pthread_mutex_t ReadLock;	
	int iPort;
	iTCPServerInfo *TCPServerInfo;
	
	int hasPendingBeffer;
	char PendingBuffer[2048];
	int PendingBefferLength;
	long int iRequestNo;
	
	/*Pool Management*/
	int isReleased;
	struct TCPClientInfo* PoolNext;
	int PoolIndex;	
} iTCPClientInfo;

typedef struct TCPRingBuffer
{
	/*Fields Here*/
	char cBuffer[5500];
	int iLength;
	iTCPClientInfo *TCPClientInfo;
	
	/*Pool Management*/
	int isReleased;
	struct TCPRingBuffer* PoolNext;
	int PoolIndex;
} iTCPRingBuffer;
//RingBufferTCPServerImplementation [End]

typedef struct StackObjects
{
	iThreadPool DecodeThreadPool;
	iThreadPool EncodeThreadPool;
	iThreadPool RoutingThreadPool;
	struct ASTDataPtr *StickySessionPtr;
	struct MessagePool *ASTDataPtrPool;
	struct MessagePool *DiamMessagePool;
	struct MessagePool *DiamDecodeMessagePool;
	struct MessagePool *DiamCDataPool;
	struct MessagePool *DiamAVPPool;
	struct MessagePool *QueuePool;	
	struct MessagePool *DiamRoutePool;
	struct MessagePool *TimerPool;
	struct MessagePool *StickySessionPool;
	struct MessagePool *ArrayListPool;	
	struct MessagePool *ArrayElementPool;
	
	struct SessionMessagePool *SessionPool;
	struct RealmInfo RealmTable[100];
	int RealmTableCurrentCount;
	int RealmTableMaxEntries; //100
	pthread_mutex_t RealmTableLock;
	iMemoryUsage TotalMemoryUsage;
	iMemoryUsage PreviousMemoryUsage;
	char PerformanceCounterName[50][100];
	int iPerformanceCounterIndex;	
	
	iQueue DecodeMessageQueue;
	iQueue RoutingMessageQueue;

	iQueue LogQueue;
		
	iQueue AppMessageQueue1;	
	iQueue AppMessageQueue2;
	iQueue AppMessageQueue3;	

		
	#if DIAMDRA
	iHBHInfo HBHDB[10000000];
	int CurrentHBH;
	int MinHBH;
	int MaxHBH;
	pthread_mutex_t HBHLock;	
	#endif
	
	iPCounter ServerCounter[10];
	int ServerCounterCount;
	
	iLogConfig LoggerConfig[5];
	int LoggerCount;	

	//int iLogCat[30];
	iLogCat LogCatInfo[30];
	int LogCatCount;
	
	int iLoggerId;		

	//RingBufferTCPServerImplementation
	struct MessagePool *TCPRingBufferPool;
	struct MessagePool *TCPClientInfoPool;
	
	struct MessagePool *ClientInfoPool;
	
	int iEPoolNoOfReadThreds;
	int iEPoolInit;	
	int iEPollFDCount;
	iEPollData EPollData[MAX_EPOLL_THREADS];	
	
	int ClientInfoCount;
	iClientInfo * ClientInfoHead;
	iClientInfo * ClientInfoCurrent;
	pthread_mutex_t ClientInfoLock;
	
	int SctpClientInfoCount;
	iClientInfo * SctpClientInfoHead;
	iClientInfo * SctpClientInfoCurrent;
	pthread_mutex_t SctpClientInfoLock;	
} iStackObjects;


//NodeType = 1  ... Client ..
//NodeType = 2  ... Proxy/Realy/Agent ..
//NodeType = 3  ... Server ..




typedef struct CCRMini
{
	int CmdCode;
	int Request;
	int ApplicationId;
	unsigned long H2HId;
	unsigned long E2EId;
	unsigned char cSessionId[300];
	unsigned char cOriginHost[300];
	unsigned char cOriginRealm[300];
	unsigned char cDesinationRealm[300];
	unsigned int AuthApplicationId;
	unsigned char cServiceContextId[300];
	int RequestType;
	unsigned int RequestNumber;
	unsigned int OriginStateId;		
} iCCRMini;



typedef struct ExecutionTime
{
	struct timeval before;
	struct timeval after;
	struct timeval lapsed;
} iExecTime; 

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



void init_iMessagePool( iMessagePool ** pMessagePool)
{
	iMessagePool * oMessagePool = NULL;
	
	lib_malloc2(sizeof(iMessagePool), (void **) &oMessagePool);
	lib_malloc2(sizeof(iMessagePtr), (void **) &oMessagePool->FreePool);
	lib_malloc2(sizeof(iMessagePtr), (void **) &oMessagePool->BusyPool);	
	
	oMessagePool->FreePool->Count = 0;
	oMessagePool->BusyPool->Count = 0;
	oMessagePool->PoolSize = 0;

	pthread_mutex_init( &oMessagePool->Lock, NULL);
	pthread_mutex_init( &oMessagePool->FreePool->Lock, NULL);
	pthread_mutex_init( &oMessagePool->BusyPool->Lock, NULL);
	
	*pMessagePool = oMessagePool;
}

//===============================================================================================================
// Session Management

#define SESSION_KEY_BUFFER_SIZE 250

typedef struct SessionBaseRecord  
{
	char cKey[SESSION_KEY_BUFFER_SIZE];
	unsigned int iKey;
	void* Data;	
    //struct SessionBaseRecord *PoolNext;
    struct SessionBaseRecord* SessionNext;
    
	int isReleased;
	struct SessionBaseRecord* NextRecord;
	int PoolIndex;    
    
} iSessionBaseRecord;


typedef struct SessionMessagePtr
{
	iSessionBaseRecord *HeadPtr;
	iSessionBaseRecord *CurrPtr;
	int Count;
	pthread_mutex_t Lock;
	
} iSessionMessagePtr;


typedef struct SessionMessagePool
{
	struct SessionMessagePtr *FreePool;
	iSessionBaseRecord *SBRHeadPtr;
	iSessionBaseRecord *SBRCurrPtr;
	
	int PushCount;
	int PopCount;
	int CurrentSize;
	
	int SMCount;
	int PoolSize;
	pthread_mutex_t Lock;
	
} iSessionMessagePool;


typedef struct HostConfigData
{
	int Id;
	char sHostURI[200];
	char sHostRealm[120];
	int iAcceptUnknownPeer;
	int iValidateSuppApplications;	
	unsigned int uiSuppApp1;
	unsigned int uiSuppApp2;
	unsigned int uiSuppApp3;
	unsigned int uiSuppApp4;
	unsigned int uiSuppApp5;
	unsigned int uiSuppVen1;
	unsigned int uiSuppVen2;
	unsigned int uiSuppVen3;
	unsigned int uiSuppVen4;
	unsigned int uiSuppVen5;
	int isDeleted;
	
	int iInbSecurity;
	char sHostIP[36];
	char sProdName[75];
	int uiAuthAppId1;
	int uiAuthAppId2;
	int uiAuthAppId3;
	int uiAuthAppId4;
	int uiAuthAppId5;
	int uiAcctAppId1;
	int uiAcctAppId2;
	int uiAcctAppId3;
	int uiAcctAppId4;
	int uiAcctAppId5;
	int uiVendId1;
	int uiVendId2;
	int uiVendId3;
	int uiVendId4;
	int uiVendId5;
	
	char sHostName[200];
	int iPortNo;
	int iStarted;
	int fd;
} iHostConfigData;

typedef struct PeerConfigDataProxy
{
	int PeerConfigData_Id;
	iSctpStreamBuffer SctpStreamBuffer[100];
} iPeerConfigDataProxy;

typedef struct PeerConfigData
{
	int Id;
	char sPeerURI[200];
	char sPeerRealm[120];
	char sIPAddress[120];
	unsigned int uiSuppAppVendorId1;
	unsigned int uiSuppApp1;
	unsigned int uiSuppAppVendorId2;
	unsigned int uiSuppApp2;
	unsigned int uiSuppAppVendorId3;
	unsigned int uiSuppApp3;
	unsigned int uiSuppAppVendorId4;
	unsigned int uiSuppApp4;
	unsigned int uiSuppAppVendorId5;
	unsigned int uiSuppApp5;
	int isDeleted;
	int isActive;
	int HostEntryId;
	int uiAuthAppId1;
	int uiAuthAppId2;
	int uiAuthAppId3;
	int uiAuthAppId4;
	int uiAuthAppId5;
	int uiAcctAppId1;
	int uiAcctAppId2;
	int uiAcctAppId3;
	int uiAcctAppId4;
	int uiAcctAppId5;
	int uiVendId1;
	int uiVendId2;
	int uiVendId3;
	int uiVendId4;
	int uiVendId5;	
	
	int iFd;
	int iConnected;
	int DoNotConnect;
	int isCERSuccess;
	int iIdleTime;
	int iDWRCount;
	
	char sPeerName[200];
	int iPortNo;
	int iStarted;	
	long int iResponseNo;
	int iTransportType; //0 - TCP, 1 - SCTP
} iPeerConfigData;

typedef struct SessionInfo
{
	char UserName[100];
	char Password[100];
	char GUID[40];
} iSessionInfo;

typedef struct SocketReadThread
{
	int efd;
	pthread_t thread_id;
	int isBusy;	
	sem_t sem_lock;
	int Index;
	int iTransportType; //0-TCP, 1 - SCTP
	
	iClientInfo * ClientInfo;
	iTCPClientInfo * TCPClientInfo;
	struct epoll_event *epl_events;
		
	struct SocketReadThread * Next;
} iSocketReadThread;

typedef struct PeerInfoList
{
	iPeerConfigData * Peers[40];
	int PeerServerCount;	
} iPeerInfoList;

typedef struct RealmRow
{
	char sRealmName[250];
	iPeerConfigData * PeerConfigData[40];
	int PeerIndexCount;
} iRealmRow;

/*
	Diameter Core 23-06-2018
*/
typedef struct ApplicationServer
{
	iSessionInfo Sessions[25];
	int SessionCount;
	int WebPort;
	iMessagePool *WebClientInfoPool;
	void *WebRequestQueue;
	int iCatLog;
	
	//stated host-info
	iHostConfigData StartedHosts[10];
	int StartedHostsCount;
	
	//This is the Peer Table
	iPeerConfigData PeerConfigData[40];
	int PeerServerCount;
	
	//Realm Table ( contains peer indexes)
	iRealmRow RealmRows[40];	//Size Of Peer Table
	int RealmRowCount;

	/*SCTP*/	
	pthread_mutex_t  SocketReadThreadLock;
	iSocketReadThread * SocketReadThreadRoot;
	iSocketReadThread * SocketReadThreadCurrent;
	int SocketReadThreadCount;
	
	pthread_mutex_t  TCPSocketReadThreadLock;
	iSocketReadThread * TCPSocketReadThreadRoot;
	iSocketReadThread * TCPSocketReadThreadCurrent;
	int TCPSocketReadThreadCount;	
} iApplicationServer;

iApplicationServer * oApplicationServer = NULL; 

//-------------------------------------------------------------------------------------------------------------------------




#define MAX_RECORDS 10000000


typedef struct MemoryRecord
{
	struct MemoryRecord* PoolNext;
	int PoolIndex;
	int isReleased;
	
	//void * Data;
	uint8_t * Data;
} iMemoryRecord;


typedef struct MemoryBlock
{
	char Name[100];
	int Size;
	int InitCount;
	int IncrCount;	
	
	struct MemoryRecord *HeadPtr;
	struct MemoryRecord *CurrPtr;	

	long int TotalCount;	
	int Count;
	pthread_mutex_t Lock;	
} iMemoryBlock;



typedef struct PersistantRecord
{
	struct MemoryRecord *MemoryRecordInfo;
} iPersistantRecord;


typedef struct MemoryManagement
{
	int MemoryBlockCount;
	struct MemoryBlock MemoryBlocks[10];
	struct PersistantRecord PRecord[MAX_RECORDS];
	
	long PRecordCount;
	pthread_mutex_t PRecordLock;		
} iMemoryManagement;

iMemoryManagement objMemoryManagement;


long __storeRecord(struct MemoryRecord *mRecord)
{
	long iPRecordCount;
	pthread_mutex_lock( &objMemoryManagement.PRecordLock );
	
	(objMemoryManagement.PRecordCount > MAX_RECORDS) ? objMemoryManagement.PRecordCount = 0 : 0 ;

	iPRecordCount = objMemoryManagement.PRecordCount;
	
	objMemoryManagement.PRecord[iPRecordCount].MemoryRecordInfo = mRecord;

	objMemoryManagement.PRecordCount++;	
	pthread_mutex_unlock( &objMemoryManagement.PRecordLock );	
	
	return iPRecordCount;
}

struct MemoryRecord * __getRecord(long index)
{
	if( index > 0 && index < MAX_RECORDS)
	{
		struct MemoryRecord *mr = NULL;
		
		pthread_mutex_lock( &objMemoryManagement.PRecordLock );
		
		mr = objMemoryManagement.PRecord[index].MemoryRecordInfo;
		
		objMemoryManagement.PRecord[index].MemoryRecordInfo = NULL;
		
		pthread_mutex_unlock( &objMemoryManagement.PRecordLock );
		
		return mr;
	}
	
	return NULL;	
}


void __getRecord2( long index, struct MemoryRecord *mRecord)
{
	if( index > 0 && index < MAX_RECORDS)
	{
		pthread_mutex_lock( &objMemoryManagement.PRecordLock );
		mRecord = objMemoryManagement.PRecord[index].MemoryRecordInfo;
		objMemoryManagement.PRecord[index].MemoryRecordInfo = NULL;
		pthread_mutex_unlock( &objMemoryManagement.PRecordLock );		
	}
}

void __getRecord3( long index, struct MemoryRecord ** mRecord)
{
	if( index > 0 && index < MAX_RECORDS)
	{
		pthread_mutex_lock( &objMemoryManagement.PRecordLock );
		*mRecord = objMemoryManagement.PRecord[index].MemoryRecordInfo;
		objMemoryManagement.PRecord[index].MemoryRecordInfo = NULL;
		pthread_mutex_unlock( &objMemoryManagement.PRecordLock );		
	}
}

int __registerMemoryBlock( int iMemorySize, int initCount, int incrCount, char *name)
{
	objMemoryManagement.MemoryBlockCount++;
	
	memset( &objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].Name, 0, sizeof(objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].Name));
	
	strcpy( objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].Name, name);
	
	objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].Size = iMemorySize;
	objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].InitCount = initCount;	
	objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].IncrCount = incrCount;		
	objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].Count = 0;
	objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].TotalCount = 0;
	
	pthread_mutex_init( &objMemoryManagement.MemoryBlocks[objMemoryManagement.MemoryBlockCount].Lock, NULL);
	
	return objMemoryManagement.MemoryBlockCount;
}

void __printMemoryBlockInfo( int blockId)
{
	printf("-----------------------------------------------------------------------\n");
	printf("Name = %s, TotalCount = %ld, Count = %d\n", 
		objMemoryManagement.MemoryBlocks[blockId].Name, 
		objMemoryManagement.MemoryBlocks[blockId].TotalCount,
		objMemoryManagement.MemoryBlocks[blockId].Count);
		
	APP_LOG( LOG_LEVEL_DEBUG, __FILE__, __LINE__, 
		"Name = %s, TotalCount = %ld, Count = %d |%s", 
		objMemoryManagement.MemoryBlocks[blockId].Name, 
		objMemoryManagement.MemoryBlocks[blockId].TotalCount,
		objMemoryManagement.MemoryBlocks[blockId].Count , __FUNCTION__);		
		
	printf("-----------------------------------------------------------------------\n");
}


void __addToMemoryPool( int blockId, struct MemoryRecord *imr, int bInLockedMode)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &objMemoryManagement.MemoryBlocks[blockId].Lock );
	}
	
	//if( objMemoryManagement.MemoryBlocks[blockId].HeadPtr == NULL)
	if(!objMemoryManagement.MemoryBlocks[blockId].HeadPtr)	
	{
		objMemoryManagement.MemoryBlocks[blockId].HeadPtr = objMemoryManagement.MemoryBlocks[blockId].CurrPtr = imr;
	}
	else
	{
		objMemoryManagement.MemoryBlocks[blockId].CurrPtr->PoolNext = imr;
	}

	objMemoryManagement.MemoryBlocks[blockId].CurrPtr = imr;
	objMemoryManagement.MemoryBlocks[blockId].Count++;	
	
	if(bInLockedMode)
	{
		pthread_mutex_unlock( &objMemoryManagement.MemoryBlocks[blockId].Lock );
	}	
}



void __aquireMemory( int blockId, int incrMemory)
{
	int _blockSize = objMemoryManagement.MemoryBlocks[blockId].InitCount;
	
	if( incrMemory == 1)
	{
		_blockSize = objMemoryManagement.MemoryBlocks[blockId].IncrCount;
	}

	int i = 0;
	
	for( i = 0; i < _blockSize; i++ )
	{
		struct MemoryRecord * imr = NULL;
		
		lib_malloc2( sizeof(struct MemoryRecord), (void **) &imr);
		
		imr->PoolNext = NULL;
		imr->PoolIndex = (objMemoryManagement.MemoryBlocks[blockId].TotalCount + i);
		imr->isReleased = 0;
		//imr->Data = NULL;
		//(void **) 
		lib_malloc2( objMemoryManagement.MemoryBlocks[blockId].Size, (void **) &imr->Data);
		
		__addToMemoryPool( blockId, imr, 0);
	}
	
	objMemoryManagement.MemoryBlocks[blockId].TotalCount += _blockSize;
}


void __initalizeMemory()
{
	int i = 0;
	
	for( i = 0; i <  (objMemoryManagement.MemoryBlockCount+1); i++ )
	{
		__aquireMemory( i, 0);
	}

	objMemoryManagement.PRecordCount = 0;
	pthread_mutex_init( &objMemoryManagement.PRecordLock, NULL);	
	
	for( i = 0; i < MAX_RECORDS; i++)
	{
		objMemoryManagement.PRecord[i].MemoryRecordInfo = NULL;
	}
	

/*	
	printf("=====Memory Created Sucessfully==============================================================================\n");
	
	for( i = 0; i <  (objMemoryManagement.MemoryBlockCount+1); i++ )
	{
		printf("Memory Info BlockId[%d] Count[%d] EachSize[%d]\n", i, objMemoryManagement.MemoryBlocks[i].Count, objMemoryManagement.MemoryBlocks[i].Size);
	}
	
	printf("=====Memory Created Sucessfully==============================================================================\n");	
	
	printf("%s End\n", __FUNCTION__);		
*/
 
}


struct MemoryRecord *__allocateMemory( int blockId)
{
	struct MemoryRecord* oMemoryRecord = NULL;

	pthread_mutex_lock( &objMemoryManagement.MemoryBlocks[blockId].Lock );
	
	oMemoryRecord = objMemoryManagement.MemoryBlocks[blockId].HeadPtr;
	
	//if( oMemoryRecord == NULL) 
	if(!oMemoryRecord) 	
	{
		__aquireMemory( blockId, 1);
		oMemoryRecord = objMemoryManagement.MemoryBlocks[blockId].HeadPtr;
	}
	
	//if( oMemoryRecord != NULL)
	if(oMemoryRecord)	
	{
		objMemoryManagement.MemoryBlocks[blockId].HeadPtr = oMemoryRecord->PoolNext;
		oMemoryRecord->PoolNext = NULL;
	}
		
	oMemoryRecord->PoolNext = NULL;	
	oMemoryRecord->isReleased = 0;
	objMemoryManagement.MemoryBlocks[blockId].Count--;
	
	pthread_mutex_unlock( &objMemoryManagement.MemoryBlocks[blockId].Lock );
	
	return oMemoryRecord;
}

void __releaseMemory(int blockId, struct MemoryRecord *mRecord)
{
	if( mRecord->isReleased == 0)
	{
		mRecord->isReleased = 1;
		__addToMemoryPool( blockId, mRecord, 1);
	}
}


//-------------------------------------------------------------------------------------------------------------------------




typedef struct StackTimerRecord
{
	long startTime;
	long endTime;
	long recordId;
	struct MemoryRecord *mRecord;
	int isActive;
	int timerCalled;
	
	struct StackTimerRecord *PoolNext;
	
} iStackTimerRecord;

typedef struct StackTimer
{
	struct StackTimerRecord *HeadPtr;
	struct StackTimerRecord *CurrPtr;	

	struct StackTimerRecord *TimedOutHeadPtr;
	struct StackTimerRecord *TimedOutCurrPtr;	
	
	pthread_mutex_t TimedOutLock;	
	pthread_mutex_t Lock;
	int MemoryBlockId;	
	
	long Count;
	
	long InMessages;
	long OutMessages;
	long TimedOutMessages;
	
} iStackTimer;

//600 seconds ., (10 Minutes)
#define EVENT_TIMER_MAXSECONDS  600

typedef struct AObjectPointer
{
	void * Data;
	int ClearTimeOut;	
	struct AObjectPointer * Next;
	
	struct AObjectPointer* PoolNext;
	int PoolIndex;
	int isReleased;
} IAObjectPointer;


typedef struct ATimerNode
{
	int Index;
    IAObjectPointer* Head;
	IAObjectPointer* Current;
	pthread_mutex_t Lock;
} IATimerNode;

typedef struct EventTimerObjects
{
	int CIndex;
	IATimerNode *TNodes[EVENT_TIMER_MAXSECONDS];
    
	IAObjectPointer* RootHead;
	IAObjectPointer* RootCurrent;
	pthread_mutex_t RootLock;
	
	int MemoryBlockId;
} IEventTimerObjects;

typedef struct DRARoutingInfo
{
	unsigned long long int Min;
	unsigned long long int Max;
	int PrimaryNodeId;
	int FallBackNodeId;
	
	struct InterfaceEndPoint IEndPoint[2];
	int EndPointIndex;
} iDRARoutingInfo;

typedef struct VendorSpecificAuthApplicationId
{
	int iVendorId;
	int iAuthApplicationId;	
} iVendorSpecificAuthApplicationId;

typedef struct ServiceContextRouting
{
	int ServiceContextRoutingAppId;
	char DestinationHostName[200];
	char ServiceContext[200];	
} iServiceContextRouting;

typedef struct StackConfig
{
	char HostName[250];
	char HostRealmName[250];
	char ProductName[250];
	char IP[30];
	char IP2[30];
	char IP3[30];
	char IP4[30];
	char IP5[30];
	int EnableServiceContextBasedRouting;
	iServiceContextRouting ServiceContextRoutingInfo[10];
	int ServiceContextRoutingCount;
	int CheckSocketBeforeSend;
	int MultiHome;
	int MultiHomeAndRequiredBind;	
	int MultiHomeIpCount;
	int SctpEnableStreamInfo;	
	int DecodeThreadPoolCount;
	int EncodeThreadPoolCount;
	int RoutingThreadCount;
	int Port;
	int HostTransportType;
	int HostPort[10];
	int HostPortCount;
	int iAuthApplicationId[10];
	int iAuthApplicationIdCount;
	int iAcctApplicationId[10];
	int iAcctApplicationIdCount;	
	iVendorSpecificAuthApplicationId VendorSpecificAuthApplicationId[10];
	int iVendorSpecificAuthApplicationIdCount;
	int iCatLog_CoreSockets;
	int iCatLog_CoreDecode;
	int iCatLog_CoreRouting;
	int NoOfPeers;
	int iLoadedPeerConfigCount;
	int VendorId;
	int NodeType; 
	int NoOfAppSupported ;
	int WatchDogRequestInterval;
	int SupportedAppIds[10];
	struct PeerInfo Peers[36];
	struct InterfaceEndPoint IEndPoint[36];	//Should be Equel with peer info (Destination Realm)
	int EndPointIndex;
	
	struct InterfaceEndPoint HostNameIEndPoint[36];	//Should be Equel with peer info (Destination Host)
	int HostNameEndPointIndex;
	
	struct InterfaceEndPoint HRIEndPoint[36];	//Should be Equel with peer info (Destination Host + Realm)
	int HREndPointIndex;
	
	struct InterfaceEndPoint AppIEndPoint[36];	//Should be Equel with peer info (ApplicationId)
	int AppEndPointIndex;
	
	//Known Clients
	//Accept Only From Known Clients will be one of the feature
	int AcceptUnknownClinet;
	//0 - Yes
	//1 - No
	int NoOfClients;
	struct ClientInfo Clients[36];
	int ReConnectSeconds;
	int MessageRoutingMode;
	
	iDRARoutingInfo IMSIRouting[5];
	iDRARoutingInfo MSISDNRouting[5];
	iDRARoutingInfo IMEIRouting[5];
	
	struct InterfaceEndPoint PeerEndPoint[36];
	int HashCharLength;
	int DRARoutingModule;
	
	char SessionIdFormat[200];		
	char SessionIdPrefix[100];
	
	char MAC_ADDRESS_KEY[512];	
	char LICENSE_FILE[249];
	int LicenseFileFound;
	int ConfigPort;
	int SessionIdRotNo;
	unsigned long SessionIdSeg1StartNo;
	unsigned long SessionIdSeg2StartNo;
	unsigned long HBHId;
	unsigned long E2EId;		

	//struct StackTimer STimer;
	IEventTimerObjects *oEventTimerObjects;
	
	int LoggerMemoryBlockId;

	char SimulateDestinationRelam[100];	
	int EnablePerformaceThread;
	pthread_mutex_t SessionIdLock;
	pthread_mutex_t HBHLock;
	int QueueMode;
			
} iStackConfig;

struct StackConfig objStackConfig;
struct StackObjects objStackObjects;

int registerPerformanceCounter( char *name)
{
	if( objStackObjects.iPerformanceCounterIndex < 50)
	{
		//printf("registerPerformanceCounter=%s\n", name);
		
		objStackObjects.iPerformanceCounterIndex++;
				
		//strcpy( objStackObjects.PerformanceCounterName[objStackObjects.iPerformanceCounterIndex], name);
		memcpy( objStackObjects.PerformanceCounterName[objStackObjects.iPerformanceCounterIndex], name, 100);
		return (objStackObjects.iPerformanceCounterIndex);
	}
	return -1;
}


long int* getPerformanceCounterItem(int i)
{
	long int *cItem = NULL;
	
	switch(i)
	{
		case 0:
			cItem = &objStackObjects.TotalMemoryUsage.c001;
			break;
		case 1:
			cItem = &objStackObjects.TotalMemoryUsage.c002;
			break;
		case 2:
			cItem = &objStackObjects.TotalMemoryUsage.c003;
			break;
		case 3:
			cItem = &objStackObjects.TotalMemoryUsage.c004;
			break;
		case 4:
			cItem = &objStackObjects.TotalMemoryUsage.c005;
			break;
		case 5:
			cItem = &objStackObjects.TotalMemoryUsage.c006;
			break;
		case 6:
			cItem = &objStackObjects.TotalMemoryUsage.c007;
			break;
		case 7:
			cItem = &objStackObjects.TotalMemoryUsage.c008;
			break;
		case 8:
			cItem = &objStackObjects.TotalMemoryUsage.c009;
			break;
		case 9:
			cItem = &objStackObjects.TotalMemoryUsage.c010;
			break;
		case 10:
			cItem = &objStackObjects.TotalMemoryUsage.c011;
			break;
		case 11:
			cItem = &objStackObjects.TotalMemoryUsage.c012;
			break;
		case 12:
			cItem = &objStackObjects.TotalMemoryUsage.c013;
			break;
		case 13:
			cItem = &objStackObjects.TotalMemoryUsage.c014;
			break;
		case 14:
			cItem = &objStackObjects.TotalMemoryUsage.c015;
			break;
		case 15:
			cItem = &objStackObjects.TotalMemoryUsage.c016;
			break;
		case 16:
			cItem = &objStackObjects.TotalMemoryUsage.c017;
			break;
		case 17:
			cItem = &objStackObjects.TotalMemoryUsage.c018;
			break;
		case 18:
			cItem = &objStackObjects.TotalMemoryUsage.c019;
			break;
		case 19:
			cItem = &objStackObjects.TotalMemoryUsage.c020;
			break;
		case 20:
			cItem = &objStackObjects.TotalMemoryUsage.c021;
			break;
		case 21:
			cItem = &objStackObjects.TotalMemoryUsage.c022;
			break;
		case 22:
			cItem = &objStackObjects.TotalMemoryUsage.c023;
			break;
		case 23:
			cItem = &objStackObjects.TotalMemoryUsage.c024;
			break;
		case 24:
			cItem = &objStackObjects.TotalMemoryUsage.c025;
			break;
		case 25:
			cItem = &objStackObjects.TotalMemoryUsage.c026;
			break;
		case 26:
			cItem = &objStackObjects.TotalMemoryUsage.c027;
			break;
		case 27:
			cItem = &objStackObjects.TotalMemoryUsage.c028;
			break;
		case 28:
			cItem = &objStackObjects.TotalMemoryUsage.c029;
			break;
		case 29:
			cItem = &objStackObjects.TotalMemoryUsage.c030;
			break;
		case 30:
			cItem = &objStackObjects.TotalMemoryUsage.c031;
			break;
		case 31:
			cItem = &objStackObjects.TotalMemoryUsage.c032;
			break;
		case 32:
			cItem = &objStackObjects.TotalMemoryUsage.c033;
			break;
		case 33:
			cItem = &objStackObjects.TotalMemoryUsage.c034;
			break;
		case 34:
			cItem = &objStackObjects.TotalMemoryUsage.c035;
			break;
		case 35:
			cItem = &objStackObjects.TotalMemoryUsage.c036;
			break;
		case 36:
			cItem = &objStackObjects.TotalMemoryUsage.c037;
			break;
		case 37:
			cItem = &objStackObjects.TotalMemoryUsage.c038;
			break;
		case 38:
			cItem = &objStackObjects.TotalMemoryUsage.c039;
			break;
		case 39:
			cItem = &objStackObjects.TotalMemoryUsage.c040;
			break;
		case 40:
			cItem = &objStackObjects.TotalMemoryUsage.c041;
			break;
		case 41:
			cItem = &objStackObjects.TotalMemoryUsage.c042;
			break;
		case 42:
			cItem = &objStackObjects.TotalMemoryUsage.c043;
			break;
		case 43:
			cItem = &objStackObjects.TotalMemoryUsage.c044;
			break;
		case 44:
			cItem = &objStackObjects.TotalMemoryUsage.c045;
			break;
		case 45:
			cItem = &objStackObjects.TotalMemoryUsage.c046;
			break;
		case 46:
			cItem = &objStackObjects.TotalMemoryUsage.c047;
			break;
		case 47:
			cItem = &objStackObjects.TotalMemoryUsage.c048;
			break;
		case 48:
			cItem = &objStackObjects.TotalMemoryUsage.c049;
			break;
		case 49:
			cItem = &objStackObjects.TotalMemoryUsage.c050;
			break;
		default:
			break;
	}
	

	return cItem;
}

void incrPerformanceCounter(int i)
{
	long int *cItem = getPerformanceCounterItem( i);
	
	//if( cItem != NULL)
	if(cItem)	
	{
		if( *cItem > 2147483646)
		{
			*cItem = 0;
		}	
		else
		{
			//printf("getPerformanceCounterItem++ %d %ld\n", i, *cItem);
			(*cItem)++;
		}
	}
}

//----------------------------------------------------------------------------------------------------------------------------
void __si_createLicenseKey( char * macAddress)
{
	struct timeval tv;
	struct timezone tzone;
	gettimeofday( &tv, &tzone);
	struct tm *timeinfo = gmtime( &tv.tv_sec);	
	
	char keyLen[20];
	
	keyLen[2] = macAddress[0];
	keyLen[4] = macAddress[1];
	keyLen[6] = macAddress[2];
	keyLen[8] = macAddress[3];
	keyLen[10] = macAddress[4];
	keyLen[12] = macAddress[5];
	
	keyLen[0] = timeinfo->tm_sec;
	keyLen[1] = (timeinfo->tm_sec + 5);	
	keyLen[3] = timeinfo->tm_sec + macAddress[3];
	keyLen[5] = timeinfo->tm_sec + macAddress[5];
	keyLen[7] = timeinfo->tm_sec + macAddress[2];
	keyLen[9] = timeinfo->tm_sec + macAddress[1];
	keyLen[11] = timeinfo->tm_sec + 11;
	keyLen[13] = timeinfo->tm_sec + 23;
	keyLen[14] = timeinfo->tm_sec + 34;
	keyLen[15] = timeinfo->tm_sec + 45;
	keyLen[16] = timeinfo->tm_sec + 56;
	keyLen[17] = timeinfo->tm_sec + 67;
	keyLen[18] = timeinfo->tm_sec + 78;
	keyLen[19] = 0;
	
	if( ( keyLen[0] % 2) == 1)
	{
		//printf( "MOD(1)\n");
		keyLen[2] = macAddress[5];
		keyLen[4] = macAddress[4];
		keyLen[6] = macAddress[3];
		keyLen[8] = macAddress[2];
		keyLen[10] = macAddress[1];
		keyLen[12] = macAddress[0];		
	}
	else
	{
		//printf( "MOD(0)\n");
	}
	
	/*
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
		macAddress[0] & 0xFF,
		macAddress[1] & 0xFF,
		macAddress[2] & 0xFF,
		macAddress[3] & 0xFF,
		macAddress[4] & 0xFF,
		macAddress[5] & 0xFF
	);
	*/
	/*
	int i = 0;
	for( i = 0; i < 20; i++)
	{
		if( i > 0){
			printf("-");
		}
		printf("%02x", keyLen[i] & 0xFF);
	}
	
	printf("\n");
	*/
	
	char sEncoded[200];
	memset( &sEncoded, 0, sizeof(sEncoded));
	
	Base64encode( sEncoded, keyLen, 20);
	//printf( "sEncoded = %s\n", sEncoded);
	
	char sCorrupted[400];
	memset( &sCorrupted, 0, sizeof(sCorrupted));	

	static const char xx[] =
    "wA4B5C2D1E5FhGlHpIpJdKgLaMtNyOrPwQrRsSqTqUdVaWqXcYdZabcdefghijklmnopqrstuvwxyz0123456ww7892+/wA4B5C2D1E5FhGlHpIpJdKgLaMtNyOrPwQrRsSqTqUdVaWqXcYdZabcdefghijklmnopqrstuvwxyz0123456ww7892+/wA4B5C2D1E5FhGlHpIpJdKgLaMtNyOrPwQrRsSqTqUdVaWqXcYdZabcdefghijklmnopqrstuvwxyz0123456ww7892+/uvwxyz0123456ww7892+/wA4B5C2D1E5FhGlHpIpJdKgLaMtNyOrPwQrRsSqTqUdVaWqXcYdZabcdefghijklmnopqrstuvwxyz0123456ww7892+/";
	
	int j = 0;
	int i = 0;
	
	for( i = 0; i < strlen(sEncoded); i++)
	{
		sCorrupted[j] = sEncoded[i];
		j++;
		sCorrupted[j] = xx[ timeinfo->tm_sec + i];
		j++;		
	}
	sCorrupted[j-1] = '=';
	
	printf( "%s\n", sCorrupted);
}

void __si_retrieveMACAddressFromKey( char * base64, char * macAddress)
{
	int len = strlen( base64);
	if( (len % 2) == 0)
	{
		//printf("valid length\n");
		char sEncoded[200];
		memset( &sEncoded, 0, sizeof(sEncoded));		
		
		int i = 0;
		int j = 0;
		
		for( i = 0; i < len; i++)
		{
			if( (i % 2) == 0)
			{	
				sEncoded[j] = base64[i];
				j++;
			}
		}
		
		//printf("O=%s\n", sEncoded);
		
		char keyLen[20];
		memset( keyLen, 0, sizeof(keyLen));
		
		Base64decode( keyLen, sEncoded);
		
		/*
		i = 0;
		for( i = 0; i < 20; i++)
		{
			if( i > 0){
				printf("-");
			}
			printf("%02x", keyLen[i] & 0xFF);
		}
		printf("\n");
		*/
		
		//char macAddress[6];
		
		if( ( keyLen[0] % 2) == 1)
		{
			macAddress[5] = keyLen[2];
			macAddress[4] = keyLen[4];
			macAddress[3] = keyLen[6];
			macAddress[2] = keyLen[8];
			macAddress[1] = keyLen[10];
			macAddress[0] = keyLen[12];
		}
		else
		{
			macAddress[0] = keyLen[2];
			macAddress[1] = keyLen[4];
			macAddress[2] = keyLen[6];
			macAddress[3] = keyLen[8];
			macAddress[4] = keyLen[10];
			macAddress[5] = keyLen[12];			
		}
		
		/*
		printf("__si_retrieveLicenseKey %02x:%02x:%02x:%02x:%02x:%02x\n", 
			macAddress[0] & 0xFF,
			macAddress[1] & 0xFF,
			macAddress[2] & 0xFF,
			macAddress[3] & 0xFF,
			macAddress[4] & 0xFF,
			macAddress[5] & 0xFF
		);	
		*/	
	}
	else
	{
		printf("invalid encoded mac-address length\n");
	}
}

int __si_ValidateMACAddress( char * macAddress)
{
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

	int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	if (sock <= 0) 
	{ 
		printf( "socket creation failed for MAC Validation | (%d) - %s \n", errno, strerror(errno));
		exit(0);
	};
	
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
	
    if ( ioctl(sock, SIOCGIFCONF, &ifc) == -1) 
	{ 
		printf( "ioctl failed for MAC Validation | (%d) - %s \n", errno, strerror(errno));
		exit(0);
	}	
	
	struct ifreq * it = ifc.ifc_req;
    const struct ifreq * const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	
	for (; it != end; ++it) 
	{
		strcpy(ifr.ifr_name, it->ifr_name);
		//printf( "%s \n", it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) 
		{
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) 
			{
				if (ioctl( sock, SIOCGIFHWADDR, &ifr) == 0) 
				{
					/*
					printf( "address : %02x:%02x:%02x:%02x:%02x:%02x \n", 
						ifr.ifr_hwaddr.sa_data[0] & 0xFF,
						ifr.ifr_hwaddr.sa_data[1] & 0xFF,
						ifr.ifr_hwaddr.sa_data[2] & 0xFF,
						ifr.ifr_hwaddr.sa_data[3] & 0xFF,
						ifr.ifr_hwaddr.sa_data[4] & 0xFF,
						ifr.ifr_hwaddr.sa_data[5] & 0xFF
					);
					
					printf( "address : %02x:%02x:%02x:%02x:%02x:%02x \n", 
						macAddress[0] & 0xFF,
						macAddress[1] & 0xFF,
						macAddress[2] & 0xFF,
						macAddress[3] & 0xFF,
						macAddress[4] & 0xFF,
						macAddress[5] & 0xFF
					);
					*/
					
					if( ifr.ifr_hwaddr.sa_data[0] == macAddress[0] && ifr.ifr_hwaddr.sa_data[1] == macAddress[1] && 
						ifr.ifr_hwaddr.sa_data[2] == macAddress[2] && ifr.ifr_hwaddr.sa_data[3] == macAddress[3] && 
						ifr.ifr_hwaddr.sa_data[4] == macAddress[4] && ifr.ifr_hwaddr.sa_data[5] == macAddress[5])
					{
						return 1;
					}
				}
			}
		}
	}
	
	return 0;
}


void __coreValidateMAC()
{
	//int __si_ValidateMACAddress( char * macAddress)
}

//----------------------------------------------------------------------------------------------------------------------------
// Timer Functions





void __addToStackTimer(struct StackTimerRecord *stRecord)
{

}


void __addToStackTimerTimeout(struct StackTimerRecord *stRecord)
{

}

IAObjectPointer* allocateIAObjectPointer();
void releaseIAObjectPointer( IAObjectPointer* oMsg);


void * __eventTimerInsertItem( IATimerNode *tTimerNode, void * pPointer)
{
	pthread_mutex_lock( &tTimerNode->Lock);
	
	IAObjectPointer * iap = (IAObjectPointer *)allocateIAObjectPointer();
	
	//if( tTimerNode->Head == NULL)
	if(!tTimerNode->Head)	
	{
		tTimerNode->Head = iap;
		tTimerNode->Head->Data = pPointer;
		tTimerNode->Current = tTimerNode->Head;
	}
	else
	{
		tTimerNode->Current->Next = iap;
		tTimerNode->Current->Next->Data = pPointer;
		tTimerNode->Current = tTimerNode->Current->Next;
	}
	
	pthread_mutex_unlock( &tTimerNode->Lock);
	return iap;
}

void * __eventTimerInsert( int iSeconds, void * pPointer, long *lSts)
{
	if(iSeconds > EVENT_TIMER_MAXSECONDS)
	{	
		*lSts = -1;
		return NULL;
	}
	
	long insertAt = objStackConfig.oEventTimerObjects->CIndex + iSeconds;

	if( insertAt >= EVENT_TIMER_MAXSECONDS)
	{	
		*lSts = insertAt - EVENT_TIMER_MAXSECONDS;
		return NULL;
	}
	
	if( insertAt < 0)
	{
		*lSts = -2;
		return NULL;
	}
	
	if( insertAt > EVENT_TIMER_MAXSECONDS)
	{
		*lSts = -3;
		return NULL;
	}
	
	void * refObj = __eventTimerInsertItem( objStackConfig.oEventTimerObjects->TNodes[ insertAt], pPointer);
	
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Timer Inserted for seconds[%d] insertAt[%ld] pPointer[%p]", iSeconds, insertAt, pPointer);
	
	*lSts = insertAt;
	
	return refObj;
}

void __setTimeOut( long lRecordId, int timeInSeconds)
{
	
}


void __clearTimeOut( long lRecordId)
{
	
} 

void * __setObjTimeOut( void * vObject, int timeInSeconds, long *lSts)
{
	return __eventTimerInsert( timeInSeconds, vObject, lSts);
}


void __setObjTimeOut2( void * vObject, int timeInSeconds, long *lSts, void **timerPtr)
{
	*timerPtr = __eventTimerInsert( timeInSeconds, vObject, lSts);
}

void __clearObjTimeOut( void * tPtr)
{
	//if( tPtr != NULL)
	if(tPtr)	
	{
		//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "__clearObjTimeOut for pPointer[%p] CIndex[%d]", ((IAObjectPointer*)tPtr)->Data, objStackConfig.oEventTimerObjects->CIndex);	
		
		((IAObjectPointer*)tPtr)->ClearTimeOut = 1;
		((IAObjectPointer*)tPtr)->Data = NULL;
	}
}


void __eventTimerMove()
{
	pthread_mutex_lock( &objStackConfig.oEventTimerObjects->RootLock);
	pthread_mutex_lock( &objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Lock);
	
	//if( objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Head != NULL)
	if( objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Head )	
	{
		//if( objStackConfig.oEventTimerObjects->RootHead == NULL)
		if(!objStackConfig.oEventTimerObjects->RootHead)	
		{
			objStackConfig.oEventTimerObjects->RootHead = objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Head;
			objStackConfig.oEventTimerObjects->RootCurrent = objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Current;
		}
		else
		{
			objStackConfig.oEventTimerObjects->RootCurrent->Next = objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Head;
			objStackConfig.oEventTimerObjects->RootCurrent = objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Current;
		}
	}
	
	objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Head = NULL;
	objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Current = NULL;
	
	pthread_mutex_unlock( &objStackConfig.oEventTimerObjects->TNodes[ objStackConfig.oEventTimerObjects->CIndex]->Lock);
	pthread_mutex_unlock( &objStackConfig.oEventTimerObjects->RootLock);
}

void *appTimerThread(void* args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	while(1)
	{
		__eventTimerMove();
		
		objStackConfig.oEventTimerObjects->CIndex++;
		
		if( objStackConfig.oEventTimerObjects->CIndex >= (EVENT_TIMER_MAXSECONDS))
			objStackConfig.oEventTimerObjects->CIndex = 0;
		
		usleep(999999);
	}		
	return NULL;	
}


int (*pServerTimeOutCallbackHandler)( long lRecordId) = NULL;
int (*pServerTimeOutCallbackHandler2)( void* dObj) = NULL;

void *appTimerCallbackThread(void* args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	while(1)
	{
		IAObjectPointer* oRootHead = NULL;
		
		pthread_mutex_lock( &objStackConfig.oEventTimerObjects->RootLock);
		
		//if(objStackConfig.oEventTimerObjects->RootHead != NULL)
		if(objStackConfig.oEventTimerObjects->RootHead)	
		{
			oRootHead = objStackConfig.oEventTimerObjects->RootHead;
			objStackConfig.oEventTimerObjects->RootHead = objStackConfig.oEventTimerObjects->RootCurrent = NULL;
		}
		
		pthread_mutex_unlock( &objStackConfig.oEventTimerObjects->RootLock);
		
		//if( oRootHead != NULL)
		if(oRootHead)	
		{
			//while( oRootHead != NULL)
			while(oRootHead)	
			{
				IAObjectPointer* e1 = oRootHead;
				oRootHead = e1->Next;
				e1->Next = NULL;
				
				//if( pServerTimeOutCallbackHandler2 != NULL && e1->ClearTimeOut == 0)
				if(pServerTimeOutCallbackHandler2 && e1->ClearTimeOut == 0)	
				{
					if( e1->Data != NULL) 
					{
						//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Calling TimeOutCallBack for pPointer[%p] CIndex[%d]", e1->Data, objStackConfig.oEventTimerObjects->CIndex);	
						pServerTimeOutCallbackHandler2( e1->Data);
					}	
				}
				
				releaseIAObjectPointer(e1 );
			}
		}
		
		usleep(99999);	// 1/10 second
	}
	return NULL;
}


//----------------------------------------------------------------------------------------------------------------------------

int initPCounter(char *name, char *ipAddress, int port)
{
	int iCouurentIndex = objStackObjects.ServerCounterCount;	
	
	if( objStackObjects.ServerCounterCount > 9)
		return -1;
	
	strcpy( objStackObjects.ServerCounter[iCouurentIndex].Name, name);
	strcpy( objStackObjects.ServerCounter[iCouurentIndex].IpAddress, ipAddress);		
	
	objStackObjects.ServerCounter[iCouurentIndex].Port = port;
	objStackObjects.ServerCounter[iCouurentIndex].iRequest = 0;
	objStackObjects.ServerCounter[iCouurentIndex].iResponse = 0;		
	objStackObjects.ServerCounter[iCouurentIndex].isActive = 0;
	objStackObjects.ServerCounter[iCouurentIndex].CTimes = 0;
	objStackObjects.ServerCounter[iCouurentIndex].isConfigured = 1;
	
	objStackObjects.ServerCounterCount++;
	return iCouurentIndex;
}

void setActive( int iPCounterId, int isActive)
{
	if( iPCounterId >= 0 && iPCounterId < 10)
	{
		objStackObjects.ServerCounter[iPCounterId].isActive = isActive;
		
		if(isActive == 1) {
			objStackObjects.ServerCounter[iPCounterId].CTimes++;		
		}	
	}
}

void incrementRequest( int iPCounterId)
{
	if( iPCounterId >= 0 && iPCounterId < 10)
	{
		objStackObjects.ServerCounter[iPCounterId].iRequest++;
	}
}

void incrementResponse( int iPCounterId)
{
	if( iPCounterId >= 0 && iPCounterId < 10)
	{
		objStackObjects.ServerCounter[iPCounterId].iResponse++;
	}
}
//===============================================================================================================





int AVP_CHUNK_SIZE = 128;
//int AVP_CHUNK_SIZE = 256;
//int AVP_CHUNK_SIZE = 512;
int DIAM_BUFFER_SIZE_HEADER_SIZE = 20;
//int DIAM_BUFFER_SIZE_PER_REQUEST = 2560;
int DIAM_BUFFER_SIZE_PER_REQUEST = 4096;

void initDiamRequest(struct DiamMessage * diamMessage, int iProxyable, int iCmdCode, int iAppId);
int appSendMsgToClientOrPeer(struct DiamMessage* dmMessage, iClientInfo * cliInfo, int iPeerIndex);
void appAddAvpToDiamMessage( struct DiamMessage* dmMsg, struct DiamAvp * dmAvp);
void addAvp( struct DiamAvp * dmAvpParent, struct DiamAvp * dmAvpChild);
void closeAndCleanClientSocket(iClientInfo * cliInfo);
void closePeerConnection(int * iPeerThreadIndex);
void closeClientConnection(int * iClientThreadIndex);
void encodeDiamMessage( struct DiamMessage * dmMsg, char *buffer);
void releaseDiamRawData(struct DiamRawData* dmMsg);
void fillMiniData( struct DiamMessage *dmMsg, iCCRMini *oCCR);
struct QueueRecord* allocateQueueRecord();
void releaseQueueRecord(struct QueueRecord* dmMsg);
struct DiamRouteMessage* allocateDiamRouteMessage();

#if DIAMDRA
void setNextHBHId();
#endif



/*
void* __popDataWithUnsigned32Key( unsigned int iKey);
void* __popDataWithStrKey( char *cData);
void __pushDataWithUnsigned32Key( unsigned int iKey, void *ptrData);
void __pushDataWithStrKey( char *cKey, void *ptrData);	
*/

struct DiamAvp* allocateDiamAvp();
struct DiamMessage* allocateMessage();
struct DiamRawData* allocateDiamRawData();
struct CData* allocateCData();
void releaseMessage(struct DiamMessage* dmMsg);
void releaseCData(struct CData* oCData);
void releaseDiamAvp(struct DiamAvp* oDiamAvp);
void releaseDiamRouteMessage(struct DiamRouteMessage* dmMsg);
void Enquee( void *Data, struct Queue *oQueue);
void* __getASTItem( IASTDataPtr *dataPtr, char * Key, int setNull, pthread_mutex_t *pLock, void **dataOut);
int __addASTItem( IASTDataPtr *dataPtr, char * Key, void * Data, pthread_mutex_t *pLock);
iStickySessionInfo * allocateStickySessionInfo();
void releaseStickySessionPool( iStickySessionInfo* oMsg);
void closeAndCleanClientPeerConfigSocket( iPeerConfigData * oPeerConfigData);

/*
typedef int (*DiamMessageHandler)(struct DiamMessage* dmMsg);
DiamMessageHandler cbHandler;

//void setMessageHandler( void (*f)(struct DiamMessage*) )
void setMessageHandler( DiamMessageHandler cbPtr)
{
	//cbHandler = cbPtr;
}
*/

//int DoIt(float a, char b, char c)  __attribute__((cdecl));

int DoIt(float a, char b, char c)
{
	//printf("DoIt\n");
	return a+b+c;
}

int (*pt2Function)(float, char, char) = NULL;

int (*pServerMessageHandler)( struct DiamMessage*) = NULL;




void setHandler( int (*ptrHandler)(struct DiamMessage*))
{
	pServerMessageHandler = ptrHandler;
}


void setTimeOutHandler( int (*ptrHandler)( long lRecordId))
{
	pServerTimeOutCallbackHandler = ptrHandler;
}

/*
int (*pServerTimeOutCallbackHandler)( long lRecordId) = NULL;
int (*pServerTimeOutCallbackHandler2)( void* dObj) = NULL;
*/
void setObjectTimeOutHandler( int (*ptrHandler)( void* dObj))
{
	pServerTimeOutCallbackHandler2 = ptrHandler;
}

void hexDump(char* data, int length)
{
	int i;

	printf("\n");
	for( i = 0; i < length; i++)
	{
		printf("0x%X ", data[i]);
	}
	printf("\n");
}

void __initStartTime( iExecTime *oExecTime)
{
	struct timezone tzone;	
	gettimeofday( &oExecTime->before, &tzone);
}

void __initEndTime( iExecTime *oExecTime)
{
	struct timezone tzone;	
	gettimeofday( &oExecTime->after, &tzone);
	
	if ( oExecTime->before.tv_usec > oExecTime->after.tv_usec)
	{
		oExecTime->after.tv_usec += 1000000;
		oExecTime->after.tv_sec--;
	}
	
	oExecTime->lapsed.tv_usec = oExecTime->after.tv_usec - oExecTime->before.tv_usec;
	oExecTime->lapsed.tv_sec  = oExecTime->after.tv_sec  - oExecTime->before.tv_sec;	
}


/*
 * Commented:07-06-2016
void encodeUnsigned32(unsigned int val, struct DiamAvp * dmAvp)
{
	dmAvp->PayLoad = (struct CData*)lib_malloc(sizeof(struct CData));
	dmAvp->PayLoad->Data = (char*)lib_malloc(4);
	dmAvp->PayLoad->len = 4;

	encodeIntTo4Bytes( val, dmAvp->PayLoad->Data, 0);
}
*/

/*
 * Commented:07-06-2016
void encodeSigned32( int val, struct DiamAvp * dmAvp)
{
	dmAvp->PayLoad = (struct CData*)lib_malloc(sizeof(struct CData));
	dmAvp->PayLoad->Data = (char*)lib_malloc(4);
	dmAvp->PayLoad->len = 4;

	encodeIntTo4Bytes( val, dmAvp->PayLoad->Data, 0);
}
*/

void encodeOctetString(char * buffer, int length, struct DiamAvp * dmAvp)
{
	//dmAvp->PayLoad = (struct CData*)lib_malloc(sizeof(struct CData));
	//dmAvp->PayLoad->Data = (char*)lib_malloc(length);
	//dmAvp->PayLoad->len = length;
	dmAvp->PayLoad = (struct CData*)allocateCData();

	//memset( dmAvp->PayLoad->Data, 0, AVP_CHUNK_SIZE);
	memcpy( dmAvp->PayLoad->Data, buffer, length);

	dmAvp->PayLoad->len = length;
}

//
//void encodeDiamAvp_Depricated( struct DiamAvp * dmAvp, int level)
//{
//	//if(dmAvp->isEncoded == 1) return;
//
//	char sStr[] = "-------------------";
//
//	char preFix[(level*2)+1];
//	memset( &preFix, 0, (level*2) );
//	strncpy( preFix, sStr, (level*2) );
//
//	preFix[(level*2)] = '\0';
//	//printf("%s encoding DiamAvp[%d] isGrouped[%d] level[%d] \n", preFix, dmAvp->AvpCode, dmAvp->isGrouped, level);
//
//	//if(dmAvp->AvpCode == 0) return;
//
//	//if(dmAvp->GroupHead != NULL && dmAvp->isGrouped == 1)
//	if(dmAvp->GroupHead != NULL && dmAvp->iDataType == GROUPED)
//	{
//		//printf("\n---GroupHead Encoded Start-----------------------------------------------------------\n");
//		//all avp data will be encoded when data is assigned or add or set
//		//just encode header
//
//		//printf("Group Head is Not NULL for AvpCode[%d]\n", dmAvp->AvpCode);
//
//		int mLength = 0;
//		struct DiamAvp * childDmAvp = dmAvp->GroupHead;
//
//		while(childDmAvp != NULL)
//		{
//			//printf("%s calling encodeDiamAvp for ParentAvp[%d] ChildAvpCode[%d]\n", preFix, dmAvp->AvpCode, childDmAvp->AvpCode);
//
//			//encodeDiamAvp( childDmAvp, level + 1);
//			encodeDiamAvp_Depricated( childDmAvp, level + 1);
//
//			mLength += childDmAvp->AvpPayLoad->len;
//			childDmAvp = childDmAvp->Next;
//		}
//
//		//printf("%s Child Data Encoded For AVP[%d]\n", preFix, dmAvp->AvpCode);
//		//by this time AVP Childs PayLoad(Data) has been set incliding AvpPayLoad(Total Data with headers)
//
//		/*
//		childDmAvp = dmAvp->GroupHead;
//		while(childDmAvp != NULL)
//		{
//			mLength += childDmAvp->AvpPayLoad->len;
//			childDmAvp = childDmAvp->Next;
//		}
//		*/
//
//		char *buffer = (char*)lib_malloc( mLength);
//		memset( buffer, 0, mLength);
//
//		//printf("%s Calculated Length Of Group AVP[%d]  Length[%d]\n", preFix, dmAvp->AvpCode , mLength);
//
//
//		mLength = 0;
//		childDmAvp = dmAvp->GroupHead;
//
//		while(childDmAvp != NULL)
//		{
//			//printf("%s AVP Code[%d] Length[%d]\n", preFix, childDmAvp->AvpCode, childDmAvp->AvpPayLoad->len);
//			childDmAvp->AvpPayLoad->len;
//			childDmAvp = childDmAvp->Next;
//		}
//
//
//		mLength = 0;
//		childDmAvp = dmAvp->GroupHead;
//
//		while(childDmAvp != NULL)
//		{
//			memcpy( buffer + mLength, childDmAvp->AvpPayLoad->Data , childDmAvp->AvpPayLoad->len);
//
//			mLength += childDmAvp->AvpPayLoad->len;
//			childDmAvp = childDmAvp->Next;
//		}
//
//		//printf("%s Copied Buffer Group AVP[%d]  Length[%d]\n", preFix, dmAvp->AvpCode , mLength);
//
//		dmAvp->PayLoad = (struct CData*)lib_malloc(sizeof(struct CData));
//		dmAvp->PayLoad->Data = (char*)lib_malloc(mLength);
//		dmAvp->PayLoad->len = mLength;
//
//		memset( dmAvp->PayLoad->Data, 0, mLength);
//		memcpy( dmAvp->PayLoad->Data, buffer, mLength);
//
//		//printf("%s Group AVP[%d] Length[%d] Data Done\n", preFix, dmAvp->AvpCode , mLength);
//	}
//
//
//	int iHeader = 8;
//	int iDataLength;
//	int iPadded = 0;
//	int iAvpLength;
//
//	if( dmAvp->Flags.VendorSpecific == 1)
//	{
//		iHeader = 12;
//	}
//
//	iDataLength = dmAvp->PayLoad->len;
//
//	iAvpLength = iHeader + iDataLength;
//
//	int rem = iDataLength % 4;
//
//	if(rem > 0)
//	{
//		iPadded = 4 - rem;
//	}
//
//	char *buffer = (char*)lib_malloc( iAvpLength + iPadded);
//	memset( buffer, 0, iAvpLength + iPadded);
//
//	encodeIntTo4Bytes( dmAvp->AvpCode, buffer, 0);
//
//	if( dmAvp->Flags.VendorSpecific == 1)
//	{
//		buffer[4] |= 1 << 7;
//	}
//
//	if( dmAvp->Flags.Mandatory == 1)
//	{
//		buffer[4] |= 1 << 6;
//	}
//
//	encodeIntTo3BytesFrm( &dmAvp->AvpLength, buffer, 5);
//
//	if(iHeader == 12)
//	{
//		encodeIntTo4Bytes( dmAvp->VendorId, buffer, 8 );
//	}
//
//	memcpy( buffer + iHeader, dmAvp->PayLoad->Data , dmAvp->PayLoad->len);
//
//
//	dmAvp->AvpLength = iAvpLength;
//	dmAvp->Padding = iPadded;
//
//	dmAvp->AvpPayLoad = (struct CData*)lib_malloc(sizeof(struct CData));
//	dmAvp->AvpPayLoad->Data = buffer;
//	dmAvp->AvpPayLoad->len = dmAvp->AvpLength + dmAvp->Padding;
//
//	dmAvp->isEncoded = 1;
//
//	//printf("%s encodedd DiamAvp[%d]\n", preFix, dmAvp->AvpCode);
//}


void hexDumpDiamAvp(struct DiamAvp * dmAvp)
{
//	if(dmAvp->isEncoded == 0)
//		encodeDiamAvp_Depricated( dmAvp, 0);


	//hexDump( dmAvp->AvpPayLoad->Data, dmAvp->AvpPayLoad->len);
}

void hexDumpDiamMessage(struct DiamMessage * dmMsg)
{
	//hexDump( dmMsg->RespPayLoad->Data, dmMsg->RespPayLoad->len);
}

void calcAvpDataLength(struct DiamAvp* dmAvp)
{
	//int iLength = 0;
	int iHeader = 8;
	int iDataLength = 0;
	int iPadded = 0;
	int iAvpLength = 0;

	if( dmAvp->Flags.VendorSpecific == 1)
	{
		iHeader = 12;
	}

	switch( dmAvp->iDataType)
	{
		case SIGNED_32:
		case UNSIGNED_32:
			iDataLength = 4;
			break;
		case SIGNED_64:
		case UNSIGNED_64:
			iDataLength = 8;
			break;
		case OCTET_STRING:
			if( dmAvp->PayLoad)
			{
				iDataLength = dmAvp->PayLoad->len;
			}
			else
			{
				iDataLength = 0;
			}
			break;
		case GROUPED:
			iDataLength = 0;
			break;
		default:
			iDataLength = 0;
			break;
	}

	iAvpLength = iHeader + iDataLength;

	int rem = iDataLength % 4;

	if(rem > 0)
	{
		iPadded = 4 - rem;
	}

	dmAvp->HeaderLength = iHeader;
	dmAvp->AvpLength = iAvpLength;
	dmAvp->Padding = iPadded;
	dmAvp->PayLoadLength = iDataLength;

	//if( dmAvp->AvpCode == 421)
	//	printf("AVPCode:%d HeaderLength:%d iDataLength:%d iPadded:%d iAvpLength:%d\n", dmAvp->AvpCode, iHeader, iDataLength, iPadded, iAvpLength);

}

void calcGroupItemAvpDataLength(struct DiamAvp* dmAvp)
{
	int iLength = 0;
	int iHeader = 8;
	int iDataLength;
	int iPadded = 0;
	int iAvpLength;

	if( dmAvp->Flags.VendorSpecific == 1)
	{
		iHeader = 12;
	}
	
	//find length of all childs
	struct DiamAvp* dmGHAvp = NULL;
	dmGHAvp = dmAvp->GroupHead;
	
	//while(dmGHAvp != NULL)
	while(dmGHAvp)	
	{
		if( dmGHAvp->iDataType == GROUPED)
		{
			//printf("Calculating GroupedAVP Length for AVP[%d] ", dmAvp->AvpCode);			
			calcGroupItemAvpDataLength( dmGHAvp);			
		}
		else
		{
			//printf("Calculating AVP Length for AVP[%d] ", dmAvp->AvpCode);
			calcAvpDataLength( dmGHAvp);
		}

		//printf("AvpLength [%d] Padding[%d] AvpTotalLength[%d]\n", dmAvp->AvpLength, dmAvp->Padding, (dmAvp->AvpLength + dmAvp->Padding));
		iLength += (dmGHAvp->AvpLength + dmGHAvp->Padding);
					
		dmGHAvp = dmGHAvp->Next;
	}
	
	dmAvp->HeaderLength = iHeader;
	dmAvp->AvpLength = ( iHeader + iLength);	//Avp Length includes heading
	dmAvp->Padding = 0;							//assumption: Group AVP Never have padding	
	dmAvp->PayLoadLength = iLength;
}



void encodeAVPInfo( struct DiamAvp* dmAvp, char* buffer)
{
	//printf("%s AvpCode[%d]\n", __FUNCTION__, dmAvp->AvpCode);
	encodeIntTo4Bytes( dmAvp->AvpCode, buffer, 0);

	if( dmAvp->Flags.VendorSpecific == 1)
	{
		buffer[4] |= 1 << 7;
	}

	if( dmAvp->Flags.Mandatory == 1)
	{
		buffer[4] |= 1 << 6;
	}

	encodeIntTo3BytesFrm( &dmAvp->AvpLength, buffer, 5);

	if(dmAvp->HeaderLength == 12)
	{
		encodeIntTo4Bytes( dmAvp->VendorId, buffer, 8 );
	}

	switch( dmAvp->iDataType)
	{
		case SIGNED_32:
			encodeIntTo4Bytes( dmAvp->intVal, buffer + dmAvp->HeaderLength, 0);
			break;
		case UNSIGNED_32:
			encodeIntTo4Bytes( dmAvp->usIntVal, buffer + dmAvp->HeaderLength, 0);
			break;
		case SIGNED_64:
			//TODO: 8 Bytes
			//encodeIntTo4Bytes( dmAvp->int64Val, buffer + dmAvp->HeaderLength, 0);
			//encodeInt64ToChar( dmAvp->int64Val, buffer + dmAvp->HeaderLength);
			
			//Commented On 24-11-2016
			//encodeIntTo4Bytes( dmAvp->int64Val, buffer + dmAvp->HeaderLength + 4, 0);
			encodeLongTo8Bytes( dmAvp->int64Val, (buffer + dmAvp->HeaderLength), 0);
			break;
		case UNSIGNED_64:
			//TODO: 8 Bytes
			//encodeIntTo4Bytes( dmAvp->usInt64Val, buffer + dmAvp->HeaderLength, 0);
			//encodeInt64ToChar( dmAvp->usInt64Val, buffer + dmAvp->HeaderLength);
			//encodeIntTo4Bytes( dmAvp->int64Val, buffer + dmAvp->HeaderLength + 4, 0);
			
			//Commented On 24-11-2016
			//encodeIntTo4Bytes( dmAvp->usInt64Val, buffer + dmAvp->HeaderLength + 4, 0);
			
			//printf("AvpCode[%d] usInt64Val[%ld]\n", dmAvp->AvpCode, dmAvp->usInt64Val);
			encodeULongTo8Bytes( dmAvp->usInt64Val, (buffer + dmAvp->HeaderLength), 0);
			break;
		case OCTET_STRING:
			if( dmAvp->PayLoad)
			{	
				memcpy( buffer + dmAvp->HeaderLength, dmAvp->PayLoad->Data , dmAvp->PayLoad->len);
			}
			break;
		case GROUPED:
			break;
		default:
			break;
	}
}


void encodeGroupedAVPInfo( struct DiamAvp* dmAvp, char* buffer)
{
	encodeIntTo4Bytes( dmAvp->AvpCode, buffer, 0);
	//printf("%s AvpCode[%d]\n", __FUNCTION__, dmAvp->AvpCode);

	if( dmAvp->Flags.VendorSpecific == 1)
	{
		buffer[4] |= 1 << 7;
	}

	if( dmAvp->Flags.Mandatory == 1)
	{
		buffer[4] |= 1 << 6;
	}

	encodeIntTo3BytesFrm( &dmAvp->AvpLength, buffer, 5);

	if(dmAvp->HeaderLength == 12)
	{
		encodeIntTo4Bytes( dmAvp->VendorId, buffer, 8 );
	}

	struct DiamAvp* dmGHAvp = NULL;
	dmGHAvp = dmAvp->GroupHead;
	
	//move buffer pointer
	buffer += dmAvp->HeaderLength;
	
	//while(dmGHAvp != NULL)
	while(dmGHAvp)	
	{
		if( dmGHAvp->iDataType == GROUPED)
		{
			encodeGroupedAVPInfo( dmGHAvp, buffer);			
		}
		else
		{
			encodeAVPInfo( dmGHAvp, buffer);
		}
		
		buffer += (dmGHAvp->AvpLength + dmGHAvp->Padding);
		dmGHAvp = dmGHAvp->Next;
	}	
}

void removeDiamAvp( struct DiamMessage * dmMsg, int iAvpCode)
{
	struct DiamAvp * dmAvp = NULL;
	struct DiamAvp * lastAvp = NULL;
	dmAvp = dmMsg->Head;
	
	while(dmAvp )
	{
		if( dmAvp->AvpCode == iAvpCode)
		{
			if( dmAvp == dmMsg->Head)
			{
				dmMsg->Head = dmAvp->Next;
				releaseDiamAvp( dmAvp);
				break;
			}
			else
			{
				if(lastAvp)
				{
					lastAvp->Next = dmAvp->Next;
					releaseDiamAvp( dmAvp);
					break;
				}
			}
		}
		lastAvp = dmAvp;
		dmAvp = dmAvp->Next;
	}
}

/**
 * New API for Encoding
 *
 */
void encodeDiamMessage( struct DiamMessage * dmMsg, char* buffer)
{
	if( dmMsg->isReleased == 1)
	{
		printf( "ERROR: called encodeDiamMessage after releaseMessage\n");
		dmMsg->Length = 0;
		//bug in application, for handling in stack this statement is required.
		return;
	}
	
	int iLength = 20;

	struct DiamAvp* dmAvp = NULL;
	dmAvp = dmMsg->Head;

	int i = 0;

	//while(dmAvp != NULL)
	while( dmAvp )	
	{
		if( dmAvp->iDataType == GROUPED)
		{
			//printf("Calculating GroupedAVP Length for AVP[%d] ", dmAvp->AvpCode);			
			calcGroupItemAvpDataLength( dmAvp);	
		}
		else
		{
			//printf("Calculating AVP Length for AVP[%d] ", dmAvp->AvpCode);
			calcAvpDataLength( dmAvp);
		}
		
		//printf("AvpLength [%d] Padding[%d] AvpTotalLength[%d]\n", dmAvp->AvpLength, dmAvp->Padding, (dmAvp->AvpLength + dmAvp->Padding));
		iLength += (dmAvp->AvpLength + dmAvp->Padding);

		i++;
		dmAvp = dmAvp->Next;
	}

	dmMsg->Length = iLength;
	memset( buffer, 0, dmMsg->Length);

	//printf("Message Length Calucated[%d]\n", dmMsg->Length);

	buffer[0] = 1;
	encodeIntTo3BytesFrm( &dmMsg->Length, buffer, 1);

	if(dmMsg->Flags.Request == 1)
	{
		buffer[4] |= 1 << 7;
	}

	if(dmMsg->Flags.Proxyable == 1)
	{
		buffer[4] |= 1 << 6;
	}
	
	if(dmMsg->Flags.Error == 1)
	{
		buffer[4] |= 1 << 5;
	}
	
	if(dmMsg->Flags.Retransmit == 1)
	{
		buffer[4] |= 1 << 4;
	}	

	encodeIntTo3BytesFrm( &dmMsg->CmdCode, buffer, 5);
	encodeIntTo4Bytes( dmMsg->AppId, buffer, 8);
	encodeLongTo4Bytes( dmMsg->HBHId, buffer, 12);
	encodeLongTo4Bytes( dmMsg->E2EId, buffer, 16);

	int iCurrentIndex = 20;

	dmAvp = dmMsg->Head;
	//while(dmAvp != NULL)
	while(dmAvp)	
	{
		//printf("Encoding AVP[%d] iCurrentIndex[%d]\n", dmAvp->AvpCode, iCurrentIndex);

		if( dmAvp->iDataType == GROUPED)
		{
			encodeGroupedAVPInfo( dmAvp, buffer + iCurrentIndex);
		}
		else
		{
			encodeAVPInfo( dmAvp, buffer + iCurrentIndex);
		}

		iCurrentIndex += (dmAvp->AvpLength + dmAvp->Padding);
		dmAvp = dmAvp->Next;
	}

	//printf("Message Encoding Completed Length[%d] Encoded Length[%d]\n", dmMsg->Length, iCurrentIndex);

	dmMsg->Length = iLength;
}

/*
void encodeDiamMessage_Depricated( struct DiamMessage * dmMsg)
{
	dmMsg->Length = 20;

	struct DiamAvp* dmAvp = NULL;
	dmAvp = dmMsg->Head;

	int i = 0;

	while(dmAvp != NULL)
	{
		if(dmAvp->isEncoded == 0)
		{
			encodeDiamAvp_Depricated( dmAvp, 0);
		}

		dmMsg->Length += dmAvp->AvpPayLoad->len;

		i++;
		dmAvp = dmAvp->Next;
	}

	char *buffer = (char*)lib_malloc(dmMsg->Length);
	memset( buffer, 0, dmMsg->Length);

	buffer[0] = 1;
	encodeIntTo3BytesFrm( &dmMsg->Length, buffer, 1);

	if(dmMsg->Flags.Request == 1)
	{
		buffer[4] |= 1 << 7;
	}

	if(dmMsg->Flags.Proxyable == 1)
	{
		buffer[4] |= 1 << 6;
	}

	encodeIntTo3BytesFrm( &dmMsg->CmdCode, buffer, 5);
	encodeIntTo4Bytes( dmMsg->AppId, buffer, 8);
	encodeLongTo4Bytes( dmMsg->HBHId, buffer, 12);
	encodeLongTo4Bytes( dmMsg->E2EId, buffer, 16);

	int iCurrentIndex = 20;

	dmAvp = dmMsg->Head;
	while(dmAvp != NULL)
	{
		memcpy( buffer + iCurrentIndex, dmAvp->AvpPayLoad->Data , dmAvp->AvpPayLoad->len);

		iCurrentIndex += dmAvp->AvpPayLoad->len;
		dmAvp = dmAvp->Next;
	}

	//dmMsg->RespPayLoad = (struct CData*)lib_malloc(sizeof(struct CData));
	//dmMsg->RespPayLoad->Data = buffer;
	//dmMsg->RespPayLoad->len = dmMsg->Length;

	//printf("Message Encoded Succesfully ..cmdCode[%d] length[%d]\n", dmMsg->CmdCode, dmMsg->Length);
	//hexDumpDiamMessage(dmMsg);
}
*/

void freeDiamAvpsInDiamMessage(struct DiamMessage* oDiamMessage)
{
	return;

	struct DiamAvp* dmAvp = NULL;
	dmAvp = oDiamMessage->Head;

	int iFreedPayLoad = 0;
	int iFreedAvpPayLoad = 0;

	//while(dmAvp != NULL)
	while(dmAvp)	
	{
		oDiamMessage->Current = dmAvp->Next;

		//if( dmAvp->PayLoad != NULL)
		if( dmAvp->PayLoad )	
		{
			//printf("Freeing PayLoad Memory for AVP[%d]\n", dmAvp->AvpCode);

			free( dmAvp->PayLoad->Data);
			dmAvp->PayLoad->Data = NULL;

			free(dmAvp->PayLoad);
			dmAvp->PayLoad = NULL;

			iFreedPayLoad++;
		}

		/*
		if( dmAvp->AvpPayLoad != NULL)
		{
			//printf("Freeing AvpPayLoad Memory for AVP[%d]\n", dmAvp->AvpCode);

			free(dmAvp->AvpPayLoad->Data);
			dmAvp->AvpPayLoad->Data = NULL;

			free(dmAvp->AvpPayLoad);
			dmAvp->AvpPayLoad = NULL;

			iFreedAvpPayLoad++;
		}
		*/

		dmAvp = oDiamMessage->Current;
	}

	//printf("Freeing iFreedPayLoad[%d] iFreedAvpPayLoad[%d]\n", iFreedPayLoad, iFreedAvpPayLoad);
}


void encodeUnsigned32AVP( int iAvpCode, int iMandatory, unsigned int iUnsigned32, struct DiamAvp *dmAvp, int vendorId)
{
	//memset( dmAvp, 0, sizeof(struct DiamAvp));

	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (vendorId > 0) ? 1 : 0;
	dmAvp->VendorId = vendorId;
	dmAvp->usIntVal = iUnsigned32;
	dmAvp->iDataType = UNSIGNED_32;

	//encodeUnsigned32( iUnsigned32, dmAvp);
	//encodeDiamAvp( dmAvp, 0);

	//printf("================[AvpCode(%d)]=================================\n",iAvpCode);
	//hexDumpDiamAvp( dmAvp);
	//printf("=================================================\n");
}


void encodeUnsigned64AVP( int iAvpCode, int iMandatory, unsigned long lUnsigned64, struct DiamAvp *dmAvp, int iVendorId)
{
	//memset( dmAvp, 0, sizeof(struct DiamAvp));

	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->usInt64Val = lUnsigned64;
	dmAvp->iDataType = UNSIGNED_64;

	//encodeUnsigned32( lUnsigned64, dmAvp);
	//encodeDiamAvp( dmAvp, 0);
}


void encodeInteger32AVP( int iAvpCode, int iMandatory, int iInteger32, struct DiamAvp *dmAvp, int iVendorId)
{
	//memset( dmAvp, 0, sizeof(struct DiamAvp));

	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->intVal = iInteger32;
	dmAvp->iDataType = SIGNED_32;

	//encodeUnsigned32( iInteger32, dmAvp);
	//encodeDiamAvp( dmAvp, 0);
}

void encodeOctetStringAVP( int iAvpCode, int iMandatory, char * sData, struct DiamAvp *dmAvp, int vendorId, int sDataLength)
{
	//memset( dmAvp, 0, sizeof(struct DiamAvp));

	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (vendorId > 0) ? 1 : 0;
	dmAvp->VendorId = vendorId;
	dmAvp->iDataType = OCTET_STRING;

	encodeOctetString( sData, sDataLength, dmAvp);
	//encodeDiamAvp( dmAvp, 0);

	//printf("================[AvpCode(%d)]=================================\n",iAvpCode);
	//hexDumpDiamAvp( dmAvp);
	//printf("=================================================\n");
}


void getIPV4Address(char *buffer4Bytes, char *ipAddress)
{
	int ip;
	decodeIntValueFrom4Bytes( &ip, buffer4Bytes, 0);
	
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    sprintf(ipAddress, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);
}



void encodeAddressAVP( int iAvpCode, int iMandatory, int ipAddressType, char * sIPAddress, struct DiamAvp *dmAvp, int vendorId)
{
	//memset( dmAvp, 0, sizeof(struct DiamAvp));

	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (vendorId > 0) ? 1 : 0;
	dmAvp->VendorId = vendorId;
	dmAvp->iDataType = OCTET_STRING;

	char buffer[6];
	buffer[0] = 0;
	buffer[1] = ipAddressType;

	int a, b, c, d;
	sscanf( sIPAddress, "%d.%d.%d.%d", &a, &b, &c, &d);
	unsigned long num = 0;

	num = (num << 8) + a;
	num = (num << 8) + b;
	num = (num << 8) + c;
	num = (num << 8) + d;

	encodeLongTo4Bytes( num, buffer, 2 );

	encodeOctetString( buffer, 6, dmAvp);
	//encodeDiamAvp( dmAvp, 0);

	//printf("================[AvpCode(%d)]=================================\n",iAvpCode);
	//hexDumpDiamAvp( dmAvp);
	//printf("=================================================\n");
}


void encodeHostIPAddressAVP( char * sIPAddress, struct DiamAvp *dmAvp, int vendorId)
{
	encodeAddressAVP( 257, 1, 1, sIPAddress, dmAvp, vendorId);
}

void encodeResultCodeAVP(unsigned int iUnsigned32, struct DiamAvp *dmAvp, int vendorId)
{
	encodeUnsigned32AVP( 268, 1, iUnsigned32, dmAvp, vendorId);
}

void encodeOriginStateIdAVP(unsigned int iUnsigned32, struct DiamAvp *dmAvp, int vendorId)
{
	encodeUnsigned32AVP( 278, 1, iUnsigned32, dmAvp, vendorId);
}

void encodeVendorIdAVP(unsigned int iUnsigned32, struct DiamAvp *dmAvp, int vendorId)
{
	encodeUnsigned32AVP( 266, 1, iUnsigned32, dmAvp, vendorId);
}

void encodeAuthApplicationIdAVP(unsigned int iUnsigned32, struct DiamAvp *dmAvp, int vendorId)
{
	encodeUnsigned32AVP( 258, 1, iUnsigned32, dmAvp, vendorId);
}

void encodeOriginHostAVP(char * sOctectString, struct DiamAvp *dmAvp, int vendorId, int sOctectStringLength)
{
	encodeOctetStringAVP( 264, 1, sOctectString, dmAvp, vendorId, sOctectStringLength);
}

void encodeOriginRealmAVP(char * sOctectString, struct DiamAvp *dmAvp, int vendorId, int sOctectStringLength)
{
	encodeOctetStringAVP( 296, 1, sOctectString, dmAvp, vendorId, sOctectStringLength);
}

void encodeErrorMessageAVP(char * sOctectString, struct DiamAvp *dmAvp, int vendorId, int sOctectStringLength)
{
	encodeOctetStringAVP( 281, 0, sOctectString, dmAvp, vendorId, sOctectStringLength);
}

void encodeProductNameAVP(char * sOctectString, struct DiamAvp *dmAvp, int vendorId, int sOctectStringLength)
{
	encodeOctetStringAVP( 269, 0, sOctectString, dmAvp, vendorId, sOctectStringLength);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Helper functions for Generated Code
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct DiamAvp * __createAVP()
{
	struct DiamAvp * dmAvp = (struct DiamAvp *)lib_malloc(sizeof(struct DiamAvp));
	//memset( dmAvp, 0, sizeof(struct DiamAvp));

	dmAvp->GroupHead = dmAvp->GroupCurrent = NULL;

	return dmAvp;
}

struct DiamMessage * __createMessage()
{
	struct DiamMessage * dmMsg = (struct DiamMessage *)lib_malloc(sizeof(struct DiamMessage));
	return dmMsg;
}


void __freeMessage(struct DiamMessage *dmMessage )
{
	//printf("Freeing Memory for Message[%d] isRequest[%d]\n", dmMessage->CmdCode, dmMessage->Flags.Request);

	/*
	freeDiamAvpsInDiamMessage( dmMessage);

	if( dmMessage->RespPayLoad != NULL)
	{
		free( dmMessage->RespPayLoad->Data);
		dmMessage->RespPayLoad->Data = NULL;

		free( dmMessage->RespPayLoad);
		dmMessage->RespPayLoad = NULL;
	}

	free( dmMessage);
	dmMessage = NULL;
	*/

	//printf("Freed Memory\n");
}



void setOctetStringAVP( struct DiamAvp *dmAvp, int iAvpCode, char *sOctetString, int iVendorId, int iMandatory, int iLength)
{
	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->iDataType = OCTET_STRING;

	encodeOctetString( sOctetString, iLength, dmAvp);
}


void addOctetStringAVP( struct DiamMessage *dmMessage, int iAvpCode, char *sOctetString, int iVendorId, int iMandatory, int iLength)
{
	struct DiamAvp * dmAvp = (struct DiamAvp *) allocateDiamAvp();

	setOctetStringAVP( dmAvp, iAvpCode, sOctetString, iVendorId, iMandatory, iLength);

	appAddAvpToDiamMessage( dmMessage, dmAvp);
}


void setUnsigned32AVP( struct DiamAvp *dmAvp, int iAvpCode, unsigned int uiUnsigned32, int iVendorId, int iMandatory)
{
	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->iDataType = UNSIGNED_32;
	dmAvp->usIntVal = uiUnsigned32;

	//encodeUnsigned32( uiUnsigned32, dmAvp);
}


void addUnsigned32AVP( struct DiamMessage *dmMessage, int iAvpCode, unsigned int uiUnsigned32, int iVendorId, int iMandatory)
{
	struct DiamAvp * dmAvp = (struct DiamAvp *) allocateDiamAvp();

	setUnsigned32AVP( dmAvp, iAvpCode, uiUnsigned32, iVendorId, iMandatory);

	appAddAvpToDiamMessage( dmMessage, dmAvp);
}

void setInteger32AVP( struct DiamAvp *dmAvp, int iAvpCode, int iInteger32, int iVendorId, int iMandatory)
{
	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->iDataType = SIGNED_32;
	dmAvp->intVal = iInteger32;

	//encodeSigned32( iInteger32, dmAvp);
}

void addInteger32AVP( struct DiamMessage *dmMessage, int iAvpCode, int iInteger32, int iVendorId, int iMandatory)
{
	struct DiamAvp * dmAvp = (struct DiamAvp *) allocateDiamAvp();

	setInteger32AVP( dmAvp, iAvpCode, iInteger32, iVendorId, iMandatory);

	appAddAvpToDiamMessage( dmMessage, dmAvp);
}


void setInteger64AVP( struct DiamAvp *dmAvp, int iAvpCode, long lInteger64, int iVendorId, int iMandatory)
{
	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->iDataType = SIGNED_64;
	dmAvp->int64Val = lInteger64;
}


void addInteger64AVP( struct DiamMessage *dmMessage, int iAvpCode, long lInteger64, int iVendorId, int iMandatory)
{
	struct DiamAvp * dmAvp = (struct DiamAvp *) allocateDiamAvp();

	//setUnsigned32AVP( dmAvp, iAvpCode, lInteger64, iVendorId, iMandatory);
	setInteger64AVP( dmAvp, iAvpCode, lInteger64, iVendorId, iMandatory);
	
	appAddAvpToDiamMessage( dmMessage, dmAvp);
}


void setUnsigned64AVP( struct DiamAvp *dmAvp, int iAvpCode, unsigned long ulUnsigned64, int iVendorId, int iMandatory)
{
	dmAvp->AvpCode = iAvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->iDataType = UNSIGNED_64;
	dmAvp->usInt64Val = ulUnsigned64;
}

void addUnsigned64AVP( struct DiamMessage *dmMessage, int iAvpCode, unsigned long ulUnsigned64, int iVendorId, int iMandatory)
{
	struct DiamAvp * dmAvp = (struct DiamAvp *) allocateDiamAvp();

	//setUnsigned32AVP( dmAvp, iAvpCode, ulUnsigned64, iVendorId, iMandatory);
	setUnsigned64AVP( dmAvp, iAvpCode, ulUnsigned64, iVendorId, iMandatory);

	appAddAvpToDiamMessage( dmMessage, dmAvp);
}


void setGroupedAVP( struct DiamMessage *dmMessage, int AvpCode, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	dmAvp->AvpCode = AvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	//dmAvp->isGrouped = 1;
	dmAvp->iDataType = GROUPED;

	appAddAvpToDiamMessage( dmMessage, dmAvp);
}

void setAddressAVP( struct DiamAvp *dmAvp, int AvpCode, char *sIPAddress, int iVendorId, int iMandatory)
{
	dmAvp->AvpCode = AvpCode;
	dmAvp->Flags.Mandatory = iMandatory;
	dmAvp->Flags.VendorSpecific = (iVendorId > 0) ? 1 : 0;
	dmAvp->VendorId = iVendorId;
	dmAvp->iDataType = OCTET_STRING;


	char buffer[6];
	buffer[0] = 0;
	buffer[1] = 1;

	int a, b, c, d;
	sscanf( sIPAddress, "%d.%d.%d.%d", &a, &b, &c, &d);
	unsigned long num = 0;

	num = (num << 8) + a;
	num = (num << 8) + b;
	num = (num << 8) + c;
	num = (num << 8) + d;

	encodeLongTo4Bytes( num, buffer, 2 );
	encodeOctetString( buffer, 6, dmAvp);
}


void addAddressAVP( struct DiamMessage *dmMessage, int AvpCode, char *sHostIPAddress, int iVendorId, int iMandatory)
{
	struct DiamAvp * dmAvp = (struct DiamAvp *) allocateDiamAvp();
	setAddressAVP( dmAvp, AvpCode, sHostIPAddress, iVendorId, iMandatory);
	appAddAvpToDiamMessage( dmMessage, dmAvp);
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Generated Code
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/**
* AVP Code : 921
* Data Type : OctetString
*/
void addCNIPMulticastDistributionAVP( struct DiamMessage *dmMessage, char *sCNIPMulticastDistribution, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_CNIPMulticastDistribution, sCNIPMulticastDistribution, iVendorId, iMandatory, iLength);
}


void setCNIPMulticastDistributionAVP( struct DiamAvp *dmAvp, char *sCNIPMulticastDistribution, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_CNIPMulticastDistribution, sCNIPMulticastDistribution, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2116
* Data Type : OctetString
*/
void addContentIDAVP( struct DiamMessage *dmMessage, char *sContentID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ContentID, sContentID, iVendorId, iMandatory, iLength);
}


void setContentIDAVP( struct DiamAvp *dmAvp, char *sContentID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ContentID, sContentID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2117
* Data Type : OctetString
*/
void addContentProviderIDAVP( struct DiamMessage *dmMessage, char *sContentProviderID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ContentProviderID, sContentProviderID, iVendorId, iMandatory, iLength);
}


void setContentProviderIDAVP( struct DiamAvp *dmAvp, char *sContentProviderID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ContentProviderID, sContentProviderID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2115
* Data Type : OctetString
*/
void addDCDInformationAVP( struct DiamMessage *dmMessage, char *sDCDInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_DCDInformation, sDCDInformation, iVendorId, iMandatory, iLength);
}


void setDCDInformationAVP( struct DiamAvp *dmAvp, char *sDCDInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_DCDInformation, sDCDInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2104
* Data Type : OctetString
*/
void addDeliveryStatusAVP( struct DiamMessage *dmMessage, char *sDeliveryStatus, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_DeliveryStatus, sDeliveryStatus, iVendorId, iMandatory, iLength);
}


void setDeliveryStatusAVP( struct DiamAvp *dmAvp, char *sDeliveryStatus, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_DeliveryStatus, sDeliveryStatus, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 510
* Data Type : OctetString
*/
void addFlowsAVP( struct DiamMessage *dmMessage, char *sFlows, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_Flows, sFlows, iVendorId, iMandatory, iLength);
}


void setFlowsAVP( struct DiamAvp *dmAvp, char *sFlows, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_Flows, sFlows, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1026
* Data Type : OctetString
*/
void addGuaranteedBitrateULAVP( struct DiamMessage *dmMessage, char *sGuaranteedBitrateUL, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_GuaranteedBitrateUL, sGuaranteedBitrateUL, iVendorId, iMandatory, iLength);
}


void setGuaranteedBitrateULAVP( struct DiamAvp *dmAvp, char *sGuaranteedBitrateUL, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_GuaranteedBitrateUL, sGuaranteedBitrateUL, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2110
* Data Type : OctetString
*/
void addIMInformationAVP( struct DiamMessage *dmMessage, char *sIMInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_IMInformation, sIMInformation, iVendorId, iMandatory, iLength);
}


void setIMInformationAVP( struct DiamAvp *dmAvp, char *sIMInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_IMInformation, sIMInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 604
* Data Type : OctetString
*/
void addMandatoryCapabilityAVP( struct DiamMessage *dmMessage, char *sMandatoryCapability, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MandatoryCapability, sMandatoryCapability, iVendorId, iMandatory, iLength);
}


void setMandatoryCapabilityAVP( struct DiamAvp *dmAvp, char *sMandatoryCapability, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MandatoryCapability, sMandatoryCapability, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 515
* Data Type : OctetString
*/
void addMaxRequestedBandwidthDLAVP( struct DiamMessage *dmMessage, char *sMaxRequestedBandwidthDL, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MaxRequestedBandwidthDL, sMaxRequestedBandwidthDL, iVendorId, iMandatory, iLength);
}


void setMaxRequestedBandwidthDLAVP( struct DiamAvp *dmAvp, char *sMaxRequestedBandwidthDL, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MaxRequestedBandwidthDL, sMaxRequestedBandwidthDL, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 516
* Data Type : OctetString
*/
void addMaxRequestedBandwidthULAVP( struct DiamMessage *dmMessage, char *sMaxRequestedBandwidthUL, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MaxRequestedBandwidthUL, sMaxRequestedBandwidthUL, iVendorId, iMandatory, iLength);
}


void setMaxRequestedBandwidthULAVP( struct DiamAvp *dmAvp, char *sMaxRequestedBandwidthUL, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MaxRequestedBandwidthUL, sMaxRequestedBandwidthUL, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 907
* Data Type : OctetString
*/
void addMBMS2G3GIndicatorAVP( struct DiamMessage *dmMessage, char *sMBMS2G3GIndicator, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MBMS2G3GIndicator, sMBMS2G3GIndicator, iVendorId, iMandatory, iLength);
}


void setMBMS2G3GIndicatorAVP( struct DiamAvp *dmAvp, char *sMBMS2G3GIndicator, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MBMS2G3GIndicator, sMBMS2G3GIndicator, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 903
* Data Type : OctetString
*/
void addMBMSServiceAreaAVP( struct DiamMessage *dmMessage, char *sMBMSServiceArea, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MBMSServiceArea, sMBMSServiceArea, iVendorId, iMandatory, iLength);
}


void setMBMSServiceAreaAVP( struct DiamAvp *dmAvp, char *sMBMSServiceArea, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MBMSServiceArea, sMBMSServiceArea, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 906
* Data Type : OctetString
*/
void addMBMSServiceTypeAVP( struct DiamMessage *dmMessage, char *sMBMSServiceType, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MBMSServiceType, sMBMSServiceType, iVendorId, iMandatory, iLength);
}


void setMBMSServiceTypeAVP( struct DiamAvp *dmAvp, char *sMBMSServiceType, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MBMSServiceType, sMBMSServiceType, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 908
* Data Type : OctetString
*/
void addMBMSSessionIdentityAVP( struct DiamMessage *dmMessage, char *sMBMSSessionIdentity, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MBMSSessionIdentity, sMBMSSessionIdentity, iVendorId, iMandatory, iLength);
}


void setMBMSSessionIdentityAVP( struct DiamAvp *dmAvp, char *sMBMSSessionIdentity, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MBMSSessionIdentity, sMBMSSessionIdentity, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 701
* Data Type : OctetString
*/
void addMSISDNAVP( struct DiamMessage *dmMessage, char *sMSISDN, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MSISDN, sMSISDN, iVendorId, iMandatory, iLength);
}


void setMSISDNAVP( struct DiamAvp *dmAvp, char *sMSISDN, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MSISDN, sMSISDN, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2111
* Data Type : OctetString
*/
void addNumberOfMessagesSuccessfullyExplodedAVP( struct DiamMessage *dmMessage, char *sNumberOfMessagesSuccessfullyExploded, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_NumberOfMessagesSuccessfullyExploded, sNumberOfMessagesSuccessfullyExploded, iVendorId, iMandatory, iLength);
}


void setNumberOfMessagesSuccessfullyExplodedAVP( struct DiamAvp *dmAvp, char *sNumberOfMessagesSuccessfullyExploded, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_NumberOfMessagesSuccessfullyExploded, sNumberOfMessagesSuccessfullyExploded, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2112
* Data Type : OctetString
*/
void addNumberOfMessagesSuccessfullySentAVP( struct DiamMessage *dmMessage, char *sNumberOfMessagesSuccessfullySent, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_NumberOfMessagesSuccessfullySent, sNumberOfMessagesSuccessfullySent, iVendorId, iMandatory, iLength);
}


void setNumberOfMessagesSuccessfullySentAVP( struct DiamAvp *dmAvp, char *sNumberOfMessagesSuccessfullySent, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_NumberOfMessagesSuccessfullySent, sNumberOfMessagesSuccessfullySent, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 605
* Data Type : OctetString
*/
void addOptionalCapabilityAVP( struct DiamMessage *dmMessage, char *sOptionalCapability, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_OptionalCapability, sOptionalCapability, iVendorId, iMandatory, iLength);
}


void setOptionalCapabilityAVP( struct DiamAvp *dmAvp, char *sOptionalCapability, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_OptionalCapability, sOptionalCapability, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1046
* Data Type : OctetString
*/
void addPriorityLevelAVP( struct DiamMessage *dmMessage, char *sPriorityLevel, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PriorityLevel, sPriorityLevel, iVendorId, iMandatory, iLength);
}


void setPriorityLevelAVP( struct DiamAvp *dmAvp, char *sPriorityLevel, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PriorityLevel, sPriorityLevel, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1016
* Data Type : OctetString
*/
void addQoSInformationAVP( struct DiamMessage *dmMessage, char *sQoSInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_QoSInformation, sQoSInformation, iVendorId, iMandatory, iLength);
}


void setQoSInformationAVP( struct DiamAvp *dmAvp, char *sQoSInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_QoSInformation, sQoSInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1028
* Data Type : OctetString
*/
void addQoSClassIdentifierAVP( struct DiamMessage *dmMessage, char *sQoSClassIdentifier, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_QoSClassIdentifier, sQoSClassIdentifier, iVendorId, iMandatory, iLength);
}


void setQoSClassIdentifierAVP( struct DiamAvp *dmAvp, char *sQoSClassIdentifier, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_QoSClassIdentifier, sQoSClassIdentifier, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 909
* Data Type : OctetString
*/
void addRAIAVP( struct DiamMessage *dmMessage, char *sRAI, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_RAI, sRAI, iVendorId, iMandatory, iLength);
}


void setRAIAVP( struct DiamAvp *dmAvp, char *sRAI, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_RAI, sRAI, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 901
* Data Type : OctetString
*/
void addRequiredMBMSBearerCapabilitiesAVP( struct DiamMessage *dmMessage, char *sRequiredMBMSBearerCapabilities, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_RequiredMBMSBearerCapabilities, sRequiredMBMSBearerCapabilities, iVendorId, iMandatory, iLength);
}


void setRequiredMBMSBearerCapabilitiesAVP( struct DiamAvp *dmAvp, char *sRequiredMBMSBearerCapabilities, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_RequiredMBMSBearerCapabilities, sRequiredMBMSBearerCapabilities, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 603
* Data Type : OctetString
*/
void addServerCapabilitiesAVP( struct DiamMessage *dmMessage, char *sServerCapabilities, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ServerCapabilities, sServerCapabilities, iVendorId, iMandatory, iLength);
}


void setServerCapabilitiesAVP( struct DiamAvp *dmAvp, char *sServerCapabilities, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ServerCapabilities, sServerCapabilities, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 602
* Data Type : OctetString
*/
void addServerNameAVP( struct DiamMessage *dmMessage, char *sServerName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ServerName, sServerName, iVendorId, iMandatory, iLength);
}


void setServerNameAVP( struct DiamAvp *dmAvp, char *sServerName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ServerName, sServerName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1256
* Data Type : OctetString
*/
void addServiceGenericInformationAVP( struct DiamMessage *dmMessage, char *sServiceGenericInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ServiceGenericInformation, sServiceGenericInformation, iVendorId, iMandatory, iLength);
}


void setServiceGenericInformationAVP( struct DiamAvp *dmAvp, char *sServiceGenericInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ServiceGenericInformation, sServiceGenericInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 650
* Data Type : OctetString
*/
void addSessionPriorityAVP( struct DiamMessage *dmMessage, char *sSessionPriority, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SessionPriority, sSessionPriority, iVendorId, iMandatory, iLength);
}


void setSessionPriorityAVP( struct DiamAvp *dmAvp, char *sSessionPriority, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SessionPriority, sSessionPriority, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1401
* Data Type : OctetString
*/
void addTerminalInformationAVP( struct DiamMessage *dmMessage, char *sTerminalInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TerminalInformation, sTerminalInformation, iVendorId, iMandatory, iLength);
}


void setTerminalInformationAVP( struct DiamAvp *dmAvp, char *sTerminalInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TerminalInformation, sTerminalInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 900
* Data Type : OctetString
*/
void addTMGIAVP( struct DiamMessage *dmMessage, char *sTMGI, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TMGI, sTMGI, iVendorId, iMandatory, iLength);
}


void setTMGIAVP( struct DiamAvp *dmAvp, char *sTMGI, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TMGI, sTMGI, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2113
* Data Type : OctetString
*/
void addTotalNumberOfMessagesExplodedAVP( struct DiamMessage *dmMessage, char *sTotalNumberOfMessagesExploded, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TotalNumberOfMessagesExploded, sTotalNumberOfMessagesExploded, iVendorId, iMandatory, iLength);
}


void setTotalNumberOfMessagesExplodedAVP( struct DiamAvp *dmAvp, char *sTotalNumberOfMessagesExploded, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TotalNumberOfMessagesExploded, sTotalNumberOfMessagesExploded, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2114
* Data Type : OctetString
*/
void addTotalNumberOfMessagesSentAVP( struct DiamMessage *dmMessage, char *sTotalNumberOfMessagesSent, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TotalNumberOfMessagesSent, sTotalNumberOfMessagesSent, iVendorId, iMandatory, iLength);
}


void setTotalNumberOfMessagesSentAVP( struct DiamAvp *dmAvp, char *sTotalNumberOfMessagesSent, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TotalNumberOfMessagesSent, sTotalNumberOfMessagesSent, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 606
* Data Type : OctetString
*/
void addUserDataAVP( struct DiamMessage *dmMessage, char *sUserData, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_UserData, sUserData, iVendorId, iMandatory, iLength);
}


void setUserDataAVP( struct DiamAvp *dmAvp, char *sUserData, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_UserData, sUserData, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1102
* Data Type : OctetString
*/
void addVASIdAVP( struct DiamMessage *dmMessage, char *sVASId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_VASId, sVASId, iVendorId, iMandatory, iLength);
}


void setVASIdAVP( struct DiamAvp *dmAvp, char *sVASId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_VASId, sVASId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1101
* Data Type : OctetString
*/
void addVASPIdAVP( struct DiamMessage *dmMessage, char *sVASPId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_VASPId, sVASPId, iVendorId, iMandatory, iLength);
}


void setVASPIdAVP( struct DiamAvp *dmAvp, char *sVASPId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_VASPId, sVASPId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2060
* Data Type : Grouped
*/
void setTariffInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_TariffInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1270
* Data Type : Grouped
*/
void setTimeQuotaMechanismAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_TimeQuotaMechanism, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 833
* Data Type : Grouped
*/
void setTimeStampsAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_TimeStamps, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2046
* Data Type : Grouped
*/
void setTrafficDataVolumesAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_TrafficDataVolumes, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1264
* Data Type : Grouped
*/
void setTriggerAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_Trigger, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 851
* Data Type : Grouped
*/
void setTrunkGroupIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_TrunkGroupId, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2061
* Data Type : Grouped
*/
void setUnitCostAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_UnitCost, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 875
* Data Type : Grouped
*/
void setWLANInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_WLANInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 892
* Data Type : Grouped
*/
void setWLANRadioContainerAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_WLANRadioContainer, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 456
* Data Type : Grouped
*/
void setMultipleServicesCreditControlAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_MultipleServicesCreditControl, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 55
* Data Type : Time
*/
void addEventTimestampAVP( struct DiamMessage *dmMessage, char *sEventTimestamp, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_EventTimestamp, sEventTimestamp, iVendorId, iMandatory, iLength);
}


void setEventTimestampAVP( struct DiamAvp *dmAvp, char *sEventTimestamp, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_EventTimestamp, sEventTimestamp, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2038
* Data Type : Time
*/
void addChangeTimeAVP( struct DiamMessage *dmMessage, char *sChangeTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ChangeTime, sChangeTime, iVendorId, iMandatory, iLength);
}


void setChangeTimeAVP( struct DiamAvp *dmAvp, char *sChangeTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ChangeTime, sChangeTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1267
* Data Type : Time
*/
void addEnvelopeEndTimeAVP( struct DiamMessage *dmMessage, char *sEnvelopeEndTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_EnvelopeEndTime, sEnvelopeEndTime, iVendorId, iMandatory, iLength);
}


void setEnvelopeEndTimeAVP( struct DiamAvp *dmAvp, char *sEnvelopeEndTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_EnvelopeEndTime, sEnvelopeEndTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1269
* Data Type : Time
*/
void addEnvelopeStartTimeAVP( struct DiamMessage *dmMessage, char *sEnvelopeStartTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_EnvelopeStartTime, sEnvelopeStartTime, iVendorId, iMandatory, iLength);
}


void setEnvelopeStartTimeAVP( struct DiamAvp *dmAvp, char *sEnvelopeStartTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_EnvelopeStartTime, sEnvelopeStartTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1258
* Data Type : Time
*/
void addEventChargingTimeStampAVP( struct DiamMessage *dmMessage, char *sEventChargingTimeStamp, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_EventChargingTimeStamp, sEventChargingTimeStamp, iVendorId, iMandatory, iLength);
}


void setEventChargingTimeStampAVP( struct DiamAvp *dmAvp, char *sEventChargingTimeStamp, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_EventChargingTimeStamp, sEventChargingTimeStamp, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1262
* Data Type : Time
*/
void addPoCChangeTimeAVP( struct DiamMessage *dmMessage, char *sPoCChangeTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PoCChangeTime, sPoCChangeTime, iVendorId, iMandatory, iLength);
}


void setPoCChangeTimeAVP( struct DiamAvp *dmAvp, char *sPoCChangeTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PoCChangeTime, sPoCChangeTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1275
* Data Type : Time
*/
void addSDPAnswerTimestampAVP( struct DiamMessage *dmMessage, char *sSDPAnswerTimestamp, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SDPAnswerTimestamp, sSDPAnswerTimestamp, iVendorId, iMandatory, iLength);
}


void setSDPAnswerTimestampAVP( struct DiamAvp *dmAvp, char *sSDPAnswerTimestamp, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SDPAnswerTimestamp, sSDPAnswerTimestamp, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1274
* Data Type : Time
*/
void addSDPOfferTimestampAVP( struct DiamMessage *dmMessage, char *sSDPOfferTimestamp, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SDPOfferTimestamp, sSDPOfferTimestamp, iVendorId, iMandatory, iLength);
}


void setSDPOfferTimestampAVP( struct DiamAvp *dmAvp, char *sSDPOfferTimestamp, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SDPOfferTimestamp, sSDPOfferTimestamp, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 834
* Data Type : Time
*/
void addSIPRequestTimestampAVP( struct DiamMessage *dmMessage, char *sSIPRequestTimestamp, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SIPRequestTimestamp, sSIPRequestTimestamp, iVendorId, iMandatory, iLength);
}


void setSIPRequestTimestampAVP( struct DiamAvp *dmAvp, char *sSIPRequestTimestamp, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SIPRequestTimestamp, sSIPRequestTimestamp, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 835
* Data Type : Time
*/
void addSIPResponseTimestampAVP( struct DiamMessage *dmMessage, char *sSIPResponseTimestamp, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SIPResponseTimestamp, sSIPResponseTimestamp, iVendorId, iMandatory, iLength);
}


void setSIPResponseTimestampAVP( struct DiamAvp *dmAvp, char *sSIPResponseTimestamp, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SIPResponseTimestamp, sSIPResponseTimestamp, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2012
* Data Type : Time
*/
void addSMDischargeTimeAVP( struct DiamMessage *dmMessage, char *sSMDischargeTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SMDischargeTime, sSMDischargeTime, iVendorId, iMandatory, iLength);
}


void setSMDischargeTimeAVP( struct DiamAvp *dmAvp, char *sSMDischargeTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SMDischargeTime, sSMDischargeTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2041
* Data Type : Time
*/
void addStartTimeAVP( struct DiamMessage *dmMessage, char *sStartTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_StartTime, sStartTime, iVendorId, iMandatory, iLength);
}


void setStartTimeAVP( struct DiamAvp *dmAvp, char *sStartTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_StartTime, sStartTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2042
* Data Type : Time
*/
void addStopTimeAVP( struct DiamMessage *dmMessage, char *sStopTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_StopTime, sStopTime, iVendorId, iMandatory, iLength);
}


void setStopTimeAVP( struct DiamAvp *dmAvp, char *sStopTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_StopTime, sStopTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1202
* Data Type : Time
*/
void addSubmissionTimeAVP( struct DiamMessage *dmMessage, char *sSubmissionTime, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SubmissionTime, sSubmissionTime, iVendorId, iMandatory, iLength);
}


void setSubmissionTimeAVP( struct DiamAvp *dmAvp, char *sSubmissionTime, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SubmissionTime, sSubmissionTime, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2043
* Data Type : Time
*/
void addTimeFirstUsageAVP( struct DiamMessage *dmMessage, char *sTimeFirstUsage, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TimeFirstUsage, sTimeFirstUsage, iVendorId, iMandatory, iLength);
}


void setTimeFirstUsageAVP( struct DiamAvp *dmAvp, char *sTimeFirstUsage, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TimeFirstUsage, sTimeFirstUsage, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2044
* Data Type : Time
*/
void addTimeLastUsageAVP( struct DiamMessage *dmMessage, char *sTimeLastUsage, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TimeLastUsage, sTimeLastUsage, iVendorId, iMandatory, iLength);
}


void setTimeLastUsageAVP( struct DiamAvp *dmAvp, char *sTimeLastUsage, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TimeLastUsage, sTimeLastUsage, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 257
* Data Type : Address
*/
void addHostIPAddressAVP( struct DiamMessage *dmMessage, char *sHostIPAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_HostIPAddress, sHostIPAddress, iVendorId, iMandatory);
}


void setHostIPAddressAVP( struct DiamAvp *dmAvp, char *sHostIPAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_HostIPAddress, sHostIPAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 846
* Data Type : Address
*/
void addCGAddressAVP( struct DiamMessage *dmMessage, char *sCGAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_CGAddress, sCGAddress, iVendorId, iMandatory);
}


void setCGAddressAVP( struct DiamAvp *dmAvp, char *sCGAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_CGAddress, sCGAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 2018
* Data Type : Address
*/
void addClientAddressAVP( struct DiamMessage *dmMessage, char *sClientAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_ClientAddress, sClientAddress, iVendorId, iMandatory);
}


void setClientAddressAVP( struct DiamAvp *dmAvp, char *sClientAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_ClientAddress, sClientAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 847
* Data Type : Address
*/
void addGGSNAddressAVP( struct DiamMessage *dmMessage, char *sGGSNAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_GGSNAddress, sGGSNAddress, iVendorId, iMandatory);
}


void setGGSNAddressAVP( struct DiamAvp *dmAvp, char *sGGSNAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_GGSNAddress, sGGSNAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 2008
* Data Type : Address
*/
void addOriginatorSCCPAddressAVP( struct DiamMessage *dmMessage, char *sOriginatorSCCPAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_OriginatorSCCPAddress, sOriginatorSCCPAddress, iVendorId, iMandatory);
}


void setOriginatorSCCPAddressAVP( struct DiamAvp *dmAvp, char *sOriginatorSCCPAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_OriginatorSCCPAddress, sOriginatorSCCPAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 895
* Data Type : Address
*/
void addPDGAddressAVP( struct DiamMessage *dmMessage, char *sPDGAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_PDGAddress, sPDGAddress, iVendorId, iMandatory);
}


void setPDGAddressAVP( struct DiamAvp *dmAvp, char *sPDGAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_PDGAddress, sPDGAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 1227
* Data Type : Address
*/
void addPDPAddressAVP( struct DiamMessage *dmMessage, char *sPDPAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_PDPAddress, sPDPAddress, iVendorId, iMandatory);
}


void setPDPAddressAVP( struct DiamAvp *dmAvp, char *sPDPAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_PDPAddress, sPDPAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 2010
* Data Type : Address
*/
void addRecipientSCCPAddressAVP( struct DiamMessage *dmMessage, char *sRecipientSCCPAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_RecipientSCCPAddress, sRecipientSCCPAddress, iVendorId, iMandatory);
}


void setRecipientSCCPAddressAVP( struct DiamAvp *dmAvp, char *sRecipientSCCPAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_RecipientSCCPAddress, sRecipientSCCPAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 848
* Data Type : Address
*/
void addServedPartyIPAddressAVP( struct DiamMessage *dmMessage, char *sServedPartyIPAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_ServedPartyIPAddress, sServedPartyIPAddress, iVendorId, iMandatory);
}


void setServedPartyIPAddressAVP( struct DiamAvp *dmAvp, char *sServedPartyIPAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_ServedPartyIPAddress, sServedPartyIPAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 1228
* Data Type : Address
*/
void addSGSNAddressAVP( struct DiamMessage *dmMessage, char *sSGSNAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_SGSNAddress, sSGSNAddress, iVendorId, iMandatory);
}


void setSGSNAddressAVP( struct DiamAvp *dmAvp, char *sSGSNAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_SGSNAddress, sSGSNAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 2017
* Data Type : Address
*/
void addSMSCAddressAVP( struct DiamMessage *dmMessage, char *sSMSCAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_SMSCAddress, sSMSCAddress, iVendorId, iMandatory);
}


void setSMSCAddressAVP( struct DiamAvp *dmAvp, char *sSMSCAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_SMSCAddress, sSMSCAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 890
* Data Type : Address
*/
void addWAGAddressAVP( struct DiamMessage *dmMessage, char *sWAGAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_WAGAddress, sWAGAddress, iVendorId, iMandatory);
}


void setWAGAddressAVP( struct DiamAvp *dmAvp, char *sWAGAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_WAGAddress, sWAGAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 894
* Data Type : Address
*/
void addWLANUELocalIPAddressAVP( struct DiamMessage *dmMessage, char *sWLANUELocalIPAddress, int iVendorId, int iMandatory)
{
	addAddressAVP( dmMessage, AVP_WLANUELocalIPAddress, sWLANUELocalIPAddress, iVendorId, iMandatory);
}


void setWLANUELocalIPAddressAVP( struct DiamAvp *dmAvp, char *sWLANUELocalIPAddress, int iVendorId, int iMandatory)
{
	setAddressAVP( dmAvp, AVP_WLANUELocalIPAddress, sWLANUELocalIPAddress, iVendorId, iMandatory);
}


/**
* AVP Code : 292
* Data Type : DiamURI
*/
void addRedirectHostAVP( struct DiamMessage *dmMessage, char *sRedirectHost, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_RedirectHost, sRedirectHost, iVendorId, iMandatory, iLength);
}


void setRedirectHostAVP( struct DiamAvp *dmAvp, char *sRedirectHost, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_RedirectHost, sRedirectHost, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 861
* Data Type : Integer32
*/
void addCauseCodeAVP( struct DiamMessage *dmMessage, int iCauseCode, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_CauseCode, iCauseCode, iVendorId, iMandatory);
}


void setCauseCodeAVP( struct DiamAvp *dmAvp, int iCauseCode, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_CauseCode, iCauseCode, iVendorId, iMandatory);
}


/**
* AVP Code : 2037
* Data Type : Integer32
*/
void addChangeConditionAVP( struct DiamMessage *dmMessage, int iChangeCondition, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ChangeCondition, iChangeCondition, iVendorId, iMandatory);
}


void setChangeConditionAVP( struct DiamAvp *dmAvp, int iChangeCondition, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ChangeCondition, iChangeCondition, iVendorId, iMandatory);
}


/**
* AVP Code : 2001
* Data Type : Integer32
*/
void addDataCodingSchemeAVP( struct DiamMessage *dmMessage, int iDataCodingScheme, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_DataCodingScheme, iDataCodingScheme, iVendorId, iMandatory);
}


void setDataCodingSchemeAVP( struct DiamAvp *dmAvp, int iDataCodingScheme, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_DataCodingScheme, iDataCodingScheme, iVendorId, iMandatory);
}


/**
* AVP Code : 2039
* Data Type : Integer32
*/
void addDiagnosticsAVP( struct DiamMessage *dmMessage, int iDiagnostics, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_Diagnostics, iDiagnostics, iVendorId, iMandatory);
}


void setDiagnosticsAVP( struct DiamAvp *dmAvp, int iDiagnostics, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_Diagnostics, iDiagnostics, iVendorId, iMandatory);
}


/**
* AVP Code : 13
* Data Type : OctetString
*/
void addTGPPChargingCharacteristicsAVP( struct DiamMessage *dmMessage, char *sTGPPChargingCharacteristics, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPChargingCharacteristics, sTGPPChargingCharacteristics, iVendorId, iMandatory, iLength);
}


void setTGPPChargingCharacteristicsAVP( struct DiamAvp *dmAvp, char *sTGPPChargingCharacteristics, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPChargingCharacteristics, sTGPPChargingCharacteristics, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2
* Data Type : OctetString
*/
void addTGPPChargingIdAVP( struct DiamMessage *dmMessage, char *sTGPPChargingId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPChargingId, sTGPPChargingId, iVendorId, iMandatory, iLength);
}


void setTGPPChargingIdAVP( struct DiamAvp *dmAvp, char *sTGPPChargingId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPChargingId, sTGPPChargingId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 9
* Data Type : OctetString
*/
void addTGPPGGSNMCCMNCAVP( struct DiamMessage *dmMessage, char *sTGPPGGSNMCCMNC, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPGGSNMCCMNC, sTGPPGGSNMCCMNC, iVendorId, iMandatory, iLength);
}


void setTGPPGGSNMCCMNCAVP( struct DiamAvp *dmAvp, char *sTGPPGGSNMCCMNC, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPGGSNMCCMNC, sTGPPGGSNMCCMNC, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 8
* Data Type : OctetString
*/
void addTGPPIMSIMCCMNCAVP( struct DiamMessage *dmMessage, char *sTGPPIMSIMCCMNC, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPIMSIMCCMNC, sTGPPIMSIMCCMNC, iVendorId, iMandatory, iLength);
}


void setTGPPIMSIMCCMNCAVP( struct DiamAvp *dmAvp, char *sTGPPIMSIMCCMNC, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPIMSIMCCMNC, sTGPPIMSIMCCMNC, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 23
* Data Type : OctetString
*/
void addTGPPMSTimeZoneAVP( struct DiamMessage *dmMessage, char *sTGPPMSTimeZone, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPMSTimeZone, sTGPPMSTimeZone, iVendorId, iMandatory, iLength);
}


void setTGPPMSTimeZoneAVP( struct DiamAvp *dmAvp, char *sTGPPMSTimeZone, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPMSTimeZone, sTGPPMSTimeZone, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 10
* Data Type : OctetString
*/
void addTGPPNSAPIAVP( struct DiamMessage *dmMessage, char *sTGPPNSAPI, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPNSAPI, sTGPPNSAPI, iVendorId, iMandatory, iLength);
}


void setTGPPNSAPIAVP( struct DiamAvp *dmAvp, char *sTGPPNSAPI, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPNSAPI, sTGPPNSAPI, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 3
* Data Type : OctetString
*/
void addTGPPPDPTypeAVP( struct DiamMessage *dmMessage, char *sTGPPPDPType, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPPDPType, sTGPPPDPType, iVendorId, iMandatory, iLength);
}


void setTGPPPDPTypeAVP( struct DiamAvp *dmAvp, char *sTGPPPDPType, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPPDPType, sTGPPPDPType, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 21
* Data Type : OctetString
*/
void addTGPPRATTypeAVP( struct DiamMessage *dmMessage, char *sTGPPRATType, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPRATType, sTGPPRATType, iVendorId, iMandatory, iLength);
}


void setTGPPRATTypeAVP( struct DiamAvp *dmAvp, char *sTGPPRATType, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPRATType, sTGPPRATType, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 12
* Data Type : OctetString
*/
void addTGPPSelectionModeAVP( struct DiamMessage *dmMessage, char *sTGPPSelectionMode, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPSelectionMode, sTGPPSelectionMode, iVendorId, iMandatory, iLength);
}


void setTGPPSelectionModeAVP( struct DiamAvp *dmAvp, char *sTGPPSelectionMode, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPSelectionMode, sTGPPSelectionMode, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 11
* Data Type : OctetString
*/
void addTGPPSessionStopIndicatorAVP( struct DiamMessage *dmMessage, char *sTGPPSessionStopIndicator, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPSessionStopIndicator, sTGPPSessionStopIndicator, iVendorId, iMandatory, iLength);
}


void setTGPPSessionStopIndicatorAVP( struct DiamAvp *dmAvp, char *sTGPPSessionStopIndicator, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPSessionStopIndicator, sTGPPSessionStopIndicator, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 18
* Data Type : OctetString
*/
void addTGPPSGSNMCCMNCAVP( struct DiamMessage *dmMessage, char *sTGPPSGSNMCCMNC, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPSGSNMCCMNC, sTGPPSGSNMCCMNC, iVendorId, iMandatory, iLength);
}


void setTGPPSGSNMCCMNCAVP( struct DiamAvp *dmAvp, char *sTGPPSGSNMCCMNC, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPSGSNMCCMNC, sTGPPSGSNMCCMNC, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 22
* Data Type : OctetString
*/
void addTGPPUserLocationInfoAVP( struct DiamMessage *dmMessage, char *sTGPPUserLocationInfo, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPPUserLocationInfo, sTGPPUserLocationInfo, iVendorId, iMandatory, iLength);
}


void setTGPPUserLocationInfoAVP( struct DiamAvp *dmAvp, char *sTGPPUserLocationInfo, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPPUserLocationInfo, sTGPPUserLocationInfo, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 5535
* Data Type : OctetString
*/
void addTGPP2BSIDAVP( struct DiamMessage *dmMessage, char *sTGPP2BSID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TGPP2BSID, sTGPP2BSID, iVendorId, iMandatory, iLength);
}


void setTGPP2BSIDAVP( struct DiamAvp *dmAvp, char *sTGPP2BSID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TGPP2BSID, sTGPP2BSID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 503
* Data Type : OctetString
*/
void addAccessNetworkChargingIdentifierValueAVP( struct DiamMessage *dmMessage, char *sAccessNetworkChargingIdentifierValue, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AccessNetworkChargingIdentifierValue, sAccessNetworkChargingIdentifierValue, iVendorId, iMandatory, iLength);
}


void setAccessNetworkChargingIdentifierValueAVP( struct DiamAvp *dmAvp, char *sAccessNetworkChargingIdentifierValue, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AccessNetworkChargingIdentifierValue, sAccessNetworkChargingIdentifierValue, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 505
* Data Type : OctetString
*/
void addAFChargingIdentifierAVP( struct DiamMessage *dmMessage, char *sAFChargingIdentifier, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AFChargingIdentifier, sAFChargingIdentifier, iVendorId, iMandatory, iLength);
}


void setAFChargingIdentifierAVP( struct DiamAvp *dmAvp, char *sAFChargingIdentifier, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AFChargingIdentifier, sAFChargingIdentifier, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1034
* Data Type : OctetString
*/
void addAllocationRetentionPriorityAVP( struct DiamMessage *dmMessage, char *sAllocationRetentionPriority, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AllocationRetentionPriority, sAllocationRetentionPriority, iVendorId, iMandatory, iLength);
}


void setAllocationRetentionPriorityAVP( struct DiamAvp *dmAvp, char *sAllocationRetentionPriority, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AllocationRetentionPriority, sAllocationRetentionPriority, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2101
* Data Type : OctetString
*/
void addApplicationServerIDAVP( struct DiamMessage *dmMessage, char *sApplicationServerID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ApplicationServerID, sApplicationServerID, iVendorId, iMandatory, iLength);
}


void setApplicationServerIDAVP( struct DiamAvp *dmAvp, char *sApplicationServerID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ApplicationServerID, sApplicationServerID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2102
* Data Type : OctetString
*/
void addApplicationServiceTypeAVP( struct DiamMessage *dmMessage, char *sApplicationServiceType, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ApplicationServiceType, sApplicationServiceType, iVendorId, iMandatory, iLength);
}


void setApplicationServiceTypeAVP( struct DiamAvp *dmAvp, char *sApplicationServiceType, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ApplicationServiceType, sApplicationServiceType, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2103
* Data Type : OctetString
*/
void addApplicationSessionIDAVP( struct DiamMessage *dmMessage, char *sApplicationSessionID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ApplicationSessionID, sApplicationSessionID, iVendorId, iMandatory, iLength);
}


void setApplicationSessionIDAVP( struct DiamAvp *dmAvp, char *sApplicationSessionID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ApplicationSessionID, sApplicationSessionID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1004
* Data Type : OctetString
*/
void addChargingRuleBaseNameAVP( struct DiamMessage *dmMessage, char *sChargingRuleBaseName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ChargingRuleBaseName, sChargingRuleBaseName, iVendorId, iMandatory, iLength);
}


void setChargingRuleBaseNameAVP( struct DiamAvp *dmAvp, char *sChargingRuleBaseName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ChargingRuleBaseName, sChargingRuleBaseName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 294
* Data Type : DiameterIdentity
*/
void addErrorReportingHostAVP( struct DiamMessage *dmMessage, char *sErrorReportingHost, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ErrorReportingHost, sErrorReportingHost, iVendorId, iMandatory, iLength);
}


void setErrorReportingHostAVP( struct DiamAvp *dmAvp, char *sErrorReportingHost, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ErrorReportingHost, sErrorReportingHost, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 264
* Data Type : DiameterIdentity
*/
void addOriginHostAVP( struct DiamMessage *dmMessage, char *sOriginHost, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_OriginHost, sOriginHost, iVendorId, iMandatory, iLength);
}


void setOriginHostAVP( struct DiamAvp *dmAvp, char *sOriginHost, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_OriginHost, sOriginHost, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 296
* Data Type : DiameterIdentity
*/
void addOriginRealmAVP( struct DiamMessage *dmMessage, char *sOriginRealm, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_OriginRealm, sOriginRealm, iVendorId, iMandatory, iLength);
}


void setOriginRealmAVP( struct DiamAvp *dmAvp, char *sOriginRealm, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_OriginRealm, sOriginRealm, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 280
* Data Type : DiameterIdentity
*/
void addProxyHostAVP( struct DiamMessage *dmMessage, char *sProxyHost, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ProxyHost, sProxyHost, iVendorId, iMandatory, iLength);
}


void setProxyHostAVP( struct DiamAvp *dmAvp, char *sProxyHost, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ProxyHost, sProxyHost, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 282
* Data Type : DiameterIdentity
*/
void addRouteRecordAVP( struct DiamMessage *dmMessage, char *sRouteRecord, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_RouteRecord, sRouteRecord, iVendorId, iMandatory, iLength);
}


void setRouteRecordAVP( struct DiamAvp *dmAvp, char *sRouteRecord, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_RouteRecord, sRouteRecord, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 300
* Data Type : Grouped
*/
void setE2ESequenceAVPAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_E2ESequenceAVP, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 297
* Data Type : Grouped
*/
void setExperimentalResultAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ExperimentalResult, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 279
* Data Type : Grouped
*/
void setFailedAVPAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_FailedAVP, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 284
* Data Type : Grouped
*/
void setProxyInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ProxyInfo, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 443
* Data Type : Grouped
*/
void setSubscriptionIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_SubscriptionId, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 260
* Data Type : Grouped
*/
void setVendorSpecificApplicationIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_VendorSpecificApplicationId, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 437
* Data Type : Grouped
*/
void setRequestedServiceUnitAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_RequestedServiceUnit, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 446
* Data Type : Grouped
*/
void setUsedServiceUnitAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_UsedServiceUnit, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 440
* Data Type : Grouped
*/
void setServiceParameterInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ServiceParameterInfo, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 458
* Data Type : Grouped
*/
void setUserEquipmentInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_UserEquipmentInfo, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2052
* Data Type : Grouped
*/
void setAccumulatedCostAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_AccumulatedCost, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1207
* Data Type : Grouped
*/
void setAdditionalContentInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_AdditionalContentInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 898
* Data Type : Grouped
*/
void setAddressDomainAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_AddressDomain, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1276
* Data Type : Grouped
*/
void setAFCorrelationInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_AFCorrelationInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2053
* Data Type : Grouped
*/
void setAoCCostInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_AoCCostInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2054
* Data Type : Grouped
*/
void setAoCInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_AoCInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 850
* Data Type : Grouped
*/
void setApplicationServerInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ApplicationServerInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2056
* Data Type : Grouped
*/
void setCurrentTariffAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_CurrentTariff, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2002
* Data Type : Grouped
*/
void setDestinationInterfaceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_DestinationInterface, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1272
* Data Type : Grouped
*/
void setEarlyMediaDescriptionAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_EarlyMediaDescription, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1266
* Data Type : Grouped
*/
void setEnvelopeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_Envelope, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 823
* Data Type : Grouped
*/
void setEventTypeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_EventType, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 876
* Data Type : Grouped
*/
void setIMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_IMSInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2062
* Data Type : Grouped
*/
void setIncrementalCostAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_IncrementalCost, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 838
* Data Type : Grouped
*/
void setInterOperatorIdentifierAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_InterOperatorIdentifier, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1232
* Data Type : Grouped
*/
void setLCSClientIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_LCSClientId, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 878
* Data Type : Grouped
*/
void setLCSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_LCSInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1239
* Data Type : Grouped
*/
void setLCSRequestorIdAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_LCSRequestorId, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1244
* Data Type : Grouped
*/
void setLocationTypeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_LocationType, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 880
* Data Type : Grouped
*/
void setMBMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_MBMSInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 889
* Data Type : Grouped
*/
void setMessageBodyAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_MessageBody, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1213
* Data Type : Grouped
*/
void setMessageClassAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_MessageClass, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1203
* Data Type : Grouped
*/
void setMMContentTypeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_MMContentType, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 877
* Data Type : Grouped
*/
void setMMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_MMSInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2030
* Data Type : Grouped
*/
void setMMTelInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_MMTelInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2057
* Data Type : Grouped
*/
void setNextTariffAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_NextTariff, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1278
* Data Type : Grouped
*/
void setOfflineChargingAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_OfflineCharging, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 886
* Data Type : Grouped
*/
void setOriginatorAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_OriginatorAddress, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2027
* Data Type : Grouped
*/
void setOriginatorReceivedAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_OriginatorReceivedAddress, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2009
* Data Type : Grouped
*/
void setOriginatorInterfaceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_OriginatorInterface, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1260
* Data Type : Grouped
*/
void setParticipantGroupAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ParticipantGroup, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 879
* Data Type : Grouped
*/
void setPoCInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_PoCInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1252
* Data Type : Grouped
*/
void setPoCUserRoleAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_PoCUserRole, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 865
* Data Type : Grouped
*/
void setPSFurnishChargingInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_PSFurnishChargingInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 874
* Data Type : Grouped
*/
void setPSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_PSInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2058
* Data Type : Grouped
*/
void setRateElementAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_RateElement, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1201
* Data Type : Grouped
*/
void setRecipientAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_RecipientAddress, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2026
* Data Type : Grouped
*/
void setRecipientInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_RecipientInfo, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2028
* Data Type : Grouped
*/
void setRecipientReceivedAddressAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_RecipientReceivedAddress, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2021
* Data Type : Grouped
*/
void setRemainingBalanceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_RemainingBalance, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2059
* Data Type : Grouped
*/
void setScaleFactorAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ScaleFactor, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 843
* Data Type : Grouped
*/
void setSDPMediaComponentAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_SDPMediaComponent, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1273
* Data Type : Grouped
*/
void setSDPTimeStampsAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_SDPTimeStamps, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2040
* Data Type : Grouped
*/
void setServiceDataContainerAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ServiceDataContainer, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 873
* Data Type : Grouped
*/
void setServiceInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ServiceInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1249
* Data Type : Grouped
*/
void setServiceSpecificInfoAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_ServiceSpecificInfo, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2000
* Data Type : Grouped
*/
void setSMSInformationAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_SMSInformation, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2048
* Data Type : Grouped
*/
void setSupplementaryServiceAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_SupplementaryService, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 1255
* Data Type : Grouped
*/
void setTalkBurstExchangeAVP( struct DiamMessage *dmMessage, struct DiamAvp *dmAvp, int iVendorId, int iMandatory)
{
	setGroupedAVP( dmMessage, AVP_TalkBurstExchange, dmAvp, iVendorId, iMandatory);
}


/**
* AVP Code : 2023
* Data Type : UTF8String
*/
void addCarrierSelectRoutingInformationAVP( struct DiamMessage *dmMessage, char *sCarrierSelectRoutingInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_CarrierSelectRoutingInformation, sCarrierSelectRoutingInformation, iVendorId, iMandatory, iLength);
}


void setCarrierSelectRoutingInformationAVP( struct DiamAvp *dmAvp, char *sCarrierSelectRoutingInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_CarrierSelectRoutingInformation, sCarrierSelectRoutingInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 857
* Data Type : UTF8String
*/
void addChargedPartyAVP( struct DiamMessage *dmMessage, char *sChargedParty, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ChargedParty, sChargedParty, iVendorId, iMandatory, iLength);
}


void setChargedPartyAVP( struct DiamAvp *dmAvp, char *sChargedParty, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ChargedParty, sChargedParty, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 828
* Data Type : UTF8String
*/
void addContentDispositionAVP( struct DiamMessage *dmMessage, char *sContentDisposition, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ContentDisposition, sContentDisposition, iVendorId, iMandatory, iLength);
}


void setContentDispositionAVP( struct DiamAvp *dmAvp, char *sContentDisposition, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ContentDisposition, sContentDisposition, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 826
* Data Type : UTF8String
*/
void addContentTypeAVP( struct DiamMessage *dmMessage, char *sContentType, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ContentType, sContentType, iVendorId, iMandatory, iLength);
}


void setContentTypeAVP( struct DiamAvp *dmAvp, char *sContentType, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ContentType, sContentType, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1230
* Data Type : UTF8String
*/
void addDeferredLocationEventTypeAVP( struct DiamMessage *dmMessage, char *sDeferredLocationEventType, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_DeferredLocationEventType, sDeferredLocationEventType, iVendorId, iMandatory, iLength);
}


void setDeferredLocationEventTypeAVP( struct DiamAvp *dmAvp, char *sDeferredLocationEventType, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_DeferredLocationEventType, sDeferredLocationEventType, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1200
* Data Type : UTF8String
*/
void addDomainNameAVP( struct DiamMessage *dmMessage, char *sDomainName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_DomainName, sDomainName, iVendorId, iMandatory, iLength);
}


void setDomainNameAVP( struct DiamAvp *dmAvp, char *sDomainName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_DomainName, sDomainName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 825
* Data Type : UTF8String
*/
void addEventAVP( struct DiamMessage *dmMessage, char *sEvent, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_Event, sEvent, iVendorId, iMandatory, iLength);
}


void setEventAVP( struct DiamAvp *dmAvp, char *sEvent, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_Event, sEvent, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 841
* Data Type : UTF8String
*/
void addIMSChargingIdentifierAVP( struct DiamMessage *dmMessage, char *sIMSChargingIdentifier, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_IMSChargingIdentifier, sIMSChargingIdentifier, iVendorId, iMandatory, iLength);
}


void setIMSChargingIdentifierAVP( struct DiamAvp *dmAvp, char *sIMSChargingIdentifier, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_IMSChargingIdentifier, sIMSChargingIdentifier, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1281
* Data Type : UTF8String
*/
void addIMSCommunicationServiceIdentifierAVP( struct DiamMessage *dmMessage, char *sIMSCommunicationServiceIdentifier, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_IMSCommunicationServiceIdentifier, sIMSCommunicationServiceIdentifier, iVendorId, iMandatory, iLength);
}


void setIMSCommunicationServiceIdentifierAVP( struct DiamAvp *dmAvp, char *sIMSCommunicationServiceIdentifier, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_IMSCommunicationServiceIdentifier, sIMSCommunicationServiceIdentifier, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 852
* Data Type : UTF8String
*/
void addIncomingTrunkGroupIdAVP( struct DiamMessage *dmMessage, char *sIncomingTrunkGroupId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_IncomingTrunkGroupId, sIncomingTrunkGroupId, iVendorId, iMandatory, iLength);
}


void setIncomingTrunkGroupIdAVP( struct DiamAvp *dmAvp, char *sIncomingTrunkGroupId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_IncomingTrunkGroupId, sIncomingTrunkGroupId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2003
* Data Type : UTF8String
*/
void addInterfaceIdAVP( struct DiamMessage *dmMessage, char *sInterfaceId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_InterfaceId, sInterfaceId, iVendorId, iMandatory, iLength);
}


void setInterfaceIdAVP( struct DiamAvp *dmAvp, char *sInterfaceId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_InterfaceId, sInterfaceId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2004
* Data Type : UTF8String
*/
void addInterfacePortAVP( struct DiamMessage *dmMessage, char *sInterfacePort, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_InterfacePort, sInterfacePort, iVendorId, iMandatory, iLength);
}


void setInterfacePortAVP( struct DiamAvp *dmAvp, char *sInterfacePort, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_InterfacePort, sInterfacePort, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2005
* Data Type : UTF8String
*/
void addInterfaceTextAVP( struct DiamMessage *dmMessage, char *sInterfaceText, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_InterfaceText, sInterfaceText, iVendorId, iMandatory, iLength);
}


void setInterfaceTextAVP( struct DiamAvp *dmAvp, char *sInterfaceText, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_InterfaceText, sInterfaceText, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1233
* Data Type : UTF8String
*/
void addLCSClientDialedByMSAVP( struct DiamMessage *dmMessage, char *sLCSClientDialedByMS, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_LCSClientDialedByMS, sLCSClientDialedByMS, iVendorId, iMandatory, iLength);
}


void setLCSClientDialedByMSAVP( struct DiamAvp *dmAvp, char *sLCSClientDialedByMS, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_LCSClientDialedByMS, sLCSClientDialedByMS, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1234
* Data Type : UTF8String
*/
void addLCSClientExternalIDAVP( struct DiamMessage *dmMessage, char *sLCSClientExternalID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_LCSClientExternalID, sLCSClientExternalID, iVendorId, iMandatory, iLength);
}


void setLCSClientExternalIDAVP( struct DiamAvp *dmAvp, char *sLCSClientExternalID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_LCSClientExternalID, sLCSClientExternalID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1231
* Data Type : UTF8String
*/
void addLCSClientNameAVP( struct DiamMessage *dmMessage, char *sLCSClientName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_LCSClientName, sLCSClientName, iVendorId, iMandatory, iLength);
}


void setLCSClientNameAVP( struct DiamAvp *dmAvp, char *sLCSClientName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_LCSClientName, sLCSClientName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1236
* Data Type : UTF8String
*/
void addLCSDataCodingSchemeAVP( struct DiamMessage *dmMessage, char *sLCSDataCodingScheme, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_LCSDataCodingScheme, sLCSDataCodingScheme, iVendorId, iMandatory, iLength);
}


void setLCSDataCodingSchemeAVP( struct DiamAvp *dmAvp, char *sLCSDataCodingScheme, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_LCSDataCodingScheme, sLCSDataCodingScheme, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1238
* Data Type : UTF8String
*/
void addLCSNameStringAVP( struct DiamMessage *dmMessage, char *sLCSNameString, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_LCSNameString, sLCSNameString, iVendorId, iMandatory, iLength);
}


void setLCSNameStringAVP( struct DiamAvp *dmAvp, char *sLCSNameString, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_LCSNameString, sLCSNameString, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1240
* Data Type : UTF8String
*/
void addLCSRequestorIdStringAVP( struct DiamMessage *dmMessage, char *sLCSRequestorIdString, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_LCSRequestorIdString, sLCSRequestorIdString, iVendorId, iMandatory, iLength);
}


void setLCSRequestorIdStringAVP( struct DiamAvp *dmAvp, char *sLCSRequestorIdString, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_LCSRequestorIdString, sLCSRequestorIdString, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1242
* Data Type : UTF8String
*/
void addLocationEstimateAVP( struct DiamMessage *dmMessage, char *sLocationEstimate, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_LocationEstimate, sLocationEstimate, iVendorId, iMandatory, iLength);
}


void setLocationEstimateAVP( struct DiamAvp *dmAvp, char *sLocationEstimate, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_LocationEstimate, sLocationEstimate, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1288
* Data Type : UTF8String
*/
void addMediaInitiatorPartyAVP( struct DiamMessage *dmMessage, char *sMediaInitiatorParty, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MediaInitiatorParty, sMediaInitiatorParty, iVendorId, iMandatory, iLength);
}


void setMediaInitiatorPartyAVP( struct DiamAvp *dmAvp, char *sMediaInitiatorParty, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MediaInitiatorParty, sMediaInitiatorParty, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1210
* Data Type : UTF8String
*/
void addMessageIDAVP( struct DiamMessage *dmMessage, char *sMessageID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_MessageID, sMessageID, iVendorId, iMandatory, iLength);
}


void setMessageIDAVP( struct DiamAvp *dmAvp, char *sMessageID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_MessageID, sMessageID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2064
* Data Type : UTF8String
*/
void addNodeIdAVP( struct DiamMessage *dmMessage, char *sNodeId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_NodeId, sNodeId, iVendorId, iMandatory, iLength);
}


void setNodeIdAVP( struct DiamAvp *dmAvp, char *sNodeId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_NodeId, sNodeId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2024
* Data Type : UTF8String
*/
void addNumberPortabilityRoutingInformationAVP( struct DiamMessage *dmMessage, char *sNumberPortabilityRoutingInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_NumberPortabilityRoutingInformation, sNumberPortabilityRoutingInformation, iVendorId, iMandatory, iLength);
}


void setNumberPortabilityRoutingInformationAVP( struct DiamAvp *dmAvp, char *sNumberPortabilityRoutingInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_NumberPortabilityRoutingInformation, sNumberPortabilityRoutingInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 839
* Data Type : UTF8String
*/
void addOriginatingIOIAVP( struct DiamMessage *dmMessage, char *sOriginatingIOI, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_OriginatingIOI, sOriginatingIOI, iVendorId, iMandatory, iLength);
}


void setOriginatingIOIAVP( struct DiamAvp *dmAvp, char *sOriginatingIOI, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_OriginatingIOI, sOriginatingIOI, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 853
* Data Type : UTF8String
*/
void addOutgoingTrunkGroupIdAVP( struct DiamMessage *dmMessage, char *sOutgoingTrunkGroupId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_OutgoingTrunkGroupId, sOutgoingTrunkGroupId, iVendorId, iMandatory, iLength);
}


void setOutgoingTrunkGroupIdAVP( struct DiamAvp *dmAvp, char *sOutgoingTrunkGroupId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_OutgoingTrunkGroupId, sOutgoingTrunkGroupId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 887
* Data Type : UTF8String
*/
void addParticipantsInvolvedAVP( struct DiamMessage *dmMessage, char *sParticipantsInvolved, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ParticipantsInvolved, sParticipantsInvolved, iVendorId, iMandatory, iLength);
}


void setParticipantsInvolvedAVP( struct DiamAvp *dmAvp, char *sParticipantsInvolved, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ParticipantsInvolved, sParticipantsInvolved, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 858
* Data Type : UTF8String
*/
void addPoCControllingAddressAVP( struct DiamMessage *dmMessage, char *sPoCControllingAddress, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PoCControllingAddress, sPoCControllingAddress, iVendorId, iMandatory, iLength);
}


void setPoCControllingAddressAVP( struct DiamAvp *dmAvp, char *sPoCControllingAddress, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PoCControllingAddress, sPoCControllingAddress, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 859
* Data Type : UTF8String
*/
void addPoCGroupNameAVP( struct DiamMessage *dmMessage, char *sPoCGroupName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PoCGroupName, sPoCGroupName, iVendorId, iMandatory, iLength);
}


void setPoCGroupNameAVP( struct DiamAvp *dmAvp, char *sPoCGroupName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PoCGroupName, sPoCGroupName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1229
* Data Type : UTF8String
*/
void addPoCSessionIdAVP( struct DiamMessage *dmMessage, char *sPoCSessionId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PoCSessionId, sPoCSessionId, iVendorId, iMandatory, iLength);
}


void setPoCSessionIdAVP( struct DiamAvp *dmAvp, char *sPoCSessionId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PoCSessionId, sPoCSessionId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1253
* Data Type : UTF8String
*/
void addPoCUserRoleIDsAVP( struct DiamMessage *dmMessage, char *sPoCUserRoleIDs, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PoCUserRoleIDs, sPoCUserRoleIDs, iVendorId, iMandatory, iLength);
}


void setPoCUserRoleIDsAVP( struct DiamAvp *dmAvp, char *sPoCUserRoleIDs, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PoCUserRoleIDs, sPoCUserRoleIDs, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1245
* Data Type : UTF8String
*/
void addPositioningDataAVP( struct DiamMessage *dmMessage, char *sPositioningData, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PositioningData, sPositioningData, iVendorId, iMandatory, iLength);
}


void setPositioningDataAVP( struct DiamAvp *dmAvp, char *sPositioningData, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PositioningData, sPositioningData, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1223
* Data Type : UTF8String
*/
void addReplyApplicIDAVP( struct DiamMessage *dmMessage, char *sReplyApplicID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ReplyApplicID, sReplyApplicID, iVendorId, iMandatory, iLength);
}


void setReplyApplicIDAVP( struct DiamAvp *dmAvp, char *sReplyApplicID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ReplyApplicID, sReplyApplicID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1251
* Data Type : UTF8String
*/
void addRequestedPartyAddressAVP( struct DiamMessage *dmMessage, char *sRequestedPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_RequestedPartyAddress, sRequestedPartyAddress, iVendorId, iMandatory, iLength);
}


void setRequestedPartyAddressAVP( struct DiamAvp *dmAvp, char *sRequestedPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_RequestedPartyAddress, sRequestedPartyAddress, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 845
* Data Type : UTF8String
*/
void addSDPMediaDescriptionAVP( struct DiamMessage *dmMessage, char *sSDPMediaDescription, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SDPMediaDescription, sSDPMediaDescription, iVendorId, iMandatory, iLength);
}


void setSDPMediaDescriptionAVP( struct DiamAvp *dmAvp, char *sSDPMediaDescription, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SDPMediaDescription, sSDPMediaDescription, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 844
* Data Type : UTF8String
*/
void addSDPMediaNameAVP( struct DiamMessage *dmMessage, char *sSDPMediaName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SDPMediaName, sSDPMediaName, iVendorId, iMandatory, iLength);
}


void setSDPMediaNameAVP( struct DiamAvp *dmAvp, char *sSDPMediaName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SDPMediaName, sSDPMediaName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 842
* Data Type : UTF8String
*/
void addSDPSessionDescriptionAVP( struct DiamMessage *dmMessage, char *sSDPSessionDescription, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SDPSessionDescription, sSDPSessionDescription, iVendorId, iMandatory, iLength);
}


void setSDPSessionDescriptionAVP( struct DiamAvp *dmAvp, char *sSDPSessionDescription, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SDPSessionDescription, sSDPSessionDescription, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 855
* Data Type : UTF8String
*/
void addServiceIdAVP( struct DiamMessage *dmMessage, char *sServiceId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ServiceId, sServiceId, iVendorId, iMandatory, iLength);
}


void setServiceIdAVP( struct DiamAvp *dmAvp, char *sServiceId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ServiceId, sServiceId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 863
* Data Type : UTF8String
*/
void addServiceSpecificDataAVP( struct DiamMessage *dmMessage, char *sServiceSpecificData, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ServiceSpecificData, sServiceSpecificData, iVendorId, iMandatory, iLength);
}


void setServiceSpecificDataAVP( struct DiamAvp *dmAvp, char *sServiceSpecificData, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ServiceSpecificData, sServiceSpecificData, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 824
* Data Type : UTF8String
*/
void addSIPMethodAVP( struct DiamMessage *dmMessage, char *sSIPMethod, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SIPMethod, sSIPMethod, iVendorId, iMandatory, iLength);
}


void setSIPMethodAVP( struct DiamAvp *dmAvp, char *sSIPMethod, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SIPMethod, sSIPMethod, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 840
* Data Type : UTF8String
*/
void addTerminatingIOIAVP( struct DiamMessage *dmMessage, char *sTerminatingIOI, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TerminatingIOI, sTerminatingIOI, iVendorId, iMandatory, iLength);
}


void setTerminatingIOIAVP( struct DiamAvp *dmAvp, char *sTerminatingIOI, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TerminatingIOI, sTerminatingIOI, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1215
* Data Type : UTF8String
*/
void addTokenTextAVP( struct DiamMessage *dmMessage, char *sTokenText, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_TokenText, sTokenText, iVendorId, iMandatory, iLength);
}


void setTokenTextAVP( struct DiamAvp *dmAvp, char *sTokenText, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_TokenText, sTokenText, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 830
* Data Type : UTF8String
*/
void addUserSessionIdAVP( struct DiamMessage *dmMessage, char *sUserSessionId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_UserSessionId, sUserSessionId, iVendorId, iMandatory, iLength);
}


void setUserSessionIdAVP( struct DiamAvp *dmAvp, char *sUserSessionId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_UserSessionId, sUserSessionId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1246
* Data Type : UTF8String
*/
void addWLANSessionIdAVP( struct DiamMessage *dmMessage, char *sWLANSessionId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_WLANSessionId, sWLANSessionId, iVendorId, iMandatory, iLength);
}


void setWLANSessionIdAVP( struct DiamAvp *dmAvp, char *sWLANSessionId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_WLANSessionId, sWLANSessionId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 444
* Data Type : UTF8String
*/
void addSubscriptionIdDataAVP( struct DiamMessage *dmMessage, char *sSubscriptionIdData, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SubscriptionIdData, sSubscriptionIdData, iVendorId, iMandatory, iLength);
}


void setSubscriptionIdDataAVP( struct DiamAvp *dmAvp, char *sSubscriptionIdData, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SubscriptionIdData, sSubscriptionIdData, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 44
* Data Type : OctetString
*/
void addAccountingSessionIdAVP( struct DiamMessage *dmMessage, char *sAccountingSessionId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AccountingSessionId, sAccountingSessionId, iVendorId, iMandatory, iLength);
}


void setAccountingSessionIdAVP( struct DiamAvp *dmAvp, char *sAccountingSessionId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AccountingSessionId, sAccountingSessionId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 25
* Data Type : OctetString
*/
void addClassAVP( struct DiamMessage *dmMessage, char *sClass, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_Class, sClass, iVendorId, iMandatory, iLength);
}


void setClassAVP( struct DiamAvp *dmAvp, char *sClass, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_Class, sClass, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 33
* Data Type : OctetString
*/
void addProxyStateAVP( struct DiamMessage *dmMessage, char *sProxyState, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ProxyState, sProxyState, iVendorId, iMandatory, iLength);
}


void setProxyStateAVP( struct DiamAvp *dmAvp, char *sProxyState, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ProxyState, sProxyState, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 411
* Data Type : OctetString
*/
void addCCCorrelationIdAVP( struct DiamMessage *dmMessage, char *sCCCorrelationId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_CCCorrelationId, sCCCorrelationId, iVendorId, iMandatory, iLength);
}


void setCCCorrelationIdAVP( struct DiamAvp *dmAvp, char *sCCCorrelationId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_CCCorrelationId, sCCCorrelationId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1263
* Data Type : OctetString
*/
void addAccessNetworkInformationAVP( struct DiamMessage *dmMessage, char *sAccessNetworkInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AccessNetworkInformation, sAccessNetworkInformation, iVendorId, iMandatory, iLength);
}


void setAccessNetworkInformationAVP( struct DiamAvp *dmAvp, char *sAccessNetworkInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AccessNetworkInformation, sAccessNetworkInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 854
* Data Type : OctetString
*/
void addBearerServiceAVP( struct DiamMessage *dmMessage, char *sBearerService, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_BearerService, sBearerService, iVendorId, iMandatory, iLength);
}


void setBearerServiceAVP( struct DiamAvp *dmAvp, char *sBearerService, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_BearerService, sBearerService, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 866
* Data Type : OctetString
*/
void addPSFreeFormatDataAVP( struct DiamMessage *dmMessage, char *sPSFreeFormatData, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_PSFreeFormatData, sPSFreeFormatData, iVendorId, iMandatory, iLength);
}


void setPSFreeFormatDataAVP( struct DiamAvp *dmAvp, char *sPSFreeFormatData, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_PSFreeFormatData, sPSFreeFormatData, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2022
* Data Type : OctetString
*/
void addRefundInformationAVP( struct DiamMessage *dmMessage, char *sRefundInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_RefundInformation, sRefundInformation, iVendorId, iMandatory, iLength);
}


void setRefundInformationAVP( struct DiamAvp *dmAvp, char *sRefundInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_RefundInformation, sRefundInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2013
* Data Type : OctetString
*/
void addSMProtocolIDAVP( struct DiamMessage *dmMessage, char *sSMProtocolID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SMProtocolID, sSMProtocolID, iVendorId, iMandatory, iLength);
}


void setSMProtocolIDAVP( struct DiamAvp *dmAvp, char *sSMProtocolID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SMProtocolID, sSMProtocolID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2014
* Data Type : OctetString
*/
void addSMStatusAVP( struct DiamMessage *dmMessage, char *sSMStatus, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SMStatus, sSMStatus, iVendorId, iMandatory, iLength);
}


void setSMStatusAVP( struct DiamAvp *dmAvp, char *sSMStatus, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SMStatus, sSMStatus, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2015
* Data Type : OctetString
*/
void addSMUserDataHeaderAVP( struct DiamMessage *dmMessage, char *sSMUserDataHeader, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SMUserDataHeader, sSMUserDataHeader, iVendorId, iMandatory, iLength);
}


void setSMUserDataHeaderAVP( struct DiamAvp *dmAvp, char *sSMUserDataHeader, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SMUserDataHeader, sSMUserDataHeader, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 891
* Data Type : OctetString
*/
void addWAGPLMNIdAVP( struct DiamMessage *dmMessage, char *sWAGPLMNId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_WAGPLMNId, sWAGPLMNId, iVendorId, iMandatory, iLength);
}


void setWAGPLMNIdAVP( struct DiamAvp *dmAvp, char *sWAGPLMNId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_WAGPLMNId, sWAGPLMNId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 421
* Data Type : Unsigned64
*/
void addCCTotalOctetsAVP( struct DiamMessage *dmMessage, unsigned long ulCCTotalOctets, int iVendorId, int iMandatory)
{
	addUnsigned64AVP( dmMessage, AVP_CCTotalOctets, ulCCTotalOctets, iVendorId, iMandatory);
}


void setCCTotalOctetsAVP( struct DiamAvp *dmAvp, unsigned long ulCCTotalOctets, int iVendorId, int iMandatory)
{
	setUnsigned64AVP( dmAvp, AVP_CCTotalOctets, ulCCTotalOctets, iVendorId, iMandatory);
}


/**
* AVP Code : 412
* Data Type : Unsigned64
*/
void addCCInputOctetsAVP( struct DiamMessage *dmMessage, unsigned long ulCCInputOctets, int iVendorId, int iMandatory)
{
	addUnsigned64AVP( dmMessage, AVP_CCInputOctets, ulCCInputOctets, iVendorId, iMandatory);
}


void setCCInputOctetsAVP( struct DiamAvp *dmAvp, unsigned long ulCCInputOctets, int iVendorId, int iMandatory)
{
	setUnsigned64AVP( dmAvp, AVP_CCInputOctets, ulCCInputOctets, iVendorId, iMandatory);
}


/**
* AVP Code : 414
* Data Type : Unsigned64
*/
void addCCOutputOctetsAVP( struct DiamMessage *dmMessage, unsigned long ulCCOutputOctets, int iVendorId, int iMandatory)
{
	addUnsigned64AVP( dmMessage, AVP_CCOutputOctets, ulCCOutputOctets, iVendorId, iMandatory);
}


void setCCOutputOctetsAVP( struct DiamAvp *dmAvp, unsigned long ulCCOutputOctets, int iVendorId, int iMandatory)
{
	setUnsigned64AVP( dmAvp, AVP_CCOutputOctets, ulCCOutputOctets, iVendorId, iMandatory);
}


/**
* AVP Code : 287
* Data Type : Unsigned64
*/
void addAccountingSubSessionIdAVP( struct DiamMessage *dmMessage, unsigned long ulAccountingSubSessionId, int iVendorId, int iMandatory)
{
	addUnsigned64AVP( dmMessage, AVP_AccountingSubSessionId, ulAccountingSubSessionId, iVendorId, iMandatory);
}


void setAccountingSubSessionIdAVP( struct DiamAvp *dmAvp, unsigned long ulAccountingSubSessionId, int iVendorId, int iMandatory)
{
	setUnsigned64AVP( dmAvp, AVP_AccountingSubSessionId, ulAccountingSubSessionId, iVendorId, iMandatory);
}


/**
* AVP Code : 419
* Data Type : Unsigned64
*/
void addCCSubSessionIdAVP( struct DiamMessage *dmMessage, unsigned long ulCCSubSessionId, int iVendorId, int iMandatory)
{
	addUnsigned64AVP( dmMessage, AVP_CCSubSessionId, ulCCSubSessionId, iVendorId, iMandatory);
}


void setCCSubSessionIdAVP( struct DiamAvp *dmAvp, unsigned long ulCCSubSessionId, int iVendorId, int iMandatory)
{
	setUnsigned64AVP( dmAvp, AVP_CCSubSessionId, ulCCSubSessionId, iVendorId, iMandatory);
}


/**
* AVP Code : 293
* Data Type : DiameterIdentity
*/
void addDestinationHostAVP( struct DiamMessage *dmMessage, char *sDestinationHost, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_DestinationHost, sDestinationHost, iVendorId, iMandatory, iLength);
}


void setDestinationHostAVP( struct DiamAvp *dmAvp, char *sDestinationHost, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_DestinationHost, sDestinationHost, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 283
* Data Type : DiameterIdentity
*/
void addDestinationRealmAVP( struct DiamMessage *dmMessage, char *sDestinationRealm, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_DestinationRealm, sDestinationRealm, iVendorId, iMandatory, iLength);
}

void addDestinationRealmSimulated( struct DiamMessage *dmMessage, int iVendorId, int iMandatory)
{
	addOctetStringAVP( dmMessage, AVP_DestinationRealm, objStackConfig.SimulateDestinationRelam, iVendorId, iMandatory, strlen(objStackConfig.SimulateDestinationRelam));
}


void setDestinationRealmAVP( struct DiamAvp *dmAvp, char *sDestinationRealm, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_DestinationRealm, sDestinationRealm, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2055
* Data Type : Enumerated
*/
void addAoCRequestTypeAVP( struct DiamMessage *dmMessage, int iAoCRequestType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_AoCRequestType, iAoCRequestType, iVendorId, iMandatory);
}


void setAoCRequestTypeAVP( struct DiamAvp *dmAvp, int iAoCRequestType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_AoCRequestType, iAoCRequestType, iVendorId, iMandatory);
}


/**
* AVP Code : 1214
* Data Type : Enumerated
*/
void addClassIdentifierAVP( struct DiamMessage *dmMessage, int iClassIdentifier, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ClassIdentifier, iClassIdentifier, iVendorId, iMandatory);
}


void setClassIdentifierAVP( struct DiamAvp *dmAvp, int iClassIdentifier, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ClassIdentifier, iClassIdentifier, iVendorId, iMandatory);
}


/**
* AVP Code : 1220
* Data Type : Enumerated
*/
void addContentClassAVP( struct DiamMessage *dmMessage, int iContentClass, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ContentClass, iContentClass, iVendorId, iMandatory);
}


void setContentClassAVP( struct DiamAvp *dmAvp, int iContentClass, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ContentClass, iContentClass, iVendorId, iMandatory);
}


/**
* AVP Code : 1216
* Data Type : Enumerated
*/
void addDeliveryReportRequestedAVP( struct DiamMessage *dmMessage, int iDeliveryReportRequested, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_DeliveryReportRequested, iDeliveryReportRequested, iVendorId, iMandatory);
}


void setDeliveryReportRequestedAVP( struct DiamAvp *dmAvp, int iDeliveryReportRequested, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_DeliveryReportRequested, iDeliveryReportRequested, iVendorId, iMandatory);
}


/**
* AVP Code : 1221
* Data Type : Enumerated
*/
void addDRMContentAVP( struct DiamMessage *dmMessage, int iDRMContent, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_DRMContent, iDRMContent, iVendorId, iMandatory);
}


void setDRMContentAVP( struct DiamAvp *dmAvp, int iDRMContent, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_DRMContent, iDRMContent, iVendorId, iMandatory);
}


/**
* AVP Code : 2051
* Data Type : Enumerated
*/
void addDynamicAddressFlagAVP( struct DiamMessage *dmMessage, int iDynamicAddressFlag, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_DynamicAddressFlag, iDynamicAddressFlag, iVendorId, iMandatory);
}


void setDynamicAddressFlagAVP( struct DiamAvp *dmAvp, int iDynamicAddressFlag, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_DynamicAddressFlag, iDynamicAddressFlag, iVendorId, iMandatory);
}


/**
* AVP Code : 1268
* Data Type : Enumerated
*/
void addEnvelopeReportingAVP( struct DiamMessage *dmMessage, int iEnvelopeReporting, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_EnvelopeReporting, iEnvelopeReporting, iVendorId, iMandatory);
}


void setEnvelopeReportingAVP( struct DiamAvp *dmAvp, int iEnvelopeReporting, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_EnvelopeReporting, iEnvelopeReporting, iVendorId, iMandatory);
}


/**
* AVP Code : 1224
* Data Type : Enumerated
*/
void addFileRepairSupportedAVP( struct DiamMessage *dmMessage, int iFileRepairSupported, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_FileRepairSupported, iFileRepairSupported, iVendorId, iMandatory);
}


void setFileRepairSupportedAVP( struct DiamAvp *dmAvp, int iFileRepairSupported, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_FileRepairSupported, iFileRepairSupported, iVendorId, iMandatory);
}


/**
* AVP Code : 2006
* Data Type : Enumerated
*/
void addInterfaceTypeAVP( struct DiamMessage *dmMessage, int iInterfaceType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_InterfaceType, iInterfaceType, iVendorId, iMandatory);
}


void setInterfaceTypeAVP( struct DiamAvp *dmAvp, int iInterfaceType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_InterfaceType, iInterfaceType, iVendorId, iMandatory);
}


/**
* AVP Code : 1241
* Data Type : Enumerated
*/
void addLCSClientTypeAVP( struct DiamMessage *dmMessage, int iLCSClientType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_LCSClientType, iLCSClientType, iVendorId, iMandatory);
}


void setLCSClientTypeAVP( struct DiamAvp *dmAvp, int iLCSClientType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_LCSClientType, iLCSClientType, iVendorId, iMandatory);
}


/**
* AVP Code : 1237
* Data Type : Enumerated
*/
void addLCSFormatIndicatorAVP( struct DiamMessage *dmMessage, int iLCSFormatIndicator, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_LCSFormatIndicator, iLCSFormatIndicator, iVendorId, iMandatory);
}


void setLCSFormatIndicatorAVP( struct DiamAvp *dmAvp, int iLCSFormatIndicator, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_LCSFormatIndicator, iLCSFormatIndicator, iVendorId, iMandatory);
}


/**
* AVP Code : 1243
* Data Type : Enumerated
*/
void addLocationEstimateTypeAVP( struct DiamMessage *dmMessage, int iLocationEstimateType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_LocationEstimateType, iLocationEstimateType, iVendorId, iMandatory);
}


void setLocationEstimateTypeAVP( struct DiamAvp *dmAvp, int iLocationEstimateType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_LocationEstimateType, iLocationEstimateType, iVendorId, iMandatory);
}


/**
* AVP Code : 2020
* Data Type : Enumerated
*/
void addLowBalanceIndicationAVP( struct DiamMessage *dmMessage, int iLowBalanceIndication, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_LowBalanceIndication, iLowBalanceIndication, iVendorId, iMandatory);
}


void setLowBalanceIndicationAVP( struct DiamAvp *dmAvp, int iLowBalanceIndication, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_LowBalanceIndication, iLowBalanceIndication, iVendorId, iMandatory);
}


/**
* AVP Code : 1225
* Data Type : Enumerated
*/
void addMBMSUserServiceTypeAVP( struct DiamMessage *dmMessage, int iMBMSUserServiceType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_MBMSUserServiceType, iMBMSUserServiceType, iVendorId, iMandatory);
}


void setMBMSUserServiceTypeAVP( struct DiamAvp *dmAvp, int iMBMSUserServiceType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_MBMSUserServiceType, iMBMSUserServiceType, iVendorId, iMandatory);
}


/**
* AVP Code : 882
* Data Type : Enumerated
*/
void addMediaInitiatorFlagAVP( struct DiamMessage *dmMessage, int iMediaInitiatorFlag, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_MediaInitiatorFlag, iMediaInitiatorFlag, iVendorId, iMandatory);
}


void setMediaInitiatorFlagAVP( struct DiamAvp *dmAvp, int iMediaInitiatorFlag, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_MediaInitiatorFlag, iMediaInitiatorFlag, iVendorId, iMandatory);
}


/**
* AVP Code : 1211
* Data Type : Enumerated
*/
void addMessageTypeAVP( struct DiamMessage *dmMessage, int iMessageType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_MessageType, iMessageType, iVendorId, iMandatory);
}


void setMessageTypeAVP( struct DiamAvp *dmAvp, int iMessageType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_MessageType, iMessageType, iVendorId, iMandatory);
}


/**
* AVP Code : 1248
* Data Type : Enumerated
*/
void addMMBoxStorageRequestedAVP( struct DiamMessage *dmMessage, int iMMBoxStorageRequested, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_MMBoxStorageRequested, iMMBoxStorageRequested, iVendorId, iMandatory);
}


void setMMBoxStorageRequestedAVP( struct DiamAvp *dmAvp, int iMMBoxStorageRequested, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_MMBoxStorageRequested, iMMBoxStorageRequested, iVendorId, iMandatory);
}


/**
* AVP Code : 862
* Data Type : Enumerated
*/
void addNodeFunctionalityAVP( struct DiamMessage *dmMessage, int iNodeFunctionality, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_NodeFunctionality, iNodeFunctionality, iVendorId, iMandatory);
}


void setNodeFunctionalityAVP( struct DiamAvp *dmAvp, int iNodeFunctionality, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_NodeFunctionality, iNodeFunctionality, iVendorId, iMandatory);
}


/**
* AVP Code : 864
* Data Type : Enumerated
*/
void addOriginatorAVP( struct DiamMessage *dmMessage, int iOriginator, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_Originator, iOriginator, iVendorId, iMandatory);
}


void setOriginatorAVP( struct DiamAvp *dmAvp, int iOriginator, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_Originator, iOriginator, iVendorId, iMandatory);
}


/**
* AVP Code : 1259
* Data Type : Enumerated
*/
void addParticipantAccessPriorityAVP( struct DiamMessage *dmMessage, int iParticipantAccessPriority, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ParticipantAccessPriority, iParticipantAccessPriority, iVendorId, iMandatory);
}


void setParticipantAccessPriorityAVP( struct DiamAvp *dmAvp, int iParticipantAccessPriority, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ParticipantAccessPriority, iParticipantAccessPriority, iVendorId, iMandatory);
}


/**
* AVP Code : 2049
* Data Type : Enumerated
*/
void addParticipantActionTypeAVP( struct DiamMessage *dmMessage, int iParticipantActionType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ParticipantActionType, iParticipantActionType, iVendorId, iMandatory);
}


void setParticipantActionTypeAVP( struct DiamAvp *dmAvp, int iParticipantActionType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ParticipantActionType, iParticipantActionType, iVendorId, iMandatory);
}


/**
* AVP Code : 1247
* Data Type : Enumerated
*/
void addPDPContextTypeAVP( struct DiamMessage *dmMessage, int iPDPContextType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PDPContextType, iPDPContextType, iVendorId, iMandatory);
}


void setPDPContextTypeAVP( struct DiamAvp *dmAvp, int iPDPContextType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PDPContextType, iPDPContextType, iVendorId, iMandatory);
}


/**
* AVP Code : 1261
* Data Type : Enumerated
*/
void addPoCChangeConditionAVP( struct DiamMessage *dmMessage, int iPoCChangeCondition, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PoCChangeCondition, iPoCChangeCondition, iVendorId, iMandatory);
}


void setPoCChangeConditionAVP( struct DiamAvp *dmAvp, int iPoCChangeCondition, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PoCChangeCondition, iPoCChangeCondition, iVendorId, iMandatory);
}


/**
* AVP Code : 2025
* Data Type : Enumerated
*/
void addPoCEventTypeAVP( struct DiamMessage *dmMessage, int iPoCEventType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PoCEventType, iPoCEventType, iVendorId, iMandatory);
}


void setPoCEventTypeAVP( struct DiamAvp *dmAvp, int iPoCEventType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PoCEventType, iPoCEventType, iVendorId, iMandatory);
}


/**
* AVP Code : 883
* Data Type : Enumerated
*/
void addPoCServerRoleAVP( struct DiamMessage *dmMessage, int iPoCServerRole, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PoCServerRole, iPoCServerRole, iVendorId, iMandatory);
}


void setPoCServerRoleAVP( struct DiamAvp *dmAvp, int iPoCServerRole, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PoCServerRole, iPoCServerRole, iVendorId, iMandatory);
}


/**
* AVP Code : 1277
* Data Type : Enumerated
*/
void addPoCSessionInitiationtypeAVP( struct DiamMessage *dmMessage, int iPoCSessionInitiationtype, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PoCSessionInitiationtype, iPoCSessionInitiationtype, iVendorId, iMandatory);
}


void setPoCSessionInitiationtypeAVP( struct DiamAvp *dmAvp, int iPoCSessionInitiationtype, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PoCSessionInitiationtype, iPoCSessionInitiationtype, iVendorId, iMandatory);
}


/**
* AVP Code : 884
* Data Type : Enumerated
*/
void addPoCSessionTypeAVP( struct DiamMessage *dmMessage, int iPoCSessionType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PoCSessionType, iPoCSessionType, iVendorId, iMandatory);
}


void setPoCSessionTypeAVP( struct DiamAvp *dmAvp, int iPoCSessionType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PoCSessionType, iPoCSessionType, iVendorId, iMandatory);
}


/**
* AVP Code : 1254
* Data Type : Enumerated
*/
void addPoCUserRoleinfoUnitsAVP( struct DiamMessage *dmMessage, int iPoCUserRoleinfoUnits, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PoCUserRoleinfoUnits, iPoCUserRoleinfoUnits, iVendorId, iMandatory);
}


void setPoCUserRoleinfoUnitsAVP( struct DiamAvp *dmAvp, int iPoCUserRoleinfoUnits, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PoCUserRoleinfoUnits, iPoCUserRoleinfoUnits, iVendorId, iMandatory);
}


/**
* AVP Code : 1209
* Data Type : Enumerated
*/
void addPriorityAVP( struct DiamMessage *dmMessage, int iPriority, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_Priority, iPriority, iVendorId, iMandatory);
}


void setPriorityAVP( struct DiamAvp *dmAvp, int iPriority, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_Priority, iPriority, iVendorId, iMandatory);
}


/**
* AVP Code : 867
* Data Type : Enumerated
*/
void addPSAppendFreeFormatDataAVP( struct DiamMessage *dmMessage, int iPSAppendFreeFormatData, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_PSAppendFreeFormatData, iPSAppendFreeFormatData, iVendorId, iMandatory);
}


void setPSAppendFreeFormatDataAVP( struct DiamAvp *dmAvp, int iPSAppendFreeFormatData, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_PSAppendFreeFormatData, iPSAppendFreeFormatData, iVendorId, iMandatory);
}


/**
* AVP Code : 1222
* Data Type : Enumerated
*/
void addReadReplyReportRequestedAVP( struct DiamMessage *dmMessage, int iReadReplyReportRequested, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ReadReplyReportRequested, iReadReplyReportRequested, iVendorId, iMandatory);
}


void setReadReplyReportRequestedAVP( struct DiamAvp *dmAvp, int iReadReplyReportRequested, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ReadReplyReportRequested, iReadReplyReportRequested, iVendorId, iMandatory);
}


/**
* AVP Code : 2011
* Data Type : Enumerated
*/
void addReplyPathRequestedAVP( struct DiamMessage *dmMessage, int iReplyPathRequested, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ReplyPathRequested, iReplyPathRequested, iVendorId, iMandatory);
}


void setReplyPathRequestedAVP( struct DiamAvp *dmAvp, int iReplyPathRequested, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ReplyPathRequested, iReplyPathRequested, iVendorId, iMandatory);
}


/**
* AVP Code : 872
* Data Type : Enumerated
*/
void addReportingReasonAVP( struct DiamMessage *dmMessage, int iReportingReason, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ReportingReason, iReportingReason, iVendorId, iMandatory);
}


void setReportingReasonAVP( struct DiamAvp *dmAvp, int iReportingReason, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ReportingReason, iReportingReason, iVendorId, iMandatory);
}


/**
* AVP Code : 829
* Data Type : Enumerated
*/
void addRoleofNodeAVP( struct DiamMessage *dmMessage, int iRoleofNode, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_RoleofNode, iRoleofNode, iVendorId, iMandatory);
}


void setRoleofNodeAVP( struct DiamAvp *dmAvp, int iRoleofNode, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_RoleofNode, iRoleofNode, iVendorId, iMandatory);
}


/**
* AVP Code : 2036
* Data Type : Enumerated
*/
void addSDPTypeAVP( struct DiamMessage *dmMessage, int iSDPType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SDPType, iSDPType, iVendorId, iMandatory);
}


void setSDPTypeAVP( struct DiamAvp *dmAvp, int iSDPType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SDPType, iSDPType, iVendorId, iMandatory);
}


/**
* AVP Code : 2047
* Data Type : Enumerated
*/
void addServingNodeTypeAVP( struct DiamMessage *dmMessage, int iServingNodeType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ServingNodeType, iServingNodeType, iVendorId, iMandatory);
}


void setServingNodeTypeAVP( struct DiamAvp *dmAvp, int iServingNodeType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ServingNodeType, iServingNodeType, iVendorId, iMandatory);
}


/**
* AVP Code : 2065
* Data Type : Enumerated
*/
void addSGWChangeAVP( struct DiamMessage *dmMessage, int iSGWChange, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SGWChange, iSGWChange, iVendorId, iMandatory);
}


void setSGWChangeAVP( struct DiamAvp *dmAvp, int iSGWChange, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SGWChange, iSGWChange, iVendorId, iMandatory);
}


/**
* AVP Code : 2007
* Data Type : Enumerated
*/
void addSMMessageTypeAVP( struct DiamMessage *dmMessage, int iSMMessageType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SMMessageType, iSMMessageType, iVendorId, iMandatory);
}


void setSMMessageTypeAVP( struct DiamAvp *dmAvp, int iSMMessageType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SMMessageType, iSMMessageType, iVendorId, iMandatory);
}


/**
* AVP Code : 2016
* Data Type : Enumerated
*/
void addSMSNodeAVP( struct DiamMessage *dmMessage, int iSMSNode, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SMSNode, iSMSNode, iVendorId, iMandatory);
}


void setSMSNodeAVP( struct DiamAvp *dmAvp, int iSMSNode, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SMSNode, iSMSNode, iVendorId, iMandatory);
}


/**
* AVP Code : 2029
* Data Type : Enumerated
*/
void addSMServiceTypeAVP( struct DiamMessage *dmMessage, int iSMServiceType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SMServiceType, iSMServiceType, iVendorId, iMandatory);
}


void setSMServiceTypeAVP( struct DiamAvp *dmAvp, int iSMServiceType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SMServiceType, iSMServiceType, iVendorId, iMandatory);
}


/**
* AVP Code : 2033
* Data Type : Enumerated
*/
void addSubscriberRoleAVP( struct DiamMessage *dmMessage, int iSubscriberRole, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SubscriberRole, iSubscriberRole, iVendorId, iMandatory);
}


void setSubscriberRoleAVP( struct DiamAvp *dmAvp, int iSubscriberRole, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SubscriberRole, iSubscriberRole, iVendorId, iMandatory);
}


/**
* AVP Code : 1271
* Data Type : Enumerated
*/
void addTimeQuotaTypeAVP( struct DiamMessage *dmMessage, int iTimeQuotaType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_TimeQuotaType, iTimeQuotaType, iVendorId, iMandatory);
}


void setTimeQuotaTypeAVP( struct DiamAvp *dmAvp, int iTimeQuotaType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_TimeQuotaType, iTimeQuotaType, iVendorId, iMandatory);
}


/**
* AVP Code : 870
* Data Type : Enumerated
*/
void addTriggerTypeAVP( struct DiamMessage *dmMessage, int iTriggerType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_TriggerType, iTriggerType, iVendorId, iMandatory);
}


void setTriggerTypeAVP( struct DiamAvp *dmAvp, int iTriggerType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_TriggerType, iTriggerType, iVendorId, iMandatory);
}


/**
* AVP Code : 1204
* Data Type : Enumerated
*/
void addTypeNumberAVP( struct DiamMessage *dmMessage, int iTypeNumber, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_TypeNumber, iTypeNumber, iVendorId, iMandatory);
}


void setTypeNumberAVP( struct DiamAvp *dmAvp, int iTypeNumber, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_TypeNumber, iTypeNumber, iVendorId, iMandatory);
}


/**
* AVP Code : 1279
* Data Type : Enumerated
*/
void addUserParticipatingTypeAVP( struct DiamMessage *dmMessage, int iUserParticipatingType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_UserParticipatingType, iUserParticipatingType, iVendorId, iMandatory);
}


void setUserParticipatingTypeAVP( struct DiamAvp *dmAvp, int iUserParticipatingType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_UserParticipatingType, iUserParticipatingType, iVendorId, iMandatory);
}


/**
* AVP Code : 50
* Data Type : UTF8String
*/
void addAcctMultiSessionIdAVP( struct DiamMessage *dmMessage, char *sAcctMultiSessionId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AcctMultiSessionId, sAcctMultiSessionId, iVendorId, iMandatory, iLength);
}


void setAcctMultiSessionIdAVP( struct DiamAvp *dmAvp, char *sAcctMultiSessionId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AcctMultiSessionId, sAcctMultiSessionId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 281
* Data Type : UTF8String
*/
void addErrorMessageAVP( struct DiamMessage *dmMessage, char *sErrorMessage, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ErrorMessage, sErrorMessage, iVendorId, iMandatory, iLength);
}


void setErrorMessageAVP( struct DiamAvp *dmAvp, char *sErrorMessage, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ErrorMessage, sErrorMessage, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 269
* Data Type : UTF8String
*/
void addProductNameAVP( struct DiamMessage *dmMessage, char *sProductName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ProductName, sProductName, iVendorId, iMandatory, iLength);
}


void setProductNameAVP( struct DiamAvp *dmAvp, char *sProductName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ProductName, sProductName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 263
* Data Type : UTF8String
*/
void addSessionIdAVP( struct DiamMessage *dmMessage, char *sSessionId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_SessionId, sSessionId, iVendorId, iMandatory, iLength);
}


void setSessionIdAVP( struct DiamAvp *dmAvp, char *sSessionId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_SessionId, sSessionId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1
* Data Type : UTF8String
*/
void addUserNameAVP( struct DiamMessage *dmMessage, char *sUserName, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_UserName, sUserName, iVendorId, iMandatory, iLength);
}


void setUserNameAVP( struct DiamAvp *dmAvp, char *sUserName, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_UserName, sUserName, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 461
* Data Type : UTF8String
*/
void addServiceContextIdAVP( struct DiamMessage *dmMessage, char *sServiceContextId, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ServiceContextId, sServiceContextId, iVendorId, iMandatory, iLength);
}


void setServiceContextIdAVP( struct DiamAvp *dmAvp, char *sServiceContextId, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ServiceContextId, sServiceContextId, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1205
* Data Type : UTF8String
*/
void addAdditionalTypeInformationAVP( struct DiamMessage *dmMessage, char *sAdditionalTypeInformation, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AdditionalTypeInformation, sAdditionalTypeInformation, iVendorId, iMandatory, iLength);
}


void setAdditionalTypeInformationAVP( struct DiamAvp *dmAvp, char *sAdditionalTypeInformation, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AdditionalTypeInformation, sAdditionalTypeInformation, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 897
* Data Type : UTF8String
*/
void addAddressDataAVP( struct DiamMessage *dmMessage, char *sAddressData, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AddressData, sAddressData, iVendorId, iMandatory, iLength);
}


void setAddressDataAVP( struct DiamAvp *dmAvp, char *sAddressData, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AddressData, sAddressData, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1280
* Data Type : UTF8String
*/
void addAlternateChargedPartyAddressAVP( struct DiamMessage *dmMessage, char *sAlternateChargedPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AlternateChargedPartyAddress, sAlternateChargedPartyAddress, iVendorId, iMandatory, iLength);
}


void setAlternateChargedPartyAddressAVP( struct DiamAvp *dmAvp, char *sAlternateChargedPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AlternateChargedPartyAddress, sAlternateChargedPartyAddress, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 837
* Data Type : UTF8String
*/
void addApplicationprovidedcalledpartyaddressAVP( struct DiamMessage *dmMessage, char *sApplicationprovidedcalledpartyaddress, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_Applicationprovidedcalledpartyaddress, sApplicationprovidedcalledpartyaddress, iVendorId, iMandatory, iLength);
}


void setApplicationprovidedcalledpartyaddressAVP( struct DiamAvp *dmAvp, char *sApplicationprovidedcalledpartyaddress, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_Applicationprovidedcalledpartyaddress, sApplicationprovidedcalledpartyaddress, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 836
* Data Type : UTF8String
*/
void addApplicationServerAVP( struct DiamMessage *dmMessage, char *sApplicationServer, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ApplicationServer, sApplicationServer, iVendorId, iMandatory, iLength);
}


void setApplicationServerAVP( struct DiamAvp *dmAvp, char *sApplicationServer, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ApplicationServer, sApplicationServer, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1218
* Data Type : UTF8String
*/
void addApplicIDAVP( struct DiamMessage *dmMessage, char *sApplicID, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_ApplicID, sApplicID, iVendorId, iMandatory, iLength);
}


void setApplicIDAVP( struct DiamAvp *dmAvp, char *sApplicID, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_ApplicID, sApplicID, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 2035
* Data Type : UTF8String
*/
void addAssociatedPartyAddressAVP( struct DiamMessage *dmMessage, char *sAssociatedPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AssociatedPartyAddress, sAssociatedPartyAddress, iVendorId, iMandatory, iLength);
}


void setAssociatedPartyAddressAVP( struct DiamAvp *dmAvp, char *sAssociatedPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AssociatedPartyAddress, sAssociatedPartyAddress, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 856
* Data Type : UTF8String
*/
void addAssociatedURIAVP( struct DiamMessage *dmMessage, char *sAssociatedURI, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AssociatedURI, sAssociatedURI, iVendorId, iMandatory, iLength);
}


void setAssociatedURIAVP( struct DiamAvp *dmAvp, char *sAssociatedURI, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AssociatedURI, sAssociatedURI, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 849
* Data Type : UTF8String
*/
void addAuthorizedQoSAVP( struct DiamMessage *dmMessage, char *sAuthorizedQoS, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AuthorizedQoS, sAuthorizedQoS, iVendorId, iMandatory, iLength);
}


void setAuthorizedQoSAVP( struct DiamAvp *dmAvp, char *sAuthorizedQoS, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AuthorizedQoS, sAuthorizedQoS, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1219
* Data Type : UTF8String
*/
void addAuxApplicInfoAVP( struct DiamMessage *dmMessage, char *sAuxApplicInfo, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_AuxApplicInfo, sAuxApplicInfo, iVendorId, iMandatory, iLength);
}


void setAuxApplicInfoAVP( struct DiamAvp *dmAvp, char *sAuxApplicInfo, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_AuxApplicInfo, sAuxApplicInfo, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 1250
* Data Type : UTF8String
*/
void addCalledAssertedIdentityAVP( struct DiamMessage *dmMessage, char *sCalledAssertedIdentity, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_CalledAssertedIdentity, sCalledAssertedIdentity, iVendorId, iMandatory, iLength);
}


void setCalledAssertedIdentityAVP( struct DiamAvp *dmAvp, char *sCalledAssertedIdentity, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_CalledAssertedIdentity, sCalledAssertedIdentity, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 832
* Data Type : UTF8String
*/
void addCalledPartyAddressAVP( struct DiamMessage *dmMessage, char *sCalledPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_CalledPartyAddress, sCalledPartyAddress, iVendorId, iMandatory, iLength);
}


void setCalledPartyAddressAVP( struct DiamAvp *dmAvp, char *sCalledPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_CalledPartyAddress, sCalledPartyAddress, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 831
* Data Type : UTF8String
*/
void addCallingPartyAddressAVP( struct DiamMessage *dmMessage, char *sCallingPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	addOctetStringAVP( dmMessage, AVP_CallingPartyAddress, sCallingPartyAddress, iVendorId, iMandatory, iLength);
}


void setCallingPartyAddressAVP( struct DiamAvp *dmAvp, char *sCallingPartyAddress, int iVendorId, int iMandatory, int iLength)
{
	setOctetStringAVP( dmAvp, AVP_CallingPartyAddress, sCallingPartyAddress, iVendorId, iMandatory, iLength);
}


/**
* AVP Code : 432
* Data Type : Unsigned32
*/
void addRatingGroupAVP( struct DiamMessage *dmMessage, unsigned int uiRatingGroup, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_RatingGroup, uiRatingGroup, iVendorId, iMandatory);
}


void setRatingGroupAVP( struct DiamAvp *dmAvp, unsigned int uiRatingGroup, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_RatingGroup, uiRatingGroup, iVendorId, iMandatory);
}


/**
* AVP Code : 420
* Data Type : Unsigned32
*/
void addCCTimeAVP( struct DiamMessage *dmMessage, unsigned int uiCCTime, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_CCTime, uiCCTime, iVendorId, iMandatory);
}


void setCCTimeAVP( struct DiamAvp *dmAvp, unsigned int uiCCTime, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_CCTime, uiCCTime, iVendorId, iMandatory);
}


/**
* AVP Code : 85
* Data Type : Unsigned32
*/
void addAcctInterimIntervalAVP( struct DiamMessage *dmMessage, unsigned int uiAcctInterimInterval, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_AcctInterimInterval, uiAcctInterimInterval, iVendorId, iMandatory);
}


void setAcctInterimIntervalAVP( struct DiamAvp *dmAvp, unsigned int uiAcctInterimInterval, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_AcctInterimInterval, uiAcctInterimInterval, iVendorId, iMandatory);
}


/**
* AVP Code : 259
* Data Type : Unsigned32
*/
void addAcctApplicationIdAVP( struct DiamMessage *dmMessage, unsigned int uiAcctApplicationId, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_AcctApplicationId, uiAcctApplicationId, iVendorId, iMandatory);
}


void setAcctApplicationIdAVP( struct DiamAvp *dmAvp, unsigned int uiAcctApplicationId, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_AcctApplicationId, uiAcctApplicationId, iVendorId, iMandatory);
}


/**
* AVP Code : 258
* Data Type : Unsigned32
*/
void addAuthApplicationIdAVP( struct DiamMessage *dmMessage, unsigned int uiAuthApplicationId, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_AuthApplicationId, uiAuthApplicationId, iVendorId, iMandatory);
}

void addVendorSpecificApplicationId( struct DiamMessage * diamMessage, unsigned int iVendorId, unsigned int iAuthApplicationId)
{
	struct DiamAvp *oVendorSpecificApplicationId = (struct DiamAvp*)allocateDiamAvp();
	setGroupedAVP( diamMessage, AVP_VendorSpecificApplicationId, oVendorSpecificApplicationId, 0, 1);
	
	struct DiamAvp *oVendorIdAvp = (struct DiamAvp*)allocateDiamAvp();
	setUnsigned32AVP( oVendorIdAvp, AVP_VendorId, iVendorId, 0, 1);
	
	struct DiamAvp *oAuthApplicationIdAvp = (struct DiamAvp*)allocateDiamAvp();
	setUnsigned32AVP( oAuthApplicationIdAvp, AVP_AuthApplicationId, iAuthApplicationId, 0, 1);
	
	addAvp( oVendorSpecificApplicationId, oVendorIdAvp);
	addAvp( oVendorSpecificApplicationId, oAuthApplicationIdAvp);
}

void addVendorSpecificApplicationId2( struct DiamMessage * diamMessage, unsigned int iVendorId, unsigned int iAuthApplicationId, unsigned int iAcctApplicationId)
{
	if( iAuthApplicationId > 0 || iAcctApplicationId > 0)
	{	
		struct DiamAvp *oVendorSpecificApplicationId = (struct DiamAvp*)allocateDiamAvp();
		setGroupedAVP( diamMessage, AVP_VendorSpecificApplicationId, oVendorSpecificApplicationId, 0, 1);
		
		struct DiamAvp *oVendorIdAvp = (struct DiamAvp*)allocateDiamAvp();
		setUnsigned32AVP( oVendorIdAvp, AVP_VendorId, iVendorId, 0, 1);
		addAvp( oVendorSpecificApplicationId, oVendorIdAvp);
		
		//printf("iAuthApplicationId=%u %s\n", iAuthApplicationId, __FUNCTION__);
		if( iAuthApplicationId > 0 )
		{
			struct DiamAvp *oAuthApplicationIdAvp = (struct DiamAvp*)allocateDiamAvp();
			setUnsigned32AVP( oAuthApplicationIdAvp, AVP_AuthApplicationId, iAuthApplicationId, 0, 1);
			addAvp( oVendorSpecificApplicationId, oAuthApplicationIdAvp);
		}
		
		//printf("iAcctApplicationId=%u %s\n", iAcctApplicationId, __FUNCTION__);
		if( iAcctApplicationId > 0 )
		{
			struct DiamAvp *oAcctApplicationIdAvp = (struct DiamAvp*)allocateDiamAvp();
			setUnsigned32AVP( oAcctApplicationIdAvp, AVP_AcctApplicationId, iAcctApplicationId, 0, 1);
			addAvp( oVendorSpecificApplicationId, oAcctApplicationIdAvp);	
		}	
	}
}

void addVendorSpecificApplicationId3( struct DiamMessage * diamMessage, iVendorSpecificApplicationId * oVendorSpecificApplicationId)
{
	addVendorSpecificApplicationId2( diamMessage, oVendorSpecificApplicationId->iVendorId, oVendorSpecificApplicationId->iAuthApplicationId, oVendorSpecificApplicationId->iAcctApplicationId);
}

void setAuthApplicationIdAVP( struct DiamAvp *dmAvp, unsigned int uiAuthApplicationId, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_AuthApplicationId, uiAuthApplicationId, iVendorId, iMandatory);
}


/**
* AVP Code : 485
* Data Type : Unsigned32
*/
void addAccountingRecordNumberAVP( struct DiamMessage *dmMessage, unsigned int uiAccountingRecordNumber, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_AccountingRecordNumber, uiAccountingRecordNumber, iVendorId, iMandatory);
}


void setAccountingRecordNumberAVP( struct DiamAvp *dmAvp, unsigned int uiAccountingRecordNumber, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_AccountingRecordNumber, uiAccountingRecordNumber, iVendorId, iMandatory);
}


/**
* AVP Code : 291
* Data Type : Unsigned32
*/
void addAuthorizationLifetimeAVP( struct DiamMessage *dmMessage, unsigned int uiAuthorizationLifetime, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_AuthorizationLifetime, uiAuthorizationLifetime, iVendorId, iMandatory);
}


void setAuthorizationLifetimeAVP( struct DiamAvp *dmAvp, unsigned int uiAuthorizationLifetime, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_AuthorizationLifetime, uiAuthorizationLifetime, iVendorId, iMandatory);
}


/**
* AVP Code : 276
* Data Type : Unsigned32
*/
void addAuthGracePeriodAVP( struct DiamMessage *dmMessage, unsigned int uiAuthGracePeriod, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_AuthGracePeriod, uiAuthGracePeriod, iVendorId, iMandatory);
}


void setAuthGracePeriodAVP( struct DiamAvp *dmAvp, unsigned int uiAuthGracePeriod, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_AuthGracePeriod, uiAuthGracePeriod, iVendorId, iMandatory);
}


/**
* AVP Code : 298
* Data Type : Unsigned32
*/
void addExperimentalResultCodeAVP( struct DiamMessage *dmMessage, unsigned int uiExperimentalResultCode, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ExperimentalResultCode, uiExperimentalResultCode, iVendorId, iMandatory);
}


void setExperimentalResultCodeAVP( struct DiamAvp *dmAvp, unsigned int uiExperimentalResultCode, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ExperimentalResultCode, uiExperimentalResultCode, iVendorId, iMandatory);
}


/**
* AVP Code : 267
* Data Type : Unsigned32
*/
void addFirmwareRevisionAVP( struct DiamMessage *dmMessage, unsigned int uiFirmwareRevision, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_FirmwareRevision, uiFirmwareRevision, iVendorId, iMandatory);
}


void setFirmwareRevisionAVP( struct DiamAvp *dmAvp, unsigned int uiFirmwareRevision, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_FirmwareRevision, uiFirmwareRevision, iVendorId, iMandatory);
}


/**
* AVP Code : 299
* Data Type : Unsigned32
*/
void addInbandSecurityIdAVP( struct DiamMessage *dmMessage, unsigned int uiInbandSecurityId, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_InbandSecurityId, uiInbandSecurityId, iVendorId, iMandatory);
}


void setInbandSecurityIdAVP( struct DiamAvp *dmAvp, unsigned int uiInbandSecurityId, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_InbandSecurityId, uiInbandSecurityId, iVendorId, iMandatory);
}


/**
* AVP Code : 272
* Data Type : Unsigned32
*/
void addMultiRoundTimeOutAVP( struct DiamMessage *dmMessage, unsigned int uiMultiRoundTimeOut, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_MultiRoundTimeOut, uiMultiRoundTimeOut, iVendorId, iMandatory);
}


void setMultiRoundTimeOutAVP( struct DiamAvp *dmAvp, unsigned int uiMultiRoundTimeOut, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_MultiRoundTimeOut, uiMultiRoundTimeOut, iVendorId, iMandatory);
}


/**
* AVP Code : 278
* Data Type : Unsigned32
*/
void addOriginStateIdAVP( struct DiamMessage *dmMessage, unsigned int uiOriginStateId, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_OriginStateId, uiOriginStateId, iVendorId, iMandatory);
}


void setOriginStateIdAVP( struct DiamAvp *dmAvp, unsigned int uiOriginStateId, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_OriginStateId, uiOriginStateId, iVendorId, iMandatory);
}


/**
* AVP Code : 262
* Data Type : Unsigned32
*/
void addRedirectMaxCacheTimeAVP( struct DiamMessage *dmMessage, unsigned int uiRedirectMaxCacheTime, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_RedirectMaxCacheTime, uiRedirectMaxCacheTime, iVendorId, iMandatory);
}


void setRedirectMaxCacheTimeAVP( struct DiamAvp *dmAvp, unsigned int uiRedirectMaxCacheTime, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_RedirectMaxCacheTime, uiRedirectMaxCacheTime, iVendorId, iMandatory);
}


/**
* AVP Code : 268
* Data Type : Unsigned32
*/
void addResultCodeAVP( struct DiamMessage *dmMessage, unsigned int uiResultCode, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ResultCode, uiResultCode, iVendorId, iMandatory);
}


void setResultCodeAVP( struct DiamAvp *dmAvp, unsigned int uiResultCode, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ResultCode, uiResultCode, iVendorId, iMandatory);
}


/**
* AVP Code : 27
* Data Type : Unsigned32
*/
void addSessionTimeoutAVP( struct DiamMessage *dmMessage, unsigned int uiSessionTimeout, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_SessionTimeout, uiSessionTimeout, iVendorId, iMandatory);
}


void setSessionTimeoutAVP( struct DiamAvp *dmAvp, unsigned int uiSessionTimeout, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_SessionTimeout, uiSessionTimeout, iVendorId, iMandatory);
}


/**
* AVP Code : 270
* Data Type : Unsigned32
*/
void addSessionBindingAVP( struct DiamMessage *dmMessage, unsigned int uiSessionBinding, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_SessionBinding, uiSessionBinding, iVendorId, iMandatory);
}


void setSessionBindingAVP( struct DiamAvp *dmAvp, unsigned int uiSessionBinding, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_SessionBinding, uiSessionBinding, iVendorId, iMandatory);
}


/**
* AVP Code : 265
* Data Type : Unsigned32
*/
void addSupportedVendorIdAVP( struct DiamMessage *dmMessage, unsigned int uiSupportedVendorId, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_SupportedVendorId, uiSupportedVendorId, iVendorId, iMandatory);
}


void setSupportedVendorIdAVP( struct DiamAvp *dmAvp, unsigned int uiSupportedVendorId, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_SupportedVendorId, uiSupportedVendorId, iVendorId, iMandatory);
}


/**
* AVP Code : 266
* Data Type : Unsigned32
*/
void addVendorIdAVP( struct DiamMessage *dmMessage, unsigned int uiVendorId, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_VendorId, uiVendorId, iVendorId, iMandatory);
}


void setVendorIdAVP( struct DiamAvp *dmAvp, unsigned int uiVendorId, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_VendorId, uiVendorId, iVendorId, iMandatory);
}


/**
* AVP Code : 415
* Data Type : Unsigned32
*/
void addCCRequestNumberAVP( struct DiamMessage *dmMessage, unsigned int uiCCRequestNumber, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_CCRequestNumber, uiCCRequestNumber, iVendorId, iMandatory);
}


void setCCRequestNumberAVP( struct DiamAvp *dmAvp, unsigned int uiCCRequestNumber, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_CCRequestNumber, uiCCRequestNumber, iVendorId, iMandatory);
}


/**
* AVP Code : 439
* Data Type : Unsigned32
*/
void addServiceIdentifierAVP( struct DiamMessage *dmMessage, unsigned int uiServiceIdentifier, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ServiceIdentifier, uiServiceIdentifier, iVendorId, iMandatory);
}


void setServiceIdentifierAVP( struct DiamAvp *dmAvp, unsigned int uiServiceIdentifier, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ServiceIdentifier, uiServiceIdentifier, iVendorId, iMandatory);
}


/**
* AVP Code : 1265
* Data Type : Unsigned32
*/
void addBaseTimeIntervalAVP( struct DiamMessage *dmMessage, unsigned int uiBaseTimeInterval, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_BaseTimeInterval, uiBaseTimeInterval, iVendorId, iMandatory);
}


void setBaseTimeIntervalAVP( struct DiamAvp *dmAvp, unsigned int uiBaseTimeInterval, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_BaseTimeInterval, uiBaseTimeInterval, iVendorId, iMandatory);
}


/**
* AVP Code : 827
* Data Type : Unsigned32
*/
void addContentLengthAVP( struct DiamMessage *dmMessage, unsigned int uiContentLength, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ContentLength, uiContentLength, iVendorId, iMandatory);
}


void setContentLengthAVP( struct DiamAvp *dmAvp, unsigned int uiContentLength, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ContentLength, uiContentLength, iVendorId, iMandatory);
}


/**
* AVP Code : 1206
* Data Type : Unsigned32
*/
void addContentSizeAVP( struct DiamMessage *dmMessage, unsigned int uiContentSize, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ContentSize, uiContentSize, iVendorId, iMandatory);
}


void setContentSizeAVP( struct DiamAvp *dmAvp, unsigned int uiContentSize, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ContentSize, uiContentSize, iVendorId, iMandatory);
}


/**
* AVP Code : 888
* Data Type : Unsigned32
*/
void addExpiresAVP( struct DiamMessage *dmMessage, unsigned int uiExpires, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_Expires, uiExpires, iVendorId, iMandatory);
}


void setExpiresAVP( struct DiamAvp *dmAvp, unsigned int uiExpires, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_Expires, uiExpires, iVendorId, iMandatory);
}


/**
* AVP Code : 2063
* Data Type : Unsigned32
*/
void addLocalSequenceNumberAVP( struct DiamMessage *dmMessage, unsigned int uiLocalSequenceNumber, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_LocalSequenceNumber, uiLocalSequenceNumber, iVendorId, iMandatory);
}


void setLocalSequenceNumberAVP( struct DiamAvp *dmAvp, unsigned int uiLocalSequenceNumber, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_LocalSequenceNumber, uiLocalSequenceNumber, iVendorId, iMandatory);
}


/**
* AVP Code : 1212
* Data Type : Unsigned32
*/
void addMessageSizeAVP( struct DiamMessage *dmMessage, unsigned int uiMessageSize, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_MessageSize, uiMessageSize, iVendorId, iMandatory);
}


void setMessageSizeAVP( struct DiamAvp *dmAvp, unsigned int uiMessageSize, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_MessageSize, uiMessageSize, iVendorId, iMandatory);
}


/**
* AVP Code : 2034
* Data Type : Unsigned32
*/
void addNumberOfDiversionsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfDiversions, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_NumberOfDiversions, uiNumberOfDiversions, iVendorId, iMandatory);
}


void setNumberOfDiversionsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfDiversions, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_NumberOfDiversions, uiNumberOfDiversions, iVendorId, iMandatory);
}


/**
* AVP Code : 2019
* Data Type : Unsigned32
*/
void addNumberOfMessagesSentAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfMessagesSent, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_NumberOfMessagesSent, uiNumberOfMessagesSent, iVendorId, iMandatory);
}


void setNumberOfMessagesSentAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfMessagesSent, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_NumberOfMessagesSent, uiNumberOfMessagesSent, iVendorId, iMandatory);
}


/**
* AVP Code : 885
* Data Type : Unsigned32
*/
void addNumberOfParticipantsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfParticipants, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_NumberOfParticipants, uiNumberOfParticipants, iVendorId, iMandatory);
}


void setNumberOfParticipantsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfParticipants, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_NumberOfParticipants, uiNumberOfParticipants, iVendorId, iMandatory);
}


/**
* AVP Code : 1282
* Data Type : Unsigned32
*/
void addNumberOfReceivedTalkBurstsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfReceivedTalkBursts, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_NumberOfReceivedTalkBursts, uiNumberOfReceivedTalkBursts, iVendorId, iMandatory);
}


void setNumberOfReceivedTalkBurstsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfReceivedTalkBursts, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_NumberOfReceivedTalkBursts, uiNumberOfReceivedTalkBursts, iVendorId, iMandatory);
}


/**
* AVP Code : 1283
* Data Type : Unsigned32
*/
void addNumberOfTalkBurstsAVP( struct DiamMessage *dmMessage, unsigned int uiNumberOfTalkBursts, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_NumberOfTalkBursts, uiNumberOfTalkBursts, iVendorId, iMandatory);
}


void setNumberOfTalkBurstsAVP( struct DiamAvp *dmAvp, unsigned int uiNumberOfTalkBursts, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_NumberOfTalkBursts, uiNumberOfTalkBursts, iVendorId, iMandatory);
}


/**
* AVP Code : 896
* Data Type : Unsigned32
*/
void addPDGChargingIdAVP( struct DiamMessage *dmMessage, unsigned int uiPDGChargingId, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_PDGChargingId, uiPDGChargingId, iVendorId, iMandatory);
}


void setPDGChargingIdAVP( struct DiamAvp *dmAvp, unsigned int uiPDGChargingId, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_PDGChargingId, uiPDGChargingId, iVendorId, iMandatory);
}


/**
* AVP Code : 2050
* Data Type : Unsigned32
*/
void addPDNConnectionIDAVP( struct DiamMessage *dmMessage, unsigned int uiPDNConnectionID, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_PDNConnectionID, uiPDNConnectionID, iVendorId, iMandatory);
}


void setPDNConnectionIDAVP( struct DiamAvp *dmAvp, unsigned int uiPDNConnectionID, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_PDNConnectionID, uiPDNConnectionID, iVendorId, iMandatory);
}


/**
* AVP Code : 881
* Data Type : Unsigned32
*/
void addQuotaConsumptionTimeAVP( struct DiamMessage *dmMessage, unsigned int uiQuotaConsumptionTime, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_QuotaConsumptionTime, uiQuotaConsumptionTime, iVendorId, iMandatory);
}


void setQuotaConsumptionTimeAVP( struct DiamAvp *dmAvp, unsigned int uiQuotaConsumptionTime, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_QuotaConsumptionTime, uiQuotaConsumptionTime, iVendorId, iMandatory);
}


/**
* AVP Code : 871
* Data Type : Unsigned32
*/
void addQuotaHoldingTimeAVP( struct DiamMessage *dmMessage, unsigned int uiQuotaHoldingTime, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_QuotaHoldingTime, uiQuotaHoldingTime, iVendorId, iMandatory);
}


void setQuotaHoldingTimeAVP( struct DiamAvp *dmAvp, unsigned int uiQuotaHoldingTime, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_QuotaHoldingTime, uiQuotaHoldingTime, iVendorId, iMandatory);
}


/**
* AVP Code : 1284
* Data Type : Unsigned32
*/
void addReceivedTalkBurstTimeAVP( struct DiamMessage *dmMessage, unsigned int uiReceivedTalkBurstTime, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ReceivedTalkBurstTime, uiReceivedTalkBurstTime, iVendorId, iMandatory);
}


void setReceivedTalkBurstTimeAVP( struct DiamAvp *dmAvp, unsigned int uiReceivedTalkBurstTime, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ReceivedTalkBurstTime, uiReceivedTalkBurstTime, iVendorId, iMandatory);
}


/**
* AVP Code : 1285
* Data Type : Unsigned32
*/
void addReceivedTalkBurstVolumeAVP( struct DiamMessage *dmMessage, unsigned int uiReceivedTalkBurstVolume, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ReceivedTalkBurstVolume, uiReceivedTalkBurstVolume, iVendorId, iMandatory);
}


void setReceivedTalkBurstVolumeAVP( struct DiamAvp *dmAvp, unsigned int uiReceivedTalkBurstVolume, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ReceivedTalkBurstVolume, uiReceivedTalkBurstVolume, iVendorId, iMandatory);
}


/**
* AVP Code : 2032
* Data Type : Unsigned32
*/
void addServiceModeAVP( struct DiamMessage *dmMessage, unsigned int uiServiceMode, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ServiceMode, uiServiceMode, iVendorId, iMandatory);
}


void setServiceModeAVP( struct DiamAvp *dmAvp, unsigned int uiServiceMode, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ServiceMode, uiServiceMode, iVendorId, iMandatory);
}


/**
* AVP Code : 1257
* Data Type : Unsigned32
*/
void addServiceSpecificTypeAVP( struct DiamMessage *dmMessage, unsigned int uiServiceSpecificType, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ServiceSpecificType, uiServiceSpecificType, iVendorId, iMandatory);
}


void setServiceSpecificTypeAVP( struct DiamAvp *dmAvp, unsigned int uiServiceSpecificType, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ServiceSpecificType, uiServiceSpecificType, iVendorId, iMandatory);
}


/**
* AVP Code : 2031
* Data Type : Unsigned32
*/
void addServiceTypeAVP( struct DiamMessage *dmMessage, unsigned int uiServiceType, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_ServiceType, uiServiceType, iVendorId, iMandatory);
}


void setServiceTypeAVP( struct DiamAvp *dmAvp, unsigned int uiServiceType, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_ServiceType, uiServiceType, iVendorId, iMandatory);
}


/**
* AVP Code : 1286
* Data Type : Unsigned32
*/
void addTalkBurstTimeAVP( struct DiamMessage *dmMessage, unsigned int uiTalkBurstTime, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_TalkBurstTime, uiTalkBurstTime, iVendorId, iMandatory);
}


void setTalkBurstTimeAVP( struct DiamAvp *dmAvp, unsigned int uiTalkBurstTime, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_TalkBurstTime, uiTalkBurstTime, iVendorId, iMandatory);
}


/**
* AVP Code : 1287
* Data Type : Unsigned32
*/
void addTalkBurstVolumeAVP( struct DiamMessage *dmMessage, unsigned int uiTalkBurstVolume, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_TalkBurstVolume, uiTalkBurstVolume, iVendorId, iMandatory);
}


void setTalkBurstVolumeAVP( struct DiamAvp *dmAvp, unsigned int uiTalkBurstVolume, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_TalkBurstVolume, uiTalkBurstVolume, iVendorId, iMandatory);
}


/**
* AVP Code : 868
* Data Type : Unsigned32
*/
void addTimeQuotaThresholdAVP( struct DiamMessage *dmMessage, unsigned int uiTimeQuotaThreshold, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_TimeQuotaThreshold, uiTimeQuotaThreshold, iVendorId, iMandatory);
}


void setTimeQuotaThresholdAVP( struct DiamAvp *dmAvp, unsigned int uiTimeQuotaThreshold, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_TimeQuotaThreshold, uiTimeQuotaThreshold, iVendorId, iMandatory);
}


/**
* AVP Code : 2045
* Data Type : Unsigned32
*/
void addTimeUsageAVP( struct DiamMessage *dmMessage, unsigned int uiTimeUsage, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_TimeUsage, uiTimeUsage, iVendorId, iMandatory);
}


void setTimeUsageAVP( struct DiamAvp *dmAvp, unsigned int uiTimeUsage, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_TimeUsage, uiTimeUsage, iVendorId, iMandatory);
}


/**
* AVP Code : 1226
* Data Type : Unsigned32
*/
void addUnitQuotaThresholdAVP( struct DiamMessage *dmMessage, unsigned int uiUnitQuotaThreshold, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_UnitQuotaThreshold, uiUnitQuotaThreshold, iVendorId, iMandatory);
}


void setUnitQuotaThresholdAVP( struct DiamAvp *dmAvp, unsigned int uiUnitQuotaThreshold, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_UnitQuotaThreshold, uiUnitQuotaThreshold, iVendorId, iMandatory);
}


/**
* AVP Code : 869
* Data Type : Unsigned32
*/
void addVolumeQuotaThresholdAVP( struct DiamMessage *dmMessage, unsigned int uiVolumeQuotaThreshold, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_VolumeQuotaThreshold, uiVolumeQuotaThreshold, iVendorId, iMandatory);
}


void setVolumeQuotaThresholdAVP( struct DiamAvp *dmAvp, unsigned int uiVolumeQuotaThreshold, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_VolumeQuotaThreshold, uiVolumeQuotaThreshold, iVendorId, iMandatory);
}


/**
* AVP Code : 893
* Data Type : Unsigned32
*/
void addWLANTechnologyAVP( struct DiamMessage *dmMessage, unsigned int uiWLANTechnology, int iVendorId, int iMandatory)
{
	addUnsigned32AVP( dmMessage, AVP_WLANTechnology, uiWLANTechnology, iVendorId, iMandatory);
}


void setWLANTechnologyAVP( struct DiamAvp *dmAvp, unsigned int uiWLANTechnology, int iVendorId, int iMandatory)
{
	setUnsigned32AVP( dmAvp, AVP_WLANTechnology, uiWLANTechnology, iVendorId, iMandatory);
}


/**
* AVP Code : 450
* Data Type : Enumerated
*/
void addSubscriptionIdTypeAVP( struct DiamMessage *dmMessage, int iSubscriptionIdType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SubscriptionIdType, iSubscriptionIdType, iVendorId, iMandatory);
}


void setSubscriptionIdTypeAVP( struct DiamAvp *dmAvp, int iSubscriptionIdType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SubscriptionIdType, iSubscriptionIdType, iVendorId, iMandatory);
}


/**
* AVP Code : 483
* Data Type : Enumerated
*/
void addAccountingRealtimeRequiredAVP( struct DiamMessage *dmMessage, int iAccountingRealtimeRequired, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_AccountingRealtimeRequired, iAccountingRealtimeRequired, iVendorId, iMandatory);
}


void setAccountingRealtimeRequiredAVP( struct DiamAvp *dmAvp, int iAccountingRealtimeRequired, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_AccountingRealtimeRequired, iAccountingRealtimeRequired, iVendorId, iMandatory);
}


/**
* AVP Code : 480
* Data Type : Enumerated
*/
void addAccountingRecordTypeAVP( struct DiamMessage *dmMessage, int iAccountingRecordType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_AccountingRecordType, iAccountingRecordType, iVendorId, iMandatory);
}


void setAccountingRecordTypeAVP( struct DiamAvp *dmAvp, int iAccountingRecordType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_AccountingRecordType, iAccountingRecordType, iVendorId, iMandatory);
}


/**
* AVP Code : 274
* Data Type : Enumerated
*/
void addAuthRequestTypeAVP( struct DiamMessage *dmMessage, int iAuthRequestType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_AuthRequestType, iAuthRequestType, iVendorId, iMandatory);
}


void setAuthRequestTypeAVP( struct DiamAvp *dmAvp, int iAuthRequestType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_AuthRequestType, iAuthRequestType, iVendorId, iMandatory);
}


/**
* AVP Code : 277
* Data Type : Enumerated
*/
void addAuthSessionStateAVP( struct DiamMessage *dmMessage, int iAuthSessionState, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_AuthSessionState, iAuthSessionState, iVendorId, iMandatory);
}


void setAuthSessionStateAVP( struct DiamAvp *dmAvp, int iAuthSessionState, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_AuthSessionState, iAuthSessionState, iVendorId, iMandatory);
}


/**
* AVP Code : 285
* Data Type : Enumerated
*/
void addReAuthRequestTypeAVP( struct DiamMessage *dmMessage, int iReAuthRequestType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_ReAuthRequestType, iReAuthRequestType, iVendorId, iMandatory);
}


void setReAuthRequestTypeAVP( struct DiamAvp *dmAvp, int iReAuthRequestType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_ReAuthRequestType, iReAuthRequestType, iVendorId, iMandatory);
}


/**
* AVP Code : 273
* Data Type : Enumerated
*/
void addDisconnectCauseAVP( struct DiamMessage *dmMessage, int iDisconnectCause, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_DisconnectCause, iDisconnectCause, iVendorId, iMandatory);
}


void setDisconnectCauseAVP( struct DiamAvp *dmAvp, int iDisconnectCause, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_DisconnectCause, iDisconnectCause, iVendorId, iMandatory);
}


/**
* AVP Code : 261
* Data Type : Enumerated
*/
void addRedirectHostUsageAVP( struct DiamMessage *dmMessage, int iRedirectHostUsage, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_RedirectHostUsage, iRedirectHostUsage, iVendorId, iMandatory);
}


void setRedirectHostUsageAVP( struct DiamAvp *dmAvp, int iRedirectHostUsage, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_RedirectHostUsage, iRedirectHostUsage, iVendorId, iMandatory);
}


/**
* AVP Code : 271
* Data Type : Enumerated
*/
void addSessionServerFailoverAVP( struct DiamMessage *dmMessage, int iSessionServerFailover, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_SessionServerFailover, iSessionServerFailover, iVendorId, iMandatory);
}


void setSessionServerFailoverAVP( struct DiamAvp *dmAvp, int iSessionServerFailover, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_SessionServerFailover, iSessionServerFailover, iVendorId, iMandatory);
}


/**
* AVP Code : 295
* Data Type : Enumerated
*/
void addTerminationCauseAVP( struct DiamMessage *dmMessage, int iTerminationCause, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_TerminationCause, iTerminationCause, iVendorId, iMandatory);
}


void setTerminationCauseAVP( struct DiamAvp *dmAvp, int iTerminationCause, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_TerminationCause, iTerminationCause, iVendorId, iMandatory);
}


/**
* AVP Code : 416
* Data Type : Enumerated
*/
void addCCRequestTypeAVP( struct DiamMessage *dmMessage, int iCCRequestType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_CCRequestType, iCCRequestType, iVendorId, iMandatory);
}


void setCCRequestTypeAVP( struct DiamAvp *dmAvp, int iCCRequestType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_CCRequestType, iCCRequestType, iVendorId, iMandatory);
}


/**
* AVP Code : 436
* Data Type : Enumerated
*/
void addRequestedActionAVP( struct DiamMessage *dmMessage, int iRequestedAction, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_RequestedAction, iRequestedAction, iVendorId, iMandatory);
}


void setRequestedActionAVP( struct DiamAvp *dmAvp, int iRequestedAction, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_RequestedAction, iRequestedAction, iVendorId, iMandatory);
}


/**
* AVP Code : 455
* Data Type : Enumerated
*/
void addMultipleServicesIndicatorAVP( struct DiamMessage *dmMessage, int iMultipleServicesIndicator, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_MultipleServicesIndicator, iMultipleServicesIndicator, iVendorId, iMandatory);
}


void setMultipleServicesIndicatorAVP( struct DiamAvp *dmAvp, int iMultipleServicesIndicator, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_MultipleServicesIndicator, iMultipleServicesIndicator, iVendorId, iMandatory);
}


/**
* AVP Code : 1217
* Data Type : Enumerated
*/
void addAdaptationsAVP( struct DiamMessage *dmMessage, int iAdaptations, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_Adaptations, iAdaptations, iVendorId, iMandatory);
}


void setAdaptationsAVP( struct DiamAvp *dmAvp, int iAdaptations, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_Adaptations, iAdaptations, iVendorId, iMandatory);
}


/**
* AVP Code : 1208
* Data Type : Enumerated
*/
void addAddresseeTypeAVP( struct DiamMessage *dmMessage, int iAddresseeType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_AddresseeType, iAddresseeType, iVendorId, iMandatory);
}


void setAddresseeTypeAVP( struct DiamAvp *dmAvp, int iAddresseeType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_AddresseeType, iAddresseeType, iVendorId, iMandatory);
}


/**
* AVP Code : 899
* Data Type : Enumerated
*/
void addAddressTypeAVP( struct DiamMessage *dmMessage, int iAddressType, int iVendorId, int iMandatory)
{
	addInteger32AVP( dmMessage, AVP_AddressType, iAddressType, iVendorId, iMandatory);
}


void setAddressTypeAVP( struct DiamAvp *dmAvp, int iAddressType, int iVendorId, int iMandatory)
{
	setInteger32AVP( dmAvp, AVP_AddressType, iAddressType, iVendorId, iMandatory);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Generated Code End
////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/*
void getAvpCode(struct DiamMessage* dmMsg, int *iAvpCode)
{
	*iAvpCode = dmMsg->CmdCode;
}
*/

void getCommandInfo(struct DiamMessage* dmMsg, int *iCmdCode, int *iIsRequest, int *iApplicationId, unsigned long *lH2HId, unsigned long *lE2EId)
{
	*iCmdCode = dmMsg->CmdCode;
	*iIsRequest = dmMsg->Flags.Request;
	*iApplicationId = dmMsg->AppId;
	*lH2HId = dmMsg->HBHId;
	*lE2EId = dmMsg->E2EId;
}

void copyHBHIdToTemp( struct DiamMessage * dmMsg)
{
	dmMsg->tempHBHId = dmMsg->HBHId;
}

void copyHBHIdFromTemp( struct DiamMessage * dmMsg)
{
	dmMsg->HBHId = dmMsg->tempHBHId;
}

long int getHBHId( struct DiamMessage * dmMsg)
{
	return dmMsg->HBHId;
}

void setHBHId( struct DiamMessage * dmMsg, long int hbhId)
{
	dmMsg->HBHId = hbhId;
}

int getCmdCode(struct DiamMessage* dmMsg)
{
	return dmMsg->CmdCode;
}

int isRequest(struct DiamMessage* dmMsg)
{
	return dmMsg->Flags.Request;
}

int isErrorBitSet(struct DiamMessage* dmMsg)
{
	return dmMsg->Flags.Error;
}

int isRetransmitBitSet(struct DiamMessage* dmMsg)
{
	return dmMsg->Flags.Retransmit;
}

int getApplicationId( struct DiamMessage* dmMsg)
{
	return dmMsg->AppId;
}

//struct DiamAvp


void getNewSessionId( char *sSessionId)
{
	unsigned long s1;
	int r1;
	unsigned long s2;	 
	
	pthread_mutex_lock( &objStackConfig.SessionIdLock);

	r1 = objStackConfig.SessionIdRotNo;	
	s1 = objStackConfig.SessionIdSeg1StartNo;
	s2 = objStackConfig.SessionIdSeg2StartNo;
		
	objStackConfig.SessionIdSeg1StartNo++;
	objStackConfig.SessionIdSeg2StartNo++;	
	
	pthread_mutex_unlock( &objStackConfig.SessionIdLock);
	
	sprintf( sSessionId, objStackConfig.SessionIdFormat, objStackConfig.SessionIdPrefix, s1, r1, s2);
}

void addNewSessionId( iDiamString *oDiamString)
{
	getNewSessionId( oDiamString->Value);
	oDiamString->Length = strlen( oDiamString->Value);
}

void helper_setDiamString( iDiamString *oDiamString, char *sValue, int iLen)
{
	if( iLen > 0)
	{	
		memcpy( oDiamString->Value, sValue, iLen);
		oDiamString->Length = iLen;
	}
	else
	{
		strcpy( oDiamString->Value, sValue);
		oDiamString->Length = strlen(sValue);
	}
}

void helper_setDiamStringTiny( iDiamStringTiny *oDiamString, char *sValue, int iLen)
{
	if( iLen > 0)
	{	
		memcpy( oDiamString->Value, sValue, iLen);
		oDiamString->Length = iLen;
	}
	else
	{
		strcpy( oDiamString->Value, sValue);
		oDiamString->Length = strlen(sValue);
	}
}

void helper_copyDiamString( iDiamString *oDstDiamString, iDiamString *oSrcDiamString)
{
	memcpy( oDstDiamString, oSrcDiamString, sizeof(iDiamString));
}

void addSessionId( struct DiamMessage * diamMessage)
{
	unsigned long s1;
	int r1;
	unsigned long s2;	 
	
	pthread_mutex_lock( &objStackConfig.SessionIdLock);

	r1 = objStackConfig.SessionIdRotNo;	
	s1 = objStackConfig.SessionIdSeg1StartNo;
	s2 = objStackConfig.SessionIdSeg2StartNo;
		
	objStackConfig.SessionIdSeg1StartNo++;
	objStackConfig.SessionIdSeg2StartNo++;	
	
	pthread_mutex_unlock( &objStackConfig.SessionIdLock);


	char sSessionId[250];
	memset( &sSessionId, 0, sizeof(sSessionId));

	sprintf( sSessionId, objStackConfig.SessionIdFormat, objStackConfig.SessionIdPrefix, s1, r1, s2);
		
	//strcpy( sSessionId, "rggsn;1465017251;577655;3_13546");

	addSessionIdAVP( diamMessage, sSessionId, 0, 1, strlen(sSessionId));
}

void addOriginHost( struct DiamMessage * diamMessage)
{
	struct DiamAvp * dmAvpOriginHost = (struct DiamAvp *)allocateDiamAvp();
	if( oApplicationServer) {
		encodeOriginHostAVP( (char*)oApplicationServer->StartedHosts[0].sHostName, dmAvpOriginHost, 0, strlen(oApplicationServer->StartedHosts[0].sHostName));
	} else {
		encodeOriginHostAVP( (char*)objStackConfig.HostName, dmAvpOriginHost, 0, strlen(objStackConfig.HostName));
	}
	appAddAvpToDiamMessage( diamMessage, dmAvpOriginHost);
}

void addOriginRealm( struct DiamMessage * diamMessage)
{
	struct DiamAvp * dmAvpOriginRealm = (struct DiamAvp *)allocateDiamAvp();
	if( oApplicationServer) {
		encodeOriginRealmAVP( (char*)oApplicationServer->StartedHosts[0].sHostRealm, dmAvpOriginRealm, 0, strlen(oApplicationServer->StartedHosts[0].sHostRealm));
	} else {
		encodeOriginRealmAVP( (char*)objStackConfig.HostRealmName, dmAvpOriginRealm, 0, strlen(objStackConfig.HostRealmName));
	}
	appAddAvpToDiamMessage( diamMessage, dmAvpOriginRealm);
}

void addDestinationRealm( struct DiamMessage * diamMessage, int iPeerIndex)
{
	//struct DiamAvp * dmAvpDestinationRealm = (struct DiamAvp *)allocateDiamAvp();
	//encodeOriginRealmAVP( (char*)objStackConfig.Peers[iPeerIndex].PeerHostRealmName, dmAvpDestinationRealm, 0, strlen(objStackConfig.Peers[iPeerIndex].PeerHostRealmName));
	//addDestinationRealmAVP
	//appAddAvpToDiamMessage( diamMessage, dmAvpDestinationRealm);
	addDestinationRealmAVP( diamMessage, (char*)objStackConfig.Peers[iPeerIndex].PeerHostRealmName, 0, 1, strlen(objStackConfig.Peers[iPeerIndex].PeerHostRealmName));
}

void addOriginStateId( struct DiamMessage * diamMessage)
{
	addOriginStateIdAVP( diamMessage, 2319, 0, 1);
}

void addSubscriptionIdEndUserE164( struct DiamMessage * diamMessage, char *sEndUserE164, int len)
{
	struct DiamAvp *oSubscriptionIdTypeAvp1 = (struct DiamAvp*)allocateDiamAvp();
    setSubscriptionIdTypeAVP( oSubscriptionIdTypeAvp1, 0, 0, 1);
	
	struct DiamAvp *oSubscriptionIdDataAvp1 = (struct DiamAvp*)allocateDiamAvp();
    setSubscriptionIdDataAVP( oSubscriptionIdDataAvp1, sEndUserE164, 0, 1, len);
	
	struct DiamAvp *oSubscriptionIdAvp = (struct DiamAvp*)allocateDiamAvp();
    setSubscriptionIdAVP( diamMessage, oSubscriptionIdAvp, 0, 1 );	
	
	addAvp( oSubscriptionIdAvp, oSubscriptionIdTypeAvp1);
	addAvp( oSubscriptionIdAvp, oSubscriptionIdDataAvp1);
}

void addSubscriptionIdIMSI( struct DiamMessage * diamMessage, char *sIMSI, int len)
{
	struct DiamAvp *oSubscriptionIdTypeAvp1 = (struct DiamAvp*)allocateDiamAvp();
    setSubscriptionIdTypeAVP( oSubscriptionIdTypeAvp1, 1, 0, 1);
	
	struct DiamAvp *oSubscriptionIdDataAvp1 = (struct DiamAvp*)allocateDiamAvp();
    setSubscriptionIdDataAVP( oSubscriptionIdDataAvp1, sIMSI, 0, 1, len);	
	
	struct DiamAvp *oSubscriptionIdAvp = (struct DiamAvp*)allocateDiamAvp();
    setSubscriptionIdAVP( diamMessage, oSubscriptionIdAvp, 0, 1 );	
	
	addAvp( oSubscriptionIdAvp, oSubscriptionIdTypeAvp1);
	addAvp( oSubscriptionIdAvp, oSubscriptionIdDataAvp1);	
}

void createDiamAvp(struct DiamAvp * dmAvp, struct DiamMessage * diamMessage)
{
	dmAvp = (struct DiamAvp *)allocateDiamAvp();
	memset( dmAvp, 0, sizeof(struct DiamAvp));
	appAddAvpToDiamMessage( diamMessage, dmAvp);
}


void createWatchDogRequest(struct DiamMessage * dmCER)
{
	dmCER->Flags.Request = 1;
	//dmCER->Flags.Proxyable = 0;
	//dmCER->CmdCode = 280;
	//dmCER->AppId = 0;
	//dmCER->HBHId = 0;
	//dmCER->E2EId = 0;
	initDiamRequest( dmCER, 0, 280, 0);

	addOriginHost( dmCER);
	addOriginRealm( dmCER);
	addOriginStateId( dmCER);
}




void createWatchDogAnswer(struct DiamMessage * dmCEA, struct DiamMessage * dmCER)
{
	dmCEA->Flags.Request = 0;
	dmCEA->Flags.Proxyable = 0;
	dmCEA->CmdCode = dmCER->CmdCode;
	dmCEA->AppId = dmCER->AppId;
	dmCEA->HBHId = dmCER->HBHId;
	dmCEA->E2EId = dmCER->E2EId;

	dmCEA->AvpCount = 0;

	addResultCodeAVP( dmCEA, 2001, 0, 1);
	addOriginHost( dmCEA);
	addOriginRealm( dmCEA);
}

void initDiamAnswer(struct DiamMessage * diamMessageRequest, struct DiamMessage * diamMessageAnswer, int iProxyable)
{
	diamMessageAnswer->Flags.Request = 0;
	diamMessageAnswer->Flags.Proxyable = iProxyable;
	diamMessageAnswer->CmdCode = diamMessageRequest->CmdCode;
	diamMessageAnswer->AppId = diamMessageRequest->AppId;
	diamMessageAnswer->HBHId = diamMessageRequest->HBHId;
	diamMessageAnswer->E2EId = diamMessageRequest->E2EId;	
}




void initDiamRequest(struct DiamMessage * diamMessage, int iProxyable, int iCmdCode, int iAppId)
{
	diamMessage->Flags.Request = 1;
	diamMessage->Flags.Proxyable = iProxyable;
	diamMessage->CmdCode = iCmdCode;
	diamMessage->AppId = iAppId;
	
	pthread_mutex_lock( &objStackConfig.SessionIdLock);

	diamMessage->HBHId = objStackConfig.HBHId;
	diamMessage->E2EId = objStackConfig.E2EId;

	objStackConfig.E2EId++;
	objStackConfig.HBHId++;	

	pthread_mutex_unlock( &objStackConfig.SessionIdLock);
	
	diamMessage->AvpCount = 0;
}

void setE2EId( struct DiamMessage * diamMessage, unsigned long E2EId)
{
	diamMessage->E2EId = E2EId;
}

void setRetransmit( struct DiamMessage * diamMessage)
{
	diamMessage->Flags.Retransmit = 1;
}

void getE2EId( struct DiamMessage * diamMessage, unsigned long *E2EId)
{
	*E2EId = diamMessage->E2EId;
}

void createDiamChildAvp(struct DiamAvp * dmAvp, struct DiamAvp * dmParentAvp)
{
	dmAvp = (struct DiamAvp *)allocateDiamAvp();
	memset( dmAvp, 0, sizeof(struct DiamAvp));
}

void addVendorSpecificApplicationId( struct DiamMessage * diamMessage, unsigned int iVendorId, unsigned int iAuthApplicationId);

void createDPR( struct DiamMessage * dmCER)
{
	dmCER->Flags.Request = 1;
	initDiamRequest( dmCER, 0, 282, 0);	
	addOriginHostAVP( dmCER, (char*)objStackConfig.HostName, 0, 1, strlen(objStackConfig.HostName));
	addOriginRealmAVP( dmCER, (char*)objStackConfig.HostRealmName, 0, 1, strlen(objStackConfig.HostRealmName));	
	addDisconnectCauseAVP( dmCER, 2, 0, 1);
}

void createCER( struct DiamMessage * dmCER, int iAuthApplicationId, int iPeerThreadIndex)
{
	dmCER->Flags.Request = 1;
	initDiamRequest( dmCER, 0, 257, 0);

	dmCER->AvpCount = 0;
	
	#if DIAMDRA
	
		if( iPeerThreadIndex >= 0)
		{	
			if( strlen(objStackConfig.Peers[iPeerThreadIndex].ClientHostName)  > 0)
			{
				addOriginHostAVP( dmCER, (char*)objStackConfig.Peers[iPeerThreadIndex].ClientHostName, 0, 1, strlen(objStackConfig.Peers[iPeerThreadIndex].ClientHostName));
				addOriginRealmAVP( dmCER, (char*)objStackConfig.Peers[iPeerThreadIndex].ClientHostRealmName, 0, 1, strlen(objStackConfig.Peers[iPeerThreadIndex].ClientHostRealmName));	
			}
			else
			{
				addOriginHostAVP( dmCER, (char*)objStackConfig.HostName, 0, 1, strlen(objStackConfig.HostName));
				addOriginRealmAVP( dmCER, (char*)objStackConfig.HostRealmName, 0, 1, strlen(objStackConfig.HostRealmName));
			}	
		}
		else
		{
			addOriginHostAVP( dmCER, (char*)objStackConfig.HostName, 0, 1, strlen(objStackConfig.HostName));
			addOriginRealmAVP( dmCER, (char*)objStackConfig.HostRealmName, 0, 1, strlen(objStackConfig.HostRealmName));			
		}
	#else
		addOriginHostAVP( dmCER, (char*)objStackConfig.HostName, 0, 1, strlen(objStackConfig.HostName));
		addOriginRealmAVP( dmCER, (char*)objStackConfig.HostRealmName, 0, 1, strlen(objStackConfig.HostRealmName));
	#endif
	
	addVendorIdAVP( dmCER, objStackConfig.VendorId, 0, 1);
	addProductNameAVP( dmCER, (char*)objStackConfig.ProductName, 0, 1, strlen(objStackConfig.ProductName));

	
	#if DIAMDRA
		
		if( iPeerThreadIndex >= 0)
		{
			if( strlen(objStackConfig.Peers[iPeerThreadIndex].ClientHostName)  > 0)
			{
				addAuthApplicationIdAVP( dmCER, iAuthApplicationId, 0, 0);				
			}
			else
			{
				addAuthApplicationIdAVP( dmCER, 4294967295, 0, 0);
			}
		}
		else
		{
			addAuthApplicationIdAVP( dmCER, 4294967295, 0, 0);
		}
	#else
		if( iAuthApplicationId > 0 && objStackConfig.iAuthApplicationIdCount == 0)
		{
			addAuthApplicationIdAVP( dmCER, iAuthApplicationId, 0, 0);
		}		
		
		int i;
		
		for( i = 0; i < objStackConfig.iAuthApplicationIdCount; i++)
		{
			addAuthApplicationIdAVP( dmCER, objStackConfig.iAuthApplicationId[i], 0, 0);
		}
		
		for( i = 0; i < objStackConfig.iAcctApplicationIdCount; i++)
		{
			addAuthApplicationIdAVP( dmCER, objStackConfig.iAcctApplicationId[i], 0, 0);
		}

		for( i = 0; i < objStackConfig.iVendorSpecificAuthApplicationIdCount; i++)
		{
			addVendorSpecificApplicationId( dmCER, objStackConfig.VendorSpecificAuthApplicationId[i].iVendorId, objStackConfig.VendorSpecificAuthApplicationId[i].iAuthApplicationId );
		}
		
	#endif
	
	addHostIPAddressAVP( dmCER, (char *)objStackConfig.IP, 0, 1 );
	addOriginStateIdAVP( dmCER, 0, 0, 1);
	addInbandSecurityIdAVP( dmCER, 0, 0, 1);
	addFirmwareRevisionAVP( dmCER, 1, 0, 0);	
}

void createCEA( struct DiamMessage * dmCEA, struct DiamMessage * dmCER, unsigned int iResultCode, unsigned int iRequestedAppId)
{
	dmCEA->Flags.Request = 0;
	dmCEA->Flags.Proxyable = 0;
	dmCEA->CmdCode = dmCER->CmdCode;
	dmCEA->AppId = dmCER->AppId;
	dmCEA->HBHId = dmCER->HBHId;
	dmCEA->E2EId = dmCER->E2EId;

	dmCEA->AvpCount = 0;

	addResultCodeAVP( dmCEA, iResultCode, 0, 1 );
	addOriginHost( dmCEA);
	addOriginRealm( dmCEA);
	addHostIPAddressAVP( dmCEA, (char *)objStackConfig.IP, 0, 1 );
	addVendorIdAVP( dmCEA, objStackConfig.VendorId, 0, 1);
	addProductNameAVP( dmCEA, (char*)objStackConfig.ProductName, 0, 1, strlen(objStackConfig.ProductName));
	addOriginStateId( dmCEA);
	addErrorMessageAVP( dmCEA, (char*)"DIAMETER_SUCCESS", 0, 1, 16);
	
	int i = 0;
	for( i = 0; i < objStackConfig.NoOfAppSupported; i++)
	{
		addAuthApplicationIdAVP( dmCEA, objStackConfig.SupportedAppIds[i], 0, 0);
	}
	
	addInbandSecurityIdAVP( dmCEA, 0, 0, 1);
	addVendorSpecificApplicationId( dmCEA, 10415, iRequestedAppId);
	addFirmwareRevisionAVP( dmCEA, 2, 0, 0);
}

void createCEA2(struct DiamMessage * dmCEA, struct DiamMessage * dmCER, unsigned int iResultCode, iHostConfigData * oHostConfigData)
{
	//requires validation, hence not using this et all
	
	dmCEA->Flags.Request = 0;
	dmCEA->Flags.Proxyable = 0;
	dmCEA->CmdCode = dmCER->CmdCode;
	dmCEA->AppId = dmCER->AppId;
	dmCEA->HBHId = dmCER->HBHId;
	dmCEA->E2EId = dmCER->E2EId;

	dmCEA->AvpCount = 0;

	addResultCodeAVP( dmCEA, iResultCode, 0, 1 );
	addOriginHostAVP( dmCEA, (char*)oHostConfigData->sHostName, 0, 1, strlen(oHostConfigData->sHostName));
	addHostIPAddressAVP( dmCEA, (char *)objStackConfig.IP, 0, 1 );
	addOriginRealmAVP( dmCEA, (char*)oHostConfigData->sHostRealm, 0, 1, strlen(oHostConfigData->sHostRealm));
	
	addVendorIdAVP( dmCEA, 10415, 0, 1);
	addProductNameAVP( dmCEA, (char*)oHostConfigData->sProdName, 0, 1, strlen(oHostConfigData->sProdName));
	addOriginStateId( dmCEA);
	addErrorMessageAVP( dmCEA, (char*)"DIAMETER_SUCCESS", 0, 1, 16);
	addInbandSecurityIdAVP( dmCEA, 0, 0, 1);
	addFirmwareRevisionAVP( dmCEA, 2, 0, 0);
}


void createDWA2(struct DiamMessage* dmMessage, struct DiamMessage* dmMessageRequest, int iResultCode, iHostConfigData * oHostConfigData)
{
	dmMessage->Flags.Request = 0;
	dmMessage->Flags.Proxyable = 0;
	dmMessage->CmdCode = dmMessageRequest->CmdCode;
	dmMessage->AppId = dmMessageRequest->AppId;
	dmMessage->HBHId = dmMessageRequest->HBHId;
	dmMessage->E2EId = dmMessageRequest->E2EId;

	dmMessage->AvpCount = 0;

	addResultCodeAVP( dmMessage, iResultCode, 0, 1 );
	addOriginHostAVP( dmMessage, (char*)oHostConfigData->sHostName, 0, 1, strlen(oHostConfigData->sHostName));
	addOriginRealmAVP( dmMessage, (char*)oHostConfigData->sHostRealm, 0, 1, strlen(oHostConfigData->sHostRealm));
	
	addOriginStateId( dmMessage);
	addErrorMessageAVP( dmMessage, (char*)"DIAMETER_SUCCESS", 0, 1, 16);

	//encodeDiamMessage( dmMessage );
}

void createDWA(struct DiamMessage* dmMessage, struct DiamMessage* dmMessageRequest, int iResultCode)
{
	dmMessage->Flags.Request = 0;
	dmMessage->Flags.Proxyable = 0;
	dmMessage->CmdCode = dmMessageRequest->CmdCode;
	dmMessage->AppId = dmMessageRequest->AppId;
	dmMessage->HBHId = dmMessageRequest->HBHId;
	dmMessage->E2EId = dmMessageRequest->E2EId;

	dmMessage->AvpCount = 0;

	addResultCodeAVP( dmMessage, iResultCode, 0, 1 );
	addOriginHost( dmMessage);
	addOriginRealm( dmMessage);
	
	addOriginStateId( dmMessage);
	addErrorMessageAVP( dmMessage, (char*)"DIAMETER_SUCCESS", 0, 1, 16);

	//encodeDiamMessage( dmMessage );
}


void freeDiamRawData(struct DiamRawData* dDiamRawData)
{
	//printf("freeing DiamRawData\n");

	/*
	free(dDiamRawData->Header->Data);
	dDiamRawData->Header->Data = NULL;

	free(dDiamRawData->PayLoad->Data);
	dDiamRawData->PayLoad->Data = NULL;

	free(dDiamRawData->Header);
	free(dDiamRawData->PayLoad);
	free(dDiamRawData);

	dDiamRawData->Header = NULL;
	dDiamRawData->PayLoad = NULL;
	dDiamRawData = NULL;
	*/
}

struct DiamAvp* iteratorMoveFirst(struct DiamMessage* dmMsg);
struct DiamAvp* iteratorMoveNext(struct DiamMessage* dmMsg);
struct DiamAvp* avpIteratorMoveFirst(struct DiamAvp* dmAvp);
struct DiamAvp* avpIteratorMoveNext(struct DiamAvp* dmAvp);

int hasVendorIdInDiamMessage( struct DiamMessage* dmMsg, unsigned int iVendorId)
{
	struct DiamAvp* dmAvp = (struct DiamAvp*)iteratorMoveFirst(dmMsg);
	int iAvpCode = 0;
	
	while(dmAvp)
	{
		iAvpCode = getAvpCode(dmAvp);
		if( iAvpCode == 266 )
		{
			//printf("usIntVal %u iVendorId(%u) dt[%d]\n", dmAvp->usIntVal , iVendorId, dmAvp->iDataType);
			if( dmAvp->usIntVal == iVendorId)
				return 1;
		}
		dmAvp = (struct DiamAvp*) iteratorMoveNext(dmMsg);
	}
	return 0;
}

int hasAuthApplicationIdInDiamMessage( struct DiamMessage* dmMsg, unsigned int iAuthApplicationId)
{
	struct DiamAvp* dmAvp = (struct DiamAvp*)iteratorMoveFirst(dmMsg);
	int iAvpCode = 0;
	
	while(dmAvp)
	{
		iAvpCode = getAvpCode(dmAvp);
		if( iAvpCode == 258 )
		{
			if( dmAvp->usIntVal == iAuthApplicationId)
				return 1;
		}
		dmAvp = (struct DiamAvp*) iteratorMoveNext(dmMsg);
	}
	return 0;
}

int hasAcctApplicationIdInDiamMessage( struct DiamMessage* dmMsg, unsigned int iAcctApplicationId)
{
	struct DiamAvp* dmAvp = (struct DiamAvp*)iteratorMoveFirst(dmMsg);
	int iAvpCode = 0;
	
	while(dmAvp)
	{
		iAvpCode = getAvpCode(dmAvp);
		if( iAvpCode == 259 )
		{
			if( dmAvp->usIntVal == iAcctApplicationId)
				return 1;
		}
		dmAvp = (struct DiamAvp*) iteratorMoveNext(dmMsg);
	}
	return 0;
}

unsigned int core_getUnsignedIntFromGroupedAVP(struct DiamAvp* parentDmAvp, int iAVPCode)
{
	struct DiamAvp* dmAvp = (struct DiamAvp*)avpIteratorMoveFirst( parentDmAvp);
	
	while(dmAvp)
	{
		int ilvAvpCode = getAvpCode(dmAvp);
		
		if( iAVPCode == ilvAvpCode)
		{
			return dmAvp->usIntVal;
		}
		
		dmAvp = (struct DiamAvp*) avpIteratorMoveNext( parentDmAvp);
	}
	return -1;
}

int hasVSApplicationIdInDiamMessage( struct DiamMessage* dmMsg, unsigned int iVendorId, unsigned int iAuthApplicationId)
{
	struct DiamAvp* dmAvp = (struct DiamAvp*)iteratorMoveFirst(dmMsg);
	int iAvpCode = 0;
	
	while(dmAvp)
	{
		iAvpCode = getAvpCode(dmAvp);
		if( iAvpCode == 260 )
		{
			unsigned int iAuthApplicationIdFromMsg = -1;
			unsigned int iVendorIdFromMsg = -1;
			
			iVendorIdFromMsg = core_getUnsignedIntFromGroupedAVP( dmAvp, 266);
			iAuthApplicationIdFromMsg = core_getUnsignedIntFromGroupedAVP( dmAvp, 258);
			
			if( iAuthApplicationIdFromMsg == iAuthApplicationId && iVendorId == iVendorIdFromMsg)
				return 1;		
		}
		dmAvp = (struct DiamAvp*) iteratorMoveNext(dmMsg);
	}
	return 0;
}

void releaseClientInfo(iClientInfo* oClientInfo);



//10024
void appValidateCERAndSendCEA2( struct DiamMessage* oDiamMessage, iClientInfo * cliInfo, int iPeerIndex)
{
	if(!cliInfo)
	{
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "cliInfo got NULL");
		return;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received CER From Client Fd[%d]", cliInfo->fd);
	
	if( cliInfo->HostConfig)
	{
		iHostConfigData * oHostConfigData = (iHostConfigData *)cliInfo->HostConfig;
		
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "HostRealm[%s] sHostName[%s] iValApp[%d] iAcceptUnknownPeer[%d]",
				oHostConfigData->sHostRealm, oHostConfigData->sHostName, 
				oHostConfigData->iValidateSuppApplications, oHostConfigData->iAcceptUnknownPeer);
		
		int bFoundOrigHost = 0;
		int bFoundOrigRealm = 0;
		int bFoundInbandSecurity = 0;
		
		unsigned int usInbandSecurity = 0;
		
		struct DiamMessage *dmMessage = (struct DiamMessage *)allocateMessage();
		
		dmMessage->Flags.Request = 0;
		dmMessage->Flags.Proxyable = 0;
		dmMessage->CmdCode = oDiamMessage->CmdCode;
		dmMessage->AppId = oDiamMessage->AppId;
		dmMessage->HBHId = oDiamMessage->HBHId;
		dmMessage->E2EId = oDiamMessage->E2EId;
		dmMessage->AvpCount = 0;

		struct DiamAvp* dmAvp = NULL;
		dmAvp = oDiamMessage->Head;		
		
		while(dmAvp)	
		{
			if(dmAvp->AvpCode == AVP_OriginRealm)
			{
				memcpy( cliInfo->OriginRealm, dmAvp->PayLoad->Data, dmAvp->PayLoad->len);	
				memcpy( cliInfo->ClientHostRealmName, dmAvp->PayLoad->Data, dmAvp->PayLoad->len);
				bFoundOrigRealm = 1;
			}
			else if(dmAvp->AvpCode == 299)
			{
				usInbandSecurity = dmAvp->usIntVal;
				bFoundInbandSecurity = 1;
			}
			else if( dmAvp->AvpCode == AVP_OriginHost)
			{
				memcpy( cliInfo->ClientHostName, dmAvp->PayLoad->Data, dmAvp->PayLoad->len);
				bFoundOrigHost = 1;				
			}
			
			if( bFoundOrigRealm == 1 && bFoundInbandSecurity == 1 && bFoundOrigHost == 1)
				break;
			
			dmAvp = dmAvp->Next;
		}
		
		addResultCodeAVP( dmMessage, 2001, 0, 1 );
		struct DiamAvp * dmResultCodeAvp = dmMessage->Current;
		
		addOriginHostAVP( dmMessage, (char*)oHostConfigData->sHostName, 0, 1, strlen(oHostConfigData->sHostName));
		addOriginRealmAVP( dmMessage, (char*)oHostConfigData->sHostRealm, 0, 1, strlen(oHostConfigData->sHostRealm));
		
		
		/* 
		printf("HostName :%s %ld, HostRealm :%s %ld \n", 
			oHostConfigData->sHostName, strlen(oHostConfigData->sHostName), 
			oHostConfigData->sHostRealm, strlen(oHostConfigData->sHostRealm));
		*/

		addOriginStateId( dmMessage);
		
		//------------------------------------------------------------
		if( oHostConfigData->uiVendId1 > 0)
		{	
			if( hasVendorIdInDiamMessage( oDiamMessage, oHostConfigData->uiVendId1) == 1)
			{
				addVendorIdAVP( dmMessage, oHostConfigData->uiVendId1, 0, 0);
				cliInfo->VendorIds[cliInfo->VendorIdsCount] = oHostConfigData->uiVendId1;
				cliInfo->VendorIdsCount++;
			}
		}
		
		if( oHostConfigData->uiVendId2 > 0)
		{
			if( hasVendorIdInDiamMessage( oDiamMessage, oHostConfigData->uiVendId2) == 1)
			{
				addVendorIdAVP( dmMessage, oHostConfigData->uiVendId2, 0, 0);
				cliInfo->VendorIds[cliInfo->VendorIdsCount] = oHostConfigData->uiVendId2;
				cliInfo->VendorIdsCount++;
			}
		}
		
		if( oHostConfigData->uiVendId3 > 0)
		{
			if( hasVendorIdInDiamMessage( oDiamMessage, oHostConfigData->uiVendId3) == 1)
			{	
				addVendorIdAVP( dmMessage, oHostConfigData->uiVendId3, 0, 0);
				cliInfo->VendorIds[cliInfo->VendorIdsCount] = oHostConfigData->uiVendId3;
				cliInfo->VendorIdsCount++;				
			}
		}
		
		if( oHostConfigData->uiVendId4 > 0)
		{	
			if( hasVendorIdInDiamMessage( oDiamMessage, oHostConfigData->uiVendId4) == 1)
			{	
				addVendorIdAVP( dmMessage, oHostConfigData->uiVendId4, 0, 0);
				cliInfo->VendorIds[cliInfo->VendorIdsCount] = oHostConfigData->uiVendId4;
				cliInfo->VendorIdsCount++;					
			}
		}
		
		if( oHostConfigData->uiVendId5 > 0)
		{	
			if( hasVendorIdInDiamMessage( oDiamMessage, oHostConfigData->uiVendId5) == 1)
			{
				addVendorIdAVP( dmMessage, oHostConfigData->uiVendId5, 0, 0);		
				cliInfo->VendorIds[cliInfo->VendorIdsCount] = oHostConfigData->uiVendId5;
				cliInfo->VendorIdsCount++;				
			}
		}
		
		//------------------------------------------------------------
		int bFoundCommonApplication = 0;
		
		if( oHostConfigData->uiAuthAppId1 > 0)
		{
			if( hasAuthApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAuthAppId1) == 1) 
			{
				addAuthApplicationIdAVP( dmMessage, oHostConfigData->uiAuthAppId1, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AuthApplicationIds[cliInfo->AuthApplicationIdsCount] = oHostConfigData->uiAuthAppId1;
				cliInfo->AuthApplicationIdsCount++;
			}
		}
		
		if( oHostConfigData->uiAuthAppId2 > 0) 
		{
			if( hasAuthApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAuthAppId2) == 1) 
			{
				addAuthApplicationIdAVP( dmMessage, oHostConfigData->uiAuthAppId2, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AuthApplicationIds[cliInfo->AuthApplicationIdsCount] = oHostConfigData->uiAuthAppId2;
				cliInfo->AuthApplicationIdsCount++;				
			}
		}
		
		if( oHostConfigData->uiAuthAppId3 > 0) 
		{
			if( hasAuthApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAuthAppId3) == 1) 
			{
				addAuthApplicationIdAVP( dmMessage, oHostConfigData->uiAuthAppId3, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AuthApplicationIds[cliInfo->AuthApplicationIdsCount] = oHostConfigData->uiAuthAppId3;
				cliInfo->AuthApplicationIdsCount++;				
			}
		}
		
		if( oHostConfigData->uiAuthAppId4 > 0) 
		{
			if( hasAuthApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAuthAppId4) == 1) 
			{
				addAuthApplicationIdAVP( dmMessage, oHostConfigData->uiAuthAppId4, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AuthApplicationIds[cliInfo->AuthApplicationIdsCount] = oHostConfigData->uiAuthAppId4;
				cliInfo->AuthApplicationIdsCount++;				
			}
		}
		
		if( oHostConfigData->uiAuthAppId5 > 0)
		{
			if( hasAuthApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAuthAppId5) == 1)
			{
				addAuthApplicationIdAVP( dmMessage, oHostConfigData->uiAuthAppId5, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AuthApplicationIds[cliInfo->AuthApplicationIdsCount] = oHostConfigData->uiAuthAppId5;
				cliInfo->AuthApplicationIdsCount++;				
			}
		}
		
		//------------------------------------------------------------
		
		if( oHostConfigData->uiAcctAppId1 > 0)
		{
			if( hasAcctApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAcctAppId1) == 1)
			{
				addAcctApplicationIdAVP( dmMessage, oHostConfigData->uiAcctAppId1, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AcctApplicationIds[cliInfo->AcctApplicationIdsCount] = oHostConfigData->uiAcctAppId1;
				cliInfo->AcctApplicationIdsCount++;
			}
		}
		
		if( oHostConfigData->uiAcctAppId2 > 0)
		{
			if( hasAcctApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAcctAppId2) == 1)
			{
				addAcctApplicationIdAVP( dmMessage, oHostConfigData->uiAcctAppId2, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AcctApplicationIds[cliInfo->AcctApplicationIdsCount] = oHostConfigData->uiAcctAppId2;
				cliInfo->AcctApplicationIdsCount++;
			}
		}
		
		if( oHostConfigData->uiAcctAppId3 > 0)
		{
			if( hasAcctApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAcctAppId3) == 1)
			{
				addAcctApplicationIdAVP( dmMessage, oHostConfigData->uiAcctAppId3, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AcctApplicationIds[cliInfo->AcctApplicationIdsCount] = oHostConfigData->uiAcctAppId3;
				cliInfo->AcctApplicationIdsCount++;				
			}
		}
		
		if( oHostConfigData->uiAcctAppId4 > 0)
		{
			if( hasAcctApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAcctAppId4) == 1)
			{
				addAcctApplicationIdAVP( dmMessage, oHostConfigData->uiAcctAppId4, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AcctApplicationIds[cliInfo->AcctApplicationIdsCount] = oHostConfigData->uiAcctAppId4;
				cliInfo->AcctApplicationIdsCount++;				
			}
		}
		
		if( oHostConfigData->uiAcctAppId5 > 0)
		{
			if( hasAcctApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiAcctAppId5) == 1)
			{
				addAcctApplicationIdAVP( dmMessage, oHostConfigData->uiAcctAppId5, 0, 0);
				bFoundCommonApplication = 1;
				cliInfo->AcctApplicationIds[cliInfo->AcctApplicationIdsCount] = oHostConfigData->uiAcctAppId5;
				cliInfo->AcctApplicationIdsCount++;				
			}
		}
		
		//-------------------------------------------------------------
		if( oHostConfigData->uiSuppVen1 > 0 && oHostConfigData->uiSuppApp1 > 0)
		{
			if( hasVSApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiSuppVen1, oHostConfigData->uiSuppApp1) == 1)
			{
				addVendorSpecificApplicationId( dmMessage, oHostConfigData->uiSuppVen1, oHostConfigData->uiSuppApp1 );
				bFoundCommonApplication = 1;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iAuthApplicationId = oHostConfigData->uiSuppApp1;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iVendorId = oHostConfigData->uiSuppVen1;
				cliInfo->SupportedVendorApplicationIdsCount++;
			}
		}
		
		if( oHostConfigData->uiSuppVen2 > 0 && oHostConfigData->uiSuppApp2 > 0)
		{
			if( hasVSApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiSuppVen2, oHostConfigData->uiSuppApp2) == 1)
			{
				addVendorSpecificApplicationId( dmMessage, oHostConfigData->uiSuppVen2, oHostConfigData->uiSuppApp2 );
				bFoundCommonApplication = 1;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iAuthApplicationId = oHostConfigData->uiSuppApp2;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iVendorId = oHostConfigData->uiSuppVen2;
				cliInfo->SupportedVendorApplicationIdsCount++;
				
			}
		}
		
		if( oHostConfigData->uiSuppVen3 > 0 && oHostConfigData->uiSuppApp3 > 0)
		{
			if( hasVSApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiSuppVen3, oHostConfigData->uiSuppApp3) == 1)
			{
				addVendorSpecificApplicationId( dmMessage, oHostConfigData->uiSuppVen3, oHostConfigData->uiSuppApp3 );
				bFoundCommonApplication = 1;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iAuthApplicationId = oHostConfigData->uiSuppApp3;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iVendorId = oHostConfigData->uiSuppVen3;
				cliInfo->SupportedVendorApplicationIdsCount++;
			}
		}
		
		if( oHostConfigData->uiSuppVen4 > 0 && oHostConfigData->uiSuppApp4 > 0)
		{
			if( hasVSApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiSuppVen4, oHostConfigData->uiSuppApp4) == 1)
			{
				addVendorSpecificApplicationId( dmMessage, oHostConfigData->uiSuppVen4, oHostConfigData->uiSuppApp4 );
				bFoundCommonApplication = 1;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iAuthApplicationId = oHostConfigData->uiSuppApp4;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iVendorId = oHostConfigData->uiSuppVen4;
				cliInfo->SupportedVendorApplicationIdsCount++;
			}
		}
		
		if( oHostConfigData->uiSuppVen5 > 0 && oHostConfigData->uiSuppApp5 > 0)
		{
			if( hasVSApplicationIdInDiamMessage( oDiamMessage, oHostConfigData->uiSuppVen5, oHostConfigData->uiSuppApp5) == 1)
			{
				addVendorSpecificApplicationId( dmMessage, oHostConfigData->uiSuppVen5, oHostConfigData->uiSuppApp5 );
				bFoundCommonApplication = 1;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iAuthApplicationId = oHostConfigData->uiSuppApp5;
				cliInfo->SupportedVendorApplicationIds[cliInfo->SupportedVendorApplicationIdsCount].iVendorId = oHostConfigData->uiSuppVen5;
				cliInfo->SupportedVendorApplicationIdsCount++;
			}
		}

		int iResultCode = 2001;

		if( bFoundOrigRealm == 0)
		{
			iResultCode = 5005;
			dmResultCodeAvp->usIntVal = iResultCode;
			//addResultCodeAVP( dmMessage, iResultCode, 0, 1 );
			addErrorMessageAVP( dmMessage, (char*)"DIAMETER_MISSING_AVP", 0, 1, 20);
		}
		else if( bFoundInbandSecurity == 1 && usInbandSecurity != 0)
		{
			iResultCode = 5017;
			dmResultCodeAvp->usIntVal = iResultCode;
			//currently we are not supporting tls/dtls
			//addResultCodeAVP( dmMessage, iResultCode, 0, 1 );
			addErrorMessageAVP( dmMessage, (char*)"DIAMETER_NO_COMMON_SECURITY", 0, 1, 27);			
		}
		else 
		{
			if( oHostConfigData->iValidateSuppApplications == 1)
			{
				//check for any common applications.
				if( bFoundCommonApplication == 0)
				{
					iResultCode = 5010;
					dmResultCodeAvp->usIntVal = iResultCode;
					//addResultCodeAVP( dmMessage, iResultCode, 0, 1 );
					addErrorMessageAVP( dmMessage, (char*)"DIAMETER_NO_COMMON_APPLICATION", 0, 1, 30);
				}
				else
				{
					//addResultCodeAVP( dmMessage, iResultCode, 0, 1 );
					addErrorMessageAVP( dmMessage, (char*)"DIAMETER_SUCCESS", 0, 1, 16);					
				}
			}
			else
			{
				//addResultCodeAVP( dmMessage, iResultCode, 0, 1 );
				addErrorMessageAVP( dmMessage, (char*)"DIAMETER_SUCCESS", 0, 1, 16);
			}
		}
		
		/*
		printf("VID=%d AAI=%d AAI=%d SVA=%d\n", 
			cliInfo->VendorIdsCount, cliInfo->AuthApplicationIdsCount, 
				cliInfo->AcctApplicationIdsCount, cliInfo->SupportedVendorApplicationIdsCount);
		*/
		
		appSendMsgToClientOrPeer( dmMessage, cliInfo, iPeerIndex);
		
		if( iResultCode != 2001 )
		{
			close( cliInfo->fd);
			shutdown( cliInfo->fd, 2);
			releaseClientInfo( cliInfo);
		}
	}
	else
	{
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Invalid Scenario, HostConfig should present");
	}
}

void appHandleDisconnectPeerRequest2( struct DiamMessage* oDiamMessage, iClientInfo * cliInfo, int iPeerIndex)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received DPR From Client Fd[%d]", cliInfo->fd);

	struct DiamMessage *dmMessage = (struct DiamMessage *)allocateMessage();

	dmMessage->Flags.Request = 0;
	dmMessage->Flags.Proxyable = 0;
	dmMessage->CmdCode = oDiamMessage->CmdCode;
	dmMessage->AppId = oDiamMessage->AppId;
	dmMessage->HBHId = oDiamMessage->HBHId;
	dmMessage->E2EId = oDiamMessage->E2EId;

	dmMessage->AvpCount = 0;

	addResultCodeAVP( dmMessage, 2001, 0, 1 );
	addOriginHost( dmMessage);
	addOriginRealm( dmMessage);
	addErrorMessageAVP( dmMessage, (char*)"DIAMETER_SUCCESS", 0, 1, 16);

	appSendMsgToClientOrPeer( dmMessage, cliInfo, iPeerIndex );
	
	close( cliInfo->fd);
	shutdown( cliInfo->fd, 2);
	releaseClientInfo( cliInfo);
}

void appHandleDisconnectPeerRequest( struct DiamMessage* oDiamMessage, iClientInfo * cliInfo, int iPeerIndex)
{
	if( oApplicationServer)
	{	
		//, oDiamRawData;
		appHandleDisconnectPeerRequest2( oDiamMessage, cliInfo, iPeerIndex);
		return; 
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received DPR From Client Fd[%d]", cliInfo->fd);

	struct DiamMessage *dmMessage = (struct DiamMessage *)allocateMessage();
	
	dmMessage->Flags.Request = 0;
	dmMessage->Flags.Proxyable = 0;
	dmMessage->CmdCode = oDiamMessage->CmdCode;
	dmMessage->AppId = oDiamMessage->AppId;
	dmMessage->HBHId = oDiamMessage->HBHId;
	dmMessage->E2EId = oDiamMessage->E2EId;

	dmMessage->AvpCount = 0;

	addResultCodeAVP( dmMessage, 2001, 0, 1 );
	addOriginHost( dmMessage);
	addOriginRealm( dmMessage);
	addErrorMessageAVP( dmMessage, (char*)"DIAMETER_SUCCESS", 0, 1, 16);
	
	appSendMsgToClientOrPeer( dmMessage, cliInfo, iPeerIndex );
	
	closeAndCleanClientSocket( cliInfo);
}

/*
 * Either Host or Peer Receives CER
 *
 */
void appValidateCERAndSendCEA(struct DiamMessage* oDiamMessage, iClientInfo * cliInfo, int iPeerIndex)
{
	if( oApplicationServer)
	{	
		//, oDiamRawData;
		appValidateCERAndSendCEA2( oDiamMessage, cliInfo, iPeerIndex);
		return; 
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received CER From Client Fd[%d]", cliInfo->fd);

	unsigned int iRequestedAppId;
	iRequestedAppId = 0;
	
	memset( cliInfo->OriginRealm, 0, sizeof( cliInfo->OriginRealm));
	memset( cliInfo->OriginHost, 0, sizeof( cliInfo->OriginHost));

	int bFoundApplicationId = 0;
	int bFoundOrigRealm = 0;
	int bFoundOrigHost = 0;
	
	struct DiamAvp* dmAvp = NULL;
	dmAvp = oDiamMessage->Head;

	//while(dmAvp != NULL)
	while(dmAvp)	
	{
		if(dmAvp->AvpCode == AVP_AuthApplicationId)
		{
			iRequestedAppId = dmAvp->usIntVal;
			bFoundApplicationId = 1;
			//break;
		}
		
		if(dmAvp->AvpCode == AVP_OriginRealm)
		{
			memcpy( cliInfo->OriginRealm, dmAvp->PayLoad->Data, dmAvp->PayLoad->len);	
			bFoundOrigRealm = 1;
		}

		if(dmAvp->AvpCode == AVP_OriginHost)
		{
			memcpy( cliInfo->OriginHost, dmAvp->PayLoad->Data, dmAvp->PayLoad->len);	
			bFoundOrigHost = 1;
		}
		
		if(bFoundApplicationId == 1 && bFoundOrigRealm == 1 && bFoundOrigHost == 1)
		{
			break;
		}

		dmAvp = dmAvp->Next;
	}

	//printf("%s:%d FoundApplicationId[%d] iRequestedAppId[%d] OriginRealm[%s]\n", __FUNCTION__, __LINE__, bFoundApplicationId, iRequestedAppId, cliInfo->OriginRealm);

	//DIAMETER_APPLICATION_UNSUPPORTED :: 3007
	int iResultCode = 2001;
	int i = 0;
	int bNodeSupportsRequestedAppId = 0;

	if(bFoundApplicationId == 1)
	{
		bNodeSupportsRequestedAppId = 0;

		for( i = 0; i < objStackConfig.NoOfAppSupported; i++)
		{
			if(objStackConfig.SupportedAppIds[i] == iRequestedAppId)
			{
				bNodeSupportsRequestedAppId = 1;
				break;
			}
		}
		
		if(bNodeSupportsRequestedAppId == 0 && iRequestedAppId == 4294967295)
		{
			bNodeSupportsRequestedAppId = 1;
		}
		

		if(bNodeSupportsRequestedAppId == 0)
		{
			iResultCode = 3007;
		}
	} 
	else
	{
		iResultCode = 3007;
	}
	
	if( bFoundOrigRealm == 0 && iResultCode == 2001)
	{
		//Missing AVP., 
		iResultCode = 5005;
	}
	
	if( iResultCode == 3007)
	{
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Supperssing ApplicatioId Validation Replacing ResultCode=3007 with 2001");
		iResultCode = 2001;
	}
	
	if(iResultCode == 2001)
	{
		//Add to Realm Table
		
		pthread_mutex_lock( &objStackObjects.RealmTableLock );		
		
		int i = 0;
		int bFoundEntry = -1;
		
		//if found, close existing connection and update this
		// need to update 100 in struct
		
		for( i = 0; i < 100; i++)
		{
			if( i < objStackObjects.RealmTableCurrentCount)
			{
				if( strcmp( objStackObjects.RealmTable[i].RealmName, cliInfo->OriginRealm) == 0
					&& strcmp( objStackObjects.RealmTable[i].HostName, cliInfo->OriginHost) == 0
				)
				{
					int j = 0;
					for( j = 0; j < objStackObjects.RealmTable[i].AppCount; j++)
					{
						if( objStackObjects.RealmTable[i].AppId[j] == iRequestedAppId)
						{
							bFoundEntry = i;
							break;
						}
					}
					
					if( bFoundEntry >= 0)
						break;
				}
			}
		}
		
		if( bFoundEntry >= 0)
		{

			//Connection Closing is Not Job of this Function, just Update to new reference.
			/*
			//printf("Found Entry Index[%d] CLOSING.......\n", bFoundEntry);
			//close exiting connection
			if( cliInfo != objStackObjects.RealmTable[bFoundEntry].clientInfo)
			{
				//Dont Close Self Connection
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "CER Update Closing Exiting Connection and Updating new for Client Info %p Index=%d ClientFd[%d] OriginHost[%s] OriginRealm[%s]", cliInfo, cliInfo->PoolIndex, cliInfo->fd, cliInfo->OriginHost, cliInfo->OriginRealm);
				closeAndCleanClientSocket( objStackObjects.RealmTable[bFoundEntry].clientInfo);
			}	
			else
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Recycled Client Info %p Index=%d ClientFd[%d] OriginHost[%s] OriginRealm[%s]", cliInfo, cliInfo->PoolIndex, cliInfo->fd, cliInfo->OriginHost, cliInfo->OriginRealm);
			}
			*/
			
			//Update Fd for further answers
			//objStackObjects.RealmTable[bFoundEntry].clientInfo->fd = cliInfo->fd;
			objStackObjects.RealmTable[bFoundEntry].clientInfo = cliInfo;
			
			//add AppId, if requested new
			int j = 0;
			int bFoundAppId = 0;
			
			for( j = 0; j < 10; j++)
			{
				if( j < objStackObjects.RealmTable[bFoundEntry].AppCount )
				{
					if( objStackObjects.RealmTable[bFoundEntry].AppId[j] == iRequestedAppId)
					{
						bFoundAppId = 1;
						break;
					}
				}	
			}
			
			if( bFoundAppId == 0)
			{
				objStackObjects.RealmTable[bFoundEntry].AppId[objStackObjects.RealmTable[bFoundEntry].AppCount] = iRequestedAppId;
				objStackObjects.RealmTable[bFoundEntry].AppCount++;
			}
			
			cliInfo->RoutingTableIndex = bFoundEntry;
			
			objStackObjects.RealmTable[bFoundEntry].clientInfo = cliInfo; 
			//printf("Entry Updated Index[%d]\n", bFoundEntry);
		}
		else
		{
			//if not found add entry
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "CER Insert new for Client Info %p Index=%d ClientFd[%d] OriginHost[%s] OriginRealm[%s]", cliInfo, cliInfo->PoolIndex, cliInfo->fd, cliInfo->OriginHost, cliInfo->OriginRealm);			
			strcpy( objStackObjects.RealmTable[objStackObjects.RealmTableCurrentCount].RealmName, cliInfo->OriginRealm);
			strcpy( objStackObjects.RealmTable[objStackObjects.RealmTableCurrentCount].HostName, cliInfo->OriginHost);

			objStackObjects.RealmTable[objStackObjects.RealmTableCurrentCount].AppId[0] = iRequestedAppId;
			objStackObjects.RealmTable[objStackObjects.RealmTableCurrentCount].AppCount++;
			objStackObjects.RealmTable[objStackObjects.RealmTableCurrentCount].clientInfo = cliInfo; 
			cliInfo->RoutingTableIndex = objStackObjects.RealmTableCurrentCount;

			//printf("Added to Realm Table RealmName[%s] iRequestedAppId[%d]\n", objStackObjects.RealmTable[objStackObjects.RealmTableCurrentCount].RealmName, iRequestedAppId);
			
			objStackObjects.RealmTableCurrentCount++;
		}
		pthread_mutex_unlock( &objStackObjects.RealmTableLock );		
	}
	

	//printf("%s:%d NodeSupportsRequestedAppId[%d]\n", __FUNCTION__, __LINE__, bNodeSupportsRequestedAppId);

	#if 0

	printf("=REALM-TABLE-INFO==============================================================================\n");
	
	int j = 0;
	for( j = 0; j < objStackObjects.RealmTableCurrentCount; j++)
	{
		struct RealmInfo oRealmInfo = objStackObjects.RealmTable[j];
		
		printf("%d, %s fd=%d supported apps >> ", j, oRealmInfo.RealmName, oRealmInfo.clientInfo->fd );
		
		int z = 0;
		for( z = 0; z < oRealmInfo.AppCount; z++)
		{
			printf(" %d", oRealmInfo.AppId[z]);
		}	
		
		printf("\n");
	}
	
	printf("=REALM-TABLE-INFO==============================================================================\n");

	#endif


	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CEA Response With ResultCode[%d] for ClientFd[%d] OriginRealm[%s]", iResultCode, cliInfo->fd, cliInfo->OriginRealm);

	struct DiamMessage *dmMessage = (struct DiamMessage *)allocateMessage();
	createCEA( dmMessage, oDiamMessage, iResultCode, iRequestedAppId);

	appSendMsgToClientOrPeer( dmMessage, cliInfo, iPeerIndex );
}

int __corePrintClientConnectionInfo()
{
	int i = 0;
	int j = 0;
	
	for( i = 0; i < objStackObjects.RealmTableCurrentCount; i++)
	{
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "%d, RealmName=%s HostName=%s", i, objStackObjects.RealmTable[i].RealmName, objStackObjects.RealmTable[i].HostName);
		
		for( j = 0; j < objStackObjects.RealmTable[i].AppCount; j++)
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "%d, AppId[%d]=%d", i, j, objStackObjects.RealmTable[i].AppId[j]);
		}
	}		
}

int __coreGetClientByAppIdHostAndRealm( void ** vClientInfo, unsigned int iRequestedAppId, char *sClientHost, char * sClientRealm)
{
	int i = 0;
	int bFoundEntry = -1;
	int j = 0;
	
	for( i = 0; i < objStackObjects.RealmTableCurrentCount; i++)
	{
		if( strcmp( objStackObjects.RealmTable[i].RealmName, sClientRealm) == 0 && strcmp( objStackObjects.RealmTable[i].HostName, sClientHost) == 0 )
		{
			for( j = 0; j < objStackObjects.RealmTable[i].AppCount; j++)
			{
				if( objStackObjects.RealmTable[i].AppId[j] == iRequestedAppId)
				{
					bFoundEntry = i;
					*vClientInfo = objStackObjects.RealmTable[i].clientInfo;
					break;
				}
			}
			
			if( bFoundEntry >= 0)
				break;
		}
	}
	
	return bFoundEntry;
}

int sendMessageToClient( struct DiamMessage* oDiamMessage, char *sRealmName, int iApplicationId)
{
	iClientInfo * cliInfo = NULL;
	int i = 0;
	
	
	for( i = 0 ; i < objStackObjects.RealmTableCurrentCount; i++)
	{
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "LookUp By DestRealm Only:: ClientHostRealmName[%s] sRealmName[%s] iApplicationId[%d] AppId[%d]", objStackObjects.RealmTable[i].RealmName, sRealmName, iApplicationId, objStackObjects.RealmTable[i].AppId[0]);
					
		if( (strcmp( objStackObjects.RealmTable[i].RealmName, sRealmName) == 0))
		{
			// && iApplicationId == objStackObjects.RealmTable[i].AppId[0]
			cliInfo = objStackObjects.RealmTable[i].clientInfo;
			break;
		}
	}
	

	/*	
	for( i = 0 ; i < objStackConfig.NoOfClients; i++)
	{
		if( objStackConfig.Clients[i].iConnectToClient == 1)
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "LookUp ClientHostRealmName[%s] sRealmName[%s] iApplicationId[%d] AppId[%d]", objStackConfig.Clients[i].ClientHostRealmName, sRealmName, iApplicationId, objStackConfig.Clients[i].AppId);
			
			if( (strcmp( objStackConfig.Clients[i].ClientHostRealmName, sRealmName) == 0) && iApplicationId == objStackConfig.Clients[i].AppId)
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Found Client");
				cliInfo = &objStackConfig.Clients[i];
				break;
			}
		}		
	}
	*/
	
	//if( cliInfo == NULL)
	if(!cliInfo)	
	{
		return -1;
	}
	
	appSendMsgToClientOrPeer( oDiamMessage, cliInfo, -1);
	
	return 1;
}


void appSendDWA(struct DiamMessage* oDiamMessage, iClientInfo * cliInfo, int iPeerIndex)
{
	struct DiamMessage * dmMessage = (struct DiamMessage *)allocateMessage();
	createDWA( dmMessage, oDiamMessage, 2001);

	appSendMsgToClientOrPeer( dmMessage, cliInfo, iPeerIndex );
}

void appSendDWA2(struct DiamMessage* oDiamMessage, iDiamRawData * oDiamRawData)
{
	int bSent = 0;
	if( oApplicationServer)
	{
		if(oDiamRawData->CliInfo)
		{
			if(oDiamRawData->CliInfo->HostConfig)
			{
				bSent = 1;
				iHostConfigData * oHostConfigData = (iHostConfigData *)oDiamRawData->CliInfo->HostConfig;
				
				struct DiamMessage * dmMessage = (struct DiamMessage *)allocateMessage();
				createDWA2( dmMessage, oDiamMessage, 2001, oHostConfigData);
				appSendMsgToClientOrPeer( dmMessage, oDiamRawData->CliInfo, oDiamRawData->iPeerIndex);
			}
		}
	}
	
	if(bSent == 0)
	{
		appSendDWA( oDiamMessage, oDiamRawData->CliInfo, oDiamRawData->iPeerIndex);
	}	
}


/*
void appAddChildAvpToDiamAvp( struct DiamAvp* dmParent, struct DiamAvp * dmChildAvp)
{
	if(dmParent->Head == NULL)
	{
		dmParent->Head = dmParent->Current = dmChildAvp;
	}
	else
	{
		dmParent->Current->Next = dmChildAvp;
	}

	dmParent->Current = dmChildAvp;
	//dmParent->AvpCount++;
}
*/

void appAddAvpToDiamMessage( struct DiamMessage* dmMsg, struct DiamAvp * dmAvp)
{
	//if( dmMsg != NULL)
	if( dmMsg)	
	{
		//if(dmMsg->Head == NULL)
		if(!dmMsg->Head)	
		{
			dmMsg->Head = dmMsg->Current = dmAvp;
		}
		else
		{
			dmMsg->Current->Next = dmAvp;
		}

		dmMsg->Current = dmAvp;
		dmMsg->AvpCount++;
	}
}

void addAvpToMessage( struct DiamMessage* dmMsg, struct DiamAvp * dmAvp)
{
	appAddAvpToDiamMessage( dmMsg, dmAvp);
}

struct DiamAvp* avpIteratorMoveFirst(struct DiamAvp* dmAvp)
{
	dmAvp->GroupCurrent = dmAvp->GroupHead;
	return dmAvp->GroupCurrent;
}

struct DiamAvp* avpIteratorMoveNext(struct DiamAvp* dmAvp)
{
	//if(dmAvp->GroupCurrent == NULL)
	if(!dmAvp->GroupCurrent)	
	{
		return NULL;
	}
	
	//if(dmAvp->GroupCurrent->Next == NULL)
	if(!dmAvp->GroupCurrent->Next)	
	{
		return NULL;
	}	
	
	struct DiamAvp* cAvp = dmAvp->GroupCurrent->Next;

	dmAvp->GroupCurrent = cAvp;

	return cAvp;	
}

char * getSessionId( struct DiamMessage* dmMsg)
{
	return dmMsg->SessionId;
}






unsigned int getResultCode( struct DiamMessage* dmMsg)
{
	return dmMsg->iResultCode;
}

int getCCRequestType( struct DiamMessage* dmMsg)
{
	return dmMsg->iCCReqType;
}

unsigned int getCCRequestNumber( struct DiamMessage* dmMsg)
{
	return dmMsg->iCCReqNo;
}


struct DiamAvp* iteratorMoveFirst(struct DiamMessage* dmMsg)
{
	dmMsg->Current = dmMsg->Head;
	return dmMsg->Current;
}

struct DiamAvp* iteratorMoveNext(struct DiamMessage* dmMsg)
{
	//if(dmMsg->Current == NULL)
	if(!dmMsg->Current)	
	{
		return NULL;
	}

	//if(dmMsg->Current->Next == NULL)
	if(!dmMsg->Current->Next)
	{
		return NULL;
	}

	struct DiamAvp* cAvp = dmMsg->Current->Next;

	dmMsg->Current = cAvp;

	return cAvp;
}

int getAvpCode(struct DiamAvp *dmAvp)
{
	return dmAvp->AvpCode;
}

int getVendorId(struct DiamAvp *dmAvp)
{
	return dmAvp->VendorId;
}


void getIntValue( struct DiamAvp *dmAvp, int *iVal)
{
	*iVal = dmAvp->intVal;
}

void getLongValue( struct DiamAvp *dmAvp, long *iVal)
{
	*iVal = dmAvp->int64Val;
}

void getULongValue( struct DiamAvp *dmAvp, unsigned long *iVal)
{
	*iVal = dmAvp->usInt64Val;
}

void getUnsignedIntValue( struct DiamAvp *dmAvp, unsigned int *uiVal)
{
	*uiVal = dmAvp->usIntVal;
}

void getOctetString( struct DiamAvp *dmAvp, unsigned char *cStr, int *iLength)
{
	if( dmAvp->PayLoad)
	{
		memcpy( cStr, dmAvp->PayLoad->Data, dmAvp->PayLoad->len);
		*iLength = dmAvp->PayLoad->len;		
	}	
}


void addAvp( struct DiamAvp * dmAvpParent, struct DiamAvp * dmAvpChild)
{
	//printf( "Adding Avp ... ParentAvp[%d] ChildAvp[%d]\n", dmAvpParent->AvpCode, dmAvpChild->AvpCode);

	//if(dmAvpParent->GroupHead == NULL)
	if(!dmAvpParent->GroupHead)	
	{
		dmAvpParent->GroupHead = dmAvpParent->GroupCurrent = dmAvpChild;
	}
	else
	{
		dmAvpParent->GroupCurrent->Next = dmAvpChild;
	}

	dmAvpParent->GroupCurrent = dmAvpChild;
	
	//printf("added Child AVPCode:%d to Parent AVPCode:%d\n", dmAvpChild->AvpCode, dmAvpParent->AvpCode);
}

void appPeerRoutingError( struct DiamMessage* dmMsg, struct DiamRawData* dDiamRawData, int iResultCode, int iSourceInfo)
{
	/*
	printf("App Peer Routing Error (Line=%d) DestRealm[%s] AppId[%d]\n", iSourceInfo, dmMsg->DestRealm, dmMsg->AppId);
	dDiamRawData->iDecodeFull = 1;
	dDiamRawData->iRoutinError = 1;
	dDiamRawData->iErrorCode =  iResultCode;		//5006		DIAMETER_RESOURCES_EXCEEDED
													//5012		DIAMETER_UNABLE_TO_COMPLY	
	releaseMessage( dmMsg);												
											
	Enquee( dDiamRawData, &objStackObjects.DecodeMessageQueue);		
	*/
	
	LOGCAT( objStackConfig.iCatLog_CoreRouting, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 	
		"Sending Error Response to SessionID<%s> ResultCode:%d", dmMsg->SessionId, iResultCode);
	
	struct DiamMessage *oDiamCCA = allocateMessage();
	initDiamAnswer( dmMsg, oDiamCCA, 1);

	addSessionIdAVP( oDiamCCA, dmMsg->SessionId, 0, 1, strlen(dmMsg->SessionId));
	addOriginHost( oDiamCCA);
	addOriginRealm( oDiamCCA);
	//addDestinationRealmAVP( oDiamCCA, dmMsg->DestRealm, 0, 1, strlen(dmMsg->DestRealm) );		
	//addAuthApplicationIdAVP( oDiamCCA, dmMsg->AppId, 0, 1);
	//addServiceContextIdAVP( oDiamCCA, oiCCR.cServiceContextId, 0, 1, strlen(oiCCR.cServiceContextId) );
	//addCCRequestTypeAVP( oDiamCCA, dmMsg->iCCReqType, 0, 1);
	//addCCRequestNumberAVP( oDiamCCA, dmMsg->iCCReqNo, 0, 1);	
	addResultCodeAVP( oDiamCCA, iResultCode, 0, 1);		
	
	switch( iResultCode)
	{
		case 3002:
			addErrorMessageAVP( oDiamCCA, (char*)"DIAMETER_UNABLE_TO_DELIVER", 0, 1, 26);
			break;			
		case 3008:
			addErrorMessageAVP( oDiamCCA, (char*)"DIAMETER_INVALID_HDR_BITS", 0, 1, 25);
			break;
		case 5006:
			addErrorMessageAVP( oDiamCCA, (char*)"DIAMETER_RESOURCES_EXCEEDED", 0, 1, 27);
			break;
		case 5012:
			addErrorMessageAVP( oDiamCCA, (char*)"DIAMETER_UNABLE_TO_COMPLY", 0, 1, 25);
			break;			
		default:
			break;
	}
	
	appSendMsgToClientOrPeer( oDiamCCA, dDiamRawData->CliInfo, -1);	
	
	releaseDiamRawData( dDiamRawData);
	releaseMessage( dmMsg);
	releaseMessage( oDiamCCA);	
	/**/
	




	//dDiamRawData->CliInfo->RoutingError++;
}

void appSendRoutingErrorToClient( struct DiamMessage* dmMsg, struct DiamRawData* dDiamRawData)
{
	appPeerRoutingError( dmMsg, dDiamRawData, dDiamRawData->iErrorCode, __LINE__);
	
	/*
	iCCRMini oiCCR;
	memset( &oiCCR, 0, sizeof(iCCRMini));

	fillMiniData( dmMsg, &oiCCR);	
	
	struct DiamMessage *oDiamCCA = allocateMessage();
	initDiamAnswer( dmMsg, oDiamCCA, 1);

	addSessionIdAVP( oDiamCCA, dmMsg->SessionId, 0, 1, strlen(dmMsg->SessionId));
	addOriginHost( oDiamCCA);
	addOriginRealm( oDiamCCA);
	addDestinationRealmAVP( oDiamCCA, oiCCR.cOriginRealm, 0, 1, strlen(oiCCR.cOriginRealm) );		
	addAuthApplicationIdAVP( oDiamCCA, 4, 0, 1);
	addServiceContextIdAVP( oDiamCCA, oiCCR.cServiceContextId, 0, 1, strlen(oiCCR.cServiceContextId) );
	addCCRequestTypeAVP( oDiamCCA, 1, 0, 1);
	addCCRequestNumberAVP( oDiamCCA, oiCCR.RequestNumber, 0, 1);	
	addResultCodeAVP( oDiamCCA, dDiamRawData->iErrorCode, 0, 1);		
	
	
	appSendMsgToClientOrPeer( oDiamCCA, dDiamRawData->CliInfo, -1);	
	
	releaseDiamRawData( dDiamRawData);
	releaseMessage( dmMsg);
	releaseMessage( oDiamCCA);
	*/
}


struct PeerEndPointRecord* findEndPointRecordByHostName( struct DiamMessage* oDiamMessage)
{
	int i = 0;
	struct PeerEndPointRecord* iEndPointRecord = NULL;
	
	for( i = 0; i < objStackConfig.HostNameEndPointIndex; i++)
	{
		if( strcmp( objStackConfig.HostNameIEndPoint[i].HostName, oDiamMessage->DestHost) == 0 )
		{
			int z = 0;
			for( z = 0; z < objStackConfig.HostNameIEndPoint[i].EndPointRecordCount; z++)
			{
				if( objStackConfig.HostNameIEndPoint[i].EndPointRecord[z].AppId == oDiamMessage->AppId)
				{
					iEndPointRecord = &objStackConfig.HostNameIEndPoint[i].EndPointRecord[z];
					iEndPointRecord->RequestNo++;
					break;
				}	
			}
		}
		
		//if( iEndPointRecord != NULL)
		if(iEndPointRecord)	
		{
			break;
		}
	}
	
	return iEndPointRecord;
}

struct PeerEndPointRecord* findEndPointRecordByAppId( struct DiamMessage* oDiamMessage)
{
	int i = 0;
	struct PeerEndPointRecord* iEndPointRecord = NULL;
	
	for( i = 0; i < objStackConfig.AppEndPointIndex; i++)
	{
		if( objStackConfig.AppIEndPoint[i].AppId == oDiamMessage->AppId)
		{
			iEndPointRecord = &objStackConfig.AppIEndPoint[i].EndPointRecord[0];
			iEndPointRecord->RequestNo++;
			break;
		}
	}
	
	return iEndPointRecord;
}

struct PeerEndPointRecord* findEndPointRecordByRealmAndHostName( struct DiamMessage* oDiamMessage)
{
	int i = 0;
	struct PeerEndPointRecord* iEndPointRecord = NULL;
	
	char sPeerDH[400];
	memset( &sPeerDH, 0, sizeof(sPeerDH));
	sprintf( sPeerDH, "%s@%s", oDiamMessage->DestHost, oDiamMessage->DestRealm);
	
	for( i = 0; i < objStackConfig.HREndPointIndex; i++)
	{
		if( strcmp( objStackConfig.HRIEndPoint[i].HostRealm, sPeerDH) == 0 )
		{
			int z = 0;
			for( z = 0; z < objStackConfig.HRIEndPoint[i].EndPointRecordCount; z++)
			{
				if( objStackConfig.HRIEndPoint[i].EndPointRecord[z].AppId == oDiamMessage->AppId)
				{
					iEndPointRecord = &objStackConfig.HRIEndPoint[i].EndPointRecord[z];
					iEndPointRecord->RequestNo++;
					break;
				}	
			}
		}
		
		//if( iEndPointRecord != NULL)
		if(iEndPointRecord)	
		{
			break;
		}
	}
	
	return iEndPointRecord;
}


struct PeerEndPointRecord* findEndPointRecordByMSISDNRange( struct DiamMessage* oDiamMessage)
{
	int i = 0;
	struct PeerEndPointRecord* iEndPointRecord = NULL;
	
	if( oDiamMessage->MSISDN > 0)
	{
		for( i = 0; i < 5; i++)
		{
			if( objStackConfig.MSISDNRouting[i].Min >= oDiamMessage->MSISDN && objStackConfig.MSISDNRouting[i].Max <= oDiamMessage->MSISDN)
			{
				iEndPointRecord = &objStackConfig.MSISDNRouting[i].IEndPoint[0].EndPointRecord[0];
				iEndPointRecord->RequestNo++;				
				break;
			}
		}
	}	
	
	return iEndPointRecord;
}


struct PeerEndPointRecord* findEndPointRecordByIMSIRange( struct DiamMessage* oDiamMessage)
{
	int i = 0;
	struct PeerEndPointRecord* iEndPointRecord = NULL;
	CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "IMSI = %lld", oDiamMessage->IMSI);
	
	if( oDiamMessage->IMSI > 0)
	{
		for( i = 0; i < 5; i++)
		{
			CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "i = %d, MIN = %lld, MAX = %lld", i, objStackConfig.IMSIRouting[i].Min, objStackConfig.IMSIRouting[i].Max);
			
			if( objStackConfig.IMSIRouting[i].Min >= oDiamMessage->IMSI && objStackConfig.IMSIRouting[i].Max <= oDiamMessage->IMSI)
			{
				iEndPointRecord = &objStackConfig.IMSIRouting[i].IEndPoint[0].EndPointRecord[0];
				iEndPointRecord->RequestNo++;				
				break;
			}
		}
	}
	
	return iEndPointRecord;
}


static unsigned long calc_hash_lastchars( char* key);

int sendToPeerBySession( struct DiamMessage* oDiamMessage)
{
	struct InterfaceEndPoint * iEndPoint = NULL;
	struct PeerEndPointRecord* iEndPointRecord = NULL;	
	
	int i;
	
	for( i = 0; i < objStackConfig.EndPointIndex; i++)
	{
		if( strcmp( objStackConfig.IEndPoint[i].Realm, oDiamMessage->DestRealm) == 0 )
		{
			int z = 0;
			for( z = 0; z < objStackConfig.IEndPoint[i].EndPointRecordCount; z++)
			{
				if( objStackConfig.IEndPoint[i].EndPointRecord[z].AppId == oDiamMessage->AppId)
				{
					iEndPointRecord = &objStackConfig.IEndPoint[i].EndPointRecord[z];
					iEndPointRecord->RequestNo++;
					break;
				}	
			}
		}
		
		if(iEndPointRecord)	
		{
			break;
		}
	}
	
	if(iEndPointRecord)
	{	
		int activePeers[36];
		int activePeerCount = 0;		
		
		int i = 0;
		for( i = 0; i < iEndPointRecord->PeerIndexCount; i++)
		{
			if( objStackConfig.Peers[ iEndPointRecord->PeerIndexes[i] ].isCEASuccess == 1 )
			{
				activePeers[activePeerCount] = iEndPointRecord->PeerIndexes[i];
				activePeerCount++;
			}
		}
		
		if( activePeerCount > 0)
		{	
			int iPeerIndex = -1;
				
			if( activePeerCount == 1) 
			{
				iPeerIndex = activePeers[0];
			} 
			else
			{
				int iv = ( calc_hash_lastchars( oDiamMessage->SessionId ) % activePeerCount);
				
				if( iv >= 0)
				{
					iPeerIndex = activePeers[iv];
				}
				else if( activePeerCount == 1)
				{
					iPeerIndex = activePeers[0];					
				}
				else
				{
					return -3;			
				}	
				
				return sendMessageToPeer( oDiamMessage, iPeerIndex);		
				
				
			}
		}
		else
		{
			return -4;
		}			
	}
	else
	{
		return -1;
	}
	
	return -1;
}


void gerActivePeerIndexsByAppId( int iAppId, int *activePeers, int max, int *count)
{
	//int activePeers[max];
	int activePeerCount = 0;
	*count = 0;
	
	int i = 0;
	for( i = 0; i < objStackConfig.NoOfPeers; i++)
	{
		if( objStackConfig.Peers[i].isCEASuccess == 1 && objStackConfig.Peers[i].AppId == iAppId)
		{
			activePeers[activePeerCount] = i;
			activePeerCount++;
			
			if( activePeerCount >= max )
				break;	
		}
	}
	
	//*outIndexes = &activePeers;
	*count = activePeerCount;	
}



int corePeerSupportsAuthApplicationIds( int iAppId, iPeerConfigData * oPeerConfigData)
{
	if( oPeerConfigData->uiAuthAppId1 == iAppId 
			|| oPeerConfigData->uiAuthAppId2 == iAppId
			|| oPeerConfigData->uiAuthAppId3 == iAppId
			|| oPeerConfigData->uiAuthAppId4 == iAppId
			|| oPeerConfigData->uiAuthAppId5 == iAppId)
	{
		return 1;
	}
	return 0;
}

int corePeerSupportsAcctApplicationIds( int iAppId, iPeerConfigData * oPeerConfigData)
{
	if( oPeerConfigData->uiAcctAppId1 == iAppId 
			|| oPeerConfigData->uiAcctAppId2 == iAppId
			|| oPeerConfigData->uiAcctAppId3 == iAppId
			|| oPeerConfigData->uiAcctAppId4 == iAppId
			|| oPeerConfigData->uiAcctAppId5 == iAppId)
	{
		return 1;
	}
	return 0;
}

int corePeerSupportsVendorApplicationIds( int iAppId, iPeerConfigData * oPeerConfigData)
{
	if( oPeerConfigData->uiSuppApp1 == iAppId 
			|| oPeerConfigData->uiSuppApp2 == iAppId
			|| oPeerConfigData->uiSuppApp3 == iAppId
			|| oPeerConfigData->uiSuppApp4 == iAppId
			|| oPeerConfigData->uiSuppApp5 == iAppId)
	{
		return 1;
	}
	return 0;
}

//need to implement cache for this
void __coreGetPeerByAppIdAndRealm( iPeerInfoList * oPeerInfoList, int iAppId, char * cRealName)
{
	int i = 0;	
	iRealmRow * oRealmRow = NULL;
	
	for( i = 0; i < oApplicationServer->RealmRowCount; i++)
	{
		if( strcmp( oApplicationServer->RealmRows[i].sRealmName, cRealName) == 0)
		{
			oRealmRow = &oApplicationServer->RealmRows[i];
			break;
		}
	}
	
	if( oRealmRow)
	{
		for( i = 0; i < oRealmRow->PeerIndexCount; i++)
		{
			if( oRealmRow->PeerConfigData[i]->iConnected == 1 && oRealmRow->PeerConfigData[i]->isCERSuccess == 1)
			{
				if( corePeerSupportsAcctApplicationIds( iAppId, oRealmRow->PeerConfigData[i]) 
						|| corePeerSupportsAuthApplicationIds( iAppId, oRealmRow->PeerConfigData[i])
						|| corePeerSupportsVendorApplicationIds( iAppId, oRealmRow->PeerConfigData[i])
					)
				{
					oPeerInfoList->Peers[oPeerInfoList->PeerServerCount] = oRealmRow->PeerConfigData[i];
					oPeerInfoList->PeerServerCount++;
				}
			}	
		}
	}
}

int __coreSendMessageToPeerByAppId( struct DiamMessage *oDiamCCR, char * cDestRealm)
{
	iPeerInfoList oPeerInfoList;
	memset( &oPeerInfoList, 0, sizeof(oPeerInfoList));
	__coreGetPeerByAppIdAndRealm( &oPeerInfoList, oDiamCCR->AppId, cDestRealm);
	int bSuccess = -1;
	
	if( oPeerInfoList.PeerServerCount > 0)
	{
		printf("Found %d Peer(s) for this Realm %s, AppId=%d\n", oPeerInfoList.PeerServerCount, cDestRealm, oDiamCCR->AppId);
		
		if( oPeerInfoList.PeerServerCount == 1)
		{
			if( oPeerInfoList.Peers[0]->iTransportType == 0)
			{
				
			} 
			else if(oPeerInfoList.Peers[0]->iTransportType == 1)
			{
				bSuccess = appSCTPSendMsg( &oPeerInfoList.Peers[0]->iFd, oDiamCCR);

				if( bSuccess < 0 && errno == EPIPE)
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending DiamMessage Failed For Peer[%d] SockFd[%d]", oPeerInfoList.Peers[0]->Id, oPeerInfoList.Peers[0]->iFd);
					closeAndCleanClientPeerConfigSocket( oPeerInfoList.Peers[0]);
				}				
			}
		}
	} 
	else 
	{
		printf("No Peers Found for this Realm %s, AppId=%d\n", cDestRealm, oDiamCCR->AppId);
		return -1;
	}
	
	return 0;
}


void appRouteMessageToPeer2( struct DiamMessage* oDiamMessage, struct DiamRawData* dDiamRawData)
{
	iPeerInfoList oPeerInfoList;
	memset( &oPeerInfoList, 0, sizeof(oPeerInfoList));
	
	__coreGetPeerByAppIdAndRealm( &oPeerInfoList, oDiamMessage->AppId, oDiamMessage->DestRealm);
	
	if( oPeerInfoList.PeerServerCount == 0)
	{
		//printf("No EndPoint Now...Sending DIAMETER_UNABLE_TO_DELIVER\n");
		
		LOGCAT( objStackConfig.iCatLog_CoreRouting, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
			"No EndPoint Found for SessionID<%s>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId );
			
		appPeerRoutingError( oDiamMessage, dDiamRawData, 3002, __LINE__);		
	}
	
	
}

void appRouteMessageToPeerModule1( struct DiamMessage* oDiamMessage, struct DiamRawData * dDiamRawData)
{
	int i;
	int iServiceContextBasedRouting = 0;
	
	char sHostNames[5][200];
	int iHostNameCount = 0;
	
	if( objStackConfig.EnableServiceContextBasedRouting == 1)
	{
		memset( sHostNames, 0, sizeof(sHostNames));
		
		if( oDiamMessage->hasServiceContextId == 1)
		{
			for( i = 0; i < objStackConfig.ServiceContextRoutingCount; i++)
			{
				if( objStackConfig.ServiceContextRoutingInfo[i].ServiceContextRoutingAppId == oDiamMessage->AppId
					&& strcmp( objStackConfig.ServiceContextRoutingInfo[i].ServiceContext, oDiamMessage->ServiceContext) == 0
				)
				{
					strcpy( sHostNames[iHostNameCount], objStackConfig.ServiceContextRoutingInfo[i].DestinationHostName);
					iHostNameCount++;	
				}
			}
		}
	}
	
	if( iHostNameCount > 0)
	{
		iServiceContextBasedRouting = 1;
	}
	
	int activePeers[36];
	int activePeerCount = 0;
	int j = 0;
		
	if( iServiceContextBasedRouting == 1)
	{
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			if( objStackConfig.Peers[i].isCEASuccess == 1 && objStackConfig.Peers[i].isConnected == 1 
				&& objStackConfig.Peers[i].AppId == oDiamMessage->AppId)
			{
				for( j = 0; j < iHostNameCount; j++)
				{
					if( strcmp( objStackConfig.Peers[i].PeerHostName , sHostNames[j]) == 0)
					{
						activePeers[activePeerCount] = i;
						activePeerCount++;
						break; //break inner loop
					}
				}
			}
		}
	}
	else
	{
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			if( objStackConfig.Peers[i].isCEASuccess == 1 && objStackConfig.Peers[i].isConnected == 1 
				&& objStackConfig.Peers[i].AppId == oDiamMessage->AppId)
			{
				if( strcmp( objStackConfig.Peers[i].PeerHostRealmName , oDiamMessage->DestRealm) == 0)
				{
					activePeers[activePeerCount] = i;
					activePeerCount++;
				}
			}
		}	
	}
	
	if( activePeerCount == 0)
	{
		APP_LOG( LOG_LEVEL_CRITICAL, __FILE__, __LINE__, 
			"No Peer Found for SessionID<%s> DestRealm<%s> AppId<%d>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId, oDiamMessage->DestRealm, oDiamMessage->AppId);
		
		appPeerRoutingError( oDiamMessage, dDiamRawData, 3002, __LINE__);
		return;	
	}
	
	int iPeerIndex = -1;
	
	int iv = ( calc_hash_lastchars( oDiamMessage->SessionId ) % activePeerCount);

	if( iv >= 0)
	{
		iPeerIndex = activePeers[iv];
	}
	else if( activePeerCount == 1)
	{
		iPeerIndex = activePeers[0];					
	}
	else
	{
		APP_LOG( LOG_LEVEL_CRITICAL, __FILE__, __LINE__, 
			"No Peer Found for SessionID<%s> DestRealm<%s> AppId<%d>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId, oDiamMessage->DestRealm, oDiamMessage->AppId);

		appPeerRoutingError( oDiamMessage, dDiamRawData, 3002, __LINE__);
		return;
	}
	
	#if DIAMDRA

	pthread_mutex_lock( &objStackObjects.HBHLock);
	
	setNextHBHId();
	
	objStackObjects.HBHDB[objStackObjects.CurrentHBH].OriginalHBH = oDiamMessage->HBHId;
	objStackObjects.HBHDB[objStackObjects.CurrentHBH].oClientInfo = dDiamRawData->CliInfo;
	
	encodeLongTo4Bytes( objStackObjects.CurrentHBH, dDiamRawData->Header->Data, 12);			
	
	pthread_mutex_unlock( &objStackObjects.HBHLock);	
	
	#endif	

	int iLength = ( dDiamRawData->Header->len + dDiamRawData->PayLoad->len );
	char buffer[iLength];
	
	memset( &buffer, 0, sizeof(buffer));
	memcpy( &buffer, dDiamRawData->Header->Data, dDiamRawData->Header->len);
	memcpy( &buffer[20], dDiamRawData->PayLoad->Data, dDiamRawData->PayLoad->len);
	
	int iSentBytes = send( objStackConfig.Peers[iPeerIndex].fd, &buffer , iLength, 0 );
	
	
}

//10022
void appRouteMessageToPeer( struct DiamMessage* oDiamMessage, struct DiamRawData* dDiamRawData)
{
	if( oApplicationServer)
	{
		appRouteMessageToPeer2( oDiamMessage, dDiamRawData);
		return;
	}
	
	if( oDiamMessage->Flags.Proxyable == 0)
	{
		APP_LOG( LOG_LEVEL_CRITICAL, __FILE__, __LINE__, 
			"Sending DIAMETER_INVALID_HDR_BITS for SessionID<%s> DestRealm<%s> AppId<%d>", oDiamMessage->SessionId, oDiamMessage->DestRealm, oDiamMessage->AppId);
		
		appPeerRoutingError( oDiamMessage, dDiamRawData, 3008, __LINE__);
		return;
	}
	
	if( objStackConfig.DRARoutingModule == 1)
	{
		appRouteMessageToPeerModule1( oDiamMessage, dDiamRawData);
		return;
	}
	
	//printf("Entered appRouteMessageToPeer...\n");
	struct InterfaceEndPoint * iEndPoint = NULL;
	struct PeerEndPointRecord* iEndPointRecord = NULL;
	iStickySessionInfo *oSSInfo = NULL;
	
	/*
	if( oDiamMessage->iCCReqType > 1)
	{
		oSSInfo = __getASTItem( objStackObjects.StickySessionPtr, oDiamMessage->SessionId, 0);
	}
	*/
	
		//Route based on Realm And AppId
	//oDiamMessage->DestRealm
	//oDiamMessage->AppId

	int i = 0;
	
	//if( oSSInfo != NULL)
	if(oSSInfo)	
	{
		iEndPointRecord = &objStackConfig.PeerEndPoint[ oSSInfo->iPeerIndex ].EndPointRecord[0];
		iEndPointRecord->RequestNo++;
		
		if( objStackConfig.Peers[ oSSInfo->iPeerIndex ].isCEASuccess == 0 )
		{
			iEndPointRecord = NULL;
		}
	}
	
	//if( iEndPointRecord == NULL )
	if(!iEndPointRecord)	
	{	
		switch(objStackConfig.MessageRoutingMode)
		{
			//Imsi Range Routing
			case 1:
				iEndPointRecord = findEndPointRecordByIMSIRange( oDiamMessage);
				break;
			//Dest Host Routing
			case 2:
				iEndPointRecord = findEndPointRecordByHostName( oDiamMessage);
				break;
			//Application ID Routing
			case 3:
				iEndPointRecord = findEndPointRecordByAppId( oDiamMessage);
				break;
			//dest_realm + dest_host + Application ID
			case 4:
				iEndPointRecord = findEndPointRecordByRealmAndHostName( oDiamMessage);
				break;
			//MSISDN Range
			case 5:
				iEndPointRecord = findEndPointRecordByMSISDNRange( oDiamMessage);
				break;
			//IMEI Range
			case 6:
				break;
			//Origination Host
			case 7:
				break;
			//User Profile
			case 8:
				break;
		}
	}
		
	
	
	//if(iEndPointRecord == NULL)
	if(!iEndPointRecord)	
	{
		//Default Routing  -- DestRealm 
		
		for( i = 0; i < objStackConfig.EndPointIndex; i++)
		{
			if( strcmp( objStackConfig.IEndPoint[i].Realm, oDiamMessage->DestRealm) == 0 )
			{
				int z = 0;
				for( z = 0; z < objStackConfig.IEndPoint[i].EndPointRecordCount; z++)
				{
					if( objStackConfig.IEndPoint[i].EndPointRecord[z].AppId == oDiamMessage->AppId)
					{
						iEndPointRecord = &objStackConfig.IEndPoint[i].EndPointRecord[z];
						iEndPointRecord->RequestNo++;
						break;
					}	
				}
			}
			
			//if( iEndPointRecord != NULL)
			if(iEndPointRecord)	
			{
				break;
			}
		}
		
		if(!iEndPointRecord)
		{
			APP_LOG( LOG_LEVEL_DEBUG, __FILE__, __LINE__, 
				"iEndPointRecord is NULL while DRA Routing Count-EndPointIndex<%d>... |%s", objStackConfig.EndPointIndex , __FUNCTION__);

			for( i = 0; i < objStackConfig.EndPointIndex; i++)
			{				
				if( strcmp( objStackConfig.IEndPoint[i].Realm, oDiamMessage->DestRealm) == 0 )
				{
					if( objStackConfig.IEndPoint[i].EndPointRecordCount > 0)
					{
						int z = 0;
						for( z = 0; z < objStackConfig.IEndPoint[i].EndPointRecordCount; z++)
						{
							APP_LOG( LOG_LEVEL_DEBUG, __FILE__, __LINE__, 
							"Available-AppId<%d> Required-AppId<%d> for DestRealm<%s>... |%s", 
								objStackConfig.IEndPoint[i].EndPointRecord[z].AppId, oDiamMessage->AppId,
								oDiamMessage->DestRealm, __FUNCTION__);
						}
					}
					else
					{
						APP_LOG( LOG_LEVEL_DEBUG, __FILE__, __LINE__, 
							"No EndPointRecordCount Found for DestRealm<%s>... |%s", oDiamMessage->DestRealm, __FUNCTION__);						
					}	
				}
			}
		
		}
	}
	
	
	
	//if(iEndPointRecord == NULL)
	if(!iEndPointRecord)	
	{
		//DIAMETER_UNABLE_TO_COMPLY
		//5012
		//Message rejected because of unspecified reasons.
		//Send Unable to Comply
		
		// Intended Realm is not recognized.
		// DIAMETER_REALM_NOT_SERVED    3003
		
		// Message cant be delivered because there is no Host with Diameter URI present in Destination-Host AVP in associated Realm.
		// DIAMETER_UNABLE_TO_DELIVER   3002
		
		//printf("No EndPoint Now...Sending DIAMETER_UNABLE_TO_DELIVER\n");
		
		/*
		LOGCAT( objStackConfig.iCatLog_CoreRouting, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
			"No EndPoint Found for SessionID<%s>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId );
		*/
		
		APP_LOG( LOG_LEVEL_CRITICAL, __FILE__, __LINE__, 
			"No EndPoint Found for SessionID<%s> DestRealm<%s> AppId<%d>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId, oDiamMessage->DestRealm, oDiamMessage->AppId);
		
		appPeerRoutingError( oDiamMessage, dDiamRawData, 3002, __LINE__);
	}
	else
	{
		int activePeers[36];
		int activePeerCount = 0;		
		
		int i = 0;
		for( i = 0; i < iEndPointRecord->PeerIndexCount; i++)
		{
			if( objStackConfig.Peers[ iEndPointRecord->PeerIndexes[i] ].isCEASuccess == 1 )
			{
				activePeers[activePeerCount] = iEndPointRecord->PeerIndexes[i];
				activePeerCount++;
			}
		}
		
		if( activePeerCount > 0)
		{
			//printf("activePeerCount=%d\n", activePeerCount);

			
			int iPeerIndex = -1;
			
			if( activePeerCount == 1) 
			{
				iPeerIndex = activePeers[0];
			} 
			else
			{
				//int iv = ( iEndPointRecord->RequestNo % activePeerCount);
				int iv = ( calc_hash_lastchars( oDiamMessage->SessionId ) % activePeerCount);
				
				if( iv >= 0)
				{
					iPeerIndex = activePeers[iv];
				}
				else if( activePeerCount == 1)
				{
					iPeerIndex = activePeers[0];					
				}
				else
				{
					/*
					LOGCAT( objStackConfig.iCatLog_CoreRouting, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
						"No Peer Found for SessionID<%s>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId );
					*/
					
					APP_LOG( LOG_LEVEL_CRITICAL, __FILE__, __LINE__, 
						"No Peer Found for SessionID<%s> DestRealm<%s> AppId<%d>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId, oDiamMessage->DestRealm, oDiamMessage->AppId);

			
					appPeerRoutingError( oDiamMessage, dDiamRawData, 3002, __LINE__);
					return;		
				}	
			}
			
			//printf("selected iPeerIndex=%d\n", iPeerIndex);
			
			
			#if DIAMDRA

			pthread_mutex_lock( &objStackObjects.HBHLock);
			
			setNextHBHId();
			
			objStackObjects.HBHDB[objStackObjects.CurrentHBH].OriginalHBH = oDiamMessage->HBHId;
			objStackObjects.HBHDB[objStackObjects.CurrentHBH].oClientInfo = dDiamRawData->CliInfo;
			
			encodeLongTo4Bytes( objStackObjects.CurrentHBH, dDiamRawData->Header->Data, 12);			
			
			pthread_mutex_unlock( &objStackObjects.HBHLock);	
			
			#endif
			
			//printf("before sending message=%d\n", iPeerIndex);

			//send to Peer here
			int iLength = ( dDiamRawData->Header->len + dDiamRawData->PayLoad->len );
			char buffer[iLength];
			
			memset( &buffer, 0, sizeof(buffer));
			memcpy( &buffer, dDiamRawData->Header->Data, dDiamRawData->Header->len);
			memcpy( &buffer[20], dDiamRawData->PayLoad->Data, dDiamRawData->PayLoad->len);
			
			int iSentBytes = send( objStackConfig.Peers[iPeerIndex].fd, &buffer , iLength, 0 );
			
			//printf("sent message bytes=%d IP=%s Port=%d\n", iSentBytes, objStackConfig.Peers[iPeerIndex].PeerIP, objStackConfig.Peers[iPeerIndex].PeerPort);
			
			if(iSentBytes == iLength)
			{
				objStackObjects.TotalMemoryUsage.SocketWriteCount++;
				objStackConfig.Peers[iPeerIndex].MessagesRouted++;
				
				//LOGCAT( objStackConfig.iCatLog_CoreRouting, 
				APP_LOG( LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
					"Routed Diameter Message with SessionID<%s> to PeerIP <%s> PeerPort <%d> MessagesRouted <%ld>", oDiamMessage->SessionId, objStackConfig.Peers[iPeerIndex].PeerIP, objStackConfig.Peers[iPeerIndex].PeerPort, objStackConfig.Peers[iPeerIndex].MessagesRouted);
				
				/*
				if( oSSInfo == NULL && oDiamMessage->iCCReqType < 3 )
				{
					oSSInfo = allocateStickySessionInfo();
					oSSInfo->iPeerIndex = iPeerIndex;
					
					//__addASTItem( objStackObjects.StickySessionPtr, oDiamMessage->SessionId, oSSInfo);
				}
				else if( oSSInfo != NULL && oDiamMessage->iCCReqType == 3)
				{
					releaseStickySessionPool( oSSInfo);
					//__addASTItem( objStackObjects.StickySessionPtr, oDiamMessage->SessionId, NULL);
				}
				*/
				
				releaseMessage( oDiamMessage);
				releaseDiamRawData( dDiamRawData);	
			}
			else
			{
				if( iSentBytes < 0 && errno == EPIPE)
				{
					//LOGCAT( objStackConfig.iCatLog_CoreSockets, 
					APP_LOG( LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
						"Sending Failed enountered EPIPE closing Connection, for Diameter Message SessionID<%s>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId );
					
					closePeerConnection( &iPeerIndex);	
				}

				//LOGCAT( objStackConfig.iCatLog_CoreRouting, 
				APP_LOG( LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
					"Sending Failed for Diameter Message SessionID<%s>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId );
			
				appPeerRoutingError( oDiamMessage, dDiamRawData, 3002, __LINE__);
			}
		}
		else
		{
			//LOGCAT( objStackConfig.iCatLog_CoreRouting, 
			APP_LOG( LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
				"No Active Peer Found for Diameter Message SessionID<%s>...Sending DIAMETER_UNABLE_TO_DELIVER", oDiamMessage->SessionId );
					
			appPeerRoutingError( oDiamMessage, dDiamRawData, 3002, __LINE__);
		}
	 
	}
}

//10023
void appRouteMessageToClient( struct DiamMessage* oDiamMessage, struct DiamRawData* dDiamRawData)
{
	iClientInfo *oClientInfo = NULL;
	
	#if DIAMDRA
	
	if( oDiamMessage->HBHId > objStackObjects.MinHBH && oDiamMessage->HBHId < objStackObjects.MaxHBH)
	{
		//if( objStackObjects.HBHDB[oDiamMessage->HBHId].oClientInfo != NULL)
		if(objStackObjects.HBHDB[oDiamMessage->HBHId].oClientInfo)	
		{
			oClientInfo = objStackObjects.HBHDB[oDiamMessage->HBHId].oClientInfo;
			encodeLongTo4Bytes( objStackObjects.HBHDB[oDiamMessage->HBHId].OriginalHBH, dDiamRawData->Header->Data, 12);
		
			objStackObjects.HBHDB[oDiamMessage->HBHId].oClientInfo = NULL;
			objStackObjects.HBHDB[oDiamMessage->HBHId].OriginalHBH = 0;
		}
	}	
	
	#endif
	
	
	//if( oClientInfo != NULL)
	if( oClientInfo )	
	{
		//TODO:CHECK-THIS
		//if( oClientInfo->isActive == 1)
		if( oClientInfo->fd >= 0 )
		{
			//printf("Sending Response to Client[%s] oClientInfo->fd[%d]\n", cData, oClientInfo->fd);
			
			int iLength = (dDiamRawData->Header->len + dDiamRawData->PayLoad->len);
			char buffer[iLength];
			memset( &buffer, 0, sizeof(buffer));
			memcpy( &buffer, dDiamRawData->Header->Data, dDiamRawData->Header->len);
			memcpy( &buffer[20], dDiamRawData->PayLoad->Data, dDiamRawData->PayLoad->len);
			
			//printf( "Sending Message to RealmIndex[%d] Name[%s] Target[%s] fd[%d] BufferLength[%d]\n", iRealmIndex,  objStackObjects.RealmTable[ iRealmIndex ].RealmName, oDiamMessage->DestRealm , objStackObjects.RealmTable[ iRealmIndex ].clientInfo->fd, iLength);
			
			//hexDump( buffer, iLength);
			
			int iSentBytes = send( oClientInfo->fd, &buffer , iLength, 0 );

			if(iSentBytes == iLength)
			{
				oClientInfo->SentMessages++;
				objStackObjects.TotalMemoryUsage.SocketWriteCount++;			
				
				//LOGCAT( objStackConfig.iCatLog_CoreRouting, 
				APP_LOG( LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
					"Routing Back to Client SUCCESS, Diameter Message with SessionID<%s> fd<%d> SentMessages<%ld>", oDiamMessage->SessionId, oClientInfo->fd, oClientInfo->SentMessages);	
			}
			else
			{
				if( iSentBytes < 0 && errno == EPIPE)
				{
					closeAndCleanClientSocket( oClientInfo);
				}
				
				//LOGCAT( objStackConfig.iCatLog_CoreRouting, 
				APP_LOG( LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, 
					"Routing Back to Client FAILED, Diameter Message with SessionID<%s> fd<%d>", oDiamMessage->SessionId, oClientInfo->fd);	

				objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidLength++;
			}	
		}	
		else
		{
			objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidActiveState++;			
		}	
	}
	else
	{
		objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidClientObject++;
	}
	
	
	releaseMessage( oDiamMessage);
	releaseDiamRawData( dDiamRawData);	
}

//10021
void appRouteQueuedMessage( struct DiamRouteMessage* oDiamRouteMessage)
{
	//printf("Routing Queued Message\n");
	
	struct DiamMessage* oDiamMessage = oDiamRouteMessage->DiamMessagePtr;
	struct DiamRawData* dDiamRawData = oDiamRouteMessage->DiamRawDataPtr;
	
	//printf("iMessageArrivedFrom[%d] iRoutinError=[%d] iRequestNo=[%d]\n", dDiamRawData->iMessageArrivedFrom, dDiamRawData->iRoutinError, dDiamRawData->iRequestNo);
	
	if( dDiamRawData->iMessageArrivedFrom == 2 && dDiamRawData->iRoutinError == 1 )
	{
		//send it to Client
		appSendRoutingErrorToClient( oDiamMessage, dDiamRawData);
	}
	else
	{
		//if( dDiamRawData->CliInfo != NULL)
		if(dDiamRawData->CliInfo)	
		{
			//printf("appRouteMessageToPeer\n");
			appRouteMessageToPeer( oDiamMessage, dDiamRawData);
		}
		else if( dDiamRawData->iPeerIndex >= 0)
		{
			//printf("appRouteMessageToClient\n");		
			appRouteMessageToClient( oDiamMessage, dDiamRawData);	
		}
		else
		{
			//printf("Received Request From Unknown Source\n");
			releaseMessage( oDiamMessage);
			releaseDiamRawData( dDiamRawData);	
		}
	}
	
	oDiamRouteMessage->DiamMessagePtr = NULL;
	oDiamRouteMessage->DiamRawDataPtr = NULL;
	
	releaseDiamRouteMessage( oDiamRouteMessage);
}

 //10020
void appRouteMessage( struct DiamMessage* oDiamMessage, struct DiamRawData* dDiamRawData)
{
	//printf("Route Message to Host[%s] Realm[%s]\n" , oDiamMessage->DestHost, oDiamMessage->DestRealm);
	
	if( objStackConfig.QueueMode == 0)
	{
		//if( dDiamRawData->CliInfo != NULL)
		if(dDiamRawData->CliInfo)	
		{
			//Received Request from Cient
			//search and send it to PeerServer
			//Get DestinationRealm and Route It
			
			//printf("Received Request From CLIENT\n");
			
			appRouteMessageToPeer( oDiamMessage, dDiamRawData);
		}
		else if( dDiamRawData->iPeerIndex >= 0)
		{
			//Received Response from Peer Server
			//printf("Received Request/Answer From CLIENT\n");		
			appRouteMessageToClient( oDiamMessage, dDiamRawData);	
		}
		else
		{
			//Handle Unknown case
			printf("Received Request From Unknown Source\n");
		}
	}
	else
	{
		struct DiamRouteMessage *objRouteMessage = (struct DiamRouteMessage *)allocateDiamRouteMessage();
		objRouteMessage->DiamMessagePtr = oDiamMessage;
		objRouteMessage->DiamRawDataPtr = dDiamRawData;	
		
		Enquee( objRouteMessage, &objStackObjects.RoutingMessageQueue);
	}

}


void appDecodeDiamGroupedAvp(char* dataPtr, struct DiamAvp* dmParentAvp, int iLevel)
{
	//printf("Total Bytes To Decode for Grouped AVPCode[%d]  Length[%d] iLevel[%d]\n", dmParentAvp->AvpCode, (dmParentAvp->AvpLength + dmParentAvp->Padding) , iLevel);
	
	
	
	int iCurrentByteIndex = 0;
	
	while(iCurrentByteIndex < ((dmParentAvp->AvpLength + dmParentAvp->Padding) - dmParentAvp->HeaderLength))
	{
		int iHeaderLength = 8;
		int iDataLength = 0;
		int iAvpTotLength = 0;
		int iAvpLength = 0;
		int isVendorSpecfic = 0;
		int isMandatory = 0;
		int iAvpCode = 0;

		iHeaderLength = 8;

		decodeIntValueFrom4Bytes( &iAvpCode, dataPtr, iCurrentByteIndex);
		decodeBitVal( &isVendorSpecfic, dataPtr, (iCurrentByteIndex + 4), 7);
		decodeBitVal( &isMandatory, dataPtr, (iCurrentByteIndex + 4), 6);
		decodeIntValueFrom3Bytes( &iAvpLength, dataPtr, (iCurrentByteIndex + 5));

		if(iAvpCode < 0)
		{
			//printf("%X %X %X %X\n", dDiamRawData->PayLoad->Data[iCurrentByteIndex], dDiamRawData->PayLoad->Data[iCurrentByteIndex + 1], dDiamRawData->PayLoad->Data[iCurrentByteIndex + 2], dDiamRawData->PayLoad->Data[iCurrentByteIndex + 3]);
		}

		if(isVendorSpecfic == 1)
		{
			iHeaderLength = 12;
		}

		iDataLength = iAvpLength - iHeaderLength;

		int rem = iAvpLength % 4;
		int iPadded = 0;



		if(rem > 0)
		{
			iPadded = 4 - rem;
		}

		//iAvpTotLength is Full bytes of AVP, AVP Length value includes only data length not padded length
		iAvpTotLength = iAvpLength + iPadded;



		int VendorId = 0;
		if(isVendorSpecfic == 1)
		{
			decodeIntValueFrom4Bytes( &VendorId, dataPtr, iCurrentByteIndex + (iHeaderLength-4));
		}
	

		struct DiamAvp* dmAvp = (struct DiamAvp*) allocateDiamAvp();
		dmAvp->AvpCode = iAvpCode;
		dmAvp->AvpLength = iAvpLength;
		dmAvp->Padding = iPadded;
		dmAvp->PayLoadLength = iDataLength;
		dmAvp->HeaderLength = iHeaderLength;
		dmAvp->VendorId = VendorId;
		dmAvp->Flags.VendorSpecific = isVendorSpecfic;
		dmAvp->Flags.Mandatory = isMandatory;
		//dmAvp->PayLoad = avpPayLoadData;
		dmAvp->Next = NULL;

		dmAvp->iDataType = getAvpDataType( dmAvp->AvpCode );

		switch( dmAvp->iDataType)
		{
			case SIGNED_32:
				decodeIntValueFrom4Bytes( &dmAvp->intVal, dataPtr + (iCurrentByteIndex + iHeaderLength), 0);
				break;
			case UNSIGNED_32:
				decodeIntValueFrom4Bytes( &dmAvp->usIntVal, dataPtr + (iCurrentByteIndex + iHeaderLength), 0);
				break;
			case SIGNED_64:
				//Commented on 24-11-2016
				//decodeLongValueFrom4Bytes( &dmAvp->int64Val, dataPtr + (iCurrentByteIndex + iHeaderLength + 4), 0);
				
				dmAvp->int64Val = charToLong( dataPtr + (iCurrentByteIndex + iHeaderLength));
				
				//printf("1 iAvpCode=%d Val=%ld\n", iAvpCode, dmAvp->int64Val);
				//hexDump( dataPtr + (iCurrentByteIndex + iHeaderLength + 4), 4);
				//hexDump( dataPtr + (iCurrentByteIndex), 16);
				break;
			case UNSIGNED_64:
				//Commented on 24-11-2016
				//decodeLongValueFrom4Bytes( &dmAvp->usInt64Val, dataPtr + (iCurrentByteIndex + iHeaderLength + 4), 0);
				
				dmAvp->usInt64Val = charToULong( dataPtr + (iCurrentByteIndex + iHeaderLength));
				
				//printf("2 iAvpCode=%d Val=%ld\n", iAvpCode, dmAvp->usInt64Val);
				//hexDump( dataPtr + (iCurrentByteIndex + iHeaderLength + 4), 4);
				//hexDump( dataPtr + (iCurrentByteIndex), 16);
				break;
			case OCTET_STRING:
				dmAvp->PayLoad = (struct CData*)allocateCData();
				if( iDataLength < AVP_CHUNK_SIZE) 
				{
					memcpy( dmAvp->PayLoad->Data, dataPtr + (iCurrentByteIndex + iHeaderLength), iDataLength);
				}
				/*
				else
				{
					printf("Received OCTET_STRING More then our DataVariable[%d], RequiredSize[%d] for AVPCode[%d] \n", AVP_CHUNK_SIZE, iDataLength, dmAvp->AvpCode);
				}
				*/
				dmAvp->PayLoad->len = iDataLength;
				break;
			case GROUPED:
				appDecodeDiamGroupedAvp( dataPtr + (iCurrentByteIndex + iHeaderLength), dmAvp, (iLevel+1));
				break;
			default:
				break;
		}
		
		addAvp( dmParentAvp, dmAvp);
		iCurrentByteIndex += iAvpTotLength;
	}
}

void appLogDiamGroupedAvp( struct DiamAvp* dmAvp, int indent)
{
	char sTabs[20];
	memset( sTabs, 0, sizeof(sTabs));
	memset( sTabs, '\t', indent);
	
	struct DiamAvp* dmGHAvp = NULL;
	struct DiamAvp* dmGroupNext = NULL;
	dmGHAvp = dmAvp->GroupHead;

	while( dmGHAvp)	
	{
		switch( dmGHAvp->iDataType)
		{
			case SIGNED_32:
				CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "%s AVP[%d] SIGNED_32 DATA[%d]", sTabs, dmGHAvp->AvpCode, dmGHAvp->intVal);
				break;
			case UNSIGNED_32:
				CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "%s AVP[%d] UNSIGNED_32 DATA[%u]", sTabs, dmGHAvp->AvpCode, dmGHAvp->usIntVal);
				break;
			case SIGNED_64:
				CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "%s AVP[%d] UNSIGNED_64 DATA[%ld]", sTabs, dmGHAvp->AvpCode, dmGHAvp->int64Val);
				break;				
			case UNSIGNED_64:
				CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "%s AVP[%d] UNSIGNED_64 DATA[%lu]", sTabs, dmGHAvp->AvpCode, dmGHAvp->usInt64Val);
				break;
			case OCTET_STRING:
				CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "%s AVP[%d] OCTET_STRING DATA[%s] len[%d]", sTabs, dmGHAvp->AvpCode, dmGHAvp->PayLoad->Data, dmGHAvp->PayLoad->len);
				break;
			case GROUPED:
			{
				struct DiamAvp* gDiamAvp1 = dmGHAvp->GroupHead;
				
				if( gDiamAvp1) {
					CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "%s AVP[%d] GROUPED len[%d]", sTabs, gDiamAvp1->AvpCode, gDiamAvp1->AvpLength);
				}
				
				appLogDiamGroupedAvp( dmGHAvp, 1 + indent);
			}
				break;
			default:
				break;
		}		
		
		dmGroupNext = dmGHAvp->Next;
		dmGHAvp = dmGroupNext;
	}
		
}

void appLogDiamMessage( struct DiamMessage *oDiamMessage)
{
	int iPrintMessage = 1;

	if( iPrintMessage == 1)
	{
		CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "=======================================================================================================================");
		
		if( oDiamMessage->Flags.Request == 1)
		{
			CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Diameter Request[%d]", oDiamMessage->CmdCode);
		}
		else 
		{
			CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Diameter Answer[%d]", oDiamMessage->CmdCode);
		}
		
		CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "IsRequest = [%d], CmdCode = [%d], Length = [%d], AppId = [%d], HBHId = [%lu], E2EId =[%lu]", oDiamMessage->Flags.Request ,oDiamMessage->CmdCode, oDiamMessage->Length, oDiamMessage->AppId, oDiamMessage->HBHId, oDiamMessage->E2EId);

		struct DiamAvp* dmAvp = NULL;
		dmAvp = oDiamMessage->Head;
		int i = 0;
			
		while(dmAvp)
		{
			//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "index = [%d], AvpCode = [%d] AvpLength[%d] Padding[%d] VendorId[%d] PayLoadLength[%d] HeaderLength[%d]", i, dmAvp->AvpCode, dmAvp->AvpLength, dmAvp->Padding, dmAvp->VendorId, dmAvp->PayLoadLength, dmAvp->HeaderLength);
			//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "AvpCode=[%d] iDataType=[%d]", dmAvp->AvpCode, dmAvp->iDataType);

			switch( dmAvp->iDataType)
			{
				case SIGNED_32:
					CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "AVP[%d] SIGNED_32 DATA[%d]", dmAvp->AvpCode, dmAvp->intVal);
					break;
				case UNSIGNED_32:
					CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "AVP[%d] UNSIGNED_32 DATA[%u]", dmAvp->AvpCode, dmAvp->usIntVal);
					break;
				case SIGNED_64:
					CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "AVP[%d] UNSIGNED_64 DATA[%ld]", dmAvp->AvpCode, dmAvp->int64Val);
					break;				
				case UNSIGNED_64:
					CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "AVP[%d] UNSIGNED_64 DATA[%lu]", dmAvp->AvpCode, dmAvp->usInt64Val);
					break;
				case OCTET_STRING:
					CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "AVP[%d] OCTET_STRING DATA[%s] len[%d]", dmAvp->AvpCode, dmAvp->PayLoad->Data, dmAvp->PayLoad->len);
					break;
				case GROUPED:
				{
					struct DiamAvp* gDiamAvp = dmAvp->GroupHead;
					
					if(gDiamAvp) {
						CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "AVP[%d] GROUPED len[%d]", gDiamAvp->AvpCode, gDiamAvp->AvpLength);
					}
					
					appLogDiamGroupedAvp( dmAvp, 1);
				}
					break;
				default:
					break;
			}

			dmAvp = dmAvp->Next;
			i++;
		}

		CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "=======================================================================================================================");
	}
}


void core_handleCloseTCPClient( iTCPClientInfo* oClientInfo);

void appDecodeDiamMessage(void* dataPtr)
{
	struct DiamRawData* dDiamRawData = (struct DiamRawData*)dataPtr;
	struct DiamMessage* oDiamMessage = allocateMessage();

	oDiamMessage->AvpCount = 0;
	oDiamMessage->Head = oDiamMessage->Current = NULL;
	memset( &oDiamMessage->SessionId, 0, sizeof(oDiamMessage->SessionId));	
	oDiamMessage->iResultCode  = oDiamMessage->iCCReqNo = 0;
	oDiamMessage->iCCReqType = 0;
	oDiamMessage->hasServiceContextId = 0;
	oDiamMessage->iLoopDetected = 0;

	decodeIntValueFrom3Bytes( &oDiamMessage->Length, dDiamRawData->Header->Data, 1);
	decodeBitVal( &oDiamMessage->Flags.Request, dDiamRawData->Header->Data, 4, 7);
	decodeBitVal( &oDiamMessage->Flags.Proxyable, dDiamRawData->Header->Data, 4, 6);
	decodeBitVal( &oDiamMessage->Flags.Error, dDiamRawData->Header->Data, 4, 5);
	decodeBitVal( &oDiamMessage->Flags.Retransmit, dDiamRawData->Header->Data, 4, 4);
	decodeIntValueFrom3Bytes( &oDiamMessage->CmdCode, dDiamRawData->Header->Data, 5);
	decodeIntValueFrom4Bytes( &oDiamMessage->AppId, dDiamRawData->Header->Data, 8);
	decodeLongValueFrom4Bytes( &oDiamMessage->HBHId, dDiamRawData->Header->Data, 12);
	decodeLongValueFrom4Bytes( &oDiamMessage->E2EId, dDiamRawData->Header->Data, 16);

	//printf("Flags [0x%x] Request[%d]\n",  dDiamRawData->PayLoad->Data[4], oDiamMessage->Flags.Request);
	//printf("CmdCode [%d] Request[%d]\n",  oDiamMessage->CmdCode, oDiamMessage->Flags.Request);




	//int isRequest = oDiamMessage->Flags.Request;
	int iDecodeMessage = 1;
	int iDecodeOnlyRoutingInfo = 0;

	//DRA && Not Equals CER/DWR/DPR
	if( objStackConfig.NodeType == 2 && oDiamMessage->CmdCode != 257 && oDiamMessage->CmdCode != 280 && oDiamMessage->CmdCode != 282)
	{
		iDecodeMessage = 0;
		iDecodeOnlyRoutingInfo = 1;
	}

	iDecodeMessage = 1;
	
	//printf("decode disabled\n");
	//return;
	
	if(iDecodeMessage == 1)
	{
		int iCurrentByteIndex = 0;
		int iHeaderLength = 8;
		int iDataLength = 0;
		int iAvpTotLength = 0;
		int iAvpLength = 0;
		int isVendorSpecfic = 0;
		int isMandatory = 0;
		int iAvpCode = 0;

		//printf("dDiamRawData->iDecodeFull=%d\n", dDiamRawData->iDecodeFull);

		while(iCurrentByteIndex < dDiamRawData->PayLoad->len)
		{
			iHeaderLength = 8;

			decodeIntValueFrom4Bytes( &iAvpCode, dDiamRawData->PayLoad->Data, iCurrentByteIndex);
			decodeBitVal( &isVendorSpecfic, dDiamRawData->PayLoad->Data, (iCurrentByteIndex + 4), 7);
			decodeBitVal( &isMandatory, dDiamRawData->PayLoad->Data, (iCurrentByteIndex + 4), 6);
			decodeIntValueFrom3Bytes( &iAvpLength, dDiamRawData->PayLoad->Data, (iCurrentByteIndex + 5));

			if(iAvpCode < 0)
			{
				printf("%X %X %X %X\n", dDiamRawData->PayLoad->Data[iCurrentByteIndex], dDiamRawData->PayLoad->Data[iCurrentByteIndex + 1], dDiamRawData->PayLoad->Data[iCurrentByteIndex + 2], dDiamRawData->PayLoad->Data[iCurrentByteIndex + 3]);
			}



			if(isVendorSpecfic == 1)
			{
				iHeaderLength = 12;
			}



			iDataLength = iAvpLength - iHeaderLength;



			int rem = iAvpLength % 4;
			int iPadded = 0;



			if(rem > 0)
			{
				iPadded = 4 - rem;
			}


			iAvpTotLength = iAvpLength + iPadded;



			int VendorId = 0;
			if(isVendorSpecfic == 1)
			{
				decodeIntValueFrom4Bytes( &VendorId, dDiamRawData->PayLoad->Data, iCurrentByteIndex + (iHeaderLength-4));
			}



			//printf("iDataLength[%d] AvpCode[%d] iHeaderLength[%d],iAvpLength[%d], iPadded[%d], iAvpTotLength[%d] iCurrentByteIndex[%d]\n", iDataLength, iAvpCode, iHeaderLength, iAvpLength, iPadded, iAvpTotLength, iCurrentByteIndex);
			//printf("\n");

			//struct DiamAvp* dmAvp = (struct DiamAvp*)lib_malloc(sizeof(struct DiamAvp));
			//memset( dmAvp, 0, sizeof(sizeof(struct DiamAvp)));
			
			//printf( "objStackConfig.NodeType[%d] iDecodeOnlyRoutingInfo[%d] iAvpCode[%d]\n", objStackConfig.NodeType, iDecodeOnlyRoutingInfo, iAvpCode);

			
			
			
			if((iDecodeOnlyRoutingInfo == 1 && (iAvpCode == AVP_RouteRecord || iAvpCode == AVP_ServiceContextId || iAvpCode == AVP_DestinationHost || iAvpCode == AVP_DestinationRealm || iAvpCode == AVP_SessionId || iAvpCode == AVP_CCRequestType || iAvpCode == AVP_CCRequestNumber)) 
				|| iDecodeOnlyRoutingInfo == 0 
				|| ( iAvpCode == 443 && oDiamMessage->MSISDN == -1 && objStackConfig.MessageRoutingMode == 5)
				|| ( iAvpCode == 443 && oDiamMessage->IMSI == -1 && objStackConfig.MessageRoutingMode == 1)				
				|| dDiamRawData->iDecodeFull == 1 )
			{ 
				struct DiamAvp* dmAvp = (struct DiamAvp*) allocateDiamAvp();
				dmAvp->AvpCode = iAvpCode;
				dmAvp->AvpLength = iAvpLength;
				dmAvp->Padding = iPadded;
				dmAvp->PayLoadLength = iDataLength;
				dmAvp->HeaderLength = iHeaderLength;
				dmAvp->VendorId = VendorId;
				dmAvp->Flags.VendorSpecific = isVendorSpecfic;
				dmAvp->Flags.Mandatory = isMandatory;
				//dmAvp->PayLoad = avpPayLoadData;
				dmAvp->Next = NULL;

				dmAvp->iDataType = getAvpDataType( dmAvp->AvpCode );

				switch( dmAvp->iDataType)
				{
					case SIGNED_32:
						decodeIntValueFrom4Bytes( &dmAvp->intVal, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength), 0);
						
						if( dmAvp->AvpCode == AVP_CCRequestType)
							oDiamMessage->iCCReqType = dmAvp->intVal;
							
						break;
					case UNSIGNED_32:
						decodeIntValueFrom4Bytes( &dmAvp->usIntVal, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength), 0);
						
						if( dmAvp->AvpCode == AVP_CCRequestNumber)
							oDiamMessage->iCCReqNo = dmAvp->usIntVal;
						else if( dmAvp->AvpCode == AVP_ResultCode)
							oDiamMessage->iResultCode = dmAvp->usIntVal;								
							
						break;
					case SIGNED_64:
						//decodeTo64BitValue( &dmAvp->int64Val, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength));
						
						//Commented On 24-11-2016
						//decodeLongValueFrom4Bytes( &dmAvp->int64Val, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength + 4), 0);
						
						dmAvp->int64Val = charToLong( (dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength)) );
						break;
					case UNSIGNED_64:
						//decodeTo64BitValue( &dmAvp->usInt64Val, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength));
						
						//Commented On 24-11-2016
						//decodeLongValueFrom4Bytes( &dmAvp->usInt64Val, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength + 4), 0);
						
						dmAvp->usInt64Val = charToULong( (dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength)) );
						break;
					case GROUPED:
						appDecodeDiamGroupedAvp( dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength), dmAvp, 0);
						
						if( ( iAvpCode == 443 && oDiamMessage->MSISDN == -1 && objStackConfig.MessageRoutingMode == 5) || ( iAvpCode == 443 && oDiamMessage->IMSI == -1 && objStackConfig.MessageRoutingMode == 1) )
						{
							//if( dmAvp->GroupHead != NULL)
							if(dmAvp->GroupHead)	
							{
								if(dmAvp->GroupHead->AvpCode == 450 && dmAvp->GroupHead->intVal == 0)
								{
									//MSISDN
									if( dmAvp->GroupCurrent->AvpCode == 444)
									{
										oDiamMessage->MSISDN = atoll(dmAvp->GroupCurrent->PayLoad->Data);
									}
								}
								else if(dmAvp->GroupHead->AvpCode == 450 && dmAvp->GroupHead->intVal == 1)
								{
									//IMSI
									if( dmAvp->GroupCurrent->AvpCode == 444)
									{
										oDiamMessage->IMSI = atoll(dmAvp->GroupCurrent->PayLoad->Data);
									}
								}
							}
						}
						
						break;
					case OCTET_STRING:
						dmAvp->PayLoad = (struct CData*)allocateCData();
						
						if( iDataLength < AVP_CHUNK_SIZE)
						{
							memcpy( dmAvp->PayLoad->Data, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength), iDataLength);
						}
						/*
						else
						{
							printf("Received OCTET_STRING More then our DataVariable[%d], RequiredSize[%d] for AVPCode[%d] \n", AVP_CHUNK_SIZE, iDataLength, dmAvp->AvpCode);
						}
						*/
						
						dmAvp->PayLoad->len = iDataLength;
						
						if( objStackConfig.NodeType == 2)
						{
							if( dmAvp->AvpCode == AVP_DestinationRealm)
							{
								memset( &oDiamMessage->DestRealm, 0, sizeof(oDiamMessage->DestRealm));
								memcpy( &oDiamMessage->DestRealm, dmAvp->PayLoad->Data, iDataLength);
								oDiamMessage->DestRealm[iDataLength] = '\0';
								
								//printf("Copied AVP_DestinationRealm[%s] src[%s] iDataLength[%d]\n", oDiamMessage->DestRealm, dmAvp->PayLoad->Data, iDataLength);
							}
							else if(dmAvp->AvpCode == AVP_DestinationHost)
							{
								memset( &oDiamMessage->DestHost, 0, sizeof(oDiamMessage->DestHost));
								memcpy( &oDiamMessage->DestHost, dmAvp->PayLoad->Data, iDataLength);
								oDiamMessage->DestHost[iDataLength] = '\0';	
								
								//printf("Copied AVP_DestinationHost[%s] src[%s] iDataLength[%d]\n", oDiamMessage->DestHost, dmAvp->PayLoad->Data, iDataLength);						
							}
							else if(dmAvp->AvpCode == AVP_ServiceContextId)
							{
								memset( &oDiamMessage->ServiceContext, 0, sizeof(oDiamMessage->ServiceContext));
								memcpy( &oDiamMessage->ServiceContext, dmAvp->PayLoad->Data, iDataLength);
								oDiamMessage->hasServiceContextId = 1;
								oDiamMessage->ServiceContext[iDataLength] = '\0';
							}
							else if(dmAvp->AvpCode == AVP_RouteRecord && oDiamMessage->Flags.Request == 1)
							{
								if( strcmp( dmAvp->PayLoad->Data, objStackConfig.HostName) == 0)
								{
									oDiamMessage->iLoopDetected = 1;
								}
							}							
						}
						
						if( dmAvp->AvpCode == AVP_SessionId)
						{
							//SessionId
							memcpy( &oDiamMessage->SessionId, dmAvp->PayLoad->Data, iDataLength);
							oDiamMessage->SessionId[iDataLength] = '\0';	
						}
						
						break;
					default:
						break;
				}

				//struct CData* avpPayLoadData = (struct CData*)lib_malloc(sizeof(struct CData));
				//avpPayLoadData->Data = (char *)lib_malloc( iDataLength);
				//memset(avpPayLoadData->Data, '\0', iDataLength);

				//avpPayLoadData->len = iDataLength;
				//memcpy( avpPayLoadData->Data, dDiamRawData->PayLoad->Data + (iCurrentByteIndex + iHeaderLength), (iDataLength));

				//avpPayLoadData->Data[avpPayLoadData->len] = '\0';

				appAddAvpToDiamMessage( oDiamMessage, dmAvp);
			}

			iCurrentByteIndex += iAvpTotLength;

		}

		oDiamMessage->sinfo_stream = 0;

		int iPrintMessage = 0;

		if( iPrintMessage == 1)
		{
			printf("=======================================================================================================================\n");
			
			if( oDiamMessage->Flags.Request == 1)
			{
				printf( "Received Request[%d]\n", oDiamMessage->CmdCode);
			}
			else 
			{
				printf( "Received Answer[%d]\n", oDiamMessage->CmdCode);
			}
			
			
			printf( "HeaderLength = [%d], PayLoadLength = [%d] ", dDiamRawData->Header->len, dDiamRawData->PayLoad->len);
			printf( "Request = [%d], CmdCode = [%d], Length = [%d], AppId = [%d], HBHId = [%lu], E2EId =[%lu] \n", oDiamMessage->Flags.Request ,oDiamMessage->CmdCode, oDiamMessage->Length, oDiamMessage->AppId, oDiamMessage->HBHId, oDiamMessage->E2EId);


			struct DiamAvp* dmAvp = NULL;
			dmAvp = oDiamMessage->Head;
			int i = 0;

			//while(dmAvp != NULL)
			while(dmAvp)	
			{
				printf("index = [%d], AvpCode = [%d] AvpLength[%d] Padding[%d] VendorId[%d] PayLoadLength[%d] HeaderLength[%d]", i, dmAvp->AvpCode, dmAvp->AvpLength, dmAvp->Padding, dmAvp->VendorId, dmAvp->PayLoadLength, dmAvp->HeaderLength);

				switch( dmAvp->iDataType)
				{
					case SIGNED_32:
						printf(" DATA[%d]\n", dmAvp->intVal);
						break;
					case UNSIGNED_32:
						printf(" DATA[%d]\n", dmAvp->usIntVal);
						break;
					case SIGNED_64:
					case UNSIGNED_64:
						break;
					case OCTET_STRING:
						printf(" DATA[%s] len[%d]\n", dmAvp->PayLoad->Data, dmAvp->PayLoad->len);
						break;
					case GROUPED:
					{
						printf("\n");
						struct DiamAvp* gDiamAvp = dmAvp->GroupHead;
						int j = 0;
						while(gDiamAvp)
						{
							printf("    --- grouped index = [%d], AvpCode = [%d] AvpLength[%d] Padding[%d] VendorId[%d] PayLoadLength[%d] HeaderLength[%d]\n", 
							j, gDiamAvp->AvpCode, gDiamAvp->AvpLength, gDiamAvp->Padding, gDiamAvp->VendorId, gDiamAvp->PayLoadLength, gDiamAvp->HeaderLength);
							gDiamAvp = gDiamAvp->Next;
							j++;
						}
					}
						break;
					default:
						break;
				}

				dmAvp = dmAvp->Next;
				i++;
			}

			printf("=======================================================================================================================\n");
		}
	}

	
	//printf("------------------------------ post-decode disabled ------------------------------\n");
	//return;	

	/*
	 * The First Request from Client should be CER
	 * Or
	 * The Peer is Sending CEA
	 */
	
	/**/
	LOGCAT( objStackConfig.iCatLog_CoreDecode, LOG_LEVEL_CRITICAL, 
		__FUNCTION__, __LINE__, "Decoded Message, iRequestNo[%ld] SessionID[%s] AppId[%d] CmdCode[%d] Request[%d] HBHId[%lu] E2EId[%lu]" , 
		dDiamRawData->iRequestNo, oDiamMessage->SessionId, oDiamMessage->AppId, 
		oDiamMessage->CmdCode, oDiamMessage->Flags.Request,
		oDiamMessage->HBHId, oDiamMessage->E2EId);
	
	//printf("iRequestNo[%ld] CmdCode[%d] Flags.Request[%d]\n", dDiamRawData->iRequestNo, oDiamMessage->CmdCode, oDiamMessage->Flags.Request);

	//printf("------------------------------ routing disabled ------------------------------\n");
	//return;	
	
	int bReleaseMsg = 1;
	
	if(dDiamRawData->iRequestNo == 0)
	{
		if(oDiamMessage->CmdCode == 257 )
		{
			if(oDiamMessage->Flags.Request == 1)
			{
				//printf("__here %d\n", __LINE__);
				appValidateCERAndSendCEA( oDiamMessage, dDiamRawData->CliInfo, dDiamRawData->iPeerIndex);
				//bReleaseMsg = 0;
				//return;
			}
			else
			{
				//int i = 0;
				unsigned int iResultCode;
				iResultCode = -1;

				struct DiamAvp* dmAvp = NULL;
				dmAvp = oDiamMessage->Head;

				//while(dmAvp != NULL)
				while(dmAvp)	
				{
					if(dmAvp->AvpCode == AVP_ResultCode)
					{
						iResultCode = dmAvp->usIntVal;

						break;
					}
					dmAvp = dmAvp->Next;
				}

				if(iResultCode == 2001)
				{
					if( dDiamRawData->iPeerIndex >= 0)
					{
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received Success CEA From Peer[%d] with ResultCode[%d]", dDiamRawData->iPeerIndex, iResultCode);
						objStackConfig.Peers[dDiamRawData->iPeerIndex].isCEASuccess = 1;
					}
					//else if( dDiamRawData->CliInfo != NULL)
					else if(dDiamRawData->CliInfo)	
					{
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received Success CEA From Client[%d] with ResultCode[%d]", dDiamRawData->CliInfo->ClientIndex, iResultCode);
						dDiamRawData->CliInfo->isCEASuccess = 1;						
					}
					else if(dDiamRawData->PeerConfigData)
					{
						printf("CEA Successful..........\n");
						iPeerConfigData * oPeerConfigData = (iPeerConfigData *)dDiamRawData->PeerConfigData;
						oPeerConfigData->isCERSuccess = 1;
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received Success CEA From Peer->Id[%d] PeerName[%s] Port[%d] with ResultCode[%d]", oPeerConfigData->Id, oPeerConfigData->sPeerName, oPeerConfigData->iPortNo, iResultCode);
					}
				}
				else
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received Failed CEA From Peer[%d] with ResultCode[%d]", dDiamRawData->iPeerIndex, iResultCode);
					
					if( dDiamRawData->iPeerIndex >= 0)
					{
						closePeerConnection( &dDiamRawData->iPeerIndex);
						//objStackConfig.Peers[dDiamRawData->iPeerIndex].isCEASuccess = -5;
						objStackConfig.Peers[dDiamRawData->iPeerIndex].isCEASuccess = 0;
					}
					//else if( dDiamRawData->CliInfo != NULL)
					else if(dDiamRawData->CliInfo)	
					{
						/*
						if( oApplicationServer)
						{
							if( dDiamRawData->CliInfo->TransportType == 3)
							{
								closeClientConnection( &dDiamRawData->CliInfo->ClientIndex);
							}
							else if( dDiamRawData->CliInfo->TransportType == 1)
							{
								iTCPClientInfo * oTCPClientInfo = (iTCPClientInfo *)dDiamRawData->CliInfo;
								core_handleCloseTCPClient( oTCPClientInfo);
							}
							dDiamRawData->CliInfo->isCEASuccess = 0;							
						}
						else
						{
							closeClientConnection( &dDiamRawData->CliInfo->ClientIndex);
							dDiamRawData->CliInfo->isCEASuccess = 0;
						}
						*/	
						if( dDiamRawData->CliInfo->ClientIndex > 0)
							closeClientConnection( &dDiamRawData->CliInfo->ClientIndex);
						
						if( dDiamRawData->CliInfo->TransportType >= 0)
						{
							closeAndCleanClientSocket( dDiamRawData->CliInfo);
						}
						
						dDiamRawData->CliInfo->isCEASuccess = 0;
					}
					else if(dDiamRawData->PeerConfigData)
					{
						iPeerConfigData * oPeerConfigData = (iPeerConfigData *)dDiamRawData->PeerConfigData;
						oPeerConfigData->DoNotConnect = 1;
						closeAndCleanClientPeerConfigSocket( oPeerConfigData);
					}
					/*
					else if(dDiamRawData->TCPCliInfo)
					{
						//iPeerConfigData * oPeerConfigData = (iPeerConfigData *)dDiamRawData->PeerConfigData;
						//oPeerConfigData->DoNotConnect = 1;
						//closeAndCleanClientPeerConfigSocket( oPeerConfigData);
						iTCPClientInfo * oTCPClientInfo = (iTCPClientInfo *)dDiamRawData->TCPCliInfo;
						core_handleCloseTCPClient( oTCPClientInfo);
					}
					*/		
				}

			}

		}
		else
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "First Message Should be CER from Client[%d], but Received[%d]", dDiamRawData->CliInfo->fd, oDiamMessage->CmdCode);
			closeAndCleanClientSocket(dDiamRawData->CliInfo);
		}
	}
	else
	{
		//handle Other Request/Answer
		//CER/DWR/DPR/CCR

		if(oDiamMessage->Flags.Request == 1)
		{
			if(oDiamMessage->CmdCode == 257)
			{
				//printf("__here %d\n", __LINE__);
				appValidateCERAndSendCEA( oDiamMessage, dDiamRawData->CliInfo, dDiamRawData->iPeerIndex);
				//bReleaseMsg = 0;
				//return;
			}
			else if(oDiamMessage->CmdCode == 280)
			{
				//appSendDWA( oDiamMessage, dDiamRawData->CliInfo, dDiamRawData->iPeerIndex );
				appSendDWA2( oDiamMessage, dDiamRawData);
			}
			else if(oDiamMessage->CmdCode == 282)
			{
				//Handle Disconnect Peer Request
				appHandleDisconnectPeerRequest( oDiamMessage, dDiamRawData->CliInfo, dDiamRawData->iPeerIndex);
			}
			else
			{
				if(objStackConfig.NodeType == 2)
				{
					//DRA Instance...Route Message
					appRouteMessage( oDiamMessage, dDiamRawData);
					bReleaseMsg = 0;
				}
				else if( pServerMessageHandler > 0)
				{
					//Request Comes from Client
					oDiamMessage->ptrClientInfo = dDiamRawData->CliInfo;
					oDiamMessage->sinfo_stream = dDiamRawData->sinfo_stream;
					
					#if SCTP_SUPPORT
						oDiamMessage->sinfo_assoc_id = dDiamRawData->sinfo_assoc_id;
						memcpy( &oDiamMessage->sinfo, &dDiamRawData->sinfo, sizeof(struct sctp_sndrcvinfo));
					#endif
					
					releaseDiamRawData( dDiamRawData);
					pServerMessageHandler( oDiamMessage);
					return;
				} 
				else
				{
					printf("oDiamMessage->CmdCode[%d]........Not Handled Request iRequestNo[%ld] NodeType[%d]\n", oDiamMessage->CmdCode, dDiamRawData->iRequestNo, objStackConfig.NodeType);
				}
			}
		}
		else
		{
			//printf("Handle Diameter Answer., CmdCode[%d]\n", oDiamMessage->CmdCode);

			if(oDiamMessage->CmdCode == 280)
			{
				//DWA
				//int i = 0;
				unsigned int iResultCode;
				iResultCode = -1;

				struct DiamAvp* dmAvp = NULL;
				dmAvp = oDiamMessage->Head;

				//while(dmAvp != NULL)
				while(dmAvp)	
				{
					if(dmAvp->AvpCode == AVP_ResultCode)
					{
						iResultCode = dmAvp->usIntVal;

						break;
					}
					dmAvp = dmAvp->Next;
				}
				
				if(iResultCode == 2001)
				{
					if( dDiamRawData->iPeerIndex >= 0)
					{
						objStackConfig.Peers[dDiamRawData->iPeerIndex].iDWRCount--;
					}
					else if( dDiamRawData->CliInfo )
					{
						
					}
				}
				else
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received DWR Failure ResultCode[%d]", iResultCode);
				}
			}
			else if(oDiamMessage->CmdCode == 282)
			{
				//Handle Disconnect Peer Request
			}			
			else if(oDiamMessage->CmdCode == 257)
			{
				//int i = 0;
				unsigned int iResultCode;
				iResultCode = -1;

				struct DiamAvp* dmAvp = NULL;
				dmAvp = oDiamMessage->Head;

				//while(dmAvp != NULL)
				while(dmAvp)	
				{
					if(dmAvp->AvpCode == AVP_ResultCode)
					{
						iResultCode = dmAvp->usIntVal;

						break;
					}
					dmAvp = dmAvp->Next;
				}
				
				if(iResultCode == 2001)
				{
					if( dDiamRawData->iPeerIndex >= 0)
					{
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received Success CEA From Peer[%d] with ResultCode[%d]", dDiamRawData->iPeerIndex, iResultCode);
						objStackConfig.Peers[dDiamRawData->iPeerIndex].isCEASuccess = 1;
					}
					//else if( dDiamRawData->CliInfo != NULL)
					else if( dDiamRawData->CliInfo )
					{
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received Success CEA From Client[%d] with ResultCode[%d]", dDiamRawData->CliInfo->ClientIndex, iResultCode);
						dDiamRawData->CliInfo->isCEASuccess = 1;
					}
				}
				else
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Received Failed CEA From Peer[%d] with ResultCode[%d]", dDiamRawData->iPeerIndex, iResultCode);
					
					if( dDiamRawData->iPeerIndex >= 0)
					{
						closePeerConnection( &dDiamRawData->iPeerIndex);
						//objStackConfig.Peers[dDiamRawData->iPeerIndex].isCEASuccess = -5;
						objStackConfig.Peers[dDiamRawData->iPeerIndex].isCEASuccess = 0;
					}
					//else if( dDiamRawData->CliInfo != NULL)
					else if( dDiamRawData->CliInfo )	
					{
						closeClientConnection( &dDiamRawData->CliInfo->ClientIndex);
						dDiamRawData->CliInfo->isCEASuccess = 0;
					}
					else if( dDiamRawData->PeerConfigData)
					{
						iPeerConfigData * oPeerConfigData = (iPeerConfigData *)dDiamRawData->PeerConfigData;
						oPeerConfigData->DoNotConnect = 1;
						closeAndCleanClientPeerConfigSocket( oPeerConfigData);
					}					
				}
				
			}
			else if(objStackConfig.NodeType == 2)
			{
				//DRA Instance...Route Message
				appRouteMessage( oDiamMessage, dDiamRawData);	
				bReleaseMsg = 0;				
			}
			else if( pServerMessageHandler > 0)
			{
				//Request Comes from Client
				oDiamMessage->ptrClientInfo = dDiamRawData->CliInfo;
				oDiamMessage->sinfo_stream = dDiamRawData->sinfo_stream;
				
				#if SCTP_SUPPORT
					oDiamMessage->sinfo_assoc_id = dDiamRawData->sinfo_assoc_id;
					memcpy( &oDiamMessage->sinfo, &dDiamRawData->sinfo, sizeof(struct sctp_sndrcvinfo));
				#endif
				
				releaseDiamRawData( dDiamRawData);
				pServerMessageHandler( oDiamMessage);
				return;				
			}
			else
			{
				printf("oDiamMessage->CmdCode[%d]........Not Handled Answer iRequestNo[%ld] \n", oDiamMessage->CmdCode, dDiamRawData->iRequestNo);				
			}
		}
		
	}

	if( bReleaseMsg == 1)
	{	
		releaseMessage(oDiamMessage);
		releaseDiamRawData( dDiamRawData);
	}	
}


void fillMiniData( struct DiamMessage *dmMsg, iCCRMini *oCCR)
{
	getCommandInfo( dmMsg, &oCCR->CmdCode, &oCCR->Request, &oCCR->ApplicationId, &oCCR->H2HId, &oCCR->E2EId);
	
	struct DiamAvp* dmAvp = (struct DiamAvp*)iteratorMoveFirst(dmMsg);

	//while(dmAvp != NULL)
	while(dmAvp)	
	{
		int iAvpCode = getAvpCode(dmAvp);
		int iAvpDataType = getAvpDataType( iAvpCode);
		
		switch( iAvpDataType )
		{
			case SIGNED_32:
				{
					//int iVal = 0;
					//getIntValue( dmAvp, &iVal);
					//printf("AVPCode[%d] Value[%d]\n", iAvpCode, iVal);
					
					if( iAvpCode == AVP_CCRequestType)
					{
						//oCCR->RequestType = iVal;
						getIntValue( dmAvp, &oCCR->RequestType);
					}
					
				}	
				break;
			case UNSIGNED_32:
				{	
					//unsigned int uiVal = 0; 
					//getUnsignedIntValue( dmAvp, &uiVal);
					//printf("AVPCode[%d] unsigned Value[%d]\n", iAvpCode, uiVal);
					
					if( iAvpCode == AVP_AuthApplicationId)
					{
						//oCCR->AuthApplicationId = uiVal;
						getUnsignedIntValue( dmAvp, &oCCR->AuthApplicationId);
					}
					else if(iAvpCode == AVP_CCRequestNumber)
					{
						//oCCR->RequestNumber = uiVal;
						getUnsignedIntValue( dmAvp, &oCCR->RequestNumber);
					}
					else if(iAvpCode == AVP_OriginStateId)
					{
						//oCCR->OriginStateId = uiVal;
						getUnsignedIntValue( dmAvp, &oCCR->OriginStateId);						
					}
				}	
				break;
			case SIGNED_64:
				break;
			case UNSIGNED_64:
				break;
			case OCTET_STRING:
				{
					int iLength;
					
					/*
					char cData[300];
					memset( cData, '\0', sizeof(cData));
					getOctetString( dmAvp, cData, &iLength);
					printf( "AVPCode[%d] String Value[%s] iLength[%d]\n", iAvpCode, cData, iLength);
					*/
					if( iAvpCode == AVP_SessionId)
					{
						getOctetString( dmAvp, oCCR->cSessionId, &iLength);
					}
					else if( iAvpCode == AVP_OriginHost)
					{
						getOctetString( dmAvp, oCCR->cOriginHost, &iLength);
					}
					else if( iAvpCode == AVP_OriginRealm)
					{
						getOctetString( dmAvp, oCCR->cOriginRealm, &iLength);
					}
					else if( iAvpCode == AVP_DestinationRealm)
					{
						getOctetString( dmAvp, oCCR->cDesinationRealm, &iLength);
					}
					else if( iAvpCode == AVP_ServiceContextId)
					{
						getOctetString( dmAvp, oCCR->cServiceContextId, &iLength);
					}
						
				}			
				break;
			case GROUPED:
				break;
			default:
				break;
		}

		dmAvp = (struct DiamAvp*) iteratorMoveNext(dmMsg);
	}	
}




void appHandleQuitCommand()
{
	char userOption[50];

	do
	{
		scanf("%s", userOption);
	}
	while (strcmp ( "q", userOption) != 0 );

	//clean up items

	//printf("exit\n");
}

void closeAndCleanClientSocket( iClientInfo * cliInfo)
{
	if(cliInfo->isActive == 1)
	{	
		cliInfo->isActive = 0;
		close(cliInfo->fd);
		shutdown(cliInfo->fd, 2);
	}
	
	int ifd = cliInfo->fd;
	cliInfo->fd = -1;	
	
	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closed Socket Connection For OriginHost[%s] OriginRealm[%s] FD[%d]", cliInfo->OriginHost, cliInfo->OriginRealm, ifd);
}


iWorkerThread * appAllocateDecodeThread()
{
	iWorkerThread * oWorkerThread;
	iWorkerThread * objWorkerThread;
	objWorkerThread = NULL;

	pthread_mutex_lock( &objStackObjects.DecodeThreadPool.aquireLock);

	oWorkerThread = (iWorkerThread *)objStackObjects.DecodeThreadPool.Head;

	//while( oWorkerThread != NULL)
	while( oWorkerThread )	
	{
		if(oWorkerThread->isFree == 1)
		{
			oWorkerThread->isFree = 0;
			objStackObjects.DecodeThreadPool.FreeCount--;

			objWorkerThread = oWorkerThread;

			break;
		}

		oWorkerThread = oWorkerThread->Next;
	}
	pthread_mutex_unlock( &objStackObjects.DecodeThreadPool.aquireLock);

	/*
	if(objWorkerThread == NULL)
	{
		//printf("No Worker Threads are Free, FreeCount[%d] \n", objStackObjects.DecodeThreadPool.FreeCount);
	}
	else
	{
		//printf("Allocated Worker Thread Index [%d]  FreeCount[%d] \n", objWorkerThread->Index , objStackObjects.DecodeThreadPool.FreeCount);
	}
	*/ 

	return objWorkerThread;
}




void Enquee( void *Data, struct Queue *oQueue)
{
	pthread_mutex_lock( &oQueue->Lock);

	//if( oQueue->Rear == NULL)
	if(!oQueue->Rear)	
	{
		oQueue->Rear = (iQueueRecord*)allocateQueueRecord();
		oQueue->Rear->Data = Data;
		oQueue->Rear->Next = NULL;
		oQueue->Front = oQueue->Rear;
		
		//printf("Message Enqueed Here [type(%d)] %d\n", oQueue->Type, __LINE__ );
	}
	else
	{
		oQueue->Temp = (iQueueRecord*)allocateQueueRecord();
		oQueue->Temp->Data = Data;
		oQueue->Temp->Next = NULL;
		
		oQueue->Rear->Next = oQueue->Temp;
		oQueue->Rear = oQueue->Temp;
		
		//printf("Message Enqueed Here [type(%d)] %d\n", oQueue->Type, __LINE__ );
	}	
	
	oQueue->TotalQueued++;
	oQueue->QueueCount++;
	//printf(" QueueCount %lu\n", oQueue->QueueCount);
	
	pthread_mutex_unlock( &oQueue->Lock);	
	
	//#if DIAMDRA	
		sem_post( &oQueue->sem_lock);
	//#endif	
}


void *Dequee(struct Queue *oQueue)
{
	void *Data = NULL;
	
	//#if DIAMDRA
		sem_wait( &oQueue->sem_lock);
	//#endif
	
	pthread_mutex_lock( &oQueue->Lock);	
	
	oQueue->Front1 = oQueue->Front;
	
	//if( oQueue->Front1 == NULL)
	if(!oQueue->Front1)
	{
		//printf("1 RET FROM %d\n", __LINE__ );
	}
	else
	{
		//printf("2 RET FROM %d\n", __LINE__ );		
		//if( oQueue->Front1->Next != NULL)
		if( oQueue->Front1->Next)	
		{
			oQueue->Front1 = oQueue->Front1->Next;
			Data = oQueue->Front->Data;
			releaseQueueRecord( oQueue->Front);
			oQueue->Front = oQueue->Front1;
			
			//printf("3 RET FROM [type(%d)] %d\n", oQueue->Type, __LINE__ );					
			//printf("RET FROM %d iRequestNo=%d PoolIndex=%d HL=%d PL=%d\n", __LINE__ , Data->iRequestNo, Data->PoolIndex , Data->Header->len, Data->PayLoad->len );			
		}
		else
		{
			Data = oQueue->Front->Data;
			releaseQueueRecord( oQueue->Front);
			oQueue->Front = oQueue->Rear = NULL;
			
			//printf("4 RET FROM [type(%d)] %d\n", oQueue->Type, __LINE__ );
			//printf("RET FROM %d iRequestNo=%d PoolIndex=%d HL=%d PL=%d\n", __LINE__ , Data->iRequestNo, Data->PoolIndex , Data->Header->len, Data->PayLoad->len );			
		}
		
		oQueue->TotalDequeued++;
		oQueue->QueueCount--;
	}
	
	pthread_mutex_unlock( &oQueue->Lock);	
	
	return Data;
}

void Enquee1( void *Data)
{
	Enquee( Data, &objStackObjects.AppMessageQueue1);
}

void LogEnquee( void *Data)
{
	Enquee( Data, &objStackObjects.LogQueue);
}

void Enquee2( void *Data)
{
	Enquee( Data, &objStackObjects.AppMessageQueue2);
}

void Enquee3( void *Data)
{
	Enquee( Data, &objStackObjects.AppMessageQueue3);
}

void *Dequee1()
{
	return (void *)Dequee( &objStackObjects.AppMessageQueue1);
}

void *LogDequee()
{
	return (void *)Dequee( &objStackObjects.LogQueue);
}

void *Dequee2()
{
	return (void *)Dequee( &objStackObjects.AppMessageQueue2);
}

void *Dequee3()
{
	return (void *)Dequee( &objStackObjects.AppMessageQueue3);
}




void appPostMsg( struct DiamRawData *dDiamRawData)
{
	if( objStackConfig.QueueMode == 0)
	{
		iWorkerThread *objWorkerThread;
		objWorkerThread = appAllocateDecodeThread();
		
		//printf("Allocated Thread [%d]\n", objWorkerThread->Index);

		//if(objWorkerThread != NULL)
		if(objWorkerThread)	
		{
			objStackObjects.TotalMemoryUsage.DecodeThreadAllocatedCount++;
			
			objWorkerThread->Data = (void*)dDiamRawData;
			sem_post( &objWorkerThread->sem_lock);
		}
		else
		{
			//printf("Got NULL as Worker Thread\n");
			objStackObjects.TotalMemoryUsage.DecodeThreadRejectedCount++;

			//Send Error Message
			//TODO:Post it to Rejection/Error Queue.

			//till then
			releaseDiamRawData( dDiamRawData);
		}
	}
	else
	{
		//long backLog = objStackObjects.TotalMemoryUsage.DiamMessageAllocatedCount - objStackObjects.TotalMemoryUsage.DiamMessageReleaseCount;
		
		long backLog = objStackObjects.DiamMessagePool->FreePool->Count;
		
		//if( backLog < 100000)
			
		if( backLog > 500)	
		{
			//printf("backLog=[%ld] dDiamRawData->iRoutinError=%d LINE=[%d] type(%d)\n", backLog, dDiamRawData->iRoutinError, __LINE__, objStackObjects.DecodeMessageQueue.Type);
			Enquee( dDiamRawData, &objStackObjects.DecodeMessageQueue);
		}
		else
		{
			//appPeerRoutingError();
			//has to send Error
			//releaseDiamRawData( dDiamRawData);
			
			//printf("backLog=[%ld] dDiamRawData->iRoutinError=%d LINE=[%d] type(%d)\n", backLog, dDiamRawData->iRoutinError, __LINE__, objStackObjects.DecodeMessageQueue.Type);			
			
			//Message Received From Client and Presently Out of Space and reject the message
			if( dDiamRawData->iMessageArrivedFrom == 2)
			{
				//printf("setting Routing Error\n");
				
				dDiamRawData->iDecodeFull = 1;
				dDiamRawData->iRoutinError = 1;
				dDiamRawData->iErrorCode =  5006;		//5006		DIAMETER_RESOURCES_EXCEEDED
														//5012		DIAMETER_UNABLE_TO_COMPLY	
														
				Enquee( dDiamRawData, &objStackObjects.DecodeMessageQueue);	
			}
			else
			{
				//Message Received from Peer, Ignore it as we cant send error message here
				releaseDiamRawData( dDiamRawData);
			}
		}
		
		/*
		if( objStackObjects.DecodeMessageQueue.QueueCount < objStackObjects.DecodeMessageQueue.QueueLimit)
		{
			Enquee( dDiamRawData, &objStackObjects.DecodeMessageQueue);
		} 
		else
		{
			objStackObjects.TotalMemoryUsage.DecodeThreadRejectedCount++;
			releaseDiamRawData( dDiamRawData);			
		}
		*/ 
	}
}

typedef struct Config_View_Request
{
	int RequestType;
} ConfigViewRequest;

typedef struct Config_View_Response
{
	int RequestType;
	int TotalSegments;
	int SegmentIndex;
	
	char PeerHostName[250];
	char PeerHostRealmName[250];
	char PeerIP[30];
	int PeerPort;
	int isConnected;
	int isCEASuccess;
	int AppId;
	int PeerId;
	
} ConfigViewResponse;

#define NodeRequestType_View 1


void * appConfigThread(void *args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	return NULL;
}



void handle_sctp_event( void * buf, int iLen);

void * appSctpClientThread( void * args)
{
	#if SCTP_SUPPORT
	
	iClientInfo * cliInfo = (iClientInfo *)args;
	cliInfo->isActive = 1;
	unsigned int iMessageLength, iBodySize;
	
	int n = 0, flags = 0, ret;
	//socklen_t from_len;
	struct sctp_sndrcvinfo sinfo = {0};
	//struct sockaddr_in addr = {0};
	 
	//ssize_t count;
	char buf[5000];
	char totbuf[10000];
	int iTotalBufferLength = 0;
	int PendingBufferLength = 0;
	int iUsedBufferSize = 0;
	
	struct pollfd fds;	
	fds.fd     = cliInfo->fd;
	fds.events = POLLIN;
	struct DiamRawData * oDiamRawData = NULL;
	long int iRequestNo = 0;
	memset( &cliInfo->SctpStreamBuffer, 0, sizeof( cliInfo->SctpStreamBuffer));
	
	CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Created Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);

	int sctp_buffer_pool_size = sizeof(cliInfo->SctpStreamBuffer) / sizeof(iSctpStreamBuffer);
	int ifc = 0;
	
	while(1)
	{
		iRequestNo = 0;
		
		for( ifc = 0; ifc < sctp_buffer_pool_size; ifc++)
		{
			cliInfo->SctpStreamBuffer[ ifc].PendingBufferLength = 0;
		}
		
		
		while( cliInfo->isActive == 1)
		{
			if( cliInfo->CloseIt == 1)
			{
				close( cliInfo->fd);
				shutdown( cliInfo->fd, 2);
				cliInfo->isActive = 0;
				break;
			}
			
			ret = poll( &fds, 1, 1000);

			if( ret == 0)
			{
				continue;
			}

			if( ret < 0)
			{
				close( cliInfo->fd);
				shutdown( cliInfo->fd, 2);
				cliInfo->isActive = 0;
				break;
			}

			if( ret > 0)
			{
				n = sctp_recvmsg( cliInfo->fd, buf, sizeof( buf), (struct sockaddr *)NULL, 0, &sinfo, &flags);
				
				if( flags & MSG_NOTIFICATION ) 
				{
					union sctp_notification  *snp = (union sctp_notification *)buf;
					
					if(snp)
					{
						if( SCTP_SHUTDOWN_EVENT == snp->sn_header.sn_type )
						{
							CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "SCTP_SHUTDOWN_EVENT Notified, closing connection");
							close( cliInfo->fd);
							shutdown( cliInfo->fd, 2);
							cliInfo->isActive = 0;
							break;
						}
					}
					
					handle_sctp_event( buf, n );
				}
				else
				{
					if( (ret == 1 && n == 0) || n < 0)
					{
						CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "SCTP_SHUTDOWN_EVENT Notified, closing connection");
						close( cliInfo->fd);
						shutdown( cliInfo->fd, 2);
						cliInfo->isActive = 0;
						break;
					}
					
					if( n > 0)
					{
						CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "stream %d, PPID %d.: received-bytes: %d", sinfo.sinfo_stream, ntohl(sinfo.sinfo_ppid), n);
						
						if( cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength > 0)
						{
							PendingBufferLength = cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength;
							memcpy( totbuf, cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, PendingBufferLength);
							memcpy( &totbuf[PendingBufferLength], buf, n);
							iTotalBufferLength = PendingBufferLength + n;
							cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = 0;
						}
						else
						{
							memcpy( totbuf, buf, n);
							iTotalBufferLength = n;
						}
						
						iUsedBufferSize = 0;
						
						while( iUsedBufferSize < iTotalBufferLength)
						{
							//Received Buffer should be at-least greater than diam header
							//as we already read the buffer from network
							if( ( iTotalBufferLength - iUsedBufferSize) > DIAM_BUFFER_SIZE_HEADER_SIZE)
							{
								oDiamRawData = allocateDiamRawData();
								oDiamRawData->Header->len = DIAM_BUFFER_SIZE_HEADER_SIZE;
								memcpy( oDiamRawData->Header->Data, &totbuf[iUsedBufferSize], DIAM_BUFFER_SIZE_HEADER_SIZE);
								
								decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);
								
								//printf("iMessageLength = %d\n", iMessageLength);
								if( iMessageLength > DIAM_BUFFER_SIZE_PER_REQUEST )
								{
									CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Received message-size[%sd] More than application can handle", iMessageLength);
									cliInfo->CloseIt = 1;
									break;
								}
								
								if( ( iTotalBufferLength - iUsedBufferSize) >= iMessageLength )
								{
									memcpy( oDiamRawData->PayLoad->Data, &totbuf[iUsedBufferSize + DIAM_BUFFER_SIZE_HEADER_SIZE], (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE));

									oDiamRawData->iPeerIndex = -1;
									oDiamRawData->iRequestNo = iRequestNo;
									oDiamRawData->iMessageArrivedFrom = 10;
									oDiamRawData->iRouteMessageTo = 2;	
									oDiamRawData->PayLoad->len = (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE);
									oDiamRawData->CliInfo = cliInfo;
									oDiamRawData->sinfo_stream = sinfo.sinfo_stream;
									oDiamRawData->sinfo_assoc_id = sinfo.sinfo_assoc_id;
									memcpy( &oDiamRawData->sinfo, &sinfo, sizeof(struct sctp_sndrcvinfo));

									objStackObjects.TotalMemoryUsage.SocketReadCount++;
									appPostMsg( oDiamRawData);
									
									iRequestNo++;
									iUsedBufferSize += iMessageLength;									
								}
								else
								{
									releaseDiamRawData( oDiamRawData);
									cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
									memcpy( cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[iUsedBufferSize], ( iTotalBufferLength - iUsedBufferSize));
									break;
								}
								
							}
							else
							{
								cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
								memcpy( cliInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[iUsedBufferSize], ( iTotalBufferLength - iUsedBufferSize));
								break;
							}
							
						}
						
						CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "host-client thread iUsedBufferSize[%d] , iTotalBufferLength[%d]", iUsedBufferSize, iTotalBufferLength);
						
					}
				}
			}
				
		}
		
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Waiting Thread appClientThread cliInfo->isActive[%d] Client Info=%p Index=%d fd=%d", cliInfo->isActive, cliInfo, cliInfo->PoolIndex, cliInfo->fd);
		sem_wait( &cliInfo->sem_lock);
		cliInfo->isActive = 1;
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "New Client and Resumed Thread appClientThread cliInfo->isActive[%d] Client Info=%p Index=%d fd=%d", cliInfo->isActive, cliInfo, cliInfo->PoolIndex, cliInfo->fd);
	}
	
	#endif
}

/**
 * App Connected Client Thread
 */
void * appClientThread( void * args)
{
	iClientInfo * cliInfo = (iClientInfo *)args;
	cliInfo->isActive = 1;
	int iRequestNo = 0;
	unsigned int iMessageLength, iBodySize;

	CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Created Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);

	while(1)
	{
		iRequestNo = 0;
		
		while(cliInfo->isActive)
		{
			fd_set rfds;
			struct timeval tv;
			int selectFlag = 0;


			FD_ZERO( &rfds);
			FD_SET( cliInfo->fd, &rfds);
			memset( (char *)&tv, 0, sizeof(tv));

			tv.tv_usec = 3;
			tv.tv_sec = 3;

			selectFlag = select( cliInfo->fd + 1, &rfds, NULL, NULL, &tv);

			
			if(selectFlag < 0 )
			{
				if(cliInfo->isActive == 0)
				{
					break;
				}
				continue;
			}

			if(selectFlag == 0)
			{
				if(cliInfo->isActive == 0)
				{
					break;
				}
			}

			if(selectFlag > 0)
			{
				if(FD_ISSET( cliInfo->fd, &rfds))
				{
					int iReceivedSize = 0;
					int iHeaderSize = 20;

					struct DiamRawData *oDiamRawData = allocateDiamRawData();
					memset( oDiamRawData->Header->Data, 0, DIAM_BUFFER_SIZE_HEADER_SIZE);
					oDiamRawData->Header->len = iHeaderSize;

					iReceivedSize = recv( cliInfo->fd, oDiamRawData->Header->Data, iHeaderSize, 0 );

					if( iReceivedSize <= 0)
					{
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Connection, RecivedSize/Bytes[%d], cliInfo->isActive[%d]", iReceivedSize, cliInfo->isActive);
						closeAndCleanClientSocket(cliInfo);
						break;					
					}
					
					if( iReceivedSize < iHeaderSize)
					{
						int leftOverBytes = iHeaderSize - iReceivedSize;
						
						iReceivedSize = recv( cliInfo->fd, &oDiamRawData->Header->Data[iReceivedSize], leftOverBytes, 0 );
						
						if( leftOverBytes != iReceivedSize)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Connection, HeaderSize[%d] and RecivedSize[%d] Not Matched cliInfo->isActive[%d]", iHeaderSize, iReceivedSize, cliInfo->isActive);
							closeAndCleanClientSocket(cliInfo);
							break;
						}
					}

					

					decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);

					iBodySize = iMessageLength - iHeaderSize;
					memset( oDiamRawData->PayLoad->Data, 0, DIAM_BUFFER_SIZE_PER_REQUEST);
					
					#if HIGH_BUFF
					
						int bOuterLoop = 0;
						int iNRecvBytes = 0;
						iReceivedSize = 0;
						
						while( iNRecvBytes < iBodySize)
						{
							iReceivedSize = recv( cliInfo->fd, &oDiamRawData->PayLoad->Data[iNRecvBytes], (iBodySize - iNRecvBytes), 0 );
							
							if( iReceivedSize > 0)
							{
								iNRecvBytes += iReceivedSize;
							}
							else
							{
								//check error 
								bOuterLoop = 1;
								CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Connection, iBodySize[%d] and RecivedSize[%d] Not Matched cliInfo->isActive[%d]", iBodySize, iNRecvBytes, cliInfo->isActive);
								closeAndCleanClientSocket( cliInfo);	
								break;
							}
						}	
					
						if( bOuterLoop == 1)
						{
							break;
						}
						
					#else
						
						iReceivedSize = recv( cliInfo->fd, oDiamRawData->PayLoad->Data, iBodySize, 0 );

						if( iReceivedSize != iBodySize)
						{
							int leftOverBytes = iBodySize - iReceivedSize;
							iReceivedSize = recv( cliInfo->fd, &oDiamRawData->PayLoad->Data[iReceivedSize], leftOverBytes, 0 );
							
							if( leftOverBytes != iReceivedSize)
							{
								CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Connection, iBodySize[%d] and RecivedSize[%d] Not Matched cliInfo->isActive[%d]", iBodySize, iReceivedSize, cliInfo->isActive);
								closeAndCleanClientSocket(cliInfo);
								break;
							}					
						}
						
					#endif

					oDiamRawData->PayLoad->len = iBodySize;
					oDiamRawData->iRequestNo = iRequestNo;
					oDiamRawData->CliInfo = cliInfo;
					oDiamRawData->iPeerIndex = -1;
					oDiamRawData->iMessageArrivedFrom = 2;
					oDiamRawData->iRouteMessageTo = 1;
					
					cliInfo->ReceivedMessages++;
					objStackObjects.TotalMemoryUsage.SocketReadCount++;

					appPostMsg( oDiamRawData);

					iRequestNo++;
				}
			}
		}

		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Waiting Thread appClientThread cliInfo->isActive[%d] Client Info=%p Index=%d fd=%d", cliInfo->isActive, cliInfo, cliInfo->PoolIndex, cliInfo->fd);
		sem_wait( &cliInfo->sem_lock);
		cliInfo->isActive = 1;
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "New Client and Resumed Thread appClientThread cliInfo->isActive[%d] Client Info=%p Index=%d fd=%d", cliInfo->isActive, cliInfo, cliInfo->PoolIndex, cliInfo->fd);
	}
	
	//pthread_exit( NULL);
	return NULL;
}

typedef struct HostPortInfo
{
	int iPort;
	int IPType; 	//1:v4/2:v6
	char sIPAddress[32];
} iHostPortInfo;


void v1GetiClientInfo( iClientInfo ** cliInfo, int *bLaunchThread)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Total cliInfo Threads=%d", objStackObjects.ClientInfoCount);
	
	pthread_mutex_lock( &objStackObjects.ClientInfoLock );
	int inx = 0;
	
	iClientInfo * lCliInfo = objStackObjects.ClientInfoHead;
	
	while( lCliInfo)
	{
		if( lCliInfo->isActive == 0)
		{
			*cliInfo = lCliInfo;
			*bLaunchThread = 0;
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Re-Using cliInfo and Thread will not be Created %p Index=%d", lCliInfo, lCliInfo->PoolIndex);
			break;
		}
		lCliInfo = lCliInfo->NextClientInfo;
		inx++;
	}
	
	if(!lCliInfo)
	{
		lCliInfo = (iClientInfo *) lib_malloc( sizeof(iClientInfo));
		memset( lCliInfo, 0, sizeof(iClientInfo));
		lCliInfo->PoolIndex = inx;
		sem_init( &lCliInfo->sem_lock, 0, 0);
		lCliInfo->NextClientInfo = NULL;
		
		if(!objStackObjects.ClientInfoHead)
		{
			objStackObjects.ClientInfoHead = objStackObjects.ClientInfoCurrent = lCliInfo;
		}
		else
		{
			objStackObjects.ClientInfoCurrent->NextClientInfo = lCliInfo;
			objStackObjects.ClientInfoCurrent = lCliInfo;
		}
		
		objStackObjects.ClientInfoCount++;
		*bLaunchThread = 1;
		*cliInfo = lCliInfo;
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Created New cliInfo and Thread will be Created %p Index=%d", lCliInfo, lCliInfo->PoolIndex);
	}
	
	pthread_mutex_unlock( &objStackObjects.ClientInfoLock );
}


void v1SctpGetiClientInfo( iClientInfo ** cliInfo, int *bLaunchThread)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Total cliInfo Threads=%d", objStackObjects.SctpClientInfoCount);
	
	pthread_mutex_lock( &objStackObjects.SctpClientInfoLock );
	int inx = 0;
	
	iClientInfo * lCliInfo = objStackObjects.SctpClientInfoHead;
	
	while( lCliInfo)
	{
		if( lCliInfo->isActive == 0)
		{
			*cliInfo = lCliInfo;
			*bLaunchThread = 0;
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Re-Using cliInfo and Thread will not be Created %p Index=%d", lCliInfo, lCliInfo->PoolIndex);
			break;
		}
		lCliInfo = lCliInfo->NextClientInfo;
		inx++;
	}
	
	if(!lCliInfo)
	{
		lCliInfo = (iClientInfo *) lib_malloc( sizeof(iClientInfo));
		memset( lCliInfo, 0, sizeof(iClientInfo));
		lCliInfo->PoolIndex = inx;
		sem_init( &lCliInfo->sem_lock, 0, 0);
		lCliInfo->NextClientInfo = NULL;
		
		if(!objStackObjects.SctpClientInfoHead)
		{
			objStackObjects.SctpClientInfoHead = objStackObjects.SctpClientInfoCurrent = lCliInfo;
		}
		else
		{
			objStackObjects.SctpClientInfoCurrent->NextClientInfo = lCliInfo;
			objStackObjects.SctpClientInfoCurrent = lCliInfo;
		}
		
		objStackObjects.SctpClientInfoCount++;
		*bLaunchThread = 1;
		*cliInfo = lCliInfo;
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Created New cliInfo and Thread will be Created %p Index=%d", lCliInfo, lCliInfo->PoolIndex);
	}
	
	pthread_mutex_unlock( &objStackObjects.SctpClientInfoLock );
}


//10026
void * appHostThread_IPv4_MultiPort( void *args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iHostPortInfo * oHostPortInfo = (iHostPortInfo *)args;
	
	if( !oHostPortInfo) return NULL;
	
	int iPort = oHostPortInfo->iPort;
	int serverSocket, newSocket, clilen;
	struct sockaddr_in serverAddr, cli_addr;
	int bLaunchThread = 0;	
	
	serverSocket = socket(PF_INET, SOCK_STREAM, 0);

	if(serverSocket == -1)
	{
		printf("Host Server Socket Creation Failed (Host Process)\n");
		exit(1);
	}
	
	int yes = 1;

	if( setsockopt( serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
	{
		printf("setsockopt SO_REUSEADDR failed\n");
		exit(1);
	}

	memset( &(serverAddr.sin_zero), '\0', 8);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(iPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if( bind( serverSocket, (struct sockaddr *) &serverAddr, sizeof(struct sockaddr)) != 0)
	{
		printf("Server Bind Failed\n");
		exit(1);
	}

	if( listen( serverSocket, 5) == 0)
	{
		while(1)
		{
			clilen = sizeof(cli_addr);
			newSocket = accept( serverSocket, (struct sockaddr *) &cli_addr, (socklen_t *) &clilen);

			if( newSocket != -1)
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Client Connected With SocketId=%d", newSocket);
				
				iClientInfo * cliInfo = NULL;
				//lib_malloc(sizeof(iClientInfo));
				v1GetiClientInfo( &cliInfo, &bLaunchThread);
				
				memcpy( &cliInfo->clientAddr, &cli_addr, clilen);
				cliInfo->fd = newSocket;
				cliInfo->RoutingTableIndex = -1;
				cliInfo->RoutingError = 0;
				cliInfo->ReceivedMessages = 0;
				cliInfo->SentMessages = 0;				
				cliInfo->TransportType = 0;
				
				if( bLaunchThread == 1)
				{	
					int iRet;
					pthread_t s_pthread_id;

					pthread_attr_t attr;
					pthread_attr_init( &attr);
					pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

					iRet = pthread_create( &s_pthread_id, &attr, appClientThread, (void *)cliInfo);

					if(iRet)
					{
						perror("Error: ");
						printf("unable to create Thread for New Connection \n");
						exit(-1);
					}
					
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Created Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);
				}
				else
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Resuming Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);
					sem_post( &cliInfo->sem_lock);
				}
			}

		}
	}

	return NULL;	
}

int core_pthread_create( pthread_t *thread, void *(*start_routine) (void *), void *arg)
{
	//pthread_t s_pthread_id;

	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);	
	
	return pthread_create( thread, &attr, start_routine, arg);
}

int core_pthread_create2( void *(*start_routine) (void *), void *arg)
{
	pthread_t s_pthread_id;

	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);	
	
	return pthread_create( &s_pthread_id, &attr, start_routine, arg);
}


void allocateClientInfoW( iClientInfo ** dataPtr);


void * appHostSctpThread( void * args)
{
	#if SCTP_SUPPORT
	
	int sd = -1, on = 1, sdconn, fd = 0;
	//struct sockaddr_in6 serveraddr, clientaddr;
	struct sockaddr_in serveraddr, clientaddr;
	int addrlen = sizeof(clientaddr);
	char str[INET6_ADDRSTRLEN];

	struct sctp_initmsg initmsg;
	struct sctp_event_subscribe events;
	memset( &events, 0, sizeof (events));
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_send_failure_event = 1;
	events.sctp_address_event = 1;
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;	
	int i = 0;

	if ((sd = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0) 
	//if ((sd = socket( PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) < 0) 	
	{
		perror("socket() failed AF_INET");
		exit(0);
	}
			
	if ( setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "setsockopt(SO_REUSEADDR) failed for Host-Server Port : %d", objStackConfig.Port);
		exit(0);
	}
	
	memset( &serveraddr, 0, sizeof(serveraddr));
	//check support of IPv6
	/*
	serveraddr.sin6_family = AF_INET6;
	serveraddr.sin6_port   = htons( objStackConfig.Port );
	serveraddr.sin6_addr   = in6addr_any;
	*/
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons( objStackConfig.Port);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);	
  
	if( objStackConfig.MultiHome == 0 || objStackConfig.MultiHomeAndRequiredBind == 1)
	{	
		if ( bind( sd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
		{
			perror("sctp bind() failed");
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "sctp bind() failed for Host-Server Port : %d", objStackConfig.Port);
			exit(0);
		}
	}
	
	if( objStackConfig.MultiHome == 1)
	{
		int is = 0;
		struct sockaddr_in serveraddr1;
		
		for( is = 0; is < objStackConfig.MultiHomeIpCount; is++)
		{
			memset( &serveraddr1, 0, sizeof(struct sockaddr_in));
			
			serveraddr1.sin_family = AF_INET;
			serveraddr1.sin_port = htons( objStackConfig.Port);
			
			if( is == 0)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP, is, sd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP);
			}
			else if( is == 1)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP2, is, sd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP2);
			}
			else if( is == 2)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP3, is, sd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP3);
			}
			else if( is == 3)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP4, is, sd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP4);
			}
			else if( is == 4)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP5, is, sd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP5);
			}
			
			int ierror = sctp_bindx( sd, (struct sockaddr*)&serveraddr1, 1, SCTP_BINDX_ADD_ADDR);
			printf( "ierror=%d EBADF=%d ENOTSOCK=%d EFAULT=%d EINVAL=%d EACCES=%d\n", ierror, EBADF, ENOTSOCK, EFAULT, EINVAL, EACCES);
			
			if ( ierror < 0) 
			{
				perror("[ error with sctp_bindx ]");
			}
		}
	}
	
	
	memset (&initmsg, 0, sizeof (initmsg));
	initmsg.sinit_num_ostreams = 5;
	initmsg.sinit_max_instreams = 5;
	initmsg.sinit_max_attempts = 4;
	
	if( setsockopt ( sd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof (initmsg)) < 0 )
	{
		perror("setsockopt( IPPROTO_SCTP, SCTP_INITMSG) failed");
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "setsockopt( IPPROTO_SCTP, SCTP_INITMSG) failed for Host-Server Port : %d", objStackConfig.Port);
		exit(0);				
	}

	if (listen( sd, 10) < 0)
	{
		perror("listen() failed");
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "listen() failed for Host-Server Port : %d", objStackConfig.Port);
		exit(0);
	}
	
	iClientInfo * cliInfo = NULL;
	int bLaunchThread = 0;
	
	while(1)
	{
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "waiting for new incoming connection on FD=%d for sctp" , sd);	
		sdconn = accept( sd, NULL, NULL);
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "accepted client FD=%d for sctp" , sd);
		
		if( sdconn > 0)
		{
			getpeername( sdconn, (struct sockaddr *)&clientaddr, (socklen_t *)&addrlen);
			
			if( inet_ntop( AF_INET, &clientaddr.sin_addr, str, sizeof(str))) 
			{
				if ( setsockopt( sdconn, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events)) < 0) 
				{
					printf("setsockopt SCTP_EVENTS\n");
					CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "setsockopt SCTP_EVENTS FD=%d for new sctp connection %d" , sd, sdconn);
					exit(1);
				}
				
				v1SctpGetiClientInfo( &cliInfo, &bLaunchThread);
				
				memcpy( &cliInfo->clientAddr, &clientaddr, addrlen);
				cliInfo->fd = sdconn;
				cliInfo->CloseIt = 0;
				cliInfo->isActive = 1;
				cliInfo->RoutingTableIndex = -1;
				cliInfo->RoutingError = 0;
				cliInfo->ReceivedMessages = 0;
				cliInfo->SentMessages = 0;	
				//cliInfo->HostConfig = (void *)oHostConfigData;
				cliInfo->TransportType = 1;
				
				if( bLaunchThread == 1)
				{
					int iRet;
					pthread_t s_pthread_id;

					pthread_attr_t attr;
					pthread_attr_init( &attr);
					pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

					iRet = pthread_create( &s_pthread_id, &attr, appSctpClientThread, (void *)cliInfo);

					if(iRet)
					{
						perror("Error: ");
						printf("unable to create Thread for New Connection \n");
						exit(-1);
					}
					
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Created Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);
				}
				else
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Resuming Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);
					sem_post( &cliInfo->sem_lock);
				}
						
			}
		}
	}
	
	#endif
}

/**
 * App Main Socket Listen Thread, Hosted
 */
void * appHostThread(void *args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	int iPort = objStackConfig.Port;
	int serverSocket, newSocket, clilen;
	struct sockaddr_in serverAddr, cli_addr;
	int bLaunchThread = 0;
	
	serverSocket = socket(PF_INET, SOCK_STREAM, 0);

	if(serverSocket == -1)
	{
		printf("Server Socket Creation Failed (Host Process)\n");
		exit(1);
	}

	int yes = 1;

	if( setsockopt( serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
	{
		printf("setsockopt SO_REUSEADDR failed\n");
		exit(1);
	}

	memset( &(serverAddr.sin_zero), '\0', 8);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(iPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if( bind( serverSocket, (struct sockaddr *) &serverAddr, sizeof(struct sockaddr)) != 0)
	{
		printf("Server Bind Failed\n");
		exit(1);
	}

	if( listen( serverSocket, 5) == 0)
	{
		while(1)
		{
			clilen = sizeof(cli_addr);
			newSocket = accept( serverSocket, (struct sockaddr *) &cli_addr, (socklen_t *)&clilen);

			if( newSocket != -1)
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Client Connected With SocketId=%d", newSocket);
				
				//iClientInfo * cliInfo = lib_malloc(sizeof(iClientInfo));
				iClientInfo * cliInfo = NULL;
				//lib_malloc(sizeof(iClientInfo));
				v1GetiClientInfo( &cliInfo, &bLaunchThread);
				
				memcpy( &cliInfo->clientAddr, &cli_addr, clilen);
				cliInfo->fd = newSocket;
				cliInfo->RoutingTableIndex = -1;
				cliInfo->RoutingError = 0;
				cliInfo->ReceivedMessages = 0;
				cliInfo->SentMessages = 0;				
				cliInfo->TransportType = 0;

				if( bLaunchThread == 1)
				{	
					int iRet;
					pthread_t s_pthread_id;

					pthread_attr_t attr;
					pthread_attr_init( &attr);
					pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

					iRet = pthread_create( &s_pthread_id, &attr, appClientThread, (void *)cliInfo);

					if(iRet)
					{
						perror("Error: ");
						printf("unable to create Thread for New Connection \n");
						exit(-1);
					}
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Created Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);
				}
				else
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Resuming Thread for Client Info %p Index=%d fd=%d", cliInfo, cliInfo->PoolIndex, cliInfo->fd);
					sem_post( &cliInfo->sem_lock);
				}
			}

		}
	}

	return NULL;
}




void * appDecodeThread( void* argsThreadInfo)
{
	iWorkerThread *objWorkerThread = (iWorkerThread*)argsThreadInfo;

	while(1)
	{
		if(sem_wait( &objWorkerThread->sem_lock)  == 0)
		{
			appDecodeDiamMessage(objWorkerThread->Data);

			struct ThreadPool *Parent = (struct ThreadPool *)objWorkerThread->Parent;


			pthread_mutex_lock(&Parent->aquireLock);

			objStackObjects.TotalMemoryUsage.DecodeThreadReleaseCount++;
			Parent->FreeCount++;
			objWorkerThread->isFree = 1;

			pthread_mutex_unlock(&Parent->aquireLock);
		}
	}

	return NULL;
}

void * appDecodeDequeeThread( void* argsThreadInfo)
{
	//iWorkerThread *objWorkerThread = (iWorkerThread*)argsThreadInfo;

	//int z = 1;
	void *Data = NULL;
	
	while(1)
	{
		//if( z >= 50) z = 1;
		
		
		Data = (struct DiamRawData*)Dequee( &objStackObjects.DecodeMessageQueue);

		//if( Data != NULL)
		if(Data)	
		{
			//z = 1;
			appDecodeDiamMessage( Data);
		}
		else
		{
			//usleep( z * 500);
			//z++;
		}
		
		Data = NULL;
	}

	return NULL;	
}


void * appRoutingDequeeThread( void* argsThreadInfo)
{
	//iWorkerThread *objWorkerThread = (iWorkerThread*)argsThreadInfo;

	//int z = 1;
	void *Data = NULL;
	
	while(1)
	{
		//if( z >= 50) z = 1;
		
		Data = (struct DiamRouteMessage*)Dequee( &objStackObjects.RoutingMessageQueue);

		//if( Data != NULL)
		if(Data)	
		{
			//z = 1;
			appRouteQueuedMessage( Data);
		}
		else
		{
			//usleep( z * 500);
			//z++;
		}
		
		Data = NULL;
	}

	return NULL;	
}


int appConnectToSctpPeer( int * iPeerThreadIndex)
{
	#if SCTP_SUPPORT
	
	objStackConfig.Peers[*iPeerThreadIndex].isConnected = 0;
	objStackConfig.Peers[*iPeerThreadIndex].isCEASuccess = 0;

	int fd = 0, ret = 0;
	struct sctp_initmsg   initmsg;
    struct sctp_event_subscribe events;	

	if ((fd = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1) 
	//if ((fd = socket( PF_INET, SOCK_SEQPACKET, IPPROTO_SCTP)) == -1) 	
	{
		printf("ipv4 socket creation failed for sctp peer-connection for IP=%s Port[%d]\n", objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "ipv4 socket creation failed for sctp peer-connection for IP=%s Port[%d]\n", objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
		return -1;
	}
	
	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "socket creation for sctp peer-connection for IP=%s Port[%d] with fd[%d]\n", 
		objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort, fd);
	
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_send_failure_event = 1;
	events.sctp_address_event = 1;
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;	
	ret = setsockopt( fd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events));
	
	if (ret < 0) 
	{
		printf("set socket options SCTP_EVENTS failed for sctp peer-connection for IP=%s Port[%d]\n", objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
		return -1;
	}
	
	memset(&initmsg, 0, sizeof(struct sctp_initmsg));
	initmsg.sinit_num_ostreams = 5;
	initmsg.sinit_max_instreams = 5;
	initmsg.sinit_max_attempts = 4;
	ret = setsockopt( fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg));

	if (ret < 0) 
	{
		printf("set socket options SCTP_INITMSG failed for sctp peer-connection for IP=%s Port[%d]\n", objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
		return -1;
	}
	
	
	//---------------------------------------------------------------------------------------------------------
	// Client Binding
	if( objStackConfig.MultiHome == 1)
	{
		int is = 0;
		struct sockaddr_in serveraddr1;
		int ierror;
		
		for( is = 0; is < objStackConfig.MultiHomeIpCount; is++)
		{
			memset( &serveraddr1, 0, sizeof(struct sockaddr_in));
			
			serveraddr1.sin_family = AF_INET;
			//serveraddr1.sin_port = htons( objStackConfig.Port);
			
			if( is == 0)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP, is, fd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP);
			}
			else if( is == 1)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP2, is, fd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP2);
			}
			else if( is == 2)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP3, is, fd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP3);
			}
			else if( is == 3)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP4, is, fd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP4);
			}
			else if( is == 4)
			{
				printf("sctp_bindx with ipaddress=%s index = %d sd=%d\n", objStackConfig.IP5, is, fd);
				serveraddr1.sin_addr.s_addr = inet_addr( objStackConfig.IP5);
			}
			
			ierror = sctp_bindx( fd, (struct sockaddr*)&serveraddr1, 1, SCTP_BINDX_ADD_ADDR);
			printf( "client_sctp_bindx ierror=%d EBADF=%d ENOTSOCK=%d EFAULT=%d EINVAL=%d EACCES=%d\n", ierror, EBADF, ENOTSOCK, EFAULT, EINVAL, EACCES);
			
			if ( ierror < 0) 
			{
				perror("[ error with sctp_bindx ]");
			}
		}
	}	
	
	//---------------------------------------------------------------------------------------------------------
	
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr( objStackConfig.Peers[*iPeerThreadIndex].PeerIP);
	addr.sin_port = htons( objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
	
	sctp_assoc_t sctp_assId = ((*iPeerThreadIndex) + 1);
	
	//if ( connect( fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1) 
	if ( sctp_connectx( fd, (struct sockaddr *)&addr, 1, &sctp_assId) == -1)
	{
		//printf("connection to sctp peer-server failed for IP=%s Port[%d]\n", objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "connection to sctp peer-server failed for IP=%s Port[%d]", objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
		return -1;
	}
	else
	{
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Connected Successfully to sctp_connectx Peer[%d] fd[%d]", *iPeerThreadIndex, fd);
		objStackConfig.Peers[*iPeerThreadIndex].fd = fd;
		objStackConfig.Peers[*iPeerThreadIndex].isConnected = 1;
	}

	return 1;
	
	#endif
	
	return -1;
}

int appConnectToPeer( int * iPeerThreadIndex)
{
	objStackConfig.Peers[*iPeerThreadIndex].isConnected = 0;
	objStackConfig.Peers[*iPeerThreadIndex].isCEASuccess = 0;

	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "appConnectToPeer[%d] IP[%s] PORT[%d]", *iPeerThreadIndex, objStackConfig.Peers[*iPeerThreadIndex].PeerIP, objStackConfig.Peers[*iPeerThreadIndex].PeerPort);
	
	int sockfd;

	struct sockaddr_in their_paddr;

	their_paddr.sin_family = PF_INET;
	their_paddr.sin_addr.s_addr = inet_addr( objStackConfig.Peers[*iPeerThreadIndex].PeerIP );
	their_paddr.sin_port = htons( objStackConfig.Peers[*iPeerThreadIndex].PeerPort);

	memset(&(their_paddr.sin_zero), '\0', 8);

	if ((sockfd = socket( PF_INET, SOCK_STREAM, 0)) == -1)
	{
	   	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Socket creation failed for Peer[%d]", *iPeerThreadIndex);
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&their_paddr,sizeof(struct sockaddr)) == -1)
	{
		close( sockfd);
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Connect failed for Peer[%d]", *iPeerThreadIndex);
		return -1;
	}

	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Connected Successfully to Peer[%d] fd[%d]", *iPeerThreadIndex, sockfd);
	objStackConfig.Peers[*iPeerThreadIndex].fd = sockfd;
	objStackConfig.Peers[*iPeerThreadIndex].isConnected = 1;
	return 0;
}

int appConnectToClient( int * iClientThreadIndex)
{
	objStackConfig.Clients[*iClientThreadIndex].isConnected = 0;
	objStackConfig.Clients[*iClientThreadIndex].isCEASuccess = 0;

	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "appConnectToClient[%d] IP[%s] PORT[%d]", *iClientThreadIndex, objStackConfig.Clients[*iClientThreadIndex].ClientIP, objStackConfig.Clients[*iClientThreadIndex].ClientPort);
	
	int sockfd;

	struct sockaddr_in their_paddr;

	their_paddr.sin_family = PF_INET;
	their_paddr.sin_addr.s_addr = inet_addr( objStackConfig.Clients[*iClientThreadIndex].ClientIP );
	their_paddr.sin_port = htons( objStackConfig.Clients[*iClientThreadIndex].ClientPort);

	memset(&(their_paddr.sin_zero), '\0', 8);

	if ((sockfd = socket( PF_INET, SOCK_STREAM, 0)) == -1)
	{
	   	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Socket creation failed for Clients[%d]", *iClientThreadIndex);
		return -1;
	}

	if (connect(sockfd, (struct sockaddr *)&their_paddr,sizeof(struct sockaddr)) == -1)
	{
		close( sockfd);
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Connect failed for Clients[%d]", *iClientThreadIndex);
		return -1;
	}

	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Connected Successfully to Clients[%d] fd[%d]", *iClientThreadIndex, sockfd);
	objStackConfig.Clients[*iClientThreadIndex].fd = sockfd;
	objStackConfig.Clients[*iClientThreadIndex].isConnected = 1;
	return 0;	
}




int appSCTPSendMsg( int *fd, struct DiamMessage * dmMsg)
{
	#if SCTP_SUPPORT
	
	char buffer[2048];
	memset( &buffer, 0, sizeof(buffer));

	encodeDiamMessage( dmMsg, buffer );
	//int iLength = dmMsg->Length;

	
	//int iSentBytes = send( *fd, &buffer , dmMsg->Length, 0 );
	int iSentBytes = 0;
	
	if( (dmMsg->sinfo_stream >= 0 && dmMsg->sinfo_stream < 64) && objStackConfig.SctpEnableStreamInfo == 1)
	{
		struct sctp_sndrcvinfo sinfo;
		memset( &sinfo, 0, sizeof( struct sctp_sndrcvinfo));
		
		//sinfo.sinfo_ppid = htonl(46);
		sinfo.sinfo_stream = dmMsg->sinfo_stream;
		sinfo.sinfo_flags = 0;
		sinfo.sinfo_assoc_id = dmMsg->sinfo_assoc_id;
		//iSentBytes = sctp_sendmsg( *fd, &buffer, dmMsg->Length, NULL, 0, 0, 0, 0, 0, 0);
		
		iSentBytes = sctp_send( *fd, &buffer, dmMsg->Length, &sinfo, 0);
		
		//iSentBytes = sctp_send( *fd, &buffer, dmMsg->Length, &dmMsg->sinfo, 0);
		//iSentBytes = sctp_sendmsg( *fd, &buffer, dmMsg->Length, NULL, 0, 0, 0, dmMsg->sinfo_stream, 0, 0);
	}
	else
	{
		iSentBytes = sctp_sendmsg( *fd, &buffer, dmMsg->Length, NULL, 0, 0, 0, 0, 0, 0);
	}
	
	
	if( iSentBytes == dmMsg->Length)
	{
		objStackObjects.TotalMemoryUsage.SocketWriteCount++;
	}				

	releaseMessage( dmMsg);
	return iSentBytes;
	#else
	return 0;	
	#endif
}

int appSendMsg( int *fd, struct DiamMessage * dmMsg)
{
	char buffer[2048];
	memset( &buffer, 0, sizeof(buffer));

	encodeDiamMessage( dmMsg, buffer );
	//int iLength = dmMsg->Length;

	if( objStackConfig.CheckSocketBeforeSend == 1)
	{
		int r;
		r = fcntl( (*fd), F_GETFL);
		
		if (r == -1)
		{
			releaseMessage( dmMsg);
			return -1;
		}
		else if( r & O_RDONLY)
		{
			releaseMessage( dmMsg);
			return -1;			
		}
	}
	
	int iSentBytes = send( *fd, &buffer , dmMsg->Length, 0 );

	if( iSentBytes == dmMsg->Length)
	{
		objStackObjects.TotalMemoryUsage.SocketWriteCount++;
	}				

	releaseMessage( dmMsg);
	return iSentBytes;
}

int appSendMsgToClientOrPeer(struct DiamMessage* dmMessage, iClientInfo * cliInfo, int iPeerIndex)
{
	//printf("%s cliInfo[%p] iPeerIndex[%d] oApplicationServer[%p]\n", __FUNCTION__, cliInfo, iPeerIndex, oApplicationServer);
	
	if(iPeerIndex >= 0)
	{
		int bSuccess = 0;
		
		if( objStackConfig.Peers[iPeerIndex].TransportType == 1)
		{	
			bSuccess = appSCTPSendMsg( &objStackConfig.Peers[iPeerIndex].fd, dmMessage );
		}
		else
		{
			bSuccess = appSendMsg( &objStackConfig.Peers[iPeerIndex].fd, dmMessage );
		}
		
		
		if(bSuccess < 0 && errno == EPIPE)
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Send CEA failed for peer, closing connection iPeerIndex[%d]", iPeerIndex);
			closePeerConnection( &iPeerIndex);
			return 0;
		}

		return 1;
	}
	//else if(cliInfo != NULL)
	else if(cliInfo)	
	{
		cliInfo->SentMessages++;
		int bSuccess = 0;
		//printf("->1\n");
		
		if( oApplicationServer)
		{
			//printf("->2\n");
			if( cliInfo->TransportType == 1)
			{
				//SCTP
				//printf("->3\n");
				bSuccess = appSCTPSendMsg( &cliInfo->fd, dmMessage );
				//printf("oApplicationServer[%p] cliInfo->fd[%d] dmMessage[%p] bSuccess[%d]\n", oApplicationServer, cliInfo->fd, dmMessage, bSuccess);
				
				if(bSuccess < 0 && errno == EPIPE)
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Send CEA failed for Client, closing connection[%d]", cliInfo->fd);
					closeAndCleanClientSocket( cliInfo);
				}
			}
			else if( cliInfo->TransportType == 0)
			{
				//TCP
				bSuccess = appSendMsg( &cliInfo->fd, dmMessage );
				
				if(bSuccess < 0 && errno == EPIPE)
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Send CEA failed for Client, closing connection[%d]", cliInfo->fd);
					closeAndCleanClientSocket( cliInfo);
				}				
			}
		}
		else
		{
			//printf("%s cliInfo->TransportType[%d]\n", __FUNCTION__, cliInfo->TransportType);
			
			if( cliInfo->TransportType == 1)
			{	
				bSuccess = appSCTPSendMsg( &cliInfo->fd, dmMessage );
			}
			else
			{
				bSuccess = appSendMsg( &cliInfo->fd, dmMessage );
			}
				
			if(bSuccess < 0 && errno == EPIPE)
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Send CEA failed for Client, closing connection[%d]", cliInfo->fd);
				closeAndCleanClientSocket( cliInfo);
			}
		}
		return bSuccess;
	}
	else
	{
		return -1;
	}
}

void closeClientConnection(int * iClientThreadIndex)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Client Connection ClientId[%d]", *iClientThreadIndex);		
	
	if( objStackConfig.Clients[*iClientThreadIndex].isConnected == 1)
	{	
		close(objStackConfig.Clients[*iClientThreadIndex].fd);
		shutdown(objStackConfig.Clients[*iClientThreadIndex].fd, 2);
		objStackConfig.Clients[*iClientThreadIndex].fd = -1;
	
		objStackConfig.Clients[*iClientThreadIndex].isConnected = 0;
		objStackConfig.Clients[*iClientThreadIndex].isCEASuccess = 0;
	}
}


void closePeerConnection(int * iPeerThreadIndex)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Peer Connection PeerId[%d]", *iPeerThreadIndex);		
	
	if( objStackConfig.Peers[*iPeerThreadIndex].isConnected == 1)
	{	
		close(objStackConfig.Peers[*iPeerThreadIndex].fd);
		shutdown(objStackConfig.Peers[*iPeerThreadIndex].fd, 2);
		objStackConfig.Peers[*iPeerThreadIndex].fd = -1;
	
		objStackConfig.Peers[*iPeerThreadIndex].isConnected = 0;
		objStackConfig.Peers[*iPeerThreadIndex].isCEASuccess = 0;
	}
}

int sendCERToPeer(int iPeerThreadIndex)
{
	struct DiamMessage * dmCER = allocateMessage();
	createCER( dmCER, objStackConfig.Peers[iPeerThreadIndex].AppId, iPeerThreadIndex);

	int iSentBytes = 0;
	
	if( objStackConfig.Peers[iPeerThreadIndex].TransportType == 1)
	{	
		iSentBytes = appSCTPSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmCER);
	}
	else
	{
		iSentBytes = appSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmCER);
	}
	
	if( iSentBytes < 0 && errno == EPIPE)
	{
		closePeerConnection( &iPeerThreadIndex);
	}
	
	return 0;
}

int sendAnswer(struct DiamMessage *oDiamRequestMessage, struct DiamMessage *oDiamRequestAnswer)
{
	//if( oDiamRequestMessage->ptrClientInfo != NULL)
	if(oDiamRequestMessage->ptrClientInfo)
	{
		int iSentBytes = 0;
		
		if( oDiamRequestMessage->ptrClientInfo->TransportType == 1)
		{	
			iSentBytes = appSCTPSendMsg( &oDiamRequestMessage->ptrClientInfo->fd, oDiamRequestAnswer);
		}
		else
		{
			iSentBytes = appSendMsg( &oDiamRequestMessage->ptrClientInfo->fd, oDiamRequestAnswer);
		}
		
		
		//should release by user application
		//releaseMessage( oDiamRequestMessage);

		if( iSentBytes < 0 && errno == EPIPE)
		{
			closeAndCleanClientSocket( oDiamRequestMessage->ptrClientInfo);
			return 0;
		}
		
		return 1;		
	}
	
	return 0;
}


int sendMessageToDRA( struct DiamMessage * oDiamMessage, int updateHbHId)
{
	if( updateHbHId == 1)
	{	
		pthread_mutex_lock( &objStackConfig.SessionIdLock);
		
		if( objStackConfig.HBHId <= 0)
		{
			objStackConfig.HBHId = 1000;
		}
		
		oDiamMessage->HBHId = objStackConfig.HBHId;
		objStackConfig.HBHId++;
		
		if( objStackConfig.HBHId > 4294967000)
		{
			objStackConfig.HBHId = 1000;
		}
		
		pthread_mutex_unlock( &objStackConfig.SessionIdLock);
	}
	
	if( oDiamMessage->ptrClientInfo)
	{
		int iSentBytes = 0;
		
		if( oDiamMessage->ptrClientInfo->TransportType == 1)
		{	
			iSentBytes = appSCTPSendMsg( &oDiamMessage->ptrClientInfo->fd, oDiamMessage);
		}
		else
		{
			iSentBytes = appSendMsg( &oDiamMessage->ptrClientInfo->fd, oDiamMessage);
		}
		
		if( iSentBytes < 0 && errno == EPIPE)
		{
			closeAndCleanClientSocket( oDiamMessage->ptrClientInfo);
			return 0;
		}
		
		return 1;		
	}
	
	return 0;
}

int sendMessageToPeer(struct DiamMessage *oDiamMessage, int iPeerThreadIndex)
{
	return appSendMsgToClientOrPeer( oDiamMessage, NULL, iPeerThreadIndex);
}

int isPeerReady( int iPeerThreadIndex)
{
	if( iPeerThreadIndex < objStackConfig.NoOfPeers )
	{
		if(objStackConfig.Peers[iPeerThreadIndex].isConnected == 0)
		{
			return 2;
		}

		if(objStackConfig.Peers[iPeerThreadIndex].isCEASuccess == 0 && objStackConfig.Peers[iPeerThreadIndex].isConnected == 1)
		{
			return 3;
		}

		if(objStackConfig.Peers[iPeerThreadIndex].isCEASuccess == 1 && objStackConfig.Peers[iPeerThreadIndex].isConnected == 1)
		{
			return 1;
		}

		return 0;
	}
	else
	{
		return -1;
	}
}

void * appStartConfigThread(void *args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Started Config Thread");

	int iPort = objStackConfig.ConfigPort;
	int serverSocket, newSocket, clilen;
	struct sockaddr_in serverAddr, cli_addr;
	
	serverSocket = socket(PF_INET, SOCK_STREAM, 0);

	if(serverSocket == -1)
	{
		printf("Server Socket Creation Failed (Config Port)\n");
		exit(1);
	}
	
	int yes = 1;

	if( setsockopt( serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
	{
		printf("setsockopt SO_REUSEADDR failed for Config Port\n");
		exit(1);
	}	
	
	memset( &(serverAddr.sin_zero), '\0', 8);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(iPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	
	if( bind( serverSocket, (struct sockaddr *) &serverAddr, sizeof(struct sockaddr)) != 0)
	{
		printf("Server Bind Failed\n");
		exit(1);
	}
	
	if( listen( serverSocket, 5) == 0)
	{
		while(1)
		{
			clilen = sizeof(cli_addr);
			newSocket = accept( serverSocket, (struct sockaddr *) &cli_addr, (socklen_t *)&clilen);
			
			if( newSocket != -1)
			{
				iClientInfo * cliInfo = lib_malloc(sizeof(iClientInfo));

				memcpy( &cliInfo->clientAddr, &cli_addr, clilen);
				cliInfo->fd = newSocket;
				
				int iRet;
				pthread_t s_pthread_id;

				pthread_attr_t attr;
				pthread_attr_init( &attr);
				pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

				iRet = pthread_create( &s_pthread_id, &attr, appConfigThread, (void *)cliInfo);

				if(iRet)
				{
					perror("Error: ");
					printf("unable to create Thread for New Connection for appConfigThread \n");
					exit(-1);
				}
								
			}			
		}	
	}	
		
	
	return NULL;
}

typedef struct PeerClientInfo
{
	int iPeerThreadIndex;
	int iClientInfoId;
	
} iPeerClientInfo;


void * appStartPeerClientThread(void *args)
{
	iPeerClientInfo * oPeerClientInfo = (iPeerClientInfo *) (intptr_t) args;	
	
	printf("%s iPeerThreadIndex=%d iClientInfoId=%d\n", __FUNCTION__, oPeerClientInfo->iPeerThreadIndex, oPeerClientInfo->iClientInfoId );
	
	return NULL;
}


void * appStartSctpPeerThread( void * args)
{
	#if SCTP_SUPPORT
	
	int iPeerThreadIndex = (int) (intptr_t) args;
	int is = 0;
	int iSts;
	unsigned int iMessageLength, iBodySize;
	
	struct DiamMessage * dmCER = NULL;
	struct DiamMessage * dmDWR = NULL;
	struct DiamRawData * oDiamRawData = NULL;
	
	int iWaitTime = 3;
	int iRequestNo = 0;
	struct pollfd fds;
	char buf[5000];
	int n = 0, flags = 0, ret;
	struct sctp_sndrcvinfo sinfo = {0};
	
	iPeerConfigDataProxy lvPeerConfigDataProxy;
	memset( &lvPeerConfigDataProxy, 0, sizeof(iPeerConfigDataProxy));
	
	char totbuf[10000];
	int iTotalBufferLength = 0;
	int PendingBufferLength = 0;
	int iUsedBufferSize = 0;

	while(1)
	{
		if(objStackConfig.Peers[iPeerThreadIndex].isCEASuccess == -5)
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Exiting Peer Thread, App does not support Configured Interface[%d]", objStackConfig.Peers[iPeerThreadIndex].AppId);
			break;
		}
		
		iSts = appConnectToSctpPeer( &iPeerThreadIndex);
		
		if( iSts < 0)
		{
			for( is = 0; is < objStackConfig.ReConnectSeconds; is++)
			{
				usleep( 999999);
			}	
		}

		if(objStackConfig.Peers[iPeerThreadIndex].isConnected == 1)
		{
			dmCER = allocateMessage();
			createCER( dmCER, objStackConfig.Peers[iPeerThreadIndex].AppId, iPeerThreadIndex);
			
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd, objStackConfig.Peers[iPeerThreadIndex].PeerIP, objStackConfig.Peers[iPeerThreadIndex].PeerPort);

			int bSuccess = appSCTPSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmCER);
			
			if( bSuccess < 0 && errno == EPIPE)
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd);
				closePeerConnection( &iPeerThreadIndex);
			}
		}
		
		objStackConfig.Peers[iPeerThreadIndex].iIdleTime = 0;
		objStackConfig.Peers[iPeerThreadIndex].iDWRCount = 0;
		fds.fd     = objStackConfig.Peers[iPeerThreadIndex].fd;
		fds.events = POLLIN;

		memset( &lvPeerConfigDataProxy, 0, sizeof(iPeerConfigDataProxy));
		
		while( objStackConfig.Peers[iPeerThreadIndex].isConnected == 1)
		{
			ret = poll( &fds, 1, 1000);
			
			if( ret == 0)
			{
				objStackConfig.Peers[iPeerThreadIndex].iIdleTime += 1;
				
				if( objStackConfig.Peers[iPeerThreadIndex].iIdleTime >= objStackConfig.WatchDogRequestInterval )
				{
					if( objStackConfig.Peers[iPeerThreadIndex].isCEASuccess == 0)
					{
						dmCER = allocateMessage();
						createCER( dmCER, objStackConfig.Peers[iPeerThreadIndex].AppId, iPeerThreadIndex);
			
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd, objStackConfig.Peers[iPeerThreadIndex].PeerIP, objStackConfig.Peers[iPeerThreadIndex].PeerPort);

						int bSuccess = appSCTPSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmCER);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd);
							closePeerConnection( &iPeerThreadIndex);
							continue;
						}						
					}
					else
					{
						if( objStackConfig.Peers[iPeerThreadIndex].iDWRCount > 1)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Peer[%d] SockFd[%d], Connection, DWA Not Received Pending Count(%d)", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd, objStackConfig.Peers[iPeerThreadIndex].iDWRCount);
							objStackConfig.Peers[iPeerThreadIndex].iDWRCount = 0;
							closePeerConnection( &iPeerThreadIndex);
							continue;							
						}
						
						dmDWR = allocateMessage();
						createWatchDogRequest( dmDWR);

						int bSuccess = appSCTPSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmDWR);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending DWR Failed For Peer[%d] SockFd[%d] bSuccess=%d errno=%d (%s)", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd, bSuccess, errno, strerror( errno ));
							closePeerConnection( &iPeerThreadIndex);
							continue;
						}
						
						objStackConfig.Peers[iPeerThreadIndex].iDWRCount++;
					}
					
					objStackConfig.Peers[iPeerThreadIndex].iIdleTime = 0;
				}
				
				continue;
			}
			
			if( ret < 0)
			{
				closePeerConnection( &iPeerThreadIndex);
				break;
			}
			
			if( ret > 0)
			{
				n = sctp_recvmsg( objStackConfig.Peers[iPeerThreadIndex].fd, buf, sizeof(buf), (struct sockaddr *)NULL, 0, &sinfo, &flags);
				
				if( flags & MSG_NOTIFICATION ) 
				{
					union sctp_notification  *snp = (union sctp_notification *)buf;
					if(snp)
					{
						if( SCTP_SHUTDOWN_EVENT == snp->sn_header.sn_type)
						{
							closePeerConnection( &iPeerThreadIndex);
							break;
						}
						handle_sctp_event( buf, n );
					}
				}
				else 
				{
					if( (ret == 1 && n == 0) || n < 0)
					{
						closePeerConnection( &iPeerThreadIndex);
						break;
					}

					if( n > 0)
					{
						CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "stream %d, PPID %d.: bytes-received-X-P:%d", sinfo.sinfo_stream, ntohl(sinfo.sinfo_ppid), n);
						
						if( lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength > 0)
						{
							PendingBufferLength = lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength;
							memcpy( totbuf, lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, PendingBufferLength);
							memcpy( &totbuf[PendingBufferLength], buf, n);
							iTotalBufferLength = PendingBufferLength + n;
							lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = 0;
						}
						else
						{
							memcpy( totbuf, buf, n);
							iTotalBufferLength = n;
						}
						
						iUsedBufferSize = 0;
						while( iUsedBufferSize < iTotalBufferLength)
						{
							if( ( iTotalBufferLength - iUsedBufferSize) > DIAM_BUFFER_SIZE_HEADER_SIZE)
							{
								oDiamRawData = allocateDiamRawData();
								oDiamRawData->Header->len = DIAM_BUFFER_SIZE_HEADER_SIZE;
								memcpy( oDiamRawData->Header->Data, &totbuf[iUsedBufferSize], DIAM_BUFFER_SIZE_HEADER_SIZE);
								decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);
								
								if( ( iTotalBufferLength - iUsedBufferSize) >= iMessageLength )
								{
									CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "iMessageLength = %d sufficient body message", iMessageLength);
									memcpy( oDiamRawData->PayLoad->Data, &totbuf[iUsedBufferSize + DIAM_BUFFER_SIZE_HEADER_SIZE], (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE));

									oDiamRawData->iPeerIndex = iPeerThreadIndex;
									oDiamRawData->iRequestNo = iRequestNo;
									oDiamRawData->iMessageArrivedFrom = 10;
									oDiamRawData->iRouteMessageTo = 2;	
									oDiamRawData->PayLoad->len = (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE);
									oDiamRawData->sinfo_stream = sinfo.sinfo_stream;
									oDiamRawData->sinfo_assoc_id = sinfo.sinfo_assoc_id;
									memcpy( &oDiamRawData->sinfo, &sinfo, sizeof(struct sctp_sndrcvinfo));
									
									objStackObjects.TotalMemoryUsage.SocketReadCount++;
									appPostMsg( oDiamRawData);
									//releaseDiamRawData( oDiamRawData);
									//printf("releaseDiamRawData=%p\n", oDiamRawData);
																		
									objStackConfig.Peers[iPeerThreadIndex].iResponseNo++;
									iRequestNo++;
									iUsedBufferSize += iMessageLength;										
								}
								else
								{
									releaseDiamRawData( oDiamRawData);
									//printf("message is less than header(20) size = %d\n", iTotalBufferLength);
									CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
									lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
									memcpy( lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
									break;									
								}
							}
							else
							{
								CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
								lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
								memcpy( lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
								break;
							}
						}	
						
						CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "while exited peer thread iUsedBufferSize[%d] , iTotalBufferLength[%d]\n", iUsedBufferSize, iTotalBufferLength);
					}
				}
			}
			
		}
		
	}
	
	#endif
}

/**
 * Connect To Server
 *  
 * */
void * appStartPeerThread(void *args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	int iPeerThreadIndex = (int) (intptr_t) args;
	int is = 0;
	int iSts;
	unsigned int iMessageLength, iBodySize;
	
	while(1)
	{
		if(objStackConfig.Peers[iPeerThreadIndex].isCEASuccess == -5)
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Exiting Peer Thread, App does not support Configured Interface[%d]", objStackConfig.Peers[iPeerThreadIndex].AppId);
			break;
		}

		iSts = appConnectToPeer( &iPeerThreadIndex);

		if( iSts < 0)
		{
			for( is = 0; is < objStackConfig.ReConnectSeconds; is++)
			{
				usleep( 999999);
			}	
		}
		
		if(objStackConfig.Peers[iPeerThreadIndex].isConnected == 1)
		{
			struct DiamMessage * dmCER = allocateMessage();
			createCER( dmCER, objStackConfig.Peers[iPeerThreadIndex].AppId, iPeerThreadIndex);
			
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd, objStackConfig.Peers[iPeerThreadIndex].PeerIP, objStackConfig.Peers[iPeerThreadIndex].PeerPort);

			int bSuccess = appSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmCER);

			if( bSuccess < 0 && errno == EPIPE)
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd);
				closePeerConnection( &iPeerThreadIndex);
			}
		}

		objStackConfig.Peers[iPeerThreadIndex].iIdleTime = 0;
		objStackConfig.Peers[iPeerThreadIndex].iDWRCount = 0;
		int iWaitTime = 3;
		int iRequestNo = 0;

		while(objStackConfig.Peers[iPeerThreadIndex].isConnected == 1)
		{
			fd_set rfds;
			struct timeval tv;
			int selectFlag = 0;

			FD_ZERO( &rfds);
			FD_SET( objStackConfig.Peers[iPeerThreadIndex].fd, &rfds);
			memset( (char *)&tv, 0, sizeof(tv));

			//wait 3 seconds
			tv.tv_usec = iWaitTime;
			tv.tv_sec = iWaitTime;

			selectFlag = select( objStackConfig.Peers[iPeerThreadIndex].fd + 1, &rfds, NULL, NULL, &tv);

			if(selectFlag < 0 )
			{
				if( objStackConfig.Peers[iPeerThreadIndex].isConnected == 0)
				{
					break;
				}
				continue;
			}

			if(selectFlag == 0)
			{
				if(objStackConfig.Peers[iPeerThreadIndex].isConnected == 0)
				{
					break;
				}

				objStackConfig.Peers[iPeerThreadIndex].iIdleTime += iWaitTime;

				if( objStackConfig.Peers[iPeerThreadIndex].iIdleTime >= objStackConfig.WatchDogRequestInterval )
				{
					if(objStackConfig.Peers[iPeerThreadIndex].isCEASuccess == 0)
					{
						struct DiamMessage *dmCER = allocateMessage();
						createCER( dmCER, objStackConfig.Peers[iPeerThreadIndex].AppId, iPeerThreadIndex);
			
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd, objStackConfig.Peers[iPeerThreadIndex].PeerIP, objStackConfig.Peers[iPeerThreadIndex].PeerPort);

						int bSuccess = appSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmCER);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd);
							closePeerConnection( &iPeerThreadIndex);
							continue;
						}
					}
					else
					{
						if( objStackConfig.Peers[iPeerThreadIndex].iDWRCount > 2)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Peer[%d] SockFd[%d], Connection, DWA Not Received Pending Count(%d)", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd, objStackConfig.Peers[iPeerThreadIndex].iDWRCount);
							objStackConfig.Peers[iPeerThreadIndex].iDWRCount = 0;
							closePeerConnection( &iPeerThreadIndex);
							continue;
						}
						
						//send watch dog request
						struct DiamMessage *dmDWR = allocateMessage();
						createWatchDogRequest( dmDWR);

						int bSuccess = appSendMsg( &objStackConfig.Peers[iPeerThreadIndex].fd, dmDWR);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending DWR Failed For Peer[%d] SockFd[%d]", iPeerThreadIndex, objStackConfig.Peers[iPeerThreadIndex].fd);
							closePeerConnection( &iPeerThreadIndex);
							continue;
						}
						
						objStackConfig.Peers[iPeerThreadIndex].iDWRCount++;
					}


					objStackConfig.Peers[iPeerThreadIndex].iIdleTime = 0;
				}

			}

			if(selectFlag > 0)
			{
				if(FD_ISSET( objStackConfig.Peers[iPeerThreadIndex].fd, &rfds))
				{
					int iReceivedSize = 0;
					int iHeaderSize = 20;

					struct DiamRawData *oDiamRawData = allocateDiamRawData();
					memset( oDiamRawData->Header->Data, 0, DIAM_BUFFER_SIZE_HEADER_SIZE);
					oDiamRawData->Header->len = iHeaderSize;

					iReceivedSize = recv( objStackConfig.Peers[iPeerThreadIndex].fd, oDiamRawData->Header->Data, iHeaderSize, 0 );

					if( iReceivedSize != iHeaderSize)
					{
						int leftOverBytes = iHeaderSize - iReceivedSize;
						
						iReceivedSize = recv( objStackConfig.Peers[iPeerThreadIndex].fd, &oDiamRawData->Header->Data[iReceivedSize], leftOverBytes, 0 );
						
						if( leftOverBytes != iReceivedSize)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Peer Connection, HeaderSize[%d] and RecivedSize[%d] Not Matched iPeerThreadIndex[%d]", iHeaderSize, iReceivedSize, iPeerThreadIndex);
							closePeerConnection( &iPeerThreadIndex);
							break;
						}						
					}

					

					decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);

					iBodySize = iMessageLength - iHeaderSize;
					memset( oDiamRawData->PayLoad->Data, 0, DIAM_BUFFER_SIZE_PER_REQUEST);

				#if HIGH_BUFF
				
					int bOuterLoop = 0;
					int iNRecvBytes = 0;
					iReceivedSize = 0;
					
					while( iNRecvBytes < iBodySize)
					{
						iReceivedSize = recv( objStackConfig.Peers[iPeerThreadIndex].fd, &oDiamRawData->PayLoad->Data[iNRecvBytes], (iBodySize - iNRecvBytes), 0 );
						
						if( iReceivedSize > 0)
						{
							iNRecvBytes += iReceivedSize;
						}
						else
						{
							//check error 
							bOuterLoop = 1;
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Peer Connection, iBodySize[%d] and RecivedSize[%d] Not Matched cliInfo->isActive[%d]", iBodySize, iReceivedSize, iPeerThreadIndex);
							closePeerConnection( &iPeerThreadIndex);	
							break;
						}
					}	
				
					if( bOuterLoop == 1)
					{
						break;
					}
					
				#else
					
					iReceivedSize = recv( objStackConfig.Peers[iPeerThreadIndex].fd, oDiamRawData->PayLoad->Data, iBodySize, 0 );

					if( iReceivedSize != iBodySize)
					{
						int leftOverBytes = iBodySize - iReceivedSize;
						
						iReceivedSize = recv( objStackConfig.Peers[iPeerThreadIndex].fd, &oDiamRawData->PayLoad->Data[iReceivedSize], leftOverBytes, 0 );
						
						if( leftOverBytes != iReceivedSize)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Peer Connection, iBodySize[%d] and RecivedSize[%d] Not Matched cliInfo->isActive[%d]", iBodySize, iReceivedSize, iPeerThreadIndex);
							closePeerConnection( &iPeerThreadIndex);
							break;
						}
					}
					
				#endif
				
					/*
					iReceivedSize = recv( objStackConfig.Peers[iPeerThreadIndex].fd, oDiamRawData->PayLoad->Data, iBodySize, 0 );

					if( iReceivedSize != iBodySize)
					{
						int leftOverBytes = iBodySize - iReceivedSize;
						
						iReceivedSize = recv( objStackConfig.Peers[iPeerThreadIndex].fd, &oDiamRawData->PayLoad->Data[iReceivedSize], leftOverBytes, 0 );
						
						if( leftOverBytes != iReceivedSize)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Peer Connection, iBodySize[%d] and RecivedSize[%d] Not Matched cliInfo->isActive[%d]", iBodySize, iReceivedSize, iPeerThreadIndex);
							closePeerConnection( &iPeerThreadIndex);
							break;
						}
					}
					*/
					


					oDiamRawData->PayLoad->len = iBodySize;

					oDiamRawData->iRequestNo = iRequestNo;
					oDiamRawData->CliInfo = NULL;
					oDiamRawData->iPeerIndex = iPeerThreadIndex;
					oDiamRawData->iMessageArrivedFrom = 1;
					oDiamRawData->iRouteMessageTo = 2;

					objStackObjects.TotalMemoryUsage.SocketReadCount++;

					appPostMsg( oDiamRawData);

					objStackConfig.Peers[iPeerThreadIndex].iResponseNo++;
					iRequestNo++;
				}
			}

		}

		usleep(10000);
	}

	return NULL;
}


void * appStartClientThread( void* args)
{
	return NULL;
	/*
	
	int iClientThreadIndex = (int) (intptr_t) args;
	
	while(1)
	{
		if( objStackConfig.Clients[iClientThreadIndex].isCEASuccess == -5)
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Exiting Client Thread, App does not support Configured Interface[%d]", objStackConfig.Clients[iClientThreadIndex].AppId);
			break;
		}
		
		int iSts = appConnectToClient( &iClientThreadIndex);

		if( iSts < 0)
		{
			int is = 10;
			
			for( is = 0; is < objStackConfig.ReConnectSeconds; is++)
			{
				usleep( 999999);
			}	
		}

		if(objStackConfig.Clients[iClientThreadIndex].isConnected == 1)
		{
			struct DiamMessage * dmCER = allocateMessage();
			createCER( dmCER, objStackConfig.Clients[iClientThreadIndex].AppId, -1);
			
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Clients[%d] SockFd[%d] IP[%s] Port[%d]", iClientThreadIndex, objStackConfig.Clients[iClientThreadIndex].fd, objStackConfig.Clients[iClientThreadIndex].ClientIP, objStackConfig.Clients[iClientThreadIndex].ClientPort);
			
			int bSuccess = appSendMsg( &objStackConfig.Clients[iClientThreadIndex].fd, dmCER);

			if( bSuccess < 0 && errno == EPIPE)
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Clients[%d] SockFd[%d]", iClientThreadIndex, objStackConfig.Clients[iClientThreadIndex].fd);
				closeClientConnection( &iClientThreadIndex);
			}
		}
		
		objStackConfig.Clients[iClientThreadIndex].iIdleTime = 0;
		int iWaitTime = 3;
		int iRequestNo = 0;
		
		while(objStackConfig.Clients[iClientThreadIndex].isConnected == 1)
		{
			fd_set rfds;
			struct timeval tv;
			int selectFlag = 0;

			FD_ZERO( &rfds);
			FD_SET( objStackConfig.Clients[iClientThreadIndex].fd, &rfds);
			memset( (char *)&tv, 0, sizeof(tv));

			//wait 3 seconds
			tv.tv_usec = iWaitTime;
			tv.tv_sec = iWaitTime;

			selectFlag = select( objStackConfig.Clients[iClientThreadIndex].fd + 1, &rfds, NULL, NULL, &tv);

			if(selectFlag < 0 )
			{
				if( objStackConfig.Clients[iClientThreadIndex].isConnected == 0)
				{
					break;
				}
				continue;
			}
			
			if(selectFlag == 0)
			{
				if(objStackConfig.Clients[iClientThreadIndex].isConnected == 0)
				{
					break;
				}
				
				objStackConfig.Clients[iClientThreadIndex].iIdleTime += iWaitTime;
				
				if( objStackConfig.Clients[iClientThreadIndex].iIdleTime >= objStackConfig.WatchDogRequestInterval )
				{
					if(objStackConfig.Clients[iClientThreadIndex].isCEASuccess == 0)
					{
						struct DiamMessage *dmCER = allocateMessage();
						createCER( dmCER, objStackConfig.Clients[iClientThreadIndex].AppId, -1);
						
						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Clients[%d] SockFd[%d] IP[%s] Port[%d]", iClientThreadIndex, objStackConfig.Clients[iClientThreadIndex].fd, objStackConfig.Clients[iClientThreadIndex].ClientIP, objStackConfig.Clients[iClientThreadIndex].ClientPort);
						
						int bSuccess = appSendMsg( &objStackConfig.Clients[iClientThreadIndex].fd, dmCER);
						
						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Clients[%d] SockFd[%d]", iClientThreadIndex, objStackConfig.Clients[iClientThreadIndex].fd);
							closeClientConnection( &iClientThreadIndex);
							continue;
						}
					}
					else
					{
						//send watch dog request
						struct DiamMessage *dmDWR = allocateMessage();
						createWatchDogRequest( dmDWR);
						
						int bSuccess = appSendMsg( &objStackConfig.Clients[iClientThreadIndex].fd, dmDWR);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending DWR Failed For Clients[%d] SockFd[%d]", iClientThreadIndex, objStackConfig.Clients[iClientThreadIndex].fd);
							closeClientConnection( &iClientThreadIndex);
							continue;
						}
					}
					
					objStackConfig.Clients[iClientThreadIndex].iIdleTime = 0;
				}
			}
			
			if(selectFlag > 0)
			{
				if(FD_ISSET( objStackConfig.Clients[iClientThreadIndex].fd, &rfds))
				{
					int iReceivedSize = 0;
					int iHeaderSize = 20;
					
					struct DiamRawData *oDiamRawData = allocateDiamRawData();
					memset( oDiamRawData->Header->Data, 0, DIAM_BUFFER_SIZE_HEADER_SIZE);
					oDiamRawData->Header->len = iHeaderSize;
					
					iReceivedSize = recv( objStackConfig.Clients[iClientThreadIndex].fd, oDiamRawData->Header->Data, iHeaderSize, 0 );

					if( iReceivedSize != iHeaderSize)
					{
						int leftOverBytes = iHeaderSize - iReceivedSize;
						
						iReceivedSize = recv( objStackConfig.Clients[iClientThreadIndex].fd, &oDiamRawData->Header->Data[iReceivedSize], leftOverBytes, 0 );
						
						if( leftOverBytes != iReceivedSize)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Client Connection, HeaderSize[%d] and RecivedSize[%d] Not Matched iClientThreadIndex[%d]", iHeaderSize, iReceivedSize, iClientThreadIndex);
							closeClientConnection( &iClientThreadIndex);
							break;
						}						
					}

					int iMessageLength, iBodySize;
					
					decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);
					
					iBodySize = iMessageLength - iHeaderSize;
					
					memset( oDiamRawData->PayLoad->Data, 0, DIAM_BUFFER_SIZE_PER_REQUEST);
					
					iReceivedSize = recv( objStackConfig.Clients[iClientThreadIndex].fd, oDiamRawData->PayLoad->Data, iBodySize, 0 );

					if( iReceivedSize != iBodySize)
					{
						int leftOverBytes = iBodySize - iReceivedSize;
						
						iReceivedSize = recv( objStackConfig.Clients[iClientThreadIndex].fd, &oDiamRawData->PayLoad->Data[iReceivedSize], leftOverBytes, 0 );
						
						if( leftOverBytes != iReceivedSize)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Closing Client Connection, iBodySize[%d] and RecivedSize[%d] Not Matched cliInfo->isActive[%d]", iBodySize, iReceivedSize, iClientThreadIndex);
							closeClientConnection( &iClientThreadIndex);
							break;
						}	
					}
					
					oDiamRawData->PayLoad->len = iBodySize;
					oDiamRawData->iRequestNo = iRequestNo;
					oDiamRawData->CliInfo = &objStackConfig.Clients[iClientThreadIndex];
					oDiamRawData->iPeerIndex = -1;
					oDiamRawData->iMessageArrivedFrom = 2;
					oDiamRawData->iRouteMessageTo = 1;
					
					objStackConfig.Clients[iClientThreadIndex].ReceivedMessages++;
					objStackObjects.TotalMemoryUsage.SocketReadCount++;

					appPostMsg( oDiamRawData);

					iRequestNo++;
				}
			}
		}
		
		usleep(10000);
	}
	*/
	
	return NULL;
}

void startStack()
{
	pthread_t s_pthread_id;
	int iRet;
	
	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);
	
	if( objStackConfig.Port > 0)
	{	
		if( objStackConfig.HostTransportType == 1)
		{	
			//Sctp
			iRet = pthread_create( &s_pthread_id, &attr, appHostSctpThread, (void *)NULL);			
		}
		else
		{
			iRet = pthread_create( &s_pthread_id, &attr, appHostThread, (void *)NULL);
		}
		
		if(iRet)
		{
			printf("Unable to Create Host Thread(appHostThread)\n");
			exit(-1);
		}
	}
	
	if( objStackConfig.HostPortCount > 0)
	{
		int i = 0;
		for( i = 0; i < objStackConfig.HostPortCount; i++)
		{
			if( objStackConfig.HostPort[i] > 0)
			{
				iHostPortInfo * oHostPortInfo = (iHostPortInfo *) lib_malloc( sizeof(iHostPortInfo));
				memset( oHostPortInfo, 0, sizeof(iHostPortInfo));
				oHostPortInfo->iPort = objStackConfig.HostPort[i];
				
				iRet = pthread_create( &s_pthread_id, &attr, appHostThread_IPv4_MultiPort, (void *)oHostPortInfo);
				
				if(iRet)
				{
					printf("Unable to Create Host Thread(appHostThread)\n");
					exit(-1);
				}
			}
		}
	}

	if( objStackConfig.NoOfPeers > 0)
	{
		pthread_t peer_pthread_id[objStackConfig.NoOfPeers];
		int i = 0;
				
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			//int *iPtr = &i;
			
			if( objStackConfig.Peers[i].TransportType == 1)
			{
				iRet = pthread_create( &peer_pthread_id[i], &attr, appStartSctpPeerThread, (void *)i);
			}
			else
			{
				iRet = pthread_create( &peer_pthread_id[i], &attr, appStartPeerThread, (void *)i);
			}
			
			if(iRet)
			{
				printf("unable to create appStartPeerThread[%d]\n", i);
				exit(-1);
			}
			
			if( i >= 0)
			{
				//lets first thread read value
				usleep(9999);
			}
			
			/*
			if( objStackConfig.Peers[i].ClientInfoCount > 0)
			{
				int j = 0;
				
				pthread_t cli_peer_pthread_id[objStackConfig.Peers[i].ClientInfoCount];
				
				for( j = 0; j < objStackConfig.Peers[i].ClientInfoCount; j++)
				{
					iPeerClientInfo * oPeerClientInfo = ( iPeerClientInfo *) lib_malloc( sizeof(iPeerClientInfo) );
					memset( oPeerClientInfo, 0, sizeof( iPeerClientInfo));
					
					oPeerClientInfo->iPeerThreadIndex = i;
					oPeerClientInfo->iClientInfoId = objStackConfig.Peers[i].ClientInfo[j];
					
					iRet = pthread_create( &cli_peer_pthread_id[j], &attr, appStartPeerClientThread, oPeerClientInfo);
					
					if(iRet)
					{
						printf("unable to create appStartPeerClientThread[%d]\n", i);
						exit(-1);
					}
				}	
			}
			*/
		}
	}
	
	if( objStackConfig.NoOfClients > 0)
	{
		//pthread_t peer_pthread_id[objStackConfig.NoOfClients];
		int i = 0;
		
		for( i = 0; i < objStackConfig.NoOfClients; i++)
		{
			objStackConfig.Clients[i].ClientIndex = i;
			
			/*
			if( objStackConfig.Clients[i].iConnectToClient == 1)
			{
				iRet = pthread_create( &peer_pthread_id[i], &attr, appStartClientThread, (void *)i);
				
				if(iRet)
				{
					printf("unable to create appStartPeerThread[%d]\n", i);
					exit(-1);
				}
				
				if( i > 0)
				{
					//lets first thread read value
					usleep(999);
				}
			}
			*/		
		}
	}
	
	if( objStackConfig.ConfigPort > 0)
	{
		pthread_t config_pthread;
		
		iRet = pthread_create( &config_pthread, &attr, appStartConfigThread, NULL);
		
		if(iRet)
		{
			printf("unable to create Config Thread[%d]\n", 0);
			exit(-1);
		}		
	}
}


void initThreadPool(iThreadPool *objThreadPool, int iCount, void *(*routine)( void*))
{
    pthread_mutex_init(&objThreadPool->aquireLock, NULL);

    objThreadPool->Head = NULL;
    objThreadPool->Current = NULL;
	objThreadPool->ThreadCount = iCount;
	objThreadPool->FreeCount = iCount;

	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);
	
	int i;

    for (i = 0; i < iCount; i++)
    {
    	iWorkerThread * oWorkerThread = (iWorkerThread*)lib_malloc(sizeof(iWorkerThread));

    	//if( oWorkerThread == NULL)
		if(!oWorkerThread)	
		{
			printf("Worker Thread Creation Failed\n");
			exit(-1);
		}

    	//if(objThreadPool->Head == NULL)
		if(!objThreadPool->Head)	
    	{
    		objThreadPool->Head = oWorkerThread;
    	}
    	else
    	{
    		objThreadPool->Current->Next = oWorkerThread;
    	}

    	if( sem_init( &oWorkerThread->sem_lock, 0, 0) < 0)
    	{
    		printf("Semaphore Initialization Failed\n");
    		exit(-1);
    	}

    	oWorkerThread->Parent = objThreadPool;
    	oWorkerThread->isFree = 1;
    	oWorkerThread->Index = i;
		oWorkerThread->Next = NULL;
		objThreadPool->Current = oWorkerThread;

		//printf("Created Worker Thread [%d]\n", i);
	}

    iWorkerThread * oWorkerThread = objThreadPool->Head;


    //while( oWorkerThread != NULL)
	while(oWorkerThread)	
    {
    	pthread_t s_pthread_id;
    	int iRet;
    	iRet = pthread_create( &s_pthread_id, &attr, routine, (void *)oWorkerThread);

    	if(iRet)
    	{
    		printf("unable to create worker thread\n");
    		exit(-1);
    	}

    	oWorkerThread = oWorkerThread->Next;
    }

	//printf("Created Worker Threads[%d]\n", iCount);
}



int corebStartStack = 1;
/**
 * @brief Initializes Stack
 * @return void
 */
void initalizeServer()
{
	if( objStackConfig.QueueMode == 0)
	{
		initThreadPool( &objStackObjects.DecodeThreadPool, objStackConfig.DecodeThreadPoolCount, appDecodeThread);
	}
	else
	{
		printf("starting decode-threads:%d, routing-threads:%d QueueMode=%d\n", objStackConfig.DecodeThreadPoolCount, objStackConfig.RoutingThreadCount, objStackConfig.QueueMode);
		initThreadPool( &objStackObjects.DecodeThreadPool, objStackConfig.DecodeThreadPoolCount, appDecodeDequeeThread);
		initThreadPool( &objStackObjects.RoutingThreadPool, objStackConfig.RoutingThreadCount, appRoutingDequeeThread);		
	}

	if( corebStartStack ) {
		startStack();
	}	
}

void parsePeerClientInfo( iPeerInfo * oPeerInfo, char * cfline)
{
	oPeerInfo->ClientInfoCount = 0;
	
	char * pch;
	pch = strtok( cfline, ",");
	int i = 0;
	
	while (pch)	
	{
		if( i < 10)
		{
			oPeerInfo->ClientInfo[oPeerInfo->ClientInfoCount] = atoi(pch);
			printf( "ClientInfo[%d] = %d \n", oPeerInfo->ClientInfoCount, oPeerInfo->ClientInfo[oPeerInfo->ClientInfoCount]);
			oPeerInfo->ClientInfoCount++;
			
			pch = strtok ( NULL, ",");
			i++;
		}
	}
	
	printf("ClientInfoCount = %d\n", oPeerInfo->ClientInfoCount);
}

void parseRoutingInfo( iDRARoutingInfo * piDRARoutingInfo, char * cfline)
{
	char * pch;
	pch = strtok( cfline, ",");
	int i = 0;
	
	//while (pch != NULL)
	while (pch)	
	{
		if(i == 0) {
			piDRARoutingInfo->Min = atoll( pch);
		} else if(i == 1) {
			piDRARoutingInfo->Max = atoll( pch);
		} else if(i == 2) {
			piDRARoutingInfo->PrimaryNodeId = atoi( pch);
		} else if(i == 3) {
			piDRARoutingInfo->FallBackNodeId = atoi( pch);
		}
		
		pch = strtok ( NULL, ",");
		i++;
	}
	
	printf( "Min[%llu] Max[%llu] PrimaryNodeId[%d] FallBackNodeId[%d]\n", piDRARoutingInfo->Min, piDRARoutingInfo->Max, piDRARoutingInfo->PrimaryNodeId, piDRARoutingInfo->FallBackNodeId );

}

int (*ptrCoreOnConfigItemHandler)( char *, char *, int ) = NULL;

void setCoreOnConfigItemHandler( int (*ptrHandler)( char *, char *, int))
{
	ptrCoreOnConfigItemHandler = ptrHandler;
}

void core_addiAuthApplicationId(int iAuthApplicationId)
{
	if( objStackConfig.iAuthApplicationIdCount < 10)
	{
		objStackConfig.iAuthApplicationId[ objStackConfig.iAuthApplicationIdCount] = iAuthApplicationId;
		objStackConfig.iAuthApplicationIdCount++;
	}
}

void core_addiAcctApplicationId(int iAcctApplicationId)
{
	if( objStackConfig.iAcctApplicationIdCount < 10)
	{
		objStackConfig.iAcctApplicationId[ objStackConfig.iAcctApplicationIdCount] = iAcctApplicationId;
		objStackConfig.iAcctApplicationIdCount++;
	}
}

void core_addiVendorSpecificAuthApplicationId( int iVendorId, int iAuthApplicationId)
{
	if( objStackConfig.iVendorSpecificAuthApplicationIdCount < 10)
	{
		objStackConfig.VendorSpecificAuthApplicationId[ objStackConfig.iVendorSpecificAuthApplicationIdCount].iVendorId = iVendorId;
		objStackConfig.VendorSpecificAuthApplicationId[ objStackConfig.iVendorSpecificAuthApplicationIdCount].iAuthApplicationId = iAuthApplicationId;
		objStackConfig.iVendorSpecificAuthApplicationIdCount++;
	}
}


#define FILENAME "SERVER.txt"
#define MAXBUF 1024
#define DELIM "="


int core_bConfigFileAvailable = 1;

void initConfig(char* configFileName)
{
	printf("F:%s\n", __FUNCTION__);
	
	memset( &objStackConfig, 0, sizeof(struct StackConfig));
	memset( &objStackObjects, 0, sizeof(struct StackObjects));
	
	objStackConfig.iAcctApplicationIdCount = 0;
	objStackConfig.iAuthApplicationIdCount = 0;
	objStackConfig.iVendorSpecificAuthApplicationIdCount = 0;
	objStackConfig.CheckSocketBeforeSend = 0;
	objStackConfig.DRARoutingModule = 0;
	
	objStackObjects.iEPoolNoOfReadThreds = MAX_EPOLL_THREADS;
	
	memset( &objMemoryManagement , 0, sizeof(iMemoryManagement));	
	objMemoryManagement.MemoryBlockCount = -1;	
	objMemoryManagement.PRecordCount = 1;
	
	objStackConfig.LoggerMemoryBlockId = __registerMemoryBlock( sizeof(struct LogMessage), 10, 10, (char*)"Logger");

	objStackObjects.ClientInfoCount = 0;
	objStackObjects.ClientInfoHead = objStackObjects.ClientInfoCurrent = NULL;
	pthread_mutex_init( &objStackObjects.ClientInfoLock, NULL);
	
	objStackObjects.SctpClientInfoCount = 0;
	objStackObjects.SctpClientInfoHead = objStackObjects.SctpClientInfoCurrent = NULL;
	pthread_mutex_init( &objStackObjects.SctpClientInfoLock, NULL);
	
	
	objStackConfig.oEventTimerObjects = (IEventTimerObjects *)lib_malloc( sizeof(IEventTimerObjects) );
	
	if(!objStackConfig.oEventTimerObjects)
	{
		printf("memory allocation failed for objStackConfig.oEventTimerObjects\n");
		exit(0);
	}

	memset( objStackConfig.oEventTimerObjects, 0, sizeof(sizeof(IEventTimerObjects)));
	
	objStackConfig.oEventTimerObjects->MemoryBlockId =  __registerMemoryBlock( sizeof(struct StackTimerRecord), 100000, 10000, (char*)"Timer");
	
	objStackConfig.oEventTimerObjects->CIndex = 0;
	objStackConfig.oEventTimerObjects->RootHead = NULL;
	objStackConfig.oEventTimerObjects->RootCurrent = NULL;
	pthread_mutex_init( &objStackConfig.oEventTimerObjects->RootLock, NULL);
	
	int ix = 0;
	for( ix = 0; ix < EVENT_TIMER_MAXSECONDS; ix++)
	{
		objStackConfig.oEventTimerObjects->TNodes[ix] = (IATimerNode *)lib_malloc(sizeof(IATimerNode));
		objStackConfig.oEventTimerObjects->TNodes[ix]->Index = ix;
		pthread_mutex_init( &objStackConfig.oEventTimerObjects->TNodes[ix]->Lock, NULL);
	}
	
	objStackConfig.ReConnectSeconds = 30;
	objStackConfig.AcceptUnknownClinet = 0;
	
	
	//objStackConfig.DecodeThreadPoolCount = 25;
	objStackConfig.DecodeThreadPoolCount = 20;
	objStackConfig.RoutingThreadCount = 10;	
	objStackConfig.EncodeThreadPoolCount = 5;
	objStackConfig.WatchDogRequestInterval = 12;
	objStackConfig.iLoadedPeerConfigCount = 0;
	objStackConfig.EndPointIndex = 0;
	
	
	
	
	
	
	memset( &objStackObjects.ServerCounter, 0, sizeof(objStackObjects.ServerCounter));
	
	
	
	objStackObjects.LogCatCount = 0;
	

	objStackObjects.iLoggerId = 0;
	
	objStackObjects.LoggerConfig[0].iHandle = 0;
	objStackObjects.LoggerConfig[1].iHandle = 0;
	objStackObjects.LoggerConfig[2].iHandle = 0;
	objStackObjects.LoggerConfig[3].iHandle = 0;	

	objStackObjects.LoggerConfig[0].CSVMode = 0;
	objStackObjects.LoggerConfig[1].CSVMode = 0;
	objStackObjects.LoggerConfig[2].CSVMode = 0;
	objStackObjects.LoggerConfig[3].CSVMode = 1;

	
	
	memset( &objStackObjects.LoggerConfig[0].Prefix, 0, sizeof(objStackObjects.LoggerConfig[0].Prefix));
	memset( &objStackObjects.LoggerConfig[1].Prefix, 0, sizeof(objStackObjects.LoggerConfig[1].Prefix));
	memset( &objStackObjects.LoggerConfig[2].Prefix, 0, sizeof(objStackObjects.LoggerConfig[2].Prefix));
	memset( &objStackObjects.LoggerConfig[3].Prefix, 0, sizeof(objStackObjects.LoggerConfig[3].Prefix));	
	
	memset( &objStackObjects.LoggerConfig[0].Path, 0, sizeof(objStackObjects.LoggerConfig[0].Path));
	memset( &objStackObjects.LoggerConfig[1].Path, 0, sizeof(objStackObjects.LoggerConfig[1].Path));
	memset( &objStackObjects.LoggerConfig[2].Path, 0, sizeof(objStackObjects.LoggerConfig[2].Path));
	memset( &objStackObjects.LoggerConfig[3].Path, 0, sizeof(objStackObjects.LoggerConfig[3].Path));
	
	
	strcpy( objStackObjects.LoggerConfig[0].Prefix, "STK"); 
	strcpy( objStackObjects.LoggerConfig[1].Prefix, "PER"); 
	strcpy( objStackObjects.LoggerConfig[2].Prefix, "APP");
	strcpy( objStackObjects.LoggerConfig[3].Prefix, "CSV");	
			
	strcpy( objStackObjects.LoggerConfig[0].Path, "./stacklogs"); 
	strcpy( objStackObjects.LoggerConfig[1].Path, "./perflogs"); 
	strcpy( objStackObjects.LoggerConfig[2].Path, "./applogs"); 	
	strcpy( objStackObjects.LoggerConfig[3].Path, "./csvlogs");	
	
	
	objStackObjects.LoggerConfig[0].iLoggingThreshold = 5;
	objStackObjects.LoggerConfig[1].iLoggingThreshold = 5;
	objStackObjects.LoggerConfig[2].iLoggingThreshold = 5;
	objStackObjects.LoggerConfig[3].iLoggingThreshold = 5;	
	
	pthread_mutex_init( &objStackObjects.LoggerConfig[0].Lock, NULL);
	pthread_mutex_init( &objStackObjects.LoggerConfig[1].Lock, NULL);
	pthread_mutex_init( &objStackObjects.LoggerConfig[2].Lock, NULL);
	pthread_mutex_init( &objStackObjects.LoggerConfig[3].Lock, NULL);
	
	objStackObjects.LoggerConfig[0].iFileIndex = 1;
	objStackObjects.LoggerConfig[1].iFileIndex = 1;
	objStackObjects.LoggerConfig[2].iFileIndex = 1;	
	objStackObjects.LoggerConfig[3].iFileIndex = 1;	
		
	objStackObjects.LoggerConfig[0].Enabled = 1;	//Stack
	objStackObjects.LoggerConfig[1].Enabled = 0;	//Perf
	objStackObjects.LoggerConfig[2].Enabled = 1;	//App Logs
	objStackObjects.LoggerConfig[3].Enabled = 0;	//CSV	
		
	objStackObjects.RealmTableCurrentCount = 0;
	objStackObjects.RealmTableMaxEntries = 0;
	
	
	objStackObjects.iPerformanceCounterIndex = -1;
	objStackObjects.TotalMemoryUsage.DiamRawDataAllocatedCount = 0;
	objStackObjects.TotalMemoryUsage.DiamRawDataReleaseCount = 0;	
	objStackObjects.TotalMemoryUsage.DiamMessageAllocatedCount = 0;
	objStackObjects.TotalMemoryUsage.DiamMessageReleaseCount = 0;	
	objStackObjects.TotalMemoryUsage.DiamAVPAllocatedCount = 0;
	objStackObjects.TotalMemoryUsage.DiamAVPReleaseCount = 0;
	objStackObjects.TotalMemoryUsage.DiamCDataAllocatedCount = 0;
	objStackObjects.TotalMemoryUsage.DiamCDataReleaseCount = 0;
	objStackObjects.TotalMemoryUsage.DecodeThreadAllocatedCount = 0;
	objStackObjects.TotalMemoryUsage.DecodeThreadReleaseCount = 0;	
	objStackObjects.TotalMemoryUsage.DecodeThreadRejectedCount = 0;
	objStackObjects.TotalMemoryUsage.SocketReadCount = 0;
	objStackObjects.TotalMemoryUsage.SocketWriteCount = 0;		
	objStackObjects.TotalMemoryUsage.QueueRecordAllocatedCount = 0;
	objStackObjects.TotalMemoryUsage.QueueRecordReleasedCount = 0;
	objStackObjects.TotalMemoryUsage.DiamRoutePoolAllocatedCount = 0;
	objStackObjects.TotalMemoryUsage.DiamRoutePoolReleasedCount = 0;
	objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidClientObject = 0;
	objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidActiveState = 0;
	objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidLength = 0;
		
	objStackObjects.PreviousMemoryUsage.DiamRawDataAllocatedCount = 0;
	objStackObjects.PreviousMemoryUsage.DiamRawDataReleaseCount = 0;	
	objStackObjects.PreviousMemoryUsage.DiamMessageAllocatedCount = 0;
	objStackObjects.PreviousMemoryUsage.DiamMessageReleaseCount = 0;	
	objStackObjects.PreviousMemoryUsage.DiamAVPAllocatedCount = 0;
	objStackObjects.PreviousMemoryUsage.DiamAVPReleaseCount = 0;
	objStackObjects.PreviousMemoryUsage.DiamCDataAllocatedCount = 0;
	objStackObjects.PreviousMemoryUsage.DiamCDataReleaseCount = 0;
	objStackObjects.PreviousMemoryUsage.DecodeThreadAllocatedCount = 0;
	objStackObjects.PreviousMemoryUsage.DecodeThreadReleaseCount = 0;	
	objStackObjects.PreviousMemoryUsage.DecodeThreadRejectedCount = 0;
	objStackObjects.PreviousMemoryUsage.SocketReadCount = 0;
	objStackObjects.PreviousMemoryUsage.SocketWriteCount = 0;
	objStackObjects.PreviousMemoryUsage.QueueRecordAllocatedCount = 0;
	objStackObjects.PreviousMemoryUsage.QueueRecordReleasedCount = 0;
	objStackObjects.PreviousMemoryUsage.DiamRoutePoolAllocatedCount = 0;
	objStackObjects.PreviousMemoryUsage.DiamRoutePoolReleasedCount = 0;			
	objStackObjects.PreviousMemoryUsage.UnableToDeliverInvalidClientObject = 0;
	objStackObjects.PreviousMemoryUsage.UnableToDeliverInvalidActiveState = 0;
	objStackObjects.PreviousMemoryUsage.UnableToDeliverInvalidLength = 0;
	

	
		
	objStackConfig.QueueMode = 1;	
	objStackConfig.EnablePerformaceThread = 0;
	memset( &objStackConfig.SimulateDestinationRelam, 0, sizeof(objStackConfig.SimulateDestinationRelam));

	pthread_mutex_init( &objStackConfig.SessionIdLock, NULL);
	pthread_mutex_init( &objStackConfig.HBHLock, NULL);		
	pthread_mutex_init( &objStackObjects.RealmTableLock, NULL);

	
	

	ix = 0;
	for( ix = 0; ix < 36; ix++)
	{
		objStackConfig.Peers[ix].MessagesRouted = 0;
		objStackConfig.Peers[ix].iResponseNo = 0;
	}
	
	objStackConfig.MessageRoutingMode = 0;
	objStackConfig.LicenseFileFound = 0;
	objStackConfig.HashCharLength = 10;
	
	char logsPath[400] = {0};
	memset( &logsPath, 0 , sizeof(logsPath));

	objStackConfig.ConfigPort = -1;
	objStackConfig.Port = -1;

	if( core_bConfigFileAvailable == 0)
	{
		return;
	}
	
	FILE *file = NULL;
	file = fopen( configFileName, "r");

	//if (file != NULL)
	if (file)	
	{
		char line[MAXBUF];
		//int i = 0;
		char cfKey[30]={0};
		char *cfline;

		while(fgets( line, sizeof(line), file) != NULL)
		{
			/*
			cfline = NULL;

			memset(cfKey,0,sizeof(cfKey));
			cfline = strstr((char *)line,DELIM);
			cfline = cfline + strlen(DELIM);

			strncpy((char*)cfKey,(char *)line,(cfline-line));

			cfKey[cfline-line-1]='\0';
			*/
			
			cfline = NULL;

			memset(cfKey,0,sizeof(cfKey));
			cfline = strstr((char *)line,DELIM);
			
			if( cfline)
			{	
				cfline = cfline + strlen(DELIM);

				if( strlen( cfline) > 0)
				{
					strncpy((char*)cfKey,(char *)line,(cfline-line));
					cfKey[ cfline-line-1]='\0';
				}
				else
				{
					continue;
				}
			}
			else
			{
				continue;
			}

			if( strcmp( (char*) "HOSTNAME", cfKey) == 0)
			{
				memcpy( objStackConfig.HostName, cfline, (strlen(cfline)-1));
				printf( "HostName[%s]\n", objStackConfig.HostName);
			}
			else if( strcmp( (char*) "LOGS_PATH", cfKey) == 0)
			{
				memcpy( logsPath, cfline, (strlen(cfline)-1));

				sprintf( objStackObjects.LoggerConfig[0].Path, "%s%s", logsPath, "stacklogs");
				sprintf( objStackObjects.LoggerConfig[1].Path, "%s%s", logsPath, "perflogs");
				sprintf( objStackObjects.LoggerConfig[2].Path, "%s%s", logsPath, "applogs");
				
				printf( "LOGS_PATH[%s]\n", logsPath);
			}
			else if( strcmp( (char*) "LOGS_PATH_STK", cfKey) == 0)
			{
				memcpy( logsPath, cfline, (strlen(cfline)-1));
				sprintf( objStackObjects.LoggerConfig[0].Path, "%s%s", logsPath, "");
			}
			else if( strcmp( (char*) "LOGS_PATH_PERF", cfKey) == 0)
			{
				memcpy( logsPath, cfline, (strlen(cfline)-1));
				sprintf( objStackObjects.LoggerConfig[1].Path, "%s%s", logsPath, "");
			}
			else if( strcmp( (char*) "LOGS_PATH_APP", cfKey) == 0)
			{
				memcpy( logsPath, cfline, (strlen(cfline)-1));
				sprintf( objStackObjects.LoggerConfig[2].Path, "%s%s", logsPath, "");
			}
			else if( strcmp( (char*) "LOGS_PATH_CSV", cfKey) == 0)
			{
				memcpy( logsPath, cfline, (strlen(cfline)-1));
				sprintf( objStackObjects.LoggerConfig[3].Path, "%s%s", logsPath, "");
			}
			else if( strcmp( (char*) "STK_LOG_LEVEL", cfKey) == 0)
			{
				objStackObjects.LoggerConfig[0].iLoggingThreshold = atoi(cfline);
				printf( "STK_LOG_LEVEL[%d]\n", objStackObjects.LoggerConfig[0].iLoggingThreshold);
			}
			else if( strcmp( (char*) "CHECK_SOCKET_BEFORE_SEND", cfKey) == 0)
			{
				objStackConfig.CheckSocketBeforeSend = atoi(cfline);
				printf( "CHECK_SOCKET_BEFORE_SEND[%d]\n", objStackConfig.CheckSocketBeforeSend);
			}
			else if( strcmp( (char*) "DRA_ROUTING_MODULE", cfKey) == 0)
			{
				objStackConfig.DRARoutingModule = atoi(cfline);
				printf( "DRA_ROUTING_MODULE[%d]\n", objStackConfig.DRARoutingModule);
			}
			else if( strcmp( (char*) "APP_LOG_LEVEL", cfKey) == 0)
			{
				objStackObjects.LoggerConfig[2].iLoggingThreshold = atoi(cfline);
				printf( "APP_LOG_LEVEL[%d]\n", objStackObjects.LoggerConfig[2].iLoggingThreshold);
			}
			else if( strcmp( (char*) "ENABLEDISABLE_CSV_LOG", cfKey) == 0)
			{
				objStackObjects.LoggerConfig[3].Enabled = atoi(cfline);
				printf( "ENABLEDISABLE_CSV_LOG[%d]\n", objStackObjects.LoggerConfig[3].Enabled);
			}
			else if( strcmp( (char*) "WATCH_DOG_TIMER", cfKey) == 0)
			{
				objStackConfig.WatchDogRequestInterval = atoi(cfline);
				
				if( objStackConfig.WatchDogRequestInterval < 10 || objStackConfig.WatchDogRequestInterval > 30)
				{
					objStackConfig.WatchDogRequestInterval = 12;
					printf( "WATCH_DOG_TIMER[%d] Defaulted\n", objStackConfig.WatchDogRequestInterval);
				}
				else
				{
					printf( "WATCH_DOG_TIMER[%d]\n", objStackConfig.WatchDogRequestInterval);
				}
			}
			else if( strcmp( (char*) "LAST_CHAR_LENGTH_FORHASH", cfKey) == 0)
			{
				objStackConfig.HashCharLength = atoi(cfline);
				printf( "LAST_CHAR_LENGTH_FORHASH[%d]\n", objStackConfig.HashCharLength);
			}
			else if( strcmp( (char*) "ENABLEDISABLE_PERF_LOG", cfKey) == 0)
			{
				objStackObjects.LoggerConfig[1].Enabled = atoi(cfline);
				printf( "ENABLEDISABLE_PERF_LOG[%d]\n", objStackObjects.LoggerConfig[1].Enabled);
			}
			else if( strcmp( (char*) "RECONNECT_SECONDS", cfKey) == 0)
			{
				objStackConfig.ReConnectSeconds = atoi(cfline);
				printf( "RECONNECT_SECONDS[%d]\n", objStackConfig.ReConnectSeconds);
			}
			else if( strcmp( (char*) "ACCEPT_UNKNOWN_CLIENT", cfKey) == 0)
			{
				objStackConfig.AcceptUnknownClinet = atoi(cfline);
				printf( "ACCEPT_UNKNOWN_CLIENT[%d]\n", objStackConfig.AcceptUnknownClinet );
			}
			else if( strcmp( (char*) "MESSAGE_ROUTING_MODE", cfKey) == 0)
			{
				objStackConfig.MessageRoutingMode = atoi(cfline);
				printf( "MESSAGE_ROUTING_MODE[%d]\n", objStackConfig.MessageRoutingMode );
			}
			else if( strcmp( (char*) "IMSI_RANGE_ROUTING_INFO_1", cfKey) == 0)
			{
				printf( "IMSI_RANGE_ROUTING_INFO_1[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMSIRouting[0], cfline);
			}
			else if( strcmp( (char*) "IMSI_RANGE_ROUTING_INFO_2", cfKey) == 0)
			{
				printf( "IMSI_RANGE_ROUTING_INFO_2[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMSIRouting[1], cfline);
			}
			else if( strcmp( (char*) "IMSI_RANGE_ROUTING_INFO_3", cfKey) == 0)
			{
				printf( "IMSI_RANGE_ROUTING_INFO_3[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMSIRouting[2], cfline);
			}
			else if( strcmp( (char*) "IMSI_RANGE_ROUTING_INFO_4", cfKey) == 0)
			{
				printf( "IMSI_RANGE_ROUTING_INFO_4[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMSIRouting[3], cfline);
			}
			else if( strcmp( (char*) "IMSI_RANGE_ROUTING_INFO_5", cfKey) == 0)
			{
				printf( "IMSI_RANGE_ROUTING_INFO_5[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMSIRouting[4], cfline);
			}
			else if( strcmp( (char*) "MSISDN_RANGE_ROUTING_INFO_1", cfKey) == 0)
			{
				printf( "MSISDN_RANGE_ROUTING_INFO_1[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.MSISDNRouting[0], cfline);
			}
			else if( strcmp( (char*) "MSISDN_RANGE_ROUTING_INFO_2", cfKey) == 0)
			{
				printf( "MSISDN_RANGE_ROUTING_INFO_2[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.MSISDNRouting[1], cfline);
			}
			else if( strcmp( (char*) "MSISDN_RANGE_ROUTING_INFO_3", cfKey) == 0)
			{
				printf( "MSISDN_RANGE_ROUTING_INFO_3[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.MSISDNRouting[2], cfline);
			}
			else if( strcmp( (char*) "MSISDN_RANGE_ROUTING_INFO_4", cfKey) == 0)
			{
				printf( "MSISDN_RANGE_ROUTING_INFO_4[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.MSISDNRouting[3], cfline);
			}
			else if( strcmp( (char*) "MSISDN_RANGE_ROUTING_INFO_5", cfKey) == 0)
			{
				printf( "MSISDN_RANGE_ROUTING_INFO_5[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.MSISDNRouting[4], cfline);
			}
			else if( strcmp( (char*) "IMEI_RANGE_ROUTING_INFO_1", cfKey) == 0)
			{
				printf( "IMEI_RANGE_ROUTING_INFO_1[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMEIRouting[0], cfline);
			}
			else if( strcmp( (char*) "IMEI_RANGE_ROUTING_INFO_2", cfKey) == 0)
			{
				printf( "IMEI_RANGE_ROUTING_INFO_2[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMEIRouting[1], cfline);
			}
			else if( strcmp( (char*) "IMEI_RANGE_ROUTING_INFO_3", cfKey) == 0)
			{
				printf( "IMEI_RANGE_ROUTING_INFO_3[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMEIRouting[2], cfline);
			}
			else if( strcmp( (char*) "IMEI_RANGE_ROUTING_INFO_4", cfKey) == 0)
			{
				printf( "IMEI_RANGE_ROUTING_INFO_4[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMEIRouting[3], cfline);
			}
			else if( strcmp( (char*) "IMEI_RANGE_ROUTING_INFO_5", cfKey) == 0)
			{
				printf( "IMEI_RANGE_ROUTING_INFO_5[%s]\n", cfline );
				parseRoutingInfo( &objStackConfig.IMEIRouting[4], cfline);
			}
			else if( strcmp( (char*) "CONFIG_PORT", cfKey) == 0)
			{
				objStackConfig.ConfigPort = atoi(cfline);
				printf( "CONFIG_PORT[%d]\n", objStackConfig.ConfigPort);
			}
			else if( strcmp( (char*) "HOSTIP", cfKey) == 0)
			{
				memcpy( objStackConfig.IP, cfline, (strlen(cfline)-1));
				printf( "IP[%s]\n", objStackConfig.IP);
			}
			else if( strcmp( (char*) "HOSTIP_2", cfKey) == 0)
			{
				memcpy( objStackConfig.IP2, cfline, (strlen(cfline)-1));
				printf( "HOSTIP_2[%s]\n", objStackConfig.IP2);
			}
			else if( strcmp( (char*) "HOSTIP_3", cfKey) == 0)
			{
				memcpy( objStackConfig.IP3, cfline, (strlen(cfline)-1));
				printf( "HOSTIP_3[%s]\n", objStackConfig.IP3);
			}
			else if( strcmp( (char*) "HOSTIP_4", cfKey) == 0)
			{
				memcpy( objStackConfig.IP4, cfline, (strlen(cfline)-1));
				printf( "HOSTIP_4[%s]\n", objStackConfig.IP4);
			}
			else if( strcmp( (char*) "HOSTIP_5", cfKey) == 0)
			{
				memcpy( objStackConfig.IP5, cfline, (strlen(cfline)-1));
				printf( "HOSTIP_5[%s]\n", objStackConfig.IP5);
			}
			else if( strcmp( (char*) "SCTP_MULTI_HOME", cfKey) == 0)
			{
				objStackConfig.MultiHome = atoi(cfline);
				printf( "SCTP_MULTI_HOME[%d]\n", objStackConfig.MultiHome);
			}
			else if( strcmp( (char*) "SCTP_MULTI_HOME_AND_REQUIRED_BIND", cfKey) == 0)
			{
				objStackConfig.MultiHomeAndRequiredBind = atoi(cfline);
				printf( "SCTP_MULTI_HOME_AND_REQUIRED_BIND[%d]\n", objStackConfig.MultiHomeAndRequiredBind);
			}
			else if( strcmp( (char*) "SCTP_MULTI_HOME_IP_COUNT", cfKey) == 0)
			{
				objStackConfig.MultiHomeIpCount = atoi(cfline);
				printf( "SCTP_MULTI_HOME_IP_COUNT[%d]\n", objStackConfig.MultiHomeIpCount);
			}
			else if( strcmp( (char*) "SCTP_ENABLE_STREAM_INFO", cfKey) == 0)
			{
				objStackConfig.SctpEnableStreamInfo = atoi(cfline);
				printf( "SCTP_ENABLE_STREAM_INFO[%d]\n", objStackConfig.SctpEnableStreamInfo);
			}			
			else if( strcmp( (char*) "HOSTREALM", cfKey) == 0)
			{
				memcpy( objStackConfig.HostRealmName, cfline, (strlen(cfline)-1));
				printf( "HOSTREALM[%s]\n", objStackConfig.HostRealmName);
			}
			else if( strcmp( (char*) "HOST_TRANSPORT_TYPE", cfKey) == 0)
			{
				objStackConfig.HostTransportType = atoi(cfline);
				printf( "HOST_TRANSPORT_TYPE[%d]\n", objStackConfig.HostTransportType);
			}
			else if( strcmp( (char*) "PORT", cfKey) == 0)
			{
				objStackConfig.Port = atoi(cfline);
				printf( "PORT[%d]\n", objStackConfig.Port);
			}
			else if( strcmp( (char*) "HOST_PORT_1", cfKey) == 0)
			{
				objStackConfig.HostPort[0] = atoi(cfline);
				printf( "HOST_PORT_1[%d]\n", objStackConfig.HostPort[0]);
				objStackConfig.HostPortCount++;
			}			
			else if( strcmp( (char*) "HOST_PORT_2", cfKey) == 0)
			{
				objStackConfig.HostPort[1] = atoi(cfline);
				printf( "HOST_PORT_2[%d]\n", objStackConfig.HostPort[1]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "HOST_PORT_3", cfKey) == 0)
			{
				objStackConfig.HostPort[2] = atoi(cfline);
				printf( "HOST_PORT_3[%d]\n", objStackConfig.HostPort[2]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "HOST_PORT_4", cfKey) == 0)
			{
				objStackConfig.HostPort[3] = atoi(cfline);
				printf( "HOST_PORT_4[%d]\n", objStackConfig.HostPort[3]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "HOST_PORT_5", cfKey) == 0)
			{
				objStackConfig.HostPort[4] = atoi(cfline);
				printf( "HOST_PORT_5[%d]\n", objStackConfig.HostPort[4]);
				objStackConfig.HostPortCount++;
			}			
			else if( strcmp( (char*) "HOST_PORT_6", cfKey) == 0)
			{
				objStackConfig.HostPort[5] = atoi(cfline);
				printf( "HOST_PORT_6[%d]\n", objStackConfig.HostPort[5]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "HOST_PORT_7", cfKey) == 0)
			{
				objStackConfig.HostPort[6] = atoi(cfline);
				printf( "HOST_PORT_7[%d]\n", objStackConfig.HostPort[6]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "HOST_PORT_8", cfKey) == 0)
			{
				objStackConfig.HostPort[7] = atoi(cfline);
				printf( "HOST_PORT_8[%d]\n", objStackConfig.HostPort[7]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "HOST_PORT_9", cfKey) == 0)
			{
				objStackConfig.HostPort[8] = atoi(cfline);
				printf( "HOST_PORT_9[%d]\n", objStackConfig.HostPort[8]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "HOST_PORT_10", cfKey) == 0)
			{
				objStackConfig.HostPort[9] = atoi(cfline);
				printf( "HOST_PORT_10[%d]\n", objStackConfig.HostPort[9]);
				objStackConfig.HostPortCount++;
			}
			else if( strcmp( (char*) "NO_OF_DECODE_THREADS", cfKey) == 0)
			{
				objStackConfig.DecodeThreadPoolCount = atoi(cfline);
				printf( "NO_OF_DECODE_THREADS[%d]\n", objStackConfig.DecodeThreadPoolCount);
			}
			/*
			else if( strcmp( (char*) "NODE_TYPE", cfKey) == 0)
			{
				objStackConfig.NodeType = atoi(cfline);
				printf( "NODE_TYPE[%d]\n", objStackConfig.NodeType);
			}
			*/ 
			else if( strcmp( (char*) "NO_OF_PEERS", cfKey) == 0)
			{
				objStackConfig.NoOfPeers = atoi(cfline);
				printf( "NO_OF_PEERS[%d]\n", objStackConfig.NoOfPeers);
			}
			else if( strcmp( (char*) "NO_OF_CLIENTS", cfKey) == 0)
			{
				objStackConfig.NoOfClients = atoi(cfline);
				printf( "NO_OF_CLIENTS[%d]\n", objStackConfig.NoOfClients);
			}
			else if( strcmp( (char*) "NO_OF_APP_SUPPORTED", cfKey) == 0)
			{
				objStackConfig.NoOfAppSupported = atoi(cfline);
				printf( "NO_OF_APP_SUPPORTED[%d]\n", objStackConfig.NoOfAppSupported );
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_1", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[0] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_1[%d]\n", objStackConfig.SupportedAppIds[0]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_2", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[1] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_2[%d]\n", objStackConfig.SupportedAppIds[1]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_3", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[2] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_3[%d]\n", objStackConfig.SupportedAppIds[2]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_4", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[3] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_4[%d]\n", objStackConfig.SupportedAppIds[3]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_5", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[4] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_5[%d]\n", objStackConfig.SupportedAppIds[4]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_6", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[5] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_6[%d]\n", objStackConfig.SupportedAppIds[5]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_7", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[6] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_7[%d]\n", objStackConfig.SupportedAppIds[6]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_8", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[7] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_8[%d]\n", objStackConfig.SupportedAppIds[7]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_9", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[8] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_9[%d]\n", objStackConfig.SupportedAppIds[8]);
			}
			else if( strcmp( (char*) "SUPPORTED_APP_INTERFACE_10", cfKey) == 0)
			{
				objStackConfig.SupportedAppIds[9] = atoi(cfline);
				printf( "SUPPORTED_APP_INTERFACE_10[%d]\n", objStackConfig.SupportedAppIds[9]);
			}
			else if( strcmp( (char*) "VENDOR_ID", cfKey) == 0)
			{
				objStackConfig.VendorId = atoi(cfline);
				printf( "VENDOR_ID[%d]\n", objStackConfig.VendorId);
			}
			else if( strcmp( (char*) "PRODUCT_NAME", cfKey) == 0)
			{
				memcpy( objStackConfig.ProductName, cfline, (strlen(cfline)-1));
				printf( "PRODUCT_NAME[%s]\n", objStackConfig.ProductName);
			}
			
			else if( strcmp( (char*) "CLIENT_PORT_1", cfKey) == 0)
			{
				objStackConfig.Clients[0].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_1[%d]\n", objStackConfig.Clients[0].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_1", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[0].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_1[%s]\n", objStackConfig.Clients[0].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_1", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[0].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_1[%s]\n", objStackConfig.Clients[0].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_1", cfKey) == 0)
			{
				objStackConfig.Clients[0].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_1[%d]\n", objStackConfig.Clients[0].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_1", cfKey) == 0)
			{
				objStackConfig.Clients[0].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_1[%d]\n", objStackConfig.Clients[0].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_2", cfKey) == 0)
			{
				objStackConfig.Clients[1].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_2[%d]\n", objStackConfig.Clients[1].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_2", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[1].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_2[%s]\n", objStackConfig.Clients[1].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_2", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[1].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_2[%s]\n", objStackConfig.Clients[1].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_2", cfKey) == 0)
			{
				objStackConfig.Clients[1].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_2[%d]\n", objStackConfig.Clients[1].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_2", cfKey) == 0)
			{
				objStackConfig.Clients[1].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_2[%d]\n", objStackConfig.Clients[1].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_3", cfKey) == 0)
			{
				objStackConfig.Clients[2].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_3[%d]\n", objStackConfig.Clients[2].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_3", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[2].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_3[%s]\n", objStackConfig.Clients[2].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_3", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[2].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_3[%s]\n", objStackConfig.Clients[2].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_3", cfKey) == 0)
			{
				objStackConfig.Clients[2].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_3[%d]\n", objStackConfig.Clients[2].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_3", cfKey) == 0)
			{
				objStackConfig.Clients[2].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_3[%d]\n", objStackConfig.Clients[2].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_4", cfKey) == 0)
			{
				objStackConfig.Clients[3].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_4[%d]\n", objStackConfig.Clients[3].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_4", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[3].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_4[%s]\n", objStackConfig.Clients[3].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_4", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[3].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_4[%s]\n", objStackConfig.Clients[3].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_4", cfKey) == 0)
			{
				objStackConfig.Clients[3].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_4[%d]\n", objStackConfig.Clients[3].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_4", cfKey) == 0)
			{
				objStackConfig.Clients[3].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_4[%d]\n", objStackConfig.Clients[3].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_5", cfKey) == 0)
			{
				objStackConfig.Clients[4].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_5[%d]\n", objStackConfig.Clients[4].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_5", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[4].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_5[%s]\n", objStackConfig.Clients[4].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_5", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[4].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_5[%s]\n", objStackConfig.Clients[4].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_5", cfKey) == 0)
			{
				objStackConfig.Clients[4].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_5[%d]\n", objStackConfig.Clients[4].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_5", cfKey) == 0)
			{
				objStackConfig.Clients[4].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_5[%d]\n", objStackConfig.Clients[4].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_6", cfKey) == 0)
			{
				objStackConfig.Clients[5].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_6[%d]\n", objStackConfig.Clients[5].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_6", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[5].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_6[%s]\n", objStackConfig.Clients[5].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_6", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[5].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_6[%s]\n", objStackConfig.Clients[5].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_6", cfKey) == 0)
			{
				objStackConfig.Clients[5].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_6[%d]\n", objStackConfig.Clients[5].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_6", cfKey) == 0)
			{
				objStackConfig.Clients[5].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_6[%d]\n", objStackConfig.Clients[5].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_7", cfKey) == 0)
			{
				objStackConfig.Clients[6].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_7[%d]\n", objStackConfig.Clients[6].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_7", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[6].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_7[%s]\n", objStackConfig.Clients[6].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_7", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[6].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_7[%s]\n", objStackConfig.Clients[6].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_7", cfKey) == 0)
			{
				objStackConfig.Clients[6].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_7[%d]\n", objStackConfig.Clients[6].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_7", cfKey) == 0)
			{
				objStackConfig.Clients[6].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_7[%d]\n", objStackConfig.Clients[6].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_8", cfKey) == 0)
			{
				objStackConfig.Clients[7].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_8[%d]\n", objStackConfig.Clients[7].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_8", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[7].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_8[%s]\n", objStackConfig.Clients[7].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_8", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[7].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_8[%s]\n", objStackConfig.Clients[7].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_8", cfKey) == 0)
			{
				objStackConfig.Clients[7].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_8[%d]\n", objStackConfig.Clients[7].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_8", cfKey) == 0)
			{
				objStackConfig.Clients[7].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_8[%d]\n", objStackConfig.Clients[7].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_9", cfKey) == 0)
			{
				objStackConfig.Clients[8].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_9[%d]\n", objStackConfig.Clients[8].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_9", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[8].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_9[%s]\n", objStackConfig.Clients[8].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_9", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[8].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_9[%s]\n", objStackConfig.Clients[8].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_9", cfKey) == 0)
			{
				objStackConfig.Clients[8].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_9[%d]\n", objStackConfig.Clients[8].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_9", cfKey) == 0)
			{
				objStackConfig.Clients[8].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_9[%d]\n", objStackConfig.Clients[8].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_10", cfKey) == 0)
			{
				objStackConfig.Clients[9].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_10[%d]\n", objStackConfig.Clients[9].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_10", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[9].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_10[%s]\n", objStackConfig.Clients[9].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_10", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[9].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_10[%s]\n", objStackConfig.Clients[9].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_10", cfKey) == 0)
			{
				objStackConfig.Clients[9].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_10[%d]\n", objStackConfig.Clients[9].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_10", cfKey) == 0)
			{
				objStackConfig.Clients[9].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_10[%d]\n", objStackConfig.Clients[9].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_11", cfKey) == 0)
			{
				objStackConfig.Clients[10].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_11[%d]\n", objStackConfig.Clients[10].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_11", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[10].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_11[%s]\n", objStackConfig.Clients[10].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_11", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[10].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_11[%s]\n", objStackConfig.Clients[10].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_11", cfKey) == 0)
			{
				objStackConfig.Clients[10].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_11[%d]\n", objStackConfig.Clients[10].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_11", cfKey) == 0)
			{
				objStackConfig.Clients[10].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_11[%d]\n", objStackConfig.Clients[10].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_12", cfKey) == 0)
			{
				objStackConfig.Clients[11].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_12[%d]\n", objStackConfig.Clients[11].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_12", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[11].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_12[%s]\n", objStackConfig.Clients[11].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_12", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[11].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_12[%s]\n", objStackConfig.Clients[11].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_12", cfKey) == 0)
			{
				objStackConfig.Clients[11].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_12[%d]\n", objStackConfig.Clients[11].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_12", cfKey) == 0)
			{
				objStackConfig.Clients[11].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_12[%d]\n", objStackConfig.Clients[11].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_13", cfKey) == 0)
			{
				objStackConfig.Clients[12].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_13[%d]\n", objStackConfig.Clients[12].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_13", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[12].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_13[%s]\n", objStackConfig.Clients[12].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_13", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[12].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_13[%s]\n", objStackConfig.Clients[12].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_13", cfKey) == 0)
			{
				objStackConfig.Clients[12].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_13[%d]\n", objStackConfig.Clients[12].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_13", cfKey) == 0)
			{
				objStackConfig.Clients[12].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_13[%d]\n", objStackConfig.Clients[12].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_14", cfKey) == 0)
			{
				objStackConfig.Clients[13].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_14[%d]\n", objStackConfig.Clients[13].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_14", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[13].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_14[%s]\n", objStackConfig.Clients[13].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_14", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[13].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_14[%s]\n", objStackConfig.Clients[13].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_14", cfKey) == 0)
			{
				objStackConfig.Clients[13].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_14[%d]\n", objStackConfig.Clients[13].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_14", cfKey) == 0)
			{
				objStackConfig.Clients[13].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_14[%d]\n", objStackConfig.Clients[13].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_15", cfKey) == 0)
			{
				objStackConfig.Clients[14].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_15[%d]\n", objStackConfig.Clients[14].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_15", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[14].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_15[%s]\n", objStackConfig.Clients[14].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_15", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[14].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_15[%s]\n", objStackConfig.Clients[14].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_15", cfKey) == 0)
			{
				objStackConfig.Clients[14].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_15[%d]\n", objStackConfig.Clients[14].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_15", cfKey) == 0)
			{
				objStackConfig.Clients[14].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_15[%d]\n", objStackConfig.Clients[14].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_16", cfKey) == 0)
			{
				objStackConfig.Clients[15].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_16[%d]\n", objStackConfig.Clients[15].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_16", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[15].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_16[%s]\n", objStackConfig.Clients[15].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_16", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[15].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_16[%s]\n", objStackConfig.Clients[15].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_16", cfKey) == 0)
			{
				objStackConfig.Clients[15].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_16[%d]\n", objStackConfig.Clients[15].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_16", cfKey) == 0)
			{
				objStackConfig.Clients[15].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_16[%d]\n", objStackConfig.Clients[15].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_17", cfKey) == 0)
			{
				objStackConfig.Clients[16].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_17[%d]\n", objStackConfig.Clients[16].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_17", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[16].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_17[%s]\n", objStackConfig.Clients[16].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_17", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[16].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_17[%s]\n", objStackConfig.Clients[16].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_17", cfKey) == 0)
			{
				objStackConfig.Clients[16].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_17[%d]\n", objStackConfig.Clients[16].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_17", cfKey) == 0)
			{
				objStackConfig.Clients[16].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_17[%d]\n", objStackConfig.Clients[16].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_18", cfKey) == 0)
			{
				objStackConfig.Clients[17].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_18[%d]\n", objStackConfig.Clients[17].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_18", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[17].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_18[%s]\n", objStackConfig.Clients[17].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_18", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[17].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_18[%s]\n", objStackConfig.Clients[17].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_18", cfKey) == 0)
			{
				objStackConfig.Clients[17].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_18[%d]\n", objStackConfig.Clients[17].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_18", cfKey) == 0)
			{
				objStackConfig.Clients[17].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_18[%d]\n", objStackConfig.Clients[17].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_19", cfKey) == 0)
			{
				objStackConfig.Clients[18].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_19[%d]\n", objStackConfig.Clients[18].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_19", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[18].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_19[%s]\n", objStackConfig.Clients[18].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_19", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[18].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_19[%s]\n", objStackConfig.Clients[18].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_19", cfKey) == 0)
			{
				objStackConfig.Clients[18].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_19[%d]\n", objStackConfig.Clients[18].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_19", cfKey) == 0)
			{
				objStackConfig.Clients[18].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_19[%d]\n", objStackConfig.Clients[18].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_20", cfKey) == 0)
			{
				objStackConfig.Clients[19].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_20[%d]\n", objStackConfig.Clients[19].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_20", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[19].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_20[%s]\n", objStackConfig.Clients[19].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_20", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[19].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_20[%s]\n", objStackConfig.Clients[19].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_20", cfKey) == 0)
			{
				objStackConfig.Clients[19].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_20[%d]\n", objStackConfig.Clients[19].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_20", cfKey) == 0)
			{
				objStackConfig.Clients[19].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_20[%d]\n", objStackConfig.Clients[19].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_21", cfKey) == 0)
			{
				objStackConfig.Clients[20].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_21[%d]\n", objStackConfig.Clients[20].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_21", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[20].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_21[%s]\n", objStackConfig.Clients[20].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_21", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[20].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_21[%s]\n", objStackConfig.Clients[20].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_21", cfKey) == 0)
			{
				objStackConfig.Clients[20].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_21[%d]\n", objStackConfig.Clients[20].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_21", cfKey) == 0)
			{
				objStackConfig.Clients[20].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_21[%d]\n", objStackConfig.Clients[20].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_22", cfKey) == 0)
			{
				objStackConfig.Clients[21].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_22[%d]\n", objStackConfig.Clients[21].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_22", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[21].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_22[%s]\n", objStackConfig.Clients[21].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_22", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[21].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_22[%s]\n", objStackConfig.Clients[21].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_22", cfKey) == 0)
			{
				objStackConfig.Clients[21].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_22[%d]\n", objStackConfig.Clients[21].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_22", cfKey) == 0)
			{
				objStackConfig.Clients[21].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_22[%d]\n", objStackConfig.Clients[21].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_23", cfKey) == 0)
			{
				objStackConfig.Clients[22].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_23[%d]\n", objStackConfig.Clients[22].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_23", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[22].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_23[%s]\n", objStackConfig.Clients[22].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_23", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[22].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_23[%s]\n", objStackConfig.Clients[22].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_23", cfKey) == 0)
			{
				objStackConfig.Clients[22].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_23[%d]\n", objStackConfig.Clients[22].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_23", cfKey) == 0)
			{
				objStackConfig.Clients[22].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_23[%d]\n", objStackConfig.Clients[22].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_24", cfKey) == 0)
			{
				objStackConfig.Clients[23].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_24[%d]\n", objStackConfig.Clients[23].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_24", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[23].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_24[%s]\n", objStackConfig.Clients[23].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_24", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[23].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_24[%s]\n", objStackConfig.Clients[23].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_24", cfKey) == 0)
			{
				objStackConfig.Clients[23].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_24[%d]\n", objStackConfig.Clients[23].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_24", cfKey) == 0)
			{
				objStackConfig.Clients[23].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_24[%d]\n", objStackConfig.Clients[23].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_25", cfKey) == 0)
			{
				objStackConfig.Clients[24].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_25[%d]\n", objStackConfig.Clients[24].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_25", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[24].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_25[%s]\n", objStackConfig.Clients[24].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_25", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[24].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_25[%s]\n", objStackConfig.Clients[24].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_25", cfKey) == 0)
			{
				objStackConfig.Clients[24].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_25[%d]\n", objStackConfig.Clients[24].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_25", cfKey) == 0)
			{
				objStackConfig.Clients[24].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_25[%d]\n", objStackConfig.Clients[24].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_26", cfKey) == 0)
			{
				objStackConfig.Clients[25].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_26[%d]\n", objStackConfig.Clients[25].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_26", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[25].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_26[%s]\n", objStackConfig.Clients[25].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_26", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[25].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_26[%s]\n", objStackConfig.Clients[25].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_26", cfKey) == 0)
			{
				objStackConfig.Clients[25].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_26[%d]\n", objStackConfig.Clients[25].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_26", cfKey) == 0)
			{
				objStackConfig.Clients[25].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_26[%d]\n", objStackConfig.Clients[25].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_27", cfKey) == 0)
			{
				objStackConfig.Clients[26].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_27[%d]\n", objStackConfig.Clients[26].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_27", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[26].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_27[%s]\n", objStackConfig.Clients[26].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_27", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[26].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_27[%s]\n", objStackConfig.Clients[26].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_27", cfKey) == 0)
			{
				objStackConfig.Clients[26].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_27[%d]\n", objStackConfig.Clients[26].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_27", cfKey) == 0)
			{
				objStackConfig.Clients[26].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_27[%d]\n", objStackConfig.Clients[26].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_28", cfKey) == 0)
			{
				objStackConfig.Clients[27].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_28[%d]\n", objStackConfig.Clients[27].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_28", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[27].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_28[%s]\n", objStackConfig.Clients[27].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_28", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[27].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_28[%s]\n", objStackConfig.Clients[27].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_28", cfKey) == 0)
			{
				objStackConfig.Clients[27].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_28[%d]\n", objStackConfig.Clients[27].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_28", cfKey) == 0)
			{
				objStackConfig.Clients[27].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_28[%d]\n", objStackConfig.Clients[27].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_29", cfKey) == 0)
			{
				objStackConfig.Clients[28].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_29[%d]\n", objStackConfig.Clients[28].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_29", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[28].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_29[%s]\n", objStackConfig.Clients[28].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_29", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[28].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_29[%s]\n", objStackConfig.Clients[28].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_29", cfKey) == 0)
			{
				objStackConfig.Clients[28].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_29[%d]\n", objStackConfig.Clients[28].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_29", cfKey) == 0)
			{
				objStackConfig.Clients[28].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_29[%d]\n", objStackConfig.Clients[28].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_30", cfKey) == 0)
			{
				objStackConfig.Clients[29].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_30[%d]\n", objStackConfig.Clients[29].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_30", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[29].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_30[%s]\n", objStackConfig.Clients[29].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_30", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[29].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_30[%s]\n", objStackConfig.Clients[29].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_30", cfKey) == 0)
			{
				objStackConfig.Clients[29].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_30[%d]\n", objStackConfig.Clients[29].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_30", cfKey) == 0)
			{
				objStackConfig.Clients[29].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_30[%d]\n", objStackConfig.Clients[29].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_31", cfKey) == 0)
			{
				objStackConfig.Clients[30].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_31[%d]\n", objStackConfig.Clients[30].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_31", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[30].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_31[%s]\n", objStackConfig.Clients[30].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_31", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[30].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_31[%s]\n", objStackConfig.Clients[30].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_31", cfKey) == 0)
			{
				objStackConfig.Clients[30].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_31[%d]\n", objStackConfig.Clients[30].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_31", cfKey) == 0)
			{
				objStackConfig.Clients[30].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_31[%d]\n", objStackConfig.Clients[30].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_32", cfKey) == 0)
			{
				objStackConfig.Clients[31].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_32[%d]\n", objStackConfig.Clients[31].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_32", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[31].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_32[%s]\n", objStackConfig.Clients[31].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_32", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[31].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_32[%s]\n", objStackConfig.Clients[31].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_32", cfKey) == 0)
			{
				objStackConfig.Clients[31].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_32[%d]\n", objStackConfig.Clients[31].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_32", cfKey) == 0)
			{
				objStackConfig.Clients[31].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_32[%d]\n", objStackConfig.Clients[31].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_33", cfKey) == 0)
			{
				objStackConfig.Clients[32].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_33[%d]\n", objStackConfig.Clients[32].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_33", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[32].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_33[%s]\n", objStackConfig.Clients[32].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_33", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[32].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_33[%s]\n", objStackConfig.Clients[32].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_33", cfKey) == 0)
			{
				objStackConfig.Clients[32].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_33[%d]\n", objStackConfig.Clients[32].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_33", cfKey) == 0)
			{
				objStackConfig.Clients[32].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_33[%d]\n", objStackConfig.Clients[32].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_34", cfKey) == 0)
			{
				objStackConfig.Clients[33].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_34[%d]\n", objStackConfig.Clients[33].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_34", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[33].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_34[%s]\n", objStackConfig.Clients[33].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_34", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[33].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_34[%s]\n", objStackConfig.Clients[33].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_34", cfKey) == 0)
			{
				objStackConfig.Clients[33].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_34[%d]\n", objStackConfig.Clients[33].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_34", cfKey) == 0)
			{
				objStackConfig.Clients[33].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_34[%d]\n", objStackConfig.Clients[33].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_35", cfKey) == 0)
			{
				objStackConfig.Clients[34].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_35[%d]\n", objStackConfig.Clients[34].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_35", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[34].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_35[%s]\n", objStackConfig.Clients[34].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_35", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[34].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_35[%s]\n", objStackConfig.Clients[34].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_35", cfKey) == 0)
			{
				objStackConfig.Clients[34].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_35[%d]\n", objStackConfig.Clients[34].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_35", cfKey) == 0)
			{
				objStackConfig.Clients[34].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_35[%d]\n", objStackConfig.Clients[34].iConnectToClient);
			}
			else if( strcmp( (char*) "CLIENT_PORT_36", cfKey) == 0)
			{
				objStackConfig.Clients[35].ClientPort = atoi(cfline);
				printf( "CLIENT_PORT_36[%d]\n", objStackConfig.Clients[35].ClientPort);
			}
			else if( strcmp( (char*) "CLIENT_HOSTNAME_36", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[35].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTNAME_36[%s]\n", objStackConfig.Clients[35].ClientHostName);
			}
			else if( strcmp( (char*) "CLIENT_HOSTREALM_36", cfKey) == 0)
			{
				memcpy( objStackConfig.Clients[35].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "CLIENT_HOSTREALM_36[%s]\n", objStackConfig.Clients[35].ClientHostRealmName);
			}
			else if( strcmp( (char*) "CLIENT_INTERFACE_36", cfKey) == 0)
			{
				objStackConfig.Clients[35].AppId = atoi(cfline);
				printf( "CLIENT_INTERFACE_36[%d]\n", objStackConfig.Clients[35].AppId);
			}
			else if( strcmp( (char*) "CONNECT_TO_CLIENT_36", cfKey) == 0)
			{
				objStackConfig.Clients[35].iConnectToClient = atoi(cfline);
				printf( "CONNECT_TO_CLIENT_36[%d]\n", objStackConfig.Clients[35].iConnectToClient);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_1", cfKey) == 0)
			{
				objStackConfig.Peers[0].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_1[%d]\n", objStackConfig.Peers[0].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_2", cfKey) == 0)
			{
				objStackConfig.Peers[1].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_2[%d]\n", objStackConfig.Peers[1].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_3", cfKey) == 0)
			{
				objStackConfig.Peers[2].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_3[%d]\n", objStackConfig.Peers[2].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_4", cfKey) == 0)
			{
				objStackConfig.Peers[3].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_4[%d]\n", objStackConfig.Peers[3].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_5", cfKey) == 0)
			{
				objStackConfig.Peers[4].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_5[%d]\n", objStackConfig.Peers[4].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_6", cfKey) == 0)
			{
				objStackConfig.Peers[5].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_6[%d]\n", objStackConfig.Peers[5].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_7", cfKey) == 0)
			{
				objStackConfig.Peers[6].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_7[%d]\n", objStackConfig.Peers[6].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_8", cfKey) == 0)
			{
				objStackConfig.Peers[7].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_8[%d]\n", objStackConfig.Peers[7].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_9", cfKey) == 0)
			{
				objStackConfig.Peers[8].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_9[%d]\n", objStackConfig.Peers[8].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_10", cfKey) == 0)
			{
				objStackConfig.Peers[9].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_10[%d]\n", objStackConfig.Peers[9].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_11", cfKey) == 0)
			{
				objStackConfig.Peers[10].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_11[%d]\n", objStackConfig.Peers[10].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_12", cfKey) == 0)
			{
				objStackConfig.Peers[11].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_12[%d]\n", objStackConfig.Peers[11].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_13", cfKey) == 0)
			{
				objStackConfig.Peers[12].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_13[%d]\n", objStackConfig.Peers[12].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_14", cfKey) == 0)
			{
				objStackConfig.Peers[13].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_14[%d]\n", objStackConfig.Peers[13].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_15", cfKey) == 0)
			{
				objStackConfig.Peers[14].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_15[%d]\n", objStackConfig.Peers[14].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_16", cfKey) == 0)
			{
				objStackConfig.Peers[15].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_16[%d]\n", objStackConfig.Peers[15].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_17", cfKey) == 0)
			{
				objStackConfig.Peers[16].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_17[%d]\n", objStackConfig.Peers[16].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_18", cfKey) == 0)
			{
				objStackConfig.Peers[17].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_18[%d]\n", objStackConfig.Peers[17].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_19", cfKey) == 0)
			{
				objStackConfig.Peers[18].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_19[%d]\n", objStackConfig.Peers[18].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_20", cfKey) == 0)
			{
				objStackConfig.Peers[19].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_20[%d]\n", objStackConfig.Peers[19].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_21", cfKey) == 0)
			{
				objStackConfig.Peers[20].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_21[%d]\n", objStackConfig.Peers[20].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_22", cfKey) == 0)
			{
				objStackConfig.Peers[21].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_22[%d]\n", objStackConfig.Peers[21].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_23", cfKey) == 0)
			{
				objStackConfig.Peers[22].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_23[%d]\n", objStackConfig.Peers[22].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_24", cfKey) == 0)
			{
				objStackConfig.Peers[23].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_24[%d]\n", objStackConfig.Peers[23].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_25", cfKey) == 0)
			{
				objStackConfig.Peers[24].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_25[%d]\n", objStackConfig.Peers[24].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_26", cfKey) == 0)
			{
				objStackConfig.Peers[25].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_26[%d]\n", objStackConfig.Peers[25].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_27", cfKey) == 0)
			{
				objStackConfig.Peers[26].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_27[%d]\n", objStackConfig.Peers[26].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_28", cfKey) == 0)
			{
				objStackConfig.Peers[27].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_28[%d]\n", objStackConfig.Peers[27].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_29", cfKey) == 0)
			{
				objStackConfig.Peers[28].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_29[%d]\n", objStackConfig.Peers[28].TransportType);
			}
			else if( strcmp( (char*) "PEER_TRANSPORT_TYPE_30", cfKey) == 0)
			{
				objStackConfig.Peers[29].TransportType = atoi(cfline);
				printf( "PEER_TRANSPORT_TYPE_30[%d]\n", objStackConfig.Peers[29].TransportType);
			}			
			else if( strcmp( (char*) "PEER_IP_1", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[0].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_1[%s]\n", objStackConfig.Peers[0].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_2", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[1].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_2[%s]\n", objStackConfig.Peers[1].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_3", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[2].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_3[%s]\n", objStackConfig.Peers[2].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_4", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[3].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_4[%s]\n", objStackConfig.Peers[3].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_5", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[4].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_5[%s]\n", objStackConfig.Peers[4].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_6", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[5].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_6[%s]\n", objStackConfig.Peers[5].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_7", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[6].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_7[%s]\n", objStackConfig.Peers[6].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_8", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[7].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_8[%s]\n", objStackConfig.Peers[7].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_9", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[8].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_9[%s]\n", objStackConfig.Peers[8].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_10", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[9].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_10[%s]\n", objStackConfig.Peers[9].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_11", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[10].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_11[%s]\n", objStackConfig.Peers[10].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_12", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[11].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_12[%s]\n", objStackConfig.Peers[11].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_13", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[12].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_13[%s]\n", objStackConfig.Peers[12].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_14", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[13].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_14[%s]\n", objStackConfig.Peers[13].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_15", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[14].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_15[%s]\n", objStackConfig.Peers[14].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_16", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[15].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_16[%s]\n", objStackConfig.Peers[15].PeerIP);
			}			
			else if( strcmp( (char*) "PEER_IP_17", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[16].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_17[%s]\n", objStackConfig.Peers[16].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_18", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[17].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_18[%s]\n", objStackConfig.Peers[17].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_19", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[18].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_19[%s]\n", objStackConfig.Peers[18].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_20", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[19].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_20[%s]\n", objStackConfig.Peers[19].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_21", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[20].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_21[%s]\n", objStackConfig.Peers[20].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_22", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[21].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_22[%s]\n", objStackConfig.Peers[21].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_23", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[22].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_23[%s]\n", objStackConfig.Peers[22].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_24", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[23].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_24[%s]\n", objStackConfig.Peers[23].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_25", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[24].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_25[%s]\n", objStackConfig.Peers[24].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_26", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[25].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_26[%s]\n", objStackConfig.Peers[25].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_27", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[26].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_27[%s]\n", objStackConfig.Peers[26].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_28", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[27].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_28[%s]\n", objStackConfig.Peers[27].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_29", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[28].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_29[%s]\n", objStackConfig.Peers[28].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_30", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[29].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_30[%s]\n", objStackConfig.Peers[29].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_31", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[30].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_31[%s]\n", objStackConfig.Peers[30].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_32", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[31].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_32[%s]\n", objStackConfig.Peers[31].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_33", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[32].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_33[%s]\n", objStackConfig.Peers[32].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_34", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[33].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_34[%s]\n", objStackConfig.Peers[33].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_35", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[34].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_35[%s]\n", objStackConfig.Peers[34].PeerIP);
			}
			else if( strcmp( (char*) "PEER_IP_36", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[35].PeerIP, cfline, (strlen(cfline)-1));
				printf( "PEER_IP_36[%s]\n", objStackConfig.Peers[35].PeerIP);
			}
			else if( strcmp( (char*) "PEER_PORT_1", cfKey) == 0)
			{
				objStackConfig.Peers[0].PeerPort = atoi(cfline);
				printf( "PEER_PORT_1[%d]\n", objStackConfig.Peers[0].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_2", cfKey) == 0)
			{
				objStackConfig.Peers[1].PeerPort = atoi(cfline);
				printf( "PEER_PORT_2[%d]\n", objStackConfig.Peers[1].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_3", cfKey) == 0)
			{
				objStackConfig.Peers[2].PeerPort = atoi(cfline);
				printf( "PEER_PORT_3[%d]\n", objStackConfig.Peers[2].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_4", cfKey) == 0)
			{
				objStackConfig.Peers[3].PeerPort = atoi(cfline);
				printf( "PEER_PORT_4[%d]\n", objStackConfig.Peers[3].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_5", cfKey) == 0)
			{
				objStackConfig.Peers[4].PeerPort = atoi(cfline);
				printf( "PEER_PORT_5[%d]\n", objStackConfig.Peers[4].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_6", cfKey) == 0)
			{
				objStackConfig.Peers[5].PeerPort = atoi(cfline);
				printf( "PEER_PORT_6[%d]\n", objStackConfig.Peers[5].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_7", cfKey) == 0)
			{
				objStackConfig.Peers[6].PeerPort = atoi(cfline);
				printf( "PEER_PORT_7[%d]\n", objStackConfig.Peers[6].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_8", cfKey) == 0)
			{
				objStackConfig.Peers[7].PeerPort = atoi(cfline);
				printf( "PEER_PORT_8[%d]\n", objStackConfig.Peers[7].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_9", cfKey) == 0)
			{
				objStackConfig.Peers[8].PeerPort = atoi(cfline);
				printf( "PEER_PORT_9[%d]\n", objStackConfig.Peers[8].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_10", cfKey) == 0)
			{
				objStackConfig.Peers[9].PeerPort = atoi(cfline);
				printf( "PEER_PORT_10[%d]\n", objStackConfig.Peers[9].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_11", cfKey) == 0)
			{
				objStackConfig.Peers[10].PeerPort = atoi(cfline);
				printf( "PEER_PORT_11[%d]\n", objStackConfig.Peers[10].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_12", cfKey) == 0)
			{
				objStackConfig.Peers[11].PeerPort = atoi(cfline);
				printf( "PEER_PORT_12[%d]\n", objStackConfig.Peers[11].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_13", cfKey) == 0)
			{
				objStackConfig.Peers[12].PeerPort = atoi(cfline);
				printf( "PEER_PORT_13[%d]\n", objStackConfig.Peers[12].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_14", cfKey) == 0)
			{
				objStackConfig.Peers[13].PeerPort = atoi(cfline);
				printf( "PEER_PORT_14[%d]\n", objStackConfig.Peers[13].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_15", cfKey) == 0)
			{
				objStackConfig.Peers[14].PeerPort = atoi(cfline);
				printf( "PEER_PORT_15[%d]\n", objStackConfig.Peers[14].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_16", cfKey) == 0)
			{
				objStackConfig.Peers[15].PeerPort = atoi(cfline);
				printf( "PEER_PORT_16[%d]\n", objStackConfig.Peers[15].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_17", cfKey) == 0)
			{
				objStackConfig.Peers[16].PeerPort = atoi(cfline);
				printf( "PEER_PORT_17[%d]\n", objStackConfig.Peers[16].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_18", cfKey) == 0)
			{
				objStackConfig.Peers[17].PeerPort = atoi(cfline);
				printf( "PEER_PORT_18[%d]\n", objStackConfig.Peers[17].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_19", cfKey) == 0)
			{
				objStackConfig.Peers[18].PeerPort = atoi(cfline);
				printf( "PEER_PORT_19[%d]\n", objStackConfig.Peers[18].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_20", cfKey) == 0)
			{
				objStackConfig.Peers[19].PeerPort = atoi(cfline);
				printf( "PEER_PORT_20[%d]\n", objStackConfig.Peers[19].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_21", cfKey) == 0)
			{
				objStackConfig.Peers[20].PeerPort = atoi(cfline);
				printf( "PEER_PORT_21[%d]\n", objStackConfig.Peers[20].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_22", cfKey) == 0)
			{
				objStackConfig.Peers[21].PeerPort = atoi(cfline);
				printf( "PEER_PORT_22[%d]\n", objStackConfig.Peers[21].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_23", cfKey) == 0)
			{
				objStackConfig.Peers[22].PeerPort = atoi(cfline);
				printf( "PEER_PORT_23[%d]\n", objStackConfig.Peers[22].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_24", cfKey) == 0)
			{
				objStackConfig.Peers[23].PeerPort = atoi(cfline);
				printf( "PEER_PORT_24[%d]\n", objStackConfig.Peers[23].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_25", cfKey) == 0)
			{
				objStackConfig.Peers[24].PeerPort = atoi(cfline);
				printf( "PEER_PORT_25[%d]\n", objStackConfig.Peers[24].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_26", cfKey) == 0)
			{
				objStackConfig.Peers[25].PeerPort = atoi(cfline);
				printf( "PEER_PORT_26[%d]\n", objStackConfig.Peers[25].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_27", cfKey) == 0)
			{
				objStackConfig.Peers[26].PeerPort = atoi(cfline);
				printf( "PEER_PORT_27[%d]\n", objStackConfig.Peers[26].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_28", cfKey) == 0)
			{
				objStackConfig.Peers[27].PeerPort = atoi(cfline);
				printf( "PEER_PORT_28[%d]\n", objStackConfig.Peers[27].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_29", cfKey) == 0)
			{
				objStackConfig.Peers[28].PeerPort = atoi(cfline);
				printf( "PEER_PORT_29[%d]\n", objStackConfig.Peers[28].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_30", cfKey) == 0)
			{
				objStackConfig.Peers[29].PeerPort = atoi(cfline);
				printf( "PEER_PORT_30[%d]\n", objStackConfig.Peers[29].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_31", cfKey) == 0)
			{
				objStackConfig.Peers[30].PeerPort = atoi(cfline);
				printf( "PEER_PORT_31[%d]\n", objStackConfig.Peers[30].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_32", cfKey) == 0)
			{
				objStackConfig.Peers[31].PeerPort = atoi(cfline);
				printf( "PEER_PORT_32[%d]\n", objStackConfig.Peers[31].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_33", cfKey) == 0)
			{
				objStackConfig.Peers[32].PeerPort = atoi(cfline);
				printf( "PEER_PORT_33[%d]\n", objStackConfig.Peers[32].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_34", cfKey) == 0)
			{
				objStackConfig.Peers[33].PeerPort = atoi(cfline);
				printf( "PEER_PORT_34[%d]\n", objStackConfig.Peers[33].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_35", cfKey) == 0)
			{
				objStackConfig.Peers[34].PeerPort = atoi(cfline);
				printf( "PEER_PORT_35[%d]\n", objStackConfig.Peers[34].PeerPort);
			}
			else if( strcmp( (char*) "PEER_PORT_36", cfKey) == 0)
			{
				objStackConfig.Peers[35].PeerPort = atoi(cfline);
				printf( "PEER_PORT_36[%d]\n", objStackConfig.Peers[35].PeerPort);
			}
			
			else if( strcmp( (char*) "PEER_INTERFACE_1", cfKey) == 0)
			{
				objStackConfig.Peers[0].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_1[%d]\n", objStackConfig.Peers[0].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_2", cfKey) == 0)
			{
				objStackConfig.Peers[1].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_2[%d]\n", objStackConfig.Peers[1].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_3", cfKey) == 0)
			{
				objStackConfig.Peers[2].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_3[%d]\n", objStackConfig.Peers[2].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_4", cfKey) == 0)
			{
				objStackConfig.Peers[3].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_4[%d]\n", objStackConfig.Peers[3].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_5", cfKey) == 0)
			{
				objStackConfig.Peers[4].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_5[%d]\n", objStackConfig.Peers[4].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_6", cfKey) == 0)
			{
				objStackConfig.Peers[5].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_6[%d]\n", objStackConfig.Peers[5].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_7", cfKey) == 0)
			{
				objStackConfig.Peers[6].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_7[%d]\n", objStackConfig.Peers[6].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_8", cfKey) == 0)
			{
				objStackConfig.Peers[7].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_8[%d]\n", objStackConfig.Peers[7].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_9", cfKey) == 0)
			{
				objStackConfig.Peers[8].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_9[%d]\n", objStackConfig.Peers[8].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_10", cfKey) == 0)
			{
				objStackConfig.Peers[9].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_10[%d]\n", objStackConfig.Peers[9].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_11", cfKey) == 0)
			{
				objStackConfig.Peers[10].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_11[%d]\n", objStackConfig.Peers[10].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_12", cfKey) == 0)
			{
				objStackConfig.Peers[11].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_12[%d]\n", objStackConfig.Peers[11].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_13", cfKey) == 0)
			{
				objStackConfig.Peers[12].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_13[%d]\n", objStackConfig.Peers[12].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_14", cfKey) == 0)
			{
				objStackConfig.Peers[13].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_14[%d]\n", objStackConfig.Peers[13].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_15", cfKey) == 0)
			{
				objStackConfig.Peers[14].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_15[%d]\n", objStackConfig.Peers[14].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_16", cfKey) == 0)
			{
				objStackConfig.Peers[15].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_16[%d]\n", objStackConfig.Peers[15].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_17", cfKey) == 0)
			{
				objStackConfig.Peers[16].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_17[%d]\n", objStackConfig.Peers[16].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_18", cfKey) == 0)
			{
				objStackConfig.Peers[17].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_18[%d]\n", objStackConfig.Peers[17].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_19", cfKey) == 0)
			{
				objStackConfig.Peers[18].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_19[%d]\n", objStackConfig.Peers[18].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_20", cfKey) == 0)
			{
				objStackConfig.Peers[19].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_20[%d]\n", objStackConfig.Peers[19].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_21", cfKey) == 0)
			{
				objStackConfig.Peers[20].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_21[%d]\n", objStackConfig.Peers[20].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_22", cfKey) == 0)
			{
				objStackConfig.Peers[21].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_22[%d]\n", objStackConfig.Peers[21].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_23", cfKey) == 0)
			{
				objStackConfig.Peers[22].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_23[%d]\n", objStackConfig.Peers[22].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_24", cfKey) == 0)
			{
				objStackConfig.Peers[23].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_24[%d]\n", objStackConfig.Peers[23].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_25", cfKey) == 0)
			{
				objStackConfig.Peers[24].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_25[%d]\n", objStackConfig.Peers[24].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_26", cfKey) == 0)
			{
				objStackConfig.Peers[25].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_26[%d]\n", objStackConfig.Peers[25].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_27", cfKey) == 0)
			{
				objStackConfig.Peers[26].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_27[%d]\n", objStackConfig.Peers[26].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_28", cfKey) == 0)
			{
				objStackConfig.Peers[27].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_28[%d]\n", objStackConfig.Peers[27].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_29", cfKey) == 0)
			{
				objStackConfig.Peers[28].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_29[%d]\n", objStackConfig.Peers[28].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_30", cfKey) == 0)
			{
				objStackConfig.Peers[29].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_30[%d]\n", objStackConfig.Peers[29].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_31", cfKey) == 0)
			{
				objStackConfig.Peers[30].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_31[%d]\n", objStackConfig.Peers[30].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_32", cfKey) == 0)
			{
				objStackConfig.Peers[31].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_32[%d]\n", objStackConfig.Peers[31].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_33", cfKey) == 0)
			{
				objStackConfig.Peers[32].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_33[%d]\n", objStackConfig.Peers[32].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_34", cfKey) == 0)
			{
				objStackConfig.Peers[33].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_34[%d]\n", objStackConfig.Peers[33].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_35", cfKey) == 0)
			{
				objStackConfig.Peers[34].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_35[%d]\n", objStackConfig.Peers[34].AppId);
			}
			else if( strcmp( (char*) "PEER_INTERFACE_36", cfKey) == 0)
			{
				objStackConfig.Peers[35].AppId = atoi(cfline);
				objStackConfig.iLoadedPeerConfigCount++;
				printf( "PEER_INTERFACE_36[%d]\n", objStackConfig.Peers[35].AppId);
			}
			else if( strcmp( (char*) "PEER_CLIENT_1", cfKey) == 0)
			{
				printf( "PEER_CLIENT_1[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[0], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_2", cfKey) == 0)
			{
				printf( "PEER_CLIENT_2[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[1], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_3", cfKey) == 0)
			{
				printf( "PEER_CLIENT_3[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[2], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_4", cfKey) == 0)
			{
				printf( "PEER_CLIENT_4[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[3], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_5", cfKey) == 0)
			{
				printf( "PEER_CLIENT_5[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[4], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_6", cfKey) == 0)
			{
				printf( "PEER_CLIENT_6[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[5], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_7", cfKey) == 0)
			{
				printf( "PEER_CLIENT_7[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[6], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_8", cfKey) == 0)
			{
				printf( "PEER_CLIENT_8[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[7], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_9", cfKey) == 0)
			{
				printf( "PEER_CLIENT_9[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[8], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_10", cfKey) == 0)
			{
				printf( "PEER_CLIENT_10[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[9], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_11", cfKey) == 0)
			{
				printf( "PEER_CLIENT_11[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[10], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_12", cfKey) == 0)
			{
				printf( "PEER_CLIENT_12[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[11], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_13", cfKey) == 0)
			{
				printf( "PEER_CLIENT_13[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[12], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_14", cfKey) == 0)
			{
				printf( "PEER_CLIENT_14[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[13], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_15", cfKey) == 0)
			{
				printf( "PEER_CLIENT_15[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[14], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_16", cfKey) == 0)
			{
				printf( "PEER_CLIENT_16[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[15], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_17", cfKey) == 0)
			{
				printf( "PEER_CLIENT_17[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[16], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_18", cfKey) == 0)
			{
				printf( "PEER_CLIENT_18[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[17], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_19", cfKey) == 0)
			{
				printf( "PEER_CLIENT_19[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[18], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_20", cfKey) == 0)
			{
				printf( "PEER_CLIENT_20[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[19], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_21", cfKey) == 0)
			{
				printf( "PEER_CLIENT_21[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[20], cfline);
			}			
			else if( strcmp( (char*) "PEER_CLIENT_22", cfKey) == 0)
			{
				printf( "PEER_CLIENT_22[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[21], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_23", cfKey) == 0)
			{
				printf( "PEER_CLIENT_23[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[22], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_24", cfKey) == 0)
			{
				printf( "PEER_CLIENT_24[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[23], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_25", cfKey) == 0)
			{
				printf( "PEER_CLIENT_25[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[24], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_26", cfKey) == 0)
			{
				printf( "PEER_CLIENT_26[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[25], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_27", cfKey) == 0)
			{
				printf( "PEER_CLIENT_27[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[26], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_28", cfKey) == 0)
			{
				printf( "PEER_CLIENT_28[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[27], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_29", cfKey) == 0)
			{
				printf( "PEER_CLIENT_29[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[28], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_30", cfKey) == 0)
			{
				printf( "PEER_CLIENT_30[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[29], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_31", cfKey) == 0)
			{
				printf( "PEER_CLIENT_31[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[30], cfline);
			}			
			else if( strcmp( (char*) "PEER_CLIENT_32", cfKey) == 0)
			{
				printf( "PEER_CLIENT_32[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[31], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_33", cfKey) == 0)
			{
				printf( "PEER_CLIENT_33[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[32], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_34", cfKey) == 0)
			{
				printf( "PEER_CLIENT_34[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[33], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_35", cfKey) == 0)
			{
				printf( "PEER_CLIENT_35[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[34], cfline);
			}
			else if( strcmp( (char*) "PEER_CLIENT_36", cfKey) == 0)
			{
				printf( "PEER_CLIENT_36[%s]\n", cfline);
				parsePeerClientInfo( &objStackConfig.Peers[35], cfline);
			}
			
			else if( strcmp( (char*) "PEER_HOSTNAME_1", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[0].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_1[%s]\n", objStackConfig.Peers[0].PeerHostName);
			}			
			else if( strcmp( (char*) "PEER_HOSTNAME_2", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[1].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_2[%s]\n", objStackConfig.Peers[1].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_3", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[2].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_3[%s]\n", objStackConfig.Peers[2].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_4", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[3].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_4[%s]\n", objStackConfig.Peers[3].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_5", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[4].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_5[%s]\n", objStackConfig.Peers[4].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_6", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[5].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_6[%s]\n", objStackConfig.Peers[5].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_7", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[6].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_7[%s]\n", objStackConfig.Peers[6].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_8", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[7].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_8[%s]\n", objStackConfig.Peers[7].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_9", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[8].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_9[%s]\n", objStackConfig.Peers[8].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_10", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[9].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_10[%s]\n", objStackConfig.Peers[9].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_11", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[10].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_11[%s]\n", objStackConfig.Peers[10].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_12", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[11].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_12[%s]\n", objStackConfig.Peers[11].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_13", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[12].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_13[%s]\n", objStackConfig.Peers[12].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_14", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[13].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_14[%s]\n", objStackConfig.Peers[13].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_15", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[14].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_15[%s]\n", objStackConfig.Peers[14].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_16", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[15].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_16[%s]\n", objStackConfig.Peers[15].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_17", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[16].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_17[%s]\n", objStackConfig.Peers[16].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_18", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[17].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_18[%s]\n", objStackConfig.Peers[17].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_19", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[18].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_19[%s]\n", objStackConfig.Peers[18].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_20", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[19].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_20[%s]\n", objStackConfig.Peers[19].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_21", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[20].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_21[%s]\n", objStackConfig.Peers[20].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_22", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[21].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_22[%s]\n", objStackConfig.Peers[21].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_23", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[22].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_23[%s]\n", objStackConfig.Peers[22].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_24", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[23].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_24[%s]\n", objStackConfig.Peers[23].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_25", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[24].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_25[%s]\n", objStackConfig.Peers[24].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_26", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[25].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_26[%s]\n", objStackConfig.Peers[25].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_27", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[26].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_27[%s]\n", objStackConfig.Peers[26].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_28", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[27].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_28[%s]\n", objStackConfig.Peers[27].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_29", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[28].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_29[%s]\n", objStackConfig.Peers[28].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_30", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[29].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_30[%s]\n", objStackConfig.Peers[29].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_31", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[30].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_31[%s]\n", objStackConfig.Peers[30].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_32", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[31].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_32[%s]\n", objStackConfig.Peers[31].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_33", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[32].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_33[%s]\n", objStackConfig.Peers[32].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_34", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[33].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_34[%s]\n", objStackConfig.Peers[33].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_35", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[34].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_35[%s]\n", objStackConfig.Peers[34].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_HOSTNAME_36", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[35].PeerHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTNAME_36[%s]\n", objStackConfig.Peers[35].PeerHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_1", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[0].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_1[%s]\n", objStackConfig.Peers[0].ClientHostName);
			}			
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_2", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[1].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_2[%s]\n", objStackConfig.Peers[1].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_3", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[2].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_3[%s]\n", objStackConfig.Peers[2].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_4", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[3].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_4[%s]\n", objStackConfig.Peers[3].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_5", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[4].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_5[%s]\n", objStackConfig.Peers[4].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_6", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[5].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_6[%s]\n", objStackConfig.Peers[5].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_7", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[6].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_7[%s]\n", objStackConfig.Peers[6].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_8", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[7].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_8[%s]\n", objStackConfig.Peers[7].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_9", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[8].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_9[%s]\n", objStackConfig.Peers[8].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_10", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[9].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_10[%s]\n", objStackConfig.Peers[9].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_11", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[10].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_11[%s]\n", objStackConfig.Peers[10].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_12", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[11].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_12[%s]\n", objStackConfig.Peers[11].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_13", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[12].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_13[%s]\n", objStackConfig.Peers[12].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_14", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[13].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_14[%s]\n", objStackConfig.Peers[13].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_15", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[14].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_15[%s]\n", objStackConfig.Peers[14].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_16", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[15].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_16[%s]\n", objStackConfig.Peers[15].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_17", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[16].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_17[%s]\n", objStackConfig.Peers[16].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_18", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[17].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_18[%s]\n", objStackConfig.Peers[17].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_19", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[18].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_19[%s]\n", objStackConfig.Peers[18].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_20", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[19].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_20[%s]\n", objStackConfig.Peers[19].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_21", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[20].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_21[%s]\n", objStackConfig.Peers[20].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_22", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[21].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_22[%s]\n", objStackConfig.Peers[21].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_23", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[22].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_23[%s]\n", objStackConfig.Peers[22].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_24", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[23].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_24[%s]\n", objStackConfig.Peers[23].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_25", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[24].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_25[%s]\n", objStackConfig.Peers[24].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_26", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[25].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_26[%s]\n", objStackConfig.Peers[25].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_27", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[26].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_27[%s]\n", objStackConfig.Peers[26].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_28", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[27].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_28[%s]\n", objStackConfig.Peers[27].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_29", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[28].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_29[%s]\n", objStackConfig.Peers[28].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_30", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[29].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_30[%s]\n", objStackConfig.Peers[29].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_31", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[30].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_31[%s]\n", objStackConfig.Peers[30].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_32", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[31].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_32[%s]\n", objStackConfig.Peers[31].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_33", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[32].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_33[%s]\n", objStackConfig.Peers[32].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_34", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[33].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_34[%s]\n", objStackConfig.Peers[33].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_35", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[34].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_35[%s]\n", objStackConfig.Peers[34].ClientHostName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTNAME_36", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[35].ClientHostName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTNAME_36[%s]\n", objStackConfig.Peers[35].ClientHostName);
			}			
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_1", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[0].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_1[%s]\n", objStackConfig.Peers[0].ClientHostRealmName);
			}			
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_2", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[1].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_2[%s]\n", objStackConfig.Peers[1].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_3", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[2].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_3[%s]\n", objStackConfig.Peers[2].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_4", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[3].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_4[%s]\n", objStackConfig.Peers[3].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_5", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[4].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_5[%s]\n", objStackConfig.Peers[4].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_6", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[5].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_6[%s]\n", objStackConfig.Peers[5].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_7", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[6].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_7[%s]\n", objStackConfig.Peers[6].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_8", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[7].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_8[%s]\n", objStackConfig.Peers[7].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_9", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[8].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_9[%s]\n", objStackConfig.Peers[8].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_10", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[9].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_10[%s]\n", objStackConfig.Peers[9].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_11", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[10].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_11[%s]\n", objStackConfig.Peers[10].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_12", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[11].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_12[%s]\n", objStackConfig.Peers[11].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_13", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[12].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_13[%s]\n", objStackConfig.Peers[12].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_14", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[13].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_14[%s]\n", objStackConfig.Peers[13].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_15", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[14].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_15[%s]\n", objStackConfig.Peers[14].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_16", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[15].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_16[%s]\n", objStackConfig.Peers[15].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_17", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[16].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_17[%s]\n", objStackConfig.Peers[16].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_18", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[17].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_18[%s]\n", objStackConfig.Peers[17].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_19", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[18].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_19[%s]\n", objStackConfig.Peers[18].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_20", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[19].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_20[%s]\n", objStackConfig.Peers[19].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_21", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[20].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_21[%s]\n", objStackConfig.Peers[20].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_22", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[21].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_22[%s]\n", objStackConfig.Peers[21].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_23", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[22].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_23[%s]\n", objStackConfig.Peers[22].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_24", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[23].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_24[%s]\n", objStackConfig.Peers[23].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_25", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[24].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_25[%s]\n", objStackConfig.Peers[24].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_26", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[25].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_26[%s]\n", objStackConfig.Peers[25].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_27", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[26].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_27[%s]\n", objStackConfig.Peers[26].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_28", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[27].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_28[%s]\n", objStackConfig.Peers[27].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_29", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[28].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_29[%s]\n", objStackConfig.Peers[28].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_30", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[29].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_30[%s]\n", objStackConfig.Peers[29].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_31", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[30].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_31[%s]\n", objStackConfig.Peers[30].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_32", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[31].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_32[%s]\n", objStackConfig.Peers[31].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_33", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[32].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_33[%s]\n", objStackConfig.Peers[32].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_34", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[33].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_34[%s]\n", objStackConfig.Peers[33].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_35", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[34].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_35[%s]\n", objStackConfig.Peers[34].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_CLIENT_HOSTREALM_36", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[35].ClientHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_CLIENT_HOSTREALM_36[%s]\n", objStackConfig.Peers[35].ClientHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_1", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[0].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_1[%s]\n", objStackConfig.Peers[0].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_2", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[1].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_2[%s]\n", objStackConfig.Peers[1].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_3", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[2].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_3[%s]\n", objStackConfig.Peers[2].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_4", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[3].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_4[%s]\n", objStackConfig.Peers[3].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_5", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[4].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_5[%s]\n", objStackConfig.Peers[4].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_6", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[5].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_6[%s]\n", objStackConfig.Peers[5].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_7", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[6].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_7[%s]\n", objStackConfig.Peers[6].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_8", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[7].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_8[%s]\n", objStackConfig.Peers[7].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_9", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[8].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_9[%s]\n", objStackConfig.Peers[8].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_10", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[9].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_10[%s]\n", objStackConfig.Peers[9].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_11", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[10].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_11[%s]\n", objStackConfig.Peers[10].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_12", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[11].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_12[%s]\n", objStackConfig.Peers[11].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_13", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[12].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_13[%s]\n", objStackConfig.Peers[12].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_14", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[13].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_14[%s]\n", objStackConfig.Peers[13].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_15", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[14].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_15[%s]\n", objStackConfig.Peers[14].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_16", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[15].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_16[%s]\n", objStackConfig.Peers[15].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_17", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[16].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_17[%s]\n", objStackConfig.Peers[16].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_18", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[17].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_18[%s]\n", objStackConfig.Peers[17].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_19", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[18].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_19[%s]\n", objStackConfig.Peers[18].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_20", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[19].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_20[%s]\n", objStackConfig.Peers[19].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_21", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[20].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_21[%s]\n", objStackConfig.Peers[20].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_22", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[21].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_22[%s]\n", objStackConfig.Peers[21].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_23", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[22].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_23[%s]\n", objStackConfig.Peers[22].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_24", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[23].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_24[%s]\n", objStackConfig.Peers[23].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_25", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[24].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_25[%s]\n", objStackConfig.Peers[24].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_26", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[25].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_26[%s]\n", objStackConfig.Peers[25].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_27", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[26].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_27[%s]\n", objStackConfig.Peers[26].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_28", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[27].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_28[%s]\n", objStackConfig.Peers[27].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_29", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[28].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_29[%s]\n", objStackConfig.Peers[28].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_30", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[29].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_30[%s]\n", objStackConfig.Peers[29].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_31", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[30].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_31[%s]\n", objStackConfig.Peers[30].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_32", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[31].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_32[%s]\n", objStackConfig.Peers[31].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_33", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[32].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_33[%s]\n", objStackConfig.Peers[32].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_34", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[33].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_34[%s]\n", objStackConfig.Peers[33].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_35", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[34].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_35[%s]\n", objStackConfig.Peers[34].PeerHostRealmName);
			}
			else if( strcmp( (char*) "PEER_HOSTREALM_36", cfKey) == 0)
			{
				memcpy( objStackConfig.Peers[35].PeerHostRealmName, cfline, (strlen(cfline)-1));
				printf( "PEER_HOSTREALM_36[%s]\n", objStackConfig.Peers[35].PeerHostRealmName);
			}
			else if( strcmp( (char*) "SESSION_ID_FORMAT", cfKey) == 0)
			{
				memcpy( objStackConfig.SessionIdFormat, cfline, (strlen(cfline)-1));
				printf( "SESSION_ID_FORMAT[%s]\n", objStackConfig.SessionIdFormat);
			}
			else if( strcmp( (char*) "SESSION_ID_PREFIX", cfKey) == 0)
			{
				memcpy( objStackConfig.SessionIdPrefix, cfline, (strlen(cfline)-1));
				printf( "SESSION_ID_PREFIX[%s]\n", objStackConfig.SessionIdPrefix);
			}
			else if( strcmp( (char*) "SESSION_ID_SEG2_ROTAT_NO", cfKey) == 0)
			{
				objStackConfig.SessionIdRotNo = atoi(cfline);
				printf( "SESSION_ID_SEG2_ROTAT_NO[%d]\n", objStackConfig.SessionIdRotNo);
			}
			else if( strcmp( (char*) "SESSION_ID_SEG1_START_NO", cfKey) == 0)
			{
				objStackConfig.SessionIdSeg1StartNo = atol(cfline);
				printf( "SESSION_ID_SEG1_START_NO[%lu]\n", objStackConfig.SessionIdSeg1StartNo);
			}			
			else if( strcmp( (char*) "SESSION_ID_SEG2_START_NO", cfKey) == 0)
			{
				objStackConfig.SessionIdSeg2StartNo = atol(cfline);
				printf( "SESSION_ID_SEG2_START_NO[%lu]\n", objStackConfig.SessionIdSeg2StartNo);
			}
			else if( strcmp( (char*) "E2E_ID_START_NO", cfKey) == 0)
			{
				objStackConfig.E2EId = atol(cfline);
				printf( "E2E_ID_START_NO[%lu]\n", objStackConfig.E2EId);
			}
			else if( strcmp( (char*) "HBY_ID_START_NO", cfKey) == 0)
			{
				objStackConfig.HBHId = atol(cfline);
				printf( "HBY_ID_START_NO[%lu]\n", objStackConfig.HBHId);
			}
			else if( strcmp( (char*) "SIMULATE_DEST_REALM", cfKey) == 0)
			{
				memcpy( objStackConfig.SimulateDestinationRelam, cfline, (strlen(cfline)-1));
				printf( "SIMULATE_DEST_REALM[%s]\n", objStackConfig.SimulateDestinationRelam);
			}
			else if( strcmp( (char*) "ENABLE_PERF_THREAD", cfKey) == 0)
			{
				objStackConfig.EnablePerformaceThread = atol(cfline);
				printf( "ENABLE_PERF_THREAD[%d]\n", objStackConfig.EnablePerformaceThread);
			}
			else if( strcmp( (char*) "MSG_DIST_QUEUE_MODE", cfKey) == 0)
			{
				objStackConfig.QueueMode = atol(cfline);
				printf( "MSG_DIST_QUEUE_MODE[%d]\n", objStackConfig.QueueMode);
			}			
			else if( strcmp( (char*) "ROUTING_THREAD_COUNT", cfKey) == 0)
			{
				objStackConfig.RoutingThreadCount = atol(cfline);
				printf( "ROUTING_THREAD_COUNT[%d]\n", objStackConfig.RoutingThreadCount);
			}
			else if( strcmp( (char*) "BUFFER_SIZE", cfKey) == 0)
			{
				DIAM_BUFFER_SIZE_PER_REQUEST = atoi(cfline);
				printf( "BUFFER_SIZE[%d]\n", DIAM_BUFFER_SIZE_PER_REQUEST);
			}
			else if( strcmp( (char*) "LICENSE_FILE", cfKey) == 0)
			{
				objStackConfig.LicenseFileFound = 1;
				memcpy( objStackConfig.LICENSE_FILE, cfline, (strlen(cfline)-1));
				printf( "LICENSE_FILE[%s]\n", objStackConfig.LICENSE_FILE);
			}
			else if( strcmp( (char*) "MAC_ADDRESS_KEY", cfKey) == 0)
			{
				memcpy( objStackConfig.MAC_ADDRESS_KEY, cfline, (strlen(cfline)-1));
				printf( "MAC_ADDRESS_KEY[%s]\n", objStackConfig.MAC_ADDRESS_KEY);
			}
			else if( strcmp( (char*) "ENABLE_SERVICE_CONTEXT_BASED_ROUTING", cfKey) == 0)
			{
				objStackConfig.EnableServiceContextBasedRouting = atoi(cfline);
				printf( "ENABLE_SERVICE_CONTEXT_BASED_ROUTING[%d]\n", objStackConfig.EnableServiceContextBasedRouting);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_1", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[0].ServiceContext, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_1[%s]\n", objStackConfig.ServiceContextRoutingInfo[0].ServiceContext);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_1_APP_ID", cfKey) == 0)
			{
				objStackConfig.ServiceContextRoutingInfo[0].ServiceContextRoutingAppId = atoi(cfline);
				printf( "SERVICE_CONTEXT_1_APP_ID[%d]\n", objStackConfig.ServiceContextRoutingInfo[0].ServiceContextRoutingAppId);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_1_HOST_NAME", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[0].DestinationHostName, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_1_HOST_NAME[%s]\n", objStackConfig.ServiceContextRoutingInfo[0].DestinationHostName);
			}	
			else if( strcmp( (char*) "SERVICE_CONTEXT_2", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[1].ServiceContext, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_2[%s]\n", objStackConfig.ServiceContextRoutingInfo[1].ServiceContext);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_2_APP_ID", cfKey) == 0)
			{
				objStackConfig.ServiceContextRoutingInfo[1].ServiceContextRoutingAppId = atoi(cfline);
				printf( "SERVICE_CONTEXT_2_APP_ID[%d]\n", objStackConfig.ServiceContextRoutingInfo[1].ServiceContextRoutingAppId);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_2_HOST_NAME", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[1].DestinationHostName, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_2_HOST_NAME[%s]\n", objStackConfig.ServiceContextRoutingInfo[1].DestinationHostName);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_3", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[2].ServiceContext, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_3[%s]\n", objStackConfig.ServiceContextRoutingInfo[2].ServiceContext);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_3_APP_ID", cfKey) == 0)
			{
				objStackConfig.ServiceContextRoutingInfo[2].ServiceContextRoutingAppId = atoi(cfline);
				printf( "SERVICE_CONTEXT_3_APP_ID[%d]\n", objStackConfig.ServiceContextRoutingInfo[2].ServiceContextRoutingAppId);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_3_HOST_NAME", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[2].DestinationHostName, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_3_HOST_NAME[%s]\n", objStackConfig.ServiceContextRoutingInfo[2].DestinationHostName);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_4", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[3].ServiceContext, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_4[%s]\n", objStackConfig.ServiceContextRoutingInfo[3].ServiceContext);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_4_APP_ID", cfKey) == 0)
			{
				objStackConfig.ServiceContextRoutingInfo[3].ServiceContextRoutingAppId = atoi(cfline);
				printf( "SERVICE_CONTEXT_4_APP_ID[%d]\n", objStackConfig.ServiceContextRoutingInfo[3].ServiceContextRoutingAppId);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_4_HOST_NAME", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[3].DestinationHostName, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_4_HOST_NAME[%s]\n", objStackConfig.ServiceContextRoutingInfo[3].DestinationHostName);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_5", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[4].ServiceContext, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_5[%s]\n", objStackConfig.ServiceContextRoutingInfo[4].ServiceContext);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_5_APP_ID", cfKey) == 0)
			{
				objStackConfig.ServiceContextRoutingInfo[4].ServiceContextRoutingAppId = atoi(cfline);
				printf( "SERVICE_CONTEXT_5_APP_ID[%d]\n", objStackConfig.ServiceContextRoutingInfo[4].ServiceContextRoutingAppId);
			}
			else if( strcmp( (char*) "SERVICE_CONTEXT_5_HOST_NAME", cfKey) == 0)
			{
				memcpy( objStackConfig.ServiceContextRoutingInfo[4].DestinationHostName, cfline, (strlen(cfline)-1));
				printf( "SERVICE_CONTEXT_5_HOST_NAME[%s]\n", objStackConfig.ServiceContextRoutingInfo[4].DestinationHostName);
			}			
			else if( strstr( cfKey, "LOGCAT_") != NULL)
			{
				/*
				int iKeyLen = strlen((char*)"LOGCAT_");
				
				char sActualLogCatKey[100];
				memset( &sActualLogCatKey, 0, sizeof(sActualLogCatKey));
				strcpy( sActualLogCatKey, &cfKey[iKeyLen]);
				
				int iEnable = atoi(cfline);
				
				core_AddLogCat( sActualLogCatKey, iEnable);
				printf( "LOGCAT_[%s] sActualLogCatKey[%s] iEnable[%d]\n", cfKey, sActualLogCatKey, iEnable);
				*/
			}
			else if( strcmp( (char*) "AUTH_APPLICATION_ID_1", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAuthApplicationId( iAuthApplicationId);
				printf( "AUTH_APPLICATION_ID_1[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "AUTH_APPLICATION_ID_2", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAuthApplicationId( iAuthApplicationId);
				printf( "AUTH_APPLICATION_ID_2[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "AUTH_APPLICATION_ID_3", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAuthApplicationId( iAuthApplicationId);
				printf( "AUTH_APPLICATION_ID_3[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "AUTH_APPLICATION_ID_4", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAuthApplicationId( iAuthApplicationId);
				printf( "AUTH_APPLICATION_ID_4[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "AUTH_APPLICATION_ID_5", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAuthApplicationId( iAuthApplicationId);
				printf( "AUTH_APPLICATION_ID_5[%d]\n", iAuthApplicationId);
			}			
			else if( strcmp( (char*) "ACCT_APPLICATION_ID_1", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAcctApplicationId( iAuthApplicationId);
				printf( "ACCT_APPLICATION_ID_1[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "ACCT_APPLICATION_ID_2", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAcctApplicationId( iAuthApplicationId);
				printf( "ACCT_APPLICATION_ID_2[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "ACCT_APPLICATION_ID_3", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAcctApplicationId( iAuthApplicationId);
				printf( "ACCT_APPLICATION_ID_3[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "ACCT_APPLICATION_ID_4", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAcctApplicationId( iAuthApplicationId);
				printf( "ACCT_APPLICATION_ID_4[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "ACCT_APPLICATION_ID_5", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiAcctApplicationId( iAuthApplicationId);
				printf( "ACCT_APPLICATION_ID_5[%d]\n", iAuthApplicationId);
			}			
			else if( strcmp( (char*) "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_1", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiVendorSpecificAuthApplicationId( objStackConfig.VendorId, iAuthApplicationId);
				printf( "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_1[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_2", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiVendorSpecificAuthApplicationId( objStackConfig.VendorId, iAuthApplicationId);
				printf( "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_2[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_3", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiVendorSpecificAuthApplicationId( objStackConfig.VendorId, iAuthApplicationId);
				printf( "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_3[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_4", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiVendorSpecificAuthApplicationId( objStackConfig.VendorId, iAuthApplicationId);
				printf( "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_4[%d]\n", iAuthApplicationId);
			}
			else if( strcmp( (char*) "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_5", cfKey) == 0)
			{
				int iAuthApplicationId = atol(cfline);
				core_addiVendorSpecificAuthApplicationId( objStackConfig.VendorId, iAuthApplicationId);
				printf( "VENDOR_SPECIFIC_AUTH_APPLICATION_ID_5[%d]\n", iAuthApplicationId);
			}
			else 
			{
				if( ptrCoreOnConfigItemHandler > 0 && (strlen(cfline)-1) > 0)
				{
					char nstr[1000] = {0};
					memset( &nstr, 0, 1000);
					memcpy( &nstr, cfline, (strlen(cfline)-1));
					
					ptrCoreOnConfigItemHandler( (char *)cfKey, nstr, (int)(strlen(cfline)-1));
				}
			}
			

		}
		
		cfline = NULL;
		fclose( file);
		
	}
	else
	{
		printf("Diam Config File Not Found : %s\n", configFileName);
		exit(0);
	}
	
	if( objStackConfig.HashCharLength < 0)
		objStackConfig.HashCharLength = 10;
	
	if(objStackConfig.HashCharLength > 50)
		objStackConfig.HashCharLength = 50;
	
	
	if( objStackConfig.LicenseFileFound == 0)
	{
		printf("\nLicense File Not Found.\n\n");
		exit(0);
	}
	else
	{
		/*
		printf("Opening Lic File : %s\n", objStackConfig.LICENSE_FILE);
		FILE *f = fopen( objStackConfig.LICENSE_FILE, "r");
		fseek(f, 0, SEEK_END);
		long fsize = ftell(f);
		fseek(f, 0, SEEK_SET);

		char sLICString[5000] = {0};
		fread( sLICString, fsize, 1, f);
		fclose(f);
		
		sLICString[fsize] = 0;
		
		char randBuff[4] = {0};
		int i = 0;
		
		for( i = 0;i < 4; i++)
			randBuff[i] = sLICString[6+i];
		
		int rNumb = atoi(randBuff);		
		
		int bSize = fsize-11;

		char aLic[ bSize ];
		
		for( i=0;i<fsize;i++)
			aLic[i] = sLICString[i + 10];	
				
		//printf("%s\n", aLic);		
		
		iStackLicense stackLicense;
		memset( &stackLicense, 0, sizeof(stackLicense));	
		
		Base64decode( (char *)&stackLicense, aLic);
		
		decrypt( (char *)&stackLicense, rNumb, sizeof(stackLicense));
		decrypt( (char *)&stackLicense, 1407, sizeof(stackLicense));
		
		//printLicenseInfo( &stackLicense);	
		
		struct tm* tm_info;
		char strat_buffer[26];
	
		tm_info = localtime( &stackLicense.Expiry);
		strftime( strat_buffer, 26, "%Y:%m:%d %H:%M:%S", tm_info);
		*/
		
		/*
		if( IsLicenseExpired( &stackLicense) == 0)
		{
			printf("License Expired[%s]\n", strat_buffer);
			exit(0);
		}
		else
		{
			printf("License Expiry Date[%s]\n", strat_buffer);			
		}
		*/
		
		//objStackConfig.NodeType = stackLicense.NodeType;
		
#if DIAMDRA
	objStackConfig.NodeType = 2;
#endif		
		
		printf("objStackConfig.NodeType = %d  | %s\n", objStackConfig.NodeType, objStackConfig.MAC_ADDRESS_KEY);
		
		
		//exit(0);		
	}
	
	
	
	/*
	if( objStackConfig.NodeType == 2 && strcmp( objStackConfig.MAC_ADDRESS_KEY, "") == 0)
	{
		printf("please configure MAC_ADDRESS_KEY\n");
		exit(0);
	}
	
	if( objStackConfig.NodeType == 2 && strlen( objStackConfig.MAC_ADDRESS_KEY) > 0)
	{
		char sMacAddress[6];
		memset( sMacAddress, 0, sizeof(sMacAddress));
		__si_retrieveMACAddressFromKey( objStackConfig.MAC_ADDRESS_KEY, sMacAddress);
		
		if( __si_ValidateMACAddress( sMacAddress) == 0)
		{
			//
			// printf("MAC Address %02x:%02x:%02x:%02x:%02x:%02x Not Found in this Machine", 
			//	sMacAddress[0] & 0xFF,sMacAddress[1] & 0xFF,
			//	sMacAddress[2] & 0xFF,sMacAddress[3] & 0xFF,
			//	sMacAddress[4] & 0xFF,sMacAddress[5] & 0xFF
			// );
			// 
			printf("invalid MAC Address\n");
			exit(0);
		}
	}
	*/
	
	
	if( objStackConfig.ReConnectSeconds <= 0 || objStackConfig.ReConnectSeconds > 100)
	{
		printf("Invalid Configuaration for RECONNECT_SECONDS[%d] Setting Back to 30 seconds \n", objStackConfig.ReConnectSeconds);
		objStackConfig.ReConnectSeconds = 30;
	}		
	
	objStackConfig.QueueMode = 1;	

	if( ____onlyCore == 1)
	{
		objStackConfig.Port = -1;
	}
	
	if( ____onlyCore == 0)
	{	
		if(objStackConfig.NoOfPeers > 36)
		{
			printf("Current Supporting Only 6 Peers \n");
			exit(0);
		}

		if(objStackConfig.NoOfAppSupported > 10)
		{
			printf("Current Supporting Only 10 Interfaces \n");
			exit(0);
		}


		if(objStackConfig.NodeType == 2 && objStackConfig.NoOfPeers == 0)
		{
			printf("Proxy/Agent Requires Peer Configuration... No of Peers[%d] \n", objStackConfig.NoOfPeers);
			exit(0);
		}

		if(objStackConfig.NoOfPeers > 0 && objStackConfig.NoOfPeers != objStackConfig.iLoadedPeerConfigCount)
		{
			printf("No Peer of Peers Configuration Mismatch ., Configured[%d] ., Loaded[%d]\n", objStackConfig.NoOfPeers, objStackConfig.iLoadedPeerConfigCount);
			exit(0);
		}
		
		if( objStackConfig.RoutingThreadCount < 3)
		{
			printf("Configured Routing Threads[%d].., Minimum Required 3 Threads \n", objStackConfig.RoutingThreadCount);
			exit(0);		
		}
		
		//objStackConfig.RoutingThreadCount = 20;
		int i = 0;
		int j = 0;
		
		for( i = 0; i < 5; i++)
		{
			if( objStackConfig.IMSIRouting[i].Min > 0 && objStackConfig.IMSIRouting[i].Max && objStackConfig.IMSIRouting[i].PrimaryNodeId > 0)
			{
				int z = 0;
				for (z = 0; z < 36; z++)
				{
					objStackConfig.IMSIRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[z] = -1;
				}
				
				objStackConfig.IMSIRouting[i].EndPointIndex = 1;
				objStackConfig.IMSIRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[0] = objStackConfig.IMSIRouting[i].PrimaryNodeId;
				
				if( objStackConfig.IMSIRouting[i].FallBackNodeId > 0 )
				{
					objStackConfig.IMSIRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[1] = objStackConfig.IMSIRouting[i].FallBackNodeId;
				}
			}	
		}
		
		
		for( i = 0; i < 5; i++)
		{
			if( objStackConfig.MSISDNRouting[i].Min > 0 && objStackConfig.MSISDNRouting[i].Max && objStackConfig.MSISDNRouting[i].PrimaryNodeId > 0)
			{
				int z = 0;
				for (z = 0; z < 36; z++)
				{
					objStackConfig.MSISDNRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[z] = -1;
				}
				
				objStackConfig.MSISDNRouting[i].EndPointIndex = 1;
				objStackConfig.MSISDNRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[0] = objStackConfig.MSISDNRouting[i].PrimaryNodeId;
				
				if( objStackConfig.MSISDNRouting[i].FallBackNodeId > 0 )
				{
					objStackConfig.MSISDNRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[1] = objStackConfig.MSISDNRouting[i].FallBackNodeId;
				}
			}	
		}
		

		for( i = 0; i < 5; i++)
		{
			if( objStackConfig.IMEIRouting[i].Min > 0 && objStackConfig.IMEIRouting[i].Max && objStackConfig.IMEIRouting[i].PrimaryNodeId > 0)
			{
				int z = 0;
				for (z = 0; z < 36; z++)
				{
					objStackConfig.IMEIRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[z] = -1;
				}
				
				objStackConfig.IMEIRouting[i].EndPointIndex = 1;
				objStackConfig.IMEIRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[0] = objStackConfig.IMEIRouting[i].PrimaryNodeId;
				
				if( objStackConfig.IMEIRouting[i].FallBackNodeId > 0 )
				{
					objStackConfig.IMEIRouting[i].IEndPoint[0].EndPointRecord[0].PeerIndexes[1] = objStackConfig.IMEIRouting[i].FallBackNodeId;
				}
			}	
		}	
		
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			objStackConfig.PeerEndPoint[i].EndPointRecord[0].PeerIndexes[0] = i;
		}
		
		
		int iApplicationsIds[10];
		int iPeerUniqueApplicationIndex = 0;	
		memset( &iApplicationsIds, 0, sizeof(iApplicationsIds));
		
		//Find Unique ApplicationIds
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			int bFound = 0;
			int j = 0;
			
			for( j = 0; j < iPeerUniqueApplicationIndex; j++)
			{
				if( objStackConfig.Peers[i].AppId == iApplicationsIds[j])
				{
					bFound = 1;
					break;
				}
			}
			
			if( bFound == 0)
			{
				iApplicationsIds[iPeerUniqueApplicationIndex] = objStackConfig.Peers[i].AppId;
				iPeerUniqueApplicationIndex++;
			}
		}
		
		
		for( j = 0; j < iPeerUniqueApplicationIndex; j++)
		{
			objStackConfig.AppIEndPoint[j].AppId = iApplicationsIds[j];
			objStackConfig.AppEndPointIndex++;
		}
		
		j = 0;
		for( j = 0; j < objStackConfig.AppEndPointIndex; j++)	
		{
			int i = 0;
			int z = 0;
			for (z = 0; z < 36; z++)
			{
				objStackConfig.AppIEndPoint[j].EndPointRecord[i].PeerIndexes[z] = -1;
			}
		}
		
		
		for( j = 0; j < objStackConfig.AppEndPointIndex; j++)	
		{
			int z = 0;
			for ( z = 0; z < objStackConfig.NoOfPeers; z++)
			{
				if( objStackConfig.AppIEndPoint[j].AppId == objStackConfig.Peers[z].AppId)
				{
					int iT = 0;//objStackConfig.AppIEndPoint[j].EndPointRecordCount;
					objStackConfig.AppIEndPoint[j].EndPointRecord[iT].AppId = objStackConfig.Peers[z].AppId;
					
					int cI = objStackConfig.AppIEndPoint[j].EndPointRecord[iT].PeerIndexCount;
					
					objStackConfig.AppIEndPoint[j].EndPointRecord[iT].PeerIndexes[ cI ] = z;
					objStackConfig.AppIEndPoint[j].EndPointRecord[iT].PeerIndexCount++;

					objStackConfig.AppIEndPoint[j].EndPointRecordCount = 1;	
					
					objStackConfig.Peers[z].AEPI = j;
					objStackConfig.Peers[z].AEPR = 0;
					objStackConfig.Peers[z].AEPRPI = cI;
				}
			}
		}
		
		
		if( objStackConfig.AppEndPointIndex > 0)
		{	
			printf("========================================================================================\n");	
			
			printf("Peer Application Table \n");
			
			for( j = 0; j < objStackConfig.AppEndPointIndex; j++)	
			{
				printf( "objStackConfig.AppIEndPoint[%d].AppId = %d\n", j, objStackConfig.AppIEndPoint[j].AppId);
				
				for( i = 0; i < objStackConfig.AppIEndPoint[j].EndPointRecordCount; i++)	
				{
					int y = 0;
					for( y = 0; y < objStackConfig.AppIEndPoint[j].EndPointRecord[i].PeerIndexCount; y++)
					{
						printf( " ------------- PeerId[%d]\n", objStackConfig.AppIEndPoint[j].EndPointRecord[i].PeerIndexes[y]);				
					}
				}
			}
			
			printf("========================================================================================\n");	
		}
		
		
		
		
		
		
		
		
		
		
		char cPeerUniqueHostRelamNames[36][400];
		int iPeerUniqueHostRealmNameIndex = 0;
		memset( &cPeerUniqueHostRelamNames, 0, sizeof(cPeerUniqueHostRelamNames));
		
		//Find Unique Peer Destination and Realm
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			int bFound = 0;
			int j = 0;
			
			char sPeerDH[400];
			memset( &sPeerDH, 0, sizeof(sPeerDH));
			sprintf( sPeerDH, "%s@%s", objStackConfig.Peers[i].PeerHostName, objStackConfig.Peers[i].PeerHostRealmName);
			
			for( j = 0; j < iPeerUniqueHostRealmNameIndex; j++)
			{
				if( strcmp( sPeerDH, cPeerUniqueHostRelamNames[j]) == 0)
				{
					bFound = 1;
					break;
				}
			}
			
			if( bFound == 0)
			{
				strcpy( cPeerUniqueHostRelamNames[iPeerUniqueHostRealmNameIndex], sPeerDH);
				iPeerUniqueHostRealmNameIndex++;
			}
		}
		
		for( j = 0; j < iPeerUniqueHostRealmNameIndex; j++)
		{
			strcpy( objStackConfig.HRIEndPoint[j].HostRealm, cPeerUniqueHostRelamNames[j]);
			objStackConfig.HREndPointIndex++;
		}
		
		for( j = 0; j < objStackConfig.HREndPointIndex; j++)
		{
			int i = 0;
			for (i = 0; i < objStackConfig.NoOfAppSupported; i++)
			{
				objStackConfig.HRIEndPoint[j].EndPointRecord[i].AppId = objStackConfig.SupportedAppIds[i];
				objStackConfig.HRIEndPoint[j].EndPointRecordCount++;
			}
		}

		j = 0;
		for( j = 0; j < objStackConfig.HREndPointIndex; j++)	
		{
			int i = 0;
			for (i = 0; i < 36; i++)
			{
				int z = 0;
				for (z = 0; z < 36; z++)
				{
					objStackConfig.HRIEndPoint[j].EndPointRecord[i].PeerIndexes[z] = -1;
				}
			}
		}

		for( j = 0; j < objStackConfig.HREndPointIndex; j++)	
		{
			int z = 0;
			for (z = 0; z < objStackConfig.NoOfPeers; z++)
			{
				char sPeerDH[400];
				memset( &sPeerDH, 0, sizeof(sPeerDH));
				sprintf( sPeerDH, "%s@%s", objStackConfig.Peers[z].PeerHostName, objStackConfig.Peers[z].PeerHostRealmName);
				
				if( strcmp( objStackConfig.HRIEndPoint[j].HostRealm, sPeerDH) == 0)
				{
					int i = 0;
					for (i = 0; i < objStackConfig.HRIEndPoint[j].EndPointRecordCount; i++)
					{
						if( objStackConfig.HRIEndPoint[j].EndPointRecord[i].AppId == objStackConfig.Peers[z].AppId)
						{
							int cI = objStackConfig.HRIEndPoint[j].EndPointRecord[i].PeerIndexCount;
							objStackConfig.HRIEndPoint[j].EndPointRecord[i].PeerIndexes[ cI ] = z;
							objStackConfig.HRIEndPoint[j].EndPointRecord[i].PeerIndexCount++;
							
							objStackConfig.Peers[z].HREPI = j;
							objStackConfig.Peers[z].HREPR = i;
							objStackConfig.Peers[z].HREPRPI = cI;
						}
					}
				}
			}
		}
		
		
		
		
		
		
		

		
		
		char cPeerUniqueHostNames[36][200];
		int iPeerUniqueHostNameIndex = 0;
		memset( &cPeerUniqueHostNames, 0, sizeof(cPeerUniqueHostNames));
		
		//Find Unique Peer Name
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			int bFound = 0;
			int j = 0;
			
			for( j = 0; j < iPeerUniqueHostNameIndex; j++)
			{
				if( strcmp( objStackConfig.Peers[i].PeerHostName, cPeerUniqueHostNames[j]) == 0)
				{
					bFound = 1;
					break;
				}
			}
			
			if( bFound == 0)
			{
				strcpy( cPeerUniqueHostNames[iPeerUniqueHostNameIndex], objStackConfig.Peers[i].PeerHostName);
				iPeerUniqueHostNameIndex++;
			}
		}
		
		
		for( j = 0; j < iPeerUniqueHostNameIndex; j++)
		{
			strcpy( objStackConfig.HostNameIEndPoint[j].HostName, cPeerUniqueHostNames[j]);
			objStackConfig.HostNameEndPointIndex++;
		}
		
		for( j = 0; j < objStackConfig.HostNameEndPointIndex; j++)
		{
			int i = 0;
			for (i = 0; i < objStackConfig.NoOfAppSupported; i++)
			{
				objStackConfig.HostNameIEndPoint[j].EndPointRecord[i].AppId = objStackConfig.SupportedAppIds[i];
				objStackConfig.HostNameIEndPoint[j].EndPointRecordCount++;
			}
		}
		
		j = 0;
		for( j = 0; j < objStackConfig.HostNameEndPointIndex; j++)	
		{
			int i = 0;
			for (i = 0; i < 36; i++)
			{
				int z = 0;
				for (z = 0; z < 36; z++)
				{
					objStackConfig.HostNameIEndPoint[j].EndPointRecord[i].PeerIndexes[z] = -1;
				}
			}
		}
		
		for( j = 0; j < objStackConfig.HostNameEndPointIndex; j++)	
		{
			int z = 0;
			for (z = 0; z < objStackConfig.NoOfPeers; z++)
			{
				if( strcmp( objStackConfig.HostNameIEndPoint[j].HostName, objStackConfig.Peers[z].PeerHostName) == 0)
				{
					int i = 0;
					for (i = 0; i < objStackConfig.HostNameIEndPoint[j].EndPointRecordCount; i++)
					{
						if( objStackConfig.HostNameIEndPoint[j].EndPointRecord[i].AppId == objStackConfig.Peers[z].AppId)
						{
							int cI = objStackConfig.HostNameIEndPoint[j].EndPointRecord[i].PeerIndexCount;
							objStackConfig.HostNameIEndPoint[j].EndPointRecord[i].PeerIndexes[ cI ] = z;
							objStackConfig.HostNameIEndPoint[j].EndPointRecord[i].PeerIndexCount++;
							
							objStackConfig.Peers[z].HEPI = j;
							objStackConfig.Peers[z].HEPR = i;
							objStackConfig.Peers[z].HEPRPI = cI;
						}
					}
				}
			}
		}
		
		
		
		
		
		

		char cPeerUniqueNames[36][200];
		int iPeerUniqueNameIndex = 0;
		memset( &cPeerUniqueNames, 0, sizeof(cPeerUniqueNames));
		//printf( "cPeerUniqueNames Size=%d\n", sizeof(cPeerUniqueNames));
		 
		//Find Unique Peer Realms
		//int 
		i = 0;
		for( i = 0; i < objStackConfig.NoOfPeers; i++)
		{
			int bFound = 0;
			int j = 0;
			
			for( j = 0; j < iPeerUniqueNameIndex; j++)
			{
				if( strcmp( objStackConfig.Peers[i].PeerHostRealmName, cPeerUniqueNames[j]) == 0)
				{
					bFound = 1;
					break;
				}
			}
			
			if( bFound == 0)
			{
				strcpy( cPeerUniqueNames[iPeerUniqueNameIndex], objStackConfig.Peers[i].PeerHostRealmName);
				iPeerUniqueNameIndex++;
			}
		}
		
		//int 
		j = 0;
		for( j = 0; j < iPeerUniqueNameIndex; j++)
		{
			strcpy( objStackConfig.IEndPoint[j].Realm, cPeerUniqueNames[j]);
			objStackConfig.EndPointIndex++;
		}
		
		for( j = 0; j < objStackConfig.EndPointIndex; j++)
		{
			int i = 0;
			for (i = 0; i < objStackConfig.NoOfAppSupported; i++)
			{
				objStackConfig.IEndPoint[j].EndPointRecord[i].AppId = objStackConfig.SupportedAppIds[i];
				objStackConfig.IEndPoint[j].EndPointRecordCount++;
			}
		}
		
		#if 0
		
		for( j = 0; j < objStackConfig.EndPointIndex; j++)
		{
			printf( "EndPoint[%d] RealmName[%s]\n", j, objStackConfig.IEndPoint[j].Realm);
					
			int i = 0;
			for (i = 0; i < objStackConfig.IEndPoint[j].EndPointRecordCount; i++)
			{
				printf( " -------- AppId[%d]\n", objStackConfig.IEndPoint[j].EndPointRecord[i].AppId);			
			}
		}

		#endif
		
		j=0;
		for( j = 0; j < objStackConfig.EndPointIndex; j++)	
		{
			int i = 0;
			for (i = 0; i < 36; i++)
			{
				int z = 0;
				for (z = 0; z < 36; z++)
				{
					objStackConfig.IEndPoint[j].EndPointRecord[i].PeerIndexes[z] = -1;
				}	
			}	
		}	


		// Realm  -- x.com
		//		AppId 4
		//			Peer1, Peer2
		//		AppId 1662772
		//			Peer1, Peer2
		// Realm  -- ms.com
		//		AppId 4
		//			Peer5	

		for( j = 0; j < objStackConfig.EndPointIndex; j++)	
		{
			int z = 0;
			for (z = 0; z < objStackConfig.NoOfPeers; z++)
			{
				if( strcmp( objStackConfig.IEndPoint[j].Realm, objStackConfig.Peers[z].PeerHostRealmName) == 0)
				{
					int i = 0;
					for (i = 0; i < objStackConfig.IEndPoint[j].EndPointRecordCount; i++)
					{
						if( objStackConfig.IEndPoint[j].EndPointRecord[i].AppId == objStackConfig.Peers[z].AppId)
						{
							int cI = objStackConfig.IEndPoint[j].EndPointRecord[i].PeerIndexCount;
							objStackConfig.IEndPoint[j].EndPointRecord[i].PeerIndexes[ cI ] = z;
							objStackConfig.IEndPoint[j].EndPointRecord[i].PeerIndexCount++;
							
							objStackConfig.Peers[z].EPI = j;
							objStackConfig.Peers[z].EPR = i;
							objStackConfig.Peers[z].EPRPI = cI;
						}
					}
				}
			}
		}
		
		if( objStackConfig.EndPointIndex > 0)
		{	
			printf("========================================================================================\n");	
			
			printf("Peer Realm Table \n");
			
			for( j = 0; j < objStackConfig.EndPointIndex; j++)	
			{
				printf( "IEndPoint[%d].Realm[%s]\n", j, objStackConfig.IEndPoint[j].Realm);
				
				int z = 0;
				for( z = 0; z < objStackConfig.IEndPoint[j].EndPointRecordCount; z++)
				{
					printf( " ------- AppId[%d]\n", objStackConfig.IEndPoint[j].EndPointRecord[z].AppId);
					
					int y = 0;
					for( y = 0; y < objStackConfig.IEndPoint[j].EndPointRecord[z].PeerIndexCount; y++)
					{
						printf( " ------------- PeerId[%d]\n", objStackConfig.IEndPoint[j].EndPointRecord[z].PeerIndexes[y]);				
					}
				}
			}

			printf("========================================================================================\n\n");
		}
		
	}
}

int hasAppId()
{
	return 0;
}


//gcc -g DiamTcp.c -o DiamFx -lithread
/*
int main(int argc, char* argv[])
{
	if( argc >=2 )
	{
		initConfig(argv[1]);
	}
	else
	{
		printf("\nNo Configuration File Specified\n\n\n\n");
		exit(0);
	}

	initalizeServer();

	appHandleQuitCommand();

	return EXIT_SUCCESS;
}
*/













int DM_CDATA_INITIAL_POOL_SIZE = 200000;
int DM_CDATA_INCREASE_BY_POOL_SIZE = 10000;

int DIAM_TIMER_MSG_INITIAL_POOL_SIZE = 50000;
int DIAM_TIMER_MSG_INCREASE_BY_POOL_SIZE = 10000;

int DIAM_STICKY_SESSION_MSG_INITIAL_POOL_SIZE = 10000;

/*
#if DIAMDRA

	int DIAM_QUEUE_MSG_INITIAL_POOL_SIZE = 30000;
	int DIAM_QUEUE_MSG_INCREASE_BY_POOL_SIZE = 5000;	

	int DIAM_ROUTE_MSG_INITIAL_POOL_SIZE = 30000;
	int DIAM_ROUTE_MSG_INCREASE_BY_POOL_SIZE = 5000;

	int DIAM_RAW_MSG_INITIAL_POOL_SIZE = 30000;
	int DIAM_RAW_MSG_INCREASE_BY_POOL_SIZE = 5000;
	
	int DM_MSG_INITIAL_POOL_SIZE = 30000;
	int DM_MSG_INCREASE_BY_POOL_SIZE = 5000;	

	int DM_AVP_INITIAL_POOL_SIZE = 150000;
	int DM_AVP_INCREASE_BY_POOL_SIZE = 7500;

#else	
*/	
	int DIAM_QUEUE_MSG_INITIAL_POOL_SIZE = 20000;
	int DIAM_QUEUE_MSG_INCREASE_BY_POOL_SIZE = 2000;
	
	int DIAM_ROUTE_MSG_INITIAL_POOL_SIZE = 20000;
	int DIAM_ROUTE_MSG_INCREASE_BY_POOL_SIZE = 2000;

	int DIAM_RAW_MSG_INITIAL_POOL_SIZE = 20000;
	int DIAM_RAW_MSG_INCREASE_BY_POOL_SIZE = 2000;

	int DM_MSG_INITIAL_POOL_SIZE = 20000;
	int DM_MSG_INCREASE_BY_POOL_SIZE = 5000;	
	
	int DM_AVP_INITIAL_POOL_SIZE = 100000;
	int DM_AVP_INCREASE_BY_POOL_SIZE = 7500;
	
	int IE_ArrayListPool_MSG_INITIAL_POOL_SIZE = 1000;
	int IE_ArrayListPool_MSG_INCR_POOL_SIZE = 200;

	int IE_ArrayElementPool_MSG_INITIAL_POOL_SIZE = 1000;
	int IE_ArrayElementPool_MSG_INCR_POOL_SIZE = 200;
	
//#endif
/**/

int addArrayListToPool( iArrayList *oArrayList, int bInLockedMode, struct MessagePtr *mPtr)
{
    if(bInLockedMode)
    {
        pthread_mutex_lock( &mPtr->Lock );
    }

    if(!mPtr->HeadPtr)
    {
        mPtr->HeadPtr = mPtr->CurrPtr = (void*)oArrayList;
    }
    else
    {
        ((iArrayList*)mPtr->CurrPtr)->PoolNext = (void*)oArrayList;
    }

    mPtr->CurrPtr = (void*)oArrayList;
    mPtr->Count++;

    if(bInLockedMode)
    {
        pthread_mutex_unlock( &mPtr->Lock );
    }

    return 0;
}

int addArrayElementToPool( iArrayElement *oArrayElement, int bInLockedMode, struct MessagePtr *mPtr)
{
    if(bInLockedMode)
    {
        pthread_mutex_lock( &mPtr->Lock );
    }

    if(!mPtr->HeadPtr)
    {
        mPtr->HeadPtr = mPtr->CurrPtr = (void*)oArrayElement;
    }
    else
    {
        ((iArrayElement*)mPtr->CurrPtr)->PoolNext = (void*)oArrayElement;
    }

    mPtr->CurrPtr = (void*)oArrayElement;
    mPtr->Count++;

    if(bInLockedMode)
    {
        pthread_mutex_unlock( &mPtr->Lock );
    }

    return 0;
}

int addDiamRouteMessageToPool( struct DiamRouteMessage *oDiamMessage, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oDiamMessage;
	}
	else
	{
		((struct DiamRouteMessage*)mPtr->CurrPtr)->PoolNext = (void*)oDiamMessage;
	}

	mPtr->CurrPtr = (void*)oDiamMessage;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}

	return 0;	
}


int addDiamTimerMessageToPool( IAObjectPointer *oIAObjectPointer, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oIAObjectPointer;
	}
	else
	{
		((IAObjectPointer*)mPtr->CurrPtr)->PoolNext = (void*)oIAObjectPointer;
	}

	mPtr->CurrPtr = (void*)oIAObjectPointer;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}	
	return 0;
}

int addDiamStickySessionMessageToPool( iStickySessionInfo *oStickySessionInfo, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oStickySessionInfo;
	}
	else
	{
		((iStickySessionInfo*)mPtr->CurrPtr)->PoolNext = (void*)oStickySessionInfo;
	}

	mPtr->CurrPtr = (void*)oStickySessionInfo;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}	
	return 0;
}

int addMessageToPool( struct DiamMessage *oDiamMessage, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oDiamMessage;
	}
	else
	{
		((struct DiamMessage*)mPtr->CurrPtr)->PoolNext = (void*)oDiamMessage;
	}

	mPtr->CurrPtr = (void*)oDiamMessage;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}
	return 0;
}

int addDiamRawDataToPool( struct DiamRawData *oDiamRawData, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oDiamRawData;
	}
	else
	{
		((struct DiamRawData*)mPtr->CurrPtr)->PoolNext = (void*)oDiamRawData;
	}
	
	mPtr->CurrPtr = (void*)oDiamRawData;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}
	return 0;
}


int addDiamAVPToPool( struct DiamAvp *oDiamAvp, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oDiamAvp;
	}
	else
	{
		((struct DiamAvp*)mPtr->CurrPtr)->PoolNext = (void*)oDiamAvp;
	}

	mPtr->CurrPtr = (void*)oDiamAvp;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}
	return 0;
}




int addDiamCDataPool( struct CData *oCData, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oCData;
	}
	else
	{
		((struct CData*)mPtr->CurrPtr)->PoolNext = (void*)oCData;
	}

	mPtr->CurrPtr = (void*)oCData;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}
	return 0;
}


int addQueueRecordToPool( struct QueueRecord *oQueueRecord, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}

	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oQueueRecord;
	}
	else
	{
		((struct QueueRecord*)mPtr->CurrPtr)->PoolNext = (void*)oQueueRecord;
	}

	mPtr->CurrPtr = (void*)oQueueRecord;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}
	return 0;
}

int addToSessionPool( struct SessionBaseRecord *iRecord, int bInLockMode, struct SessionMessagePtr *mPtr)
{
	if(bInLockMode) {
		pthread_mutex_lock( &mPtr->Lock );
	}
	
	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)iRecord;
	}
	else
	{
		((struct SessionBaseRecord*)mPtr->CurrPtr)->NextRecord = iRecord;
	}	
	
	mPtr->CurrPtr = iRecord;
	mPtr->Count++;

	if(bInLockMode) {	
		pthread_mutex_unlock( &mPtr->Lock );
	}
	return 0;
}

int addASTDataPtrMessageToPool( struct ASTDataPtr *astDataPtr, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
	{
		pthread_mutex_lock( &mPtr->Lock );
	}
	
	//if( mPtr->HeadPtr == NULL)
	if(!mPtr->HeadPtr)	
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)astDataPtr;
	}
	else
	{
		((struct ASTDataPtr*)mPtr->CurrPtr)->PoolNext = (void*)astDataPtr;
	}

	mPtr->CurrPtr = (void*)astDataPtr;
	mPtr->Count++;

	if(bInLockedMode)
	{
		pthread_mutex_unlock( &mPtr->Lock );
	}
	
	return 1;
};

void createArrayListPool( int iBatchSize)
{
    CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating ArrayListPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.ArrayListPool->PoolSize);

    int i = 0;

    for (i = 0; i < iBatchSize; i++)
    {
        iArrayList *oArrayList = (iArrayList *)lib_malloc(sizeof(iArrayList));

        oArrayList->isReleased = 1;
        oArrayList->PoolIndex = ( objStackObjects.ArrayListPool->PoolSize);
        oArrayList->PoolNext = NULL;

        addArrayListToPool( oArrayList, 0, objStackObjects.ArrayListPool->FreePool);

        objStackObjects.ArrayListPool->PoolSize++;
    }
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated ArrayListPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.ArrayListPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

iArrayList* allocateArrayList()
{
    iArrayList* oArrayList = NULL;

    pthread_mutex_lock( &objStackObjects.ArrayListPool->FreePool->Lock );

    oArrayList = objStackObjects.ArrayListPool->FreePool->HeadPtr;

    if(!oArrayList)
    {
        createArrayListPool( IE_ArrayListPool_MSG_INCR_POOL_SIZE);
        oArrayList = objStackObjects.ArrayListPool->FreePool->HeadPtr;
    }

    if( oArrayList)
    {
        objStackObjects.ArrayListPool->FreePool->HeadPtr = oArrayList->PoolNext;
        oArrayList->PoolNext = NULL;
    }

    objStackObjects.ArrayListPool->FreePool->Count--;
    pthread_mutex_unlock( &objStackObjects.ArrayListPool->FreePool->Lock );

    oArrayList->isReleased = 0;
    return oArrayList;
}

void arrayList_create( void **vArrayList)
{
	*vArrayList = allocateArrayList();
}

typedef struct RoutingPointer
{
	void (*Routine)(void*); 
	void (*Routine2)(void*,int); 
	iQueue *QueueObject;
	int iIndex;
} iRoutingPointer;

void * appHelperDecodeDequeeThread( void* voidRoutingPointer)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iRoutingPointer *oRoutingPointer = (iRoutingPointer*)voidRoutingPointer;

	void *Data = NULL;
		
	while(1)
	{
		Data = Dequee( oRoutingPointer->QueueObject);
		
		if(Data)
		{
			oRoutingPointer->Routine( Data);
		}
		
		Data = NULL;
	}
	
	return NULL;
}

void * appHelperDecodeDequeeThread2( void* voidRoutingPointer)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iRoutingPointer *oRoutingPointer = (iRoutingPointer*)voidRoutingPointer;

	void *Data = NULL;
		
	while(1)
	{
		Data = Dequee( oRoutingPointer->QueueObject);
		
		if(Data)
		{
			oRoutingPointer->Routine2( Data, oRoutingPointer->iIndex);
		}
		
		Data = NULL;
	}
	
	return NULL;
}

void QueuePool_CreateWithNThreads( void **pQueuePoolObject, void (*ptrCallBackHandler)(void*), int iNoOfThreads)
{
	iQueue *objQueue = (iQueue *) lib_malloc(sizeof(iQueue));
	
	pthread_mutex_init( &objQueue->Lock, NULL);
	sem_init( &objQueue->sem_lock, 0, 0);
	
	objQueue->Front = NULL;
	objQueue->Front1 = NULL;
	objQueue->Rear = NULL;
	objQueue->Temp = NULL;
	objQueue->QueueCount = 0;
	objQueue->QueueLimit = 5000;
	objQueue->Type = 1;	
	
	*pQueuePoolObject = objQueue;
	
	if(ptrCallBackHandler)
	{
		iRoutingPointer *oRoutingPointer = (iRoutingPointer *)lib_malloc(sizeof(iRoutingPointer));
		oRoutingPointer->Routine = ptrCallBackHandler;
		oRoutingPointer->QueueObject = objQueue;
		
		pthread_attr_t attr;
		pthread_attr_init( &attr);
		pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

		pthread_t peer_pthread_id[iNoOfThreads];
		int i = 0;
				
		for( i = 0; i < iNoOfThreads; i++)
		{		
			int iRet;
			iRet = pthread_create( &peer_pthread_id[i], &attr, appHelperDecodeDequeeThread, (void *)oRoutingPointer);
			
			if(iRet)
			{
				printf("unable to create threads QueuePool_CreateWithNThreads[%d]\n", i);
				exit(-1);
			}			
		}	
	}
}

void QueuePool_CreateWithNThreads2( void **pQueuePoolObject, void (*ptrCallBackHandler)(void*, int), int iNoOfThreads)
{
	//iQueue *objQueue = (iQueue *) lib_malloc(sizeof(iQueue));
	iQueue *objQueue = NULL;
	lib_malloc2( sizeof(iQueue), (void**) &objQueue);
	
	pthread_mutex_init( &objQueue->Lock, NULL);
	sem_init( &objQueue->sem_lock, 0, 0);
	
	objQueue->Front = NULL;
	objQueue->Front1 = NULL;
	objQueue->Rear = NULL;
	objQueue->Temp = NULL;
	objQueue->QueueCount = 0;
	objQueue->QueueLimit = 5000;
	objQueue->Type = 1;	
	
	*pQueuePoolObject = (void **) objQueue;
	
	if(ptrCallBackHandler)
	{
		pthread_attr_t attr;
		pthread_attr_init( &attr);
		pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

		pthread_t peer_pthread_id[iNoOfThreads];
		int i = 0;
				
		for( i = 0; i < iNoOfThreads; i++)
		{		
			iRoutingPointer *oRoutingPointer = (iRoutingPointer *)lib_malloc(sizeof(iRoutingPointer));
			oRoutingPointer->Routine2 = ptrCallBackHandler;
			oRoutingPointer->QueueObject = objQueue;
			oRoutingPointer->iIndex = i;
			
			int iRet;
			iRet = pthread_create( &peer_pthread_id[i], &attr, appHelperDecodeDequeeThread2, (void *)oRoutingPointer);
			
			if(iRet)
			{
				printf("unable to create threads QueuePool_CreateWithNThreads[%d]\n", i);
				exit(-1);
			}			
		}	
	}
}


void QueuePool_Create( void **pQueuePoolObject, void (*ptrCallBackHandler)(void*))
{
	iQueue *objQueue = (iQueue *) lib_malloc(sizeof(iQueue));
	
	pthread_mutex_init( &objQueue->Lock, NULL);
	sem_init( &objQueue->sem_lock, 0, 0);
	
	objQueue->Front = NULL;
	objQueue->Front1 = NULL;
	objQueue->Rear = NULL;
	objQueue->Temp = NULL;
	objQueue->QueueCount = 0;
	objQueue->QueueLimit = 5000;
	objQueue->Type = 1;	
	
	*pQueuePoolObject = objQueue;
	
	if(ptrCallBackHandler)
	{
		iRoutingPointer *oRoutingPointer = (iRoutingPointer *)lib_malloc(sizeof(iRoutingPointer));
		oRoutingPointer->Routine = ptrCallBackHandler;
		oRoutingPointer->QueueObject = objQueue;
		
		
		pthread_attr_t attr;
		pthread_attr_init( &attr);
		pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);
	
		pthread_t s_pthread_id;
    	int iRet;
    	iRet = pthread_create( &s_pthread_id, &attr, appHelperDecodeDequeeThread, (void *)oRoutingPointer);
	}
}




void releaseArrayList( iArrayList* oArrayList)
{
/*	
    if( oArrayList->isReleased == 0)
    {
        oArrayList->isReleased = 1;
        addArrayListToPool( oArrayList, 1, objStackObjects.ArrayListPool->FreePool);
    }
*/
	
	pthread_mutex_lock( &objStackObjects.ArrayListPool->FreePool->Lock );
	
    if( oArrayList->isReleased == 0)
    {
        oArrayList->isReleased = 1;
        addArrayListToPool( oArrayList, 0, objStackObjects.ArrayListPool->FreePool);
    }
	
	pthread_mutex_unlock( &objStackObjects.ArrayListPool->FreePool->Lock );
}

void releaseArrayElement(iArrayElement* oArrayElement);

void arrayList_destroy( void *vArrayList)
{
	//printf("AL FreePool[%d]\n", objStackObjects.ArrayListPool->FreePool->Count);
	//printf("AE FreePool[%d]\n", objStackObjects.ArrayElementPool->FreePool->Count);
	
	struct MessagePtr *mPtr = (struct MessagePtr *)vArrayList;
	pthread_mutex_lock( &mPtr->Lock );
	
	iArrayElement *oArrayElement = (iArrayElement *) mPtr->HeadPtr;
	iArrayElement *oArrayElementNext = NULL;
	
	while(oArrayElement)
	{
		oArrayElementNext = oArrayElement->PoolNext;
		oArrayElement->PoolNext = NULL;
		
		releaseArrayElement( oArrayElement);
		
		oArrayElement = oArrayElementNext;
	}
	
	mPtr->Count = 0;
	mPtr->HeadPtr = NULL;
	
	pthread_mutex_unlock( &mPtr->Lock );
	releaseArrayList( vArrayList);
	
	//printf("AL FreePool[%d]\n", objStackObjects.ArrayListPool->FreePool->Count);
	//printf("AE FreePool[%d]\n", objStackObjects.ArrayElementPool->FreePool->Count);
}

iArrayElement* allocateArrayElement();

int addArrayElementToArrayList( iArrayElement *oArrayElement, struct MessagePtr *mPtr)
{
	pthread_mutex_lock( &mPtr->Lock );
	
	if(!mPtr->HeadPtr)
    {
        mPtr->HeadPtr = mPtr->CurrPtr = (void*)oArrayElement;
    }
    else
    {
        ((iArrayElement*)mPtr->CurrPtr)->PoolNext = (void*)oArrayElement;
    }

    mPtr->CurrPtr = (void*)oArrayElement;
    mPtr->Count++;
	
	pthread_mutex_unlock( &mPtr->Lock );
	return 0;
}

iArrayElement* getArrayElementFromArrayList( struct MessagePtr *mPtr)
{
	iArrayElement* oArrayElement = NULL;
	pthread_mutex_lock( &mPtr->Lock );
	
	if(mPtr->HeadPtr)
    {
		oArrayElement = (iArrayElement *)mPtr->HeadPtr;
		mPtr->HeadPtr = oArrayElement->PoolNext;
		oArrayElement->PoolNext = NULL;
		mPtr->Count--;		
	}
	
	pthread_mutex_unlock( &mPtr->Lock );
	return oArrayElement;
}

int arrayList_Count(void *vArrayList)
{
	return ((struct MessagePtr *)vArrayList)->Count;
}

void releaseArrayElement(iArrayElement* oArrayElement);

void arrayList_pop( void *vArrayList, void **Data )
{
	*Data = NULL;
	
	iArrayElement* oArrayElement = getArrayElementFromArrayList( vArrayList);
	
	if( oArrayElement)
	{
		*Data = oArrayElement->Data;
		releaseArrayElement( oArrayElement);
	}
}

void arrayList_getIterator( void *vArrayList, void **Data )
{
	*Data = NULL;
	struct MessagePtr *mPtr = (struct MessagePtr *)vArrayList;
	
	if(mPtr->HeadPtr)
    {
		*Data = mPtr->HeadPtr; 
	}
}

void arrayList_IteratorMoveNext( void **Data )
{
	iArrayElement* oArrayElement = (iArrayElement*)*Data;
	
	if(oArrayElement)
	{
		oArrayElement = oArrayElement->PoolNext;
		*Data = oArrayElement;
	}
}

void arrayList_IteratorGetData( void *vArrayItr, void **Data)
{
	*Data = NULL;
	iArrayElement* oArrayElement = (iArrayElement*)vArrayItr;
	
	if( oArrayElement)
	{
		*Data = oArrayElement->Data;	
	}
}

void arrayList_push( void *vArrayList, void *Data )
{
	iArrayElement* oArrayElement = (iArrayElement*)allocateArrayElement();
	oArrayElement->Data = Data;	
	
	addArrayElementToArrayList( oArrayElement, vArrayList);
}

void createArrayElementPool( int iBatchSize)
{
    CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating ArrayElementPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.ArrayElementPool->PoolSize);

    int i = 0;

    for (i = 0; i < iBatchSize; i++)
    {
        iArrayElement *oArrayElement = (iArrayElement *)lib_malloc(sizeof(iArrayElement));

        oArrayElement->isReleased = 1;
        oArrayElement->PoolIndex = ( objStackObjects.ArrayElementPool->PoolSize);
        oArrayElement->PoolNext = NULL;

        addArrayElementToPool( oArrayElement, 0, objStackObjects.ArrayElementPool->FreePool);

        objStackObjects.ArrayElementPool->PoolSize++;
    }
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated ArrayElementPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.ArrayElementPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

iArrayElement* allocateArrayElement()
{
    iArrayElement* oArrayElement = NULL;

    pthread_mutex_lock( &objStackObjects.ArrayElementPool->FreePool->Lock );

    oArrayElement = objStackObjects.ArrayElementPool->FreePool->HeadPtr;

    if(!oArrayElement)
    {
        createArrayElementPool( IE_ArrayElementPool_MSG_INCR_POOL_SIZE);
        oArrayElement = objStackObjects.ArrayElementPool->FreePool->HeadPtr;
    }

    if( oArrayElement)
    {
        objStackObjects.ArrayElementPool->FreePool->HeadPtr = oArrayElement->PoolNext;
        oArrayElement->PoolNext = NULL;
    }

    objStackObjects.ArrayElementPool->FreePool->Count--;
    pthread_mutex_unlock( &objStackObjects.ArrayElementPool->FreePool->Lock );

    oArrayElement->isReleased = 0;
    return oArrayElement;
}

void releaseArrayElement(iArrayElement* oArrayElement)
{
/*	
    if( oArrayElement->isReleased == 0)
    {
        oArrayElement->isReleased = 1;
        addArrayElementToPool( oArrayElement, 1, objStackObjects.ArrayElementPool->FreePool);
    }
*/
	pthread_mutex_lock( &objStackObjects.ArrayElementPool->FreePool->Lock );
	
    if( oArrayElement->isReleased == 0)
    {
        oArrayElement->isReleased = 1;
        addArrayElementToPool( oArrayElement, 0, objStackObjects.ArrayElementPool->FreePool);
    }
	
	pthread_mutex_unlock( &objStackObjects.ArrayElementPool->FreePool->Lock );
}

//RingBufferTCPServerImplementation
int addTCPRingBufferToPool( iTCPRingBuffer *oTCPRingBuffer, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
		pthread_mutex_lock( &mPtr->Lock );

	if(!mPtr->HeadPtr)
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oTCPRingBuffer;
	}
	else
	{
		((iTCPRingBuffer*)mPtr->CurrPtr)->PoolNext = (void*)oTCPRingBuffer;
	}

	mPtr->CurrPtr = (void*)oTCPRingBuffer;
	mPtr->Count++;

	if(bInLockedMode)	
		pthread_mutex_unlock( &mPtr->Lock );
	
	return 0;
}

//RingBufferTCPServerImplementation [Start]
int IE_TCPRingBufferPool_MSG_INITIAL_POOL_SIZE = 20000;
int IE_TCPRingBufferPool_MSG_INCR_POOL_SIZE = 5000;

void createTCPRingBufferPool( int iBatchSize)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating TCPRingBufferPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.TCPRingBufferPool->PoolSize);

	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		//iTCPRingBuffer *oTCPRingBuffer = (iTCPRingBuffer *)lib_malloc(sizeof(iTCPRingBuffer));
		iTCPRingBuffer *oTCPRingBuffer = NULL;
		lib_malloc2( sizeof(iTCPRingBuffer), (void**) &oTCPRingBuffer);
		
		oTCPRingBuffer->isReleased = 1;
		oTCPRingBuffer->PoolIndex = ( objStackObjects.TCPRingBufferPool->PoolSize);
		oTCPRingBuffer->PoolNext = NULL;

		addTCPRingBufferToPool( oTCPRingBuffer, 0, objStackObjects.TCPRingBufferPool->FreePool);

		objStackObjects.TCPRingBufferPool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated TCPRingBufferPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.TCPRingBufferPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

iTCPRingBuffer* allocateTCPRingBuffer()
{
	iTCPRingBuffer* oTCPRingBuffer = NULL;

	pthread_mutex_lock( &objStackObjects.TCPRingBufferPool->FreePool->Lock );

	oTCPRingBuffer = objStackObjects.TCPRingBufferPool->FreePool->HeadPtr;

	if(!oTCPRingBuffer)
	{
		createTCPRingBufferPool( IE_TCPRingBufferPool_MSG_INCR_POOL_SIZE);
		oTCPRingBuffer = objStackObjects.TCPRingBufferPool->FreePool->HeadPtr;
	}

	if( oTCPRingBuffer)
	{
		objStackObjects.TCPRingBufferPool->FreePool->HeadPtr = oTCPRingBuffer->PoolNext;
		oTCPRingBuffer->PoolNext = NULL;
	}

	objStackObjects.TCPRingBufferPool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.TCPRingBufferPool->FreePool->Lock );

	oTCPRingBuffer->isReleased = 0;
	return oTCPRingBuffer;
}

void allocateTCPRingBufferW( iTCPRingBuffer** oTCPRingBuffer)
{
	*oTCPRingBuffer = allocateTCPRingBuffer();
}

void releaseTCPRingBuffer(iTCPRingBuffer* oTCPRingBuffer)
{
/*	
	if( oTCPRingBuffer->isReleased == 0)
	{
		oTCPRingBuffer->isReleased = 1;
		addTCPRingBufferToPool( oTCPRingBuffer, 1, objStackObjects.TCPRingBufferPool->FreePool);
	}
*/
	pthread_mutex_lock( &objStackObjects.TCPRingBufferPool->FreePool->Lock );
	
	if( oTCPRingBuffer->isReleased == 0)
	{
		oTCPRingBuffer->isReleased = 1;
		addTCPRingBufferToPool( oTCPRingBuffer, 0, objStackObjects.TCPRingBufferPool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.TCPRingBufferPool->FreePool->Lock );	
}

int IE_TCPClientInfoPool_MSG_INITIAL_POOL_SIZE = 500;
int IE_TCPClientInfoPool_MSG_INCR_POOL_SIZE = 100;

int addTCPClientInfoToPool( iTCPClientInfo *oTCPClientInfo, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode)
		pthread_mutex_lock( &mPtr->Lock );

	if(!mPtr->HeadPtr)
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oTCPClientInfo;
	}
	else
	{
		((iTCPClientInfo*)mPtr->CurrPtr)->PoolNext = (void*)oTCPClientInfo;
	}

	mPtr->CurrPtr = (void*)oTCPClientInfo;
	mPtr->Count++;

	if(bInLockedMode)	
		pthread_mutex_unlock( &mPtr->Lock );
	
	return 0;
}

void createTCPClientInfoPool( int iBatchSize)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating TCPClientInfoPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.TCPClientInfoPool->PoolSize);

	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		iTCPClientInfo *oTCPClientInfo = (iTCPClientInfo *)lib_malloc(sizeof(iTCPClientInfo));

		oTCPClientInfo->isReleased = 1;
		oTCPClientInfo->PoolIndex = ( objStackObjects.TCPClientInfoPool->PoolSize);
		oTCPClientInfo->PoolNext = NULL;

		oTCPClientInfo->hasPendingBeffer = 0;
		memset( oTCPClientInfo->PendingBuffer, 0, sizeof(oTCPClientInfo->PendingBuffer));
		oTCPClientInfo->PendingBefferLength = 0;		
		pthread_mutex_init( &oTCPClientInfo->ReadLock , NULL);
		
		addTCPClientInfoToPool( oTCPClientInfo, 0, objStackObjects.TCPClientInfoPool->FreePool);

		objStackObjects.TCPClientInfoPool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated TCPClientInfoPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.TCPClientInfoPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

iTCPClientInfo* allocateTCPClientInfo()
{
	iTCPClientInfo* oTCPClientInfo = NULL;

	pthread_mutex_lock( &objStackObjects.TCPClientInfoPool->FreePool->Lock );

	oTCPClientInfo = objStackObjects.TCPClientInfoPool->FreePool->HeadPtr;

	if(!oTCPClientInfo)
	{
		createTCPClientInfoPool( IE_TCPClientInfoPool_MSG_INCR_POOL_SIZE);
		oTCPClientInfo = objStackObjects.TCPClientInfoPool->FreePool->HeadPtr;
	}

	if( oTCPClientInfo)
	{
		objStackObjects.TCPClientInfoPool->FreePool->HeadPtr = oTCPClientInfo->PoolNext;
		oTCPClientInfo->PoolNext = NULL;
	}

	objStackObjects.TCPClientInfoPool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.TCPClientInfoPool->FreePool->Lock );

	oTCPClientInfo->iRequestNo = 0;
	oTCPClientInfo->isReleased = 0;
	return oTCPClientInfo;
}

void releaseTCPClientInfo(iTCPClientInfo* oTCPClientInfo)
{
/*	
	if( oTCPClientInfo->isReleased == 0)
	{
		oTCPClientInfo->isReleased = 1;
		addTCPClientInfoToPool( oTCPClientInfo, 1, objStackObjects.TCPClientInfoPool->FreePool);
	}
*/
	pthread_mutex_lock( &objStackObjects.TCPClientInfoPool->FreePool->Lock );
	
	if( oTCPClientInfo->isReleased == 0)
	{
		oTCPClientInfo->isReleased = 1;
		addTCPClientInfoToPool( oTCPClientInfo, 0, objStackObjects.TCPClientInfoPool->FreePool);
	}
	pthread_mutex_unlock( &objStackObjects.TCPClientInfoPool->FreePool->Lock );
}
//RingBufferTCPServerImplementation [End]		


int IE_ClientInfoPool_MSG_INITIAL_POOL_SIZE = 500;
int IE_ClientInfoPool_MSG_INCR_POOL_SIZE = 100;

int addClientInfoToPool( iClientInfo *oClientInfo, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode) {
		pthread_mutex_lock( &mPtr->Lock );
	}

	if(!mPtr->HeadPtr)
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oClientInfo;
	}
	else
	{
		((iClientInfo*)mPtr->CurrPtr)->PoolNext = (void*)oClientInfo;
	}

	mPtr->CurrPtr = (void*)oClientInfo;
	mPtr->Count++;

	if(bInLockedMode) {
		pthread_mutex_unlock( &mPtr->Lock );
	}
	return 0;
}

void createClientInfoPool( int iBatchSize)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating ClientInfoPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.ClientInfoPool->PoolSize);
	
	int i = 0;
	for (i = 0; i < iBatchSize; i++)
	{
		iClientInfo *oClientInfo = NULL;
		lib_malloc2( sizeof(iClientInfo), (void **) &oClientInfo);
		memset( oClientInfo, 0, sizeof(iClientInfo)); 

		oClientInfo->isReleased = 1;
		oClientInfo->PoolIndex = ( objStackObjects.ClientInfoPool->PoolSize);
		oClientInfo->PoolNext = NULL;

		addClientInfoToPool( oClientInfo, 0, objStackObjects.ClientInfoPool->FreePool);

		objStackObjects.ClientInfoPool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated ClientInfoPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.ClientInfoPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

iClientInfo* allocateClientInfo()
{
	iClientInfo* oClientInfo = NULL;

	pthread_mutex_lock( &objStackObjects.ClientInfoPool->FreePool->Lock );

	oClientInfo = objStackObjects.ClientInfoPool->FreePool->HeadPtr;

	if(!oClientInfo)
	{
		createClientInfoPool( IE_ClientInfoPool_MSG_INCR_POOL_SIZE);
		oClientInfo = objStackObjects.ClientInfoPool->FreePool->HeadPtr;
	}

	if( oClientInfo)
	{
		objStackObjects.ClientInfoPool->FreePool->HeadPtr = oClientInfo->PoolNext;
		oClientInfo->PoolNext = NULL;
	}

	objStackObjects.ClientInfoPool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.ClientInfoPool->FreePool->Lock );

	memset( &oClientInfo->ClientHostName, 0, sizeof(oClientInfo->ClientHostName));
	memset( &oClientInfo->ClientHostRealmName, 0, sizeof(oClientInfo->ClientHostRealmName));
	memset( &oClientInfo->ClientIP, 0, sizeof(oClientInfo->ClientIP));
	
	oClientInfo->VendorIdsCount = 0;
	oClientInfo->AuthApplicationIdsCount = 0;
	oClientInfo->AcctApplicationIdsCount = 0;
	oClientInfo->SupportedVendorApplicationIdsCount = 0;
	oClientInfo->isReleased = 0;
	
	return oClientInfo;
}
		
void allocateClientInfoW( iClientInfo **dataPtr)
{
	*dataPtr = allocateClientInfo();
}
		
void releaseClientInfo(iClientInfo* oClientInfo)
{
/*	
	if( oClientInfo->isReleased == 0)
	{
		oClientInfo->isReleased = 1;
		addClientInfoToPool( oClientInfo, 1, objStackObjects.ClientInfoPool->FreePool);
	}
*/	
	pthread_mutex_lock( &objStackObjects.ClientInfoPool->FreePool->Lock );
	
	if( oClientInfo->isReleased == 0)
	{
		oClientInfo->isReleased = 1;
		addClientInfoToPool( oClientInfo, 0, objStackObjects.ClientInfoPool->FreePool);
	}
	pthread_mutex_unlock( &objStackObjects.ClientInfoPool->FreePool->Lock );
}

		
void createQueueRecordPool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating QueueRecordPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.QueuePool->PoolSize);
	
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		struct QueueRecord *oQueueRecord = (struct QueueRecord *)lib_malloc(sizeof(struct QueueRecord));
		
		oQueueRecord->isReleased = 1;
		oQueueRecord->PoolIndex = (objStackObjects.QueuePool->PoolSize);
		oQueueRecord->Data = NULL;
		oQueueRecord->Next = NULL;
		oQueueRecord->PoolNext = NULL;

		addQueueRecordToPool( oQueueRecord, bInLockMode, objStackObjects.QueuePool->FreePool);

		objStackObjects.QueuePool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated QueueRecordPool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.QueuePool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}



void createDiamRouteMessagePool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating DiamRouteMessagePool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.DiamRoutePool->PoolSize);
	
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		struct DiamRouteMessage *oDiamRouteMessage = (struct DiamRouteMessage *)lib_malloc(sizeof(struct DiamRouteMessage));
		
		oDiamRouteMessage->isReleased = 1;
		oDiamRouteMessage->PoolIndex = (objStackObjects.DiamRoutePool->PoolSize);
		oDiamRouteMessage->PoolNext = NULL;

		addDiamRouteMessageToPool( oDiamRouteMessage, bInLockMode, objStackObjects.DiamRoutePool->FreePool);

		objStackObjects.DiamRoutePool->PoolSize++;
	}	
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated DiamRouteMessagePool iBatchSize:%d currentSize:%d", iBatchSize, objStackObjects.DiamRoutePool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

void createDiamTimerMessagePool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating DiamTimerMessagePool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.TimerPool->PoolSize);
		
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		IAObjectPointer *oIAObjectPointer = (IAObjectPointer *)lib_malloc(sizeof(IAObjectPointer));
		
		oIAObjectPointer->isReleased = 1;
		oIAObjectPointer->PoolIndex = (objStackObjects.TimerPool->PoolSize);
		oIAObjectPointer->PoolNext = NULL;

		addDiamTimerMessageToPool( oIAObjectPointer, bInLockMode, objStackObjects.TimerPool->FreePool);

		objStackObjects.TimerPool->PoolSize++;
	}

	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated DiamTimerMessagePool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.TimerPool->PoolSize);	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

void createDiamStickySessionMessagePool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating DiamStickySessionMessagePool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.StickySessionPool->PoolSize);
		
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		iStickySessionInfo *oStickySessionInfo = (iStickySessionInfo *)lib_malloc(sizeof(iStickySessionInfo));
		
		oStickySessionInfo->isReleased = 1;
		oStickySessionInfo->PoolIndex = (objStackObjects.StickySessionPool->PoolSize);
		oStickySessionInfo->PoolNext = NULL;

		addDiamStickySessionMessageToPool( oStickySessionInfo, bInLockMode, objStackObjects.StickySessionPool->FreePool);

		objStackObjects.StickySessionPool->PoolSize++;
	}	
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated DiamStickySessionMessagePool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.StickySessionPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

void createASTDataPtrPool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating ASTDataPtrPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.ASTDataPtrPool->PoolSize);
	
	int i = 0;
	for (i = 0; i < iBatchSize; i++)
	{
		struct ASTDataPtr *astDataPtr = (struct ASTDataPtr *)lib_malloc(sizeof(struct ASTDataPtr));
		astDataPtr->isReleased = 1;
		addASTDataPtrMessageToPool( astDataPtr, bInLockMode, objStackObjects.ASTDataPtrPool->FreePool);
		objStackObjects.ASTDataPtrPool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated ASTDataPtrPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.ASTDataPtrPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

void releaseASTDataPtr( struct ASTDataPtr *astDataPtr)
{
/*	
	if( astDataPtr->isReleased == 0)
	{
		addASTDataPtrMessageToPool( astDataPtr, 1, objStackObjects.ASTDataPtrPool->FreePool);
		objStackObjects.ASTDataPtrPool->PoolSize++;
	}
*/
	pthread_mutex_lock( &objStackObjects.ASTDataPtrPool->FreePool->Lock );
	
	if( astDataPtr->isReleased == 0)
	{
		astDataPtr->isReleased = 1;
		addASTDataPtrMessageToPool( astDataPtr, 0, objStackObjects.ASTDataPtrPool->FreePool);
		//objStackObjects.ASTDataPtrPool->PoolSize++;
	}
	pthread_mutex_unlock( &objStackObjects.ASTDataPtrPool->FreePool->Lock );	
}

struct ASTDataPtr* allocateASTDataPtr()
{
	struct ASTDataPtr* astDataPtr = NULL;
	
	pthread_mutex_lock( &objStackObjects.ASTDataPtrPool->FreePool->Lock );
	
	astDataPtr = objStackObjects.ASTDataPtrPool->FreePool->HeadPtr;
	
	//if( astDataPtr == NULL)
	if(!astDataPtr)	
	{
		//createASTDataPtrPool( 1000, 1);
		createASTDataPtrPool( 10000, 0);
		astDataPtr = objStackObjects.ASTDataPtrPool->FreePool->HeadPtr;
	}

	//if( astDataPtr != NULL)
	if( astDataPtr)	
	{
		objStackObjects.ASTDataPtrPool->FreePool->HeadPtr = astDataPtr->PoolNext;
	}	
	
	objStackObjects.ASTDataPtrPool->FreePool->Count--;
	
	pthread_mutex_unlock( &objStackObjects.ASTDataPtrPool->FreePool->Lock );
	
	astDataPtr->Count = 0;
	astDataPtr->GenerationId = 0;
	astDataPtr->Root = astDataPtr->Current = astDataPtr->NextItem = 0;	//astDataPtr->Parent = 0;
	astDataPtr->isReleased = 0;
	astDataPtr->isRoot = -1;
	astDataPtr->PoolNext = NULL;
	
	return astDataPtr;
}

void createSessionPool(int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating SessionPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.SessionPool->PoolSize);
	
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		struct SessionBaseRecord *iRecord = (struct SessionBaseRecord*)lib_malloc(sizeof(struct SessionBaseRecord));
		iRecord->NextRecord = NULL;
		iRecord->Data = NULL;
		iRecord->iKey = 0;
		memset( &iRecord->cKey, 0, sizeof(iRecord->cKey));
		
		addToSessionPool( iRecord, bInLockMode, objStackObjects.SessionPool->FreePool);
		
		objStackObjects.SessionPool->PoolSize++;
	}	
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated SessionPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.SessionPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}


void createDiamMessagePool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating DiamMessagePool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamMessagePool->PoolSize);
	
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		struct DiamMessage *oDiamMessage = __createMessage();

		oDiamMessage->isReleased = 1;
		oDiamMessage->PoolIndex = (objStackObjects.DiamMessagePool->PoolSize);

		addMessageToPool( oDiamMessage, bInLockMode, objStackObjects.DiamMessagePool->FreePool);

		objStackObjects.DiamMessagePool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated DiamMessagePool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamMessagePool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}



void createDiamRawDataPool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating DiamRawDataPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamDecodeMessagePool->PoolSize);
	
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		struct DiamRawData * dDiamRawData = (struct DiamRawData*)lib_malloc(sizeof(struct DiamRawData));
		struct CData* dHeaderData = (struct CData*)lib_malloc( sizeof(struct CData) );
		struct CData* dPayloadData = (struct CData*)lib_malloc( sizeof(struct CData) );

		dHeaderData->Data = (char*) lib_malloc( DIAM_BUFFER_SIZE_HEADER_SIZE );
		dPayloadData->Data = (char*) lib_malloc( DIAM_BUFFER_SIZE_PER_REQUEST );

		dDiamRawData->Header = dHeaderData;
		dDiamRawData->PayLoad = dPayloadData;

		dDiamRawData->isReleased = 1;
		dDiamRawData->PoolIndex = objStackObjects.DiamDecodeMessagePool->PoolSize;


		addDiamRawDataToPool( dDiamRawData, bInLockMode, objStackObjects.DiamDecodeMessagePool->FreePool);

		objStackObjects.DiamDecodeMessagePool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated DiamRawDataPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamDecodeMessagePool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}



void createCDataPool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating CDataPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamCDataPool->PoolSize);
	
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		struct CData* dPayloadData = (struct CData*)lib_malloc( sizeof(struct CData) );
		dPayloadData->Data = (char*) lib_malloc( AVP_CHUNK_SIZE );
		dPayloadData->len = 0;

		dPayloadData->isReleased = 1;
		dPayloadData->PoolIndex = (objStackObjects.DiamCDataPool->PoolSize);

		addDiamCDataPool( dPayloadData, bInLockMode, objStackObjects.DiamCDataPool->FreePool);

		objStackObjects.DiamCDataPool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated CDataPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamCDataPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}


void createDiamAVPPool( int iBatchSize, int bInLockMode)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating DiamAVPPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamAVPPool->PoolSize);
	
	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		struct DiamAvp* dDiamAvp = __createAVP();

		dDiamAvp->isReleased = 1;
		dDiamAvp->PoolIndex = (objStackObjects.DiamAVPPool->PoolSize);

		addDiamAVPToPool( dDiamAvp, bInLockMode, objStackObjects.DiamAVPPool->FreePool);

		objStackObjects.DiamAVPPool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated DiamAVPPool iBatchSize:%d  currentSize:%d", iBatchSize, objStackObjects.DiamAVPPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}


struct QueueRecord* allocateQueueRecord()
{
	struct QueueRecord* dmMsg = NULL;

	pthread_mutex_lock( &objStackObjects.QueuePool->FreePool->Lock );

	dmMsg = objStackObjects.QueuePool->FreePool->HeadPtr;

	//if( dmMsg == NULL)
	if(!dmMsg)	
	{
		//printf( "Pool Batch Increased by [%d]\n", objStackConfig.DecodeThreadPoolCount);
		//createQueueRecordPool( DIAM_QUEUE_MSG_INCREASE_BY_POOL_SIZE, 0);
		createQueueRecordPool( 10000, 0);

		dmMsg = objStackObjects.QueuePool->FreePool->HeadPtr;
	}

	//if( dmMsg != NULL)
	if( dmMsg)	
	{
		objStackObjects.QueuePool->FreePool->HeadPtr = dmMsg->PoolNext;
		dmMsg->PoolNext = NULL;
	}

	objStackObjects.QueuePool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.QueuePool->FreePool->Lock );

	objStackObjects.TotalMemoryUsage.QueueRecordAllocatedCount++;

	dmMsg->Next = NULL;
	dmMsg->Data = NULL;
	dmMsg->isReleased = 0;

	return dmMsg;
}


void releaseQueueRecord(struct QueueRecord* dmMsg)
{
/*	
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.QueueRecordReleasedCount++;		
		addQueueRecordToPool( dmMsg, 1, objStackObjects.QueuePool->FreePool);
	}
*/
	pthread_mutex_lock( &objStackObjects.QueuePool->FreePool->Lock );
	
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.QueueRecordReleasedCount++;		
		addQueueRecordToPool( dmMsg, 0, objStackObjects.QueuePool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.QueuePool->FreePool->Lock );
}

IAObjectPointer* allocateIAObjectPointer()
{
	IAObjectPointer* oMsg = NULL;	
	pthread_mutex_lock( &objStackObjects.TimerPool->FreePool->Lock );
	oMsg = objStackObjects.TimerPool->FreePool->HeadPtr;
	
	//if( oMsg == NULL)
	if(!oMsg)	
	{
		//createDiamTimerMessagePool( DIAM_TIMER_MSG_INCREASE_BY_POOL_SIZE, 1);
		createDiamTimerMessagePool( 50, 0);
		oMsg = objStackObjects.TimerPool->FreePool->HeadPtr;
	}
	
	//if( oMsg != NULL)
	if( oMsg)	
	{
		objStackObjects.TimerPool->FreePool->HeadPtr = oMsg->PoolNext;
		oMsg->PoolNext = NULL;
	}
	
	objStackObjects.TimerPool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.TimerPool->FreePool->Lock );
	oMsg->isReleased = 0;
	oMsg->ClearTimeOut = 0;
	
	return oMsg;
}

iStickySessionInfo* allocateStickySessionInfo()
{
	iStickySessionInfo* oMsg = NULL;	
	pthread_mutex_lock( &objStackObjects.StickySessionPool->FreePool->Lock );
	oMsg = objStackObjects.StickySessionPool->FreePool->HeadPtr;
	
	//if( oMsg == NULL)
	if(!oMsg)	
	{
		//createDiamStickySessionMessagePool( DIAM_TIMER_MSG_INCREASE_BY_POOL_SIZE, 1);
		createDiamStickySessionMessagePool( 50, 0);
		oMsg = objStackObjects.StickySessionPool->FreePool->HeadPtr;
	}
	
	//if( oMsg != NULL)
	if( oMsg)	
	{
		objStackObjects.StickySessionPool->FreePool->HeadPtr = oMsg->PoolNext;
		oMsg->PoolNext = NULL;
	}
	
	objStackObjects.StickySessionPool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.StickySessionPool->FreePool->Lock );
	oMsg->isReleased = 0;
	
	return oMsg;
}


void releaseIAObjectPointer( IAObjectPointer* oMsg)
{
/*	
	if(oMsg->isReleased == 0)
	{
		oMsg->isReleased = 1;
		addDiamTimerMessageToPool( oMsg, 1, objStackObjects.TimerPool->FreePool);
	}
*/
	pthread_mutex_lock( &objStackObjects.TimerPool->FreePool->Lock );

	if(oMsg->isReleased == 0)
	{
		oMsg->isReleased = 1;
		addDiamTimerMessageToPool( oMsg, 0, objStackObjects.TimerPool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.TimerPool->FreePool->Lock );
}


void releaseStickySessionPool( iStickySessionInfo* oMsg)
{
/*	
	if(oMsg->isReleased == 0)
	{
		oMsg->isReleased = 1;
		addDiamStickySessionMessageToPool( oMsg, 1, objStackObjects.StickySessionPool->FreePool);
	}
*/
	pthread_mutex_lock( &objStackObjects.StickySessionPool->FreePool->Lock );
	
	if(oMsg->isReleased == 0)
	{
		oMsg->isReleased = 1;
		addDiamStickySessionMessageToPool( oMsg, 0, objStackObjects.StickySessionPool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.StickySessionPool->FreePool->Lock );
	
}


struct DiamRouteMessage* allocateDiamRouteMessage()
{
	struct DiamRouteMessage* dmMsg = NULL;

	pthread_mutex_lock( &objStackObjects.DiamRoutePool->FreePool->Lock );

	dmMsg = objStackObjects.DiamRoutePool->FreePool->HeadPtr;

	//if( dmMsg == NULL)
	if(!dmMsg)	
	{
		//createDiamRouteMessagePool( DIAM_ROUTE_MSG_INCREASE_BY_POOL_SIZE, 1);
		createDiamRouteMessagePool( 50, 0);
		dmMsg = objStackObjects.DiamRoutePool->FreePool->HeadPtr;
	}

	//if( dmMsg != NULL)
	if( dmMsg)	
	{
		objStackObjects.DiamRoutePool->FreePool->HeadPtr = dmMsg->PoolNext;
		dmMsg->PoolNext = NULL;
	}

	objStackObjects.DiamRoutePool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.DiamRoutePool->FreePool->Lock );

	objStackObjects.TotalMemoryUsage.DiamRoutePoolAllocatedCount++;

	dmMsg->isReleased = 0;

	return dmMsg;
}

void releaseDiamRouteMessage(struct DiamRouteMessage* dmMsg)
{
/*	
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamRoutePoolReleasedCount++;		
		addDiamRouteMessageToPool( dmMsg, 1, objStackObjects.DiamRoutePool->FreePool);
	}
*/
	pthread_mutex_lock( &objStackObjects.DiamRoutePool->FreePool->Lock );
	
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamRoutePoolReleasedCount++;		
		addDiamRouteMessageToPool( dmMsg, 0, objStackObjects.DiamRoutePool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.DiamRoutePool->FreePool->Lock );
}


struct SessionBaseRecord* allocateSessionRecord()
{
	struct SessionBaseRecord* dmMsg = NULL;

	pthread_mutex_lock( &objStackObjects.SessionPool->FreePool->Lock );

	dmMsg = objStackObjects.SessionPool->FreePool->HeadPtr;

	//if( dmMsg == NULL)
	if(!dmMsg)	
	{
		//createSessionPool( DM_MSG_INCREASE_BY_POOL_SIZE, 1);
		createSessionPool( 50, 0);
		dmMsg = objStackObjects.SessionPool->FreePool->HeadPtr;
	}
	
	//if( dmMsg != NULL)
	if( dmMsg)	
	{
		objStackObjects.SessionPool->FreePool->HeadPtr = dmMsg->NextRecord;
		dmMsg->NextRecord = NULL;
	}
	
	objStackObjects.SessionPool->FreePool->Count--;
	
	pthread_mutex_unlock( &objStackObjects.SessionPool->FreePool->Lock );	
	
	objStackObjects.TotalMemoryUsage.SessionBaseRecordAllocatedCount++;
	
	dmMsg->iKey = 0;
	memset( &dmMsg->cKey, 0, sizeof( dmMsg->cKey));
	dmMsg->Data = NULL;
	
	return dmMsg;
}

void releaseSessionBaseRecord(struct SessionBaseRecord* dmMsg)
{
/*	
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.SessionBaseRecordReleasedCount++;		
		addToSessionPool( dmMsg, 1, objStackObjects.SessionPool->FreePool);
	}
*/
	pthread_mutex_lock( &objStackObjects.SessionPool->FreePool->Lock );
	
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.SessionBaseRecordReleasedCount++;		
		addToSessionPool( dmMsg, 0, objStackObjects.SessionPool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.SessionPool->FreePool->Lock );
}

void __addToSessionStore( struct SessionBaseRecord *rec)
{
	pthread_mutex_lock( &objStackObjects.SessionPool->Lock);
	
	//struct SessionBaseRecord* current;
	
	//if( objStackObjects.SessionPool->SBRHeadPtr == NULL) 
	if(!objStackObjects.SessionPool->SBRHeadPtr) 	
	{
		objStackObjects.SessionPool->SBRCurrPtr = objStackObjects.SessionPool->SBRHeadPtr = rec;
	} 
	else 
	{
		//current = objStackObjects.SessionPool->SBRHeadPtr;
		//rec->NextRecord = current->NextRecord;
        //current->NextRecord = rec;
        
        //((struct DiamRawData*)mPtr->CurrPtr)->PoolNext = (void*)oDiamRawData;
        
		//current = objStackObjects.SessionPool->SBRHeadPtr;
		//rec->NextRecord = objStackObjects.SessionPool->SBRHeadPtr;
		//objStackObjects.SessionPool->SBRHeadPtr = rec;
        //current->NextRecord = rec;    
        
        /*
else
	{
		((struct QueueRecord*)mPtr->CurrPtr)->PoolNext = (void*)oQueueRecord;
	}

	mPtr->CurrPtr = (void*)oQueueRecord;
	* 
	* 
         * */
        
        objStackObjects.SessionPool->SBRCurrPtr->SessionNext = rec;  
        objStackObjects.SessionPool->SBRCurrPtr = rec;
          
	}
	
	objStackObjects.SessionPool->CurrentSize++;
	objStackObjects.SessionPool->PushCount++; 
	pthread_mutex_unlock( &objStackObjects.SessionPool->Lock);	
}

IASTDataPtr *__getChildASTDataPtr( IASTDataPtr *dataPtr, short keyIndex, int kNumericVal, int isGet)
{
	//its null and get no data
	if(!dataPtr && isGet == 1) 
	{
		return NULL;
	}
		
	if(!dataPtr->Root && isGet == 1) 
	{
		return NULL;
	}
	
	//its null, created its child
	if(!dataPtr->Root && isGet == 0) 
	{	
		//dataPtr->Root IS NULL and ADD New
		
		dataPtr->Root = allocateASTDataPtr();
		dataPtr->Root->PtrCharVal = kNumericVal;
		dataPtr->Root->GenerationId = keyIndex;
		dataPtr->Root->Root = dataPtr->Root->Current = dataPtr->Root->NextItem = NULL;
		dataPtr->Root->isRoot = 1;
		dataPtr->Root->Parent = dataPtr;
		dataPtr->Root->PrevItem = NULL;
		dataPtr->Root->Count = 0;
		
		//printf("allocated keyIndex=%d kNumericVal=%d[%c] gId[%d] [%p]\n", keyIndex, kNumericVal , kNumericVal, dataPtr->Root->GenerationId, dataPtr->Root);
		
		dataPtr->Current = dataPtr->Root;
		return dataPtr->Root;
	}
	
	
	
	IASTDataPtr *childDataPtr = dataPtr->Root;	//this is where next generation starts...
	IASTDataPtr *lastChildDataPtr = NULL;
			
	while( childDataPtr)
	{	
		lastChildDataPtr = childDataPtr;
		
		if( childDataPtr->PtrCharVal == kNumericVal && (keyIndex) == childDataPtr->GenerationId) 
		{
			//printf("providing keyIndex=%d kNumericVal=%d[%c] gId[%d] [%p]\n", keyIndex, kNumericVal , kNumericVal, childDataPtr->GenerationId, childDataPtr);
			return childDataPtr;
		}
		childDataPtr = childDataPtr->NextItem;
	}
	
	if(isGet == 1) 
		return NULL;
	
	/*
	lastChildDataPtr->Next = allocateASTDataPtr();
	lastChildDataPtr->Next->PtrCharVal = kNumericVal;
	lastChildDataPtr->Next->GenerationId = keyIndex;
	lastChildDataPtr->Next->Next = NULL;
	//printf("--- provided object\n");
	printf(">> providing keyIndex=%d kNumericVal=%d[%c] gId[%d] [%p]\n", keyIndex, kNumericVal , kNumericVal, lastChildDataPtr->Next->GenerationId, lastChildDataPtr->Next);
	return lastChildDataPtr->Next;
	*/
	
	IASTDataPtr *oItem = allocateASTDataPtr();
	oItem->PtrCharVal = kNumericVal;
	oItem->GenerationId = keyIndex;
	oItem->Root = oItem->Current = oItem->NextItem = NULL;
	oItem->isRoot = 0;
	oItem->PrevItem = dataPtr->Current;
	oItem->Parent = dataPtr;
	oItem->Count = 0;

	//printf(">> allocated keyIndex=%d kNumericVal=%d[%c] gId[%d] [%p]\n", keyIndex, kNumericVal , kNumericVal, oItem->GenerationId, oItem);	
	dataPtr->Current->NextItem = oItem;
	dataPtr->Current = oItem;
	return oItem;
}


int __addASTItem( IASTDataPtr *dataPtr, char * Key, void * Data, pthread_mutex_t *pLock)
{
	pthread_mutex_lock( pLock);
	
	short il;
	int keyLen = strlen(Key);
	IASTDataPtr *childPtr = dataPtr;
	
	for( il = 0; il < keyLen; il++) 
	{
		childPtr = __getChildASTDataPtr( childPtr, il, Key[il], 0);
		
		if(!childPtr) 
		{	
			pthread_mutex_unlock( pLock);
			return -1;
		}
		else
		{
			childPtr->Count++;	//Tracking For Delete.
			//printf( "PtrCharVal:%d(%c) Count:%d isRoot:<%d> %p\n", childPtr->PtrCharVal, childPtr->PtrCharVal, childPtr->Count, childPtr->isRoot, childPtr);
		}
	}
	
	// printf("dataPtr->Root->PtrCharVal[%d](%c) GenerationId[%d]\n", dataPtr->Root->PtrCharVal, dataPtr->Root->PtrCharVal, dataPtr->Root->GenerationId);
	// printf("dataPtr->Root->Root->PtrCharVal[%d](%c) GenerationId[%d]\n", dataPtr->Root->Root->PtrCharVal, dataPtr->Root->Root->PtrCharVal, dataPtr->Root->Root->GenerationId);
	// printf("dataPtr->Root->Root->Root->PtrCharVal[%d](%c) GenerationId[%d]\n", dataPtr->Root->Root->Root->PtrCharVal, dataPtr->Root->Root->Root->PtrCharVal, dataPtr->Root->Root->Root->GenerationId);
	
	childPtr->Data = Data;
	
	pthread_mutex_unlock( pLock);
	return 1;
}

void printASTDataPtrPoolSize()
{
	printf("printASTDataPtrPoolSize = %ld\n", objStackObjects.ASTDataPtrPool->FreePool->Count);
}

int __addASTItemLock( iRootASTDataPtr *dataPtr, char * Key, void * Data)
{
	return __addASTItem( dataPtr->iASTDataPtr, Key, Data, &dataPtr->pLock);
}

int __addIndexASTItemLock( iIndexASTDataPtr *dataPtr, char * Key, void * Data)
{
	void* arrayList = NULL;
	__getASTItem( dataPtr->iASTDataPtr, Key, 0, &dataPtr->pLock, &arrayList);
	
	if(!arrayList)
	{
		arrayList_create( &arrayList);
		__addASTItem( dataPtr->iASTDataPtr, Key, arrayList, &dataPtr->pLock);
	}
	arrayList_push( arrayList, Data);
	
	return 0;
}


int __addDataToTreeIntAsKey( iRootASTDataPtr *dataPtr, int iKey, void * Data)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%d", iKey);
	
	return __addASTItemLock( dataPtr, sKey, Data);	
}

int __addDataToIndexIntAsKey( iIndexASTDataPtr *dataPtr, int iKey, void * Data)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%d", iKey);
	
	return __addIndexASTItemLock( dataPtr, sKey, Data);	
}

int __addDataToTreeLongAsKey( iRootASTDataPtr *dataPtr, long iKey, void * Data)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%ld", iKey);
	
	return __addASTItemLock( dataPtr, sKey, Data);	
}

int __addDataToIndexLongAsKey( iIndexASTDataPtr *dataPtr, long iKey, void * Data)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%ld", iKey);
	
	return __addIndexASTItemLock( dataPtr, sKey, Data);	
}

int __addDataToTreeCharAsKey( iRootASTDataPtr *dataPtr, char * Key, void * Data)
{
	return __addASTItemLock( dataPtr, Key, Data);
}

int __addDataToIndexCharAsKey( iIndexASTDataPtr *dataPtr, char * Key, void * Data)
{
	return __addIndexASTItemLock( dataPtr, Key, Data);	
}

void createRootASTDataPtr(void **rootDataPtr )
{
	iRootASTDataPtr *dataPtr = (iRootASTDataPtr *)lib_malloc( sizeof(iRootASTDataPtr) );
	dataPtr->PoolNext = NULL;
	dataPtr->iASTDataPtr = allocateASTDataPtr();
	dataPtr->iASTDataPtr->Root = dataPtr->iASTDataPtr->Current = dataPtr->iASTDataPtr->NextItem = NULL;
	dataPtr->iASTDataPtr->GenerationId = -1;
	pthread_mutex_init( &dataPtr->pLock, NULL);
	
	*rootDataPtr = dataPtr;
}

void createIndexASTDataPtr(void **indexPtr )
{
	iIndexASTDataPtr *dataPtr = (iIndexASTDataPtr *)lib_malloc( sizeof(iIndexASTDataPtr) );
	dataPtr->PoolNext = NULL;
	dataPtr->iASTDataPtr = allocateASTDataPtr();
	dataPtr->iASTDataPtr->Root = dataPtr->iASTDataPtr->Current = dataPtr->iASTDataPtr->NextItem = NULL;	
	pthread_mutex_init( &dataPtr->pLock, NULL);
	
	*indexPtr = dataPtr;
}



void* __getASTItem( IASTDataPtr *dataPtr, char * Key, int setNull, pthread_mutex_t *pLock, void **dataOut)
{
	pthread_mutex_lock( pLock);
	
	short il;
	int keyLen = strlen(Key);
	//printf("key=%s keyLen[%d]\n", Key, keyLen);
	
	IASTDataPtr * pathElements[keyLen];
	
	IASTDataPtr *childPtr = dataPtr;
	
	for( il = 0; il < keyLen; il++) 
	{
		//printf("%c", Key[il]);
		childPtr = __getChildASTDataPtr( childPtr, il, Key[il], 1);
		
		if(!childPtr) 
		{	
			*dataOut = NULL;
			pthread_mutex_unlock( pLock);
			//printf("=> 1\n");
			return NULL;
		}
		else
		{
			pathElements[il] = childPtr;
		}
	}

	/*
	for( il = keyLen; il-- > 0; ) 
	{
		if( pathElements[il])
		{
			printf( "PtrCharVal:%d(%c) Count:%d il:%d isRoot:%d %p\n", pathElements[il]->PtrCharVal, pathElements[il]->PtrCharVal, 
			pathElements[il]->Count, il, pathElements[il]->isRoot, pathElements[il]);
		}	
	}	
	*/
	
		
	if( setNull == 0)
	{
		*dataOut = childPtr->Data;
		pthread_mutex_unlock( pLock);
		//printf("=> 2\n");
		return childPtr->Data;
	}
	else	
	{
		*dataOut = childPtr->Data;
		
		void* oData	= childPtr->Data;
		childPtr->Data = NULL;
		
		for( il = keyLen; il-- > 0; ) 
		{
			//check is it having child/or in middle of path?
			// if( pathElements[il]->Root)
			// {
				// printf( "delete:: pathElements[il]->Root[%d](%c) %p pathElements[il][%d](%c)\n", 
					// pathElements[il]->Root->PtrCharVal, pathElements[il]->Root->PtrCharVal, pathElements[il]->Root, 
					// pathElements[il]->PtrCharVal, pathElements[il]->PtrCharVal);
			// }
			// else
			if( !pathElements[il]->Root)	
			{
				//its a last node, we can delete. 
				//printf("delete:: No Root [%d](%c) %d\n", pathElements[il]->PtrCharVal, pathElements[il]->PtrCharVal, il);
				
				//has next siblings
				if( pathElements[il]->NextItem)
				{
					//its root item
					if( pathElements[il]->Parent->Root == pathElements[il])
					{
						if( !pathElements[il]->Data)
						{	
							//printf("delete:: siblings check [%p] (parRoot[%p] [%p])\n",  pathElements[il]->NextItem, pathElements[il]->Parent->Root, pathElements[il]);
						
							//if root and this is same?
							pathElements[il]->Parent->Root = pathElements[il]->NextItem;
							pathElements[il]->NextItem->PrevItem = NULL;
							pathElements[il]->Root = pathElements[il]->Current = pathElements[il]->NextItem = pathElements[il]->PrevItem = NULL;
							releaseASTDataPtr( pathElements[il]);
							//printf("releaseASTDataPtr Called __LINE__:%d Key[%s] %p\n", __LINE__, Key, pathElements[il]);
						}
					}
					//its a middle node
					else if(pathElements[il]->PrevItem && pathElements[il]->NextItem)
					{
						pathElements[il]->PrevItem->NextItem = pathElements[il]->NextItem;
						pathElements[il]->NextItem->PrevItem = pathElements[il]->PrevItem;
						pathElements[il]->Root = pathElements[il]->Current = pathElements[il]->NextItem = pathElements[il]->PrevItem = NULL;
						releaseASTDataPtr( pathElements[il]);
						//printf("releaseASTDataPtr Called __LINE__:%d Key[%s] %p\n", __LINE__, Key, pathElements[il]);
					}
				}
				//has prev siblings, may be this is last element
				else if(pathElements[il]->PrevItem)
				{
					pathElements[il]->Parent->Current = pathElements[il]->PrevItem;
					pathElements[il]->PrevItem->NextItem = NULL;
					pathElements[il]->Root = pathElements[il]->Current = pathElements[il]->NextItem = pathElements[il]->PrevItem = NULL;
					releaseASTDataPtr( pathElements[il]);
					//printf("releaseASTDataPtr Called __LINE__:%d Key[%s] %p\n", __LINE__, Key, pathElements[il]);
				}
				else
				{
					//No Next and No Prev
					// pathElements[il]->Parent->Current = pathElements[il]->Parent->Root;
					
					pathElements[il]->Parent->Current = pathElements[il]->Parent->Root = NULL;
					pathElements[il]->Root = pathElements[il]->Current = pathElements[il]->NextItem = pathElements[il]->PrevItem = NULL;
					releaseASTDataPtr( pathElements[il]);
					//printf("releaseASTDataPtr Called __LINE__:%d Key[%s] %p\n", __LINE__, Key, pathElements[il]);				
				}
				
			}
			
			
			//if its is at end delete the node.
			//check does it has sibings and its root? make next sibling as root.
			//if its in middle join others
			//if its end delete
			
		}


		
		pthread_mutex_unlock( pLock);
		//printf("=> 2\n");
		return oData;
	}
}

void __delParentASTItem( IASTDataPtr *dataPtr)
{
	if(dataPtr)
	{
		//check parent has other childs
	}
}

/*
void* __delASTItem( IASTDataPtr *dataPtr, char * Key, pthread_mutex_t *pLock)
{
	return NULL;
	
	pthread_mutex_lock( pLock);
	
	int il;
	int keyLen = strlen(Key);
	IASTDataPtr *childPtr = dataPtr;
	
	for( il = 0; il < keyLen; il++) 
	{
		childPtr = __getChildASTDataPtr( childPtr, il, Key[il], 1);
		
		if(!childPtr) 
		{	
			pthread_mutex_unlock( pLock);
			return -1;
		}
	}
	
	//We got the Place Holder Element
	IASTDataPtr *ParentPtr = childPtr->Parent;
	
	childPtr->Parent = NULL;
	releaseASTDataPtr( childPtr);
	__delParentASTItem( ParentPtr);
	
	pthread_mutex_unlock( pLock);
}
*/

void* __getASTItemLock( iRootASTDataPtr *dataPtr, char * Key, int setNull, void **dataOut)
{
	return __getASTItem( dataPtr->iASTDataPtr, Key, setNull, &dataPtr->pLock, dataOut);
}

void* __getIndexASTItemLock( iIndexASTDataPtr *dataPtr, char * Key, int setNull, void **dataOut)
{
	return __getASTItem( dataPtr->iASTDataPtr, Key, setNull, &dataPtr->pLock, dataOut);
}

void* __getDataFromTreeIntAsKey( iRootASTDataPtr *dataPtr, int iKey, int setNull, void **dataOut)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%d", iKey);
	
	return __getASTItemLock( dataPtr, sKey, setNull, dataOut);	
}

void* __getDataFromIndexIntAsKey( iIndexASTDataPtr *dataPtr, int iKey, int setNull, void **dataOut)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%d", iKey);
	
	return __getIndexASTItemLock( dataPtr, sKey, setNull, dataOut);	
}

void* __getDataFromTreeLongAsKey( iRootASTDataPtr *dataPtr, long iKey, int setNull, void **dataOut)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%ld", iKey);
	
	return __getASTItemLock( dataPtr, sKey, setNull, dataOut);	
}

void* __getDataFromIndexLongAsKey( iIndexASTDataPtr *dataPtr, long iKey, int setNull, void **dataOut)
{
	char sKey[25];
	memset( &sKey, 0, sizeof(sKey));
	sprintf( sKey, "%ld", iKey);
	
	return __getIndexASTItemLock( dataPtr, sKey, setNull, dataOut);	
}

void* __getDataFromTreeCharAsKey( iRootASTDataPtr *dataPtr, char * sKey, int setNull, void **dataOut)
{
	return __getASTItemLock( dataPtr, sKey, setNull, dataOut);
}

void* __getDataFromIndexCharAsKey( iIndexASTDataPtr *dataPtr, char * sKey, int setNull, void **dataOut)
{
	return __getIndexASTItemLock( dataPtr, sKey, setNull, dataOut);
}

void __pushDataWithStrKey( char *cKey, void *ptrData)
{
	struct SessionBaseRecord *rec = (struct SessionBaseRecord *)allocateSessionRecord();
	
	strcpy( rec->cKey, cKey);
	rec->Data = ptrData;
	rec->SessionNext = NULL;
	
	__addToSessionStore( rec);	
}

void __pushDataWithUnsigned32Key( unsigned int iKey, void *ptrData)
{
	struct SessionBaseRecord *rec = (struct SessionBaseRecord *)allocateSessionRecord();

	rec->iKey = iKey;	
	rec->Data = ptrData;
	rec->SessionNext = NULL;
	
	__addToSessionStore( rec);	
}

void* __popDataWithStrKey( char *cData)
{
	pthread_mutex_lock( &objStackObjects.SessionPool->Lock);
	
	void* Data = NULL;
	
	
	struct SessionBaseRecord* current = NULL;
	//struct SessionBaseRecord* previous = NULL;
	
	current = objStackObjects.SessionPool->SBRHeadPtr;	
	
	//while (current != NULL)
	while ( current)	
	{
		//printf("__popDataWithStrKey cData=%s CurrentKey=%s\n", cData, current->cKey);
		
		if( strcmp( current->cKey, cData) == 0 )
		{
			Data = current->Data;
			
			/*
			//This is the Head  
			if( previous == NULL) 
			{
				//Having Next Entry
				if( current->SessionNext != NULL)
				{
					objStackObjects.SessionPool->SBRHeadPtr = current->SessionNext;
				}
				else
				{
					//Only 1 Record, Making NULL both Pointers
					objStackObjects.SessionPool->SBRCurrPtr = objStackObjects.SessionPool->SBRHeadPtr = NULL;
				}
			}
			else
			{
				//The Record is in between
				previous->SessionNext = current->SessionNext;
				if( previous->SessionNext == NULL)
				{
					//This is the Last Record	
					objStackObjects.SessionPool->SBRCurrPtr = previous;
				}
			}
			*/
			
			/*
			memset( current->cKey, 0, sizeof(current->cKey));
			current->NextRecord = NULL;
			//current->Data = NULL;
			
			addToSessionPool( current, 1, objStackObjects.SessionPool->FreePool);			
			*/
			
			objStackObjects.SessionPool->CurrentSize--;			
			objStackObjects.SessionPool->PopCount++; 
			break;	
		}
		
		//if( Data != NULL) 
		if( Data)	
		{
			break;
		} 
		else 
		{
			current = current->SessionNext;
			//previous = current;
		}
			
	}	
	pthread_mutex_unlock( &objStackObjects.SessionPool->Lock);
	
	return Data;
}


void* __popDataWithUnsigned32Key( unsigned int iKey)
{
	void* Data = NULL;
	
	pthread_mutex_lock( &objStackObjects.SessionPool->Lock);
	
	struct SessionBaseRecord* current = NULL;
	struct SessionBaseRecord* previous = NULL;
	
	current = objStackObjects.SessionPool->SBRHeadPtr;	
	
	//while (current != NULL)
	while (current)	
	{
		//if( strcmp( current->cKey, cData) == 0 )
		if( current->iKey == iKey)
		{
			Data = current->Data;
			
			//if( previous != NULL) {
			if( previous ) {	
				previous->NextRecord = current->NextRecord;
			} else {
				objStackObjects.SessionPool->SBRHeadPtr = current->NextRecord;
			}

			memset( current->cKey, 0, sizeof(current->cKey));
			current->NextRecord = NULL;
			current->Data = NULL;
			
			addToSessionPool( current, 1, objStackObjects.SessionPool->FreePool);
			
			
			objStackObjects.SessionPool->PopCount++;
			break;	
		}
		
		//if( Data != NULL) {
		if(Data) {	
			break;
		}
		
		current = current->NextRecord;
		previous = current;
	}	
	pthread_mutex_unlock( &objStackObjects.SessionPool->Lock);
	
	return Data;
}





struct DiamRawData* allocateDiamRawData()
{
	struct DiamRawData* dmMsg = NULL;

	pthread_mutex_lock( &objStackObjects.DiamDecodeMessagePool->FreePool->Lock );

	dmMsg = objStackObjects.DiamDecodeMessagePool->FreePool->HeadPtr;

	//if( dmMsg == NULL)
	if(!dmMsg)	
	{
		//printf( "Pool Batch Increased by [%d]\n", objStackConfig.DecodeThreadPoolCount);
		//createDiamRawDataPool( DIAM_RAW_MSG_INCREASE_BY_POOL_SIZE, 1);
		createDiamRawDataPool( 100, 0);

		dmMsg = objStackObjects.DiamDecodeMessagePool->FreePool->HeadPtr;
	}

	//if( dmMsg != NULL)
	if(dmMsg)	
	{
		objStackObjects.DiamDecodeMessagePool->FreePool->HeadPtr = dmMsg->PoolNext;
		dmMsg->PoolNext = NULL;
	}

	objStackObjects.DiamDecodeMessagePool->FreePool->Count--;
	objStackObjects.TotalMemoryUsage.DiamRawDataAllocatedCount++;
	
	pthread_mutex_unlock( &objStackObjects.DiamDecodeMessagePool->FreePool->Lock );

	memset( dmMsg->Header->Data, 0, DIAM_BUFFER_SIZE_HEADER_SIZE);
	memset( dmMsg->PayLoad->Data, 0, DIAM_BUFFER_SIZE_PER_REQUEST);

	//printf("Allocated DiamRawData Pool Index[%d] PoolFreeCount[%d]\n", dmMsg->PoolIndex, objStackObjects.DiamDecodeMessagePool->FreePool->Count);

	dmMsg->iRouteMessageTo = 0;
	dmMsg->iDecodeFull = 0;
	dmMsg->iRoutinError = 0;
	dmMsg->iErrorCode = 0;
	dmMsg->isReleased = 0;
	dmMsg->CliInfo = NULL;
	dmMsg->PeerConfigData = NULL;
	dmMsg->iPeerIndex = -1;
	
	return dmMsg;
}






void releaseDiamRawData(struct DiamRawData* dmMsg)
{
	/*
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamRawDataReleaseCount++;		
		addDiamRawDataToPool( dmMsg, 1, objStackObjects.DiamDecodeMessagePool->FreePool);
	}
	*/	
	
	pthread_mutex_lock( &objStackObjects.DiamDecodeMessagePool->FreePool->Lock );
	
	if(dmMsg->isReleased == 0)
	{
		dmMsg->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamRawDataReleaseCount++;		
		addDiamRawDataToPool( dmMsg, 0, objStackObjects.DiamDecodeMessagePool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.DiamDecodeMessagePool->FreePool->Lock );	
}


struct DiamMessage* allocateMessage()
{
	struct DiamMessage* dmMsg = NULL;

	pthread_mutex_lock( &objStackObjects.DiamMessagePool->FreePool->Lock );

	dmMsg = objStackObjects.DiamMessagePool->FreePool->HeadPtr;

	//if( dmMsg == NULL)
	if(!dmMsg)	
	{
		//printf( "Pool Batch Increased by [%d]\n", DM_MSG_INCREASE_BY_POOL_SIZE);
		//createDiamMessagePool( DM_MSG_INCREASE_BY_POOL_SIZE, 1);
		createDiamMessagePool( 100, 0);
		
		dmMsg = objStackObjects.DiamMessagePool->FreePool->HeadPtr;
	}

	//if( dmMsg != NULL)
	if( dmMsg)	
	{
		objStackObjects.DiamMessagePool->FreePool->HeadPtr = dmMsg->PoolNext;
		//dmMsg->PoolNext = NULL;
	}

	objStackObjects.DiamMessagePool->FreePool->Count--;
	objStackObjects.TotalMemoryUsage.DiamMessageAllocatedCount++;
	
	pthread_mutex_unlock( &objStackObjects.DiamMessagePool->FreePool->Lock );

	

	dmMsg->CmdCode = 0;
	dmMsg->Length = 0;
	dmMsg->AppId = 0;
	dmMsg->HBHId = 0;
	dmMsg->E2EId = 0;
	memset( &dmMsg->Flags, 0, sizeof(struct CmdFlags));
	dmMsg->AvpCount = 0;
	dmMsg->Head = NULL;
	dmMsg->isReleased = 0;
	dmMsg->PoolNext = NULL;
	dmMsg->IMSI = -1;
	dmMsg->MSISDN = -1;
	dmMsg->IMEI = -1;
	
	//printf("Allocated DiamMessage Pool Index[%d] PoolFreeCount[%d]\n", dmMsg->PoolIndex, objStackObjects.DiamMessagePool->FreePool->Count);

	return dmMsg;
}

void releaseGroupedDiamAvp( struct DiamAvp* dmAvp)
{
		struct DiamAvp* dmGHAvp = NULL;
		struct DiamAvp* dmGroupNext = NULL;
		dmGHAvp = dmAvp->GroupHead;
		
		//while(dmGHAvp != NULL)
		while( dmGHAvp)	
		{
			dmGroupNext = dmGHAvp->Next;
			
			if(dmGHAvp->iDataType == OCTET_STRING)
			{
				//if(dmGHAvp->PayLoad != NULL)
				if( dmGHAvp->PayLoad)	
				{
					releaseCData( dmGHAvp->PayLoad);
					dmGHAvp->PayLoad = NULL;
				}
			} 			
			else if( dmGHAvp->iDataType == GROUPED)
			{
				releaseGroupedDiamAvp( dmGHAvp);
			}
			releaseDiamAvp( dmGHAvp);
			dmGHAvp = NULL;
			
			dmGHAvp = dmGroupNext;
		}
}


void releaseMessage(struct DiamMessage* dmMsg)
{
	//printf("releaseMessage %d \n", dmMsg->isReleased);
	
	if( dmMsg->isReleased == 0)
	{
		//printf("releaseMessage==============================================================================\n");
		dmMsg->isReleased = 1;
		
		struct DiamAvp* dmAvp = NULL;
		struct DiamAvp* dmAvpNext = NULL;
		dmAvp = dmMsg->Head;

		//while(dmAvp != NULL)
		while( dmAvp)	
		{
			dmAvpNext = dmAvp->Next;

			
			if(dmAvp->iDataType == OCTET_STRING)
			{
				//if(dmAvp->PayLoad != NULL)
				if(dmAvp->PayLoad)	
				{
					releaseCData(dmAvp->PayLoad);
					dmAvp->PayLoad = NULL;
				}
			} 
			else if( dmAvp->iDataType == GROUPED)
			{
				releaseGroupedDiamAvp( dmAvp);
			}
				
			
			//printf("release AVPCode[%d]\n", dmAvp->AvpCode);

			releaseDiamAvp( dmAvp);
			dmAvp = NULL;

			dmAvp = dmAvpNext;
		}

		
		pthread_mutex_lock( &objStackObjects.DiamMessagePool->FreePool->Lock );
		
		objStackObjects.TotalMemoryUsage.DiamMessageReleaseCount++;		
		addMessageToPool( dmMsg, 0, objStackObjects.DiamMessagePool->FreePool);
		
		pthread_mutex_unlock( &objStackObjects.DiamMessagePool->FreePool->Lock );

		//printf("Released DiamMessage Pool Index[%d] PoolFreeCount[%d]\n", dmMsg->PoolIndex, objStackObjects.DiamMessagePool->FreePool->Count);
	}
	
	
}


struct CData* allocateCData()
{
	struct CData* dmMsg = NULL;

	pthread_mutex_lock( &objStackObjects.DiamCDataPool->FreePool->Lock );

	dmMsg = objStackObjects.DiamCDataPool->FreePool->HeadPtr;

	//if( dmMsg == NULL)
	if(!dmMsg)	
	{
		//printf( "Pool Batch Increased by [%d]\n", DM_MSG_INCREASE_BY_POOL_SIZE);
		//createCDataPool( DM_CDATA_INCREASE_BY_POOL_SIZE, 1);
		createCDataPool( 100, 0);

		dmMsg = objStackObjects.DiamCDataPool->FreePool->HeadPtr;
	}

	//if( dmMsg != NULL)
	if( dmMsg)	
	{
		objStackObjects.DiamCDataPool->FreePool->HeadPtr = dmMsg->PoolNext;
		dmMsg->PoolNext = NULL;
	}

	objStackObjects.DiamCDataPool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.DiamCDataPool->FreePool->Lock );

	objStackObjects.TotalMemoryUsage.DiamCDataAllocatedCount++;

	memset( dmMsg->Data, 0, AVP_CHUNK_SIZE);
	dmMsg->len = 0;
	dmMsg->isReleased = 0;

	//printf("Allocated CData Pool Index[%d] PoolFreeCount[%d]\n", dmMsg->PoolIndex, objStackObjects.DiamCDataPool->FreePool->Count);

	return dmMsg;
}

void releaseCData(struct CData* oCData)
{
/*	
	if( oCData->isReleased == 0)
	{
		oCData->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamCDataReleaseCount++;		
		addDiamCDataPool( oCData, 1, objStackObjects.DiamCDataPool->FreePool);
	}	
*/

	pthread_mutex_lock( &objStackObjects.DiamCDataPool->FreePool->Lock );
	
	if( oCData->isReleased == 0)
	{
		oCData->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamCDataReleaseCount++;		
		addDiamCDataPool( oCData, 0, objStackObjects.DiamCDataPool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.DiamCDataPool->FreePool->Lock );
}



struct DiamAvp* allocateDiamAvp()
{
	struct DiamAvp* dmMsg = NULL;

	pthread_mutex_lock( &objStackObjects.DiamAVPPool->FreePool->Lock );

	dmMsg = objStackObjects.DiamAVPPool->FreePool->HeadPtr;

	//if( dmMsg == NULL)
	if(!dmMsg)	
	{
		//printf( "Pool Batch Increased by [%d]\n", DM_MSG_INCREASE_BY_POOL_SIZE);
		//createDiamAVPPool( DM_AVP_INCREASE_BY_POOL_SIZE, 1);
		createDiamAVPPool( 100, 0);

		dmMsg = objStackObjects.DiamAVPPool->FreePool->HeadPtr;
	}

	//if( dmMsg != NULL)
	if( dmMsg )	
	{
		objStackObjects.DiamAVPPool->FreePool->HeadPtr = dmMsg->PoolNext;
		dmMsg->PoolNext = NULL;
	}

	objStackObjects.DiamAVPPool->FreePool->Count--;
	pthread_mutex_unlock( &objStackObjects.DiamAVPPool->FreePool->Lock );
	
	objStackObjects.TotalMemoryUsage.DiamAVPAllocatedCount++;

	dmMsg->AvpCode = 0;
	dmMsg->AvpLength = 0;
	dmMsg->Padding = 0;
	dmMsg->PayLoadLength = 0;
	dmMsg->HeaderLength = 0;
	dmMsg->VendorId = 0;
	dmMsg->iDataType = -1;
	dmMsg->intVal = 0;
	dmMsg->usIntVal = 0;
	dmMsg->int64Val = 0;
	dmMsg->usInt64Val = 0;
	dmMsg->fVal = 0;
	dmMsg->PayLoad = NULL;
	dmMsg->Head = NULL;
	dmMsg->Next = NULL;
	dmMsg->GroupHead = NULL;
	dmMsg->GroupCurrent = NULL;
	dmMsg->isReleased = 0;
	memset( &dmMsg->Flags, 0 , (sizeof(struct AvpFlags)));

	//printf("Allocated DiamAvp Pool Index[%d] PoolFreeCount[%d]\n", dmMsg->PoolIndex, objStackObjects.DiamAVPPool->FreePool->Count);

	return dmMsg;
}


void releaseDiamAvp(struct DiamAvp* oDiamAvp)
{
/*	
	if( oDiamAvp->isReleased == 0)
	{
		oDiamAvp->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamAVPReleaseCount++;
		addDiamAVPToPool( oDiamAvp, 1, objStackObjects.DiamAVPPool->FreePool);
	}	
*/
	pthread_mutex_lock( &objStackObjects.DiamAVPPool->FreePool->Lock );
	
	if( oDiamAvp->isReleased == 0)
	{
		oDiamAvp->isReleased = 1;
		objStackObjects.TotalMemoryUsage.DiamAVPReleaseCount++;
		addDiamAVPToPool( oDiamAvp, 0, objStackObjects.DiamAVPPool->FreePool);
	}
	
	pthread_mutex_unlock( &objStackObjects.DiamAVPPool->FreePool->Lock );
}

void initASTItem(void* objPTR)
{
	objPTR = allocateASTDataPtr();
}

void* createMessageQueue()
{
	iQueue *iMessageQueue = (iQueue *)lib_malloc( sizeof(iQueue));
	
	pthread_mutex_init( &iMessageQueue->Lock, NULL);
	
	iMessageQueue->Front = NULL;
	iMessageQueue->Front1 = NULL;
	iMessageQueue->Rear = NULL;
	iMessageQueue->Temp = NULL;
	iMessageQueue->QueueCount = 0;
	iMessageQueue->QueueLimit = 5000;
	iMessageQueue->Type = 1;	
	
	return iMessageQueue;
}

int initMessagePool()
{
	objStackObjects.DiamMessagePool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.DiamMessagePool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.DiamMessagePool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.DiamMessagePool->FreePool->Count = 0;
	objStackObjects.DiamMessagePool->BusyPool->Count = 0;
	objStackObjects.DiamMessagePool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.DiamMessagePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamMessagePool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamMessagePool->BusyPool->Lock, NULL);

	createDiamMessagePool( DM_MSG_INITIAL_POOL_SIZE, 0);

	objStackObjects.DiamDecodeMessagePool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.DiamDecodeMessagePool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.DiamDecodeMessagePool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.DiamDecodeMessagePool->FreePool->Count = 0;
	objStackObjects.DiamDecodeMessagePool->BusyPool->Count = 0;
	objStackObjects.DiamDecodeMessagePool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.DiamDecodeMessagePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamDecodeMessagePool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamDecodeMessagePool->BusyPool->Lock, NULL);

	createDiamRawDataPool( DIAM_RAW_MSG_INITIAL_POOL_SIZE, 0);

	//DiamAVPPool
	objStackObjects.DiamAVPPool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.DiamAVPPool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.DiamAVPPool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.DiamAVPPool->FreePool->Count = 0;
	objStackObjects.DiamAVPPool->BusyPool->Count = 0;
	objStackObjects.DiamAVPPool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.DiamAVPPool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamAVPPool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamAVPPool->BusyPool->Lock, NULL);

	createDiamAVPPool( DM_AVP_INITIAL_POOL_SIZE, 0);

	//DiamCDataPool
	objStackObjects.DiamCDataPool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.DiamCDataPool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.DiamCDataPool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.DiamCDataPool->FreePool->Count = 0;
	objStackObjects.DiamCDataPool->BusyPool->Count = 0;
	objStackObjects.DiamCDataPool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.DiamCDataPool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamCDataPool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamCDataPool->BusyPool->Lock, NULL);

	createCDataPool( DM_CDATA_INITIAL_POOL_SIZE, 0);

	//QueuePool
	objStackObjects.QueuePool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.QueuePool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.QueuePool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.QueuePool->FreePool->Count = 0;
	objStackObjects.QueuePool->BusyPool->Count = 0;
	objStackObjects.QueuePool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.QueuePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.QueuePool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.QueuePool->BusyPool->Lock, NULL);


	createQueueRecordPool( DIAM_QUEUE_MSG_INITIAL_POOL_SIZE, 0);

	//DiamRoutePool
	objStackObjects.DiamRoutePool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.DiamRoutePool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.DiamRoutePool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.DiamRoutePool->FreePool->Count = 0;
	objStackObjects.DiamRoutePool->BusyPool->Count = 0;
	objStackObjects.DiamRoutePool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.DiamRoutePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamRoutePool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.DiamRoutePool->BusyPool->Lock, NULL);


	createDiamRouteMessagePool( DIAM_ROUTE_MSG_INITIAL_POOL_SIZE, 0);
	

	//TimerPool
	objStackObjects.TimerPool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.TimerPool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.TimerPool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.TimerPool->FreePool->Count = 0;
	objStackObjects.TimerPool->BusyPool->Count = 0;
	objStackObjects.TimerPool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.TimerPool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.TimerPool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.TimerPool->BusyPool->Lock, NULL);

	createDiamTimerMessagePool( DIAM_TIMER_MSG_INITIAL_POOL_SIZE, 0);
	
	
	//StickySessionPool
	objStackObjects.StickySessionPool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.StickySessionPool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.StickySessionPool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.StickySessionPool->FreePool->Count = 0;
	objStackObjects.StickySessionPool->BusyPool->Count = 0;
	objStackObjects.StickySessionPool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.StickySessionPool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.StickySessionPool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.StickySessionPool->BusyPool->Lock, NULL);

	//createDiamStickySessionMessagePool( 100000, 0);
	createDiamStickySessionMessagePool( DIAM_STICKY_SESSION_MSG_INITIAL_POOL_SIZE, 0);
	
		
	
	//ASTDataPtrPool
	objStackObjects.ASTDataPtrPool = (struct MessagePool*)lib_malloc(sizeof(struct MessagePool));
	objStackObjects.ASTDataPtrPool->FreePool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));
	objStackObjects.ASTDataPtrPool->BusyPool = (struct MessagePtr*)lib_malloc(sizeof(struct MessagePtr));

	objStackObjects.ASTDataPtrPool->FreePool->Count = 0;
	objStackObjects.ASTDataPtrPool->BusyPool->Count = 0;
	objStackObjects.ASTDataPtrPool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.ASTDataPtrPool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.ASTDataPtrPool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.ASTDataPtrPool->BusyPool->Lock, NULL);

	createASTDataPtrPool( 100000, 0);
	
	objStackObjects.StickySessionPtr = allocateASTDataPtr();

	
	/*
	objStackObjects.SessionPool = (struct SessionMessagePool *)lib_malloc(sizeof(struct SessionMessagePool));
	objStackObjects.SessionPool->FreePool = (struct SessionMessagePtr*)lib_malloc(sizeof(struct SessionMessagePtr));
	objStackObjects.SessionPool->FreePool->Count = 0;
	objStackObjects.SessionPool->FreePool->HeadPtr = NULL;
	objStackObjects.SessionPool->FreePool->CurrPtr = NULL;
	objStackObjects.SessionPool->SMCount = 0;
	objStackObjects.SessionPool->SBRHeadPtr = NULL;

	objStackObjects.SessionPool->CurrentSize = 0;	
	objStackObjects.SessionPool->PushCount = 0;
	objStackObjects.SessionPool->PopCount = 0;			
	
	pthread_mutex_init( &objStackObjects.SessionPool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.SessionPool->FreePool->Lock, NULL);
	*/

	//createSessionPool( DM_MSG_INITIAL_POOL_SIZE);



	pthread_mutex_init( &objStackObjects.DecodeMessageQueue.Lock, NULL);
	sem_init( &objStackObjects.DecodeMessageQueue.sem_lock, 0, 0);
	
	objStackObjects.DecodeMessageQueue.Front = NULL;
	objStackObjects.DecodeMessageQueue.Front1 = NULL;
	objStackObjects.DecodeMessageQueue.Rear = NULL;
	objStackObjects.DecodeMessageQueue.Temp = NULL;
	objStackObjects.DecodeMessageQueue.QueueCount = 0;
	objStackObjects.DecodeMessageQueue.QueueLimit = 5000;
	objStackObjects.DecodeMessageQueue.Type = 1;

	
	
	pthread_mutex_init( &objStackObjects.RoutingMessageQueue.Lock, NULL);
	sem_init( &objStackObjects.RoutingMessageQueue.sem_lock, 0, 0);
	
	objStackObjects.RoutingMessageQueue.Front = NULL;
	objStackObjects.RoutingMessageQueue.Front1 = NULL;
	objStackObjects.RoutingMessageQueue.Rear = NULL;
	objStackObjects.RoutingMessageQueue.Temp = NULL;
	objStackObjects.RoutingMessageQueue.QueueCount = 0;
	objStackObjects.RoutingMessageQueue.QueueLimit = 2147483647;
	objStackObjects.RoutingMessageQueue.Type = 2;

	pthread_mutex_init( &objStackObjects.LogQueue.Lock, NULL);
	sem_init( &objStackObjects.LogQueue.sem_lock, 0, 0);
	
	objStackObjects.LogQueue.Front = NULL;
	objStackObjects.LogQueue.Front1 = NULL;
	objStackObjects.LogQueue.Rear = NULL;
	objStackObjects.LogQueue.Temp = NULL;
	objStackObjects.LogQueue.QueueCount = 0;
	objStackObjects.LogQueue.QueueLimit = 2147483647;
	objStackObjects.LogQueue.Type = 3;	

	pthread_mutex_init( &objStackObjects.AppMessageQueue1.Lock, NULL);
	sem_init( &objStackObjects.AppMessageQueue1.sem_lock, 0, 0);
	
	objStackObjects.AppMessageQueue1.Front = NULL;
	objStackObjects.AppMessageQueue1.Front1 = NULL;
	objStackObjects.AppMessageQueue1.Rear = NULL;
	objStackObjects.AppMessageQueue1.Temp = NULL;
	objStackObjects.AppMessageQueue1.QueueCount = 0;
	objStackObjects.AppMessageQueue1.QueueLimit = 2147483647;
	objStackObjects.AppMessageQueue1.Type = 4;

	pthread_mutex_init( &objStackObjects.AppMessageQueue2.Lock, NULL);
	sem_init( &objStackObjects.AppMessageQueue2.sem_lock, 0, 0);
	
	objStackObjects.AppMessageQueue2.Front = NULL;
	objStackObjects.AppMessageQueue2.Front1 = NULL;
	objStackObjects.AppMessageQueue2.Rear = NULL;
	objStackObjects.AppMessageQueue2.Temp = NULL;
	objStackObjects.AppMessageQueue2.QueueCount = 0;
	objStackObjects.AppMessageQueue2.QueueLimit = 2147483647;
	objStackObjects.AppMessageQueue2.Type = 5;	
	
	pthread_mutex_init( &objStackObjects.AppMessageQueue3.Lock, NULL);
	sem_init( &objStackObjects.AppMessageQueue3.sem_lock, 0, 0);
	
	objStackObjects.AppMessageQueue3.Front = NULL;
	objStackObjects.AppMessageQueue3.Front1 = NULL;
	objStackObjects.AppMessageQueue3.Rear = NULL;
	objStackObjects.AppMessageQueue3.Temp = NULL;
	objStackObjects.AppMessageQueue3.QueueCount = 0;
	objStackObjects.AppMessageQueue3.QueueLimit = 2147483647;
	objStackObjects.AppMessageQueue3.Type = 6;

	objStackObjects.ArrayListPool = (iMessagePool *)lib_malloc(sizeof(iMessagePool));
    objStackObjects.ArrayListPool->FreePool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));
    objStackObjects.ArrayListPool->BusyPool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));

    objStackObjects.ArrayListPool->FreePool->Count = 0;
    objStackObjects.ArrayListPool->BusyPool->Count = 0;
    objStackObjects.ArrayListPool->PoolSize = 0;

    pthread_mutex_init( &objStackObjects.ArrayListPool->Lock, NULL);
    pthread_mutex_init( &objStackObjects.ArrayListPool->FreePool->Lock, NULL);
    pthread_mutex_init( &objStackObjects.ArrayListPool->BusyPool->Lock, NULL);

    createArrayListPool( IE_ArrayListPool_MSG_INITIAL_POOL_SIZE);
	
	objStackObjects.ArrayElementPool = (iMessagePool *)lib_malloc(sizeof(iMessagePool));
    objStackObjects.ArrayElementPool->FreePool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));
    objStackObjects.ArrayElementPool->BusyPool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));

    objStackObjects.ArrayElementPool->FreePool->Count = 0;
    objStackObjects.ArrayElementPool->BusyPool->Count = 0;
    objStackObjects.ArrayElementPool->PoolSize = 0;

    pthread_mutex_init( &objStackObjects.ArrayElementPool->Lock, NULL);
    pthread_mutex_init( &objStackObjects.ArrayElementPool->FreePool->Lock, NULL);
    pthread_mutex_init( &objStackObjects.ArrayElementPool->BusyPool->Lock, NULL);

    createArrayElementPool( IE_ArrayElementPool_MSG_INITIAL_POOL_SIZE);	
	
	//RingBufferTCPServerImplementation [Start]
	objStackObjects.TCPRingBufferPool = (iMessagePool *)lib_malloc(sizeof(iMessagePool));
    objStackObjects.TCPRingBufferPool->FreePool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));
    objStackObjects.TCPRingBufferPool->BusyPool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));

    objStackObjects.TCPRingBufferPool->FreePool->Count = 0;
    objStackObjects.TCPRingBufferPool->BusyPool->Count = 0;
    objStackObjects.TCPRingBufferPool->PoolSize = 0;
	
	createTCPRingBufferPool( IE_TCPRingBufferPool_MSG_INITIAL_POOL_SIZE);
	
	objStackObjects.TCPClientInfoPool = (iMessagePool *)lib_malloc(sizeof(iMessagePool));
    objStackObjects.TCPClientInfoPool->FreePool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));
    objStackObjects.TCPClientInfoPool->BusyPool = (iMessagePtr *)lib_malloc(sizeof(iMessagePtr));

    objStackObjects.TCPClientInfoPool->FreePool->Count = 0;
    objStackObjects.TCPClientInfoPool->BusyPool->Count = 0;
    objStackObjects.TCPClientInfoPool->PoolSize = 0;	
	
	createTCPClientInfoPool( IE_TCPClientInfoPool_MSG_INITIAL_POOL_SIZE);
	//RingBufferTCPServerImplementation [End]
	
	objStackObjects.ClientInfoPool = NULL;
	lib_malloc2( sizeof(iMessagePool), (void **) &objStackObjects.ClientInfoPool);
	lib_malloc2( sizeof(iMessagePtr), (void **) &objStackObjects.ClientInfoPool->FreePool);
	lib_malloc2( sizeof(iMessagePtr), (void **) &objStackObjects.ClientInfoPool->BusyPool);

	objStackObjects.ClientInfoPool->FreePool->Count = 0;
	objStackObjects.ClientInfoPool->BusyPool->Count = 0;
	objStackObjects.ClientInfoPool->PoolSize = 0;

	pthread_mutex_init( &objStackObjects.ClientInfoPool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.ClientInfoPool->FreePool->Lock, NULL);
	pthread_mutex_init( &objStackObjects.ClientInfoPool->BusyPool->Lock, NULL);	
	
	createClientInfoPool( IE_ClientInfoPool_MSG_INITIAL_POOL_SIZE);
	
	return 1;
}

//RingBufferTCPServerImplementation [Start]

//10028
void core_getLowestEPollData( iEPollData **oEPollData)
{
	objStackObjects.iEPollFDCount++;
	int iEventDataIndex = (objStackObjects.iEPollFDCount % MAX_EPOLL_THREADS);
	
	*oEPollData = &objStackObjects.EPollData[ iEventDataIndex];
}

//10029
void core_addClientInfoToWatchList( iTCPClientInfo * oTCPClientInfo)
{
	struct epoll_event event;
	
	iEPollData * oEPollData = NULL;
	core_getLowestEPollData( &oEPollData);
	
	event.data.fd = oTCPClientInfo->fd;
	event.data.ptr = oTCPClientInfo;
	//event.events = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR | EPOLLONESHOT | EPOLLRDHUP;
	event.events = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR;
	
	int s = epoll_ctl ( oEPollData->efd, EPOLL_CTL_ADD, oTCPClientInfo->fd, &event);
	oEPollData->iWatchCount++;
	
	printf("attached client fd<%d> to epoll-fd<%d> with index<%d> rval<%d> oTCPClientInfo<%p>\n", 
		oTCPClientInfo->fd, oEPollData->efd, oEPollData->index, s, oTCPClientInfo);
	
	if (s == -1) 
	{
		perror ("epoll_ctl");
		exit(0);
	}	
}

void appServer_tcpAttachToReadThread( iTCPClientInfo * oTCPClientInfo);

//10027
void * core_StartTCPServerThread( void * args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iTCPServerInfo * oTCPServerInfo = (iTCPServerInfo *)args;
	int iPort = oTCPServerInfo->iPort;
	printf("%s iPort=%d\n", __FUNCTION__, iPort);

	int sd = -1, on = 1, sdconn; 
	struct sockaddr_in serveraddr, clientaddr;
	int addrlen = sizeof(clientaddr);
	char str[INET6_ADDRSTRLEN] = {0};
	
	sd = socket( AF_INET, SOCK_STREAM, 0);
	
	if (sd < 0) 
	{
		perror("socket() failed");
		exit(0);
	}	
	
	if (setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on,sizeof(on)) < 0)
	{
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(0);
	}	
	
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	
	serveraddr.sin_port   = htons( iPort );
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if( bind( sd, (struct sockaddr *) &serveraddr, sizeof(struct sockaddr)) != 0)
	{
		printf("Server Bind Failed\n");
		exit(1);
	}
	
	printf("TCP Bind On Port[%d] sd[%d]\n", iPort, sd);
	
	if ( listen( sd, 10) < 0)
	{
		perror("listen() failed");
		exit(1);		
	}
	
	iTCPClientInfo * oTCPClientInfo = NULL;
	
	int flags, err;
	
	while(1)
	{
		sdconn = accept( sd, NULL, NULL);
		
		if( sdconn > 0)
		{
			//make socket non-blocking
			flags = fcntl( sdconn, F_GETFL, 0);
			err = fcntl( sdconn, F_SETFL, flags | O_NONBLOCK);
			//make socket non-blocking
			
			//if(!err)
			//	printf("err=%d\n", err);
			
			getpeername( sdconn, (struct sockaddr *)&clientaddr, (socklen_t *)&addrlen);

			if( inet_ntop( AF_INET, &clientaddr.sin_addr, str, sizeof(str))) 
			{
				printf("Client address is %s\n", str);
				printf("Client port is %d\n", ntohs( clientaddr.sin_port));
				
				oTCPClientInfo = allocateTCPClientInfo();
				
				if(!oTCPClientInfo)
				{
					printf("Unable to Allocate oTCPClientInfo\n");
					close( sdconn);
					shutdown( sdconn, 2);					
				}
				else
				{
					oTCPClientInfo->fd = sdconn;
					oTCPClientInfo->iPort = iPort;
					oTCPClientInfo->TCPServerInfo = oTCPServerInfo;
					oTCPClientInfo->TransportType = 0;
					oTCPClientInfo->isActive = 1;
					oTCPClientInfo->CloseIt = 0;
					oTCPClientInfo->HostConfig = (void *) oTCPServerInfo->HostConfigData;
					
					//core_addClientInfoToWatchList( oTCPClientInfo);
					appServer_tcpAttachToReadThread( oTCPClientInfo);
				}
			}	
		}
	}
	
	return NULL;
}



#define MAXEVENTS 20

//10030
void core_handleCloseTCPClient( iTCPClientInfo* oClientInfo)
{
	//client socket closed
	close( oClientInfo->fd);
	shutdown( oClientInfo->fd, 2);
	oClientInfo->isActive = 0;
	printf("client socket closed\n");	
	
	releaseTCPClientInfo( oClientInfo);
}

//10031
void core_HandleTCPRead( iTCPClientInfo * oTCPClientInfo)
{
	pthread_mutex_lock( &oTCPClientInfo->ReadLock);
	
	char tBuffer[593216];
	int icount = read ( oTCPClientInfo->fd, &tBuffer, sizeof(tBuffer));

	APP_LOG( LOG_LEVEL_DEBUG, __FILE__, __LINE__, "received message from fd<%d> icount<%d> oClientInfo<%p>|%s", oTCPClientInfo->fd, icount, oTCPClientInfo , __FUNCTION__);
	
	if( icount == 0)
	{
		pthread_mutex_unlock( &oTCPClientInfo->ReadLock);
		core_handleCloseTCPClient( oTCPClientInfo);
		return;
	}
	else
	{
		/*
			char cBuffer[99999];
			int iLength;		
		*/
		
		//999999
		iTCPRingBuffer *oTCPRingBuffer = NULL;
		oTCPRingBuffer = allocateTCPRingBuffer();
		
		if(oTCPRingBuffer)
		{
			oTCPRingBuffer->TCPClientInfo = oTCPClientInfo;
			oTCPRingBuffer->iLength = 0;
			
			if( icount < sizeof(oTCPRingBuffer->cBuffer))
			{
				memcpy( oTCPRingBuffer->cBuffer, tBuffer, icount);
				oTCPRingBuffer->iLength = icount;
				pthread_mutex_unlock( &oTCPClientInfo->ReadLock);
				
				Enquee( oTCPRingBuffer, oTCPClientInfo->TCPServerInfo->Queue);
				
				return;
			}
			
			//post oTCPRingBuffer;
		}
	}
	
	pthread_mutex_unlock( &oTCPClientInfo->ReadLock);
}

//10032
void * core_tcpserver_EPollWait( void * args)
{
	iEPollData * oEPollData = (iEPollData *)args;
	
	int n, i;
	struct epoll_event events[ MAXEVENTS ];
	//ssize_t count;
	//int icount;	
	iTCPClientInfo * oTCPClientInfo;

	while(1)
	{
		n = epoll_wait ( oEPollData->efd, events, MAXEVENTS, -1);
		
		printf("epoll fd<%d> index<%d> event-count:%d events received\n", 
			oEPollData->efd, oEPollData->index, n);		
			
		if( n == -1)
		{	
			usleep( 999999);
			continue;
		}

		for (i = 0; i < n; i++)
		{
			if ( events[i].events & EPOLLIN )
			{
				printf("EPOLLIN event index<%d>\n", i);
				oTCPClientInfo = events[i].data.ptr;
				
				core_HandleTCPRead( oTCPClientInfo);
			}
			else
			{
				printf("Unhanded ePoll Event\n");
			}
		}				
	}
	
	return NULL;
}

//10033
void core_StartTCPServer( iTCPServerInfo *oTCPServerInfo)
{
	int iRet;
	
	//This will not work, this is not a web server
	/*
	if( objStackObjects.iEPoolInit == 0)
	{
		objStackObjects.iEPoolInit = 1;
		
		int i = 0;
		for( i = 0; i < objStackObjects.iEPoolNoOfReadThreds; i++ )
		{
			objStackObjects.EPollData[i].efd = epoll_create1(0);
			objStackObjects.EPollData[i].iWatchCount = 0;
			objStackObjects.EPollData[i].index = i;
			
			//printf("Need to Create ePoll Thread\n");
			
			if (objStackObjects.EPollData[i].efd == -1)
			{
				perror ("epoll_create");
				exit(0);	
			}
			
			printf("epoll fd created <%d> for index <%d>\n", objStackObjects.EPollData[i].efd, objStackObjects.EPollData[i].index);
			
			pthread_attr_t attr;
			pthread_attr_init( &attr);
			pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);
			
			iRet = pthread_create( &objStackObjects.EPollData[i].thread_id, &attr, core_tcpserver_EPollWait, &objStackObjects.EPollData[i]);			
		}		
	}
	*/
	
	pthread_t pthread_id;
	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

	iRet = pthread_create( &pthread_id, &attr, core_StartTCPServerThread, (void *)oTCPServerInfo);
	QueuePool_CreateWithNThreads( &oTCPServerInfo->Queue, oTCPServerInfo->recvCallBack, 1);
	
	if(iRet != 0)
	{
		printf("core_StartTCPServer Failed %d\n", iRet);
		exit(0);
	}
}

//RingBufferTCPServerImplementation [End]

int (*pPerformanceLogHandler)() = NULL;

void setPerformanceLogHandler( int (*ptrHandler)())
{
	pPerformanceLogHandler = ptrHandler;
}

void* performanceCounterThread(void* args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iMemoryUsage oMemoryUsage;
	iMemoryUsage oTemp;
		
	while(1)
	{
		usleep(999100);

		iExecTime oExecTime;
		__initStartTime( &oExecTime);

		memset( &oMemoryUsage,0, sizeof(iMemoryUsage));
		memset( &oTemp,0, sizeof(iMemoryUsage));
		
		memcpy( &oMemoryUsage, &objStackObjects.TotalMemoryUsage, sizeof(iMemoryUsage));	
		
		oTemp.DiamRawDataAllocatedCount = oMemoryUsage.DiamRawDataAllocatedCount - objStackObjects.PreviousMemoryUsage.DiamRawDataAllocatedCount;
		oTemp.DiamRawDataReleaseCount = oMemoryUsage.DiamRawDataReleaseCount - objStackObjects.PreviousMemoryUsage.DiamRawDataReleaseCount;	
		oTemp.DiamMessageAllocatedCount = oMemoryUsage.DiamMessageAllocatedCount - objStackObjects.PreviousMemoryUsage.DiamMessageAllocatedCount;
		oTemp.DiamMessageReleaseCount = oMemoryUsage.DiamMessageReleaseCount - objStackObjects.PreviousMemoryUsage.DiamMessageReleaseCount;	
		oTemp.DiamAVPAllocatedCount = oMemoryUsage.DiamAVPAllocatedCount - objStackObjects.PreviousMemoryUsage.DiamAVPAllocatedCount;
		oTemp.DiamAVPReleaseCount = oMemoryUsage.DiamAVPReleaseCount - objStackObjects.PreviousMemoryUsage.DiamAVPReleaseCount;	
		oTemp.DiamCDataAllocatedCount = oMemoryUsage.DiamCDataAllocatedCount - objStackObjects.PreviousMemoryUsage.DiamCDataAllocatedCount;
		oTemp.DiamCDataReleaseCount = oMemoryUsage.DiamCDataReleaseCount - objStackObjects.PreviousMemoryUsage.DiamCDataReleaseCount;	
		oTemp.DecodeThreadAllocatedCount = oMemoryUsage.DecodeThreadAllocatedCount - objStackObjects.PreviousMemoryUsage.DecodeThreadAllocatedCount;
		oTemp.DecodeThreadReleaseCount = oMemoryUsage.DecodeThreadReleaseCount - objStackObjects.PreviousMemoryUsage.DecodeThreadReleaseCount;	
		oTemp.DecodeThreadRejectedCount = oMemoryUsage.DecodeThreadRejectedCount - objStackObjects.PreviousMemoryUsage.DecodeThreadRejectedCount;	
		oTemp.SocketReadCount = oMemoryUsage.SocketReadCount - objStackObjects.PreviousMemoryUsage.SocketReadCount;
		oTemp.SocketWriteCount = oMemoryUsage.SocketWriteCount - objStackObjects.PreviousMemoryUsage.SocketWriteCount;
		oTemp.QueueRecordAllocatedCount = oMemoryUsage.QueueRecordAllocatedCount - objStackObjects.PreviousMemoryUsage.QueueRecordAllocatedCount;
		oTemp.QueueRecordReleasedCount = oMemoryUsage.QueueRecordReleasedCount - objStackObjects.PreviousMemoryUsage.QueueRecordReleasedCount;
		oTemp.DiamRoutePoolAllocatedCount = oMemoryUsage.DiamRoutePoolAllocatedCount - objStackObjects.PreviousMemoryUsage.DiamRoutePoolAllocatedCount;
		oTemp.DiamRoutePoolReleasedCount = oMemoryUsage.DiamRoutePoolReleasedCount - objStackObjects.PreviousMemoryUsage.DiamRoutePoolReleasedCount;
		
		
		
		oTemp.c001 = oMemoryUsage.c001 - objStackObjects.PreviousMemoryUsage.c001;
		oTemp.c002 = oMemoryUsage.c002 - objStackObjects.PreviousMemoryUsage.c002;
		oTemp.c003 = oMemoryUsage.c003 - objStackObjects.PreviousMemoryUsage.c003;
		oTemp.c004 = oMemoryUsage.c004 - objStackObjects.PreviousMemoryUsage.c004;
		oTemp.c005 = oMemoryUsage.c005 - objStackObjects.PreviousMemoryUsage.c005;
		oTemp.c006 = oMemoryUsage.c006 - objStackObjects.PreviousMemoryUsage.c006;
		oTemp.c007 = oMemoryUsage.c007 - objStackObjects.PreviousMemoryUsage.c007;
		oTemp.c008 = oMemoryUsage.c008 - objStackObjects.PreviousMemoryUsage.c008;
		oTemp.c009 = oMemoryUsage.c009 - objStackObjects.PreviousMemoryUsage.c009;
		oTemp.c010 = oMemoryUsage.c010 - objStackObjects.PreviousMemoryUsage.c010;
		oTemp.c011 = oMemoryUsage.c011 - objStackObjects.PreviousMemoryUsage.c011;
		oTemp.c012 = oMemoryUsage.c012 - objStackObjects.PreviousMemoryUsage.c012;
		oTemp.c013 = oMemoryUsage.c013 - objStackObjects.PreviousMemoryUsage.c013;
		oTemp.c014 = oMemoryUsage.c014 - objStackObjects.PreviousMemoryUsage.c014;
		oTemp.c015 = oMemoryUsage.c015 - objStackObjects.PreviousMemoryUsage.c015;
		oTemp.c016 = oMemoryUsage.c016 - objStackObjects.PreviousMemoryUsage.c016;
		oTemp.c017 = oMemoryUsage.c017 - objStackObjects.PreviousMemoryUsage.c017;
		oTemp.c018 = oMemoryUsage.c018 - objStackObjects.PreviousMemoryUsage.c018;
		oTemp.c019 = oMemoryUsage.c019 - objStackObjects.PreviousMemoryUsage.c019;
		oTemp.c020 = oMemoryUsage.c020 - objStackObjects.PreviousMemoryUsage.c020;
		oTemp.c021 = oMemoryUsage.c021 - objStackObjects.PreviousMemoryUsage.c021;
		oTemp.c022 = oMemoryUsage.c022 - objStackObjects.PreviousMemoryUsage.c022;
		oTemp.c023 = oMemoryUsage.c023 - objStackObjects.PreviousMemoryUsage.c023;
		oTemp.c024 = oMemoryUsage.c024 - objStackObjects.PreviousMemoryUsage.c024;
		oTemp.c025 = oMemoryUsage.c025 - objStackObjects.PreviousMemoryUsage.c025;
		oTemp.c026 = oMemoryUsage.c026 - objStackObjects.PreviousMemoryUsage.c026;
		oTemp.c027 = oMemoryUsage.c027 - objStackObjects.PreviousMemoryUsage.c027;
		oTemp.c028 = oMemoryUsage.c028 - objStackObjects.PreviousMemoryUsage.c028;
		oTemp.c029 = oMemoryUsage.c029 - objStackObjects.PreviousMemoryUsage.c029;
		oTemp.c030 = oMemoryUsage.c030 - objStackObjects.PreviousMemoryUsage.c030;
		oTemp.c031 = oMemoryUsage.c031 - objStackObjects.PreviousMemoryUsage.c031;
		oTemp.c032 = oMemoryUsage.c032 - objStackObjects.PreviousMemoryUsage.c032;
		oTemp.c033 = oMemoryUsage.c033 - objStackObjects.PreviousMemoryUsage.c033;
		oTemp.c034 = oMemoryUsage.c034 - objStackObjects.PreviousMemoryUsage.c034;
		oTemp.c035 = oMemoryUsage.c035 - objStackObjects.PreviousMemoryUsage.c035;
		oTemp.c036 = oMemoryUsage.c036 - objStackObjects.PreviousMemoryUsage.c036;
		oTemp.c037 = oMemoryUsage.c037 - objStackObjects.PreviousMemoryUsage.c037;
		oTemp.c038 = oMemoryUsage.c038 - objStackObjects.PreviousMemoryUsage.c038;
		oTemp.c039 = oMemoryUsage.c039 - objStackObjects.PreviousMemoryUsage.c039;
		oTemp.c040 = oMemoryUsage.c040 - objStackObjects.PreviousMemoryUsage.c040;
		oTemp.c041 = oMemoryUsage.c041 - objStackObjects.PreviousMemoryUsage.c041;
		oTemp.c042 = oMemoryUsage.c042 - objStackObjects.PreviousMemoryUsage.c042;
		oTemp.c043 = oMemoryUsage.c043 - objStackObjects.PreviousMemoryUsage.c043;
		oTemp.c044 = oMemoryUsage.c044 - objStackObjects.PreviousMemoryUsage.c044;
		oTemp.c045 = oMemoryUsage.c045 - objStackObjects.PreviousMemoryUsage.c045;
		oTemp.c046 = oMemoryUsage.c046 - objStackObjects.PreviousMemoryUsage.c046;
		oTemp.c047 = oMemoryUsage.c047 - objStackObjects.PreviousMemoryUsage.c047;
		oTemp.c048 = oMemoryUsage.c048 - objStackObjects.PreviousMemoryUsage.c048;
		oTemp.c049 = oMemoryUsage.c049 - objStackObjects.PreviousMemoryUsage.c049;
		oTemp.c050 = oMemoryUsage.c050 - objStackObjects.PreviousMemoryUsage.c050;

		
		
		memcpy( &objStackObjects.PreviousMemoryUsage, &oMemoryUsage, sizeof(iMemoryUsage));
				
		__initEndTime( &oExecTime);
		
		char dateString[28];
		memset( &dateString, '\0', sizeof( dateString));
		makeTimeStamp( &dateString[0]);		
		
		int i = 0;
		
		/*
		printf( "\n\nTime Gap %ld-%ld  %s\n", oExecTime.lapsed.tv_sec, oExecTime.lapsed.tv_usec, dateString);
		
		
		printf("----------------------------------------------------------------------------------------------------------------\n");

		printf("T-RawData       Allocated = %06lu     Released = %06lu \n", objStackObjects.TotalMemoryUsage.DiamRawDataAllocatedCount, objStackObjects.TotalMemoryUsage.DiamRawDataReleaseCount);		
		printf("C-RawData       Allocated = %06lu     Released = %06lu      Free = %06lu \n", oTemp.DiamRawDataAllocatedCount, oTemp.DiamRawDataReleaseCount, objStackObjects.DiamDecodeMessagePool->FreePool->Count);

		printf("\n");

		printf("T-Messages      Allocated = %06lu     Released = %06lu \n", objStackObjects.TotalMemoryUsage.DiamMessageAllocatedCount, objStackObjects.TotalMemoryUsage.DiamMessageReleaseCount);		
		printf("C-Messages      Allocated = %06lu     Released = %06lu      Free = %06lu \n", oTemp.DiamMessageAllocatedCount, oTemp.DiamMessageReleaseCount, objStackObjects.DiamMessagePool->FreePool->Count);		
	
		printf("\n");
	
		printf("T-AVP           Allocated = %06lu     Released = %06lu \n", objStackObjects.TotalMemoryUsage.DiamAVPAllocatedCount, objStackObjects.TotalMemoryUsage.DiamAVPReleaseCount);		
		printf("C-AVP           Allocated = %06lu     Released = %06lu      Free = %06lu \n", oTemp.DiamAVPAllocatedCount, oTemp.DiamAVPReleaseCount, objStackObjects.DiamAVPPool->FreePool->Count);
					
		printf("\n");
						
		printf("T-String        Allocated = %06lu     Released = %06lu \n", objStackObjects.TotalMemoryUsage.DiamCDataAllocatedCount, objStackObjects.TotalMemoryUsage.DiamCDataReleaseCount);						
		printf("C-String        Allocated = %06lu     Released = %06lu      Free = %06lu \n", oTemp.DiamCDataAllocatedCount, oTemp.DiamCDataReleaseCount, objStackObjects.DiamCDataPool->FreePool->Count);
		
		printf("\n");
		
		printf("T-QueueRecord   Allocated = %06lu     Released = %06lu \n", objStackObjects.TotalMemoryUsage.QueueRecordAllocatedCount, objStackObjects.TotalMemoryUsage.QueueRecordReleasedCount);						
		printf("C-QueueRecord   Allocated = %06lu     Released = %06lu      Free = %06lu \n", oTemp.QueueRecordAllocatedCount, oTemp.QueueRecordReleasedCount, objStackObjects.QueuePool->FreePool->Count);
		
		printf("\n");		
		
		//printf("T-Queue   Allocated = %06lu     Released = %06lu \n", objStackObjects.TotalMemoryUsage.QueueRecordAllocatedCount, objStackObjects.TotalMemoryUsage.QueueRecordReleasedCount);						
		//printf("C-Queue   Allocated = %06lu     Released = %06lu      Free = %06lu \n", oTemp.QueueRecordAllocatedCount, oTemp.QueueRecordReleasedCount, objStackObjects.QueuePool->FreePool->Count);
		
		//printf("\n");				
		
		if( objStackConfig.QueueMode == 0)
		{
			printf("T-Thread        Allocated = %06lu     Released = %06lu                         Rejected = %06lu   \n", objStackObjects.TotalMemoryUsage.DecodeThreadAllocatedCount, objStackObjects.TotalMemoryUsage.DecodeThreadReleaseCount, objStackObjects.TotalMemoryUsage.DecodeThreadRejectedCount);		
			printf("C-Thread        Allocated = %06lu     Released = %06lu      Free = %06d      Rejected = %06lu\n", oTemp.DecodeThreadAllocatedCount, oTemp.DecodeThreadReleaseCount, objStackObjects.DecodeThreadPool.FreeCount, oTemp.DecodeThreadRejectedCount);
		}
		else
		{
			printf("T-DecodeQueue        TotalQueued = %06lu    TotalDequeued = %06lu   Pending = %06lu   \n", objStackObjects.DecodeMessageQueue.TotalQueued, objStackObjects.DecodeMessageQueue.TotalDequeued, objStackObjects.DecodeMessageQueue.QueueCount);		
			printf("T-Route-Queue        TotalQueued = %06lu    TotalDequeued = %06lu   Pending = %06lu   \n", objStackObjects.RoutingMessageQueue.TotalQueued, objStackObjects.RoutingMessageQueue.TotalDequeued, objStackObjects.RoutingMessageQueue.QueueCount);					
		}
		
		
		printf("\n");
		
		printf("T-Socket        Read      = %06lu     Write    = %06lu \n", objStackObjects.TotalMemoryUsage.SocketReadCount, objStackObjects.TotalMemoryUsage.SocketWriteCount);		
		printf("C-Socket        Read      = %06lu     Write    = %06lu \n", oTemp.SocketReadCount, oTemp.SocketWriteCount);
								
		if( objStackConfig.NodeType == 2)
		{
			printf("\n");
			
			int z = 0;
			
			for(z = 0; z < objStackConfig.NoOfPeers; z++)
			{
				printf("Messages Sent: %06lu   Received:%06lu     AppId:%d     Peer   Host:%s    Realm:%s               \n", objStackConfig.Peers[z].MessagesRouted, objStackConfig.Peers[z].iResponseNo, objStackConfig.Peers[z].AppId, objStackConfig.Peers[z].PeerHostName, objStackConfig.Peers[z].PeerHostRealmName); 	
			}
			
			printf("\n");
			
			for(z = 0; z < objStackObjects.RealmTableCurrentCount; z++)
			{
				printf("Client: %s   Received:%06lu     Sent:%06lu    RoutingError:%06lu \n", objStackObjects.RealmTable[z].RealmName, objStackObjects.RealmTable[z].clientInfo->ReceivedMessages, objStackObjects.RealmTable[z].clientInfo->SentMessages, objStackObjects.RealmTable[z].clientInfo->RoutingError);
			}
			
			printf("\n");	
			
			//printf("Delivary Failed To Client INVALID-OBJ:%06lu         INVALID-STATE:%06lu     INVALID-LENGTH:%06lu \n" , objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidClientObject, objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidClientObject, objStackObjects.TotalMemoryUsage.UnableToDeliverInvalidClientObject);
			
			//printf("\n");							
		}

		printf("\n");
		
		
		for( i = 0; i <  (objMemoryManagement.MemoryBlockCount+1); i++)
		{
			printf("%s MemoryBlock  Index[%d] Available:%06d  Count:%06ld\n", objMemoryManagement.MemoryBlocks[i].Name, i, objMemoryManagement.MemoryBlocks[i].Count, objMemoryManagement.MemoryBlocks[i].TotalCount );
		}	
		printf("\n");
		
		for( i = 0; i <  10; i++)
		{
			if( objStackObjects.ServerCounter[i].isConfigured == 1)
			{
				printf("%s  IP:%s  Port:%d   IsActive:%d  Request:%ld   Response:%ld\n", objStackObjects.ServerCounter[i].Name, objStackObjects.ServerCounter[i].IpAddress, objStackObjects.ServerCounter[i].Port, objStackObjects.ServerCounter[i].isActive, objStackObjects.ServerCounter[i].iRequest, objStackObjects.ServerCounter[i].iResponse);
			}
		}
		
		printf("\n");
								
		printf("----------------------------------------------------------------------------------------------------------------\n\n");
		/**/


		PERF_LOG("Time Gap %ld-%ld  %s", oExecTime.lapsed.tv_sec, oExecTime.lapsed.tv_usec, dateString);
		PERF_LOG("----------------------------------------------------------------------------------------------------------------");
		
		PERF_LOG("T-RawData       Allocated   = %09ld     Released = %09ld      Diff = %09ld", objStackObjects.TotalMemoryUsage.DiamRawDataAllocatedCount, objStackObjects.TotalMemoryUsage.DiamRawDataReleaseCount,  ( objStackObjects.DiamDecodeMessagePool->PoolSize - objStackObjects.DiamDecodeMessagePool->FreePool->Count)  );
		PERF_LOG("C-RawData       Allocated   = %09ld     Released = %09ld      Free = %09ld", oTemp.DiamRawDataAllocatedCount, oTemp.DiamRawDataReleaseCount, objStackObjects.DiamDecodeMessagePool->FreePool->Count);
		PERF_LOG("T-AVP           Allocated   = %09ld     Released = %09ld      Diff = %09ld", objStackObjects.TotalMemoryUsage.DiamAVPAllocatedCount, objStackObjects.TotalMemoryUsage.DiamAVPReleaseCount, (objStackObjects.DiamAVPPool->PoolSize - objStackObjects.DiamAVPPool->FreePool->Count));
		PERF_LOG("C-AVP           Allocated   = %09ld     Released = %09ld      Free = %09ld", oTemp.DiamAVPAllocatedCount, oTemp.DiamAVPReleaseCount, objStackObjects.DiamAVPPool->FreePool->Count);
		PERF_LOG("T-String        Allocated   = %09ld     Released = %09ld      Diff = %09ld", objStackObjects.TotalMemoryUsage.DiamCDataAllocatedCount, objStackObjects.TotalMemoryUsage.DiamCDataReleaseCount, ( objStackObjects.DiamCDataPool->PoolSize - objStackObjects.DiamCDataPool->FreePool->Count ) );
		PERF_LOG("C-String        Allocated   = %09ld     Released = %09ld      Free = %09ld", oTemp.DiamCDataAllocatedCount, oTemp.DiamCDataReleaseCount, objStackObjects.DiamCDataPool->FreePool->Count);
		PERF_LOG("T-Queue         Allocated   = %09ld     Released = %09ld      Diff = %09ld", objStackObjects.TotalMemoryUsage.QueueRecordAllocatedCount, objStackObjects.TotalMemoryUsage.QueueRecordReleasedCount, (objStackObjects.QueuePool->PoolSize - objStackObjects.QueuePool->FreePool->Count));
		PERF_LOG("C-Queue         Allocated   = %09ld     Released = %09ld      Free = %09ld", oTemp.QueueRecordAllocatedCount, oTemp.QueueRecordReleasedCount, objStackObjects.QueuePool->FreePool->Count);
		PERF_LOG("TCPRingBuff     PoolSize    = %09ld     Free     = %09ld      Diff = %09ld", objStackObjects.TCPRingBufferPool->PoolSize, objStackObjects.TCPRingBufferPool->FreePool->Count, (objStackObjects.TCPRingBufferPool->PoolSize - objStackObjects.TCPRingBufferPool->FreePool->Count));
		PERF_LOG("TCPClitInfo     PoolSize    = %09ld     Free     = %09ld      Diff = %09ld", objStackObjects.TCPClientInfoPool->PoolSize, objStackObjects.TCPClientInfoPool->FreePool->Count, (objStackObjects.TCPClientInfoPool->PoolSize - objStackObjects.TCPClientInfoPool->FreePool->Count));
		PERF_LOG("ClitInfo        PoolSize    = %09ld     Free     = %09ld      Diff = %09ld", objStackObjects.ClientInfoPool->PoolSize, objStackObjects.ClientInfoPool->FreePool->Count, (objStackObjects.ClientInfoPool->PoolSize - objStackObjects.ClientInfoPool->FreePool->Count));
		
		PERF_LOG("T-Decode-Queue  Queued      = %09ld     Dequeued = %09ld   Pending = %09ld", objStackObjects.DecodeMessageQueue.TotalQueued, objStackObjects.DecodeMessageQueue.TotalDequeued, objStackObjects.DecodeMessageQueue.QueueCount);
		PERF_LOG("T-Routed-Queue  Queued      = %09ld     Dequeued = %09ld   Pending = %09ld", objStackObjects.RoutingMessageQueue.TotalQueued, objStackObjects.RoutingMessageQueue.TotalDequeued, objStackObjects.RoutingMessageQueue.QueueCount);	
		
		PERF_LOG("T-Socket        Read        = %09ld     Write    = %09ld      Diff = %09ld", objStackObjects.TotalMemoryUsage.SocketReadCount, objStackObjects.TotalMemoryUsage.SocketWriteCount,  (objStackObjects.TotalMemoryUsage.SocketReadCount - objStackObjects.TotalMemoryUsage.SocketWriteCount) );
		PERF_LOG("C-Socket        Read        = %09ld     Write    = %09ld      Diff = %09ld", oTemp.SocketReadCount, oTemp.SocketWriteCount, (oTemp.SocketReadCount - oTemp.SocketWriteCount));
		
		if(oApplicationServer)
		{
			PERF_LOG("SCTP Socket-Read-Thread-Count %d", oApplicationServer->SocketReadThreadCount);
			PERF_LOG("TCP Socket-Read-Thread-Count %d", oApplicationServer->TCPSocketReadThreadCount);
		}
		
		if( pPerformanceLogHandler > 0)
		{
			pPerformanceLogHandler();
		}
		
		PERF_LOG("----------------------------------------------------------------------------------------------------------------");
		
		
		//Header
		/*
			TotalRawDataAllocatedCount,TotalRawDataReleaseCount,
			CurrentRawDataAllocatedCount,CurrentDiamRawDataReleaseCount,RawDataPoolFreeCount,
			TotalMessageAllocatedCount,TotalMessageReleaseCount
			CurrentMessageAllocatedCount,CurrentMessageReleaseCount,DiamMessagePoolFreeCount,
			TotalAVPAllocatedCount,TotalAVPReleaseCount,
			CurrentAVPAllocatedCount,CurrentAVPReleaseCount,AVPPoolFreePoolCount,
			TotalCDataAllocatedCount,TotalCDataReleaseCount,
			CurrentCDataAllocatedCount,CurrentCDataReleaseCount,DiamCDataPoolFreePoolCount,
			TotalQueueRecordAllocatedCount,TotalQueueRecordReleasedCount,
			CurrentQueueRecordAllocatedCount,CurrentQueueRecordReleasedCount,CurrentQueuePoolFreePoolCount
			
		*/
		
		/*
		PERF_LOG("DEFAULT %s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu", 
			dateString,
			objStackObjects.TotalMemoryUsage.DiamRawDataAllocatedCount,
			objStackObjects.TotalMemoryUsage.DiamRawDataReleaseCount,
			oTemp.DiamRawDataAllocatedCount,
			oTemp.DiamRawDataReleaseCount,
			objStackObjects.DiamDecodeMessagePool->FreePool->Count,
			objStackObjects.TotalMemoryUsage.DiamMessageAllocatedCount,
			objStackObjects.TotalMemoryUsage.DiamMessageReleaseCount,
			oTemp.DiamMessageAllocatedCount, 
			oTemp.DiamMessageReleaseCount, 
			objStackObjects.DiamMessagePool->FreePool->Count,
			objStackObjects.TotalMemoryUsage.DiamAVPAllocatedCount, 
			objStackObjects.TotalMemoryUsage.DiamAVPReleaseCount,
			oTemp.DiamAVPAllocatedCount, 
			oTemp.DiamAVPReleaseCount, 
			objStackObjects.DiamAVPPool->FreePool->Count,
			objStackObjects.TotalMemoryUsage.DiamCDataAllocatedCount, 
			objStackObjects.TotalMemoryUsage.DiamCDataReleaseCount,
			oTemp.DiamCDataAllocatedCount, 
			oTemp.DiamCDataReleaseCount, 
			objStackObjects.DiamCDataPool->FreePool->Count,
			objStackObjects.TotalMemoryUsage.QueueRecordAllocatedCount, 
			objStackObjects.TotalMemoryUsage.QueueRecordReleasedCount, 
			oTemp.QueueRecordAllocatedCount, 
			oTemp.QueueRecordReleasedCount, 
			objStackObjects.QueuePool->FreePool->Count,
			objStackObjects.DecodeMessageQueue.TotalQueued, 
			objStackObjects.DecodeMessageQueue.TotalDequeued, 
			objStackObjects.DecodeMessageQueue.QueueCount,
			objStackObjects.RoutingMessageQueue.TotalQueued, 
			objStackObjects.RoutingMessageQueue.TotalDequeued, 
			objStackObjects.RoutingMessageQueue.QueueCount,
			objStackObjects.AppMessageQueue1.TotalQueued, 
			objStackObjects.AppMessageQueue1.TotalDequeued, 
			objStackObjects.AppMessageQueue1.QueueCount,
			objStackObjects.AppMessageQueue2.TotalQueued, 
			objStackObjects.AppMessageQueue2.TotalDequeued, 
			objStackObjects.AppMessageQueue2.QueueCount,
			objStackObjects.AppMessageQueue3.TotalQueued, 
			objStackObjects.AppMessageQueue3.TotalDequeued, 
			objStackObjects.AppMessageQueue3.QueueCount,
			objStackObjects.TotalMemoryUsage.SocketReadCount, 
			objStackObjects.TotalMemoryUsage.SocketWriteCount, 
			oTemp.SocketReadCount, 
			oTemp.SocketWriteCount,
			objStackObjects.TotalMemoryUsage.DiamRoutePoolAllocatedCount, 
			objStackObjects.TotalMemoryUsage.DiamRoutePoolReleasedCount,
			oTemp.DiamRoutePoolAllocatedCount, 
			oTemp.DiamRoutePoolReleasedCount, 
			objStackObjects.DiamRoutePool->FreePool->Count
		);
		
		
		
		
		if( objStackConfig.NodeType == 2)
		{
			int z = 0;
			for(z = 0; z < objStackConfig.NoOfPeers; z++)
			{
				//printf("Messages Sent: %06lu   Received:%06lu     AppId:%d     Peer   Host:%s    Realm:%s               \n", 
				//objStackConfig.Peers[z].MessagesRouted, 
				//objStackConfig.Peers[z].iResponseNo, 
				//objStackConfig.Peers[z].AppId, 
				//objStackConfig.Peers[z].PeerHostName, 
				//objStackConfig.Peers[z].PeerHostRealmName);
				
				PERF_LOG("NODE2PeerInfo %s,%lu,%lu,%d,%s,%s", 
					dateString,
					objStackConfig.Peers[z].MessagesRouted, 
					objStackConfig.Peers[z].iResponseNo, 
					objStackConfig.Peers[z].AppId, 
					objStackConfig.Peers[z].PeerHostName, 
					objStackConfig.Peers[z].PeerHostRealmName
				);
				
			}
		}
		
		//int i = 0;
		for( i = 0; i <  (objMemoryManagement.MemoryBlockCount+1); i++)
		{
			//printf("%s MemoryBlock  Index[%d] Available:%06d  Count:%06ld\n", 
				//objMemoryManagement.MemoryBlocks[i].Name, 
				//i, 
				//objMemoryManagement.MemoryBlocks[i].Count, 
				//objMemoryManagement.MemoryBlocks[i].TotalCount 
				//);
				
			PERF_LOG("AppMemory %s,%s,%d,%d,%ld",
				dateString, objMemoryManagement.MemoryBlocks[i].Name, i, 
				objMemoryManagement.MemoryBlocks[i].Count, 
				objMemoryManagement.MemoryBlocks[i].TotalCount 
			);
		}
		
		i = 0;
		for( i = 0; i <  (objStackObjects.iPerformanceCounterIndex + 1); i++)
		{
			long int *cItem = getPerformanceCounterItem( i);
			
			//if( cItem != NULL)
			if( cItem)	
			{
				PERF_LOG("AppCounters %s, %s, %d, %ld", dateString, objStackObjects.PerformanceCounterName[i], i, *cItem);	
			}
		}
		
		
		PERF_LOG("-----");
		*/
	}
	return NULL;
}


void initPerformanceThread()
{
	//int iRet;
	pthread_t s_pthread_id;

	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

	//iRet = 
	pthread_create( &s_pthread_id, &attr, performanceCounterThread, NULL);	
}

int __core_iTimerThread_Initalized = 0;

void initTimerThread()
{
	if( __core_iTimerThread_Initalized == 0)
	{	
		__core_iTimerThread_Initalized = 1;
		
		//int iRet;
		pthread_t s_pthread_id;

		pthread_attr_t attr;
		pthread_attr_init( &attr);
		pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

		//iRet = 
		pthread_create( &s_pthread_id, &attr, appTimerThread, NULL);	
		//iRet = 
		pthread_create( &s_pthread_id, &attr, appTimerCallbackThread, NULL);
	}
}

void *appLogThread(void* args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	int sockfd;
	
	while(1)
	{
		while(objStackObjects.iLoggerId != 1) 
		{
			int iconnected = 1;

			struct sockaddr_in their_paddr;

			their_paddr.sin_family = PF_INET;
			their_paddr.sin_addr.s_addr = inet_addr( "127.0.0.1" );
			their_paddr.sin_port = htons( 9119);

			memset(&(their_paddr.sin_zero), '\0', 8);

			if ((sockfd = socket( PF_INET, SOCK_STREAM, 0)) == -1)
			{
				printf( "socket creation failed for Logger at Port[%d]\n", 9119);
				iconnected = -1;
			}

			if( iconnected == 1)
			{
				if (connect(sockfd, (struct sockaddr *)&their_paddr,sizeof(struct sockaddr)) == -1)
				{
					close( sockfd);
					iconnected = -2;
				}
			}
			
			if( iconnected == 1)
			{
				objStackObjects.iLoggerId = 1;
				//printf("Connected to LogFx >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n");
				break;
			}
			
			usleep(999999);	
		}	
		
		
		struct MemoryRecord *mRecord = (struct MemoryRecord *)LogDequee();
		
		//if( mRecord != NULL)
		if( mRecord )	
		{
			struct LogMessage *lLogMessage = (struct LogMessage *)mRecord->Data;
			
			
			int iSentBytes = send( sockfd, lLogMessage , sizeof(struct LogMessage), 0 );

			if( iSentBytes < 0 && errno == EPIPE)
			{
				objStackObjects.iLoggerId = -1;
				close( sockfd);
				shutdown( sockfd, 2);
			}
			
			__releaseMemory( objStackConfig.LoggerMemoryBlockId, mRecord);
		}
		else
		{
			usleep(666666);
		}	
	}
	
	return NULL;
}

void initLogThread()
{
	//int iRet;
	pthread_t s_pthread_id;

	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

	//iRet = 
	pthread_create( &s_pthread_id, &attr, appLogThread, NULL);
}



#if DIAMDRA

void setNextHBHId()
{
	if( objStackObjects.CurrentHBH < (objStackObjects.MaxHBH-1))
	{
		objStackObjects.CurrentHBH++;
	}
	else
	{
		objStackObjects.CurrentHBH = objStackObjects.MinHBH;
	}
}

#endif

//typedef struct stat Stat;

static int do_mkdir( const char *path, mode_t mode)
{
    struct stat     st;
    int             status = 0;

    if (stat(path, &st) != 0)
    {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    }
    else if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        status = -1;
    }

    return(status);
}

int mkpath( const char *path, mode_t mode)
{
    char           *pp;
    char           *sp;
    int             status;
    char           *copypath = (char *)strdup(path);

    status = 0;
    pp = copypath;
    while (status == 0 && (sp = strchr(pp, '/')) != 0)
    {
        if (sp != pp)
        {
            /* Neither root nor double slash in path */
            *sp = '\0';
            status = do_mkdir(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }
    if (status == 0)
        status = do_mkdir(path, mode);
    free(copypath);
    return (status);
}


void initLogger()
{
	int retd;
	int iUmask = S_IWGRP | S_IWOTH;
	int iFileCreationMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int iFlags = O_WRONLY | O_CREAT | O_APPEND;
	int iOldUmask = umask(iUmask);
	
	struct stat st = {0};
	
	if ( stat( objStackObjects.LoggerConfig[0].Path, &st) == -1) {
		mkpath( objStackObjects.LoggerConfig[0].Path, 0700);
	}

	if ( stat( objStackObjects.LoggerConfig[1].Path, &st) == -1) {
		mkpath( objStackObjects.LoggerConfig[1].Path, 0700);
	}
	
	if ( stat( objStackObjects.LoggerConfig[2].Path, &st) == -1) {
		mkpath( objStackObjects.LoggerConfig[2].Path, 0700);
	}
	
	retd = open( objStackObjects.LoggerConfig[0].Path, O_RDONLY);
	if (retd == -1)
	{
		int iDirCreationMode = iFileCreationMode | S_IXUSR | S_IXGRP | S_IXOTH;
		int p = mkdir( objStackObjects.LoggerConfig[0].Path, iDirCreationMode);
  
		if(p == -1)
		{
			printf("Error in Creating Log Directory: %s\n", objStackObjects.LoggerConfig[0].Prefix);
			exit(0);
		}
	}

	if( objStackObjects.LoggerConfig[1].Enabled == 1)
	{
		retd = open( objStackObjects.LoggerConfig[1].Path, O_RDONLY);
		if (retd == -1)
		{
			int iDirCreationMode = iFileCreationMode | S_IXUSR | S_IXGRP | S_IXOTH;
			int p = mkdir( objStackObjects.LoggerConfig[1].Path, iDirCreationMode);
	  
			if(p == -1)
			{
				printf("Error in Creating Log Directory: %s\n", objStackObjects.LoggerConfig[1].Prefix);
				exit(0);
			}
		}
	}	
	

	retd = open( objStackObjects.LoggerConfig[2].Path, O_RDONLY);
	if (retd == -1)
	{
		int iDirCreationMode = iFileCreationMode | S_IXUSR | S_IXGRP | S_IXOTH;
		int p = mkdir( objStackObjects.LoggerConfig[2].Path, iDirCreationMode);
  
		if(p == -1)
		{
			printf("Error in Creating Log Directory: %s\n", objStackObjects.LoggerConfig[2].Prefix);
			exit(0);
		}
	}

	if( objStackObjects.LoggerConfig[3].Enabled == 1)
	{
		retd = open( objStackObjects.LoggerConfig[3].Path, O_RDONLY);
		if (retd == -1)
		{
			int iDirCreationMode = iFileCreationMode | S_IXUSR | S_IXGRP | S_IXOTH;
			int p = mkdir( objStackObjects.LoggerConfig[3].Path, iDirCreationMode);
	  
			if(p == -1)
			{
				printf("Error in Creating Log Directory: %s\n", objStackObjects.LoggerConfig[3].Prefix);
				exit(0);
			}
		}
	}	
	
	char mFileNameBuffer[500];
	
	memset( &mFileNameBuffer, 0, sizeof(mFileNameBuffer));
	makeIntFileName( &mFileNameBuffer[0], objStackObjects.LoggerConfig[0].Path, objStackObjects.LoggerConfig[0].Prefix, &objStackObjects.LoggerConfig[0].iFileIndex);
	objStackObjects.LoggerConfig[0].iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);

	if( objStackObjects.LoggerConfig[1].Enabled == 1)
	{
		memset( &mFileNameBuffer, 0, sizeof(mFileNameBuffer));
		makeIntFileName( &mFileNameBuffer[0], objStackObjects.LoggerConfig[1].Path, objStackObjects.LoggerConfig[1].Prefix, &objStackObjects.LoggerConfig[1].iFileIndex);
		objStackObjects.LoggerConfig[1].iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);
	}
	
	memset( &mFileNameBuffer, 0, sizeof(mFileNameBuffer));
	makeIntFileName( &mFileNameBuffer[0], objStackObjects.LoggerConfig[2].Path, objStackObjects.LoggerConfig[2].Prefix, &objStackObjects.LoggerConfig[2].iFileIndex);
	objStackObjects.LoggerConfig[2].iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);
	
	if( objStackObjects.LoggerConfig[3].Enabled == 1)
	{
		memset( &mFileNameBuffer, 0, sizeof(mFileNameBuffer));
		makeIntFileName( &mFileNameBuffer[0], objStackObjects.LoggerConfig[3].Path, objStackObjects.LoggerConfig[3].Prefix, &objStackObjects.LoggerConfig[3].iFileIndex);
		objStackObjects.LoggerConfig[3].iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);
	}
	
	umask(iOldUmask);
	
	printf("initLogger Completed\n");
}


int LOGCAT( int iLogCatId, unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...)
{
	return 0;
	
	if( iLogCatId < 0 || iLogCatId > objStackObjects.LogCatCount)
	{
		printf("iLogCatId=%d objStackObjects.LogCatCount=%d\n", iLogCatId, objStackObjects.LogCatCount);
		return 0;
	}
	
	if( objStackObjects.LogCatInfo[iLogCatId].Enabled != 1)
		return 0;
	
	int id = 2;
	
	iLogConfig *iLog = &objStackObjects.LoggerConfig[id];
	
	if( iLog->Enabled == 0)
		return 0;
	
	
	if( ( mLoggingLevel < LOG_LEVEL_LOWER_LIMIT) || ( mLoggingLevel > LOG_LEVEL_UPPER_LIMIT) || ( mLoggingLevel > iLog->iLoggingThreshold))
    {
		return 0;
    }
    
    if( !mLogMessage || (LOG_MESSAGE_MAX_SIZE < (int)strlen(mLogMessage)) )	
		return 0;

    pthread_mutex_lock ( &iLog->Lock);

	
    //int debugTagLen;
    char* debugTag;
    unsigned long  ulThreadID = pthread_self();
    

    char m_buffer[LOGGER_BUFFER_SIZE];
    char f_buffer[LOGGER_BUFFER_SIZE];
    char dateString[28];

    memset( &dateString, '\0', sizeof( dateString));
    //makeTimeStamp2( &dateString[0]);
   
	memset( m_buffer, '\0', sizeof(m_buffer));
	memset( f_buffer, '\0', sizeof(f_buffer));
		
	//if( fileName != NULL)
	if( fileName)	
	{
		if( strrchr(fileName,'/') )
		{
			fileName=strrchr(fileName,'/');
			fileName++;
		}
	}


	
    va_list args;// = 0;
    va_start( args, mLogMessage);
    vsnprintf( m_buffer, LOG_MESSAGE_MAX_SIZE, mLogMessage, args);
	va_end( args);
	 
	switch( mLoggingLevel)
	{
		case LOG_LEVEL_CRITICAL:
			debugTag = "[C]";
			//debugTagLen = sizeof("[C]");
		break;
		case LOG_LEVEL_ERROR:
			debugTag = "[E]";
			//debugTagLen = sizeof("[E]");
		break;
		case LOG_LEVEL_WARNING:
			debugTag = "[W]";
			//debugTagLen = sizeof("[W]");
		break;
		case LOG_LEVEL_NORMAL:
			debugTag = "[I]";
			//debugTagLen = sizeof("[I]");
		break;
		case LOG_LEVEL_DEBUG:
			debugTag = "[D]";
			//debugTagLen = sizeof("[D]");
		break;
		default:
			debugTag = "[E]";
			//debugTagLen = sizeof("[E]");
		break;
	}
	
	
	if( iLog->CSVMode == 0) 
	{
		sprintf( f_buffer, "%s|%s|%lu|%s|%s|%s|%d\n", debugTag, dateString, ulThreadID, objStackObjects.LogCatInfo[iLogCatId].iLogCatName, m_buffer, fileName, lineNum);
	} 
	else 
	{
		sprintf( f_buffer, "%s\n", m_buffer);		
	}

	unsigned long m_FileSize;
	
	int bRotate = 0;
	struct stat fileStat;
	fstat( iLog->iHandle, &fileStat);
	m_FileSize = fileStat.st_size;
    
    //if(m_FileSize >= 3145728)
	if(m_FileSize >= 10485760)	
		bRotate = 1;        
	
	if( bRotate == 1)
	{
		close( iLog->iHandle);

		char mFileNameBuffer[500];
		memset( &mFileNameBuffer, 0, 500);
		makeIntFileName( &mFileNameBuffer[0], iLog->Path, iLog->Prefix, &iLog->iFileIndex);
		
		//iLog->iHandle = creat( mFileNameBuffer, O_CREAT | S_IRWXU | S_IRWXG | S_IRWXO );
		//chmod( mFileNameBuffer, 0600);
		
		int iUmask = S_IWGRP | S_IWOTH;
		int iFileCreationMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		int iFlags = O_WRONLY | O_CREAT | O_APPEND;
		int iOldUmask = umask( iUmask);
		
		iLog->iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);	
		
		umask( iOldUmask);
	}
	
	write( iLog->iHandle, f_buffer, strlen( f_buffer));
	/**/
	
	pthread_mutex_unlock ( &iLog->Lock);

	return 1;	
	 
}

int APP_LOG( unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...)
{
	int id = 2;

	iLogConfig *iLog = &objStackObjects.LoggerConfig[id];
	
	if( iLog->Enabled == 0)
		return 0;
	
	
	if( ( mLoggingLevel < LOG_LEVEL_LOWER_LIMIT) || ( mLoggingLevel > LOG_LEVEL_UPPER_LIMIT) || ( mLoggingLevel > iLog->iLoggingThreshold))
    {
		return 0;
    }
    
    if( !mLogMessage || (LOG_MESSAGE_MAX_SIZE < (int)strlen(mLogMessage)) )	
		return 0;

    pthread_mutex_lock ( &iLog->Lock);

    //int debugTagLen;
    char* debugTag;
    unsigned long  ulThreadID = pthread_self();
    

    char m_buffer[LOGGER_BUFFER_SIZE];
    char f_buffer[LOGGER_BUFFER_SIZE];
    char dateString[28];
    
    
    memset( &dateString, '\0', sizeof( dateString));
    makeTimeStamp( &dateString[0]);
    
	memset( m_buffer, '\0', sizeof(m_buffer));
	memset( f_buffer, '\0', sizeof(f_buffer));
		
	//if( fileName != NULL)
	if( fileName)	
	{
		if( strrchr(fileName,'/') )
		{
			fileName=strrchr(fileName,'/');
			fileName++;
		}
	}



    va_list args;// = 0;
    va_start( args, mLogMessage);
    vsnprintf( m_buffer, LOG_MESSAGE_MAX_SIZE, mLogMessage, args);
	va_end( args);
	 
	switch( mLoggingLevel)
	{
		case LOG_LEVEL_CRITICAL:
			debugTag = "[C]";
			//debugTagLen = sizeof("[C]");
		break;
		case LOG_LEVEL_ERROR:
			debugTag = "[E]";
			//debugTagLen = sizeof("[E]");
		break;
		case LOG_LEVEL_WARNING:
			debugTag = "[W]";
			//debugTagLen = sizeof("[W]");
		break;
		case LOG_LEVEL_NORMAL:
			debugTag = "[I]";
			//debugTagLen = sizeof("[I]");
		break;
		case LOG_LEVEL_DEBUG:
			debugTag = "[D]";
			//debugTagLen = sizeof("[D]");
		break;
		default:
			debugTag = "[E]";
			//debugTagLen = sizeof("[E]");
		break;
	}
	
	if( iLog->CSVMode == 0) 
	{
		sprintf( f_buffer, "%s|%s|%lu|%s|%s|%d\n", debugTag, dateString, ulThreadID, m_buffer, fileName, lineNum);	
	} 
	else 
	{
		sprintf( f_buffer, "%s\n", m_buffer);		
	}

	unsigned long m_FileSize;
	
	int bRotate = 0;
	struct stat fileStat;
	fstat( iLog->iHandle, &fileStat);
	m_FileSize = fileStat.st_size;
    
    //if(m_FileSize >= 3145728)
	if(m_FileSize >= 10485760)
		bRotate = 1;        
	
	if( bRotate == 1)
	{
		close( iLog->iHandle);

		char mFileNameBuffer[500];
		memset( &mFileNameBuffer, 0, 500);
		makeIntFileName( &mFileNameBuffer[0], iLog->Path, iLog->Prefix, &iLog->iFileIndex);
		
		//iLog->iHandle = creat( mFileNameBuffer, O_CREAT | S_IRWXU | S_IRWXG | S_IRWXO );
		//chmod( mFileNameBuffer, 0600);
		
		int iUmask = S_IWGRP | S_IWOTH;
		int iFileCreationMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		int iFlags = O_WRONLY | O_CREAT | O_APPEND;
		int iOldUmask = umask( iUmask);
		
		iLog->iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);	
		
		umask( iOldUmask);
	}
	
	write( iLog->iHandle, f_buffer, strlen( f_buffer));
	
	pthread_mutex_unlock ( &iLog->Lock);

	return 1;	
	 
}

int PERF_LOG( char* mLogMessage, ...)
{
	int id = 1;

	iLogConfig *iLog = &objStackObjects.LoggerConfig[id];
	
	if( iLog->Enabled == 0)
		return 0;
		
	//unsigned long mLoggingLevel = LOG_LEVEL_CRITICAL;
	
    if( !mLogMessage || (LOG_MESSAGE_MAX_SIZE < (int)strlen(mLogMessage)) )	
		return 0;

    pthread_mutex_lock ( &iLog->Lock);

    //int debugTagLen;
    //char* debugTag;
    //unsigned long  ulThreadID = pthread_self();
    

    char m_buffer[LOGGER_BUFFER_SIZE];
    char f_buffer[LOGGER_BUFFER_SIZE];
    
	memset( m_buffer, '\0', sizeof(m_buffer));
	memset( f_buffer, '\0', sizeof(f_buffer));
		
    va_list args;// = 0;
    va_start( args, mLogMessage);
    vsnprintf( m_buffer, LOG_MESSAGE_MAX_SIZE, mLogMessage, args);
	va_end( args);
	 
	sprintf( f_buffer, "%s\n", m_buffer);
	
	unsigned long m_FileSize;
	
	int bRotate = 0;
	struct stat fileStat;
	fstat( iLog->iHandle, &fileStat);
	m_FileSize = fileStat.st_size;
    
    //if(m_FileSize >= 3145728)
	if(m_FileSize >= 10485760)	
		bRotate = 1;        
	
	if( bRotate == 1)
	{
		close( iLog->iHandle);

		char mFileNameBuffer[500];
		memset( &mFileNameBuffer, 0, 500);
		makeIntFileName( &mFileNameBuffer[0], iLog->Path, iLog->Prefix, &iLog->iFileIndex);
		
		int iUmask = S_IWGRP | S_IWOTH;
		int iFileCreationMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		int iFlags = O_WRONLY | O_CREAT | O_APPEND;
		int iOldUmask = umask( iUmask);
		
		iLog->iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);	
		
		umask( iOldUmask);
	}
	
	write( iLog->iHandle, f_buffer, strlen( f_buffer));
	
	pthread_mutex_unlock ( &iLog->Lock);

	return 1;	
}


int CSV_LOG( char* mLogMessage, ...)
{
	int id = 3;

	iLogConfig *iLog = &objStackObjects.LoggerConfig[id];
	
	if( iLog->Enabled == 0)
		return 0;
		
	//unsigned long mLoggingLevel = LOG_LEVEL_CRITICAL;
	
    if( !mLogMessage || (LOG_MESSAGE_MAX_SIZE < (int)strlen(mLogMessage)) )	
		return 0;

    pthread_mutex_lock ( &iLog->Lock);

    //int debugTagLen;
    //char* debugTag;
    //unsigned long  ulThreadID = pthread_self();
    

    char m_buffer[LOGGER_BUFFER_SIZE];
    char f_buffer[LOGGER_BUFFER_SIZE];
    
	memset( m_buffer, '\0', sizeof(m_buffer));
	memset( f_buffer, '\0', sizeof(f_buffer));
		
    va_list args;// = 0;
    va_start( args, mLogMessage);
    vsnprintf( m_buffer, LOG_MESSAGE_MAX_SIZE, mLogMessage, args);
	va_end( args);
	 
	sprintf( f_buffer, "%s\n", m_buffer);
	
	/*
	if( iLog->CSVMode == 0) 
	{
		sprintf( f_buffer, "%s|%s|%lu|%s|%s|%d\n", debugTag, dateString, ulThreadID, m_buffer, fileName, lineNum);	
	} 
	else 
	{
		sprintf( f_buffer, "%s\n", m_buffer);		
	}
	*/

	unsigned long m_FileSize;
	
	int bRotate = 0;
	struct stat fileStat;
	fstat( iLog->iHandle, &fileStat);
	m_FileSize = fileStat.st_size;
    
    //if(m_FileSize >= 3145728)
	if(m_FileSize >= 10485760)	
		bRotate = 1;        
	
	if( bRotate == 1)
	{
		close( iLog->iHandle);

		char mFileNameBuffer[500];
		memset( &mFileNameBuffer, 0, 500);
		makeIntFileName( &mFileNameBuffer[0], iLog->Path, iLog->Prefix, &iLog->iFileIndex);
		
		int iUmask = S_IWGRP | S_IWOTH;
		int iFileCreationMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		int iFlags = O_WRONLY | O_CREAT | O_APPEND;
		int iOldUmask = umask( iUmask);
		
		iLog->iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);	
		
		umask( iOldUmask);
	}
	
	write( iLog->iHandle, f_buffer, strlen( f_buffer));
	
	pthread_mutex_unlock ( &iLog->Lock);

	return 1;	
}

int CLog( int id, unsigned long mLoggingLevel, const char *fileName, int lineNum, char* mLogMessage, ...)
{
	//return 0;
	
	id = 0;
	//if( id < 0 || id > 1) return 0; 
	
	iLogConfig *iLog = &objStackObjects.LoggerConfig[id];
	
	if( iLog->Enabled == 0)
		return 0;
	
	if( ( mLoggingLevel < LOG_LEVEL_LOWER_LIMIT) || ( mLoggingLevel > LOG_LEVEL_UPPER_LIMIT) || ( mLoggingLevel > iLog->iLoggingThreshold))
    {
		return 0;
    }
    
    if( !mLogMessage || (LOG_MESSAGE_MAX_SIZE < (int)strlen(mLogMessage)) )	
		return 0;

    pthread_mutex_lock ( &iLog->Lock);

    //int debugTagLen;
    char* debugTag;
    unsigned long  ulThreadID = pthread_self();
    
    char m_buffer[LOGGER_BUFFER_SIZE];
    char f_buffer[LOGGER_BUFFER_SIZE];
    char dateString[28];
    
    
    memset( &dateString, 0, sizeof( dateString));
    makeTimeStamp( &dateString[0]);
	//makeTimeStamp( dateString);
	//makeTimeStamp2( dateString);
    
	memset( m_buffer, '\0', sizeof(m_buffer));
	memset( f_buffer, '\0', sizeof(f_buffer));
		
	//if( fileName != NULL)
	if( fileName)	
	{
		if( strrchr(fileName,'/') )
		{
			fileName=strrchr(fileName,'/');
			fileName++;
		}
	}

	/**/
    va_list args;// = 0;
    va_start( args, mLogMessage);
    vsnprintf( m_buffer, LOG_MESSAGE_MAX_SIZE, mLogMessage, args);
	va_end( args);
	
	
	switch( mLoggingLevel)
	{
		case LOG_LEVEL_CRITICAL:
			debugTag = "[C]";
			break;
		case LOG_LEVEL_ERROR:
			debugTag = "[E]";
			break;
		case LOG_LEVEL_WARNING:
			debugTag = "[W]";
			break;
		case LOG_LEVEL_NORMAL:
			debugTag = "[I]";
			break;
		case LOG_LEVEL_DEBUG:
			debugTag = "[D]";
			break;
		default:
			debugTag = "[E]";
			break;
	}
	

	if( iLog->CSVMode == 0) 
	{
		sprintf( f_buffer, "%s|%s|%lu|%s|%s|%d\n", debugTag, dateString, ulThreadID, m_buffer, fileName, lineNum);	
	} 
	else 
	{
		sprintf( f_buffer, "%s\n", m_buffer);		
	}
	
	unsigned long m_FileSize;
	
	int bRotate = 0;
	struct stat fileStat;
	fstat( iLog->iHandle, &fileStat);
	m_FileSize = fileStat.st_size;
    
    //if(m_FileSize >= 3145728)
	if(m_FileSize >= 10485760)	
		bRotate = 1;        
	
	if( bRotate == 1)
	{
		close( iLog->iHandle);

		char mFileNameBuffer[500];
		memset( &mFileNameBuffer, 0, 500);
		makeFileName( &mFileNameBuffer[0], iLog->Path, iLog->Prefix);
		
		//iLog->iHandle = creat( mFileNameBuffer, O_CREAT | O_RDWR);
		int iUmask = S_IWGRP | S_IWOTH;
		int iFileCreationMode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
		int iFlags = O_WRONLY | O_CREAT | O_APPEND;
		int iOldUmask = umask( iUmask);
		
		iLog->iHandle = open( mFileNameBuffer, iFlags, iFileCreationMode);	
		
		umask( iOldUmask);		
	}
	
	write( iLog->iHandle, f_buffer, strlen( f_buffer));
	
	pthread_mutex_unlock ( &iLog->Lock);

	return 1;	
	
}


void sighandlerBase( int signum)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Caught signal %d ...\n", signum);
	printf("Caught signal %d ...\n", signum);
   //exit(1);
}



static unsigned long calc_hash(char* key)
{
	unsigned long h = 5381;
	
	while(*(key++))
		h = ((h << 5) + h) + (*key);
	
	return h;
}

static unsigned long calc_hash_lastchars(char* key)
{
	int calcLen = objStackConfig.HashCharLength;
	
	char lChars[20] = {0};
	int len = strlen(key);
	
	if( calcLen > 20) {
		calcLen = 20;
	}
	
	int iStartIndex = len - calcLen;
	
	if( iStartIndex < 0)
		iStartIndex = 0;
	
	int i;
	int j = 0;
	for( i = iStartIndex ; i <= len; i++)
	{
		lChars[j] = key[i];
		j++;
	}
	
	return abs( calc_hash( lChars));
}

void requestCore()
{
	____onlyCore = 1;
}

void setUpCore()
{
	DM_CDATA_INITIAL_POOL_SIZE = 1;
	DIAM_TIMER_MSG_INITIAL_POOL_SIZE = 50000;
	DIAM_QUEUE_MSG_INITIAL_POOL_SIZE = 100000;
	DIAM_ROUTE_MSG_INITIAL_POOL_SIZE = 1;
	DIAM_RAW_MSG_INITIAL_POOL_SIZE = 1;
	DM_MSG_INITIAL_POOL_SIZE = 1;
	DM_AVP_INITIAL_POOL_SIZE = 1;
	DIAM_STICKY_SESSION_MSG_INITIAL_POOL_SIZE = 1;
}



void InitMBMalloc( int mbVal, int iMutiply)
{
	if(!globalMxMemory)
	{
		if( iMutiply <= 0)
			iMutiply = 1;
		
		if( iMutiply > 4)
			iMutiply = 4;
		
		int reqGBMem = (mbVal*1024*1024);

		#if DIAMDRA
			printf("1 Required Memory %d Bytes [%d MB]\n", (iMutiply * reqGBMem), ((iMutiply * reqGBMem)/1024)/1024 );		
			globalMxMemory = (char*)calloc( iMutiply, reqGBMem);
			globalMxAllocatedMem = iMutiply * reqGBMem;
		#else
			printf("2 Required Memory %d Bytes [%d MB]\n", (iMutiply * reqGBMem), ((iMutiply * reqGBMem)/1024)/1024 );		
			globalMxMemory = (char*)calloc( iMutiply, reqGBMem);
			globalMxAllocatedMem = iMutiply * reqGBMem;
			
			DM_CDATA_INITIAL_POOL_SIZE = 100000;
			DIAM_TIMER_MSG_INITIAL_POOL_SIZE = 10000;
			DIAM_QUEUE_MSG_INITIAL_POOL_SIZE = 100000;
			DIAM_ROUTE_MSG_INITIAL_POOL_SIZE = 10000;
			DIAM_RAW_MSG_INITIAL_POOL_SIZE = 10000;
			DM_MSG_INITIAL_POOL_SIZE = 10000;
			DM_AVP_INITIAL_POOL_SIZE = 50000;
			DIAM_STICKY_SESSION_MSG_INITIAL_POOL_SIZE = 10000;
		#endif		

		if(!globalMxMemory) 
		{
			printf("12 memory allocation failed\n");
			exit(0);
		}		
	}
}

void __internal_skip_license_validation()
{
}

void InitMallocFX()
{
	if(!globalMxMemory)
	{
		int oneKB = 1024; //bytes
		int oneMB = oneKB * 1024;
		int oneGB = oneMB * 1024;
		int reqGBMem = ( (oneGB/2) * 1);
		//int reqGBMem = oneGB;
		
		//printf("required memory %d bytes\n", reqGBMem);		
		//globalMxMemory = (char*)malloc( reqGBMem);
		//1 = 0.5 GB, 2 = 1 GB, 3 = 1.5 GB
		//reqGBMem = 0.5 GB

		#if DIAMDRA
			reqGBMem = ( (oneGB/2) * 1);
			printf("3 Required Memory %d Bytes ( %d MB)\n", (1 * reqGBMem), ((1 * reqGBMem)/1024)/1024 );		
			globalMxMemory = (char*)calloc( 1, reqGBMem);
			globalMxAllocatedMem = 1 * reqGBMem;
		#else
			printf("4 Required Memory %d Bytes ( %d MB)\n", (1 * reqGBMem), ((1 * reqGBMem)/1024)/1024 );		
			globalMxMemory = (char*)calloc( 1, reqGBMem);	
			globalMxAllocatedMem = 1 * reqGBMem;
			
			DM_CDATA_INITIAL_POOL_SIZE = 100000;
			DIAM_TIMER_MSG_INITIAL_POOL_SIZE = 10000;
			DIAM_QUEUE_MSG_INITIAL_POOL_SIZE = 100000;
			DIAM_ROUTE_MSG_INITIAL_POOL_SIZE = 10000;
			DIAM_RAW_MSG_INITIAL_POOL_SIZE = 10000;
			DM_MSG_INITIAL_POOL_SIZE = 10000;
			DM_AVP_INITIAL_POOL_SIZE = 50000;
			DIAM_STICKY_SESSION_MSG_INITIAL_POOL_SIZE = 10000;
		#endif		

		if(!globalMxMemory) 
		{
			printf("12 memory allocation failed\n");
			exit(0);
		}
		
	}	
}


int core_AddLogCat( char *cLogCatName, int iEnable)
{
	if( objStackObjects.LogCatCount >= 30)
		return -1;
	
	int i;
	for( i = 0; i < objStackObjects.LogCatCount; i++)
	{
		//printf("%s\n", objStackObjects.LogCatInfo[i].iLogCatName);
		if( strcmp( objStackObjects.LogCatInfo[i].iLogCatName, cLogCatName) == 0)
		{
			if( iEnable != -1) {
				objStackObjects.LogCatInfo[i].Enabled = iEnable;
			}
			return i;
		}
	}
	
	objStackObjects.LogCatInfo[objStackObjects.LogCatCount].iLogCatId = objStackObjects.LogCatCount;
	strcpy( objStackObjects.LogCatInfo[objStackObjects.LogCatCount].iLogCatName, cLogCatName);
	
	if( iEnable != -1) {
		objStackObjects.LogCatInfo[objStackObjects.LogCatCount].Enabled = iEnable;
	}	
	
	objStackObjects.LogCatCount++;
	
	return (objStackObjects.LogCatCount-1);
}


//gcc -g3 -shared -o libDiamAgentFx.so -fPIC DiamTcp2.c -lpthread -DDIAMDRA
// cp * /media/anil/1E32077932075565/NEW_STK/04_06_2016/
//gcc -shared -o libDiamFx.so -fPIC DiamTcp.c -lpthread
void InitalizeStack(char* configFileName)
{
	//initMessagePool();
	//signal( SIGPIPE, SIG_IGN);

	InitMalloc();
	
	if( ____onlyCore == 1)
	{
		setUpCore();
	}

	
	globalMxCurrPos = 0;
	
	
	//if( globalMxMemory == NULL)
	if(!globalMxMemory)	
	{
		printf("Memory Allocation Failed\n");
		exit(0);
	}
	else
	{
		printf("Memory Allocated Successfully\n");	
	}
	
	/*
	char* dx = (char*)lib_malloc( oneGB * reqGBMem);	
	if( dx == NULL)
	{
		printf("dx memory allocation failed %d bytes\n", ( oneGB * reqGBMem));
		exit(0);
	}
	else
	{
		printf("dx memory allocated %d bytes\n");	
	}
	*/
	
	signal( SIGPIPE, sighandlerBase);

	initConfig( configFileName);

    //initLogThread();


	initLogger();

	/*
	objStackConfig.iCatLog_CoreSockets 		= core_AddLogCat( (char *)"CORE_SOCKETS", 1);
	objStackConfig.iCatLog_CoreDecode 		= core_AddLogCat( (char *)"CORE_DECODE", 1);	
	objStackConfig.iCatLog_CoreRouting 		= core_AddLogCat( (char *)"CORE_ROUTING", 1);
	
	core_AddLogCat( (char *)"CORE_RESERVED1", 1);
	core_AddLogCat( (char *)"CORE_RESERVED2", 1);	
	*/
	
	#if DIAMDRA
	
	printf("==========================================D R A==========================================\n");

	objStackObjects.MinHBH = 1;
	objStackObjects.MaxHBH = 10000000;
	objStackObjects.CurrentHBH = 1;
		
	int i = 0;
	
	for(i = 0; i < objStackObjects.MaxHBH; i++)
	{
		objStackObjects.HBHDB[i].oClientInfo = NULL; 
		objStackObjects.HBHDB[i].OriginalHBH = 0;
	}
	
	pthread_mutex_init( &objStackObjects.HBHLock, NULL);
		
	printf("====================================*=*=*=D R A=*=*=*====================================\n");
		
	#endif


	printf("Loaded Config\n");

	initMessagePool();


	if( objStackConfig.EnablePerformaceThread > 0)
	{
		initPerformanceThread();
	}
	
	initalizeServer();
	
	initTimerThread();
	
	//appHandleQuitCommand();
	
	printMallocStats();
	
	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Stack Initalized");
}

void InitalizeCore(char* configFileName)
{
	requestCore();
	InitalizeStack( configFileName);
}

void core_wait()
{
	while(1)
	{
		sleep(1);
	}	
}


typedef struct E2ERecord
{
	//unsigned int iRecordId;
	void *DataPtr; 
} iE2ERecord;

typedef struct E2ETable
{
	iE2ERecord *Rows;
	int iStartIndex;	//shoud not be zero;
	int iMaxRows;
	int iCurrentIndex;
	pthread_mutex_t Lock;	
} iE2ETable;

void core_createE2ETable( int iMaxRows, void **dataPtr)
{
	//printMallocStats();
	iE2ETable *oE2ETable = NULL;
	lib_malloc2( sizeof(iE2ETable), (void **) &oE2ETable);

	//printMallocStats();
	//oE2ETable->Rows = calloc( iMaxRows, sizeof(iE2ERecord));
	lib_malloc2( (iMaxRows * sizeof(iE2ERecord)), (void **) &oE2ETable->Rows);
	memset( oE2ETable->Rows, 0, (iMaxRows * sizeof(iE2ERecord)));
	
	
	//printMallocStats();
	
	oE2ETable->iStartIndex = 1;
	oE2ETable->iMaxRows = iMaxRows;
	pthread_mutex_init( &oE2ETable->Lock, NULL);
	
	
	*dataPtr = oE2ETable;	
}


int core_getNextE2EId( void *dataPtr)
{
	iE2ETable * oE2ETable = (iE2ETable *)dataPtr;

	int _id = 0;
	pthread_mutex_lock( &oE2ETable->Lock);

	if( oE2ETable->iCurrentIndex < (oE2ETable->iMaxRows-1) ) {
		oE2ETable->iCurrentIndex++; 
	} else {
		oE2ETable->iCurrentIndex = oE2ETable->iStartIndex;
	}
	
	_id = oE2ETable->iCurrentIndex;
	
	pthread_mutex_unlock( &oE2ETable->Lock);	
	return _id;
}

void core_setE2EObject( void *dataPtr, int id, void* objData)
{
	iE2ETable * oE2ETable = (iE2ETable *)dataPtr;	
	iE2ERecord * oE2ERecord = (iE2ERecord *) &oE2ETable->Rows[id];
	oE2ERecord->DataPtr = objData;
}

void core_getE2EObject( void *dataPtr, int id, void **objData)
{
	iE2ETable * oE2ETable = (iE2ETable *)dataPtr;	
	iE2ERecord * oE2ERecord = (iE2ERecord *) &oE2ETable->Rows[id];
	*objData = oE2ERecord->DataPtr;
}	
	

int getDiamString( struct DiamMessage* dmMsg, int iAVPCode, int iIndex, iDiamString * oDiamString)
{
	struct DiamAvp* dmAvp = (struct DiamAvp*)iteratorMoveFirst(dmMsg);
	int iLocalIndex = 0;
	
	while(dmAvp)	
	{
		int iCurrentAvpCode = getAvpCode( dmAvp);

		if( iCurrentAvpCode == iAVPCode)
		{
			if( iIndex == iLocalIndex)
			{
				getOctetString( dmAvp, oDiamString->Value, &oDiamString->Length);
				return 1;
			}	
			iLocalIndex++;
		}
		
		dmAvp = (struct DiamAvp*) iteratorMoveNext(dmMsg);
	}
	
	return 0;
}


//===========================================================================================================================
// Web Console

typedef struct LoginInfoData
{
	char sUserName[100];
	char sPassword[100];	
} iLoginInfoData;

typedef struct WebAuthData
{
	char sGUID[100];
} iWebAuthData;


typedef struct AddUpdateHostConfigData
{
	char sIndex[5];
	char sHostURI[200];
	char sHostRealm[120];
	char sAcceptUnknownPeer[5];
	char SuppApp1[11];
	char SuppApp2[11];
	char SuppApp3[11];
	char SuppApp4[11];
	char SuppApp5[11];
	char SuppVen1[11];
	char SuppVen2[11];
	char SuppVen3[11];
	char SuppVen4[11];
	char SuppVen5[11];	
	char sValidateSupportedApplications[5];	
	
	char sHostIP[36];
	char sProdName[75];
	char sInbandSecurity[5];	
	char AuthApp1[11];
	char AuthApp2[11];
	char AuthApp3[11];
	char AuthApp4[11];
	char AuthApp5[11];
	char AcctApp1[11];
	char AcctApp2[11];
	char AcctApp3[11];
	char AcctApp4[11];
	char AcctApp5[11];
	char VendId1[11];
	char VendId2[11];
	char VendId3[11];
	char VendId4[11];
	char VendId5[11];
	
	char sGUID[100];	
} iAddUpdateHostConfigData;



typedef struct AddUpdatePeerConfigData
{
	char sIndex[5];
	char sPeerURI[200];
	char sPeerRealm[120];
	char sIPAddress[120];
	char SuppApp1[11];
	char sIsActive[5];	
	char SuppVend1[11];
	char SuppVend2[11];
	char SuppApp2[11];
	char SuppVend3[11];
	char SuppApp3[11];
	char SuppVend4[11];
	char SuppApp4[11];
	char SuppVend5[11];
	char SuppApp5[11];
	char HostEntryId[11];
	char AuthApp1[11];
	char AuthApp2[11];
	char AuthApp3[11];
	char AuthApp4[11];
	char AuthApp5[11];
	char AcctApp1[11];
	char AcctApp2[11];
	char AcctApp3[11];
	char AcctApp4[11];
	char AcctApp5[11];
	char VendId1[11];
	char VendId2[11];
	char VendId3[11];
	char VendId4[11];
	char VendId5[11];	
	
	
	char sGUID[100];
} iAddUpdatePeerConfigData;

typedef struct StartHostConfig
{
	char sGUID[100];
	char HostEntry[11];
} iStartHostConfig;

typedef struct WebClientInfo
{ 
	char PostData[2048];
	struct sockaddr clientAddr;
	int fd;
	
	int isReleased;
	struct WebClientInfo* PoolNext;
	int PoolIndex;
} iWebClientInfo;





char *fileRootPath;
#define CHUNK 102400

int IE_WebClientInfoPool_MSG_INITIAL_POOL_SIZE = 100;
int IE_WebClientInfoPool_MSG_INCR_POOL_SIZE = 20;


int addWebClientInfoToPool( iWebClientInfo *oWebClientInfo, int bInLockedMode, struct MessagePtr *mPtr)
{
	if(bInLockedMode) {
		pthread_mutex_lock( &mPtr->Lock );
	}

	if(!mPtr->HeadPtr)
	{
		mPtr->HeadPtr = mPtr->CurrPtr = (void*)oWebClientInfo;
	}
	else
	{
		((iWebClientInfo*)mPtr->CurrPtr)->PoolNext = (void*)oWebClientInfo;
	}

	mPtr->CurrPtr = (void*)oWebClientInfo;
	mPtr->Count++;

	if(bInLockedMode) {
		pthread_mutex_unlock( &mPtr->Lock );
	}

	return 0;
}

void createWebClientInfoPool( int iBatchSize)
{
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocating WebClientInfoPool iBatchSize:%d currentSize:%d", iBatchSize, oApplicationServer->WebClientInfoPool->PoolSize);

	int i = 0;

	for (i = 0; i < iBatchSize; i++)
	{
		iWebClientInfo *oWebClientInfo = NULL;
		lib_malloc2( sizeof(iWebClientInfo), (void **) &oWebClientInfo);
		memset( oWebClientInfo, 0, sizeof(iWebClientInfo)); 

		oWebClientInfo->isReleased = 1;
		oWebClientInfo->PoolIndex = ( oApplicationServer->WebClientInfoPool->PoolSize);
		oWebClientInfo->PoolNext = NULL;

		addWebClientInfoToPool( oWebClientInfo, 0, oApplicationServer->WebClientInfoPool->FreePool);
		oApplicationServer->WebClientInfoPool->PoolSize++;
	}
	
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Allocated WebClientInfoPool iBatchSize:%d currentSize:%d", iBatchSize, oApplicationServer->WebClientInfoPool->PoolSize);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "-------------------------------------------------------------");
}

iWebClientInfo* allocateWebClientInfo()
{
	iWebClientInfo* oWebClientInfo = NULL;

	pthread_mutex_lock( &oApplicationServer->WebClientInfoPool->FreePool->Lock );

	oWebClientInfo = oApplicationServer->WebClientInfoPool->FreePool->HeadPtr;

	if(!oWebClientInfo)
	{
		createWebClientInfoPool( IE_WebClientInfoPool_MSG_INCR_POOL_SIZE);
		oWebClientInfo = oApplicationServer->WebClientInfoPool->FreePool->HeadPtr;
	}

	if( oWebClientInfo)
	{
		oApplicationServer->WebClientInfoPool->FreePool->HeadPtr = oWebClientInfo->PoolNext;
		oWebClientInfo->PoolNext = NULL;
	}

	oApplicationServer->WebClientInfoPool->FreePool->Count--;
	pthread_mutex_unlock( &oApplicationServer->WebClientInfoPool->FreePool->Lock );

	oWebClientInfo->isReleased = 0;
	return oWebClientInfo;
}

void allocateWebClientInfoW( iWebClientInfo **dataPtr)
{
	*dataPtr = allocateWebClientInfo();
}


void releaseWebClientInfo(iWebClientInfo* oWebClientInfo)
{
/*	
	if( oWebClientInfo->isReleased == 0)
	{
		oWebClientInfo->isReleased = 1;
		addWebClientInfoToPool( oWebClientInfo, 1, oApplicationServer->WebClientInfoPool->FreePool);
	}
*/
	pthread_mutex_lock( &oApplicationServer->WebClientInfoPool->FreePool->Lock );
	
	if( oWebClientInfo->isReleased == 0)
	{
		oWebClientInfo->isReleased = 1;
		addWebClientInfoToPool( oWebClientInfo, 0, oApplicationServer->WebClientInfoPool->FreePool);
	}
	
	pthread_mutex_unlock( &oApplicationServer->WebClientInfoPool->FreePool->Lock );
}

//---------------------------------------------------------------------------------------------------------------

void coreAppServer_getHostIpByName( char * cServerName, char * ipAddress, int *ipType, int *ipResolved, struct sockaddr_in6 *addr_in6)
{
	char s[100];
	int rv = 0;
	*ipType = 0;
	*ipResolved = 0;
	
	struct addrinfo hints, *servinfo, *p;
	
	rv = 0;
	memset(&hints, 0, sizeof(hints));
	//hints.ai_family = AF_UNSPEC; 				// use AF_INET6 to force IPv6
	hints.ai_family = AF_INET6; 				// use AF_INET6 to force IPv6
	hints.ai_socktype = SOCK_STREAM;
	
	// if( oHostConfig->IPAddressType == 1)
		// hints.ai_family = AF_UNSPEC;
	
	if ((rv = getaddrinfo( cServerName, NULL, &hints, &servinfo)) != 0) 	
	{
		fprintf(stderr, "getaddrinfo: %s attempting..., for v4\n", gai_strerror(rv));
		hints.ai_family = AF_UNSPEC;
		
		if ((rv = getaddrinfo( cServerName, NULL, &hints, &servinfo)) != 0) 	
		{	
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
			return;
		}
	}
		
	for(p = servinfo; p != NULL; p = p->ai_next) 
	{
		// printf("p->ai_family[%d] p->ai_socktype[%d] p->ai_protocol[%d] ", p->ai_family, p->ai_socktype, p->ai_protocol);
		// printf("p->ai_addrlen[%d] p->ai_canonname[%s] AF_INET[%d] AF_INET6[%d]\n", p->ai_addrlen, p->ai_canonname, AF_INET, AF_INET6);
		
		memset( &s, 0, sizeof(s));
		
		if( AF_INET == p->ai_family)
		{
			struct sockaddr_in *addr_in = (struct sockaddr_in *)p->ai_addr;
			inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
			
			strcpy( ipAddress, s);
			
			*ipType = 1;
			*ipResolved = 1;
		}	
		else if( AF_INET6 == p->ai_family)
		{
			addr_in6 = (struct sockaddr_in6 *)p->ai_addr;
			inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
			
			strcpy( ipAddress, s);
			
			*ipType = 2;
			*ipResolved = 1;
		}
		
		// printf("IP address: %s\n", s);
		// printf("\n");
		
		// if( *ipType == 1 && *ipResolved == 1 && oHostConfig->IPAddressType == 1)
			// break;
		// else if( *ipType == 2 && *ipResolved == 1 && oHostConfig->IPAddressType == 2)
			// break;
		
		if( *ipResolved == 1)
			break;
	}
			
}

/*
	int ipType = 0;							//1=ipV4;	2=Ipv6
	int ipResolved = 0;
	struct sockaddr_in6 addr_in6;
	char s[100] = {0};
	int bConnected = 0;

	if( ipResolved == 0)
	{	
		coreAppServer_getHostIpByName( oHostConfigData->sHostName, s, &ipType, &ipResolved, &addr_in6);
	}	
	
	if( ipResolved == 1)
	{
		
	}	
*/

//10018
void sctpserver_addReadThread( iSocketReadThread *oSocketReadThread)
{
	if(!oApplicationServer->SocketReadThreadRoot)
	{
		oApplicationServer->SocketReadThreadRoot = oApplicationServer->SocketReadThreadCurrent = oSocketReadThread;
		oApplicationServer->SocketReadThreadCount = 1;
	}
	else
	{
		oApplicationServer->SocketReadThreadCurrent->Next = oSocketReadThread;
		oApplicationServer->SocketReadThreadCurrent = oSocketReadThread;
		oApplicationServer->SocketReadThreadCount++;
	}
	oSocketReadThread->Index = oApplicationServer->SocketReadThreadCount;	
}

void tcpserver_addReadThread( iSocketReadThread *oSocketReadThread)
{
	if(!oApplicationServer->TCPSocketReadThreadRoot)
	{
		oApplicationServer->TCPSocketReadThreadRoot = oApplicationServer->TCPSocketReadThreadCurrent = oSocketReadThread;
		oApplicationServer->TCPSocketReadThreadCount = 1;
	}
	else
	{
		oApplicationServer->TCPSocketReadThreadCurrent->Next = oSocketReadThread;
		oApplicationServer->TCPSocketReadThreadCurrent = oSocketReadThread;
		oApplicationServer->TCPSocketReadThreadCount++;
	}
	oSocketReadThread->Index = oApplicationServer->TCPSocketReadThreadCount;
}


void handle_sctp_event( void *buf, int iLen)
{
	#if SCTP_SUPPORT
	
	struct sctp_assoc_change *sac;
	struct sctp_send_failed  *ssf;
	struct sctp_paddr_change *spc;
	struct sctp_remote_error *sre;
	union sctp_notification  *snp;
	char addrbuf[INET6_ADDRSTRLEN];
	const char *ap;
	struct sockaddr_in  *sin;
	struct sockaddr_in6  *sin6;

	snp = buf;

	switch ( snp->sn_header.sn_type) 
	{
		case SCTP_ASSOC_CHANGE:
			sac = &snp->sn_assoc_change;
			printf("^^^ assoc_change: state=%hu, error=%hu, instr=%hu outstr=%hu\n", sac->sac_state, sac->sac_error, sac->sac_inbound_streams, sac->sac_outbound_streams);	
			printf("^^^ SCTP_ASSOC_CHANGE\n");
			break;
		case SCTP_SEND_FAILED:
			ssf = &snp->sn_send_failed;
			printf("^^^ sendfailed: len=%hu err=%d\n", ssf->ssf_length, ssf->ssf_error);
			//printf("^^^ SCTP_SEND_FAILED\n");
			break;
		case SCTP_PEER_ADDR_CHANGE:
			spc = &snp->sn_paddr_change;
			/*
			if (spc->spc_aaddr.ss_family == AF_INET) 
			{
				sin = (struct sockaddr_in *)&spc->spc_aaddr;
				ap = (char *) inet_ntop(AF_INET, &sin->sin_addr, addrbuf, INET6_ADDRSTRLEN);
			} 
			else 
			{
				sin6 = (struct sockaddr_in6 *)&spc->spc_aaddr;
				ap = (char *) inet_ntop(AF_INET6, &sin6->sin6_addr, addrbuf, INET6_ADDRSTRLEN);
			}
			*/
			printf("^^^ SCTP_PEER_ADDR_CHANGE\n");
			//printf("^^^ SCTP_PEER_ADDR_CHANGE intf_change: %s state=%d, error=%d addrbuf=%s ss_family=%d AF_INET[%d]\n", ap, spc->spc_state, spc->spc_error, addrbuf, spc->spc_aaddr.ss_family, AF_INET);
			break;
		case SCTP_REMOTE_ERROR:
			sre = &snp->sn_remote_error;
			printf("^^^ remote_error: err=%hu len=%hu\n", ntohs(sre->sre_error), ntohs(sre->sre_length));
			//printf("SCTP_REMOTE_ERROR\n");
			break;
		case SCTP_SHUTDOWN_EVENT:
			//printf("^^^ shutdown event\n");
			printf("SCTP_SHUTDOWN_EVENT\n");
			break;	
		default:
			break;
	}	
	
	#endif
}

//Function-ID:10002, once server is accepted new connection will attaches to running idle thread or creates new thread 
void * sctpserver_ClientReadThread( void * args)
{
	#if SCTP_SUPPORT
	
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iSocketReadThread *oSocketReadThread = (iSocketReadThread *) args;

	int n = 0, flags = 0, ret;
	//socklen_t from_len;
	struct sctp_sndrcvinfo sinfo = {0};
	//struct sockaddr_in addr = {0};
	 
	//ssize_t count;
	char buf[5000];
	char totbuf[10000];
	int iTotalBufferLength = 0;
	int PendingBufferLength = 0;
	int iUsedBufferSize = 0;
	
	struct pollfd fds;
	fds.fd     = oSocketReadThread->ClientInfo->fd;
	fds.events = POLLIN;
	struct DiamRawData *oDiamRawData = NULL;
	unsigned int iMessageLength;
	long int iRequestNo = 0;
	
	//printf("size oSocketReadThread->ClientInfo->SctpStreamBuffer %ld\n", sizeof(oSocketReadThread->ClientInfo->SctpStreamBuffer));
	memset( &oSocketReadThread->ClientInfo->SctpStreamBuffer, 0, sizeof(oSocketReadThread->ClientInfo->SctpStreamBuffer));
	
	while(1)
	{
		if( oSocketReadThread->isBusy == 0)
		{
			sem_wait( &oSocketReadThread->sem_lock);
		}
		else
		{
			fds.fd = oSocketReadThread->ClientInfo->fd;
			
			while(1)
			{
				if( oSocketReadThread->ClientInfo->CloseIt == 1)
				{
					close( oSocketReadThread->ClientInfo->fd);
					shutdown( oSocketReadThread->ClientInfo->fd, 2);
					releaseClientInfo( oSocketReadThread->ClientInfo);
					oSocketReadThread->ClientInfo = NULL;
					oSocketReadThread->isBusy = 0;
					break;
				}
				
				ret = poll( &fds, 1, 1000);

				if( ret == 0)
				{
					continue;
				}

				if( ret < 0)
				{
					close( oSocketReadThread->ClientInfo->fd);
					shutdown( oSocketReadThread->ClientInfo->fd, 2);
					releaseClientInfo( oSocketReadThread->ClientInfo);
					oSocketReadThread->ClientInfo = NULL;
					oSocketReadThread->isBusy = 0;
					break;
				}

				if( ret > 0)
				{
					n = sctp_recvmsg( oSocketReadThread->ClientInfo->fd, buf, sizeof(buf), (struct sockaddr *)NULL, 0, &sinfo, &flags);
					
					if( flags & MSG_NOTIFICATION ) 
					{
						union sctp_notification  *snp = (union sctp_notification *)buf;
						
						if(snp)
						{
							if( SCTP_SHUTDOWN_EVENT == snp->sn_header.sn_type)
							{
								//printf("SCTP_SHUTDOWN_EVENT Notified, closing connection\n");
								CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "SCTP_SHUTDOWN_EVENT Notified, closing connection");
								close( oSocketReadThread->ClientInfo->fd);
								shutdown( oSocketReadThread->ClientInfo->fd, 2);
								releaseClientInfo( oSocketReadThread->ClientInfo);
								oSocketReadThread->ClientInfo = NULL;
								oSocketReadThread->isBusy = 0;
								break;	
							}
						}
						
						handle_sctp_event( buf, n );
					}
					else
					{	
						if( (ret == 1 && n == 0) || n < 0)
						{
							//printf("poll return 1 and no data , closing connection Index[%d][%p]\n", oSocketReadThread->Index, oSocketReadThread);
							CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "poll return 1 and no data , closing connection Index[%d][%p]", oSocketReadThread->Index, oSocketReadThread);
							close( oSocketReadThread->ClientInfo->fd);
							shutdown( oSocketReadThread->ClientInfo->fd, 2);
							releaseClientInfo( oSocketReadThread->ClientInfo);
							oSocketReadThread->ClientInfo = NULL;
							oSocketReadThread->isBusy = 0;
							break;
						}

						//SCTP SERVER READ		
						if( n > 0)
						{
							//printf("stream %d, PPID %d.: received-bytes: %d\n", sinfo.sinfo_stream, ntohl(sinfo.sinfo_ppid), n);
							CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "stream %d, PPID %d.: received-bytes: %d", sinfo.sinfo_stream, ntohl(sinfo.sinfo_ppid), n);
							
							if( oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength > 0)
							{
								PendingBufferLength = oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength;
								memcpy( totbuf, oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, PendingBufferLength);
								memcpy( &totbuf[PendingBufferLength], buf, n);
								iTotalBufferLength = PendingBufferLength + n;
								oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = 0;
							}
							else
							{
								memcpy( totbuf, buf, n);
								iTotalBufferLength = n;
							}
							
							//buf[5000];
							//char totbuf[5000];
							
							iUsedBufferSize = 0;
							while( iUsedBufferSize < iTotalBufferLength)
							{	
								//Received Buffer should be at-least greater than diam header
								//as we already read the buffer from network
								if( ( iTotalBufferLength - iUsedBufferSize) > DIAM_BUFFER_SIZE_HEADER_SIZE)
								{
									oDiamRawData = allocateDiamRawData();
									oDiamRawData->Header->len = DIAM_BUFFER_SIZE_HEADER_SIZE;
									memcpy( oDiamRawData->Header->Data, &totbuf[iUsedBufferSize], DIAM_BUFFER_SIZE_HEADER_SIZE);
									
									decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);
									
									//printf("iMessageLength = %d\n", iMessageLength);
									if( iMessageLength > DIAM_BUFFER_SIZE_PER_REQUEST )
									{
										CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Received message-size[%sd] More than application can handle", iMessageLength);
										oSocketReadThread->ClientInfo->CloseIt = 1;
										break;
									}	
				
									if( ( iTotalBufferLength - iUsedBufferSize) >= iMessageLength )
									{
										//printf("iMessageLength = %d sufficient body message\n", iMessageLength);
										//CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "iMessageLength = %d sufficient body message", iMessageLength);
										memcpy( oDiamRawData->PayLoad->Data, &totbuf[iUsedBufferSize + DIAM_BUFFER_SIZE_HEADER_SIZE], (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE));
	
										oDiamRawData->iPeerIndex = -1;
										oDiamRawData->iRequestNo = iRequestNo;
										oDiamRawData->iMessageArrivedFrom = 10;
										oDiamRawData->iRouteMessageTo = 2;	
										oDiamRawData->PayLoad->len = (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE);
										oDiamRawData->CliInfo = oSocketReadThread->ClientInfo;
										
										objStackObjects.TotalMemoryUsage.SocketReadCount++;
										appPostMsg( oDiamRawData);
										
										iRequestNo++;
										iUsedBufferSize += iMessageLength;
									}
									else
									{
										releaseDiamRawData( oDiamRawData);
										//printf("message is less than header(20) size = %d\n", iTotalBufferLength);
										//CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
										oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
										//memcpy( oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
										memcpy( oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[iUsedBufferSize], ( iTotalBufferLength - iUsedBufferSize));
										break;
									}
								}
								else
								{
									//printf("message is less than header(20) size = %d\n", iTotalBufferLength);
									//CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
									oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
									//memcpy( oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
									memcpy( oSocketReadThread->ClientInfo->SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[iUsedBufferSize], ( iTotalBufferLength - iUsedBufferSize));
									break;
								}
							}
							
							//printf("host-client thread iUsedBufferSize[%d] , iTotalBufferLength[%d]\n", iUsedBufferSize, iTotalBufferLength);
							CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "host-client thread iUsedBufferSize[%d] , iTotalBufferLength[%d]", iUsedBufferSize, iTotalBufferLength);
						}
					}

				}

			}
		}

	}

	#endif

	return NULL;
}

//10019
void sctpserver_startReadThread( iSocketReadThread *oSocketReadThread)
{
	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

	int iRet;
	iRet = pthread_create( &oSocketReadThread->thread_id, &attr, sctpserver_ClientReadThread, oSocketReadThread);
	
	if( iRet < 0)
	{
		printf("unable to create thread for new sctp client connection\n");
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "unable to create thread for new sctp client connection for index %d", oSocketReadThread->Index);
		exit(0);
	}	
}

void * tcpserver_ClientReadThread( void * args)
{
	CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iSocketReadThread *oSocketReadThread = (iSocketReadThread *)args;
	
	int ret;
	struct pollfd fds;
	fds.fd     = oSocketReadThread->TCPClientInfo->fd;
	fds.events = POLLIN;

	oSocketReadThread->TCPClientInfo->hasPendingBeffer = 0;
	oSocketReadThread->TCPClientInfo->PendingBefferLength = 0;
	memset( &oSocketReadThread->TCPClientInfo->PendingBuffer, 0, sizeof(oSocketReadThread->TCPClientInfo->PendingBuffer));

	
	while(1)
	{
		if( oSocketReadThread->isBusy == 0)
		{
			sem_wait( &oSocketReadThread->sem_lock);
		}
		else
		{
			fds.fd = oSocketReadThread->TCPClientInfo->fd;
			
			while(1)
			{
				if( oSocketReadThread->TCPClientInfo->CloseIt == 1)
				{
					close( oSocketReadThread->TCPClientInfo->fd);
					shutdown( oSocketReadThread->TCPClientInfo->fd, 2);
					releaseTCPClientInfo( oSocketReadThread->TCPClientInfo);
					oSocketReadThread->ClientInfo = NULL;
					oSocketReadThread->TCPClientInfo = NULL;
					oSocketReadThread->isBusy = 0;
					break;
				}				
				
				ret = poll( &fds, 1, 1000);

				if( ret == 0)
				{
					continue;
				}
				
				if( ret < 0)
				{
					close( oSocketReadThread->TCPClientInfo->fd);
					shutdown( oSocketReadThread->TCPClientInfo->fd, 2);
					releaseTCPClientInfo( oSocketReadThread->TCPClientInfo);
					oSocketReadThread->ClientInfo = NULL;
					oSocketReadThread->TCPClientInfo = NULL;
					oSocketReadThread->isBusy = 0;
					break;
				}

				
				if( ret > 0)
				{
					if (fds.revents & POLLIN) 
					{
						//char tBuffer[593216];
						//char tBuffer[5000];		//per read less than 5000
						char tBuffer[1500];			//per read only tcp packet size
						int icount = read ( oSocketReadThread->TCPClientInfo->fd, &tBuffer, sizeof(tBuffer));
	
						if( icount > 0)
						{
							pthread_mutex_lock( &oSocketReadThread->TCPClientInfo->ReadLock);
							
							iTCPRingBuffer *oTCPRingBuffer = NULL;
							oTCPRingBuffer = allocateTCPRingBuffer();
							
							if(oTCPRingBuffer)
							{
								oTCPRingBuffer->TCPClientInfo = oSocketReadThread->TCPClientInfo;
								oTCPRingBuffer->iLength = 0;
								
								if( icount < sizeof(oTCPRingBuffer->cBuffer))
								{
									memcpy( oTCPRingBuffer->cBuffer, tBuffer, icount);
									oTCPRingBuffer->iLength = icount;
									//pthread_mutex_unlock( &oTCPClientInfo->ReadLock);
									
									Enquee( oTCPRingBuffer, oSocketReadThread->TCPClientInfo->TCPServerInfo->Queue);
								}
							}
							
							pthread_mutex_unlock( &oSocketReadThread->TCPClientInfo->ReadLock);
						}
						else
						{
							close( oSocketReadThread->TCPClientInfo->fd);
							shutdown( oSocketReadThread->TCPClientInfo->fd, 2);
							releaseTCPClientInfo( oSocketReadThread->TCPClientInfo);
							oSocketReadThread->ClientInfo = NULL;
							oSocketReadThread->TCPClientInfo = NULL;
							oSocketReadThread->isBusy = 0;
							break;
						}
						
						
					}	
				}
				
			}				
		}
	}
	
	return NULL;
}

void tcpserver_startReadThread( iSocketReadThread *oSocketReadThread)
{
	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

	int iRet;
	iRet = pthread_create( &oSocketReadThread->thread_id, &attr, tcpserver_ClientReadThread, oSocketReadThread);
	
	if( iRet < 0)
	{
		printf("unable to create thread for new sctp client connection\n");
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "unable to create thread for new tcp client connection for index %d", oSocketReadThread->Index);
		exit(0);
	}	
}

void appServer_tcpAttachToReadThread( iTCPClientInfo * oTCPClientInfo)
{
	pthread_mutex_lock( &oApplicationServer->TCPSocketReadThreadLock);

	iSocketReadThread *oSocketReadThread = oApplicationServer->TCPSocketReadThreadRoot;

	while(oSocketReadThread)
	{
		if( oSocketReadThread->isBusy == 0)
		{
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Found Idle TCP Read Thread with Index : %d", oSocketReadThread->Index);
			break;
		}
		
		oSocketReadThread = oSocketReadThread->Next;
	}

	if( oSocketReadThread)
	{
		//Found idle Thread
		oSocketReadThread->isBusy = 1;
		oSocketReadThread->TCPClientInfo = oTCPClientInfo;
		oSocketReadThread->iTransportType = 0;
		
		sem_post( &oSocketReadThread->sem_lock);
	}
	else
	{
		oSocketReadThread = (iSocketReadThread *) malloc( sizeof(iSocketReadThread));
		oSocketReadThread->isBusy = 1;
		oSocketReadThread->TCPClientInfo = oTCPClientInfo;
		oSocketReadThread->iTransportType = 0;
		oSocketReadThread->Next = NULL;
		
		if( sem_init( &oSocketReadThread->sem_lock, 0, 0) < 0)
    	{
    		printf("Semaphore Initialization Failed\n");
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Semaphore Initialization Failed for tcp read-thread %p clientFd: %d", oSocketReadThread, oTCPClientInfo->fd);
    		exit(-1);
    	}
		
		tcpserver_addReadThread( oSocketReadThread);
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "created new tcp read thread with index : %d", oSocketReadThread->Index);	
		tcpserver_startReadThread( oSocketReadThread);
	}
	
	pthread_mutex_unlock( &oApplicationServer->TCPSocketReadThreadLock);
}

//10017
void appServer_sctpAttachToReadThread( iClientInfo * cliInfo)
{
	pthread_mutex_lock( &oApplicationServer->SocketReadThreadLock);
	
	iSocketReadThread *oSocketReadThread = oApplicationServer->SocketReadThreadRoot;

	while(oSocketReadThread)
	{
		if( oSocketReadThread->isBusy == 0)
		{
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Found Idle Sctp Read Thread with Index : %d", oSocketReadThread->Index);
			break;
		}
		
		oSocketReadThread = oSocketReadThread->Next;
	}		

	if( oSocketReadThread)
	{
		//Found idle Thread
		oSocketReadThread->isBusy = 1;
		oSocketReadThread->ClientInfo = cliInfo;
		oSocketReadThread->iTransportType = 1;
		
		sem_post( &oSocketReadThread->sem_lock);
	}
	else
	{
		oSocketReadThread = (iSocketReadThread *) malloc( sizeof(iSocketReadThread));
		oSocketReadThread->isBusy = 1;
		oSocketReadThread->ClientInfo = cliInfo;
		oSocketReadThread->Next = NULL;
		
		if( sem_init( &oSocketReadThread->sem_lock, 0, 0) < 0)
    	{
    		printf("Semaphore Initialization Failed\n");
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Semaphore Initialization Failed for sctp read-thread %p clientFd: %d", oSocketReadThread, cliInfo->fd);
    		exit(-1);
    	}
		
		sctpserver_addReadThread( oSocketReadThread);
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "created new sctp read thread with index : %d", oSocketReadThread->Index);	
		
		sctpserver_startReadThread( oSocketReadThread);
	}
	
	pthread_mutex_unlock( &oApplicationServer->SocketReadThreadLock);	
}

//10012
/*
void * coreAppServerStartTcpHost( void * args)
{
	iHostConfigData *oHostConfigData = (iHostConfigData *)args;
	
	while(1)
	{
		if( oHostConfigData->iStarted == 1)
		{

		}
		usleep(999999);
	}
	return NULL;
}
*/


//10013
void * coreAppServerStartSctpHost( void * args)
{
	#if SCTP_SUPPORT
	
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iHostConfigData *oHostConfigData = (iHostConfigData *)args;
	
	int sd = -1, on = 1, sdconn, fd = 0;
	struct sockaddr_in6 serveraddr, clientaddr;
	int addrlen = sizeof(clientaddr);
	char str[INET6_ADDRSTRLEN];

	struct sctp_initmsg initmsg;
	struct sctp_event_subscribe events;
	memset( &events, 0, sizeof (events));
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_send_failure_event = 1;
	events.sctp_address_event = 1;
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;	
	int i = 0;
	
	//printf("%s,%d|oHostConfigData->iStarted=%d\n", __FUNCTION__, __LINE__, oHostConfigData->iStarted);

	while(1)
	{
		if( oHostConfigData->iStarted == 1)
		{
			if ((sd = socket( AF_INET6, SOCK_STREAM, IPPROTO_SCTP)) < 0) 
			{
				perror("socket() failed");
				break;
			}
			
			fd = sd;
			for( i = 0; i < oApplicationServer->StartedHostsCount; i++)
			{
				if( oApplicationServer->StartedHosts[i].Id == oHostConfigData->Id)
				{
					oApplicationServer->StartedHosts[i].fd = fd;
					//printf("Host fd=%d On Port=%d\n", fd, oHostConfigData->iPortNo);
					break;	
				}
			}
			
			//printf("OutLoop:: Host fd=%d On Port=%d\n", fd, oHostConfigData->iPortNo);
			
			
			if (setsockopt( sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on,sizeof(on)) < 0)
			{
				perror("setsockopt(SO_REUSEADDR) failed");
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "setsockopt(SO_REUSEADDR) failed for Host-Server Port : %d", oHostConfigData->iPortNo);
				exit(0);
			}
			
			memset(&serveraddr, 0, sizeof(serveraddr));
			//check support of IPv6
			serveraddr.sin6_family = AF_INET6;
			
			serveraddr.sin6_port   = htons( oHostConfigData->iPortNo );
			serveraddr.sin6_addr   = in6addr_any;
		  
			if ( bind( sd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0)
			{
				perror("sctp bind() failed");
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "sctp bind() failed for Host-Server Port : %d", oHostConfigData->iPortNo);
				exit(0);
			}

			memset (&initmsg, 0, sizeof (initmsg));
			initmsg.sinit_num_ostreams = 10;
			initmsg.sinit_max_instreams = 10;
			initmsg.sinit_max_attempts = 4;
			
			if( setsockopt ( sd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof (initmsg)) < 0 )
			{
				perror("setsockopt( IPPROTO_SCTP, SCTP_INITMSG) failed");
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "setsockopt( IPPROTO_SCTP, SCTP_INITMSG) failed for Host-Server Port : %d", oHostConfigData->iPortNo);
				exit(0);				
			}
			
			//printf("%s,%d|listing on sctp port %d, sd=%d\n", __FUNCTION__, __LINE__, oHostConfigData->iPortNo, sd);	

			if (listen( sd, 10) < 0)
			{
				perror("listen() failed");
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "listen() failed for Host-Server Port : %d", oHostConfigData->iPortNo);
				exit(0);
			}

			iClientInfo * cliInfo = NULL;
			
			while(1)
			{
				//printf("%s| %d accept\n", __FUNCTION__, sd);
				
				if( oHostConfigData->iStarted == 0)
				{
					close( sd);
					shutdown( sd, 2);
					oApplicationServer->StartedHosts[i].fd = -1;
					break;
				}
				
				//printf("%s,%d|before accept sd=%d\n", __FUNCTION__, __LINE__, sd);
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "waiting for new incoming connection on FD=%d for sctp" , sd);	
				sdconn = accept( sd, NULL, NULL);

				oHostConfigData->iStarted = oApplicationServer->StartedHosts[i].iStarted;
				
				//printf("%s,%d|after accept sd=%d oHostConfigData->iStarted=%d\n", __FUNCTION__, __LINE__, sd, oHostConfigData->iStarted);
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "accepted client FD=%d for sctp" , sd);	
				
				if( sdconn > 0 && oHostConfigData->iStarted == 1)
				{
					getpeername( sdconn, (struct sockaddr *)&clientaddr, (socklen_t *)&addrlen);
					
					if( inet_ntop( AF_INET6, &clientaddr.sin6_addr, str, sizeof(str))) 
					{
						//printf("Client address is %s\n", str);
						//printf("Client port is %d sdconn[%d]\n", ntohs( clientaddr.sin6_port), sdconn);
						
						//events
						/* Enable ancillary data */
						if (setsockopt( sdconn, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events)) < 0) 
						{
							printf("setsockopt SCTP_EVENTS\n");
							CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "setsockopt SCTP_EVENTS FD=%d for new sctp connection %d" , sd, sdconn);
							exit(1);
						}
						
						//iClientInfo * cliInfo = malloc(sizeof(iClientInfo));
						allocateClientInfoW( &cliInfo);

						memcpy( &cliInfo->clientAddr, &clientaddr, addrlen);
						cliInfo->fd = sdconn;
						cliInfo->CloseIt = 0;
						cliInfo->isActive = 1;
						cliInfo->RoutingTableIndex = -1;
						cliInfo->RoutingError = 0;
						cliInfo->ReceivedMessages = 0;
						cliInfo->SentMessages = 0;	
						cliInfo->HostConfig = (void *)oHostConfigData;
						cliInfo->TransportType = 1;
						
						appServer_sctpAttachToReadThread( cliInfo);
					}
				}
				else
				{
					close( sdconn);
					shutdown( sdconn, 2);
				}
			}
			
		}
		
		usleep(999999);
	}
	
	#endif
	
	return NULL;
}


int stopHostServer( iHostConfigData *oHostConfigData, char * sHostName, int iPort, char * sTransport)
{
	printf("stopHostServer Id=%d, sHostName=%s, iPort=%d, sTransport=%s | %s, %d\n", oHostConfigData->Id, sHostName, iPort, sTransport, __FUNCTION__, __LINE__);

	int i = 0;
	for( i = 0; i < oApplicationServer->StartedHostsCount; i++)
	{
		if( oApplicationServer->StartedHosts[i].Id == oHostConfigData->Id)
		{
			if( oApplicationServer->StartedHosts[i].iStarted == 1)
			{
				oApplicationServer->StartedHosts[i].iStarted = 0;
				break;
			}
		}
	}
	
	/*
	if( oApplicationServer->StartedHosts[i].fd > 0)
	{
		printf("socket close connection received\n");
		
		int fd = 0, ret = 0;
		struct sctp_initmsg   initmsg;
		struct sctp_event_subscribe events;			
		
		if ((fd = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1) 
		{
			perror("error while closing host socket");
		}
		
		printf("fd created for close connection received: %d \n", fd);		
		
		events.sctp_data_io_event = 1;
		events.sctp_association_event = 1;
		events.sctp_send_failure_event = 1;
		events.sctp_address_event = 1;
		events.sctp_peer_error_event = 1;
		events.sctp_shutdown_event = 1;	
		ret = setsockopt( fd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events));
		
		if (ret < 0) 
		{
			perror("error while closing host socket 45645884544");
		}		
		
		memset(&initmsg, 0, sizeof(struct sctp_initmsg));
		initmsg.sinit_num_ostreams = 5;
		initmsg.sinit_max_instreams = 5;
		initmsg.sinit_max_attempts = 4;
		ret = setsockopt( fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg));
		
		if (ret < 0) 
		{
			perror("setsockopt SCTP_INITMSG  4745711545");
		}
	
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		//addr.sin_addr.s_addr = inet_addr(s);
		//addr.sin_addr.s_addr = htons(INADDR_ANY);
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		addr.sin_port = htons( oApplicationServer->StartedHosts[i].iPortNo);

		if ( !(connect( fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)) 	
		{
			printf("connected to socket successfully. and closing now\n");
			
			close( fd);
			shutdown( fd, 2);
		}
		else
		{
			printf("connection failed\n");
		}
		
					
		printf("Closed Host fd=%d On Port=%d\n", oApplicationServer->StartedHosts[i].fd, oApplicationServer->StartedHosts[i].iPortNo);
	}
	*/
	
	
	return 1;
}

int getSctpHostFileDescriptorValue(int Id)
{
	int i = 0;
	int fd = 0;
	
	for( i = 0; i < oApplicationServer->StartedHostsCount; i++)
	{
		if( oApplicationServer->StartedHosts[i].Id == Id)
		{
			fd = oApplicationServer->StartedHosts[i].fd;
			break;	
		}
	}
	
	return fd;	
}

//10034
void core_recvMessageFromTCPClient( void * args)
{
	iTCPRingBuffer * oTCPRingBuffer = (iTCPRingBuffer *)args;
	//printf("Message Received %p iLength<%d>|%s\n", oTCPRingBuffer, oTCPRingBuffer->iLength, __FUNCTION__);
	
	//CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Message Received %p iLength<%d>", oTCPRingBuffer, oTCPRingBuffer->iLength);
	
	struct DiamRawData * oDiamRawData = NULL;
	int iTotalBufferLength, iUsedBufferSize, iMessageLength;
	
	if( oTCPRingBuffer->iLength > 0)
	{
		pthread_mutex_lock( &oTCPRingBuffer->TCPClientInfo->ReadLock);
		
		char cBuffer[oTCPRingBuffer->iLength + 2048];
		int icount = oTCPRingBuffer->iLength;

		if( oTCPRingBuffer->TCPClientInfo->hasPendingBeffer == 1)
		{
			memcpy( cBuffer, oTCPRingBuffer->TCPClientInfo->PendingBuffer, oTCPRingBuffer->TCPClientInfo->PendingBefferLength);
			memcpy( &cBuffer[oTCPRingBuffer->TCPClientInfo->PendingBefferLength], oTCPRingBuffer->cBuffer, icount);
			
			icount += oTCPRingBuffer->TCPClientInfo->PendingBefferLength;
			
			//APP_LOG( LOG_LEVEL_DEBUG, __FILE__, __LINE__, "Processed PendingBuffer of length:%d|%s", oTCPRingBuffer->TCPClientInfo->PendingBefferLength, __FUNCTION__);
			//printf("Processed PendingBuffer of length:%d|%s\n", oTCPRingBuffer->TCPClientInfo->PendingBefferLength, __FUNCTION__);
			
			oTCPRingBuffer->TCPClientInfo->hasPendingBeffer = 0;
			oTCPRingBuffer->TCPClientInfo->PendingBefferLength = 0;
		}
		else
		{
			memcpy( cBuffer, oTCPRingBuffer->cBuffer, oTCPRingBuffer->iLength);
		}

		//int iMessageId = 0;
		//int iBufferPosition = 0;
		iUsedBufferSize = 0;
		iTotalBufferLength = icount;
		iMessageLength = 0;
		
		while( iUsedBufferSize < iTotalBufferLength)
		{
			if( ( iTotalBufferLength - iUsedBufferSize) > DIAM_BUFFER_SIZE_HEADER_SIZE)
			{
				oDiamRawData = allocateDiamRawData();
				oDiamRawData->Header->len = DIAM_BUFFER_SIZE_HEADER_SIZE;
				memcpy( oDiamRawData->Header->Data, &cBuffer[iUsedBufferSize], DIAM_BUFFER_SIZE_HEADER_SIZE);
				
				decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);
				
				//Handle message body length is greater than we handle
				if( iMessageLength > DIAM_BUFFER_SIZE_PER_REQUEST )
				{
					CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Received message-size[%d] More than application can handle", iMessageLength);
					oTCPRingBuffer->TCPClientInfo->CloseIt = 1;
					break;
				}
				
				if( ( iTotalBufferLength - iUsedBufferSize) >= iMessageLength )
				{
					//CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "iMessageLength = %d sufficient body message", iMessageLength);
					memcpy( oDiamRawData->PayLoad->Data, &cBuffer[iUsedBufferSize + DIAM_BUFFER_SIZE_HEADER_SIZE], (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE));

					oDiamRawData->iPeerIndex = -1;
					oDiamRawData->iRequestNo = oTCPRingBuffer->TCPClientInfo->iRequestNo;
					oDiamRawData->iMessageArrivedFrom = 10;
					oDiamRawData->iRouteMessageTo = 2;	
					oDiamRawData->PayLoad->len = (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE);
					//oDiamRawData->CliInfo = oTCPRingBuffer->TCPClientInfo;
					oDiamRawData->CliInfo = (struct ClientInfo *) oTCPRingBuffer->TCPClientInfo;
					
					
					objStackObjects.TotalMemoryUsage.SocketReadCount++;
					appPostMsg( oDiamRawData);
					
					oTCPRingBuffer->TCPClientInfo->iRequestNo++;
					iUsedBufferSize += iMessageLength;					
				}
				else
				{
					releaseDiamRawData( oDiamRawData);
					//CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "buffer-size=%d is less than body-size=%d iTotalBufferLength=%d, iUsedBufferSize=%d, Remaining=%d", ( iTotalBufferLength - iUsedBufferSize), iMessageLength, iTotalBufferLength, iUsedBufferSize, ( iTotalBufferLength - iUsedBufferSize));
					oTCPRingBuffer->TCPClientInfo->hasPendingBeffer = 1;
					oTCPRingBuffer->TCPClientInfo->PendingBefferLength = ( iTotalBufferLength - iUsedBufferSize);
					//memcpy( oTCPRingBuffer->TCPClientInfo->PendingBuffer, &cBuffer[( iTotalBufferLength - iUsedBufferSize)], (iTotalBufferLength-iUsedBufferSize));
					memcpy( oTCPRingBuffer->TCPClientInfo->PendingBuffer, &cBuffer[iUsedBufferSize], (iTotalBufferLength-iUsedBufferSize));
					break;					
				}
			}
			else
			{
				//CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size iTotalBufferLength=%d, iUsedBufferSize=%d, Remaining=%d", iTotalBufferLength, iUsedBufferSize, ( iTotalBufferLength - iUsedBufferSize));
				oTCPRingBuffer->TCPClientInfo->hasPendingBeffer = 1;
				oTCPRingBuffer->TCPClientInfo->PendingBefferLength = ( iTotalBufferLength - iUsedBufferSize);
				//memcpy( oTCPRingBuffer->TCPClientInfo->PendingBuffer, &cBuffer[( iTotalBufferLength - iUsedBufferSize)], (iTotalBufferLength-iUsedBufferSize));
				memcpy( oTCPRingBuffer->TCPClientInfo->PendingBuffer, &cBuffer[iUsedBufferSize], (iTotalBufferLength-iUsedBufferSize));
				break;
			}
		}
		
		pthread_mutex_unlock( &oTCPRingBuffer->TCPClientInfo->ReadLock);
	}
	
	releaseTCPRingBuffer( oTCPRingBuffer);
}


//#Host Config Server...
//10011
int startHostServer( iHostConfigData *oHostConfigData, char * sHostName, int iPort, char * sTransport)
{
	printf("starting Host-Server Id=%d, sHostName=%s, iPort=%d, sTransport=%s | [F]%s, [L]%d\n", oHostConfigData->Id, sHostName, iPort, sTransport, __FUNCTION__, __LINE__);
	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "starting Host-Server Id=%d, sHostName=%s, iPort=%d, sTransport=%s", oHostConfigData->Id, sHostName, iPort, sTransport);
	
	int i = 0;
	int bFound = 0;
	for( i = 0; i < oApplicationServer->StartedHostsCount; i++)
	{
		if( oApplicationServer->StartedHosts[i].Id == oHostConfigData->Id)
		{
			bFound = 1;
			
			//if( oApplicationServer->StartedHosts[i].iStarted == 1)
			if( oApplicationServer->StartedHosts[i].fd > 0)
			{
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Already Started Host-Server with ActiveFD: %d", oApplicationServer->StartedHosts[i].fd);
				return 1010;
			}
			break;	
		}
	}

	
	if( bFound == 0)
	{
		i = oApplicationServer->StartedHostsCount;
		memcpy( &oApplicationServer->StartedHosts[i], oHostConfigData, sizeof(iHostConfigData));
		
		strcpy( oApplicationServer->StartedHosts[i].sHostName, sHostName);
		oApplicationServer->StartedHosts[i].iPortNo = iPort;
		oApplicationServer->StartedHosts[i].iStarted = 1;
		
		oApplicationServer->StartedHostsCount++;
	}
	else
	{
		oApplicationServer->StartedHosts[i].iStarted = 1;
	}
	
	
	if( bFound == 0)
	{	
		int iRet;
		pthread_t s_pthread_id;

		pthread_attr_t attr;
		pthread_attr_init( &attr);
		pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

		if( strcmp( "tcp", sTransport) == 0) 
		{
			//printf("starting tcp host\n");
			//iRet = pthread_create( &s_pthread_id, &attr, coreAppServerStartTcpHost,  (void *) &oApplicationServer->StartedHosts[i]);
			
			iTCPServerInfo * oTCPServerInfo = NULL;
			lib_malloc2( sizeof(iTCPServerInfo), (void **) &oTCPServerInfo);
			memset( oTCPServerInfo, 0, sizeof(oTCPServerInfo));
			
			oTCPServerInfo->iPort = iPort;
			oTCPServerInfo->HostConfigData = &oApplicationServer->StartedHosts[i];
			oTCPServerInfo->recvCallBack = core_recvMessageFromTCPClient;
			core_StartTCPServer( oTCPServerInfo);
			
			iRet = 0;
		}
		else if( strcmp( "sctp", sTransport) == 0) 
		{
			//printf("starting sctp host\n");
			iRet = pthread_create( &s_pthread_id, &attr, coreAppServerStartSctpHost, (void *) &oApplicationServer->StartedHosts[i]);
		}
		else 
		{
			return 0;
		}
		
		if( iRet != 0) 
			return 0;
	}
	
	return 1;
}

//10009
int parseAndSetHostName( iHostConfigData *oHostConfigData)
{
	char aaaKey[7];
	strncpy( aaaKey, oHostConfigData->sHostURI, 6);
	aaaKey[6] = '\0';
	
	char rawUri[249];
	memset( &rawUri, 0, sizeof(rawUri));
	
	char hostName[249];
	memset( &hostName, 0, sizeof(hostName));

	char transport[5];
	strcpy( transport, "sctp");
	transport[4] = '\0';
	
	int iPort;
	int i = 0;
	int bFound = 0;
					
	if( strcmp("aaa://", aaaKey) == 0) 
	{
		strncpy( rawUri, &oHostConfigData->sHostURI[6], strlen(oHostConfigData->sHostURI)-6);
		
		char *token;
		char *saveptr1, *saveptr2;
		token = strtok_r( rawUri, ";", &saveptr1);

		if( token)
		{
			token = strtok_r( token, ":", &saveptr2);
			
			if(token)
			{
				if( strlen(saveptr2) > 0)
				{
					strcpy( hostName, token);
					iPort = atoi( saveptr2);
					strcpy( oHostConfigData->sHostName, hostName);
					
					for( i = 0; i < oApplicationServer->StartedHostsCount; i++)
					{
						if( oApplicationServer->StartedHosts[i].Id == oHostConfigData->Id)
						{
							bFound = 1;
							break;
						}
					}
					
					if( bFound == 0)
					{
						i = oApplicationServer->StartedHostsCount;
						memcpy( &oApplicationServer->StartedHosts[i], oHostConfigData, sizeof(iHostConfigData));
						oApplicationServer->StartedHostsCount++;
						
						printf("[%d] HostName=%s iPort=%d|%s\n", i, oHostConfigData->sHostName, iPort, __FUNCTION__);
					}
				}
			}
		}			
	}
	
	return 0;
}

//10008
int parseAndstartHostServer( iHostConfigData *oHostConfigData)
{
	//printf("Id=%d;URI=%s;Realm=%s L[%d]\n", oHostConfigData->Id, oHostConfigData->sHostURI, oHostConfigData->sHostRealm, __LINE__);
	//oHostConfigData.iStarted = 1;	
	
	
	
	char aaaKey[7];
	strncpy( aaaKey, oHostConfigData->sHostURI, 6);
	aaaKey[6] = '\0';
	
	char rawUri[249];
	memset( &rawUri, 0, sizeof(rawUri));
	
	char hostName[249];
	memset( &hostName, 0, sizeof(hostName));
	
	char transport[5];
	strcpy( transport, "sctp");
	transport[4] = '\0';
	
	int iPort;
	
	if( strcmp("aaa://", aaaKey) == 0) 
	{
		strncpy( rawUri, &oHostConfigData->sHostURI[6], strlen(oHostConfigData->sHostURI)-6);
		//printf( "format matched: rawUri=%s\n", rawUri);
		
		char *token;
		char *saveptr1, *saveptr2;
		token = strtok_r( rawUri, ";", &saveptr1);
		
		if( token)
		{
			//printf("token=%s, saveptr1=%s\n", token, saveptr1);			
			token = strtok_r( token, ":", &saveptr2);			
			
			if(token)
			{
				if( strlen(saveptr2) > 0)
				{
					//printf("token=%s, saveptr2=%s\n", token, saveptr2);
					strcpy( hostName, token);
					iPort = atoi( saveptr2);
					
					while(1)
					{
						token = strtok_r( saveptr1, ";", &saveptr2);
						
						if( token)
						{
							//printf("next chunk %s\n", token);
							
							token = strtok_r( token, "=", &saveptr1);
							
							//printf("token=%s, saveptr1=%s\n", token, saveptr1);
							
							if( strcmp( token, "transport") == 0)
							{
								if( strcmp( saveptr1, "tcp") == 0 )
								{
									strcpy( transport, "tcp");
									transport[3] = '\0';
								}
							}
							else 
							{
								break;
							}
							
							if( strlen(saveptr2) == 0)
								break;
							
							saveptr1 = saveptr2;
						}
						else 
						{
							break;
						}
						
						printf("in while\n");
					}
					
					//printf("hostName=%s, iPort=%d\n", hostName, iPort);
					
					if( oHostConfigData->iStarted == 1)
					{	
						CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Starting Host-Server with HostName:%s, iPort:%d, transport=%s", hostName, iPort, transport);
						CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Host-Server Uri : %s", oHostConfigData->sHostURI);
						
						return startHostServer( oHostConfigData, hostName, iPort, transport);
					}
					else
					{
						return stopHostServer( oHostConfigData, hostName, iPort, transport);
					}	
				}
				else
				{
					CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "port length found : %lu", strlen(saveptr2));
					printf("port length found : %lu \n", strlen(saveptr2));	
					return 0;
				}
			}
			else 
			{
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "error when parsing 2 split");
				printf("error when parsing 2 split\n");			
				return 0;
			}
		}
		else 
		{
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "error when parsing 1 split");
			printf("error when parsing 1 split\n");
			return 0;
		}
	} 
	else 
	{
		printf("format not matched\n");
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Invalid Host Entry Found in Configuration File, unable to start host-server");
		return 0;
	}
	
	return 1;
}


//---------------------------------------------------------------------------------------------------------------
//10006
void *webServerThread( void *args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	int iPort = oApplicationServer->WebPort;
	int serverSocket, newSocket, clilen;
	struct sockaddr_in serverAddr, cli_addr;	
	
	serverSocket = socket( PF_INET, SOCK_STREAM, 0);

	if(serverSocket == -1)
	{
		printf("server socket creation failed\n");
		exit(1);
	}

	int yes = 1;

	if( setsockopt( serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
	{
		printf("server SO_REUSEADDR failed\n");
		exit(1);
	}

	memset( &(serverAddr.sin_zero), '\0', 8);
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(iPort);
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	if( bind( serverSocket, (struct sockaddr *) &serverAddr, sizeof(struct sockaddr)) != 0)
	{
		printf("server Bind Error\n");
		exit(1);
	}

	if( listen( serverSocket, 5) == 0)
	{
		while(1)
		{
			clilen = sizeof(cli_addr);
			newSocket = accept( serverSocket, (struct sockaddr *) &cli_addr, (socklen_t *)&clilen);

			if( newSocket != -1)
			{
				iWebClientInfo * cliInfo = NULL;
				allocateWebClientInfoW( &cliInfo);
				
				memcpy( &cliInfo->clientAddr, &cli_addr, clilen);
				cliInfo->fd = newSocket;
				memset( &cliInfo->PostData, '\0', sizeof(cliInfo->PostData));

				Enquee( cliInfo, oApplicationServer->WebRequestQueue);
			}				
		}
	}
	
	return NULL;
}

int IsWebValidAuthId( char *guidId)
{
	int i = 0;
	for( i = 0; i < oApplicationServer->SessionCount; i++)
	{
		if( strcmp( oApplicationServer->Sessions[i].GUID, guidId) == 0)
		{
			return 1;
		}			
	}
	return 0;
}

void addWebJsonData( char *reponse, char *line, int *msgLength)
{
	sprintf( reponse, "%s", line);
	*msgLength += (strlen(line));	
}

void addWebHeaderLine( char *reponse, char *line, int *msgLength)
{
	sprintf( reponse, "%s\n", line);
	*msgLength += (strlen(line) + 1);
}

void addWebBody( char *reponse, char *line, int *msgLength, int iBodyMessageLength)
{
	memcpy( reponse, line, iBodyMessageLength);
	*msgLength += iBodyMessageLength;
}

void handleWebInvalidRequest( iWebClientInfo *cliInfo, char* request)
{
	char reponse[2048];
	memset( &reponse, 0 , sizeof(reponse));
	int msgLength = 0;
	
	addWebHeaderLine( &reponse[msgLength], (char *)"HTTP/1.0 200 OK", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"Content-Type: text/html", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"X-Powered-By: WebUI@SIRIK", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"Connection: close", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"", &msgLength);
	
	addWebHeaderLine( &reponse[msgLength], (char *)"Invalid Request", &msgLength);	
	
	int iSentBytes = send( cliInfo->fd, &reponse , msgLength, 0 );
	
	if( iSentBytes < msgLength)
	{
		printf("iSentBytes=%d failed\n", iSentBytes);
	}
	
	close( cliInfo->fd);
	shutdown(cliInfo->fd, 2);	
}

void getWebFileBuffer( char *filePath, char *buf, int *bufLength)
{
	char fullFilePath[500];
	memset( &fullFilePath, 0, sizeof(fullFilePath));
	sprintf( fullFilePath, "./%s/%s", fileRootPath, filePath);
	
	FILE *file;
	size_t nread;
	int fileSize = CHUNK;
	//int i;
	
	file = fopen( fullFilePath, "rb");
	
	if (file) 
	{
		fseek( file, 0, SEEK_END);
		rewind( file);
		nread = fread( buf, sizeof(char), fileSize, file);
		*bufLength = nread;
		buf[nread] = '\0';
		fclose(file);
	}
}

const char *get_filename_ext( const char *filename) 
{
    const char *dot = strrchr(filename, '.');
    if(!dot || dot == filename) return "";
    return dot + 1;
}

unsigned char WebHexChar (char c)
{
    if ('0' <= c && c <= '9') return (unsigned char)(c - '0');
    if ('A' <= c && c <= 'F') return (unsigned char)(c - 'A' + 10);
    if ('a' <= c && c <= 'f') return (unsigned char)(c - 'a' + 10);
    return 0xFF;
}

//int WebHexToBin(const char* s, unsigned char * buff, int length)
int WebHexToBin( char* s, char * buff, int length)
{
    int result;
    if (!s || !buff || length <= 0) return -1;

    for (result = 0; *s; ++result)
    {
        unsigned char msn = WebHexChar(*s++);
        if (msn == 0xFF) return -1;
        unsigned char lsn = WebHexChar(*s++);
        if (lsn == 0xFF) return -1;
        unsigned char bin = (msn << 4) + lsn;

        if (length-- <= 0) return -1;
        *buff++ = bin;
    }
    return result;
}

void sendWebResponse( iWebClientInfo *cliInfo, char *responseBody, char *contentType, int iBufLength)
{
	char reponse[CHUNK];
	memset( &reponse, 0 , sizeof(reponse));
	int msgLength = 0;
	
	addWebHeaderLine( &reponse[msgLength], (char *)"HTTP/1.0 200 OK", &msgLength);
	addWebHeaderLine( &reponse[msgLength], contentType, &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"X-Powered-By: WebUI@SIRIK", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"Connection: close", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"", &msgLength);
	
	addWebBody( &reponse[msgLength], responseBody, &msgLength, iBufLength);
	
	int iSentBytes = 0;
	iSentBytes = send( cliInfo->fd, &reponse , msgLength, 0 );
	
	if( iSentBytes < msgLength)
	{
		printf("sent failed iSentBytes=%d\n", iSentBytes);
	}	
	
	close( cliInfo->fd);
	shutdown(cliInfo->fd, 2);	
}

void sendWebSuccessResponse( iWebClientInfo *cliInfo, char * sResponse)
{
	char reponse[2048];
	memset( &reponse, 0 , sizeof(reponse));
	int msgLength = 0;
	
	addWebHeaderLine( &reponse[msgLength], (char *)"HTTP/1.0 200 OK", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"Content-Type: application/json", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"X-Powered-By: WebUI@SIRIK", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"Connection: close", &msgLength);
	addWebHeaderLine( &reponse[msgLength], (char *)"", &msgLength);
	
	addWebHeaderLine( &reponse[msgLength], sResponse, &msgLength);	
	
	int iSentBytes = send( cliInfo->fd, &reponse , msgLength, 0 );

	//printf( "%s\n", reponse);	
	//printf("iSentBytes=%d\n", iSentBytes);
	
	if( iSentBytes < msgLength)
	{
		printf("sent failed iSentBytes=%d\n", iSentBytes);
	}
	
	close( cliInfo->fd);
	shutdown(cliInfo->fd, 2);	
}

void handleWebLoginRequest( iWebClientInfo *cliInfo, char* request)
{
	iLoginInfoData lvLoginInfoData;
	memset( &lvLoginInfoData, 0, sizeof(iLoginInfoData));	
	WebHexToBin ( cliInfo->PostData, (char *)&lvLoginInfoData, strlen(cliInfo->PostData));	
	
	char sResponse[1024] = {0};
	
	if( strcmp( lvLoginInfoData.sUserName, "admin") == 0 && strcmp( lvLoginInfoData.sPassword, "admin@321") == 0)
	{
		srand (clock());
		char GUID[40];
		int t = 0;
		char *szTemp = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
		char *szHex = "0123456789ABCDEF-";
		int nLen = strlen (szTemp);

		for (t=0; t<nLen+1; t++)
		{
			int r = rand () % 16;
			char c = ' ';   

			switch (szTemp[t])
			{
				case 'x' : { c = szHex [r]; } break;
				case 'y' : { c = szHex [(r & 0x03) | 0x08]; } break;
				case '-' : { c = '-'; } break;
				case '4' : { c = '4'; } break;
			}

			GUID[t] = ( t < nLen ) ? c : 0x00;
		}		

		if( oApplicationServer->SessionCount == 0)
		{	
			strcpy( oApplicationServer->Sessions[oApplicationServer->SessionCount].UserName, lvLoginInfoData.sUserName);
			strcpy( oApplicationServer->Sessions[oApplicationServer->SessionCount].Password, lvLoginInfoData.sPassword);		
			strcpy( oApplicationServer->Sessions[oApplicationServer->SessionCount].GUID, GUID);		
			oApplicationServer->SessionCount++;
		
			int msgLength0 = 0;
			addWebJsonData( &sResponse[msgLength0], (char *)"{\"Error\":0, \"Message\" : \"Success\", \"Id\" :\"", &msgLength0);
			addWebJsonData( &sResponse[msgLength0], GUID, &msgLength0);		
			addWebJsonData( &sResponse[msgLength0], (char *)"\"}", &msgLength0);
		}
		else
		{
			strcpy( oApplicationServer->Sessions[0].UserName, lvLoginInfoData.sUserName);
			strcpy( oApplicationServer->Sessions[0].Password, lvLoginInfoData.sPassword);		
			strcpy( oApplicationServer->Sessions[0].GUID, GUID);		
		
			int msgLength0 = 0;
			addWebJsonData( &sResponse[msgLength0], (char *)"{\"Error\":0, \"Message\" : \"Success\", \"Id\" :\"", &msgLength0);
			addWebJsonData( &sResponse[msgLength0], GUID, &msgLength0);		
			addWebJsonData( &sResponse[msgLength0], (char *)"\"}", &msgLength0);			
		}
	}
	else
	{
		strcpy( sResponse, "{\"Error\":5000, \"Message\" : \"Invalid User\"}" );
	}
	
	sendWebSuccessResponse( cliInfo, sResponse);	
}

void handleWebAddUpdatePeerConfigRequest( iWebClientInfo *cliInfo, char* request)
{
	//printf("expected size=%lu received=%ld\n", (sizeof(iAddUpdatePeerConfigData)*2), strlen(cliInfo->PostData));
	
	if( strlen(cliInfo->PostData) < (sizeof(iAddUpdatePeerConfigData)*2))
	{
		int iRemainingBytes = (sizeof(iAddUpdatePeerConfigData)*2) - strlen(cliInfo->PostData);
		//printf("iRemainingBytes=%d\n", iRemainingBytes);
		read( cliInfo->fd, &cliInfo->PostData[strlen(cliInfo->PostData)], iRemainingBytes);
	}
	
	iAddUpdatePeerConfigData lvAddUpdatePeerConfigData;
	memset( &lvAddUpdatePeerConfigData, 0, sizeof(iAddUpdatePeerConfigData));
	WebHexToBin( cliInfo->PostData, (char *)&lvAddUpdatePeerConfigData, (sizeof(iAddUpdatePeerConfigData)*2));

	printf("Index=%s\n", lvAddUpdatePeerConfigData.sIndex);
	printf("PeerURI=%s\n", lvAddUpdatePeerConfigData.sPeerURI);
	printf("PeerRealm=%s\n", lvAddUpdatePeerConfigData.sPeerRealm);
	printf("IPAddress=%s\n", lvAddUpdatePeerConfigData.sIPAddress);
	printf("SuppVend1=%s\n", lvAddUpdatePeerConfigData.SuppVend1);
	printf("SuppApp1=%s\n", lvAddUpdatePeerConfigData.SuppApp1);
	printf("SuppVend2=%s\n", lvAddUpdatePeerConfigData.SuppVend2);
	printf("SuppApp2=%s\n", lvAddUpdatePeerConfigData.SuppApp2);
	printf("SuppVend3=%s\n", lvAddUpdatePeerConfigData.SuppVend3);
	printf("SuppApp3=%s\n", lvAddUpdatePeerConfigData.SuppApp3);
	printf("SuppVend4=%s\n", lvAddUpdatePeerConfigData.SuppVend4);
	printf("SuppApp4=%s\n", lvAddUpdatePeerConfigData.SuppApp4);
	printf("SuppVend5=%s\n", lvAddUpdatePeerConfigData.SuppVend5);
	printf("SuppApp5=%s\n", lvAddUpdatePeerConfigData.SuppApp5);
	printf("IsActive=%s\n", lvAddUpdatePeerConfigData.sIsActive);
	printf("HostEntryId=%s\n", lvAddUpdatePeerConfigData.HostEntryId);
	printf(".AuthApp1=%s\n", lvAddUpdatePeerConfigData.AuthApp1);
	printf(".AuthApp2=%s\n", lvAddUpdatePeerConfigData.AuthApp2);
	printf(".AuthApp3=%s\n", lvAddUpdatePeerConfigData.AuthApp3);
	printf(".AuthApp4=%s\n", lvAddUpdatePeerConfigData.AuthApp4);
	printf(".AuthApp5=%s\n", lvAddUpdatePeerConfigData.AuthApp5);
	printf(".AcctApp1=%s\n", lvAddUpdatePeerConfigData.AcctApp1);
	printf(".AcctApp2=%s\n", lvAddUpdatePeerConfigData.AcctApp2);
	printf(".AcctApp3=%s\n", lvAddUpdatePeerConfigData.AcctApp3);
	printf(".AcctApp4=%s\n", lvAddUpdatePeerConfigData.AcctApp4);
	printf(".AcctApp5=%s\n", lvAddUpdatePeerConfigData.AcctApp5);
	printf(".VendId1=%s\n", lvAddUpdatePeerConfigData.VendId1);
	printf(".VendId2=%s\n", lvAddUpdatePeerConfigData.VendId2);
	printf(".VendId3=%s\n", lvAddUpdatePeerConfigData.VendId3);
	printf(".VendId4=%s\n", lvAddUpdatePeerConfigData.VendId4);
	printf(".VendId5=%s\n", lvAddUpdatePeerConfigData.VendId5);
	printf("GUID=%s\n", lvAddUpdatePeerConfigData.sGUID);

	char sResponse[1024] = {0};
	if( IsWebValidAuthId( lvAddUpdatePeerConfigData.sGUID) == 1)
	{
		iPeerConfigData lvPeerConfigData;
		memset( &lvPeerConfigData, 0, sizeof(iPeerConfigData));

		lvPeerConfigData.Id = 0;
		
		if( strcmp( lvAddUpdatePeerConfigData.sIndex, "") != 0) {			
			lvPeerConfigData.Id = atoi(lvAddUpdatePeerConfigData.sIndex);
		}		

		strcpy( lvPeerConfigData.sPeerURI, lvAddUpdatePeerConfigData.sPeerURI);
		strcpy( lvPeerConfigData.sPeerRealm, lvAddUpdatePeerConfigData.sPeerRealm);
		strcpy( lvPeerConfigData.sIPAddress, lvAddUpdatePeerConfigData.sIPAddress);

		if( strcmp( lvAddUpdatePeerConfigData.SuppVend1, "") != 0) {
			lvPeerConfigData.uiSuppAppVendorId1 = atoi(lvAddUpdatePeerConfigData.SuppVend1);
		}		

		if( strcmp( lvAddUpdatePeerConfigData.HostEntryId, "") != 0) {
			lvPeerConfigData.HostEntryId = atoi(lvAddUpdatePeerConfigData.HostEntryId);
		} else {
			lvPeerConfigData.HostEntryId = 1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.SuppApp1, "") != 0) {
			lvPeerConfigData.uiSuppApp1 = atoi(lvAddUpdatePeerConfigData.SuppApp1);	
		}

		if( strcmp( lvAddUpdatePeerConfigData.SuppVend2, "") != 0) {
			lvPeerConfigData.uiSuppAppVendorId2 = atoi(lvAddUpdatePeerConfigData.SuppVend2);
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.SuppApp2, "") != 0) {
			lvPeerConfigData.uiSuppApp2 = atoi(lvAddUpdatePeerConfigData.SuppApp2);	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.SuppVend3, "") != 0) {
			lvPeerConfigData.uiSuppAppVendorId3 = atoi(lvAddUpdatePeerConfigData.SuppVend3);
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.SuppApp3, "") != 0) {
			lvPeerConfigData.uiSuppApp3 = atoi(lvAddUpdatePeerConfigData.SuppApp3);	
		}

		if( strcmp( lvAddUpdatePeerConfigData.SuppVend4, "") != 0) {
			lvPeerConfigData.uiSuppAppVendorId4 = atoi(lvAddUpdatePeerConfigData.SuppVend4);
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.SuppApp4, "") != 0) {
			lvPeerConfigData.uiSuppApp4 = atoi(lvAddUpdatePeerConfigData.SuppApp4);	
		}

		if( strcmp( lvAddUpdatePeerConfigData.SuppVend5, "") != 0) {
			lvPeerConfigData.uiSuppAppVendorId5 = atoi(lvAddUpdatePeerConfigData.SuppVend5);
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.SuppApp5, "") != 0) {
			lvPeerConfigData.uiSuppApp5 = atoi(lvAddUpdatePeerConfigData.SuppApp5);	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.sIsActive, "") != 0) {			
			lvPeerConfigData.isActive = atoi(lvAddUpdatePeerConfigData.sIsActive);
		}
		
		//-----------------------------------------08-apr-2018
		if( strcmp( lvAddUpdatePeerConfigData.AuthApp1, "") != 0) {
			lvPeerConfigData.uiAuthAppId1 = atoi(lvAddUpdatePeerConfigData.AuthApp1);	
		} else {
			lvPeerConfigData.uiAuthAppId1 = -1;	
		}

		if( strcmp( lvAddUpdatePeerConfigData.AuthApp2, "") != 0) {
			lvPeerConfigData.uiAuthAppId2 = atoi(lvAddUpdatePeerConfigData.AuthApp2);	
		} else {
			lvPeerConfigData.uiAuthAppId2 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.AuthApp3, "") != 0) {
			lvPeerConfigData.uiAuthAppId3 = atoi(lvAddUpdatePeerConfigData.AuthApp3);	
		} else {
			lvPeerConfigData.uiAuthAppId3 = -1;	
		}

		if( strcmp( lvAddUpdatePeerConfigData.AuthApp4, "") != 0) {
			lvPeerConfigData.uiAuthAppId4 = atoi(lvAddUpdatePeerConfigData.AuthApp4);	
		} else {
			lvPeerConfigData.uiAuthAppId4 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.AuthApp5, "") != 0) {
			lvPeerConfigData.uiAuthAppId5 = atoi(lvAddUpdatePeerConfigData.AuthApp5);	
		} else {
			lvPeerConfigData.uiAuthAppId5 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.AcctApp1, "") != 0) {
			lvPeerConfigData.uiAcctAppId1 = atoi(lvAddUpdatePeerConfigData.AcctApp1);	
		} else {
			lvPeerConfigData.uiAcctAppId1 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.AcctApp2, "") != 0) {
			lvPeerConfigData.uiAcctAppId2 = atoi(lvAddUpdatePeerConfigData.AcctApp2);	
		} else {
			lvPeerConfigData.uiAcctAppId2 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.AcctApp3, "") != 0) {
			lvPeerConfigData.uiAcctAppId3 = atoi(lvAddUpdatePeerConfigData.AcctApp3);	
		} else {
			lvPeerConfigData.uiAcctAppId3 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.AcctApp4, "") != 0) {
			lvPeerConfigData.uiAcctAppId4 = atoi(lvAddUpdatePeerConfigData.AcctApp4);	
		} else {
			lvPeerConfigData.uiAcctAppId4 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.AcctApp5, "") != 0) {
			lvPeerConfigData.uiAcctAppId5 = atoi(lvAddUpdatePeerConfigData.AcctApp5);	
		} else {
			lvPeerConfigData.uiAcctAppId5 = -1;	
		}
		
		if( strcmp( lvAddUpdatePeerConfigData.VendId1, "") != 0) {
			lvPeerConfigData.uiVendId1 = atoi(lvAddUpdatePeerConfigData.VendId1);	
		} else {
			lvPeerConfigData.uiVendId1 = -1;
		}

		if( strcmp( lvAddUpdatePeerConfigData.VendId2, "") != 0) {
			lvPeerConfigData.uiVendId2 = atoi(lvAddUpdatePeerConfigData.VendId2);	
		} else {
			lvPeerConfigData.uiVendId2 = -1;
		}

		if( strcmp( lvAddUpdatePeerConfigData.VendId3, "") != 0) {
			lvPeerConfigData.uiVendId3 = atoi(lvAddUpdatePeerConfigData.VendId3);	
		} else {
			lvPeerConfigData.uiVendId3 = -1;
		}

		if( strcmp( lvAddUpdatePeerConfigData.VendId4, "") != 0) {
			lvPeerConfigData.uiVendId4 = atoi(lvAddUpdatePeerConfigData.VendId4);	
		} else {
			lvPeerConfigData.uiVendId4 = -1;
		}

		if( strcmp( lvAddUpdatePeerConfigData.VendId5, "") != 0) {
			lvPeerConfigData.uiVendId5 = atoi(lvAddUpdatePeerConfigData.VendId5);
		} else {
			lvPeerConfigData.uiVendId5 = -1;
		}
		
		//-----------------------------------------08-apr-2018

		char fullFilePath[500];
		memset( &fullFilePath, 0, sizeof(fullFilePath)); 
		sprintf( fullFilePath, "./%s/%s", fileRootPath, (char *)"peerconfig.dat");

		FILE *fptr;

		if( access( fullFilePath, F_OK ) != -1 ) 
		{
			if( lvPeerConfigData.Id == 0)
			{	
				fptr = fopen( fullFilePath, "a+");
				
				fseek( fptr, 0, SEEK_END);
				int fileSize = ftell( fptr);
				
				lvPeerConfigData.Id = (fileSize/sizeof(iPeerConfigData)) + 1;
				fwrite( &lvPeerConfigData, sizeof(char), sizeof(iPeerConfigData), fptr);
			}	
			else
			{
				//update 
				int records = 0;
				fptr = fopen( fullFilePath, "rb+");
				
				iPeerConfigData recordInfo;
				memset( &recordInfo, 0, sizeof(iPeerConfigData));
				
				while( fread( &recordInfo, sizeof(iPeerConfigData), 1, fptr) == 1)
				{
					if(recordInfo.Id == lvPeerConfigData.Id)
					{
						fseek( fptr,  sizeof(iPeerConfigData)*records, SEEK_SET);
						fwrite( &lvPeerConfigData, sizeof(iPeerConfigData), 1, fptr);
					}
					records++;
				}
			}
			
			if( lvPeerConfigData.isActive == 1)
			{
				
			}
		}
		else
		{
			fptr = fopen( fullFilePath, "w+");			
			lvPeerConfigData.Id = 1;
			fwrite( &lvPeerConfigData, sizeof(char), sizeof(iPeerConfigData), fptr);
		}
		
		fclose(fptr);
		
		//printf("sending success\n");
		strcpy( sResponse, "{\"Error\":0, \"Message\" : \"Success\"}");
	}
	else
	{
		strcpy( sResponse, "{\"Error\":5000, \"Message\" : \"Invalid User\"}" );
	}
	
	sendWebSuccessResponse( cliInfo, sResponse);	
}

void handleWebAddUpdateHostConfigRequest( iWebClientInfo *cliInfo, char* request)
{
	if( strlen(cliInfo->PostData) < (sizeof(iAddUpdateHostConfigData)*2))
	{
		int iRemainingBytes = (sizeof(iAddUpdateHostConfigData)*2) - strlen(cliInfo->PostData);
		read( cliInfo->fd, &cliInfo->PostData[strlen(cliInfo->PostData)], iRemainingBytes);
	}
	
	iAddUpdateHostConfigData lvAddUpdateHostConfigData;
	memset( &lvAddUpdateHostConfigData, 0, sizeof(iAddUpdateHostConfigData));
	WebHexToBin( cliInfo->PostData, (char *)&lvAddUpdateHostConfigData, (sizeof(iAddUpdateHostConfigData)*2));

	
	printf("lvAddUpdateHostConfigData.sIndex=%s\n", lvAddUpdateHostConfigData.sIndex);
	printf("lvAddUpdateHostConfigData.sHostURI=%s\n", lvAddUpdateHostConfigData.sHostURI);
	printf("lvAddUpdateHostConfigData.sHostRealm=%s\n", lvAddUpdateHostConfigData.sHostRealm);
	printf("lvAddUpdateHostConfigData.sAcceptUnknownPeer=%s\n", lvAddUpdateHostConfigData.sAcceptUnknownPeer);
	printf("lvAddUpdateHostConfigData.sValidateSuppApp=%s\n", lvAddUpdateHostConfigData.sValidateSupportedApplications);
	printf("lvAddUpdateHostConfigData.SuppApp1=%s\n", lvAddUpdateHostConfigData.SuppApp1);
	printf("lvAddUpdateHostConfigData.SuppApp2=%s\n", lvAddUpdateHostConfigData.SuppApp2);
	printf("lvAddUpdateHostConfigData.SuppApp3=%s\n", lvAddUpdateHostConfigData.SuppApp3);
	printf("lvAddUpdateHostConfigData.SuppApp4=%s\n", lvAddUpdateHostConfigData.SuppApp4);
	printf("lvAddUpdateHostConfigData.SuppApp5=%s\n", lvAddUpdateHostConfigData.SuppApp5);
	printf("lvAddUpdateHostConfigData.SuppVen1=%s\n", lvAddUpdateHostConfigData.SuppVen1);
	printf("lvAddUpdateHostConfigData.SuppVen2=%s\n", lvAddUpdateHostConfigData.SuppVen2);
	printf("lvAddUpdateHostConfigData.SuppVen3=%s\n", lvAddUpdateHostConfigData.SuppVen3);
	printf("lvAddUpdateHostConfigData.SuppVen4=%s\n", lvAddUpdateHostConfigData.SuppVen4);
	printf("lvAddUpdateHostConfigData.SuppVen5=%s\n", lvAddUpdateHostConfigData.SuppVen5);
	printf("lvAddUpdateHostConfigData.sHostIP=%s\n", lvAddUpdateHostConfigData.sHostIP);
	printf("lvAddUpdateHostConfigData.sProdName=%s\n", lvAddUpdateHostConfigData.sProdName);
	printf("lvAddUpdateHostConfigData.sInbandSecurity=%s\n", lvAddUpdateHostConfigData.sInbandSecurity);
	printf("lvAddUpdateHostConfigData.AuthApp1=%s\n", lvAddUpdateHostConfigData.AuthApp1);
	printf("lvAddUpdateHostConfigData.AuthApp2=%s\n", lvAddUpdateHostConfigData.AuthApp2);
	printf("lvAddUpdateHostConfigData.AuthApp3=%s\n", lvAddUpdateHostConfigData.AuthApp3);
	printf("lvAddUpdateHostConfigData.AuthApp4=%s\n", lvAddUpdateHostConfigData.AuthApp4);
	printf("lvAddUpdateHostConfigData.AuthApp5=%s\n", lvAddUpdateHostConfigData.AuthApp5);
	printf("lvAddUpdateHostConfigData.AcctApp1=%s\n", lvAddUpdateHostConfigData.AcctApp1);
	printf("lvAddUpdateHostConfigData.AcctApp2=%s\n", lvAddUpdateHostConfigData.AcctApp2);
	printf("lvAddUpdateHostConfigData.AcctApp3=%s\n", lvAddUpdateHostConfigData.AcctApp3);
	printf("lvAddUpdateHostConfigData.AcctApp4=%s\n", lvAddUpdateHostConfigData.AcctApp4);
	printf("lvAddUpdateHostConfigData.AcctApp5=%s\n", lvAddUpdateHostConfigData.AcctApp5);
	printf("lvAddUpdateHostConfigData.VendId1=%s\n", lvAddUpdateHostConfigData.VendId1);
	printf("lvAddUpdateHostConfigData.VendId2=%s\n", lvAddUpdateHostConfigData.VendId2);
	printf("lvAddUpdateHostConfigData.VendId3=%s\n", lvAddUpdateHostConfigData.VendId3);
	printf("lvAddUpdateHostConfigData.VendId4=%s\n", lvAddUpdateHostConfigData.VendId4);
	printf("lvAddUpdateHostConfigData.VendId5=%s\n", lvAddUpdateHostConfigData.VendId5);
	printf("lvAddUpdateHostConfigData.sGUID=%s\n", lvAddUpdateHostConfigData.sGUID);
	/**/

	char sResponse[1024] = {0};
	
	if( IsWebValidAuthId( lvAddUpdateHostConfigData.sGUID) == 1)
	{
		iHostConfigData oHostConfigData;
		memset( &oHostConfigData, 0, sizeof(iHostConfigData));

		oHostConfigData.Id = 0;
		
		if( strcmp( lvAddUpdateHostConfigData.sIndex, "") != 0) {			
			oHostConfigData.Id = atoi(lvAddUpdateHostConfigData.sIndex);
		}
		
		strcpy( oHostConfigData.sHostURI, lvAddUpdateHostConfigData.sHostURI);
		strcpy( oHostConfigData.sHostRealm, lvAddUpdateHostConfigData.sHostRealm);
		strcpy( oHostConfigData.sHostIP, lvAddUpdateHostConfigData.sHostIP);
		strcpy( oHostConfigData.sProdName, lvAddUpdateHostConfigData.sProdName);
		oHostConfigData.iAcceptUnknownPeer = atoi(lvAddUpdateHostConfigData.sAcceptUnknownPeer);
		oHostConfigData.iValidateSuppApplications = atoi(lvAddUpdateHostConfigData.sValidateSupportedApplications);
		oHostConfigData.iInbSecurity = atoi(lvAddUpdateHostConfigData.sInbandSecurity);
		
		
		if( strcmp( lvAddUpdateHostConfigData.SuppApp1, "") != 0) {
			oHostConfigData.uiSuppApp1 = atoi(lvAddUpdateHostConfigData.SuppApp1);	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.SuppApp2, "") != 0) {
			oHostConfigData.uiSuppApp2 = atoi(lvAddUpdateHostConfigData.SuppApp2);	
		}

		if( strcmp( lvAddUpdateHostConfigData.SuppApp3, "") != 0) {
			oHostConfigData.uiSuppApp3 = atoi(lvAddUpdateHostConfigData.SuppApp3);	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.SuppApp4, "") != 0) {
			oHostConfigData.uiSuppApp4 = atoi(lvAddUpdateHostConfigData.SuppApp4);	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.SuppApp5, "") != 0) {
			oHostConfigData.uiSuppApp5 = atoi(lvAddUpdateHostConfigData.SuppApp5);	
		}

		if( strcmp( lvAddUpdateHostConfigData.SuppVen1, "") != 0) {
			oHostConfigData.uiSuppVen1 = atoi(lvAddUpdateHostConfigData.SuppVen1);	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.SuppVen2, "") != 0) {
			oHostConfigData.uiSuppVen2 = atoi(lvAddUpdateHostConfigData.SuppVen2);	
		}

		if( strcmp( lvAddUpdateHostConfigData.SuppVen3, "") != 0) {
			oHostConfigData.uiSuppVen3 = atoi(lvAddUpdateHostConfigData.SuppVen3);	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.SuppVen4, "") != 0) {
			oHostConfigData.uiSuppVen4 = atoi(lvAddUpdateHostConfigData.SuppVen4);	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.SuppVen5, "") != 0) {
			oHostConfigData.uiSuppVen5 = atoi(lvAddUpdateHostConfigData.SuppVen5);	
		}

		if( strcmp( lvAddUpdateHostConfigData.AuthApp1, "") != 0) {
			oHostConfigData.uiAuthAppId1 = atoi(lvAddUpdateHostConfigData.AuthApp1);	
		} else {
			oHostConfigData.uiAuthAppId1 = -1;	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.AuthApp2, "") != 0) {
			oHostConfigData.uiAuthAppId2 = atoi(lvAddUpdateHostConfigData.AuthApp2);	
		} else {
			oHostConfigData.uiAuthAppId2 = -1;	
		}		
		
		if( strcmp( lvAddUpdateHostConfigData.AuthApp3, "") != 0) {
			oHostConfigData.uiAuthAppId3 = atoi(lvAddUpdateHostConfigData.AuthApp3);	
		} else {
			oHostConfigData.uiAuthAppId3 = -1;	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.AuthApp4, "") != 0) {
			oHostConfigData.uiAuthAppId4 = atoi(lvAddUpdateHostConfigData.AuthApp4);	
		} else {
			oHostConfigData.uiAuthAppId4 = -1;	
		}		
		
		if( strcmp( lvAddUpdateHostConfigData.AuthApp5, "") != 0) {
			oHostConfigData.uiAuthAppId5 = atoi(lvAddUpdateHostConfigData.AuthApp5);	
		} else {
			oHostConfigData.uiAuthAppId5 = -1;	
		}

		if( strcmp( lvAddUpdateHostConfigData.AcctApp1, "") != 0) {
			oHostConfigData.uiAcctAppId1 = atoi(lvAddUpdateHostConfigData.AcctApp1);	
		} else {
			oHostConfigData.uiAcctAppId1 = -1;	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.AcctApp2, "") != 0) {
			oHostConfigData.uiAcctAppId2 = atoi(lvAddUpdateHostConfigData.AcctApp2);	
		} else {
			oHostConfigData.uiAcctAppId2 = -1;	
		}		
		
		if( strcmp( lvAddUpdateHostConfigData.AcctApp3, "") != 0) {
			oHostConfigData.uiAcctAppId3 = atoi(lvAddUpdateHostConfigData.AcctApp3);	
		} else {
			oHostConfigData.uiAcctAppId3 = -1;	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.AcctApp4, "") != 0) {
			oHostConfigData.uiAcctAppId4 = atoi(lvAddUpdateHostConfigData.AcctApp4);	
		} else {
			oHostConfigData.uiAcctAppId4 = -1;	
		}		
		
		if( strcmp( lvAddUpdateHostConfigData.AcctApp5, "") != 0) {
			oHostConfigData.uiAcctAppId5 = atoi(lvAddUpdateHostConfigData.AcctApp5);	
		} else {
			oHostConfigData.uiAcctAppId5 = -1;	
		}

		if( strcmp( lvAddUpdateHostConfigData.VendId1, "") != 0) {
			oHostConfigData.uiVendId1 = atoi(lvAddUpdateHostConfigData.VendId1);	
		} else {
			oHostConfigData.uiVendId1 = -1;	
		}

		if( strcmp( lvAddUpdateHostConfigData.VendId2, "") != 0) {
			oHostConfigData.uiVendId2 = atoi(lvAddUpdateHostConfigData.VendId2);	
		} else {
			oHostConfigData.uiVendId2 = -1;	
		}
		
		if( strcmp( lvAddUpdateHostConfigData.VendId3, "") != 0) {
			oHostConfigData.uiVendId3 = atoi(lvAddUpdateHostConfigData.VendId3);	
		} else {
			oHostConfigData.uiVendId3 = -1;	
		}

		if( strcmp( lvAddUpdateHostConfigData.VendId4, "") != 0) {
			oHostConfigData.uiVendId4 = atoi(lvAddUpdateHostConfigData.VendId4);	
		} else {
			oHostConfigData.uiVendId4 = -1;	
		}

		if( strcmp( lvAddUpdateHostConfigData.VendId5, "") != 0) {
			oHostConfigData.uiVendId5 = atoi(lvAddUpdateHostConfigData.VendId5);	
		} else {
			oHostConfigData.uiVendId5 = -1;	
		}
		
		char fullFilePath[500];
		memset( &fullFilePath, 0, sizeof(fullFilePath)); 
		sprintf( fullFilePath, "./%s/%s", fileRootPath, (char *)"hostconfig.dat");

		FILE *fptr;
		
		if( access( fullFilePath, F_OK ) != -1 ) 
		{
			//printf("file found path=%s\n", fullFilePath);	
			
			//add
			if( oHostConfigData.Id == 0)
			{	
				fptr = fopen( fullFilePath, "a+");
				
				fseek( fptr, 0, SEEK_END);
				int fileSize = ftell( fptr);
				
				oHostConfigData.Id = (fileSize/sizeof(iHostConfigData)) + 1;
				fwrite( &oHostConfigData, sizeof(char), sizeof(iHostConfigData), fptr);
			}	
			else
			{
				//update 
				int records = 0;
				fptr = fopen( fullFilePath, "rb+");
				
				iHostConfigData recordInfo;
				memset( &recordInfo, 0, sizeof(iHostConfigData));
				
				while( fread( &recordInfo, sizeof(iHostConfigData), 1, fptr) == 1)
				{
					if(recordInfo.Id == oHostConfigData.Id)
					{
						fseek( fptr,  sizeof(iHostConfigData)*records, SEEK_SET);
						fwrite( &oHostConfigData, sizeof(iHostConfigData), 1, fptr);
					}
					records++;
				}
			}
		}
		else
		{
			fptr = fopen( fullFilePath, "w+");			
			oHostConfigData.Id = 1;
			fwrite( &oHostConfigData, sizeof(char), sizeof(iHostConfigData), fptr);
		}
		
		fclose(fptr);
		
		strcpy( sResponse, "{\"Error\":0, \"Message\" : \"Success\"}");		
	}
	else
	{
		strcpy( sResponse, "{\"Error\":5001, \"Message\" : \"Invalid User\"}" );
		printf("Invalid User\n");
	}
	
	sendWebSuccessResponse( cliInfo, sResponse);
}

void handleWebStartHostConfigRequest( iWebClientInfo *cliInfo, char* request)
{
	iStartHostConfig lvStartHostConfig;
	memset( &lvStartHostConfig, 0, sizeof(iStartHostConfig));
	WebHexToBin( cliInfo->PostData, (char *)&lvStartHostConfig, (sizeof(iStartHostConfig)*2));
	
	printf(	"StartHost:AuthId:%s, HostEntry:%d,\n", lvStartHostConfig.sGUID, atoi( lvStartHostConfig.HostEntry));
	
	char sResponse[1024] = {0};
	
	if( IsWebValidAuthId( lvStartHostConfig.sGUID) == 1)
	{
		char fullFilePath[500];
		memset( &fullFilePath, 0, sizeof(fullFilePath)); 
		sprintf( fullFilePath, "./%s/%s", fileRootPath, (char *)"hostconfig.dat");

		if( access( fullFilePath, F_OK ) != -1 ) 
		{
			int iHostEntryId = atoi( lvStartHostConfig.HostEntry);
			
			FILE *fptr;
			iHostConfigData oHostConfigData;
			memset( &oHostConfigData, 0, sizeof(iHostConfigData));
			
			int bFound = 0;
			int records = 0;
			//int nread = 0;
			//fptr = fopen( fullFilePath, "r");
			fptr = fopen( fullFilePath, "rb+");

			while(fptr)
			{
				//nread = fread( &oHostConfigData, sizeof(char), sizeof(iHostConfigData), fptr);
				//nread = 
				fread( &oHostConfigData, sizeof(iHostConfigData), 1, fptr);
				
				if(oHostConfigData.Id == iHostEntryId)
				{
					if( oHostConfigData.iStarted == 1)
						oHostConfigData.iStarted = 0;
					else
						oHostConfigData.iStarted = 1;	
					
					fseek( fptr,  sizeof(iHostConfigData)*records, SEEK_SET);
					fwrite( &oHostConfigData, sizeof(iHostConfigData), 1, fptr);
					bFound = 1;
					break;
				}
				records++;
			}
			
			fclose(fptr);
			
			if( bFound == 0)
			{
				strcpy( sResponse, "{\"Error\":5102, \"Message\" : \"Entry Not Found\"}");
			}
			else
			{
				int ires = 0;
				ires = parseAndstartHostServer( &oHostConfigData);
				
				if( ires <= 0)
				{
					strcpy( sResponse, "{\"Error\":5015, \"Message\" : \"Error, Unable to Start\"}");
				}
				else
				{
					if( ires == 1010)
					{
						//strcpy( sResponse, "{\"Error\":0, \"Message\" : \"Already Started\"}");
						strcpy( sResponse, "{\"Error\":0, \"Message\" : \"Success .... 1010\"}");
					}
					else
					{
						strcpy( sResponse, "{\"Error\":0, \"Message\" : \"Success\"}");
					}
				}	
			}
		}
		else
		{
			strcpy( sResponse, "{\"Error\":5101, \"Message\" : \"Host Config File Not Found.\"}");
		}
	}
	else
	{
		strcpy( sResponse, "{\"Error\":5001, \"Message\" : \"Invalid User\"}" );
	}
	sendWebSuccessResponse( cliInfo, sResponse);
}

void handleWebGetAllPeerConfigRequest( iWebClientInfo *cliInfo, char* request)
{
	iWebAuthData lvAuthData;
	memset( &lvAuthData, 0, sizeof(iWebAuthData));
	WebHexToBin( cliInfo->PostData, (char *)&lvAuthData, (sizeof(iWebAuthData)*2));	

	char sResponse[20480] = {0};
	
	if(IsWebValidAuthId( lvAuthData.sGUID) == 1)
	{
		char fullFilePath[500];
		memset( &fullFilePath, 0, sizeof(fullFilePath)); 
		sprintf( fullFilePath, "./%s/%s", fileRootPath, (char *)"peerconfig.dat");

		if( access( fullFilePath, F_OK ) != -1 ) 
		{
			FILE *fptr;
			iPeerConfigData oPeerConfigData;
			memset( &oPeerConfigData, 0, sizeof(iPeerConfigData));

			fptr = fopen( fullFilePath, "r");
			
			int nread = 0;
			int msgLength0 = 0;
			addWebJsonData( &sResponse[msgLength0], (char *)"{\"Error\":0,\"Peers\":[", &msgLength0);
			
			int iAdded = 0;

			while(fptr)
			{
				nread = fread( &oPeerConfigData, sizeof(char), sizeof(iPeerConfigData), fptr);
				
				if( nread == 0)
					break;
				
				if(oPeerConfigData.isDeleted == 0)
				{
					if( iAdded > 0)
					{
						addWebJsonData( &sResponse[msgLength0], (char *)",", &msgLength0);
					}
					
					char ival[11];
					memset( ival, 0, sizeof(ival));

					addWebJsonData( &sResponse[msgLength0], (char *)"{", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"Id\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.Id);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"PeerURI\":\"", &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)oPeerConfigData.sPeerURI, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"PeerRealm\":\"", &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)oPeerConfigData.sPeerRealm, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"PeerIP\":\"", &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)oPeerConfigData.sIPAddress, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"IsActive\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.isActive);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen1\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppAppVendorId1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp1\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppApp1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					//1-----
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen2\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppAppVendorId2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp2\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppApp2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					//2-----
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen3\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppAppVendorId3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp3\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppApp3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					//3-----
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen4\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppAppVendorId4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp4\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppApp4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					//4-----
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen5\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppAppVendorId5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp5\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.uiSuppApp5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					//5-----
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"HostEntryId\":\"", &msgLength0);
					sprintf( ival, "%u", oPeerConfigData.HostEntryId);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId1\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAuthAppId1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId2\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAuthAppId2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId3\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAuthAppId3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId4\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAuthAppId4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId5\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAuthAppId5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId1\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAcctAppId1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId2\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAcctAppId2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId3\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAcctAppId3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId4\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAcctAppId4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId5\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiAcctAppId5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);


					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId1\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiVendId1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId2\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiVendId2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId3\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiVendId3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId4\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiVendId4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId5\":\"", &msgLength0);
					sprintf( ival, "%d", oPeerConfigData.uiVendId5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\"", &msgLength0);
					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"}", &msgLength0);
					
					iAdded++;
				}
			}	

			addWebJsonData( &sResponse[msgLength0], (char *)"]}", &msgLength0);
			fclose(fptr);			
		}
		else
		{
			strcpy( sResponse, "{\"Error\":0,\"Peers\":[]}");
		}
	}	
	else
	{
		strcpy( sResponse, "{\"Error\":5001, \"Message\" : \"Invalid User\"}" );
	}
	
	printf("%s\n", sResponse);
	
	sendWebSuccessResponse( cliInfo, sResponse);	
}



void handleWebGetAllHostConfigRequest( iWebClientInfo *cliInfo, char* request)
{
	iWebAuthData lvAuthData;
	memset( &lvAuthData, 0, sizeof(iWebAuthData));
	WebHexToBin( cliInfo->PostData, (char *)&lvAuthData, (sizeof(iWebAuthData)*2));	
	
	//printf(	"AuthId:%s\n", lvAuthData.sGUID);
	char sResponse[20480] = {0};
	
	if(IsWebValidAuthId( lvAuthData.sGUID) == 1)
	{
		char fullFilePath[500];
		memset( &fullFilePath, 0, sizeof(fullFilePath)); 
		sprintf( fullFilePath, "./%s/%s", fileRootPath, (char *)"hostconfig.dat");

		if( access( fullFilePath, F_OK ) != -1 ) 
		{
			FILE *fptr;
			iHostConfigData oHostConfigData;
			memset( &oHostConfigData, 0, sizeof(iHostConfigData));

			fptr = fopen( fullFilePath, "r");
			
			int nread = 0;
			int msgLength0 = 0;
			addWebJsonData( &sResponse[msgLength0], (char *)"{\"Error\":0,\"Hosts\":[", &msgLength0);
			
			int iAdded = 0;
			
			while(fptr)
			{
				nread = fread( &oHostConfigData, sizeof(char), sizeof(iHostConfigData), fptr);
				
				if( nread == 0)
					break;
				
				if(oHostConfigData.isDeleted == 0)
				{
					if( iAdded > 0)
					{
						addWebJsonData( &sResponse[msgLength0], (char *)",", &msgLength0);
					}
					
					char ival[11];
					memset( ival, 0, sizeof(ival));
					
					addWebJsonData( &sResponse[msgLength0], (char *)"{", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"Id\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.Id);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"HostURI\":\"", &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)oHostConfigData.sHostURI, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"HostRealm\":\"", &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)oHostConfigData.sHostRealm, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"HostIP\":\"", &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)oHostConfigData.sHostIP, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"ProdName\":\"", &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)oHostConfigData.sProdName, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"AcceptUnknownPeer\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.iAcceptUnknownPeer);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"ValidateSuppApp\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.iValidateSuppApplications);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"InbSecurity\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.iInbSecurity);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"IsStarted\":\"", &msgLength0);
					
					if( oHostConfigData.iStarted == 0 && getSctpHostFileDescriptorValue(oHostConfigData.Id ) > 0)
					{
						sprintf( ival, "%d", 2);
					}
					else
					{
						sprintf( ival, "%d", oHostConfigData.iStarted);
					}
					
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp1\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppApp1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp2\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppApp2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp3\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppApp3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp4\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppApp4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppApp5\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppApp5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen1\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppVen1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen2\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppVen2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen3\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppVen3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen4\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppVen4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"SuppVen5\":\"", &msgLength0);
					sprintf( ival, "%u", oHostConfigData.uiSuppVen5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId1\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAuthAppId1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId2\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAuthAppId2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId3\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAuthAppId3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId4\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAuthAppId4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAuthAppId5\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAuthAppId5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId1\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAcctAppId1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId2\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAcctAppId2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId3\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAcctAppId3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId4\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAcctAppId4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiAcctAppId5\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiAcctAppId5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);


					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId1\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiVendId1);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId2\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiVendId2);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);

					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId3\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiVendId3);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId4\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiVendId4);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\",", &msgLength0);					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"\"uiVendId5\":\"", &msgLength0);
					sprintf( ival, "%d", oHostConfigData.uiVendId5);
					addWebJsonData( &sResponse[msgLength0], (char *)ival, &msgLength0);
					addWebJsonData( &sResponse[msgLength0], (char *)"\"", &msgLength0);
					
					
					
					addWebJsonData( &sResponse[msgLength0], (char *)"}", &msgLength0);
					
					iAdded++;
				}
			}
			
			addWebJsonData( &sResponse[msgLength0], (char *)"]}", &msgLength0);
			fclose(fptr);			
		}
		else
		{
			strcpy( sResponse, "{\"Error\":0,\"Hosts\":[]}");
		}			
	}
	else
	{
		strcpy( sResponse, "{\"Error\":5001, \"Message\" : \"Invalid User\"}" );
	}
	
	sendWebSuccessResponse( cliInfo, sResponse);	
}

void handleWebRequest( iWebClientInfo *cliInfo, char* request, char *requestType, char *requestPath)
{
	int iBufLength = 0;
	
	if( strcmp( requestPath, "/") == 0)
	{
		char buf[CHUNK];	
		memset( buf, 0, sizeof(buf));	
		getWebFileBuffer( (char *)"index.html", (char *)&buf, &iBufLength);
		
		sendWebResponse( cliInfo, (char *)&buf, (char *)"Content-Type: text/html", iBufLength);
	}	
	else
	{
		if( strcmp( requestType, "GET") == 0)
		{
			char fullFilePath[500];
			memset( &fullFilePath, 0, sizeof(fullFilePath));
			sprintf( fullFilePath, "./%s/%s", fileRootPath, requestPath);
			
			if( access( fullFilePath, F_OK ) != -1 ) 
			{
				char buf[CHUNK];	
				memset( buf, 0, sizeof(buf));	
				getWebFileBuffer( (char *)requestPath, (char *)&buf, &iBufLength);
				
				char *ext = (char *)get_filename_ext( requestPath);
				char contentType[100];
				memset( &contentType, 0, sizeof(contentType));
				
				if( strcmp(  ext, "js") == 0 )
				{
					strcpy( (char *)&contentType, (char *)"Content-Type: text/html");
				}
				else if( strcmp(  ext, "png") == 0 )
				{
					strcpy( (char *)&contentType, (char *)"Content-Type: image/png");
				}
				else if( strcmp(  ext, "html") == 0 )
				{
					strcpy( (char *)&contentType, (char *)"Content-Type: text/html");
				}				
				
				sendWebResponse( cliInfo, (char *)&buf, (char *)&contentType, iBufLength);
			} 
			else 
			{
				handleWebInvalidRequest( cliInfo, request);
			}
		}			
		else if( strcmp( requestType, "POST") == 0)
		{
			char *ext = (char *)get_filename_ext( requestPath);
			
			if( strcmp("/login.json", requestPath) == 0)
			{
				CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "handle Login Request Data[%s]", cliInfo->PostData);	
				handleWebLoginRequest( cliInfo, request);
			}
			else if( strcmp("/addupdatehostconfig.json", requestPath) == 0)
			{
				CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "handle add update host config Request Data[%s]", cliInfo->PostData);
				handleWebAddUpdateHostConfigRequest( cliInfo, request);
			}
			else if( strcmp("/getallhostconfig.json", requestPath) == 0)
			{
				CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "handle get all host config Request Data[%s]", cliInfo->PostData);	
				handleWebGetAllHostConfigRequest( cliInfo, request);
			}
			else if( strcmp("/starthostconfig.json", requestPath) == 0)
			{
				CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "handle start host config Request Data[%s]", cliInfo->PostData);
				handleWebStartHostConfigRequest( cliInfo, request);
			}
			else if( strcmp("/addupdatepeerserverconfig.json", requestPath) == 0)
			{
				CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "handle add/update peer config Request Data[%s]", cliInfo->PostData);
				printf("handle add/update peer config Request Data[%s]", cliInfo->PostData);
				handleWebAddUpdatePeerConfigRequest( cliInfo, request);
			}
			else if( strcmp("/getallpeersconfig.json", requestPath) == 0)
			{
				CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "handle get all peers config Request Data[%s]", cliInfo->PostData);
				printf("handle get all peers config Request Data[%s]\n", cliInfo->PostData);
				handleWebGetAllPeerConfigRequest( cliInfo, request);
			}			
			else 
			{
				printf("POST Request Not Implemented. requestPath=[%s] ext=[%s]" , requestPath, ext);	
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "POST Request Not Implemented. requestPath=[%s] ext=[%s]" , requestPath, ext);	
				handleWebInvalidRequest( cliInfo, request);
			}
		}
	}
}



void coreParseWebRequest( iWebClientInfo *cliInfo, char* request)
{
	int i = 0;
	int iMax = 0;
    char *p = strtok ( request, "\r\n");
    char *array[15];
	
	while (p != NULL)
    {
        array[i++] = p;
        p = strtok ( NULL, "\r\n");
    }

	iMax = i;
	
	if( iMax > 0)
	{	
		char requestType[10];
		char requestPath[500];
		memset( &requestType, 0 , sizeof(requestType));
		memset( &requestPath, 0 , sizeof(requestPath));
		
		char *p1 = strtok ( array[0], " ");
		int i1 = 0;
		
		while (p1 != NULL)
		{
			if( i1 == 0)
				strcpy( requestType, p1);
			else if(i1 == 1)
				strcpy( requestPath, p1);
			else
				break;
			
			p1 = strtok ( NULL, " ");
			i1++;
		}
		
		memcpy( &cliInfo->PostData, array[iMax-1], strlen(array[iMax-1]));
		handleWebRequest( cliInfo, request, requestType, requestPath);
	}
	else
	{	
		handleWebInvalidRequest( cliInfo, request);
	}	
}

//10007
void WebRequestProcessFunction( void * args)
{
	iWebClientInfo * cliInfo = (iWebClientInfo *) args;
	
	//ssize_t readed;
	char buffer[2048];
	memset( &buffer, 0 , sizeof(buffer));
	//readed = 
	read( cliInfo->fd, &buffer, 2048);
	
	coreParseWebRequest( cliInfo, buffer);
	releaseWebClientInfo( cliInfo);
}

//10003
void startWebConsole( int iWebPort)
{
	fileRootPath = (char*) malloc( sizeof(char)*100);
	memset( fileRootPath, 0, sizeof(char)*100);
	strcpy( fileRootPath, "files");
	
	oApplicationServer = (iApplicationServer *) malloc(sizeof(iApplicationServer));
	memset( oApplicationServer, '\0', sizeof(iApplicationServer));
	oApplicationServer->SessionCount = 0;
	oApplicationServer->StartedHostsCount = 0;
	oApplicationServer->PeerServerCount = 0;
	oApplicationServer->WebPort = iWebPort;
	//oApplicationServer->iCatLog = core_AddLogCat( (char *)"CORE_WEBCONSOLE", 1);
	
	/* SCTP */
	pthread_mutex_init( &oApplicationServer->SocketReadThreadLock, NULL);
	oApplicationServer->SocketReadThreadCount = 0;
	
	/* TCP */
	pthread_mutex_init( &oApplicationServer->TCPSocketReadThreadLock, NULL);
	oApplicationServer->TCPSocketReadThreadCount = 0;	
	
	
	init_iMessagePool( &oApplicationServer->WebClientInfoPool);
	
	
	if( iWebPort <= 0)
	{
		printf("not starting web-console, port is less than or zero. port : %d  \n", iWebPort);
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "not starting web-console, port is less than or zero. port : %d", iWebPort);
		return;
	}
	
	
	printf("starting web-console on port=%d\n", iWebPort);
	CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "starting web-console on port=%d", iWebPort);

	
	QueuePool_CreateWithNThreads( &oApplicationServer->WebRequestQueue, WebRequestProcessFunction, 1);
	
	int iRet;
	pthread_t s_pthread_id;

	pthread_attr_t attr;
	pthread_attr_init( &attr);
	pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);
	
	iRet = pthread_create( &s_pthread_id, &attr, webServerThread, NULL);
	
	if(iRet)
	{
		perror("Error: ");
		printf("unable to create Thread for Web Server \n");
		exit(-1);
	}
	else
	{
		printf("started web-console on port=%d\n", iWebPort);
	}
	
	printf("------------------------------------------------------------------\n");
}

// Web Console
//===========================================================================================================================

//10004
void coreStartConfiguredHost()
{
	char fullFilePath[500];
	memset( &fullFilePath, 0, sizeof(fullFilePath)); 
	sprintf( fullFilePath, "./%s/%s", fileRootPath, (char *)"hostconfig.dat");
	int nread = 0;
		
	if( access( fullFilePath, F_OK ) != -1 ) 
	{
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Configuration File Found for Host-Server %s, Initializing it", fullFilePath);
		
		FILE *fptr;
		iHostConfigData oHostConfigData;
		memset( &oHostConfigData, 0, sizeof(iHostConfigData));
		
		fptr = fopen( fullFilePath, "r");
			
		while(fptr)
		{
			nread = fread( &oHostConfigData, sizeof(char), sizeof(iHostConfigData), fptr);
			
			if( nread == 0)
				break;
			
			if(oHostConfigData.isDeleted == 0 )
			{
				if( oHostConfigData.iStarted == 1)
				{	
					parseAndstartHostServer( &oHostConfigData);
				}
				else
				{
					parseAndSetHostName( &oHostConfigData);
				}
			}
		}
			
		fclose(fptr);
	}
	else
	{
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Configuration File NOT Found for Host-Server %s", fullFilePath);
	}
}

void coreTcpClient_connectToPeer( iPeerConfigData * oPeerConfigData, int *bConnected, int *ifd)
{
	*bConnected = 0;
	int ipType = 1;
	
	int fd = 0, ret = 0;
	
	if( ipType == 1)
	{
		if ((fd = socket( AF_INET, SOCK_STREAM, 0)) == -1) 
		{
			printf("ipv4 socket creation failed for tcp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "ipv4 socket creation failed for tcp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
		}
	}
	else
	{
		if ((fd = socket( AF_INET6, SOCK_STREAM, 0)) == -1) 
		{
			printf("ipv6 socket creation failed for tcp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "ipv6 socket creation failed for tcp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
		}		
	}	
	
	if( fd > 0)
	{
		if( ipType == 1)
		{	
			struct sockaddr_in addr;
			addr.sin_family = AF_INET;
			addr.sin_addr.s_addr = inet_addr( oPeerConfigData->sIPAddress);
			addr.sin_port = htons( oPeerConfigData->iPortNo);

			if ( connect( fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1) 
			{
				printf("connection to tcp peer-server failed for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
			}
			else
			{
				*bConnected = 1;
				*ifd = fd;
			}
		}	
	}

}




void createWatchDogRequest2(struct DiamMessage * dmCER, iPeerConfigData * oPeerConfigData);

//10015
void * coreAppServerStartTcpPeerConnection( void * args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	iPeerConfigData * oPeerConfigData = (iPeerConfigData *)args;
	oPeerConfigData->iStarted = 1;
	
	printf("TCP PeerConfig Id=%d sIPAddress[%s] iPortNo[%d] sPeerName[%s] sPeerRealm[%s]\n", 
		oPeerConfigData->Id, oPeerConfigData->sIPAddress, oPeerConfigData->iPortNo, oPeerConfigData->sPeerName, oPeerConfigData->sPeerRealm);
	
	long int iRequestNo = 0;
	int bSuccess = 0;
	int iWaitTemp = 0;
	int iHostConfigSts = 0;
	struct DiamMessage * dmCER = NULL;
	struct DiamRawData *oDiamRawData = NULL;
	struct pollfd fds;
	int n = 0, ret;
	char buf[5000];
	memset( &buf, 0, sizeof(buf));

	iSctpStreamBuffer lvStreamBuffer;
	memset( &lvStreamBuffer, 0, sizeof(iSctpStreamBuffer));
	
	char totbuf[10000];
	int iTotalBufferLength = 0;
	int PendingBufferLength = 0;
	int iUsedBufferSize = 0;
	unsigned int iMessageLength;	
	
	
	while(1)
	{
		if( oPeerConfigData->isActive == 0)
		{
			usleep(999999);
			continue;
		}
		
		while(oPeerConfigData->iConnected == 0 && oPeerConfigData->DoNotConnect == 0)
		{
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "trying to connect again to peer-id:%d", oPeerConfigData->Id);
			coreTcpClient_connectToPeer( oPeerConfigData, &oPeerConfigData->iConnected, &oPeerConfigData->iFd);
			
			if( oPeerConfigData->iConnected == 1)
			{	
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "tcp connecting to peer successful peer-id:%d", oPeerConfigData->Id);
				break;
			}
			
			for( iWaitTemp = 0; iWaitTemp < objStackConfig.ReConnectSeconds; iWaitTemp++)
			{
				usleep(999999);
			}			
		}
		
		if( oPeerConfigData->iConnected == 1)
		{
			dmCER = allocateMessage();
			iHostConfigSts = createCER2( dmCER, oPeerConfigData);

			if( iHostConfigSts == 0)
			{
				releaseMessage( dmCER);
				closeAndCleanClientPeerConfigSocket( oPeerConfigData);
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Please Configure Host Configuration and Restart peer-id:%d", oPeerConfigData->Id);
				oPeerConfigData->DoNotConnect = 1;
				continue;
			}
			else
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", oPeerConfigData->Id, oPeerConfigData->iFd, oPeerConfigData->sIPAddress, oPeerConfigData->iPortNo);

				//Send to TCP
				bSuccess = appSendMsg( &oPeerConfigData->iFd, dmCER);

				if( bSuccess < 0 && errno == EPIPE)
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", oPeerConfigData->Id, oPeerConfigData->iFd);
					closeAndCleanClientPeerConfigSocket( oPeerConfigData);
				}				
			}
		}
		
		oPeerConfigData->iIdleTime = 0;
		oPeerConfigData->iDWRCount = 0;
		fds.fd     = oPeerConfigData->iFd;
		fds.events = POLLIN;		
		
		memset( &lvStreamBuffer, 0, sizeof(iSctpStreamBuffer));
		
		while( oPeerConfigData->iConnected == 1)
		{
			ret = poll( &fds, 1, 1000);
			
			if( ret == 0)
			{
				oPeerConfigData->iIdleTime += 1;
				
				if( oPeerConfigData->iIdleTime >= objStackConfig.WatchDogRequestInterval )
				{
					if( oPeerConfigData->isCERSuccess == 0)
					{
						dmCER = allocateMessage();
						createCER2( dmCER, oPeerConfigData);

						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", oPeerConfigData->Id, oPeerConfigData->iFd, oPeerConfigData->sIPAddress, oPeerConfigData->iPortNo);

						bSuccess = appSendMsg( &oPeerConfigData->iFd, dmCER);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", oPeerConfigData->Id, oPeerConfigData->iFd);
							closeAndCleanClientPeerConfigSocket( oPeerConfigData);
							break;
						}						
					}
					else
					{
						//printf("Init Diam WatchDog Request From PEER \n");
						dmCER = allocateMessage();
						createWatchDogRequest2( dmCER, oPeerConfigData);
						
						bSuccess = appSendMsg( &oPeerConfigData->iFd, dmCER);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", oPeerConfigData->Id, oPeerConfigData->iFd);
							closeAndCleanClientPeerConfigSocket( oPeerConfigData);
							break;
						}
						
						oPeerConfigData->iDWRCount++;
					}
					
					oPeerConfigData->iIdleTime = 0;
				}
				
				continue;
			}
			
			if( ret < 0)
			{
				closeAndCleanClientPeerConfigSocket( oPeerConfigData);
				break;
			}

			if( ret > 0)
			{
				n = recv( oPeerConfigData->iFd, buf, sizeof(buf), 0 );
				
				if( n > 0)
				{
					CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "Received Bytes from Peer Connection %d", n);
					
					if( lvStreamBuffer.PendingBufferLength > 0)
					{
						PendingBufferLength = lvStreamBuffer.PendingBufferLength;
						memcpy( totbuf, lvStreamBuffer.sBuffer, PendingBufferLength);
						memcpy( &totbuf[PendingBufferLength], buf, n);
						iTotalBufferLength = PendingBufferLength + n;
						lvStreamBuffer.PendingBufferLength = 0;
					}
					else
					{
						memcpy( totbuf, buf, n);
						iTotalBufferLength = n;
					}

					iUsedBufferSize = 0;
					while( iUsedBufferSize < iTotalBufferLength)
					{
						if( ( iTotalBufferLength - iUsedBufferSize) > DIAM_BUFFER_SIZE_HEADER_SIZE)
						{
							oDiamRawData = allocateDiamRawData();
							oDiamRawData->Header->len = DIAM_BUFFER_SIZE_HEADER_SIZE;
							memcpy( oDiamRawData->Header->Data, &totbuf[iUsedBufferSize], DIAM_BUFFER_SIZE_HEADER_SIZE);
							decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);								
							
							if( ( iTotalBufferLength - iUsedBufferSize) >= iMessageLength )
							{
								CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "iMessageLength = %d sufficient body message", iMessageLength);
								memcpy( oDiamRawData->PayLoad->Data, &totbuf[iUsedBufferSize + DIAM_BUFFER_SIZE_HEADER_SIZE], (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE));

								oDiamRawData->iPeerIndex = -1;
								oDiamRawData->iRequestNo = iRequestNo;
								oDiamRawData->iMessageArrivedFrom = 10;
								oDiamRawData->iRouteMessageTo = 2;	
								oDiamRawData->PayLoad->len = (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE);
								oDiamRawData->PeerConfigData = oPeerConfigData;
								
								objStackObjects.TotalMemoryUsage.SocketReadCount++;
								appPostMsg( oDiamRawData);
																	
								oPeerConfigData->iResponseNo++;
								iRequestNo++;
								iUsedBufferSize += iMessageLength;									
							}
							else
							{
								releaseDiamRawData( oDiamRawData);

								CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
								lvStreamBuffer.PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
								memcpy( lvStreamBuffer.sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
								break;									
							}							
							
						}
						else
						{
							CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
							lvStreamBuffer.PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
							memcpy( lvStreamBuffer.sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
							break;							
						}
					}
					
					CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "while exited peer thread iUsedBufferSize[%d] , iTotalBufferLength[%d]\n", iUsedBufferSize, iTotalBufferLength);
				}
				else
				{
					closeAndCleanClientPeerConfigSocket( oPeerConfigData);
					break;
				}
			}
		}			
		
		
		usleep(999999);
	}
	
	return NULL;
}



//10016
void coreSctpClient_connectToPeer( iPeerConfigData * oPeerConfigData, int *bConnected, int *ifd)
{
	#if SCTP_SUPPORT
	
	*bConnected = 0;
	int ipType = 1;

	int fd = 0, ret = 0;
	struct sctp_initmsg   initmsg;
    struct sctp_event_subscribe events;	
	
	if( ipType == 1)
	{
		if ((fd = socket( AF_INET, SOCK_STREAM, IPPROTO_SCTP)) == -1) 
		{
			printf("ipv4 socket creation failed for sctp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "ipv4 socket creation failed for sctp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
			return;
		}
	}
	else
	{
		if ((fd = socket( AF_INET6, SOCK_STREAM, IPPROTO_SCTP)) == -1) 
		{
			printf("ipv6 socket creation failed for sctp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "ipv6 socket creation failed for sctp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
			return;
		}		
	}

	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "socket creation for sctp peer-connection for Id=%d Uri[%s] with fd[%d]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI, fd);
	
	events.sctp_data_io_event = 1;
	events.sctp_association_event = 1;
	events.sctp_send_failure_event = 1;
	events.sctp_address_event = 1;
	events.sctp_peer_error_event = 1;
	events.sctp_shutdown_event = 1;	
	ret = setsockopt( fd, IPPROTO_SCTP, SCTP_EVENTS, &events, sizeof (events));
	
	if (ret < 0) 
	{
		printf("set socket options SCTP_EVENTS failed for sctp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
		return;
	}	
	
	memset(&initmsg, 0, sizeof(struct sctp_initmsg));
	initmsg.sinit_num_ostreams = 5;
	initmsg.sinit_max_instreams = 5;
	initmsg.sinit_max_attempts = 4;
	ret = setsockopt( fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(struct sctp_initmsg));

	if (ret < 0) 
	{
		printf("set socket options SCTP_INITMSG failed for sctp peer-connection for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
		return;
	}

	if( ipType == 1)
	{	
		struct sockaddr_in addr;
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr( oPeerConfigData->sIPAddress);
		addr.sin_port = htons( oPeerConfigData->iPortNo);

		if ( connect( fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1) 
		{
			printf("connection to sctp peer-server failed for Id=%d Uri[%s]\n", oPeerConfigData->Id, oPeerConfigData->sPeerURI);
		}
		else
		{
			*bConnected = 1;
			*ifd = fd;
		}
	}	
	else
	{
		//, struct sockaddr_in6 *addr_in6 [FROM FUNCTION PARAM]
		//addr_in6->sin6_port = htons( oPeerConfigData->iPortNo);
		
		/*
		if ( connect( fd, (struct sockaddr *)addr_in6, sizeof (struct sockaddr_in6)) == -1) 
		{
			perror("connect ipv6 ");
			printf("errno=%d\n", errno);
			//break;
		}
		else
		{
			*bConnected = 1;
			oHostConfig->fd = fd;
			printf("connected successful on IPv6:%s\n", s);
		}		
		*/		
	}
	
	#endif
}

int createCER2( struct DiamMessage * dmCER, iPeerConfigData * oPeerConfigData)
{
	if( oApplicationServer->StartedHostsCount > 0)
	{
		int iHostInfo = (oPeerConfigData->HostEntryId-1);
		if( iHostInfo > oApplicationServer->StartedHostsCount) {
			iHostInfo = 0;
		}
		printf("Sending CER => Initialized Host Configuration Info [%d] selected host-entry[%d] configured[%d] PeerConfigData[%p] [%ld]\n", 
			oApplicationServer->StartedHostsCount, iHostInfo, (oPeerConfigData->HostEntryId-1), oPeerConfigData, pthread_self());
		
		dmCER->Flags.Request = 1;
		initDiamRequest( dmCER, 0, 257, 0);

		dmCER->AvpCount = 0;

		addOriginHostAVP( dmCER, (char*)oApplicationServer->StartedHosts[iHostInfo].sHostName, 0, 1, strlen(oApplicationServer->StartedHosts[iHostInfo].sHostName));
		addOriginRealmAVP( dmCER, (char*)oApplicationServer->StartedHosts[iHostInfo].sHostRealm, 0, 1, strlen(oApplicationServer->StartedHosts[iHostInfo].sHostRealm));
		addVendorIdAVP( dmCER, 10415, 0, 1);
		addProductNameAVP( dmCER, (char*)oApplicationServer->StartedHosts[iHostInfo].sProdName, 0, 1, strlen((char*)oApplicationServer->StartedHosts[iHostInfo].sProdName));
		addHostIPAddressAVP( dmCER, (char *)oApplicationServer->StartedHosts[iHostInfo].sHostIP, 0, 1 );
		addOriginStateIdAVP( dmCER, 0, 0, 1);
		//addInbandSecurityIdAVP( dmCER, oApplicationServer->StartedHosts[iHostInfo].iInbSecurity, 0, 1);
		addInbandSecurityIdAVP( dmCER, 0, 0, 1);
		addFirmwareRevisionAVP( dmCER, 1, 0, 0);
		
		//------------------------------------------------------------
		if( oPeerConfigData->uiVendId1 > 0)
			addVendorIdAVP( dmCER, oPeerConfigData->uiVendId1, 0, 0);
		
		if( oPeerConfigData->uiVendId2 > 0)
			addVendorIdAVP( dmCER, oPeerConfigData->uiVendId2, 0, 0);

		if( oPeerConfigData->uiVendId3 > 0)
			addVendorIdAVP( dmCER, oPeerConfigData->uiVendId3, 0, 0);
		
		if( oPeerConfigData->uiVendId5 > 0)
			addVendorIdAVP( dmCER, oPeerConfigData->uiVendId4, 0, 0);

		if( oPeerConfigData->uiVendId5 > 0)
			addVendorIdAVP( dmCER, oPeerConfigData->uiVendId5, 0, 0);		
		//------------------------------------------------------------
		
		if( oPeerConfigData->uiAuthAppId1 > 0)
			addAuthApplicationIdAVP( dmCER, oPeerConfigData->uiAuthAppId1, 0, 0);
		
		if( oPeerConfigData->uiAuthAppId2 > 0)
			addAuthApplicationIdAVP( dmCER, oPeerConfigData->uiAuthAppId2, 0, 0);

		if( oPeerConfigData->uiAuthAppId3 > 0)
			addAuthApplicationIdAVP( dmCER, oPeerConfigData->uiAuthAppId3, 0, 0);
		
		if( oPeerConfigData->uiAuthAppId4 > 0)
			addAuthApplicationIdAVP( dmCER, oPeerConfigData->uiAuthAppId4, 0, 0);

		if( oPeerConfigData->uiAuthAppId5 > 0)
			addAuthApplicationIdAVP( dmCER, oPeerConfigData->uiAuthAppId5, 0, 0);

		//------------------------------------------------------------
		
		if( oPeerConfigData->uiAcctAppId1 > 0)
			addAcctApplicationIdAVP( dmCER, oPeerConfigData->uiAcctAppId1, 0, 0);
		
		if( oPeerConfigData->uiAcctAppId2 > 0)
			addAcctApplicationIdAVP( dmCER, oPeerConfigData->uiAcctAppId2, 0, 0);

		if( oPeerConfigData->uiAcctAppId3 > 0)
			addAcctApplicationIdAVP( dmCER, oPeerConfigData->uiAcctAppId3, 0, 0);
		
		if( oPeerConfigData->uiAcctAppId4 > 0)
			addAcctApplicationIdAVP( dmCER, oPeerConfigData->uiAcctAppId4, 0, 0);

		if( oPeerConfigData->uiAcctAppId5 > 0)
			addAcctApplicationIdAVP( dmCER, oPeerConfigData->uiAcctAppId5, 0, 0);

		//-------------------------------------------------------------
		
		/**/
		if( oPeerConfigData->uiSuppAppVendorId1 > 0 && oPeerConfigData->uiSuppApp1 > 0)
			addVendorSpecificApplicationId( dmCER, oPeerConfigData->uiSuppAppVendorId1, oPeerConfigData->uiSuppApp1 );
		
		if( oPeerConfigData->uiSuppAppVendorId2 > 0 && oPeerConfigData->uiSuppApp2 > 0)
			addVendorSpecificApplicationId( dmCER, oPeerConfigData->uiSuppAppVendorId2, oPeerConfigData->uiSuppApp2 );
		
		if( oPeerConfigData->uiSuppAppVendorId3 > 0 && oPeerConfigData->uiSuppApp3 > 0)
			addVendorSpecificApplicationId( dmCER, oPeerConfigData->uiSuppAppVendorId3, oPeerConfigData->uiSuppApp3 );
	
		if( oPeerConfigData->uiSuppAppVendorId4 > 0 && oPeerConfigData->uiSuppApp4 > 0)
			addVendorSpecificApplicationId( dmCER, oPeerConfigData->uiSuppAppVendorId4, oPeerConfigData->uiSuppApp4 );

		if( oPeerConfigData->uiSuppAppVendorId5 > 0 && oPeerConfigData->uiSuppApp5 > 0)
			addVendorSpecificApplicationId( dmCER, oPeerConfigData->uiSuppAppVendorId5, oPeerConfigData->uiSuppApp5 );
		/**/
		
		return 1;
	}
	else
	{
		printf("No Host Configuration Found\n");
		return 0;
	}
}

void closeAndCleanClientPeerConfigSocket( iPeerConfigData * oPeerConfigData)
{
	if(oPeerConfigData->iConnected == 1)
	{	
		printf("%s :: iPeerConfigData[%d] fd[%d] Closing Connection \n", __FUNCTION__ , oPeerConfigData->Id, oPeerConfigData->iFd);
		close(oPeerConfigData->iFd);
		shutdown(oPeerConfigData->iFd, 2);
		
		oPeerConfigData->iConnected = 0;
	}
}

void createWatchDogRequest2(struct DiamMessage * dmCER, iPeerConfigData * oPeerConfigData)
{
	dmCER->Flags.Request = 1;
	//dmCER->Flags.Proxyable = 0;
	initDiamRequest( dmCER, 0, 280, 0);

	int iHostInfo = (oPeerConfigData->HostEntryId-1);
	if( iHostInfo > oApplicationServer->StartedHostsCount) {
		iHostInfo = 0;
	}
	
	addOriginHostAVP( dmCER, (char*)oApplicationServer->StartedHosts[iHostInfo].sHostName, 0, 1, strlen(oApplicationServer->StartedHosts[iHostInfo].sHostName));
	addOriginRealmAVP( dmCER, (char*)oApplicationServer->StartedHosts[iHostInfo].sHostRealm, 0, 1, strlen(oApplicationServer->StartedHosts[iHostInfo].sHostRealm));
	addOriginStateId( dmCER);
}

/*
	This functions establishes connection with sctp server, sends CER sand listens to Answers with poll
*/
//Function-ID:10001
void * coreAppServerStartSctpPeerConnection( void * args)
{
	//CLog(  0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "created thread");
	
	#if SCTP_SUPPORT
	
	iPeerConfigData * oPeerConfigData = (iPeerConfigData *)args;
	oPeerConfigData->iStarted = 1;
	oPeerConfigData->DoNotConnect = 0;
	oPeerConfigData->iFd = 0;
	oPeerConfigData->iConnected = 0;
	oPeerConfigData->isCERSuccess = 0;
	
	printf("SCTP PeerConfig Id=%d sIPAddress[%s] iPortNo[%d] sPeerName[%s] sPeerRealm[%s]\n", 
		oPeerConfigData->Id, oPeerConfigData->sIPAddress, oPeerConfigData->iPortNo, oPeerConfigData->sPeerName, oPeerConfigData->sPeerRealm);

	//int iWaitTime = 3;
	long int iRequestNo = 0;
	struct pollfd fds;
	int bSuccess = 0;
	
	//int iFd = -1;
	int iWaitTemp = 0;
	int iHostConfigSts = 0;
	//ssize_t count;
	char buf[5000];
	int n = 0, flags = 0, ret;
	//socklen_t from_len;
	struct sctp_sndrcvinfo sinfo = {0};
	//struct sockaddr_in addr = {0};
	
	struct DiamMessage * dmCER = NULL;
	struct DiamRawData *oDiamRawData = NULL;
	
	iPeerConfigDataProxy lvPeerConfigDataProxy;
	memset( &lvPeerConfigDataProxy, 0, sizeof(iPeerConfigDataProxy));

	char totbuf[10000];
	int iTotalBufferLength = 0;
	int PendingBufferLength = 0;
	int iUsedBufferSize = 0;
	unsigned int iMessageLength;
	
	while(1)
	{
		if( oPeerConfigData->isActive == 0)
		{
			usleep(999999);
			continue;
		}
		
		while(oPeerConfigData->iConnected == 0 && oPeerConfigData->DoNotConnect == 0)
		{
			//printf("trying to connect again %p\n", oPeerConfigData);
			CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "trying to connect again to peer-id:%d", oPeerConfigData->Id);
			coreSctpClient_connectToPeer( oPeerConfigData, &oPeerConfigData->iConnected, &oPeerConfigData->iFd);
			
			if( oPeerConfigData->iConnected == 1)
			{	
				//printf("sctp connection successful Id:%d\n", oPeerConfigData->Id);
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "sctp connecting to peer successful peer-id:%d", oPeerConfigData->Id);
				break;
			}
			
			for( iWaitTemp = 0; iWaitTemp < objStackConfig.ReConnectSeconds; iWaitTemp++)
			{
				usleep(999999);
			}
		}
		
		if( oPeerConfigData->iConnected == 1)
		{
			dmCER = allocateMessage();
			iHostConfigSts = createCER2( dmCER, oPeerConfigData);
			
			if( iHostConfigSts == 0)
			{
				releaseMessage( dmCER);
				closeAndCleanClientPeerConfigSocket( oPeerConfigData);
				//printf("Please Configure Host Configuration and Restart\n");
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Please Configure Host Configuration and Restart peer-id:%d", oPeerConfigData->Id);
				oPeerConfigData->DoNotConnect = 1;
				continue;
			}
			else
			{
				CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", oPeerConfigData->Id, oPeerConfigData->iFd, oPeerConfigData->sIPAddress, oPeerConfigData->iPortNo);

				//appSCTPSendMsg releases the message "dmCER"
				bSuccess = appSCTPSendMsg( &oPeerConfigData->iFd, dmCER);

				if( bSuccess < 0 && errno == EPIPE)
				{
					CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", oPeerConfigData->Id, oPeerConfigData->iFd);
					closeAndCleanClientPeerConfigSocket( oPeerConfigData);
				}				
			}			
		}
		
		oPeerConfigData->iIdleTime = 0;
		oPeerConfigData->iDWRCount = 0;
		fds.fd     = oPeerConfigData->iFd;
		fds.events = POLLIN;
		
		memset( &lvPeerConfigDataProxy, 0, sizeof(iPeerConfigDataProxy));
		while( oPeerConfigData->iConnected == 1)
		{
			ret = poll( &fds, 1, 1000);
			//printf("poll returned = %d\n", ret);			
			
			if( ret == 0)
			{
				//oPeerConfigData->iIdleTime += iWaitTime;
				oPeerConfigData->iIdleTime += 1;
				
				if( oPeerConfigData->iIdleTime >= objStackConfig.WatchDogRequestInterval )
				{
					if( oPeerConfigData->isCERSuccess == 0)
					{
						dmCER = allocateMessage();
						createCER2( dmCER, oPeerConfigData);

						CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER To Peer[%d] SockFd[%d] IP[%s] Port[%d]", oPeerConfigData->Id, oPeerConfigData->iFd, oPeerConfigData->sIPAddress, oPeerConfigData->iPortNo);

						//appSCTPSendMsg releases the message "dmCER"
						bSuccess = appSCTPSendMsg( &oPeerConfigData->iFd, dmCER);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", oPeerConfigData->Id, oPeerConfigData->iFd);
							closeAndCleanClientPeerConfigSocket( oPeerConfigData);
							break;
						}
					} 
					else 
					{
						//printf("Init Diam WatchDog Request From PEER \n");
						dmCER = allocateMessage();
						createWatchDogRequest2( dmCER, oPeerConfigData);
						
						//appSCTPSendMsg releases the message "dmCER"
						bSuccess = appSCTPSendMsg( &oPeerConfigData->iFd, dmCER);

						if( bSuccess < 0 && errno == EPIPE)
						{
							CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Sending CER Failed For Peer[%d] SockFd[%d]", oPeerConfigData->Id, oPeerConfigData->iFd);
							closeAndCleanClientPeerConfigSocket( oPeerConfigData);
							break;
						}
						oPeerConfigData->iDWRCount++;
					}
					
					oPeerConfigData->iIdleTime = 0;
				}
				
				//printf("oPeerConfigData->iIdleTime = %d\n", oPeerConfigData->iIdleTime);
				continue;
			}
			
			if( ret < 0)
			{
				closeAndCleanClientPeerConfigSocket( oPeerConfigData);
				break;
			}
			
			if( ret > 0)
			{
				n = sctp_recvmsg( oPeerConfigData->iFd, buf, sizeof(buf), (struct sockaddr *)NULL, 0, &sinfo, &flags);
				
				if( flags & MSG_NOTIFICATION ) 
				{
					union sctp_notification  *snp = (union sctp_notification *)buf;
					if(snp)
					{
						if( SCTP_SHUTDOWN_EVENT == snp->sn_header.sn_type)
						{
							closeAndCleanClientPeerConfigSocket( oPeerConfigData);
							break;						
						}
						handle_sctp_event( buf, n );
					}
				}
				else 
				{	
					if( (ret == 1 && n == 0) || n < 0)
					{
						closeAndCleanClientPeerConfigSocket( oPeerConfigData);
						break;
					}
					
					//printf("sctp_recvmsg n[%d]\n", n);
					//SCTP PEER READ 
					if( n > 0)
					{
						//printf("stream %d, PPID %d.: bytes-received-X-P:%d\n", sinfo.sinfo_stream, ntohl(sinfo.sinfo_ppid), n);
						CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "stream %d, PPID %d.: bytes-received-X-P:%d", sinfo.sinfo_stream, ntohl(sinfo.sinfo_ppid), n);
						
						if( lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength > 0)
						{
							PendingBufferLength = lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength;
							memcpy( totbuf, lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, PendingBufferLength);
							memcpy( &totbuf[PendingBufferLength], buf, n);
							iTotalBufferLength = PendingBufferLength + n;
							lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = 0;
						}
						else
						{
							memcpy( totbuf, buf, n);
							iTotalBufferLength = n;
						}
						
						iUsedBufferSize = 0;
						while( iUsedBufferSize < iTotalBufferLength)
						{
							if( ( iTotalBufferLength - iUsedBufferSize) > DIAM_BUFFER_SIZE_HEADER_SIZE)
							{
								oDiamRawData = allocateDiamRawData();
								oDiamRawData->Header->len = DIAM_BUFFER_SIZE_HEADER_SIZE;
								memcpy( oDiamRawData->Header->Data, &totbuf[iUsedBufferSize], DIAM_BUFFER_SIZE_HEADER_SIZE);
								decodeIntValueFrom3Bytes( &iMessageLength, oDiamRawData->Header->Data, 1);								
								
								//printf("iMessageLength = %d\n", iMessageLength);
								
								if( ( iTotalBufferLength - iUsedBufferSize) >= iMessageLength )
								{
									//printf("iMessageLength = %d sufficient body message\n", iMessageLength);
									
									CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "iMessageLength = %d sufficient body message", iMessageLength);
									memcpy( oDiamRawData->PayLoad->Data, &totbuf[iUsedBufferSize + DIAM_BUFFER_SIZE_HEADER_SIZE], (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE));

									oDiamRawData->iPeerIndex = -1;
									oDiamRawData->iRequestNo = iRequestNo;
									oDiamRawData->iMessageArrivedFrom = 10;
									oDiamRawData->iRouteMessageTo = 2;	
									oDiamRawData->PayLoad->len = (iMessageLength - DIAM_BUFFER_SIZE_HEADER_SIZE);
									oDiamRawData->PeerConfigData = oPeerConfigData;
									
									
									objStackObjects.TotalMemoryUsage.SocketReadCount++;
									appPostMsg( oDiamRawData);
									//releaseDiamRawData( oDiamRawData);
									//printf("releaseDiamRawData=%p\n", oDiamRawData);
																		
									oPeerConfigData->iResponseNo++;
									iRequestNo++;
									iUsedBufferSize += iMessageLength;									
								}
								else
								{
									releaseDiamRawData( oDiamRawData);
									//printf("message is less than header(20) size = %d\n", iTotalBufferLength);
									CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
									lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
									memcpy( lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
									break;									
								}
							}
							else
							{
								//printf("message is less than header(20) size = %d\n", iTotalBufferLength);
								CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "message is less than header(20) size = %d", iTotalBufferLength);
								lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].PendingBufferLength = ( iTotalBufferLength - iUsedBufferSize);
								memcpy( lvPeerConfigDataProxy.SctpStreamBuffer[sinfo.sinfo_stream].sBuffer, &totbuf[ ( iTotalBufferLength - iUsedBufferSize)], ( iTotalBufferLength - iUsedBufferSize));
								break;								
							}
						}
						
						CLog( 0, LOG_LEVEL_DEBUG, __FUNCTION__, __LINE__, "while exited peer thread iUsedBufferSize[%d] , iTotalBufferLength[%d]\n", iUsedBufferSize, iTotalBufferLength);
						//printf("while exited peer thread iUsedBufferSize[%d] , iTotalBufferLength[%d]\n", iUsedBufferSize, iTotalBufferLength);
					}
					
					
					
				}
			}
		}
		
		usleep(999999);
		
	}
	
	#endif
	
	return NULL;
}


//10014
int core_ConnectToPeerServer( iPeerConfigData * oPeerConfigData, char * hostName, int iPort, char * transport)
{
	int i = 0;
	int bFound = 0;

	for( i = 0; i < oApplicationServer->PeerServerCount; i++)
	{
		if( oApplicationServer->PeerConfigData[i].Id == oPeerConfigData->Id)
		{
			bFound = 1;
			
			if( oApplicationServer->PeerConfigData[i].isActive == 1)
			{
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Already Connected to Peer-Server and Active [%d]", oApplicationServer->PeerConfigData[i].isActive);
				return 1010;
			}
			
			if( oApplicationServer->PeerConfigData[i].isActive == 0)
			{
				oApplicationServer->PeerConfigData[i].isActive = 1;
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Activated Peer-Server Connection [%d]", oApplicationServer->PeerConfigData[i].isActive);
			}
			break;
		}
	}
	
	if( bFound == 0)
	{
		i = oApplicationServer->PeerServerCount;
		memcpy( &oApplicationServer->PeerConfigData[i], oPeerConfigData, sizeof(iPeerConfigData));
		
		strcpy( oApplicationServer->PeerConfigData[i].sPeerName, hostName);
		oApplicationServer->PeerConfigData[i].iPortNo = iPort;
		oApplicationServer->PeerServerCount++;
	}
	
	//add entry in realm Table, if not present;
	int bFoundRealmInRealmTable = 0;
	int iRealmIndexRealmTable = -1;
	int bFoundPeerIndexInRealmTable = 0;
	int j = 0;
	for( j = 0; j < oApplicationServer->RealmRowCount; j++)
	{
		if( strcmp( oApplicationServer->RealmRows[j].sRealmName, oPeerConfigData->sPeerRealm) == 0)
		{
			iRealmIndexRealmTable = j;
			bFoundRealmInRealmTable = 1;
			break;
		}
	}
	
	if( bFoundRealmInRealmTable == 0)
	{
		strcpy( oApplicationServer->RealmRows[ oApplicationServer->RealmRowCount].sRealmName, oPeerConfigData->sPeerRealm);
		iRealmIndexRealmTable = oApplicationServer->RealmRowCount;
		oApplicationServer->RealmRowCount++;
	}
	
	for( j = 0; j < oApplicationServer->RealmRows[iRealmIndexRealmTable].PeerIndexCount; j++)
	{
		if( oApplicationServer->RealmRows[iRealmIndexRealmTable].PeerConfigData[j]->Id == oPeerConfigData->Id)
		{
			bFoundPeerIndexInRealmTable = 1;
			break;
		}
	}
	
	if( bFoundPeerIndexInRealmTable == 0)
	{
		iRealmRow * oRealmRow = &oApplicationServer->RealmRows[iRealmIndexRealmTable];
		oRealmRow->PeerConfigData[ oRealmRow->PeerIndexCount] = &oApplicationServer->PeerConfigData[i];
		oRealmRow->PeerIndexCount++;
	}

	if( oApplicationServer->PeerConfigData[i].iStarted == 0)
	{
		int iRet;
		pthread_t s_pthread_id;

		pthread_attr_t attr;
		pthread_attr_init( &attr);
		pthread_attr_setdetachstate( &attr, PTHREAD_CREATE_DETACHED);

		if( strcmp( "tcp", transport) == 0) 
		{
			oApplicationServer->PeerConfigData[i].iTransportType = 0;
			iRet = pthread_create( &s_pthread_id, &attr, coreAppServerStartTcpPeerConnection,  (void *) &oApplicationServer->PeerConfigData[i]);
		}
		else if( strcmp( "sctp", transport) == 0) 
		{
			oApplicationServer->PeerConfigData[i].iTransportType = 1;
			iRet = pthread_create( &s_pthread_id, &attr, coreAppServerStartSctpPeerConnection, (void *) &oApplicationServer->PeerConfigData[i]);
		}
		else 
		{
			return 0;
		}
		
		if( iRet != 0) 
			return 0;
	
	}
	return 0;
}

int parseAndConnectToPeerServer( iPeerConfigData * oPeerConfigData)
{
	char aaaKey[7];
	strncpy( aaaKey, oPeerConfigData->sPeerURI, 6);
	aaaKey[6] = '\0';
	
	char rawUri[249];
	memset( &rawUri, 0, sizeof(rawUri));
	
	char hostName[249];
	memset( &hostName, 0, sizeof(hostName));
	
	char transport[5];
	strcpy( transport, "sctp");
	transport[4] = '\0';
	
	int iPort;

	if( strcmp("aaa://", aaaKey) == 0) 
	{
		strncpy( rawUri, &oPeerConfigData->sPeerURI[6], strlen(oPeerConfigData->sPeerURI)-6);

		char *token;
		char *saveptr1, *saveptr2;
		token = strtok_r( rawUri, ";", &saveptr1);

		if( token)
		{
			token = strtok_r( token, ":", &saveptr2);
			
			if( token)
			{
				if( strlen(saveptr2) > 0)
				{
					strcpy( hostName, token);
					iPort = atoi( saveptr2);
					
					while(1)
					{
						token = strtok_r( saveptr1, ";", &saveptr2);
						
						if( token)
						{
							token = strtok_r( token, "=", &saveptr1);
							
							if( strcmp( token, "transport") == 0)
							{
								if( strcmp( saveptr1, "tcp") == 0 )
								{
									strcpy( transport, "tcp");
									transport[3] = '\0';									
								}
							}
							else
							{
								break;
							}
							
							if( strlen(saveptr2) == 0)
								break;
							
							saveptr1 = saveptr2;							
						}
						else
						{
							break;
						}
					}
					
					return core_ConnectToPeerServer( oPeerConfigData, hostName, iPort, transport);
				}
				else
				{
					CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "port length found connecting to peer-server : %lu", strlen(saveptr2));
					printf("port length found connecting to peer-server : %lu \n", strlen(saveptr2));	
					return 0;					
				}
			}
			else
			{
				CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "error when parsing 2 split connecting to peer-server");
				printf("error when parsing 2 split connecting to peer-server\n");			
				return 0;				
			}
		}
		else
		{
			CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "error when parsing 1 split connecting to peer-server");
			printf("error when parsing 1 split connecting to peer-server\n");
			return 0;			
		}			
	}
	else
	{
		printf("format not matched for peer-server\n");
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Invalid Peer Entry Found in Configuration File, unable to connect peer-server");
		return 0;		
	}
	return 0;
}

//10005
void coreStartConfiguredPeerThreads()
{
	char fullFilePath[500];
	memset( &fullFilePath, 0, sizeof(fullFilePath)); 
	sprintf( fullFilePath, "./%s/%s", fileRootPath, (char *)"peerconfig.dat");
	int nread = 0;	
	
	if( access( fullFilePath, F_OK ) != -1 ) 
	{
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Configuration File Found for Peer-Servers %s, Initializing it", fullFilePath);
		
		FILE *fptr;
		iPeerConfigData oPeerConfigData;
		memset( &oPeerConfigData, 0, sizeof(iPeerConfigData));

		fptr = fopen( fullFilePath, "r");
		
		while(fptr)
		{
			nread = fread( &oPeerConfigData, sizeof(char), sizeof(iPeerConfigData), fptr);
			
			if( nread == 0)
				break;
			
			if( oPeerConfigData.isDeleted == 0)
			{
				if( oPeerConfigData.isActive == 1)
				{	
					printf("PeerConfig Id=%d, sPeerURI[%s], sPeerRealm[%s], sIPAddress[%s], uiSuppApp1[%d], isDeleted[%d], isActive[%d], sPeerName[%s], iPortNo[%d], iStarted[%d]\n", oPeerConfigData.Id, oPeerConfigData.sPeerURI, oPeerConfigData.sPeerRealm, oPeerConfigData.sIPAddress, oPeerConfigData.uiSuppApp1, oPeerConfigData.isDeleted, oPeerConfigData.isActive, oPeerConfigData.sPeerName, oPeerConfigData.iPortNo, oPeerConfigData.iStarted );
					CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "PeerConfig Id=%d, sPeerURI[%s], sPeerRealm[%s], sIPAddress[%s], uiSuppApp1[%d], isDeleted[%d], isActive[%d], sPeerName[%s], iPortNo[%d], iStarted[%d]\n", oPeerConfigData.Id, oPeerConfigData.sPeerURI, oPeerConfigData.sPeerRealm, oPeerConfigData.sIPAddress, oPeerConfigData.uiSuppApp1, oPeerConfigData.isDeleted, oPeerConfigData.isActive, oPeerConfigData.sPeerName, oPeerConfigData.iPortNo, oPeerConfigData.iStarted );
					
					parseAndConnectToPeerServer( &oPeerConfigData);
				}
				else
				{
					CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "PeerConfig Id=%d with URI[%s] isNot Active", 
						oPeerConfigData.Id, oPeerConfigData.sPeerURI);	
				}
			}
		}
			
	}
	else
	{
		CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Configuration File NOT Found for Peer-Servers %s", fullFilePath);
	}
}



void StartCore( int iWebPort, int initialMemory)
{
	if( initialMemory <= 0)
		initialMemory = 512;

	printf("%s initialMemory=%d\n", __FUNCTION__, initialMemory);
	
	//InitMBMalloc( 1024, 1);
	InitMBMalloc( initialMemory, 1);

	//if config file available
	int bConfigFileAvailble = 0;
	
	if(bConfigFileAvailble)
	{
		printf("Starting with configuration files.\n");
	}
	else
	{
		printf("Starting with default configuration.\n");
		
		core_bConfigFileAvailable = 0;
		initConfig("");
		
		sprintf( objStackObjects.LoggerConfig[0].Path, "%s%s", "./logs/", "stacklogs");
		sprintf( objStackObjects.LoggerConfig[1].Path, "%s%s", "./logs/", "perflogs");
		sprintf( objStackObjects.LoggerConfig[2].Path, "%s%s", "./logs/", "applogs");		

		printf("Default Logs Path=%s\n", objStackObjects.LoggerConfig[0].Path);
		
		objStackObjects.LoggerConfig[1].Enabled = 1;	//Perf
		objStackConfig.EnablePerformaceThread = 1;
		initLogger();

		/*
		objStackConfig.iCatLog_CoreSockets 		= core_AddLogCat( (char *)"CORE_SOCKETS", 1);
		objStackConfig.iCatLog_CoreDecode 		= core_AddLogCat( (char *)"CORE_DECODE", 1);	
		objStackConfig.iCatLog_CoreRouting 		= core_AddLogCat( (char *)"CORE_ROUTING", 1);
		
		core_AddLogCat( (char *)"CORE_RESERVED1", 1);
		core_AddLogCat( (char *)"CORE_RESERVED2", 1);
		*/
		
		CLog(  0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "fx::started with default configuration");
	}
	
	
	#if DIAMDRA
	
	printf("==========================================D R A==========================================\n");

	objStackObjects.MinHBH = 1;
	objStackObjects.MaxHBH = 10000000;
	objStackObjects.CurrentHBH = 1;
		
	int i = 0;
	
	for(i = 0; i < objStackObjects.MaxHBH; i++)
	{
		objStackObjects.HBHDB[i].oClientInfo = NULL; 
		objStackObjects.HBHDB[i].OriginalHBH = 0;
	}
	
	pthread_mutex_init( &objStackObjects.HBHLock, NULL);
		
	printf("====================================*=*=*=D R A=*=*=*====================================\n");
		
	#endif

	initMessagePool();
	objStackConfig.EnablePerformaceThread = 1;
	
	if( objStackConfig.EnablePerformaceThread > 0)
	{
		initPerformanceThread();
		printf("Initialized Performance Thread\n");
	}
	
	corebStartStack = 0;
	initalizeServer();
	
	initTimerThread();
	
	printMallocStats();
	
	//CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Stack Initialized [%d]", objStackConfig.NodeType);	

#if DIAMDRA
	objStackConfig.NodeType = 2;
#endif	
	
	startWebConsole( iWebPort);
	coreStartConfiguredHost();
	coreStartConfiguredPeerThreads();
	
	CLog( 0, LOG_LEVEL_CRITICAL, __FUNCTION__, __LINE__, "Stack Initialized NodeType=[%d]", objStackConfig.NodeType);
	printf("Stack Initialized NodeType=[%d]\n", objStackConfig.NodeType);	
}

//NodeType = 1  ... Client ..
//NodeType = 2  ... Proxy/Realy/Agent ..
//NodeType = 3  ... Server ..

/*
1)Diameter Relay (DRA)	Application Identifier (0xffffffff)
2)Diameter Proxy
3)Diameter Redirect 
4)Translator
*/

/*
1) Diameter Relay 
It is used to rout the message to other diameter node with the help of  
routing information received in message such as Destination-Realm, 
Destination -Host. Relay can accept the request with multiple networks.
Relay must not change message format and avps except the routing avps. 
Relay must advertise its Application Identifier (0xffffffff).
*/

/*
2)Diameter Proxy
Diameter Proxy does all that relay does. Moreover proxy can change 
message and avp format if required to apply some policies.
A Diameter Proxy MUST be called as DIAMETER X Proxy, where X is the 
application whose messages are being proxy-ed by by the node.
*/

/*
3)Diameter Redirect
Diameter Redirect agent is useful in the scenario where diameter routing 
information is stored at centralized location. Every node can get the 
rout information from Redirect agent and then forward the message. Redirect 
Agent does not forward message to any node. It just replies to the request 
received with the routing information.[Message Processing at Redirect Agent]
Redirect must advertise its Application Identifier (0xffffffff)


4)Translator
Translator changes RADIUS message to Diameter and vice-versa for backward compatibility.
*/

//Peer Based Request Routing
//Realm Based Routing
//Answer Message Routing
//Loop Detection


//cat /proc/net/sctp/eps








