#ifndef TELNET_ENGINE_H
#define TELNET_ENGINE_H

#define TELNET_PORT 23
#define BUFSIZE 2048
#define THIS_VER "1.0.0"
#define CSV_SEP "\t ;"
#define XML_IDF "idf/"
#define HEX_FRM 16
#define DEC_FRM 10
#define MODULE_TYPE_NAME "RDIO401S-32"
#define MODULE_TYPE_ID 0xC8
#define FIRST_SLOT 1
#define LAST_SLOT 32
#define CONSOLE_DELAY 1000
#define SOCKET_TIMEOUT 1000;
#define WAIT_REPLY_OBJECT_TIMEOUT 500
#define LINE_SHIFT "\r"
#define _WINSOCK_DEPRECATED_NO_WARNINGS 

#include <winsock2.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct 
{
    SOCKET clientSocket;
    HANDLE eventHandle;
    FILE *requestFile;
    char buffer[BUFSIZE];
} ThreadData;

typedef enum 
{
    ACTST_ERROR = -1,
    ACTST_IDLE = 0,
    ACTST_CONNECT,
    ACTST_CONNECTED,
    ACTST_DISCONNECT,
    ACTST_GET_NEXT,
    ACTST_REQ_SBCMON,
    ACTST_REPLY_SBCMON,
    ACTST_REQ_PBI,
    ACTST_REPLY_PBI,
    ACTST_GET_INFOBJ,
    ACTST_SET_INFOBJ,
    ACTST_REQ_READIDF,
    ACTST_GOT_READIDF,
    ACTST_SCAN_MODSLOT,
    ACTST_CHECK_MODSLOT,
    ACTST_DONE
} ActionStates;

typedef struct
{
    char topologyPath[64];
    char vessel[32];
    unsigned char ps;
    unsigned char slot;
    char utcTimeStamp[20];
    char moduleTypeName[16];
    unsigned int moduleId;
    unsigned long partNumber; 
    unsigned long hwRevision; 
    unsigned long serialNumber; 
    unsigned long cpldCode; 
    unsigned long cpldRevision; 
    unsigned long swCode;
    unsigned long swRevision; 
} InfoObj;


typedef enum 
{
    IDFS_MODULE_ID      = 0x3f,
    IDFS_PART_NUMBER_HI = 0x40, // Most significant 16 bit of part number.
    IDFS_PART_NUMBER_LO = 0x41, // Least significant 16 bit of part number.
    IDFS_HW_REVISION    = 0x42, // Hardware revision number.
    IDFS_SERIAL_NUMBER  = 0x43, // Serial number.
    IDFS_CPLD_REVISION  = 0x44, // PLD revision number.
    IDFS_SW_CODE        = 0x45, // Software code.
    IDFS_SW_VERSION     = 0x46, // Software version number.
    IDFS_CPLD_CODE      = 0x47 
} IdentityPropertyIdfs;

typedef enum 
{
    STAT_VALID_READ = 0,
    STAT_INVALID,
    STAT_READ_ERROR
} IdfStatus;

typedef enum
{
    STAT_DISABLED = 0,
    STAT_SCANNING,
    STAT_SLOT_FOUND,
    STAT_NO_SLUT_FOUND
} SlotScanStatus;

typedef struct
{
    unsigned char slot;
    uint16_t idf;
    unsigned int value;
    IdfStatus status;
} IdfRegister;

typedef struct 
{
    SlotScanStatus searchStatus;
    uint16_t foundSlot;
    uint16_t idfModuleId;
    uint16_t valueModuleId;
    IdfRegister findIdfReg;
} SlotScanning;


typedef struct {
    BOOL hexFormat;
    BOOL csvSemi;
    BOOL xmlFormat;
    char csvSym;
    DWORD waitReplyTimeout;
    int socketTimeout;
    uint32_t ipAdr;
    int ipAdrCount;
    int indexCount;
    unsigned char selectedSlot;
    uint16_t moduleId;     
} FlagSettings;


const char * state2str(ActionStates st);
void setNewState(ActionStates st);
void updateTimeStamp(char *timestamp);
void removeWhiteSpace(char *str);
BOOL expectRdi(const char *input, IdfRegister* data);
BOOL expectPbi(const char *input);
BOOL expectSbcmon(const char *input);
BOOL str2rdi(const char *input, IdfRegister* outputIdf);
char* csv2rdi(char* line, int frm);
char* getXMLattributeValue(const char *str, const char *attribute, char *buffer, size_t bufferSize);
void setXMLattributeValue(char *str, const char *attrName, const char *newValue);
BOOL isInformationObjectInXML(InfoObj* infoObj, char* line);
BOOL getIDFpathFromXML(IdfRegister* outputIdf, char* inputLine);
BOOL getXMLvalue(const char *input, const char *tag, const char *attr, char *value);
void handleReply(ThreadData *data);
void runCurrentState(ThreadData *data);
void eventHandler(HANDLE eventHandle, ThreadData *data);
DWORD WINAPI asyncSocketReader(LPVOID lpParam);
int connectTelnet(SOCKET *clientSocket, uint32_t serverIp);
void sendTelnetRequest(SOCKET clientSocket, const char *data);
void goSbcmon(HANDLE eventHandle, ThreadData *data);
BOOL getNextSlotId(HANDLE eventHandle, ThreadData *data, IdfRegister *checkSlot);
BOOL getIdfRegister(HANDLE eventHandle, ThreadData *data, IdfRegister *getIdf);

#endif // TELNET_ENGINE_H
