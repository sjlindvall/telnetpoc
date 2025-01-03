/*******************************************************************************
 * PURPOSE:
 * Automate SBCMON/PBI/RDI data harvesting using a telnet client.
 *
 * PUBLIC FUNCTIONS:
 * main
 *
 * EXTERNAL MODULES:
 * telnetclient
 * 
 * AUTHOR:
 * Sven Johan Lindvall
 *
 ******************************************************************************/

#pragma comment(lib, "ws2_32.lib")

#include "telnetclient.h"
#include <stdio.h>
#include <windows.h>
#include <stdint.h>

extern FlagSettings settings; 
extern IdfRegister checkSlot;
extern IdfRegister thisRequest;
extern ActionStates currentState; 
extern ActionStates lastState;
extern BOOL interrupted;
extern SlotScanning slotScanner;

typedef struct
{
	uint16_t *idfAddresses;
	size_t idfAddressCount;
} IdfTemplate;

IdfTemplate idfsToFetch = {0,0};


void removeComments(char *str) {
    char *start;
    while ((start = strchr(str, '#')) != NULL) {
        char *end = strchr(start, '\n');
        if (end) {
            memmove(start, end, strlen(end) + 1);
        } else {
            *start = '\0';
        }
    }
}

/*******************************************************************************
 * PRIVATE FUNCTION:
 * getIndexListFromString
 *
 * get an array of ranges/indexes from string input 
 ******************************************************************************/
unsigned int* getIndexListFromString(const char *ranges, int *count) {
    char *rangeStr = _strdup(ranges); 
    unsigned int *addresses = NULL;
    *count = 0;
    char * context;

    removeComments(rangeStr);

    char *token = strtok_s(rangeStr, ", \n", &context);
    while (token != NULL) 
    {
        unsigned int start, end;
        if (sscanf_s(token, "$%x-$%x", &start, &end) == 2 || 
            sscanf_s(token, "0x%x-0x%x", &start, &end) == 2 || 
            sscanf_s(token, "x%x-x%x", &start, &end) == 2) 
        { // got hex range
            for (unsigned int addr = start; addr <= end; addr++) 
            {
                addresses = realloc(addresses, (*count + 1) * sizeof(unsigned int));
                addresses[*count] = addr;
                (*count)++;
            }
        } 
        else if (sscanf_s(token, "$%x", &start) == 1 || 
                 sscanf_s(token, "0x%x", &start) == 1 || 
                 sscanf_s(token, "x%x", &start) == 1) 
        { // got single hex
            addresses = realloc(addresses, (*count + 1) * sizeof(unsigned int));
            addresses[*count] = start;
            (*count)++;
        } 
        else if (sscanf_s(token, "%u-%u", &start, &end) == 2) 
        { // got dec range
            for (unsigned int addr = start; addr <= end; addr++) 
            {
                addresses = realloc(addresses, (*count + 1) * sizeof(unsigned int));
                addresses[*count] = addr;
                (*count)++;
            }
        } 
        else if (sscanf_s(token, "%u", &start) == 1) 
        { // got single dec
            addresses = realloc(addresses, (*count + 1) * sizeof(unsigned int));
            addresses[*count] = start;
            (*count)++;
        }
        token = strtok_s(NULL, ", \n#",&context);
    }
    
    free(rangeStr); 
    return addresses;
}

void printIDF(IdfRegister* idfReg)
{
    if (idfReg != NULL)
    {
        if (settings.hexFormat)
            printf("Slot:%02u IDF[%04x]:%04x\n", idfReg->slot, idfReg->idf, idfReg->value);
        else
            printf("Slot:%u IDF[%u]:%u\n", idfReg->slot, idfReg->idf, idfReg->value);
    }
}

void dumpHeading()
{
    struct in_addr addr;
    addr.S_un.S_addr = settings.ipAdr;
    printf("<?xml version='1.0'?>\n\
<InformationObjects>\n\
<!-- Connected to '%s' and entering SBCMON/PBUS -->\n", inet_ntoa(addr));
}

void dumpInformationObject(InfoObj *infoObj)
{
    printf("<InformationObject class='PBUSModule' utcTimeStamp='%s' topologyPath='%s/PS/%u/PBUS/1/%u'>\n\
<IdentityProperties>\n\
<Property path='moduleId'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='softwareCode'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='serialNumber'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='cpldCode'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='cpldRevision'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='partNumber'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='hardwareRevision'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='softwareVersion'><Value type='unsignedLong'>%u</Value></Property>\n\
<Property path='moduleTypeName'><Value type='string'>%s</Value></Property>\n\
</IdentityProperties>\n\
<DynamicProperties>\n",
        infoObj->utcTimeStamp,
        infoObj->vessel,
        infoObj->ps,
        infoObj->slot,
        infoObj->moduleId,
        infoObj->swCode,
        infoObj->serialNumber,
        infoObj->cpldCode,
        infoObj->cpldRevision,
        infoObj->partNumber,
        infoObj->hwRevision,
        infoObj->swRevision,
        infoObj->moduleTypeName
    );
}

void dumpIdfObject(IdfRegister *idfReg)
{
    if (idfReg != NULL)
    {
        printf("<Property path='idf/%u'><Value type='unsignedShort'>%u</Value></Property>\n", idfReg->idf, idfReg->value);
    }
}

void dumpEnding()
{
    printf(
        "</DynamicProperties>\n\
</InformationObject>\n");
}

void dumpLastEnding()
{
    printf("</InformationObjects>\n");
}


BOOL getInformationObject(HANDLE eventHandle, ThreadData *data, InfoObj *self)
{
    BOOL result = TRUE;
    if (slotScanner.searchStatus == STAT_SLOT_FOUND)
    {
        self->moduleId = slotScanner.valueModuleId;
		strcpy_s(self->moduleTypeName, sizeof(self->moduleTypeName), MODULE_TYPE_NAME);
        self->slot = slotScanner.foundSlot;
        updateTimeStamp(self->utcTimeStamp);
		strcpy_s(self->vessel, sizeof(self->vessel), "SomeVessel");
        self->ps = 0; 
    }

    IdfRegister getIdfHi;
    getIdfHi.status = STAT_INVALID;
    getIdfHi.slot = self->slot;
    getIdfHi.idf = IDFS_PART_NUMBER_HI;
    result |= getIdfRegister( eventHandle, data, &getIdfHi);
    IdfRegister getIdfLo;
    getIdfLo.status = STAT_INVALID;
    getIdfLo.slot = self->slot;
    getIdfLo.idf = IDFS_PART_NUMBER_LO;
    result |= getIdfRegister( eventHandle, data, &getIdfLo);
    if (result && getIdfHi.status == STAT_VALID_READ && getIdfLo.status == STAT_VALID_READ)
    {
        self->partNumber = (getIdfHi.value << 16) | (getIdfLo.value);
    }

    IdfRegister getIdf;
    getIdf.slot = self->slot;
    getIdf.status = STAT_INVALID;
    getIdf.idf = IDFS_SERIAL_NUMBER;
    result |= getIdfRegister( eventHandle, data, &getIdf);
    if (result && getIdf.status == STAT_VALID_READ)
    {
        self->serialNumber = getIdf.value;
    }

    getIdf.status = STAT_INVALID;
    getIdf.idf = IDFS_SW_CODE;
    result |= getIdfRegister( eventHandle, data, &getIdf);
    if (result && getIdf.status == STAT_VALID_READ)
    {
        self->swCode = getIdf.value;
    }

    getIdf.status = STAT_INVALID;
    getIdf.idf = IDFS_CPLD_CODE;
    result |= getIdfRegister( eventHandle, data, &getIdf);
    if (result && getIdf.status == STAT_VALID_READ)
    {
        self->cpldCode = getIdf.value;
    }

    getIdf.status = STAT_INVALID;
    getIdf.idf = IDFS_HW_REVISION;
    result |= getIdfRegister( eventHandle, data, &getIdf);
    if (result && getIdf.status == STAT_VALID_READ)
    {
        self->hwRevision = getIdf.value;
    }

    getIdf.status = STAT_INVALID;
    getIdf.idf = IDFS_CPLD_REVISION;
    result |= getIdfRegister( eventHandle, data, &getIdf);
    if (result && getIdf.status == STAT_VALID_READ)
    {
        self->cpldRevision = getIdf.value;
    }

    getIdf.status = STAT_INVALID;
    getIdf.idf = IDFS_SW_VERSION;
    result |= getIdfRegister( eventHandle, data, &getIdf);
    if (result && getIdf.status == STAT_VALID_READ)
    {
        self->swRevision = getIdf.value;
    }

    return result;
}


BOOL getNextIndex(IdfTemplate *self, IdfRegister *getIdf)
{
    static int currentIndex = 0;
    if (currentIndex < self->idfAddressCount) 
    {
        getIdf->idf = self->idfAddresses[currentIndex];
        //getIdf->slot; 
        currentIndex++;
        return TRUE;
    }
    else currentIndex = 0; 
    return FALSE;
}

int idfTemplateInitFromFile(IdfTemplate *self, FILE* inputFile)
{
    char fileBuf[BUFSIZE];
    int count = 0;
    unsigned int *indexes;

    if (fread(fileBuf, 1, BUFSIZE, inputFile) > 0) 
    {
        indexes = getIndexListFromString(fileBuf, &count);
        if (count > 0) 
        {
            self->idfAddresses = malloc(sizeof(unsigned int)*count);
            for (int i = 0; i < count; i++)
            {
                self->idfAddresses[i] = indexes[i];
            }
            self->idfAddressCount = count;
        }
    }
    fprintf(stderr, "got %d items from file\n", count);
    return 0;
}

int idfTemplateInitFromString(IdfTemplate *self, const char *addressString)
{
    return 0;
}

void idfTemplateFetcherTask(IdfTemplate *self, HANDLE eventHandle, ThreadData *data)
{
    InfoObj fetchedInformationObject;
    IdfRegister findSlotIdf;
    
    if (settings.selectedSlot > 0)
    {
        thisRequest.slot = settings.selectedSlot;
        goto GO_SLOT;
    }

    dumpHeading();
        
    while(getNextSlotId(eventHandle, data, &findSlotIdf))
    {
GO_SLOT:
        thisRequest.slot = findSlotIdf.slot;
        //got slot id, output current InformationObject
        if (getInformationObject(eventHandle, data, &fetchedInformationObject))
        {
            dumpInformationObject(&fetchedInformationObject);
        }                

        //browse wanted IDF reg's
        while(getNextIndex(self, &thisRequest)) 
        {
            if (getIdfRegister(eventHandle, data, &thisRequest))
            {
                dumpIdfObject(&thisRequest);
            }
        }
        dumpEnding();
    }

    dumpLastEnding();       
}

BOOL getNextIpAddress(FlagSettings *settings)
{
    if (settings->ipAdrCount > 0)
    {
        uint32_t ip = ntohl(settings->ipAdr);
        ip++;
        settings->ipAdr = htonl(ip);
        settings->ipAdrCount--;
        return TRUE;
    }
    return FALSE;
}


int main(int argc, char* argv[]) 
{
    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;
    HANDLE eventHandle;
    DWORD threadId;
    HANDLE threadHandle;
    ThreadData *data = NULL;
    FILE *file;
    fd_set writefds;
    struct timeval tv;
    int socketTimeout = SOCKET_TIMEOUT;

    // get some user input from command line argument
    if (argc > 2) 
    {
        // got a filename ? try to open
        int result = fopen_s(&file, argv[2], "r");
        if (result > 0) 
        { 
            fprintf(stderr, "Failed to open input file\n"); 
            return 1; 
        }
    }
    else
    { // no args, print instructions
        fprintf(stderr, "Usage of Read PBus IDF Harvester V.%s:\n\
  %s <IP address> <input file> <optional continous arguments>\n\
  -s<slot> select a slot and disable scanning\n\
  -xml instead of input csv\n\
  -hex in output values\n\
  -t overide task interval (default 1000 ms)\n\
  -id<module id> overides 0xC8\n\
  -ipcnt<number of ip's>\n\
example: %s 172.21.53.191 query.txt -ipcnt9\n\
will look for a modul to query at ip address through 9 next addresses\n", THIS_VER, argv[0],argv[0]);
        return 0;
    }

    // set global settings from arguments or defaults
    settings.hexFormat = (argc > 3 && strstr(argv[3], "-hex") > 0) ? TRUE : FALSE;
    settings.xmlFormat = (argc > 3 && strstr(argv[3], "-xml") > 0) ? TRUE : FALSE;
    settings.ipAdr = (argc > 1) ? inet_addr(argv[1]) : 0;
    
    // -ipcnt<number of more addresses>
    char *ip = (argc > 3) ? strstr(argv[3],"-ipcnt") : NULL;    
    uint8_t ipCount = 0; 
    if ((ip  > 0) && (ipCount = strtol(ip+6, NULL, DEC_FRM)) < 255)
    {
        settings.ipAdrCount = ipCount;
    }
    
    // -t<time in ms> in argument, overides eventhandler waiting time
    char *t = (argc >3) ? strstr(argv[3],"-t") : NULL;   
    DWORD timeoutOveride = settings.waitReplyTimeout = WAIT_REPLY_OBJECT_TIMEOUT;
    if ((t  > 0) && (timeoutOveride = strtol(t+2, NULL, DEC_FRM)) > 99)
    {
        settings.waitReplyTimeout = timeoutOveride; 
    } 
    char *c = (argc >3) ? strstr(argv[3],"-c") : NULL;
    
    // -s<slot> in argument, sets wanted slot and disables scanning for modul slot
    char *s = (argc >3) ? strstr(argv[3],"-s") : NULL;
    settings.selectedSlot = (s  > 0) ? (unsigned char) strtol(s+2, NULL, DEC_FRM) : 0;
    
    // -id<modul id> in argument, overide 0xC8 type of modul 
    char *id = (argc >3) ? strstr(argv[3],"-id") : NULL;
    settings.moduleId = (id  > 0) ? 
        (unsigned char) strtol(id+3, NULL, strstr(id+3,"0x") ? HEX_FRM : DEC_FRM) 
        : MODULE_TYPE_ID;

    //WSA init
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
    {
        fprintf(stderr, "WSAStartup error: %d\n", WSAGetLastError());
        return 1;
    }

    do {
        // setup and connect socket
        int connectResult = connectTelnet(&clientSocket, settings.ipAdr);

        if (connectResult > 0)
        {   
            eventHandle = CreateEvent(NULL, TRUE, FALSE, NULL);
            if (eventHandle == NULL) 
            {
                fprintf(stderr, "CreateEvent() error: %d\n", GetLastError());
                closesocket(clientSocket);
                WSACleanup();
                return 1;
            }

            data = (ThreadData *) malloc(sizeof(ThreadData));
            data->clientSocket = clientSocket;
            data->eventHandle = eventHandle;
            data->requestFile = file;

            // create a thread to handle reading data sendt from the SBC's telnet server
            threadHandle = CreateThread(NULL, 0, asyncSocketReader, data, 0, &threadId);
            if (threadHandle == NULL) 
            {
                fprintf(stderr, "CreateThread() error: %d\n", GetLastError());
                closesocket(clientSocket);
                free(data);
                CloseHandle(eventHandle);
                WSACleanup();
                return 1;
            }
    
            goSbcmon(eventHandle, data);
            // in sbcmon/pbi context, 
            
            // overide slot ID ?
            if (settings.selectedSlot > 0)
                thisRequest.slot = settings.selectedSlot;
            else if (slotScanner.findIdfReg.slot > 0) 
                thisRequest.slot = slotScanner.findIdfReg.slot;

            // load and setup query data
            idfTemplateInitFromFile( &idfsToFetch, data->requestFile);
            
            // fetch and fill data
            idfTemplateFetcherTask( &idfsToFetch, eventHandle, data);
            free(idfsToFetch.idfAddresses);
            
            closesocket(clientSocket);
            CloseHandle(eventHandle);
            CloseHandle(threadHandle);
            free(data);
        } 
    } while (getNextIpAddress(&settings));

    // done! close & cleanup
    fclose(file);
    WSACleanup();

    return 0;
}
