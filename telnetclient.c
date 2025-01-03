#include "telnetclient.h"
#include <winsock2.h>
#include <windows.h>
#include <time.h>
#include <limits.h>
# include <errno.h>

const char * stateStr[] = {
    "ACTST_ERROR",
    "ACTST_IDLE" ,
    "ACTST_CONNECT",
    "ACTST_CONNECTED",
    "ACTST_DISCONNECT",
    "ACTST_GET_NEXT",
    "ACTST_REQ_SBCMON",
    "ACTST_REPLY_SBCMON",
    "ACTST_REQ_PBI",
    "ACTST_REPLY_PBI",
    "ACTST_GET_INFOBJ",
    "ACTST_SET_INFOBJ",
    "ACTST_REQ_READIDF",
    "ACTST_GOT_READIDF",
    "ACTST_SCAN_MODSLOT",
    "ACTST_CHECK_MODSLOT",
    "ACTST_DONE"
};

FlagSettings settings; 

ActionStates currentState = ACTST_IDLE; 
ActionStates lastState = ACTST_IDLE;
BOOL interrupted = TRUE;

IdfRegister thisRequest = {0,0,0,STAT_INVALID};

InfoObj ThisInfoObj = {"Norne/PS/191/PBUS/1/8", "Norne", 191, 8, "2024:16-10T06:26:09", MODULE_TYPE_NAME, MODULE_TYPE_ID};
SlotScanning slotScanner = { STAT_DISABLED, 0, MODULE_TYPE_ID, IDFS_MODULE_ID, 0};


const char * state2str(ActionStates st)
{
    return stateStr[st+1];
}

void setNewState(ActionStates st)
{
    lastState = currentState;
    currentState = st;
    fprintf(stderr, " %s -> %s\n", state2str(lastState), state2str(currentState));
}

// update the timestamp with the current time
void updateTimeStamp(char *timestamp) 
{
    time_t now = time(NULL);
	struct tm tm_struct;
	int result = gmtime_s(&tm_struct, &now);

    char new_timestamp[] = "                                  ";
    sprintf_s(new_timestamp, sizeof(new_timestamp), "%04d:%02d-%02dT%02d:%02d:%02d",
             tm_struct.tm_year + 1900,
             tm_struct.tm_mon + 1,
             tm_struct.tm_mday,
             tm_struct.tm_hour,
             tm_struct.tm_min,
             tm_struct.tm_sec);

    strcpy_s(timestamp, sizeof(new_timestamp), new_timestamp);
}

void removeWhiteSpace(char *str) 
{
    char *i = str;
    char *j = str;
    while (*j != '\0') {
        if (!isspace((unsigned char)*j)) {
            *i = *j;
            i++;
        }
        j++;
    }
    *i = '\0';
}


/*******************************************************************************
 * PRIVATE FUNCTION:
 * expectRdi
 *
 * get data fields from string with IDF values
 ******************************************************************************/
BOOL expectRdi(const char *input, IdfRegister* data)
{
    BOOL result = str2rdi(input, data);
    if (!result) {
        if (data->status == STAT_INVALID)
            return TRUE;
        else
            return FALSE;
    }
    return result;
}

BOOL expectPbi(const char *input)
{
    return ((input > 0 && strlen(input) > 0) 
             && (strstr(input, "pbi:") > 0)) ? TRUE : FALSE;
}

BOOL expectSbcmon(const char *input)
{
    BOOL result = FALSE;
    if (input > 0 && strlen(input) > 0) 
    {
        result = (strstr(input, "Test program for") > 0);
        result &= (strstr(input, "sbcmon:") > 0);
    } 
    return  result;
}


/*******************************************************************************
 * PRIVATE FUNCTION:
 * str2rdi
 *
 * get data fields from string with IDF values received from telnet server
 * returns TRUE on successful read
 ******************************************************************************/
BOOL str2rdi(const char *input, IdfRegister* outputIdf) 
{
    const char *slotKey = "slot ";
    const char *idfKey = "idf ";
    const char *hexKey = "hex =";
    char *slotPos = strstr(input, slotKey);
    char *idfPos = strstr(input, idfKey);
    char *hexPos = strstr(input, hexKey);
    unsigned int slot = 0;
    unsigned int idf = 0;
    unsigned int val = 0;

    if (outputIdf && slotPos && idfPos && hexPos) {
        sscanf_s(slotPos + strlen(slotKey), "%u", &slot);
        if (outputIdf->slot != slot)
        {
            outputIdf->status = STAT_INVALID; 
            return FALSE;
        }
        sscanf_s(idfPos + strlen(idfKey), "%x", &idf);
        outputIdf->idf = idf;
        sscanf_s(hexPos + strlen(hexKey), "%x", &val);
        outputIdf->value = val;
        outputIdf->status = STAT_VALID_READ; 
        return TRUE;
    }
    else if (strstr(input, "error") >0)
    {
        sscanf_s(slotPos + strlen(slotKey), "%u", &slot);
        outputIdf->slot = slot;
        sscanf_s(idfPos + strlen(idfKey), "%x", &idf);
        outputIdf->idf = idf;
        outputIdf->status = STAT_READ_ERROR;
        return TRUE;
    }

    outputIdf->status = STAT_INVALID;
    return FALSE;
}

char* csv2rdi(char* line, int frm) 
{
    char input[BUFSIZE];
    static char output[BUFSIZE];
    int slot = -1;
    int offs = -1;
    long val = 0l;
    errno = 0;
    char *endp;
    char* context;
    strcpy_s(input, BUFSIZE,line);
    input[sizeof(input) - 1] = '\0'; 

    //tokenize textline
    
    char *token = strtok_s(input, CSV_SEP, &context);
    if (NULL == token) return NULL;
    while (token != NULL) 
    {
        //get numeric value
        val = strtol(token, &endp, frm);
        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) 
        {
            fprintf( stderr, "strtol() conversion error in %s\n", line);
            return NULL;
        } 
        else if (endp != token) 
        { // get the 2 last row of numbers
            offs = slot; 
            slot = (int) val;
        }
        //get for next iteration
        token = strtok_s(NULL, CSV_SEP, &context);
    }

    if (slot < 0 || offs < 0) 
    {
        //some value invalid
        fprintf( stderr, "csv2rdi() invalid values in %s\n", line);
        return NULL;
    }
    else
    {
        //got good stuff, make a rdi request message
        sprintf_s(output, sizeof(output), "rdi %x %d\n", offs, slot);
        return output;
    }
}

char* getXMLattributeValue(const char *str, const char *attribute, char *buffer, size_t bufferSize) 
{
    char searchPattern[256];
    sprintf_s(searchPattern, sizeof(searchPattern), "%s='", attribute);
    
    const char *start = strstr(str, searchPattern);
    if (start) {
        start += strlen(searchPattern);
        const char *end = strchr(start, '\'');
        if (end) {
            size_t length = end - start;
            if (length < bufferSize) {
                strncpy_s(buffer, sizeof(buffer), start, length);
                buffer[length] = '\0';
                return buffer;
            }
        }
    }
    return NULL;
}

void setXMLattributeValue(char *str, const char *attrName, const char *newValue) 
{
    char searchPattern[256];
    sprintf_s(searchPattern, sizeof(searchPattern), "%s='", attrName);
    
    char *start = strstr(str, searchPattern);
    if (start) {
        start += strlen(searchPattern);
        char *end = strchr(start, '\'');
        if (end) {
            size_t newValueLen = strlen(newValue);
            size_t remainingLen = strlen(end);
            memmove(start + newValueLen, end, remainingLen + 1); 
            memcpy(start, newValue, newValueLen);
        }
    }
}

void handleReply(ThreadData *data)
{
    switch (currentState) 
    {
        case ACTST_REPLY_SBCMON:
            if (expectSbcmon(data->buffer))
            {
                setNewState(ACTST_REQ_PBI);
            }
            else
            {
                setNewState(ACTST_ERROR);
            }
            break;

        case ACTST_REPLY_PBI:
            if (expectPbi(data->buffer)) 
            {
                setNewState(ACTST_GET_NEXT);
            }
            break;

TRY_READIDF_AGAIN:
        case ACTST_GOT_READIDF:
            thisRequest.status = STAT_INVALID;
            if (expectRdi(data->buffer, &thisRequest))
            {
                settings.indexCount = (settings.indexCount < 255) ? settings.indexCount + 1 : 1 ;
                
                if (interrupted)
                {
                    break;
                }
                
                printIDF(&thisRequest);
                setNewState(ACTST_GET_NEXT);
                break;                        
            } 
            break;

        case ACTST_CHECK_MODSLOT:
            if (expectRdi(data->buffer, &slotScanner.findIdfReg))
            {
                if (slotScanner.findIdfReg.status == STAT_VALID_READ &&
                    slotScanner.findIdfReg.idf == slotScanner.idfModuleId && 
                    slotScanner.findIdfReg.value == slotScanner.valueModuleId)
                { // correct modultype found, disable scan and update 
                    slotScanner.searchStatus = STAT_SLOT_FOUND;
                    slotScanner.foundSlot = slotScanner.findIdfReg.slot;
            
                    if (interrupted) break;
                    setNewState(ACTST_SET_INFOBJ);
                    break;
                }
                else if ((slotScanner.searchStatus == STAT_SCANNING || 
                        slotScanner.findIdfReg.status == STAT_READ_ERROR) &&
                        slotScanner.findIdfReg.slot < LAST_SLOT) 
                { // not this one, try next slot
                    slotScanner.findIdfReg.slot++;
                    setNewState(ACTST_SCAN_MODSLOT);
                    break;
                }
                else            
                // no moduletype found on this unit, exit
                {
                    slotScanner.findIdfReg.slot = 0;
                    slotScanner.findIdfReg.status = STAT_INVALID;
                    slotScanner.searchStatus = STAT_NO_SLUT_FOUND;
                    setNewState(ACTST_DONE);
                    break;
                }
            }
            break;

        case ACTST_DONE:
            interrupted = TRUE;
            break;

        case ACTST_ERROR:
            fprintf( stderr, "Error in %s\n", state2str(lastState));
            setNewState(ACTST_GET_NEXT);
            break;

        default:
            fprintf(stderr, "Unexpected %s after %s\n", state2str(currentState), state2str(lastState));
            //if (LastState == ACTST_GOT_READIDF) goto TRY_READIDF_AGAIN;
            break;       
    };
}

void runCurrentState(ThreadData *data)
{
    char telnetCmd[BUFSIZE];
    static int handleRetry = 10;

    switch (currentState)
    {
        case ACTST_IDLE:
            // in correct SBCMON context, 
            // nothing to do, go get a job
            if (settings.xmlFormat)
            {
                setNewState(ACTST_GET_NEXT);
                break;
            } 
                
            break;

        case ACTST_GET_NEXT:
            // get next task to do
            
            break;

        case ACTST_ERROR:
            fprintf(stderr, "ACTST_ERROR!\n");
            setNewState(ACTST_DONE);
            break;

        case ACTST_CONNECT:
            break;

        case ACTST_CONNECTED:
            {
                struct in_addr addr;
                addr.S_un.S_addr = settings.ipAdr;
                //printf("'%s' is connected, entering SBCMON now\n", inet_ntoa(addr));
                setNewState(ACTST_REQ_SBCMON);
            }
            break;

        case ACTST_REQ_SBCMON:
            sendTelnetRequest(data->clientSocket, "sbcmon\r\n");  // Send a command to open telnet session
            setNewState(ACTST_REPLY_SBCMON);
            break;

        case ACTST_REQ_PBI:
            sendTelnetRequest(data->clientSocket, "pbi\r\n");  // Send a command to open telnet session
            setNewState(ACTST_REPLY_PBI);
            break;

        case ACTST_GET_INFOBJ:
            //no slot ? 
            if (0 == settings.selectedSlot)
            { // find slot with the right moduleId, start slot scanning
                if (slotScanner.searchStatus == STAT_DISABLED)
                {
                    slotScanner.idfModuleId = IDFS_MODULE_ID;
                    slotScanner.valueModuleId = settings.moduleId;
                    slotScanner.findIdfReg.status = STAT_INVALID;
                    slotScanner.findIdfReg.slot = FIRST_SLOT;
                    slotScanner.findIdfReg.idf = slotScanner.idfModuleId;
                    slotScanner.findIdfReg.value = 0;
                    setNewState(ACTST_SCAN_MODSLOT);
                    break;    
                }
                else
                {
                    slotScanner.findIdfReg.slot = 0;
                    setNewState(ACTST_GET_NEXT);
                    break;
                }
            } // selected slot has a value, use it
            else thisRequest.slot = settings.selectedSlot;
            
            setNewState(ACTST_SET_INFOBJ);
            break;

        case ACTST_REQ_READIDF:
        {           
            if (thisRequest.slot > 0 && thisRequest.idf > 0) 
            {
                sprintf_s(telnetCmd, sizeof(telnetCmd), "rdi %x %u\n", thisRequest.idf, thisRequest.slot);
                sendTelnetRequest(data->clientSocket, telnetCmd);
                setNewState(ACTST_GOT_READIDF);
            }
            else setNewState(ACTST_ERROR);
        }
        break;

        case ACTST_SCAN_MODSLOT:
			sprintf_s(telnetCmd, sizeof(telnetCmd), "rdi %x %u\n", slotScanner.findIdfReg.idf, slotScanner.findIdfReg.slot);
            sendTelnetRequest(data->clientSocket, telnetCmd);
            setNewState(ACTST_CHECK_MODSLOT);
            break;

        case ACTST_DISCONNECT:
            setNewState(ACTST_DONE);
            break;

        default:
            if (!handleRetry--) 
            {
                handleReply(data);
                handleRetry = 10;
            }
            break;
    }
}

/*******************************************************************************
 * PRIVATE FUNCTION:
 * eventHandler
 *
 * Event handler for the threaded socket listener and CurrentState runner
 ******************************************************************************/
void eventHandler(HANDLE eventHandle, ThreadData *data) 
{
    while (1) 
    {
        DWORD waitResult = WaitForSingleObject(eventHandle, settings.waitReplyTimeout  /*INFINITE*/);
        
        if (waitResult == WAIT_OBJECT_0) 
        {
            // got received data, do something
            handleReply(data);
        }
        
        else if (waitResult == WAIT_TIMEOUT) 
        {
            // waited long enough for received data, do something else
            if (ACTST_DONE == currentState || ACTST_ERROR == currentState) 
            {
                interrupted = TRUE;
                break; // done, quit
            }
            // run the current task
            runCurrentState(data); 
        }

        Sleep(1);

        ResetEvent(eventHandle);
        //if in interrupted mode, exit to callee
        if (interrupted) break;   
    }
}


// Thread function for handling server communication
DWORD WINAPI asyncSocketReader(LPVOID lpParam) 
{
    ThreadData *data = (ThreadData *)lpParam;
    SOCKET clientSocket = data->clientSocket;
    HANDLE eventHandle = data->eventHandle;

    int bytes = 0;
    int again = 0;
    char recvBuffer[BUFSIZE];
    char moreBuffer[BUFSIZE];
    memset(recvBuffer, 0, BUFSIZE);
    memset(moreBuffer, 0, BUFSIZE);

    while ((bytes = recv(clientSocket, recvBuffer, BUFSIZE, 0)) > 0) 
    {
        recvBuffer[bytes] = '\0';
        //fprintf(stderr, "Thread received data: %s\n", recvBuffer);

        memset(data->buffer,0, BUFSIZE);
        strcat_s(data->buffer, sizeof(data->buffer), recvBuffer);

        if (bytes < 3) {
            //missing data, try again
            Sleep(20);
            again = recv(clientSocket, moreBuffer, BUFSIZE, 0);
            if (again > 0)
            {
                moreBuffer[again] = '\0';
				strcat_s(data->buffer, sizeof(data->buffer), moreBuffer);
                fprintf(stderr, "Thread received again! : %s\n", data->buffer);
            }
        }

        SetEvent(eventHandle);
    }

    closesocket(clientSocket);
    return 0;
}

/*******************************************************************************
 * PRIVATE FUNCTION:
 * sendTelnetRequest
 *
 * send data to an open client socket
 ******************************************************************************/
void sendTelnetRequest(SOCKET clientSocket, const char *data) 
{
    int len = strlen(data);
    if (len < 1) return;
    int bytesSent = send(clientSocket, data, len, 0);
    if (bytesSent == SOCKET_ERROR) 
    { 
        fprintf(stderr, "send failed: %d\n", WSAGetLastError()); 
    } 
    else 
    { 
        fprintf(stderr, "Sent data: %s\n", data);
    } 
}

int connectTelnet(SOCKET *clientSocket, uint32_t serverIp)
{
    struct sockaddr_in serverAddr;
    int connectResult;
    int connectThis;
    int socketTimeout = SOCKET_TIMEOUT;
    fd_set writefds;
    struct timeval tv;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = serverIp;
    serverAddr.sin_port = htons(TELNET_PORT);

    *clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (*clientSocket == INVALID_SOCKET) 
    {
        fprintf(stderr, "Socket creation error: %d\n", WSAGetLastError());
        WSACleanup();
        exit(1);
    }

    // Set the socket timeout options, to prevent long failed connects 
    // Set the socket to non-blocking mode
    u_long mode = 1;
    ioctlsocket(*clientSocket, FIONBIO, &mode);

    // Attempt to connect
    connectThis = connect(*clientSocket, (struct sockaddr*) &serverAddr, sizeof(serverAddr));

    FD_ZERO(&writefds);
    FD_SET(*clientSocket, &writefds);
    tv.tv_sec = socketTimeout / 1000;
    tv.tv_usec = (socketTimeout % 1000) * 1000;

    // Wait for socket writable or connection timeout
    connectResult = select(0, NULL, &writefds, NULL, &tv);

    if (connectResult > 0 && FD_ISSET(*clientSocket, &writefds)) {
        setNewState(ACTST_CONNECTED);
    } else {
        struct in_addr addr;
        addr.S_un.S_addr = settings.ipAdr;
        fprintf(stderr, "Connect '%s' failed : %d\n", inet_ntoa(addr), WSAGetLastError());
        closesocket(*clientSocket);
        //WSACleanup();
        return connectThis;
    }

    // revert socket to blocking mode again
    mode = 0;
    ioctlsocket(*clientSocket, FIONBIO, &mode);
    return connectResult;
}

void goSbcmon(HANDLE eventHandle, ThreadData *data)
{
    while (currentState != ACTST_GET_NEXT)
    {
        eventHandler(eventHandle, data);
        //printf("Interrupted! %s\n", state2str(CurrentState) );
    }
}

BOOL getNextSlotId(HANDLE eventHandle, ThreadData *data, IdfRegister *checkSlot)
{
    //find a slot with the right moduleId
    if (slotScanner.searchStatus == STAT_DISABLED)
    {
        slotScanner.idfModuleId = IDFS_MODULE_ID;
        slotScanner.valueModuleId = settings.moduleId;
        slotScanner.findIdfReg.status = STAT_INVALID;
        slotScanner.findIdfReg.slot = FIRST_SLOT;
        slotScanner.findIdfReg.idf = slotScanner.idfModuleId;
        slotScanner.findIdfReg.value = 0;
        slotScanner.searchStatus = STAT_SCANNING;
    }
    else if (slotScanner.searchStatus == STAT_SLOT_FOUND)
    {   // continue scanning for next
        slotScanner.findIdfReg.slot++;
        slotScanner.searchStatus = STAT_SCANNING;
    }

    setNewState(ACTST_SCAN_MODSLOT);      

    while (slotScanner.searchStatus < STAT_SLOT_FOUND &&
            currentState != ACTST_DONE)
    {
        eventHandler(eventHandle, data);
        printf("");
        //printf("Interrupted! %s\n", state2str(CurrentState) );
    }

    if (slotScanner.searchStatus == STAT_SLOT_FOUND)  
    {
        checkSlot->slot = slotScanner.findIdfReg.slot;
        checkSlot->idf = slotScanner.findIdfReg.idf;
        checkSlot->value = slotScanner.findIdfReg.value;
        return TRUE;
    }
    return FALSE;
}

BOOL getIdfRegister(HANDLE eventHandle, ThreadData *data, IdfRegister *getIdf)
{
    thisRequest.slot = getIdf->slot;
    thisRequest.idf = getIdf->idf;
    thisRequest.status = STAT_INVALID;
    setNewState(ACTST_REQ_READIDF);
    while (currentState != ACTST_GOT_READIDF)
    {
        eventHandler(eventHandle, data);
        printf("");
        //printf("Interrupted! %s\n", state2str(CurrentState) );
        if (currentState == ACTST_ERROR || currentState == ACTST_DONE) return FALSE;
    }
    eventHandler(eventHandle, data);
    getIdf->value = thisRequest.value;
    getIdf->status = thisRequest.status;              
    return (thisRequest.status == STAT_VALID_READ);
}

/*******************************************************************************
 * PRIVATE FUNCTION:
 * getaLineFromFile
 *
 * read one line from a file
 ******************************************************************************/
BOOL getaLineFromFile(FILE* file, char* line, size_t maxLength) 
{  
    if (fgets(line, maxLength, file) == NULL) 
    { 
        fprintf(stderr, "end of input file\n");
        return FALSE;       
    }
    return TRUE;
} 
