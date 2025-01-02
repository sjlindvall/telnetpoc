#ifndef SBCMONSRV_H
#define SBCMONSRV_H


#define STRSIZE 256
#define INVALID -1
#define PORT 23
#define BUFSIZE 1024

typedef enum
{
    SRVST_ERROR = 0,
    SRVST_INITED,
    SRVST_LISTENING,
    SRVST_CLIENT_CONNECTED,
    SRVST_MENU_SBCMON,
    SRVST_MENU_PBI,
    SRVST_REQUEST_IDF,
    SRVST_RESPONS_IDF,
    SRVST_DISCONNECTED
} ServiceStates;

typedef struct 
{
    FILE * thisFile;
    char filename[STRSIZE];
    char ipAddress[16];
    int ipPort;
    int numberCount;
    ServiceStates state;
} Settings;

typedef struct
{
    uint8_t slot;
    uint16_t idf;
    uint16_t hex;
} IdfReg;

typedef struct
{
    uint8_t slot;
    uint16_t modid;
    char typename[16];
    char partnum[16];
    char serialnum[16];
    char hwrev[8];
    char swrev[8];
} ModInfo;

typedef struct 
{
    ModInfo  modinfo;
    IdfReg idfreg[256];
    int index;
} Database;

// Define the callback function type
typedef void (*CallbackType)(const char *message);

// Callback function that prints a message
void printMessage(const char *message) 
{
    printf("Message: %s\n", message);
}

// Another callback function that prints a different format
void printFormattedMessage(const char *message) 
{
    printf("Formatted Message: --> %s <--\n", message);
}

// Function that takes a callback and a message, and calls the callback
void performAction(CallbackType callback, const char *message) 
{
    callback(message);
}

void openFile(const char *filename, Settings *settings)
{
    strcpy(settings->filename, filename);
    settings->thisFile = fopen(settings->filename, "r");
    settings->state = (settings->thisFile != 0) ? SRVST_INITED : SRVST_ERROR;
}

void setIpAddr(const char *ipaddr, Settings *settings)
{
    strcpy(settings->ipAddress, ipaddr);
}

void interpretArgs(int cnt, char*  vals[], Settings *sets)
{
    if (cnt == 1)
    {
        printf("%s args:\n\
  -f <filename>\n\
  -ip <ip address>\n\
  -p <ip port>\n\
  -c <scan count>\n", vals[0]);
    }
    else
    {    
        //printf("Arguments:\n-------------------------\n");
        for (int n=1; n < cnt; n++)
        {
            //printf("%u : %s\n", n, vals[n]);
            if (n < cnt && strstr(vals[n],"-f") > 0)
            {
                n++;
                openFile(vals[n], sets);
            }
            else if (n < cnt && strstr(vals[n],"-ip") > 0)
            {
                n++;
                setIpAddr(vals[n], sets);
            }    
            else if (n < cnt && strstr(vals[n],"-p") > 0)
            {
                n++;
                sets->ipPort = strtol(vals[n], NULL, 10);
            }    
            else if (n < cnt && strstr(vals[n],"-c") > 0)
            {
                n++;
                sets->numberCount = strtol(vals[n], NULL,10);
            }
            else
            {
                printf("invalid argument ! %s\n", vals[n]);
            }
        }
    }
}


void printSettings(Settings *settings)
{
    printf("Settings:\n-------------------------\n\
 File       : %s\n\
 IP address : %s\n\
 IP port    : %d\n\
 Count      : %d\n\
 State      : %d\n", 
   settings->filename,
   settings->ipAddress,
   settings->ipPort,
   settings->numberCount,
   settings->state);
    printf("\n");
}

void readFile(Settings *flg, Database *db)
{
    char oneLine[STRSIZE];
    char *thisToken;
    char *rest, *more;
    char *firstArg, *secondArg, *thirdArg, *endp;
    unsigned int temp = 0;
    db->index = 0;
    int base = 16;
    // read and tokenize a line from open file
    while (fgets(oneLine, STRSIZE, flg->thisFile ) > 0)
    {
        thisToken = strtok_r(oneLine, "\t", &rest);
    // interpret first token,
        if (strstr(thisToken, "#") > 0)
        {
    // discard and do next line if token starts with '#'
            continue;
        }    
        else if (thisToken != NULL && strstr(thisToken,"idf") > 0)
        {
    // and treat rest of tokens accordingly.
            firstArg = strtok_r(rest, "\t", &more);
            base = (strstr(firstArg,"0x") > 0) ? 16 : 10;
            if (firstArg != NULL && (temp = strtol(firstArg, &endp, base)) > 0)
            {
                //printf("temp1=%x\n", temp);
                db->idfreg[db->index].slot = (uint8_t)(temp);
                secondArg = strtok_r(more, "\t", &rest);
                if (secondArg != NULL && (temp = strtol(secondArg, &endp, 16)) > 0)
                {
                    //printf("temp2=%x\n", temp);
                    db->idfreg[db->index].idf = (uint16_t)(temp);
                    thirdArg = strtok_r(rest, "\t", &more);
                    if (thirdArg != NULL && (temp = strtol(thirdArg, &endp, 16)) > 0)
                    {
                        //printf("temp3=%x\n", temp);
                        db->idfreg[db->index].hex = (uint16_t)(temp);
                        db->index++;
                    }
                }
            }
        }
    }            
}

void listDb(Database *db)
{
    printf("DB listing:\nSlot\tIDF\tHex\n---------------------\n");    
    for (int i = 0; i < db->index; i++)
    {
        printf("%d\t%x\t%x\n", db->idfreg[i].slot,db->idfreg[i].idf,db->idfreg[i].hex);
    }
    printf("\n");
}


int lkupIdfReg(Database *db, uint8_t slot, uint16_t idf)
{
    int result;
    for (int i = 0; i < db->index; i++)
    {
        // search for index
        if (db->idfreg[i].slot == slot && db->idfreg[i].idf == idf)
        {
            result = (int)(db->idfreg[i].hex);
            return result;
        }
    }
    return -1;
}

#endif