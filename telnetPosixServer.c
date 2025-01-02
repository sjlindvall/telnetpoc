#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include "sbcmonsrv.h"


Settings globals;
Database database;
IdfReg idfreg;

// Define the callback function type
typedef void (*CallbackType)(const char *message);

void handleArguments(int cnt, char*  vals[], Settings *sets)
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
        printf("Arguments:\n-------------------------\n");
        for (int n=1; n < cnt; n++)
        {
            printf("%u : %s\n", n, vals[n]);
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


typedef void (*ServiceCbt)(int argc, const char * args[]);

// Structure to hold the data to be passed to the thread
typedef struct {
    int clientSocket;
    pthread_mutex_t *mutex;
    char buffer[BUFSIZE];
    ServiceCbt service;
    ServiceStates state;
} ThreadData;


// Function to send data to an open client socket
void sendReply(int sock, const char *data) {
    ssize_t bytesSent = send(sock, data, strlen(data), 0);
    if (bytesSent == -1) {
        printf("send failed: %s\n", strerror(errno));
    } else {
        printf("sendt data: %s\n", data);
    }
}

void runConsole(ThreadData *context)
{
    printf("[%d]received data: %s\n", context->state, context->buffer);
ONE_MORE_TIME:    
    switch (context->state) {

        case SRVST_CLIENT_CONNECTED:
            if (strstr(context->buffer,"sbcmon")>0)
            {
                context->state = SRVST_MENU_SBCMON;
                sendReply(context->clientSocket, "Test program RCU bla bla\n\nSBCMON:");
            }
            else if (strstr(context->buffer,"\n") > 0)
            {
                sendReply(context->clientSocket, "->");
            }
            printf("SRVST_CLIENT_CONNECTED\n");
            break;

        case SRVST_MENU_SBCMON:
            if (strstr(context->buffer,"q")>0)
            {
                context->state = SRVST_CLIENT_CONNECTED;
                sendReply(context->clientSocket, "->");
            }
            else  if (strstr(context->buffer,"pbi")>0)
            {
                context->state = SRVST_MENU_PBI;
                printf("SRVST_MENU_PBI\n");
                sendReply(context->clientSocket, "SBCMON/PBI:");
            }
            else if (strstr(context->buffer,"\n") > 0)
            {
                sendReply(context->clientSocket, "SBCMON:");
            }
            printf("SRVST_MENU_SBCMON\n");
            break;

        case SRVST_MENU_PBI:
            if (strstr(context->buffer,"q")>0)
            {
                context->state = SRVST_MENU_SBCMON;
                sendReply(context->clientSocket, "SBCMON:");
            }
            else  if (strstr(context->buffer,"rdi")>0)
            {
                char * args  = strdup(context->buffer);
                char *argCmd, *argSlot, *argIdf;
                int slot;
                int idf;
                argCmd = strtok(args," ");
                argSlot = strtok(NULL, " ");
                argIdf = strtok(NULL, " ");
                if (argCmd != NULL && argSlot != NULL && argIdf != NULL)
                {
                    printf("arg %s %s %s\n", argCmd, argSlot, argIdf);
                    slot = strtol(argSlot, NULL, 10);
                    idf = strtol(argSlot, NULL, 16);
                    printf("int %d %d\n", slot, idf);
                    idfreg.slot = (uint8_t) slot;
                    idfreg.idf = (uint16_t) idf;
                    context->state = SRVST_REQUEST_IDF;
                    goto ONE_MORE_TIME;
                }
            }
            else if (strstr(context->buffer,"\n") > 0)
            {
                sendReply(context->clientSocket, "SBCMON/PBI:");
            }
            printf("SRVST_MENU_PBI\n");
            break;

        case SRVST_REQUEST_IDF:
            printf("IDF %d %x\n", idfreg.slot, idfreg.idf);
            context->state = SRVST_MENU_PBI;
            break;

        case SRVST_ERROR:
            break;
        default:
            break;
    }
}


// Thread function for handling client communication
void *ClientHandler(void *arg) {
    ThreadData *data = (ThreadData *)arg;
    int clientSocket = data->clientSocket;
    ssize_t bytesReceived;

    data->state =  SRVST_CLIENT_CONNECTED;
    sendReply(clientSocket, "->");
    while ((bytesReceived = recv(clientSocket, data->buffer, BUFSIZE, 0)) > 0) {
        data->buffer[bytesReceived] = '\0';
        pthread_mutex_lock(data->mutex);
        // Do some stuff with the received data
        runConsole(data);
        pthread_mutex_unlock(data->mutex);
    }

    close(clientSocket);
    free(data);
    return NULL;
}

// Event handler function
void EventHandler(pthread_mutex_t *mutex, ThreadData *data) {
    char line[BUFSIZE];

    while (1) {
        pthread_mutex_lock(mutex);
        if (strlen(line) > 0) {
            if (strstr(line, "noe") == NULL) {
                sendReply(data->clientSocket, "noe 1234  5678 FFFF");
            } else {
                printf("Echo data: %s\n", line);
                sendReply(data->clientSocket, line);  // Send data to open client socket
            }
            strcpy(line, "");
        }
        pthread_mutex_unlock(mutex);
        // Sleep for a short period to prevent busy-waiting
        usleep(100000);  // 100 milliseconds
    }
}

int main(int argc, char *argv[]) 
{
    int listenSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t addrLen = sizeof(clientAddr);
    pthread_t thread;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    handleArguments(argc, argv, &globals);
    printSettings(&globals);
    if (globals.state == SRVST_ERROR) exit(1);

    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket == -1) {
        printf("Socket creation failed: %s\n", strerror(errno));
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons((globals.ipPort > 0) ? globals.ipPort : PORT);

    if (bind(listenSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
        printf("Bind failed: %s\n", strerror(errno));
        close(listenSocket);
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == -1) {
        printf("Listen failed: %s\n", strerror(errno));
        close(listenSocket);
        return 1;
    }

    printf("Listening for connections on port %d...\n", ntohs(serverAddr.sin_port));

    while ((clientSocket = accept(listenSocket, (struct sockaddr *)&clientAddr, &addrLen)) != -1) {                        
        printf("Client %s connected.\n", inet_ntoa(clientAddr.sin_addr));

        ThreadData *data = (ThreadData *)malloc(sizeof(ThreadData));
        data->clientSocket = clientSocket;
        data->mutex = &mutex;

        // Create thread to handle client communication
        if (pthread_create(&thread, NULL, ClientHandler, data) != 0) {
            printf("Thread creation failed: %s\n", strerror(errno));
            close(clientSocket);
            free(data);
        } else {
            pthread_detach(thread);  // Detach thread to automatically clean up resources
        }
    }

    close(listenSocket);
    pthread_mutex_destroy(&mutex);

    return 0;
}
