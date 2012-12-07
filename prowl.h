#ifndef PROWL_H_
#define PROWL_H_

#define STRICT

#define SSL_PORT 443
#define HOSTNAME "prowl.weks.net"
#define MESSAGESIZE 11400
#define BUFFERSIZE 512

/* priorities */
#define PROWL_PRIORITY_VERY_LOW -2
#define PROWL_PRIORITY_MODERATE -1
#define PROWL_PRIORITY_NORMAL 0
#define PROWL_PRIORITY_HIGH 1
#define PROWL_PRIORITY_EMERGENCY 2

#define SOCKET int
#define SOCKET_ERROR -1
#define closesocket(socket) close(socket)
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* openssl headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* ssl/connection structure */
typedef struct {
    SOCKET socket;
    SSL* ssl_handle;
    SSL_CTX* ssl_context;
} prowl_connection;

int prowl_push_msg(char* api_key, int priority, char* application_name, char* event_name, char* description);

#endif