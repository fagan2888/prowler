#include "prowl.h"


static int prowl_get_response_code(char* response);
static prowl_connection* prowl_ssl_connect();
static SOCKET prowl_tcp_connect();
static char* prowl_ssl_read(prowl_connection* c);
static void prowl_ssl_disconnect(prowl_connection* c);
static char prowl_int_to_hex(char code);
static char* prowl_url_encode(char* str);

int prowl_push_msg(char* api_key, int priority, char* application_name, char* event_name, char* description)
{
    prowl_connection* c;
    char buffer[MESSAGESIZE];
    char* response = NULL;

    application_name = prowl_url_encode(application_name);
    event_name = prowl_url_encode(event_name);
    description = prowl_url_encode(description);

    if ((c = prowl_ssl_connect()) == NULL) goto end;

    sprintf(buffer, "GET /publicapi/add?apikey=%s&priority=%d&application=%s&event=%s&description=%s\r\nHost: %s\r\n\r\n",
            api_key, priority, application_name, event_name, description, HOSTNAME);
    if (SSL_write(c->ssl_handle, buffer, strlen(buffer)) <= 0) {
        fprintf(stderr, "Failed to write buffer to SSL connection\n");
        ERR_print_errors_fp(stderr);
        goto end;
    }

    response = prowl_ssl_read(c);

    prowl_ssl_disconnect(c);

end:

    free(application_name);
    free(event_name);
    free(description);

    return (response == NULL ? -1 : prowl_get_response_code(response));
}

static int prowl_get_response_code(char* response)
{
    int code;
    char* start = strstr(response, "<prowl>");

    /* invalid response */
    if (start == NULL) return -1;

    start = strstr(start, "code");

    /* invalid response */
    if (start == NULL) return -1;

    /* failed to parse code */
    if (sscanf(start, "code=\"%d\"", &code) != 1) return -1;

    free(response);

    return code;
}

static prowl_connection* prowl_ssl_connect()
{
    prowl_connection* c = (prowl_connection*)malloc(sizeof(prowl_connection));

    c->socket = prowl_tcp_connect();

    if (c->socket != SOCKET_ERROR) {
        SSL_library_init();
        SSL_load_error_strings();

        c->ssl_context = SSL_CTX_new(SSLv23_client_method());
        if (c->ssl_context == NULL) ERR_print_errors_fp(stderr);

        c->ssl_handle = SSL_new(c->ssl_context);
        if (c->ssl_handle == NULL) ERR_print_errors_fp(stderr);

        SSL_CTX_set_verify(c->ssl_context, SSL_VERIFY_PEER, SSL_VERIFY_NONE);

        if (!SSL_set_fd(c->ssl_handle, c->socket)) ERR_print_errors_fp(stderr);
        if (SSL_connect(c->ssl_handle) != 1) ERR_print_errors_fp(stderr);
    } else {
        perror("Prowl: Failed to retrieve connected socket");
    }

    return c;
}

static SOCKET prowl_tcp_connect()
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in server;
    struct hostent* host = gethostbyname(HOSTNAME);

    if (s == SOCKET_ERROR) {
        perror("Prowl: Could not create socket");
    }

    if (host == NULL) {
        perror("Prowl: Could not retrieve host by name");
    }

    memset(&server, 0, sizeof(struct sockaddr_in));
    server.sin_family = AF_INET;
    server.sin_port = htons(SSL_PORT);
    server.sin_addr = *(struct in_addr*)host->h_addr;

    if (connect(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        perror("Prowl: connect error");
    }

    return s;
}

static char* prowl_ssl_read(prowl_connection* c)
{
    int r = 1;
    char buffer[BUFFERSIZE];
    int size = BUFFERSIZE + 1;
    char* retval = (char*)malloc(size);

    memset(retval, 0, size);

    while (r > 0) {
        r = SSL_read(c->ssl_handle, buffer, BUFFERSIZE);
        if (r > 0) {
            buffer[r] = '\0';
            retval = realloc(retval, size + r);
            strcat(retval, buffer);
        }
    }

    return retval;
}

static void prowl_ssl_disconnect(prowl_connection* c)
{
    if (c->socket) {
        closesocket(c->socket);
    }

    if (c->ssl_handle) {
        SSL_shutdown(c->ssl_handle);
        SSL_free(c->ssl_handle);
    }

    if (c->ssl_context) {
        SSL_CTX_free(c->ssl_context);
    }

    free(c);
}

static char prowl_int_to_hex(char code)
{
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

static char* prowl_url_encode(char* str)
{
    char* pstr = str;
    char* buf = (char*)malloc(strlen(str) * 3 + 1);
    char* pbuf = buf;

    while (*pstr) {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~') {
            *pbuf++ = *pstr;
        } else {
            *pbuf++ = '%';
            *pbuf++ = prowl_int_to_hex(*pstr >> 4);
            *pbuf++ = prowl_int_to_hex(*pstr & 15);
        }

        pstr++;
    }
    *pbuf = '\0';

    return buf;
}