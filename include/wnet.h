#ifndef WNET_H
#define WNET_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"

#define clean_stream(stream)      (close(stream.fd))
#define clean_listener(listener)  (close(listener))
#define log_tcp_error(err)        printf("%s\n", error_log[err])
#define write_stream(client, msg) ((write(client.fd, msg, strlen(msg)) == -1) ? TCP_SEND_ERR : NO_ERR)

#define READ_CHUNK_SIZE 1024

typedef i32 TcpListener;

typedef struct {
    u16  port;
    i32  fd;
    char *addr;
} TcpStream;

typedef struct {
    SSL     *ssl;
    SSL_CTX *ctx;
} TcpSSLWrapper;

// interface for reading tcp connections
typedef struct {
    u8 *buffer;
    i32 fd;
    u64 buf_size;
    u64 capacity;
} StreamReader;

typedef enum {
    NO_ERR,
    TCP_CREAT_ERR,
    TCP_BIND_ERR,
    TCP_LIST_ERR,
    TCP_ACCP_ERR,
    TCP_SEND_ERR,
    TCP_ALLOC_ERR,
    TCP_CONN_ERR,
    TCP_NODATA_ERR,
    TCP_RESOLVE_ERR,
    TCP_KEEPALIVE_ERR,
    TCP_TMOUT_ERR
} TcpErrors;

static const char *error_log[] = {
    [NO_ERR]            = "No errors reported",
    [TCP_CREAT_ERR]     = "Error creating socket",
    [TCP_BIND_ERR]      = "Error Binding socket",
    [TCP_ACCP_ERR]      = "Error accepting connection",
    [TCP_SEND_ERR]      = "Error sending content to client",
    [TCP_ALLOC_ERR]     = "Error allocating memory for internal data structure",
    [TCP_CONN_ERR]      = "Error connecting to remote host",
    [TCP_NODATA_ERR]    = "Error, no data is available for reading",
    [TCP_RESOLVE_ERR]   = "Error resolving hostname",
    [TCP_KEEPALIVE_ERR] = "Error setting keep-alive connection",
    [TCP_TMOUT_ERR]     = "Error setting timeout"
};

void init_openssl();
SSL_CTX *create_tls13_ctx();
TcpSSLWrapper *create_openssl_conn(TcpStream stream);
void free_ssl_wrapper(TcpSSLWrapper *wrapper);

TcpErrors new_stream(TcpStream*, char*);
TcpErrors enable_keepalive(TcpStream stream);

TcpErrors set_stream_timeout(struct timeval timeout, TcpStream stream);

TcpErrors init_listener(char *addr, i32 port, TcpListener *listener);
TcpErrors incoming(TcpListener listener, TcpStream *client);

StreamReader *new_reader(TcpStream);
TcpErrors read_stream(StreamReader*);
void get_stream_data(StreamReader*, u8*);
void clean_stream_reader(StreamReader*);

#endif