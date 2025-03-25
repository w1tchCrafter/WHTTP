#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "../include/wnet.h"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_tls13_ctx() {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}

TcpSSLWrapper *create_openssl_conn(TcpStream stream) {
    SSL_CTX *ctx = create_tls13_ctx();
    if (!ctx) return NULL;

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    TcpSSLWrapper *wrapper = malloc(sizeof(TcpSSLWrapper));
    if (!wrapper) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_set_fd(ssl, stream.fd);
    wrapper->ctx = ctx;
    wrapper->ssl = ssl;

    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        free_ssl_wrapper(wrapper);
        return NULL;
    } else {
        printf("Connected using %s\n", SSL_get_cipher(ssl));
        return wrapper;
    }
}

void free_ssl_wrapper(TcpSSLWrapper *wrapper) {
    SSL_CTX_free(wrapper->ctx);
    SSL_free(wrapper->ssl);
    free(wrapper);
}

TcpErrors set_stream_timeout(struct timeval timeout, TcpStream stream) {
    i32 fd = stream.fd;

    if ((setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) == -1) return TCP_TMOUT_ERR;
    if ((setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) == -1) return TCP_TMOUT_ERR;

    return NO_ERR;
}

TcpErrors enable_keepalive(TcpStream stream) {
    // change all this for a config struct later
    // this will also improve usage
    bool keep_alive = true;
    i32 idle_time = 5; // await 60 seconds before start probing
    i32 probe_interval = 5; // await for 10 seconds between each keep alive probe
    i32 probe_max = 5; // number of probes to send before closing the connection
    i32 fd = stream.fd;

    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof keep_alive) == -1) return TCP_KEEPALIVE_ERR;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &probe_interval, sizeof probe_interval) == -1) return TCP_KEEPALIVE_ERR;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &probe_interval, sizeof probe_interval) == -1) return TCP_KEEPALIVE_ERR;
    if (setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &probe_max, sizeof probe_max) == -1) return TCP_KEEPALIVE_ERR;

    return NO_ERR;
}

TcpErrors new_stream(TcpStream *stream, char *host) { // change this function name to something about http
    i32 sockfd, port;
    struct addrinfo hints, *result, *p;
    char *hostname, *port_str;
    char *host_copy = strdup(host);
    char ipstr[INET6_ADDRSTRLEN];

    port_str = strrchr(host_copy, ':');

    // parse host string to get hostname and port
    if (port_str != NULL && port_str[1] != '/') {
        *port_str = '\0';  // Remove ':' from port string
        port_str++;        // Move to the port part
        port = atoi(port_str);
        hostname = host_copy;
    } else {
        if (!strncmp("http://", host, 7)) {
            port = 80;
            hostname = host_copy + 7;
        } else if (!strncmp("https://", host, 8)) {
            port = 443;
            hostname = host_copy + 8;
        } else {
            port = 80;  // Default to HTTP
            hostname = host_copy;
        }

    }

    // Prepare hints
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;    // ipv4 or ipv6
    hints.ai_socktype = SOCK_STREAM;

    char *path = strrchr(host_copy, '/');
    if (path) {
        remove_suffix(hostname, path); // remove path from url if any
    }

    if (getaddrinfo(hostname, NULL, &hints, &result) != 0) {
        free(host_copy);
        return TCP_RESOLVE_ERR;
    }

    for (p = result; p != NULL; p = p->ai_next) { // search for ipv4 info
        void *addr;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);

            struct sockaddr_in host_addr = {
                .sin_family = AF_INET,
                .sin_port = htons(port),
                .sin_addr.s_addr = ipv4->sin_addr.s_addr
            };

            if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                freeaddrinfo(result);
                free(host_copy);
                return TCP_CREAT_ERR;
            }

            if (connect(sockfd, (struct sockaddr*)&host_addr, sizeof host_addr) == -1) {
                close(sockfd);
                freeaddrinfo(result);
                free(host_copy);
                return TCP_CONN_ERR;
            }

            *stream = (TcpStream) {
                .fd = sockfd,
                .addr = strdup(ipstr),
                .port = port
            };

            freeaddrinfo(result);
            free(host_copy);
            return NO_ERR;
        }
    }

    // no ipv4 available...probably...
    freeaddrinfo(result);
    free(host_copy);
    return TCP_RESOLVE_ERR;
}

TcpErrors init_listener(char *addr, i32 port, TcpListener *listener) {
    i32 sockfd;
    struct sockaddr_in srv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(addr)
    };

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) return TCP_CREAT_ERR;

    if (bind(sockfd, (struct sockaddr*)&srv_addr, sizeof(srv_addr)) == -1) {
        clean_listener(sockfd);
        return TCP_BIND_ERR;
    }

    if (listen(sockfd, 1) == -1) {
        clean_listener(sockfd);
        return TCP_LIST_ERR;
    }

    *listener = sockfd;
    return NO_ERR;
}

TcpErrors incoming(TcpListener listener, TcpStream *client) {
    struct sockaddr_in client_addr = { 0 };
    i32 client_sock;
    u32 client_size = sizeof(client_addr);

    if ((client_sock = accept(listener, (struct sockaddr*)&client_addr, &client_size)) == -1) return TCP_ACCP_ERR;

    char *addr = inet_ntoa(client_addr.sin_addr);
    u16 port = ntohs(client_addr.sin_port);

    *client = (TcpStream) {
        .fd = client_sock,
        .port = port,
        .addr = addr
    };
#ifdef DEBUG_MACRO
    printf("Client connected from %s:%d\n", client->addr, client->port);
#endif
    return NO_ERR;
}

StreamReader *new_reader(TcpStream stream) {
    StreamReader *reader = malloc(sizeof(StreamReader));
    if (!reader) return NULL;

    reader->fd = stream.fd;
    reader->buf_size = 0;
    reader->capacity = READ_CHUNK_SIZE * 100;
    reader->buffer = malloc(sizeof(char) * READ_CHUNK_SIZE);

    if (!reader->buffer) {
        free(reader);
        return NULL;
    }

    return reader;
}

// reset buffer before running this function
TcpErrors read_stream(StreamReader *reader) {
    char buf[READ_CHUNK_SIZE];
    u32 bytes;
    while ((bytes = read(reader->fd, buf, READ_CHUNK_SIZE-1)) != -1) {
        buf[bytes] = '\0';
        strcat(reader->buffer, buf);
        memset(buf, 0, sizeof buf);
    }

    puts("\nno err");
    printf("%s\n", reader->buffer);
    return NO_ERR;
}


void get_stream_data(StreamReader *reader, u8 *dest) {
    memcpy(dest, reader->buffer, reader->buf_size);
    reader->buf_size = 0;
    memset(reader->buffer, 0, reader->capacity);
}

void clean_stream_reader(StreamReader *reader) {
    free(reader->buffer);
    free(reader);
}