#include <ctype.h>
#include <regex.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "../include/whttp.h"

#define START_BUF 1024

bool whttp_should_use_keepalive(char *host) {
    HttpRequest req = whttp_new_request(HTTP_METHOD_OPTIONS, host, NULL, NULL, 0); 
    HttpResponse res = whttp_do_request(NULL, req);
    char *connection_type = whttp_get_header(res, "Connection");
    bool result = false;

    if (connection_type) {
        if (!strcmp(connection_type, "keep-alive")) result = true;
        else if (!strcmp(connection_type, "close")) result = false; // redundant, but i like to make things clear
    }

    whttp_clean_request(req);
    free(res.status);
    whttp_clean_header(res);

    return result;
}

static HttpClient *whttp_default_client(char *host) {
    HttpClient *client = malloc(sizeof(HttpClient));
    if (!client) return NULL;

    *client = (HttpClient) {
        .follow_redirect = true,
        .redirect_count = HTTP_CLIENT_REDIRECT_MAX,
        .keepalive = false, ////////////////////// change to use the above function
        .timeout = (struct timeval) {
            .tv_sec = 5,
            .tv_usec = 0
        }
    };

    return client;
}

static char *get_http_status(char *response_data) { //throwing error
    char *buf = malloc(sizeof(char) * 4);
    char *code = strchr(response_data, ' ');

    *code++;
    memset(buf, 0, 4);
    strncpy(buf, code, 3);
    buf[4] = '\0';

    return buf;
}

static char *get_http_status_msg(char *response_data) {
    char *buf;
    char *code = strchr(response_data, ' ');
    u32 count = 0;
    code += 5;

    while (*code && !isspace(*code)) {
        code++;
        count++;
    }
    
    code -= count;
    buf = malloc(sizeof(char) * count);
    memset(buf, 0, count);
    strncpy(buf, code, count);
    buf[count] = '\0';

    return buf;
}

static char *get_host_path(char *host) { // free returned value after using this function
    u32 len = strlen(host);
    u32 count = 0;

    while (*host != '/' && *host) {
        host++;
        len++;
    }

    char *path = malloc(sizeof(char) * (len - count));
    (*host == '/') ? strcpy(path, host) : strcpy(path, "/");
    return path;
}

// this helper function returns the number of chars to be removed from a url string
static u32 whttp_get_protocol(char *host) {
    if (!strncmp("http://", host, 7)) return 7;
    else if (!strncmp("https://", host, 8)) return 8;
    return 0;
}

HttpHeader whttp_new_header() {
    const u32 HEADER_STARTER_CAP = 16;
    _headerValue *headers = malloc(sizeof(_headerValue) * HEADER_STARTER_CAP);

    return (HttpHeader) {
        .values = headers,
        .capacity = HEADER_STARTER_CAP,
        .size = 0
    };
}


i32 __whttp_get_header__(HttpHeader headers, char *key) {
    for (u32 i = 0; i < headers.size; i++) {
        if (!strcmp(key, headers.values[i].key)) return i;
    }

    return -1;
}

// update header value if it already exists
// add return value to indicate errors
void __whttp_set_header__(HttpHeader *header, char *key, char *value) {
    i32 index;
    if ((index = __whttp_get_header__(*header, key)) != -1) { // check if key already exists
        free(header->values[index].data);
        header->values[index].data = strdup(value);
        return;
    }

    if (header->size == header->capacity) {
        header->capacity += header->capacity;
        header->values = realloc(header->values, sizeof(_headerValue) * header->capacity);
    }

    header->values[header->size] = (_headerValue) {
        .key = strdup(key),
        .data = strdup(value)
    };

    header->size++;
}

// transform http header struct into raw string data
char *whttp_parse_header(HttpHeader header) {
    char *header_literal = malloc(sizeof(char) * START_BUF);
    u32 capacity = START_BUF;
    u32 len = 0;

    if (!header_literal) return NULL;

    for (u32 i = 0; i < header.size; i++) {
        char buf[512];
        u32 buf_len;

        format(
            buf, sizeof(buf),
            "%s: %s\r\n",
            header.values[i].key, header.values[i].data
        );

        buf_len = strlen(buf);

        if (len + buf_len > capacity) {
            capacity += START_BUF;
            header_literal = realloc(header_literal, sizeof(char) * capacity);

            if (!header_literal) return NULL;
        }

        strcat(header_literal, buf);
        len += buf_len;
    }

    return header_literal;
}

// add method to free memory
// discard header literal values, use http_parse_header instead
HttpRequest whttp_new_request(char *method, char *host, void *body, char *content_type, u64 body_len) {
    char *ht_method = strdup(method);
    char *host_cpy = strdup(host);
    char *path;
    u32 mv = whttp_get_protocol(host_cpy);
    HttpHeader headers = whttp_new_header();
    TcpStream s;

    host_cpy += mv;
    path = get_host_path(host_cpy);
    remove_suffix(host_cpy, path);
    new_stream(&s, host);

    bool use_tls = (mv == 8) ? true : false;

    HttpRequest req = {
        .url = strdup(host), //free
        .host = strdup(host_cpy), //free
        .path = path,         //free
        .method = ht_method, //free
        .conn = s,           //free using given method
        .content_len = body_len,
        //.reader = new_reader(s),  //obsolete
        .headers = headers,  //free
        .use_tls = use_tls,
        .body = NULL // change later
    };

    // using http/1.1 by default
    // http/1.1 requires this header to work
    whttp_set_header(req, "Host", req.host);
    whttp_set_header(req, "User-Agent", "whttp/1.1");
    whttp_set_header(req, "Connection", "close");

    if (!body) { req.body = ""; }
    else { req.body = body; }

    if (should_have_body(req.method) && content_type != NULL) {
        char strbuf[64]; // i doubt this number is gonna be so long...
        format(strbuf, sizeof(strbuf), "%ld", body_len); // convert long int to string
        whttp_set_header(req, "Content-Type", content_type);
        whttp_set_header(req, "Content-Length", strbuf);
    }

    host_cpy -= mv;
    free(host_cpy);
    return req;
}

static HttpHeader whttp_parse_response_headers(char *data) {
    regex_t reg;
    char *token;
    char *cp = strdup(data);
    const char *delim = "\r\n";
    const char *pattern = "^[[:alnum:]-]+:[[:space:]]+.*$";
    HttpHeader headers = whttp_new_header();

    if (regcomp(&reg, pattern, REG_EXTENDED | REG_ICASE) != 0) {
        fprintf(stderr, "Error compiling regular expression\n");
        return headers;
    }

    token = strtok(cp, delim);
    token = strtok(NULL, delim); // skip http status code line

    do {
        if ((regexec(&reg, token, 0, (regmatch_t*)NULL, 0)) == 0) {
            i32 count = 0;
            char *value = strchr(token, ' ');
            *value++;

            while (*token && *token != ':') {
                token++;
                count++;
            } 

            char key[count+1];
            token -= count;
            memset(key, 0, sizeof(key)); // don't ask me why, but the output bugs when i dont initialize this variable to zero
            strncpy(key, token, count);
            key[count+1] = '\0';
            printf("header -> %s: %s\n", key, value);

            __whttp_set_header__(&headers, key, value);
        }
        else break;
    } while(token = strtok(NULL, delim));

    free(cp);
    return headers;
}

static void *whttp_parse_response_body(u8 *response_data, u64 content_len) {
    void *buf = malloc(content_len);
    if (!buf) return NULL;

    u8 *body = strstr(response_data, "\r\n\r\n"); // use crlf to find end of headers
    if (!body) return NULL;

    body += 4; // ignore crlf
    memset(buf, 0, content_len);
    memcpy(buf, body, content_len);

    return buf;
}

HttpResponse whttp_parse_response(void *response_data, char *host) {
#define GET_HEADER_DATA(H, KEY)                  \
({                                               \
    i32 index = __whttp_get_header__(headers, KEY);  \
    (index == -1) ? "" : (H.values[index].data); \
})

//test macro
#define STR_TO_LONG(str) ((!strcmp(str, "") ? 0 : atol(str)))

    char *status = get_http_status(response_data);
    char *status_msg = get_http_status_msg(response_data);
    HttpStatus status_code = atoi(status);
    HttpHeader headers = whttp_parse_response_headers((char*) response_data);
    void *body = response_data;
    char *content_len_str = GET_HEADER_DATA(headers, "Content-Length");
    u64 content_len = STR_TO_LONG(content_len_str);

    free(status);

    // add server and client addr
    return (HttpResponse) {
        .host = strdup(host), //free
        .status = status_msg, //free
        .status_code = status_code,
        .content_len = content_len,
        .headers = headers, //free using given method
    };
#undef GET_HEADER_DATA
#undef STR_TO_LONG
}

static HttpResponse send_https_request(HttpRequest req, u8 *data) {
    init_openssl();
    TcpSSLWrapper *wrapper = create_openssl_conn(req.conn);

    if (!wrapper) {
        ERR_print_errors_fp(stderr);
        return __whttp_initialize_empty_response__();
    }

    HttpResponse res;
    u64 bytes, copied = 0;
    u64 len = 1024 * 5;
    void *buf = malloc(9096);
    void *response = malloc(len);

    if (!response || !buf) {
        fprintf(stderr, "Memory allocation failed\n");
        return __whttp_initialize_empty_response__();
    }

    memset(buf, 0, 1024);
    SSL_write(wrapper->ssl, data, strlen(data));

    while ((bytes = SSL_read(wrapper->ssl, buf, 9095)) > 0) {
        if (bytes == -1) break;
        if (copied + bytes >= len) {
            len = (copied + bytes) * 2;
            void *temp = realloc(response, len);
            if (!temp) {
                free(response);
                fprintf(stderr, "Memory allocation failed\n");
                return __whttp_initialize_empty_response__();
            }
            response = temp;
        }
        memcpy(response + copied, buf, bytes);
        memset(buf, 0, 1024);
        copied += bytes;
    }

    res = whttp_parse_response(response, req.host);
    free(response);

    free_ssl_wrapper(wrapper);
    EVP_cleanup();
    return res;
}

static HttpResponse send_http_request(HttpRequest req, u8 *data) {
    write(req.conn.fd, data, 9096 * sizeof(char));

    u64 bytes, copied = 0;
    u64 len = 1024 * 5;
    void *response = malloc(len);
    u8 buf[1024];
    memset(buf, 0, 1024);

    if (!response) {
        fprintf(stderr, "Memory allocation failed\n");
        return __whttp_initialize_empty_response__();
    }

    while ((bytes = read(req.conn.fd, buf, sizeof(buf))) > 0) {
        if (bytes == -1) break;
        if (copied + bytes >= len) {
            len = (copied + bytes) * 2;
            void *temp = realloc(response, len);
            if (!temp) {
                free(response);
                fprintf(stderr, "Memory allocation failed\n");
                return __whttp_initialize_empty_response__();
            }
            response = temp;
        }
        memcpy(response + copied, buf, bytes);
        copied += bytes;
        memset(buf, 0, 1024);
    }

    HttpResponse res = whttp_parse_response(response, req.host);
    free(response);
    return res;
}

HttpResponse whttp_do_request(HttpClient *client, HttpRequest req) {
    u8 *req_line = malloc(sizeof(char) * 9096); // fix later?
    char *header_literal = whttp_parse_header(req.headers);

    format(
        req_line, 9096 * sizeof(char),
        "%s %s HTTP/1.1\r\n"
        "%s"
        "\r\n"
        "%s",
        req.method, req.path, header_literal, req.body
    );

    if (!client) client = whttp_default_client(req.host);
    set_stream_timeout(client->timeout, req.conn);

    HttpResponse response = (req.use_tls) ? send_https_request(req, req_line) : send_http_request(req, req_line);

    free(header_literal);
    free(req_line);

    // handle redirect

    HttpStatus st = response.status_code;
    if (client->redirect_count >= 1 && client->follow_redirect && (st >= 300 && st < 400)) {
        char *location = whttp_get_header(response, "Location"); // do not free or use after freeing these headers

        // preserve the original request method only in case of status code 307 or 308
        // use http method get in any other case
        char *method = (st == HTTP_STATUS_TEMPORARY_REDIRECT || st == HTTP_STATUS_PERMANENT_REDIRECT) ? req.method : HTTP_METHOD_GET;

        HttpClient *c = whttp_default_client(location);
        HttpRequest r = whttp_new_request(method, location, NULL, NULL, req.content_len);
        whttp_set_header(r, "Referer", req.url);

        client->redirect_count--;
        c->redirect_count = client->redirect_count;
        return whttp_do_request(c, r);
    }

    return response;
}

void whttp_clean_request(HttpRequest req) {
    close(req.conn.fd);
    free(req.url);
    free(req.conn.addr);
    free(req.method);
    free(req.host);
    free(req.path);
    whttp_clean_header(req);
}

//////////////////////////////////////////////
// update below function to free HttpResponse related memory

HttpResponse whttp_get(HttpClient *client, char *path) {
    if (!client) client = whttp_default_client(path);
    
    HttpRequest req = whttp_new_request(HTTP_METHOD_GET, path, NULL, NULL, 0);
    HttpResponse res = whttp_do_request(client, req);
    return whttp_do_request(client, req);
}

// probably passing around raw unsigned char is not a good idea
HttpResponse whttp_post(char *path, u8 *body, const char *content_type, u64 body_len) {
    HttpRequest req = whttp_new_request(HTTP_METHOD_POST, path, body, content_type, body_len);
    return whttp_do_request(NULL, req);
}

HttpResponse whttp_delete(char *path) {
    HttpRequest req = whttp_new_request(HTTP_METHOD_DELETE, path, NULL, NULL, 0);
    return whttp_do_request(NULL, req);
}