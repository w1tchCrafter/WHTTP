#ifndef W_HTTP_H
#define W_HTTP_H

#include <stdbool.h>
#include <unistd.h>

#include "wnet.h"

#define HTTP_METHOD_GET "GET"
#define HTTP_METHOD_PUT "PUT"
#define HTTP_METHOD_POST "POST"
#define HTTP_METHOD_HEAD "HEAD"
#define HTTP_METHOD_PATCH "PATCH"
#define HTTP_METHOD_TRACE "TRACE"
#define HTTP_METHOD_DELETE "DELETE"
#define HTTP_METHOD_OPTIONS "OPTIONS"
#define HTTP_METHOD_CONNECT "CONNECT"

typedef enum {
    HTTP_STATUS_CONTINUE           = 100,
    HTTP_STATUS_SWITCHING_PROTOCOL = 101,
    HTTP_STATUS_PROCESSING         = 102,
    HTTP_STATUS_EARLY_HINTS        = 103,

    HTTP_STATUS_OK                     = 200,
    HTTP_STATUS_CREATED                = 201,
    HTTP_STATUS_ACCEPTED               = 202,
    HTTP_STATUS_NON_AUTHORITATIVE_INFO = 203,
    HTTP_STATUS_NO_CONTENT             = 204,
    HTTP_STATUS_RESET_CONTENT          = 205,
    HTTP_STATUS_PARTIAL_CONTENT        = 206,
    HTTP_STATUS_MULTI_STATUS           = 207,
    HTTP_STATUS_ALREADY_REPORTED       = 208,
    HTTP_STATUS_IMUSED                 = 226,

    HTTP_STATUS_MULTIPLE_CHOICES   = 300,
    HTTP_STATUS_MOVED_PERMANENTLY  = 301,
    HTTP_STATUS_FOUND              = 302,
    HTTP_STATUS_SEE_OTHER          = 303,
    HTTP_STATUS_NOT_MODIFIED       = 304,
    HTTP_STATUS_USE_PROXY          = 305,
    HTTP_STATUS_TEMPORARY_REDIRECT = 307,
    HTTP_STATUS_PERMANENT_REDIRECT = 308,

    HTTP_STATUS_BAD_REQUEST                    = 400,
    HTTP_STATUS_UNAUTHORIZED                   = 401,
    HTTP_STATUS_PAYMENT_REQUIRED               = 402,
    HTTP_STATUS_FORBIDDEN                      = 403,
    HTTP_STATUS_NOT_FOUND                      = 404,
    HTTP_STATUS_METHOD_NOT_ALLOWED             = 406,
    HTTP_STATUS_NOT_ACCEPTABLE                 = 406,
    HTTP_STATUS_PROXY_AUTH_REQUIRED            = 407,
    HTTP_STATUS_REQUEST_TIMEOUT                = 408,
    HTTP_STATUS_CONFLICT                       = 409,
    HTTP_STATUS_GONE                           = 410,
    HTTP_STATUS_LENGHT_REQUIRED                = 411,
    HTTP_STATUS_PRECONDITION_FAILED            = 412,
    HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE       = 413,
    HTTP_STATUS_REQUEST_URI_TOO_LONG           = 414,
    HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE         = 415,
    HTTP_STATUS_REQUEST_RANGE_NOT_SATISFIABLE  = 416,
    HTTP_STATUS_EXPECTATION_FAILED             = 417,
    HTTP_STATUS_TEAPOT                         = 418,
    HTTP_STATUS_MISDIRECTED_REQUEST            = 421,
    HTTP_STATUS_UNPROCESSABLE_ENTITY           = 422,
    HTTP_STATUS_LOCKED                         = 423,
    HTTP_STATUS_FAILED_DEPENDENCY              = 424,
    HTTP_STATUS_TOO_EARLY                      = 425,
    HTTP_STATUS_UPGRADE_REQUIRED               = 426,
    HTTP_STATUS_PRECONDITION_REQUIRED          = 428,
    HTTP_STATUS_TOO_MANY_REQUEST               = 429,
    HTTP_STATUS_REQUEST_HEADER_FIELD_TOO_LARGE = 431,
    HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS  = 451,

    HTTP_STATUS_INTERNAL_SERVER_ERROR           = 500,
    HTTP_STATUS_NOT_IMPLEMENTED                 = 501,
    HTTP_STATUS_BAD_GATEWAY                     = 502,
    HTTP_STATUS_SERVICE_UNAVAILABLE             = 503,
    HTTP_STATUS_GATEWAY_TIMEOUT                 = 504,
    HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED      = 505,
    HTTP_STATUS_VARIANT_ALSO_NEGOTIATES         = 506,
    HTTP_STATUS_INSUFFICIENT_STORAGE            = 507,
    HTTP_STATUS_LOOP_DETECTED                   = 508,
    HTTP_STATUS_NOT_EXTENDED                    = 510,
    HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED = 511
} HttpStatus;

typedef struct {
    char *key;
    char *data;
} _headerValue;

typedef struct {
    _headerValue *values;
    u32          size;
    u32          capacity;
} HttpHeader;

#define HTTP_CLIENT_REDIRECT_MAX 10

typedef struct {
    struct timeval timeout;
    u16    redirect_count;
    bool   follow_redirect;
    bool   keepalive;
} HttpClient;

typedef struct {
    char         *method;
    char         *host;
    char         *path;
    char         *url;
    void         *body;
    StreamReader *reader; //obsolete
    HttpHeader   headers;
    TcpStream    conn;
    u64          content_len;
    bool         use_tls;
} HttpRequest;

typedef struct {
    char         *status;
    char         *host;
    char         *path;
    void         *body;
    HttpRequest  *request;
    HttpHeader   headers;
    u64          content_len;
    HttpStatus   status_code;
} HttpResponse;

#define __whttp_initialize_empty_response__() ((HttpResponse) {.host = malloc(0), .status = malloc(0), .headers = whttp_new_header()})

#define whttp_set_header(obj, key, value) (__whttp_set_header__(&obj.headers, key, value))

#define whttp_get_header(obj, key)                    \
({                                                    \
    i32 i = __whttp_get_header__(obj.headers, key);   \
    (i == -1) ? NULL : obj.headers.values[i].data;    \
})

#define whttp_clean_header(obj)                     \
({                                                  \
    for (u32 i = 0; i < obj.headers.size; i++) {    \
        free(obj.headers.values[i].key);            \
        free(obj.headers.values[i].data);           \
    }                                               \
    free(obj.headers.values);                       \
})

// check if the given http method should have a body
#define should_have_body(METHOD)            \
(                                           \
    (strcmp(METHOD, HTTP_METHOD_GET))    || \
    (strcmp(METHOD, HTTP_METHOD_HEAD))   || \
    (strcmp(METHOD, HTTP_METHOD_OPTIONS))   \
)

bool whttp_should_use_keepalive(char *host);

// create and initialize a new ```HttpHeader``` struct
// free the field ```HttpHeader.values``` after using
// free the fields ```HttpHeader.values[int index].key``` and ```HttpHeader.values[int index].key``` after using
// example:
//
//```
//for (u32 i = 0; i < obj.headers.size; i++) { 
//    free(obj.headers.values[i].key);
//    free(obj.headers.values[i].data);
//}
//free(obj.headers.values);
//```
HttpHeader whttp_new_header();

// search the index for a specific key in a ```Httpheader``` struct
// returns -1 on error
i32 __whttp_get_header__(HttpHeader, char*);

// set a key value pair in the given ```HttpHeader``` struct
// overrides the key if it already exists
void __whttp_set_header__(HttpHeader*, char*, char*);

// this function free all the memory associated with the given ```HttpRequest``` struct
void whttp_clean_request(HttpRequest);

HttpRequest whttp_new_request(char *method, char *host, void *body, char *content_type, u64 body_len);
HttpResponse whttp_parse_response(void *response_data, char *host);
HttpResponse whttp_do_request(HttpClient *client, HttpRequest req);
HttpResponse whttp_get(HttpClient *client, char *path);
HttpResponse whttp_post(char*, u8*, const char*, u64);
HttpResponse whttp_delete(char*);

#endif