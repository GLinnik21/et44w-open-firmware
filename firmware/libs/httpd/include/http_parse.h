/* HTTP/1.x request parsing for httpd. Pure C: no OS, no SDK; host-tested (make -C libs/httpd/test). */
#ifndef HTTP_PARSE_H
#define HTTP_PARSE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    const char *method;    /* "GET", "POST", ... */
    const char *path;      /* without the query, e.g. "/api/dp" */
    const char *query;     /* after '?', "" if none */
    const char *host;      /* Host header value, "" if missing */
    bool requested_with;   /* X-Requested-With header present (cross-site pages can't set it) */
    size_t content_length; /* 0 if missing */
    size_t header_len;     /* bytes up to and including the blank line; the body starts here */
} http_request;

/* Parses the request line and headers at the start of buf[0, len). Returns 1 when the header block
 * is complete (buf is then modified in place: the strings above point into it), 0 if it isn't
 * complete yet (buf untouched), -1 if it is malformed. */
int http_parse(char *buf, size_t len, http_request *rq);

/* Host header names this device on the LAN: an IPv4 literal or a "*.local" name, optional ":port".
 * Refusing other names stops DNS-rebinding pages from reaching the device through the browser. */
bool http_host_is_local(const char *host);

/* Looks up key in "a=1&b=x%20y" (query string or form body) and URL-decodes its value into out.
 * Returns false if the key is missing or the value doesn't fit in cap - 1 bytes. */
bool http_form_get(const char *form, size_t len, const char *key, char *out, size_t cap);

#endif
