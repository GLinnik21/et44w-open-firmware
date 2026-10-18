#include "http_parse.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char *find_end(char *buf, size_t len)
{
    for (size_t i = 0; i + 3 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n')
            return buf + i + 4;
    return NULL;
}

/* Splits "Name: value" at the colon and trims the value. Returns the value, or NULL. */
static char *header_value(char *line)
{
    char *colon = strchr(line, ':');
    if (!colon || colon == line) return NULL;
    *colon = '\0';
    char *v = colon + 1;
    while (*v == ' ' || *v == '\t') v++;
    char *e = v + strlen(v);
    while (e > v && (e[-1] == ' ' || e[-1] == '\t')) *--e = '\0';
    return v;
}

int http_parse(char *buf, size_t len, http_request *rq)
{
    char *end = find_end(buf, len);
    if (!end) return 0;
    if (memchr(buf, '\0', (size_t)(end - buf))) return -1; /* would cut the header lines short */
    *rq = (http_request){.query = "", .host = "", .header_len = (size_t)(end - buf)};
    end[-2] = '\0'; /* terminates the last header line */

    char *line = buf, *next;
    bool first = true;
    while (*line) {
        char *crlf = strstr(line, "\r\n");
        if (crlf) {
            *crlf = '\0';
            next = crlf + 2;
        } else {
            next = line + strlen(line);
        }
        if (first) {
            char *sp1 = strchr(line, ' ');
            char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
            if (!sp1 || !sp2 || sp1 == line || strncmp(sp2 + 1, "HTTP/1.", 7)) return -1;
            *sp1 = *sp2 = '\0';
            rq->method = line;
            rq->path = sp1 + 1;
            if (rq->path[0] != '/') return -1;
            char *q = strchr(sp1 + 1, '?');
            if (q) {
                *q = '\0';
                rq->query = q + 1;
            }
            first = false;
        } else {
            char *v = header_value(line);
            if (!v) return -1;
            if (!strcasecmp(line, "Host")) {
                rq->host = v;
            } else if (!strcasecmp(line, "X-Requested-With")) {
                rq->requested_with = true;
            } else if (!strcasecmp(line, "Content-Length")) {
                char *e;
                unsigned long n = strtoul(v, &e, 10);
                if (e == v || *e || n > 0xFFFFul) return -1;
                rq->content_length = n;
            }
        }
        line = next;
    }
    return first ? -1 : 1;
}

bool http_host_is_local(const char *host)
{
    size_t n = strcspn(host, ":");
    if (n == 0) return false;
    if (host[n] == ':') {
        const char *p = host + n + 1;
        if (!*p) return false;
        for (; *p; p++)
            if (!isdigit((unsigned char)*p)) return false;
    }
    static const char local[] = ".local";
    size_t ln = sizeof local - 1;
    if (n > ln && !strncasecmp(host + n - ln, local, ln)) return true;
    int dots = 0, digits = 0; /* dotted quad, 1-3 digits per part */
    for (size_t i = 0; i < n; i++) {
        if (host[i] == '.') {
            if (!digits) return false;
            dots++;
            digits = 0;
        } else if (!isdigit((unsigned char)host[i]) || ++digits > 3) {
            return false;
        }
    }
    return dots == 3 && digits;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = (char)tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

bool http_form_get(const char *form, size_t len, const char *key, char *out, size_t cap)
{
    size_t klen = strlen(key);
    for (size_t i = 0; i < len;) {
        size_t j = i;
        while (j < len && form[j] != '&') j++;
        if (j - i > klen && form[i + klen] == '=' && !strncmp(form + i, key, klen)) {
            size_t o = 0;
            for (size_t k = i + klen + 1; k < j; k++) {
                char c = form[k];
                if (c == '+') {
                    c = ' ';
                } else if (c == '%') {
                    int h = k + 2 < j ? hexval(form[k + 1]) : -1, l = h >= 0 ? hexval(form[k + 2]) : -1;
                    if (l < 0) return false;
                    c = (char)(h * 16 + l);
                    k += 2;
                }
                if (o + 1 >= cap) return false;
                out[o++] = c;
            }
            out[o] = '\0';
            return true;
        }
        i = j + 1;
    }
    return false;
}
