// Minimal HTTP/1.x server: one task, one client at a time, one handler. Not a framework: the app's
// handler looks at method and path itself.
//
// - Every reply ends with "Connection: close"; the body is delimited by closing the socket.
// - Requests are refused before the handler runs if the Host header isn't a local name (IPv4 literal
//   or *.local, against DNS rebinding), or if a request other than GET lacks X-Requested-With (a
//   header cross-site pages can't send without a CORS preflight, which is never answered) — so a
//   website open in a browser on the LAN can't change settings.
// - Header block <= HTTPD_HEADER_MAX, body <= HTTPD_BODY_MAX. The request must arrive within 3 s
//   (1.5 s per read) and the reply be taken within 10 s, or the client is dropped.
// - No authentication: whoever reaches the port on the LAN can use the handler.
#ifndef HTTPD_H
#define HTTPD_H

#include <stddef.h>
#include <stdint.h>

#define HTTPD_HEADER_MAX 1024
#define HTTPD_BODY_MAX   256

typedef struct {
    const char* method;
    const char* path;
    const char* query; // "" if none
    const char* body;  // NUL-terminated
    size_t bodyLen;
} httpd_request;

typedef void (*httpd_handler)(int sock, const httpd_request* request, void* ctx);

// Creates the server task. Call once.
void httpd_start(uint16_t port, httpd_handler handler, void* ctx);

// For handlers: send the status line and headers (status 200, 400, 403, 404, 405, 413 or 500; no
// caching), then the body with httpd_send / httpd_printf.
void httpd_begin(int sock, int status, const char* contentType);
void httpd_send(int sock, const void* data, size_t len);
void httpd_printf(int sock, const char* fmt, ...) __attribute__((format(printf, 2, 3))); // <= 192 chars

// Status line + short text body.
void httpd_reply(int sock, int status, const char* text);

#endif
