#include "httpd.h"
#include "http_parse.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
#include "net_listen.h"

#define RECV_TIMEOUT_MS 1500 // browsers open idle preconnect sockets; don't let one hold the server
#define REQUEST_MS      3000 // the whole request, so a slow drip can't hold the server either
#define REPLY_MS        10000 // the whole reply, against a client that stops reading
#define DRAIN_MS        500  // reading what an early error reply left unread, so close() doesn't reset
#define RETRY_MS        1000
#define STACK_WORDS     768

static struct {
    uint16_t port;
    httpd_handler handler;
    void* ctx;
    TickType_t deadline; // for the current phase of the current client
    char buf[HTTPD_HEADER_MAX + HTTPD_BODY_MAX + 1]; // one client at a time
} s;

static void SetDeadline(uint32_t ms) {
    s.deadline = xTaskGetTickCount() + pdMS_TO_TICKS(ms);
}

static uint32_t RemainingMs(void) {
    TickType_t left = s.deadline - xTaskGetTickCount();
    return left > pdMS_TO_TICKS(REPLY_MS) ? 0 : (uint32_t) (left * portTICK_PERIOD_MS); // past it: wrapped
}

/** recv() bounded by RECV_TIMEOUT_MS and by the deadline. */
static int RecvSome(int sock, char* buf, size_t len) {
    uint32_t ms = RemainingMs();
    if (ms == 0) {
        return -1;
    }
    int timeout = ms < RECV_TIMEOUT_MS ? (int) ms : RECV_TIMEOUT_MS; // lwipopts: LWIP_SO_SNDRCVTIMEO_NONSTANDARD,
    (void) setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout); // so an int in ms
    return recv(sock, buf, len, 0);
}

static const char* StatusText(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        default: return "Internal Server Error";
    }
}

// lwIP here has no SO_SNDTIMEO (LWIP_SO_SNDTIMEO is 0), so wait with select() and send without blocking.
void httpd_send(int sock, const void* data, size_t len) {
    const char* p = data;
    while (len > 0) {
        uint32_t ms = RemainingMs();
        fd_set w;
        FD_ZERO(&w);
        FD_SET(sock, &w);
        struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
        if (ms == 0 || select(sock + 1, NULL, &w, NULL, &tv) <= 0) {
            return; // the client stopped reading: give up on this reply
        }
        int n = send(sock, p, len, MSG_DONTWAIT);
        if (n <= 0) {
            return;
        }
        p += n;
        len -= (size_t) n;
    }
}

void httpd_printf(int sock, const char* fmt, ...) {
    char line[193];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n > 0) {
        httpd_send(sock, line, (size_t) n < sizeof line ? (size_t) n : sizeof line - 1);
    }
}

void httpd_begin(int sock, int status, const char* contentType) {
    httpd_printf(sock, "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                 status, StatusText(status), contentType);
}

void httpd_reply(int sock, int status, const char* text) {
    httpd_begin(sock, status, "text/plain; charset=utf-8");
    httpd_send(sock, text, strlen(text));
}

/** Reads one request into s.buf. Returns the parsed header, or an HTTP status to reply with. */
static int Receive(int sock, http_request* rq) {
    size_t len = 0;
    int parsed = 0;
    while (parsed == 0) {
        if (len >= HTTPD_HEADER_MAX) {
            return 413;
        }
        int n = RecvSome(sock, s.buf + len, HTTPD_HEADER_MAX - len);
        if (n <= 0) {
            return -1; // timeout or closed: just drop it
        }
        len += (size_t) n;
        parsed = http_parse(s.buf, len, rq);
    }
    if (parsed < 0) {
        return 400;
    }
    if (rq->content_length > HTTPD_BODY_MAX) {
        return 413;
    }
    size_t want = rq->header_len + rq->content_length;
    while (len < want) {
        int n = RecvSome(sock, s.buf + len, want - len);
        if (n <= 0) {
            return -1;
        }
        len += (size_t) n;
    }
    s.buf[want] = '\0';
    return 200;
}

/** Answers one request. Returns true if request bytes may be left unread. */
static bool Serve(int sock) {
    SetDeadline(REQUEST_MS);
    http_request rq;
    int status = Receive(sock, &rq);
    SetDeadline(REPLY_MS);
    if (status < 0) {
        return false;
    }
    if (status != 200) {
        httpd_reply(sock, status, StatusText(status));
        return true;
    }
    if (!http_host_is_local(rq.host)) {
        httpd_reply(sock, 403, "Host must be the device's IP address or .local name");
        return false;
    }
    if (strcmp(rq.method, "GET") && !rq.requested_with) {
        httpd_reply(sock, 403, "Missing X-Requested-With");
        return false;
    }
    s.handler(sock,
              &(const httpd_request) { .method = rq.method,
                                       .path = rq.path,
                                       .query = rq.query,
                                       .body = s.buf + rq.header_len,
                                       .bodyLen = rq.content_length },
              s.ctx);
    return false;
}

/** lwIP resets a connection closed with received data unread, and the client may then never see the
 * reply: after an early error reply, read and drop the rest for a moment. */
static void Drain(int sock) {
    SetDeadline(DRAIN_MS);
    while (RecvSome(sock, s.buf, sizeof s.buf) > 0) {
    }
}

static void ServerTask(void* arg) {
    (void) arg;
    int listener;
    while ((listener = net_listen(s.port, 2)) < 0) {
        vTaskDelay(pdMS_TO_TICKS(RETRY_MS)); // lwIP not up yet
    }
    for (;;) {
        int sock = accept(listener, NULL, NULL);
        if (sock >= 0) {
            bool unread = Serve(sock);
            shutdown(sock, SHUT_WR);
            if (unread) {
                Drain(sock);
            }
            close(sock);
        }
    }
}

void httpd_start(uint16_t port, httpd_handler handler, void* ctx) {
    s.port = port;
    s.handler = handler;
    s.ctx = ctx;
    if (xTaskCreate(ServerTask, "http", STACK_WORDS, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
        printf("httpd: no memory for the server task\n");
    }
}
