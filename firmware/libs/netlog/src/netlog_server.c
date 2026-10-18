// One-client TCP log server. A new connection replaces the current one (so a stale client never
// blocks the log). Sends never block: if the client is slow, it falls behind and the ring drops the
// oldest bytes, reported inline as "[netlog: N bytes lost]".
#include "netlog.h"
#include "netlog_ring.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
#include "net_listen.h"

#define POLL_MS    50
#define CHUNK      512
#define STACK_WORDS 384 // measured use ~110 words
#define HEAP_LOG_MS 600000 // periodic "netlog: heap" + "netlog: stack free" lines
#define MAX_TASKS   24

// The "[netlog: N bytes lost]" marker for the current client. It goes out whole, before any byte after the
// gap; losses while it is still being sent go into the next one.
static struct {
    char text[40];
    size_t len, sent;
    uint32_t lost; // not in a marker yet
} note;

static void CloseClient(int* client) {
    if (*client >= 0) {
        close(*client);
        *client = -1;
    }
}

/** Accepts a waiting connection, if any, replacing the current client. Starts it at the oldest kept byte. */
static void AcceptPending(int listener, int* client, uint32_t* pos) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(listener, &fds);
    struct timeval timeout = { .tv_sec = 0, .tv_usec = POLL_MS * 1000 };
    if (select(listener + 1, &fds, NULL, NULL, &timeout) <= 0) {
        return;
    }
    int fd = accept(listener, NULL, NULL);
    if (fd < 0) {
        return;
    }
    CloseClient(client);
    int on = 1;
    (void) ioctlsocket(fd, FIONBIO, &on);
    *client = fd;
    memset(&note, 0, sizeof note);
    uint32_t head = netlog_ring_head();
    *pos = head > NETLOG_RING_SIZE ? head - NETLOG_RING_SIZE : 0;
}

/** After a failed send: true if the client is only slow, false if it is gone. */
static bool Retryable(int client) {
    int err = 0;
    socklen_t len = sizeof err;
    (void) getsockopt(client, SOL_SOCKET, SO_ERROR, &err, &len); // no errno in this lwIP build
    return err == 0 || err == EWOULDBLOCK || err == EAGAIN;
}

/** Sends what's new. Returns false if the client is gone. */
static bool Pump(int client, uint32_t* pos) {
    static char buf[CHUNK];
    uint32_t lost = 0;
    uint32_t start = *pos;
    size_t n = netlog_ring_read(pos, buf, sizeof buf, &lost);
    if (lost) {
        note.lost += lost;
        start = *pos - (uint32_t) n;
    }
    if (note.sent == note.len && note.lost) {
        note.len = (size_t) snprintf(note.text, sizeof note.text, "\n[netlog: %lu bytes lost]\n",
                                     (unsigned long) note.lost);
        note.sent = 0;
        note.lost = 0;
    }
    if (note.sent < note.len) {
        int sent = send(client, note.text + note.sent, note.len - note.sent, MSG_DONTWAIT);
        if (sent > 0) {
            note.sent += (size_t) sent;
        }
        if (note.sent < note.len) {
            *pos = start; // the log bytes wait for the marker
            return sent >= 0 || Retryable(client);
        }
    }
    if (n == 0) {
        return true;
    }
    int sent = send(client, buf, n, MSG_DONTWAIT);
    if (sent < 0) {
        *pos = start; // retry the same bytes later
        return Retryable(client);
    }
    *pos = start + (uint32_t) sent;
    return true;
}

static void ServerTask(void* arg) {
    uint16_t port = (uint16_t) (uintptr_t) arg;
    int listener;
    while ((listener = net_listen(port, 1)) < 0) {
        vTaskDelay(pdMS_TO_TICKS(1000)); // lwIP not up yet
    }
    int client = -1;
    uint32_t pos = 0;
    TickType_t lastHeapLog = 0;
    for (;;) {
        if (xTaskGetTickCount() - lastHeapLog >= pdMS_TO_TICKS(HEAP_LOG_MS)) {
            lastHeapLog = xTaskGetTickCount();
            netlog_print_memory();
        }
        AcceptPending(listener, &client, &pos); // also the loop's pacing (POLL_MS)
        if (client >= 0 && !Pump(client, &pos)) {
            CloseClient(&client);
        }
    }
}

void netlog_print_memory(void) {
    printf("netlog: heap free %u min %u\n", (unsigned) xPortGetFreeHeapSize(),
           (unsigned) xPortGetMinimumEverFreeHeapSize());
    static TaskStatus_t tasks[MAX_TASKS]; // only the netlog task calls this periodically
    UBaseType_t n = uxTaskGetSystemState(tasks, MAX_TASKS, NULL);
    printf("netlog: stack free (words)");
    for (UBaseType_t i = 0; i < n; i++) {
        printf(" %s=%u", tasks[i].pcTaskName, (unsigned) tasks[i].usStackHighWaterMark);
    }
    printf("\n");
}

void netlog_start(uint16_t port) {
    if (xTaskCreate(ServerTask, "netlog", STACK_WORDS, (void*) (uintptr_t) port, tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
        printf("netlog: no memory for the server task\n");
    }
}
