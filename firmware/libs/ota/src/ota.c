// Boot check, trial deadline, confirm and the one-client upload server.
#include "ota.h"
#include "ota_flash.h"
#include "ota_key.h"
#include "ota_receive.h"
#include "ota_state.h"

#include <stdio.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"
#include "lwip/sockets.h"
#include "net_listen.h"

#define POLL_MS      1000
#define RECV_TIMEOUT 15000 // ms of silence before an upload is dropped
#define DRAIN_MS     2000  // after an error reply, input is read and dropped this long at most
#define STACK_WORDS  2048  // measured peak ~1075 words (SHA-512 + Ed25519 verify); logged after each upload

static uint8_t publicKey[32];
static bool keyUsable;           // false: placeholder or small-order key, every upload is refused
static volatile bool confirmRequested;
static volatile TickType_t confirmRequestedAt;
static bool onTrial;             // this boot is a pending trial (server task only after start)
static TickType_t trialDeadline;
static volatile TickType_t extendedDeadline; // from ota_extend_trial; 0 = none

static void RollBack(const char* why) {
    uint32_t running = ota_running_slot();
    printf("ota: trial failed (%s), rolling back from slot 0x%lx\n", why, (unsigned long) running);
    if (running) {
        ota_invalidate_slot(running); // the record stays; the old slot sees it isn't its own and clears it
    }
    ota_reset();
}

void ota_boot_check(void) {
    ota_flash_print_info();
    ota_trial trial = ota_state_read();
    if (!trial.pending) {
        return;
    }
    uint32_t running = ota_running_slot();
    if (trial.slot != running) {
        printf("ota: trial of slot 0x%lx ended without it (running 0x%lx), cleared\n", (unsigned long) trial.slot,
               (unsigned long) running);
        ota_state_clear();
        return;
    }
    if (trial.boots >= OTA_TRIAL_BOOTS) {
        RollBack("too many boots");
    }
    ota_state_count_boot();
    onTrial = true;
    printf("ota: trial boot %lu/%u of slot 0x%lx, confirm within %u s\n", (unsigned long) trial.boots + 1,
           OTA_TRIAL_BOOTS, (unsigned long) running, OTA_TRIAL_MS / 1000);
}

void ota_confirm(void) {
    if (!confirmRequested) { // flash work happens on the OTA task, after OTA_CONFIRM_STABLE_MS
        confirmRequestedAt = xTaskGetTickCount();
        confirmRequested = true;
    }
}

void ota_extend_trial(uint32_t ms) {
    TickType_t want = xTaskGetTickCount() + pdMS_TO_TICKS(ms), cap = pdMS_TO_TICKS(OTA_TRIAL_MAX_MS);
    extendedDeadline = (int32_t) (want - cap) > 0 ? cap : want; // tick count = uptime
}

/** Runs on the OTA task: applies a confirm, or rolls back once the deadline passes. */
static void CheckTrial(void) {
    if (!onTrial) {
        return;
    }
    TickType_t now = xTaskGetTickCount();
    TickType_t extended = extendedDeadline;
    if (extended && (int32_t) (extended - trialDeadline) > 0) {
        trialDeadline = extended;
    }
    if (confirmRequested && now - confirmRequestedAt >= pdMS_TO_TICKS(OTA_CONFIRM_STABLE_MS)) {
        ota_state_clear();
        onTrial = false;
        printf("ota: image confirmed\n");
    } else if (!confirmRequested && (int32_t) (now - trialDeadline) >= 0) {
        RollBack("not confirmed in time");
    }
}

static void Reply(int sock, const char* line) {
    (void) send(sock, line, strlen(line), 0);
    (void) send(sock, "\n", 1, 0);
}

/** Error reply while the client may still be sending: closing with unread input makes lwIP reset the
 *  connection, and the reset can destroy the reply at the client. So: reply, FIN, then read and drop input for
 *  at most DRAIN_MS (bounded, so a silent or endless client can't hold up the server or the trial deadline). */
static void Refuse(int sock, const char* line) {
    Reply(sock, line);
    (void) shutdown(sock, SHUT_WR);
    int timeout = 200; // ms per recv; a pause that long ends the drain
    (void) setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    uint8_t sink[128];
    TickType_t end = xTaskGetTickCount() + pdMS_TO_TICKS(DRAIN_MS);
    while ((int32_t) (xTaskGetTickCount() - end) < 0 && recv(sock, sink, sizeof sink, 0) > 0) {
    }
}

static void Serve(int sock) {
    if (onTrial) {
        Refuse(sock, "ERR trial pending: wait for the running image to confirm");
        return;
    }
    if (!keyUsable) {
        Refuse(sock, "ERR no usable OTA key in this firmware (placeholder?): reflash over UART");
        return;
    }
    int timeout = RECV_TIMEOUT; // lwipopts: LWIP_SO_SNDRCVTIMEO_NONSTANDARD, so an int in ms
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) < 0) {
        Refuse(sock, "ERR no receive timeout");
        return;
    }
    printf("ota: upload started\n");
    const char* err = ota_receive(sock, publicKey);
    if (err) {
        printf("ota: upload rejected: %s (stack free %lu words)\n", err,
               (unsigned long) uxTaskGetStackHighWaterMark(NULL));
        char line[80];
        snprintf(line, sizeof line, "ERR %s", err);
        Refuse(sock, line);
        return;
    }
    printf("ota: image verified, rebooting into it (stack free %lu words)\n",
           (unsigned long) uxTaskGetStackHighWaterMark(NULL));
    Reply(sock, "OK verified, rebooting");
    close(sock);
    vTaskDelay(pdMS_TO_TICKS(500)); // let the reply and the log drain
    ota_reset();
}

static void ServerTask(void* arg) {
    uint16_t port = (uint16_t) (uintptr_t) arg;
    int listener = -1;
    for (;;) {
        CheckTrial();
        if (listener < 0 && (listener = net_listen(port, 1)) < 0) {
            vTaskDelay(pdMS_TO_TICKS(POLL_MS)); // lwIP not up yet
            continue;
        }
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(listener, &fds);
        struct timeval tv = { .tv_sec = POLL_MS / 1000, .tv_usec = 0 };
        if (select(listener + 1, &fds, NULL, NULL, &tv) > 0) {
            int sock = accept(listener, NULL, NULL);
            if (sock >= 0) {
                Serve(sock);
                close(sock);
            }
        }
    }
}

void ota_start(const ota_options* options) {
    memcpy(publicKey, options->publicKey, sizeof publicKey);
    keyUsable = ota_key_usable(publicKey);
    if (!keyUsable) {
        printf("ota: public key is a placeholder or weak: all uploads refused (tools/ota_keygen.py)\n");
        if (onTrial) { // an image that can never take another update must not pass its trial
            RollBack("no usable OTA key");
        }
    }
    trialDeadline = xTaskGetTickCount() + pdMS_TO_TICKS(OTA_TRIAL_MS);
    if (xTaskCreate(ServerTask, "ota", STACK_WORDS, (void*) (uintptr_t) options->port, tskIDLE_PRIORITY + 1, NULL) !=
        pdPASS) {
        printf("ota: no memory for the server task\n");
        if (onTrial) { // nothing else would enforce the deadline or take the next update
            RollBack("no OTA task");
        }
    }
}
