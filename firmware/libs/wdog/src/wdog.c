#include "wdog.h"

#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"
#include "wdt_api.h"

#define FEED_MS     1000
#define STACK_WORDS 256

static void FeedTask(void* arg) {
    (void) arg;
    for (;;) {
        watchdog_refresh();
        vTaskDelay(pdMS_TO_TICKS(FEED_MS));
    }
}

void wdog_start(void) {
    if (xTaskCreate(FeedTask, "wdog", STACK_WORDS, NULL, tskIDLE_PRIORITY + 1, NULL) != pdPASS) {
        printf("wdog: no memory for the feeder, watchdog not armed\n");
        return;
    }
    watchdog_init(WDOG_TIMEOUT_MS);
    watchdog_start();
    printf("wdog: armed, %u ms\n", WDOG_TIMEOUT_MS);
}
