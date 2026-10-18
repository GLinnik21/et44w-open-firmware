#include "ota_test.h"

#if defined(OTA_TEST_fault)
#include <stdio.h>

#include "FreeRTOS.h"
#include "task.h"

static void FaultTask(void* arg) {
    (void) arg;
    vTaskDelay(pdMS_TO_TICKS(20000));
    printf("ota_test: faulting now\n");
    vTaskDelay(pdMS_TO_TICKS(100)); // let the line reach the network log
    __builtin_trap();
}

void ota_test_start(void) {
    printf("ota_test: fault build, will fault in 20 s\n");
    xTaskCreate(FaultTask, "ota_test", 256, NULL, tskIDLE_PRIORITY + 2, NULL);
}
#elif defined(OTA_TEST_never_confirm)
#include <stdio.h>

void ota_test_start(void) {
    printf("ota_test: never_confirm build, this image will roll back\n");
}
#else
void ota_test_start(void) {
}
#endif
