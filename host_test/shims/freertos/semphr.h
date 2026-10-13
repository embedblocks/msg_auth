/* Host shim: mutex semaphores on pthread_mutex_t, with failure injection (T21). */
#pragma once
#include "freertos/FreeRTOS.h"
typedef struct { pthread_mutex_t m; } StaticSemaphore_t;
typedef StaticSemaphore_t *SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t *storage);
BaseType_t        xSemaphoreTake(SemaphoreHandle_t s, TickType_t wait);
BaseType_t        xSemaphoreGive(SemaphoreHandle_t s);
void              vSemaphoreDelete(SemaphoreHandle_t s);
