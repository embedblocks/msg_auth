/* Host shim: just enough FreeRTOS for msg_auth, on pthreads. */
#pragma once
#include <pthread.h>
#include <stdint.h>
typedef uint32_t TickType_t;
typedef long     BaseType_t;
#define pdTRUE         1
#define pdFALSE        0
#define portMAX_DELAY  ((TickType_t)0xFFFFFFFFu)
