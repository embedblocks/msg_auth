/* Host shim: heap_caps with live-allocation counting and failure injection (T21). */
#pragma once
#include <stddef.h>
#define MALLOC_CAP_INTERNAL  (1 << 11)
#define MALLOC_CAP_8BIT      (1 << 2)
void *heap_caps_calloc(size_t n, size_t size, unsigned caps);
void  heap_caps_free(void *p);
