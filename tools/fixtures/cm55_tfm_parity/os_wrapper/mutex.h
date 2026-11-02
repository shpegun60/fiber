/* Compile-only TF-M 2.0 mutex ABI boundary; not a TF-M implementation. */
#ifndef FIBER_PARITY_TFM_MUTEX_H
#define FIBER_PARITY_TFM_MUTEX_H
#include <stdint.h>
#define OS_WRAPPER_SUCCESS 0
#define OS_WRAPPER_ERROR (-1)
#define OS_WRAPPER_WAIT_FOREVER 0xFFFFFFFFu
void *os_wrapper_mutex_create(void);
uint32_t os_wrapper_mutex_acquire(void *, uint32_t);
uint32_t os_wrapper_mutex_release(void *);
uint32_t os_wrapper_mutex_delete(void *);
#endif
