/* TF-M v2.0 mutex ABI compile boundary only, not an implementation/provider. */
#ifndef FIBER_CM33_TFM_RAW_MUTEX_BOUNDARY_H
#define FIBER_CM33_TFM_RAW_MUTEX_BOUNDARY_H
#include <stdint.h>
#define OS_WRAPPER_SUCCESS 0u
#define OS_WRAPPER_ERROR UINT32_MAX
#define OS_WRAPPER_WAIT_FOREVER UINT32_MAX
void *os_wrapper_mutex_create(void);
uint32_t os_wrapper_mutex_acquire(void *handle, uint32_t timeout);
uint32_t os_wrapper_mutex_release(void *handle);
uint32_t os_wrapper_mutex_delete(void *handle);
#endif
