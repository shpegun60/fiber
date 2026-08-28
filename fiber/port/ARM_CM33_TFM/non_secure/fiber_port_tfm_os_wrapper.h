/* Exact TF-M v2.0.0 mutex wrapper surface consumed by TF-M NS interface. */
#ifndef FIBER_PORT_ARM_CM33_TFM_NON_SECURE_FIBER_PORT_TFM_OS_WRAPPER_H_
#define FIBER_PORT_ARM_CM33_TFM_NON_SECURE_FIBER_PORT_TFM_OS_WRAPPER_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIBER_PORT_TFM_OS_WRAPPER_SUCCESS 0u
#define FIBER_PORT_TFM_OS_WRAPPER_ERROR UINT32_MAX
#define FIBER_PORT_TFM_OS_WRAPPER_WAIT_FOREVER UINT32_MAX

void *os_wrapper_mutex_create(void);
uint32_t os_wrapper_mutex_acquire(void *handle, uint32_t timeout);
uint32_t os_wrapper_mutex_release(void *handle);
uint32_t os_wrapper_mutex_delete(void *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_TFM_NON_SECURE_FIBER_PORT_TFM_OS_WRAPPER_H_ */
