/* Exact TF-M v2.0.0 mutex wrapper surface consumed by TF-M NS interface. */
#ifndef FIBER_PORT_ARM_CM33F_TFM_NON_SECURE_FIBER_PORT_TFM_OS_WRAPPER_H_
#define FIBER_PORT_ARM_CM33F_TFM_NON_SECURE_FIBER_PORT_TFM_OS_WRAPPER_H_

#include <stdint.h>
#include "../../../fiber_api_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIBER_PORT_TFM_OS_WRAPPER_SUCCESS 0u
#define FIBER_PORT_TFM_OS_WRAPPER_ERROR UINT32_MAX
#define FIBER_PORT_TFM_OS_WRAPPER_WAIT_FOREVER UINT32_MAX

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void *os_wrapper_mutex_create(void);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t os_wrapper_mutex_acquire(void *handle, uint32_t timeout);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t os_wrapper_mutex_release(void *handle);
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t os_wrapper_mutex_delete(void *handle);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33F_TFM_NON_SECURE_FIBER_PORT_TFM_OS_WRAPPER_H_ */
