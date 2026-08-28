/* Selected ARM_CM33 TF-M Non-secure integration API. */
#ifndef FIBER_PORT_ARM_CM33_TFM_NON_SECURE_FIBER_PORT_TFM_ABI_H_
#define FIBER_PORT_ARM_CM33_TFM_NON_SECURE_FIBER_PORT_TFM_ABI_H_

#include <stdint.h>

#include "../../../fiber_api_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FIBER_PORT_TFM_SUCCESS 0u
#define FIBER_PORT_TFM_ERROR UINT32_MAX

/* Optional early initialization entry. It is valid only in privileged
 * Non-secure Thread/MSP mode before fiber_start(). fiber_start() invokes the
 * same idempotent operation automatically if the board did not call it. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t fiber_port_tfm_initialize(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* FIBER_PORT_ARM_CM33_TFM_NON_SECURE_FIBER_PORT_TFM_ABI_H_ */
