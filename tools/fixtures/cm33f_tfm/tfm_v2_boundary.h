/* Typed integration fixture, NOT an actual TF-M checkout/provider. */
#ifndef C3FT_TYPED_TFM_V2_BOUNDARY_H
#define C3FT_TYPED_TFM_V2_BOUNDARY_H
#include <stdint.h>
uint32_t tfm_ns_interface_init(void);
void *os_wrapper_mutex_create(void);
uint32_t os_wrapper_mutex_acquire(void *handle, uint32_t timeout);
uint32_t os_wrapper_mutex_release(void *handle);
uint32_t os_wrapper_mutex_delete(void *handle);
#endif
