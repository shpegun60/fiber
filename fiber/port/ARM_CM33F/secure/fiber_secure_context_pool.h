/* Secure-only, serialized single-core boot storage. No NSC lifecycle API,
 * CPU operations, allocator, free, or concurrency support is supplied here. */
#ifndef FIBER_ARM_CM33F_SECURE_CONTEXT_POOL_H_
#define FIBER_ARM_CM33F_SECURE_CONTEXT_POOL_H_
#include "fiber_secure_context_manifest.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Read-only boot admission. Normal startup must zero the separate 4-byte
 * marker; NOLOAD contents are not trusted until boot_initialize succeeds. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_is_pristine(void);

/* Returns 1 only after scrubbing and reading back every NOLOAD byte.
 * INITIALIZING/READY repeats return 0; unknown state or scrub failure traps.
 * Partial failure is terminal until an integration-owned fresh BSS startup. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_secure_context_pool_boot_initialize(void);
#ifdef __cplusplus
}
#endif
#endif
