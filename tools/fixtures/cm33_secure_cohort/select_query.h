/* Fixture-only NSC projection. The selected production definition inherits
 * its original entry attribute; siblings keep canonical private attributes
 * but cannot become implicit CMSE linker roots. No body or RETAIN is changed.
 */
#ifndef CM33_SECURE_COHORT_SELECT_QUERY_H
#define CM33_SECURE_COHORT_SELECT_QUERY_H
#ifndef COHORT_QUERY
#error "Select exactly one production query"
#endif
#include <stdint.h>
#include "fiber/fiber_api_attributes.h"

#define fiber_secure_gatewayNON_SECURE_CALLABLE \
    FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY

__attribute__((cmse_nonsecure_entry))
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t COHORT_QUERY(void);

#endif
