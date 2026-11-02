/* Ordinary Secure C caller: no private guard/provider root is manufactured. */
#include <stdint.h>

#ifndef COHORT_QUERY
#error "Select one ordinary immutable query"
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t COHORT_QUERY(void);

uint32_t cohort_consumer(void)
{
    return COHORT_QUERY();
}

#ifdef __cplusplus
}
#endif
