/* Test entry only; the shared application source is compiled without edits. */
#include "fiber/fiber_api_attributes.h"
FIBER_API_NORETURN void fiber_portable_application_fixture(void);
#ifdef __cplusplus
extern "C"
#endif
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void Reset_Handler(void) { fiber_portable_application_fixture(); }
