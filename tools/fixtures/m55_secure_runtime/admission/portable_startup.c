#include "fiber/fiber_api_attributes.h"
FIBER_API_NORETURN void fiber_portable_application_fixture(void);
#ifdef __cplusplus
extern "C"
#endif
FIBER_API_NORETURN void Reset_Handler(void)
{
    fiber_portable_application_fixture();
}
