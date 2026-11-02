/* Context-owned declaration of the existing application-overridable panic. */
#ifndef CTXRT_CONTEXT_PANIC_H_
#define CTXRT_CONTEXT_PANIC_H_

#include "context_api_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef FIBER_REQUIRE
# define FIBER_REQUIRE(cond, code) do { if (!(cond)) fiber_panic((code)); } while (0)
#endif

/* References stay strong; only the bundled fallback definition is weak. */
CTXRT_API_NORETURN CTXRT_API_ATTR_SENSITIVE CTXRT_GENERAL_REGS_ONLY
void fiber_panic(char code);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* CTXRT_CONTEXT_PANIC_H_ */
