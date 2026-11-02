#ifndef C55S_RUNTIME_API_FIXTURE_H
#define C55S_RUNTIME_API_FIXTURE_H
#include <stdint.h>
#include "fiber/fiber_api_decl.h"
typedef struct RuntimeScheduler {
    FiberContext *contexts[2];
    uint32_t selected, switches, first_calls;
    uintptr_t arguments[8], observed_current[8];
} RuntimeScheduler;
extern RuntimeScheduler runtime_scheduler;
extern volatile const uint32_t runtime_case, runtime_fault;
void runtime_register(FiberContext *,FiberContext *);
void runtime_callback_inside(void);
void runtime_application_failure(uint32_t);
void runtime_callback_action(void);
#endif
