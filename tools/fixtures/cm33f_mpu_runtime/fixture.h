#ifndef CM33F_MPU_RUNTIME_FIXTURE_H
#define CM33F_MPU_RUNTIME_FIXTURE_H
#include "fiber/fiber_core.h"
extern FiberContext fixture_contexts[2];
extern unsigned char fixture_stack_a[4096], fixture_stack_b[4096];
extern volatile unsigned fixture_phase;
void fixture_task_a(void *);
void fixture_task_b(void *);
FiberContext *fixture_pick(FiberContext *, void *);
void fixture_boot_check(void);
void fixture_configure_mask_negative(void);
#endif
