#ifndef C5SO_RUNTIME_FIXTURE_H
#define C5SO_RUNTIME_FIXTURE_H
#include "fiber/fiber_core.h"
#define SEED_A 0xa9a900a9u
#define SEED_B 0xb9b900b9u
#define HOSTILE_R9 0xbad00999u
extern FiberContext fixture_contexts[2];
extern uint32_t fixture_stack_a[2048],fixture_stack_b[2048];
extern volatile unsigned fixture_phase;
void fixture_task_a(void *);
void fixture_task_b(void *);
uint32_t fixture_construct(FiberContext *,void *,void *,entry_t,void *,uint32_t);
void fixture_callee_check(uint32_t,uint32_t);
FiberContext *fixture_pick(FiberContext *,void *);
void fixture_reset_setup(void);
void fixture_boot_check(void);
void fixture_initial_check(void);
void fixture_start_negative(void);
void fixture_probe(void);
#endif
