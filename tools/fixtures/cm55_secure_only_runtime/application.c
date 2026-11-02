#include "fixture.h"
FiberContext fixture_contexts[2];
__attribute__((section(".fixture_stack_a"),aligned(8))) uint32_t fixture_stack_a[2048];
__attribute__((section(".fixture_stack_b"),aligned(8))) uint32_t fixture_stack_b[2048];
volatile unsigned fixture_phase;
void fixture_main(void)
{
    fixture_reset_setup();fixture_boot_check();
    fixture_phase=1;
    uint32_t a=fixture_construct(&fixture_contexts[0],fixture_stack_a,fixture_stack_a+2048,
            fixture_task_a,(void *)(uintptr_t)0x135700a0u,SEED_A);
    uint32_t b=fixture_construct(&fixture_contexts[1],fixture_stack_b,fixture_stack_b+2048,
            fixture_task_b,(void *)(uintptr_t)0x135700b0u,SEED_B);
    fixture_callee_check(a,b);
    fixture_initial_check();fixture_phase=2;
#if EXEC_CASE == 1
    fiber_start();
#elif EXEC_CASE == 2
    fiber_scheduler_set_pick_next(NULL,fixture_contexts);
#endif
    fixture_start_negative();
    fiber_scheduler_set_pick_next(fixture_pick,fixture_contexts);
    fixture_phase=3;fiber_start();
}
