#include "fixture.h"

/* This allocating application uses the public facade, including its real
 * caller-storage expectation. No private port operation is called here. */
FiberContext fixture_contexts[2];
__attribute__((section(".fixture_stack_a"),aligned(32))) unsigned char fixture_stack_a[4096];
__attribute__((section(".fixture_stack_b"),aligned(32))) unsigned char fixture_stack_b[4096];
volatile unsigned fixture_phase;

void fixture_ns_main(void)
{
    fixture_boot_check();
    fixture_phase=1;
    fiber_init(&fixture_contexts[0],fixture_stack_a,fixture_stack_a+4096,fixture_task_a,0);
    fiber_init(&fixture_contexts[1],fixture_stack_b,fixture_stack_b+4096,fixture_task_b,0);
    fixture_phase=2;
#if EXEC_CASE == 1
    fiber_start();
#elif EXEC_CASE == 2
    fiber_scheduler_set_pick_next(0,fixture_contexts);
#endif
    fixture_configure_mask_negative();
    fiber_scheduler_set_pick_next(fixture_pick,fixture_contexts);
    fixture_phase=3;
    fiber_start();
}
