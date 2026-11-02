#include "fixture.h"
#include "report.h"
FiberContext fixture_contexts[2];
__attribute__((used,section(".fixture_stack_a"),aligned(8))) uint32_t fixture_stack_a[2048];
__attribute__((used,section(".fixture_stack_b"),aligned(8))) uint32_t fixture_stack_b[2048];
volatile unsigned fixture_phase;
static void never_started(void *arg) {(void)arg;report_exit(1,"FAIL:C3SO-INIT-ONLY-TASK\n");}
void fixture_main(void)
{
    uint32_t saved=fixture_construct(&fixture_contexts[0],fixture_stack_a,fixture_stack_a+2048,
            never_started,NULL,SEED_A);
    CHECK(saved==SEED_A);
    report_exit(0,"PASS:C3SO-INIT-ONLY\n");
}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code) {report_value("PANIC_CODE",(unsigned char)code);report_exit(1,"FAIL:C3SO-INIT-ONLY\n");}
__attribute__((noreturn)) void fixture_fault_report(const uint32_t *frame,uint32_t exc_return)
{
    report_value("FAULT_EXC_RETURN",exc_return);report_value("FAULT_PC",frame[6]);
    report_exit(1,"FAIL:C3SO-INIT-ONLY-FAULT\n");
}
