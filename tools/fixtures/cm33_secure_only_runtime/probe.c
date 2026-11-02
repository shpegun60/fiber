#include "main.h"
#include "report.h"
__attribute__((section(".fixture_stack_a"),aligned(8))) uint32_t fixture_stack_a[2048];
__attribute__((section(".fixture_stack_b"),aligned(8))) uint32_t fixture_stack_b[2048];
void fixture_main(void)
{
    volatile uint8_t *p=(volatile uint8_t *)(uintptr_t)0xe000e400u;
    uint32_t primask=__get_PRIMASK();__disable_irq();
    uint8_t old=*p;*p=255;__DSB();uint8_t mask=*p;*p=old;__DSB();__set_PRIMASK(primask);
    report_value("MODEL_PRIORITY_MASK",mask);report_value("MODEL_MPU_TYPE",MPU->TYPE);
    report_value("MODEL_CONTROL",__get_CONTROL());report_value("MODEL_CPACR",SCB->CPACR);
    report_value("MODEL_SAU_CTRL",SAU->CTRL);report_value("COMPILER_CMSE",__ARM_FEATURE_CMSE);
    report_exit(0,"PASS:C3SO-MODEL-PROBE\n");
}
__attribute__((noreturn)) void fixture_fault_report(const uint32_t *frame,uint32_t exc_return)
{
    report_value("FAULT_EXC_RETURN",exc_return);report_value("FAULT_PC",frame[6]);
    report_exit(1,"FAIL:C3SO-PROBE-FAULT\n");
}
