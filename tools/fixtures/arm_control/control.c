#include "report.h"
#define STRING_INNER(value) #value
#define STRING(value) STRING_INNER(value)

typedef struct ControlResult {
    uint32_t entry_control, ipsr, exc_return, entry_sp, entry_msp, entry_psp;
    uint32_t after_two, sp_after_two, after_three, sp_after_three;
    uint32_t return_control, return_sp;
} ControlResult;
_Static_assert(sizeof(ControlResult) == 48, "Assembly sample stride");
volatile ControlResult control_results[2];
volatile uint32_t control_phase;
extern uint8_t __msp_top[], __psp_top[];

__attribute__((noreturn)) void control_evaluate(void)
{
    for (uint32_t i = 0; i < 2; ++i) {
        const volatile ControlResult *r = &control_results[i];
        write_text(i == 0 ? "Thread-MSP" : "Thread-PSP");
        write_text(" entry="); write_hex(r->entry_control);
        write_text(" msr2="); write_hex(r->after_two);
        write_text(" msr3="); write_hex(r->after_three);
        write_text(" SP="); write_hex(r->entry_sp);
        write_text(" MSP="); write_hex(r->entry_msp);
        write_text(" PSP="); write_hex(r->entry_psp);
        write_text(" SP2="); write_hex(r->sp_after_two);
        write_text(" SP3="); write_hex(r->sp_after_three);
        write_text(" EXC_RETURN="); write_hex(r->exc_return);
        write_text(" return="); write_hex(r->return_control);
        write_text(" returnSP="); write_hex(r->return_sp);
        write_text("\n");
        require((r->entry_control & 3) == 0 && r->ipsr == 11, 30,
                "FAIL:CONTROL:exception-entry\n");
        require(r->entry_sp == r->entry_msp && r->entry_sp != r->entry_psp &&
                r->sp_after_two == r->entry_msp && r->sp_after_three == r->entry_msp,
                31, "FAIL:CONTROL:physical-MSP\n");
#if defined(BUG_RAZ_TWO)
        require((r->after_two & 3) == 0, 42, "FAIL:CONTROL:bug-RAZ-two\n");
#elif defined(BUG_RAZ_THREE)
        require((r->after_three & 3) == 1, 43, "FAIL:CONTROL:bug-RAZ-three\n");
#else
        require((r->after_two & 3) == EXPECT_TWO &&
                (r->after_three & 3) == EXPECT_THREE, 32,
                "FAIL:CONTROL:handler-write\n");
#endif
        require((r->exc_return & 12) == (i == 0 ? 8u : 12u), 33,
                "FAIL:CONTROL:EXC_RETURN-selection\n");
        require((r->return_control & 3) == (i == 0 ? 1u : 2u) &&
                r->return_sp == (uint32_t)(i == 0 ? __msp_top : __psp_top),
                34, "FAIL:CONTROL:exception-return\n");
    }
    finish(0, "PASS:CONTROL:" STRING(CONTROL_CPU) "\n");
}
