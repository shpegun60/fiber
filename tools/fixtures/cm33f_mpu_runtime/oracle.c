#include "fiber_port_private.h"
#include "fixture.h"
#include "fiber/fiber_runtime_state.h"
#pragma GCC push_options
#pragma GCC target("general-regs-only")
#include "../cm33f_mpu_first_start_execution/report.h"
#define CHECK(c) report_check((c),__LINE__)
#define REG(a) (*(volatile uint32_t *)(uintptr_t)(a))
_Static_assert(FIBER_PORT_RUNTIME_SELECTABLE==EXEC_EXPECT_RUNTIME_SELECTABLE,"explicit runtime manifest");
static unsigned first_calls,selections,yields[2];
static const unsigned from[6]={0,1,0,0,1,1},to[6]={1,0,0,1,1,0};
static uint32_t addr(const void *p) {return (uint32_t)(uintptr_t)p;}
static uint32_t top(unsigned id) {return id?0x20008000u:0x20007000u;}
static unsigned fp(unsigned id) {return EXEC_FP==1 || (EXEC_FP==2 && id==0);}
static uint32_t fpvalue(unsigned id,unsigned reg) {return (id?0x40100000u:0x3f100000u)+reg*0x1000u;}
static void mpu(unsigned id)
{
    uint32_t bases[8]={0x10004,0x20006,0x28006,0x20004021,(id?0x20007000u:0x20006000u)|3u,0x20004007,0,0};
    uint32_t limits[8]={0x1ffe1,0x27fe1,0x28fe1,0x20005fe1,((top(id)-1u)&~31u)|1u,0x20004001,0,0};
    CHECK(REG(0xe000ed94u)==5 && REG(0xe000edc0u)==0x04ff);
    uint32_t rnr=REG(0xe000ed98u);
    for(unsigned i=0;i<8;++i) {
        REG(0xe000ed98u)=i;__DSB();__ISB();
        CHECK(REG(0xe000ed9cu)==bases[i] && REG(0xe000eda0u)==limits[i]);
    }
    REG(0xe000ed98u)=rnr;__DSB();__ISB();
}
static void captures(unsigned id,unsigned count)
{
    const uint32_t *initial=(const uint32_t *)(uintptr_t)(top(id)-1024u+768u);
    CHECK(*initial==addr(&fixture_contexts[id]));
    for(unsigned round=0;round<count;++round) {
        const uint32_t *r=(const uint32_t *)(uintptr_t)(top(id)-1024u+round*256u);
        /* A public C call may clobber caller-saved GP registers. */
        for(unsigned i=4;i<12;++i) CHECK(r[i]==(id?0x22000000u:0x11000000u)+i);
        CHECK(r[14]==(fp(id)?7u:3u) && r[15]==top(id)-1024u);
        CHECK(r[16]==addr(&fixture_contexts[id]));
        if(fp(id)) {
            for(unsigned i=0;i<32;++i) CHECK(r[20+i]==fpvalue(id,i));
            CHECK(r[52]==(id?0x00800000u:0x00400000u));
        }
    }
}
void fixture_boot_check(void)
{
    CHECK(__get_IPSR()==0 && __get_CONTROL()==0 && __get_PRIMASK()==0);
    CHECK(__get_BASEPRI()==0 && __get_FAULTMASK()==0 && REG(0xe000ed94u)==0);
    CHECK(fiber_current()==NULL);
    CHECK(fiber_internal_runtime_context_configuration_is_open()==1);
}
void fixture_configure_mask_negative(void)
{
#if EXEC_CASE == 12
    __set_PRIMASK(1);
#endif
}
FIBER_SCHEDULER_HOOK_ATTR FiberContext *fixture_pick(FiberContext *current,void *user)
{
    CHECK(user==fixture_contexts && fixture_phase==3);
    CHECK(fiber_internal_runtime_context_configuration_is_open()==0);
    if(current==NULL) {
        CHECK(first_calls++==0 && selections==0);
        CHECK(__get_IPSR()==0 && __get_CONTROL()==0 && __get_PRIMASK()==1);
        CHECK(__get_BASEPRI()==0 && __get_FAULTMASK()==0 && REG(0xe000ed94u)==0);
        CHECK(fiber_current()==NULL && fiber_internal_runtime_current_context_slot==NULL);
        CHECK(REG(0xe000ed88u)==0x00f00000u);
        CHECK((REG(0xe000ef34u)&0xc0000001u)==(FIBER_FPU_LAZY?0xc0000000u:0x80000000u));
        CHECK(NVIC_GetPriority(SVCall_IRQn)==0 && NVIC_GetPriority(PendSV_IRQn)==((1u<<__NVIC_PRIO_BITS)-1u));
        report_text("PASS:C3FP-REAL-FIRST-SELECTION\n");
#if EXEC_CASE == 3
        return NULL;
#elif EXEC_CASE == 4
        fiber_scheduler_set_pick_next(fixture_pick,fixture_contexts);
#elif EXEC_CASE == 5
        __set_BASEPRI(128);
#elif EXEC_CASE == 11
        fixture_contexts[0].boot.hash^=1u;
#endif
        return &fixture_contexts[0];
    }
    CHECK(first_calls==1 && selections<6);
    unsigned id=from[selections],next=to[selections];
    CHECK(current==&fixture_contexts[id] && fiber_current()==current);
    CHECK(fiber_internal_runtime_current_context_slot==current);
    CHECK(__get_IPSR()==14 && __get_PRIMASK()==0 && __get_FAULTMASK()==0);
    CHECK(__get_BASEPRI()==FIBER_PORT_SCHEDULER_BASEPRI && (__get_CONTROL()&3u)==1u);
    mpu(id);
    const uint32_t *w=current->protected_context.words;
    unsigned special=fp(id)?49u:16u,core=fp(id)?41u:8u;
    CHECK(current->protected_context_cursor==&w[fp(id)?53:20] && w[53]==0);
    CHECK(w[special]==__get_PSP() && w[special+1]==__get_PSPLIM());
    CHECK(w[special]>=current->boot.stack_base && w[special]+(fp(id)?104u:32u)<=current->boot.stack_top);
    CHECK(w[special+3]==(fp(id)?0xffffffacu:0xffffffbcu));
    CHECK(w[core+6]==(addr(fiber_port_svc_yield_return_site)&~1u));
    if(fp(id)) {
        for(unsigned i=0;i<16;++i) CHECK(w[i]==fpvalue(id,i+16) && w[16+i]==fpvalue(id,i));
        CHECK(w[32]==(id?0x00800000u:0x00400000u));
    }
    captures(id,yields[id]++);
    ++selections;report_value("PENDSV_SELECTION",selections);
#if EXEC_CASE == 6
    return NULL;
#elif EXEC_CASE == 9
    __set_PRIMASK(1);
#elif EXEC_CASE == 10
    REG(0xe000ed98u)=4;REG(0xe000ed9cu)^=32;__DSB();__ISB();
#endif
    return &fixture_contexts[next];
}

/* Application override of the documented weak panic hook, not a reverse stub. */
#if !defined(EXEC_DEFAULT_PANIC)
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    report_value("PANIC_CODE",(unsigned char)code);report_value("PANIC_IPSR",__get_IPSR());
#if EXEC_CASE == 0
    CHECK(code=='R' && __get_IPSR()==11 && first_calls==1 && selections==6);
    CHECK(yields[0]==3 && yields[1]==3 && fiber_current()==&fixture_contexts[0]);
    captures(0,3);captures(1,2);mpu(0);
    CHECK(__get_PRIMASK()==0 && __get_BASEPRI()==0 && __get_FAULTMASK()==0);
    CHECK(__get_PSPLIM()==fixture_contexts[0].boot.stack_base && (__get_CONTROL()&3u)==1);
    report_value("VERIFIED_SWITCHES",selections);report_value("VERIFIED_FP_TASKS",fp(0)+fp(1));
    report_exit(0,"PASS:C3FP-FULL-RUNTIME\n");
#else
    const char expected=EXEC_CASE==1||EXEC_CASE==2?'K':EXEC_CASE==3||EXEC_CASE==6?'N':
        EXEC_CASE==4||EXEC_CASE==12?'p':EXEC_CASE==5?'B':EXEC_CASE==7||EXEC_CASE==8?'u':
        EXEC_CASE==9?'r':EXEC_CASE==11?'h':EXEC_CASE==13?'L':'M';
    CHECK(code==expected);
#if EXEC_CASE == 7 || EXEC_CASE == 8
    extern const unsigned char fixture_foreign_yield_continuation[],fixture_foreign_return_continuation[];
    const uint32_t *foreign_frame=(const uint32_t *)(uintptr_t)__get_PSP();
    const uint32_t pc=foreign_frame[6];
    CHECK(pc>=0x28002u && pc<0x29000u);
    CHECK(pc==(addr(EXEC_CASE==7?fixture_foreign_yield_continuation:fixture_foreign_return_continuation)&~1u));
    CHECK(*(const volatile uint16_t *)(uintptr_t)(pc-2u)==(EXEC_CASE==7?0xdf47u:0xdf48u));
    CHECK(pc!=(addr(EXEC_CASE==7?fiber_port_svc_yield_return_site:fiber_port_svc_return_return_site)&~1u));
#endif
    if(EXEC_CASE==1||EXEC_CASE==2||EXEC_CASE==12) {
        CHECK(__get_IPSR()==0 && first_calls==0 && selections==0 && fixture_phase==2);
        CHECK(fiber_internal_runtime_current_context_slot==NULL && REG(0xe000ed94u)==0);
    } else if(EXEC_CASE==13) {
        CHECK(__get_IPSR()==0 && first_calls==0 && selections==0 && fixture_phase==3);
        CHECK(fiber_internal_runtime_current_context_slot==NULL && REG(0xe000ed94u)==0);
    } else if(EXEC_CASE==3||EXEC_CASE==4||EXEC_CASE==5||EXEC_CASE==11) {
        CHECK(__get_IPSR()==0 && first_calls==1 && selections==0 && fixture_phase==3);
        CHECK(fiber_internal_runtime_current_context_slot==NULL && REG(0xe000ed94u)==0);
    } else {
        CHECK(__get_IPSR()==(EXEC_CASE==7||EXEC_CASE==8?11u:14u));
        CHECK(first_calls==1 && selections==(EXEC_CASE==7||EXEC_CASE==8?0u:1u));
        CHECK(fiber_internal_runtime_current_context_slot==&fixture_contexts[0]);
        CHECK(REG(0xe000ed94u)==5);
    }
    report_exit(0,"PASS:C3FP-RUNTIME-NEGATIVE\n");
#endif
}
#endif
__attribute__((noreturn)) void fixture_fault_report(const uint32_t *frame,uint32_t exc_return)
{
    report_value("FAULT_EXC_RETURN",exc_return);report_value("FAULT_PC",frame[6]);
    report_value("FAULT_CFSR",SCB->CFSR);report_value("FAULT_IPSR",__get_IPSR());
    report_exit(1,"FAIL:C3FP-RUNTIME-FAULT\n");
}
#pragma GCC pop_options
