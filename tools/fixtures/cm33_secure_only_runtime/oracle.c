#include "fiber_port_private.h"
#include "fixture.h"
#include "fiber/fiber_runtime_state.h"
#include "report.h"
_Static_assert(FIBER_PORT_RUNTIME_SELECTABLE==EXEC_EXPECT_RUNTIME_SELECTABLE,"explicit pending/promotion state");
_Static_assert(__ARM_FEATURE_CMSE==3,"real Secure compiler mode");
_Static_assert(FIBER_PORT_CONTEXT_ABI_PORT_ID==0x4333534f && FIBER_PORT_CONTEXT_ABI_FEATURE_MASK==2,"C3SO identity");
static unsigned first_calls,selections,yields[2];
static uint32_t initial_r9[2];
static unsigned initial_verified[2];
static uint32_t cpacr,fpccr;
static const unsigned from[6]={0,1,0,0,1,1},to[6]={1,0,0,1,1,0};
extern const unsigned char fixture_vectors[];
static uint32_t addr(const void *p){return (uint32_t)(uintptr_t)p;}
static uint32_t top(unsigned id){return id?0x30008000u:0x30006000u;}
static void bank(void)
{
    CHECK(__TZ_get_PSP_NS()==0x20001000u && __TZ_get_PSPLIM_NS()==0x20000800u);
    CHECK(MPU->CTRL==0 && SCB->CPACR==cpacr && FPU->FPCCR==fpccr);
}
void fixture_reset_setup(void)
{
    SCB->VTOR=addr(fixture_vectors);__DSB();__ISB();
    __TZ_set_PSP_NS(0x20001000u);__TZ_set_PSPLIM_NS(0x20000800u);
    cpacr=SCB->CPACR;fpccr=FPU->FPCCR;
}
void fixture_boot_check(void)
{
    CHECK(__get_IPSR()==0 && __get_CONTROL()==0 && __get_PRIMASK()==0 && __get_BASEPRI()==0 && __get_FAULTMASK()==0);
    CHECK(fiber_current()==NULL && fiber_internal_runtime_context_configuration_is_open()==1);
    CHECK(SAU->CTRL==0 && cpacr==0);bank();
}
void fixture_initial_check(void)
{
    for(unsigned id=0;id<2;++id) {
        const FiberContext *c=&fixture_contexts[id];const uint32_t *w=c->sp;
        CHECK(addr(w)==top(id)-72 && w[0]==c->boot.stack_base && w[1]==0xfffffffdu);
        initial_r9[id]=w[7];
#if EXEC_RESERVED_R9
        CHECK(w[7]==(id?SEED_B:SEED_A));
#endif
        CHECK(c->boot.abi_port_id==0x4333534fu && c->boot.abi_feature_mask==2);
        CHECK(c->boot.abi_layout_version==0x10001u && c->boot.abi_context_size==76);
    }
#if EXEC_RESERVED_R9
    report_text("PASS:C3SO-RESERVED-R9-SEED\n");
#else
    report_text("PASS:C3SO-ORDINARY-AAPCS-FRAME\n");
#endif
}
void fixture_callee_check(uint32_t a,uint32_t b)
{
    CHECK(a==SEED_A && b==SEED_B);
    report_text("PASS:C3SO-PUBLIC-R9-CALLEE-SAVE\n");
}
static void initial(unsigned id)
{
    /* The genuine common return C path may reuse this initial stack capture. */
    if(initial_verified[id])return;
    const uint32_t *r=(const uint32_t *)(uintptr_t)(top(id)-56);
    for(unsigned i=0;i<14;++i) {
        uint32_t expected=i==0?(id?0x135700b0u:0x135700a0u):i==9?initial_r9[id]:
            i==13?(addr((const void *)&fiber_internal_task_return)|1u):0;
        CHECK(r[i]==expected);
    }
    const uint32_t *meta=(const uint32_t *)(uintptr_t)(top(id)-1080+512);
    CHECK(meta[0]==2 && meta[1]==top(id) && meta[2]==addr(&fixture_contexts[id]));
    initial_verified[id]=1;
}
static void captures(unsigned id,unsigned count)
{
    initial(id);
    for(unsigned n=0;n<count;++n) {
        const uint32_t *r=(const uint32_t *)(uintptr_t)(top(id)-1080+n*128);
        for(unsigned i=4;i<12;++i)CHECK(r[i]==(id?0x22000000u:0x11000000u)+i);
        CHECK(r[14]==2 && r[15]==top(id)-1080 && r[16]==addr(&fixture_contexts[id]));
        CHECK(r[17]==fixture_contexts[id].boot.stack_base && r[18]==0 && r[19]==0 && r[20]==0);
    }
}
void fixture_start_negative(void)
{
#if EXEC_CASE == 13
    /* AAPCS call boundary guarantees the first-origin alignment precondition. */
    extern void fixture_foreign_svc(void);
    fixture_foreign_svc();
#elif EXEC_CASE == 14
    SCB->ICSR=1u<<28;__DSB();__ISB();
#elif EXEC_CASE == 15
    __set_PRIMASK(1);
#endif
}
FIBER_SCHEDULER_HOOK_ATTR FiberContext *fixture_pick(FiberContext *current,void *user)
{
    CHECK(user==fixture_contexts && fiber_internal_runtime_context_configuration_is_open()==0);bank();
    if(current==NULL) {
        CHECK(first_calls++==0 && fixture_phase==3 && selections==0);
        CHECK(__get_IPSR()==0 && __get_CONTROL()==0 && __get_PRIMASK()==0 && __get_FAULTMASK()==0);
        CHECK(__get_BASEPRI()==FIBER_PORT_SCHEDULER_BASEPRI && fiber_current()==NULL);
        CHECK(NVIC_GetPriority(SVCall_IRQn)==0 && NVIC_GetPriority(PendSV_IRQn)==((1u<<__NVIC_PRIO_BITS)-1u));
        CHECK((SCB->CCR&(1u<<9))!=0);
        report_text("PASS:C3SO-REAL-FIRST-SELECTION\n");fixture_phase=4;
#if EXEC_CASE == 3
        return NULL;
#elif EXEC_CASE == 4
        __set_BASEPRI(64);
#elif EXEC_CASE == 5
        fixture_contexts[0].boot.hash^=1;
#elif EXEC_CASE == 6
        fixture_contexts[0].sp[1]=0xfffffffdu^0x40u;
#elif EXEC_CASE == 7
        fixture_contexts[0].sp+=1;
#elif EXEC_CASE == 18 || EXEC_CASE == 19
#if EXEC_CASE == 18
        fixture_contexts[0].boot.abi_port_id^=1u;
#else
        fixture_contexts[0].boot.abi_layout_version=0;
#endif
        fixture_contexts[0].boot.hash=fiber_port_boot_record_compute_hash(&fixture_contexts[0].boot);
#endif
        return &fixture_contexts[0];
    }
    CHECK(fixture_phase==4 && first_calls==1 && selections<6);
    unsigned id=from[selections],next=to[selections];
    CHECK(current==&fixture_contexts[id] && fiber_current()==current);
    CHECK(__get_IPSR()==14 && (__get_CONTROL()&3)==0 && __get_PRIMASK()==0 && __get_FAULTMASK()==0);
    CHECK(__get_BASEPRI()==FIBER_PORT_SCHEDULER_BASEPRI && __get_PSPLIM()==current->boot.stack_base);
    CHECK(addr(current->sp)+40==__get_PSP() && current->sp[0]==current->boot.stack_base && current->sp[1]==0xfffffffdu);
    CHECK(addr(current->sp)>=current->boot.stack_base && addr(current->sp)+72<=current->boot.stack_top);
    CHECK((current->sp[17]&0x010001ffu)==0x01000000u);
    CHECK(current->sp[16]>=0x10000800u && current->sp[16]<0x10020000u);
    captures(id,yields[id]++);++selections;report_value("PENDSV_SELECTION",selections);
#if EXEC_CASE == 8
    return NULL;
#endif
    return &fixture_contexts[next];
}
#if !defined(EXEC_DEFAULT_PANIC)
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    report_value("PANIC_CODE",(unsigned char)code);report_value("PANIC_IPSR",__get_IPSR());
#if EXEC_CASE == 0
    CHECK(code=='R' && __get_IPSR()==0 && __get_CONTROL()==2);
    CHECK(first_calls==1 && selections==6 && yields[0]==3 && yields[1]==3 && fiber_current()==&fixture_contexts[0]);
    captures(0,3);captures(1,2);bank();
    CHECK(__get_PSP()>=fixture_contexts[0].boot.stack_base && __get_PSP()<top(0));
    CHECK(__get_PSPLIM()==fixture_contexts[0].boot.stack_base);
    CHECK(__get_PRIMASK()==0 && __get_BASEPRI()==0 && __get_FAULTMASK()==0);
    report_value("VERIFIED_SWITCHES",selections);report_exit(0,"PASS:C3SO-FULL-RUNTIME\n");
#elif EXEC_CASE == 16
    CHECK(code=='9' && fixture_phase==1 && first_calls==0 && selections==0 && fiber_current()==NULL);
    CHECK(fixture_contexts[0].sp[7]==(SEED_A^1u));
    report_exit(0,"PASS:C3SO-SEED-CORRUPTION-REJECTED\n");
#else
    const char expected=EXEC_CASE==1||EXEC_CASE==2?'K':EXEC_CASE==3||EXEC_CASE==8?'N':
        EXEC_CASE==4||EXEC_CASE==17?'B':EXEC_CASE==10?'b':EXEC_CASE==5?'h':EXEC_CASE==6?'x':
        EXEC_CASE==7?'A':EXEC_CASE==9||EXEC_CASE==15?'p':EXEC_CASE==11?'f':EXEC_CASE==12?'l':
        EXEC_CASE==13?'u':EXEC_CASE==18||EXEC_CASE==19?'q':'j';
    CHECK(code==expected);
    if(EXEC_CASE==1||EXEC_CASE==2||EXEC_CASE==13||EXEC_CASE==14) {
        CHECK(fixture_phase==2 && first_calls==0 && selections==0 && fiber_current()==NULL);
        CHECK(__get_IPSR()==(EXEC_CASE==13?11u:EXEC_CASE==14?14u:0u));
    } else if(EXEC_CASE==15) {
        CHECK(fixture_phase==3 && first_calls==0 && selections==0 && fiber_current()==NULL && __get_IPSR()==0);
    } else if((EXEC_CASE>=3 && EXEC_CASE<=7)||EXEC_CASE==18||EXEC_CASE==19) {
        CHECK(fixture_phase==4 && first_calls==1 && selections==0 && fiber_current()==NULL && __get_IPSR()==0);
    } else {
        CHECK(fixture_phase==4 && first_calls==1 && fiber_current()==&fixture_contexts[0]);
        CHECK(__get_IPSR()==(EXEC_CASE==8||EXEC_CASE==17?14u:EXEC_CASE==12?11u:0u));
        CHECK(selections==(EXEC_CASE==8?1u:0u));
    }
    bank();report_exit(0,"PASS:C3SO-RUNTIME-NEGATIVE\n");
#endif
}
#endif
__attribute__((noreturn)) void fixture_fault_report(const uint32_t *frame,uint32_t exc_return)
{
    report_value("FAULT_EXC_RETURN",exc_return);report_value("FAULT_IPSR",__get_IPSR());
    report_value("FAULT_CFSR",SCB->CFSR);report_value("FAULT_PC",frame[6]);
    report_exit(1,"FAIL:C3SO-RUNTIME-FAULT\n");
}
