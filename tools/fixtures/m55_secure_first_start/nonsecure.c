#include "fiber_portmacro.h"
#include "fiber_port_private.h"
#include "fiber_port_secure_context_abi.h"
#include "fiber/fiber_runtime_state.h"
#include "report.h"
void *memset(void *,int,size_t);
extern void first_construct(FiberContext *,void *,void *,entry_t,void *);
extern void first_task_entry(void *);
extern void first_foreign_255(uintptr_t top);
extern void first_foreign_70(uintptr_t top);

/* Explicit staged harness identity, not a generic runtime provider. */
FIBER_PORT_CONTEXT_COHORT_DEFINE();
__attribute__((section(".fixture_case"),used)) volatile const uint32_t first_case=0;
__attribute__((used,externally_visible)) FiberContext first_context;
__attribute__((used,externally_visible)) uint32_t *volatile first_original_frame;
static __attribute__((aligned(8))) unsigned char first_stack[1024];
POINT void first_prepared(void){__asm volatile("nop" ::: "memory");}
POINT void first_entry_checkpoint(void){__asm volatile("nop" ::: "memory");}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_ram(uintptr_t begin,uintptr_t end)
{return begin>=0x20010000u&&end<=0x20020000u&&end>begin;}
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
int fiber_addr_plausible_code(uintptr_t address)
{return address>=0x10000u&&address<0x20000u;}
/* Real barrier semantics for the retained common state functions. No generic
 * scheduler/start/schedule forward adapters or common fiber core are linked. */
FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_runtime_memory_barrier(void){__DMB();__DSB();__ISB();}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_internal_task_return(void)
{finish(92,"FAIL:C55S-FIRST:terminal-task-return-called\n");}
FIBER_API_NORETURN FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_panic(char code)
{
    emit("PANIC:C55S-FIRST code=");hex((uint32_t)code);
    emit(" IPSR=");hex(__get_IPSR());emit("\n");
    finish(93,"PANIC-EXIT:C55S-FIRST\n");
}
__attribute__((noreturn)) void first_entry_report(const uint32_t *r,uint32_t sp,uint32_t control,uint32_t limit)
{
    require(first_case<=1u,200);
    require(__get_IPSR()==0u&&control==2u,201);
    require(sp==first_context.boot.stack_top&&limit==first_context.boot.stack_base,202);
    require(r[0]==0x12345678u&&r[1]==0u&&r[2]==0u&&r[3]==0u&&r[12]==0u,203);
    for(uint32_t i=4;i<12;++i){require(r[i]==(i==9u?0x91a2b3c4u:0u),204+i);}
    require(r[13]==(((uintptr_t)&fiber_internal_task_return)|1u),217);
    require(__get_PRIMASK()==0u&&__get_BASEPRI()==0u&&__get_FAULTMASK()==0u,218);
    /* Saved-frame bytes are live PSP stack after entry. RSP checks the whole
     * image before this entry's first push; C checks only the captured GPRs. */
    require(fiber_internal_runtime_current_context_slot==&first_context,221);
    require(first_context.boot.secure_stack_bytes==(first_case==1u?64u:0u),222);
    emit("ENTRY:C55S-FIRST:fiber r4-r11=");
    for(uint32_t i=4;i<12;++i){hex(r[i]);emit(" ");}emit("\n");
    first_entry_checkpoint();
    finish(0,"PASS:C55S-FIRST:fiber\nPASS-EXIT:C55S-FIRST\n");
}
__attribute__((noreturn)) void first_ns_main(void)
{
    emit("START:C55S-FIRST:NS-fiber case=");hex(first_case);emit("\n");
    require(__get_IPSR()==0u&&__get_CONTROL()==0u&&__get_PRIMASK()==0u&&
        __get_BASEPRI()==0u&&__get_FAULTMASK()==0u,230);
    memset(&first_context,0xa5,sizeof(first_context));
    memset(first_stack,0xa5,sizeof(first_stack));
    void *begin=first_stack+3,*end=first_stack+1021;
    if(first_case==24u){begin=(void *)0x20017f03u;end=(void *)0x200189fdu;}
    first_construct(&first_context,begin,end,first_task_entry,(void *)0x12345678u);
    first_original_frame=first_context.sp;
    const uintptr_t base=(((((uintptr_t)begin+3u)&~3u)+32u)+7u)&~7u;
    const uintptr_t top=((uintptr_t)end)&~7u;
    const uint32_t image[19]={0,base,0xffffffbcu,0,0,0,0,0,0x91a2b3c4u,0,0,
        0x12345678u,0,0,0,0,((uintptr_t)&fiber_internal_task_return)|1u,
        ((uintptr_t)first_task_entry)&~1u,0x01000000u};
    require((uintptr_t)first_context.sp==top-76u,231);
    for(uint32_t i=0;i<19;++i){require(first_context.sp[i]==image[i],240+i);}
    if(first_case!=0u){fiber_port_secure_context_attach(&first_context,64u);}
    fiber_internal_runtime_close_context_configuration();
    fiber_internal_runtime_publish_current_context(&first_context);
    if(first_case==5u){first_context.sp+=1;}
    if(first_case==6u){*(uint32_t *)((((uintptr_t)begin)+3u)&~3u)^=1u;}
    if(first_case==7u){first_context.sp[2]^=4u;}
    if(first_case==8u){first_context.boot.hash^=1u;}
    if(first_case==4u){REG(0xe000ed08)=0x10100u;}
    if(first_case==22u){
        first_context.boot.stack_top+=8u;first_context.boot.avail+=8u;
        first_context.boot.hash=fiber_port_boot_record_compute_hash(&first_context.boot);
    }
    first_prepared();
    if(first_case==27u){first_foreign_255(0x20020000u);}
    if(first_case==9u||first_case==10u||first_case==12u){
        const uintptr_t msp_top=fiber_port_prepare_first_start(&first_context);
        if(first_case==9u){first_foreign_255(msp_top);}
        if(first_case==10u){first_foreign_70(msp_top);}
        fiber_port_start_first_context(msp_top-8u);
    }
    fiber_port_first_start(&first_context);
}
