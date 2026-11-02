/* Intentionally opaque: no selected type, private port, CMSIS or feature test. */
#include "api_fixture.h"
RuntimeScheduler runtime_scheduler;
__attribute__((noinline,noclone,used,externally_visible))
FiberContext *runtime_pick(FiberContext *current,void *user)
{
    RuntimeScheduler *const state=(RuntimeScheduler *)user;
    if(state!=&runtime_scheduler){runtime_application_failure(10);}
    const uint32_t index=state->first_calls+state->switches;
    if(index>=8u){runtime_application_failure(11);}
    state->arguments[index]=(uintptr_t)current;
    state->observed_current[index]=(uintptr_t)fiber_current();
    if(fiber_current()!=current){runtime_application_failure(12);}
    runtime_callback_inside();
    runtime_callback_action();
    if(!current){
        if(state->first_calls!=0u||state->switches!=0u){runtime_application_failure(13);}
        state->first_calls=1u;
        return runtime_fault==1u?0:state->contexts[0];
    }
    if(state->first_calls!=1u||current!=state->contexts[state->selected]){
        runtime_application_failure(14);
    }
    ++state->switches;
    state->selected^=1u;
    return runtime_fault==2u?0:state->contexts[state->selected];
}
void runtime_register(FiberContext *a,FiberContext *b)
{
    runtime_scheduler.contexts[0]=a;
    runtime_scheduler.contexts[1]=b;
    fiber_scheduler_set_pick_next(runtime_pick,&runtime_scheduler);
}
