/*
 * fiber_runtime_state.c
 *
 * Runtime-owned port/scheduler state used by PendSV ports.
 */

#include "fiber_runtime_state.h"
#include "port/fiber_port_selected.h"

FiberContext *volatile fiber_internal_port_current_context = 0;
FiberSchedulerPickNextFn volatile fiber_internal_port_scheduler_pick_next = 0;
void *volatile fiber_internal_port_scheduler_user = 0;
static volatile uint32_t fiber_internal_port_scheduler_selecting = 0;

typedef struct FiberSchedulerCpuState {
	uint32_t primask;
	uint32_t control;
#if FIBER_PORT_HAS_BASEPRI
	uint32_t basepri;
#endif
#if FIBER_PORT_HAS_FAULTMASK
	uint32_t faultmask;
#endif
} FiberSchedulerCpuState;

#ifndef FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH
# define FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH 0
#endif

#if (FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 0) && \
		(FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH != 1)
# error "[fiber]: FIBER_VALIDATE_BOOT_RECORD_HASH_ON_SWITCH must be 0 or 1"
#endif

static FIBER_GENERAL_REGS_ONLY
void fiber_internal_capture_scheduler_cpu_state(FiberSchedulerCpuState *const state)
{
	FIBER_REQUIRE(state != 0, 'C');

	__COMPILER_BARRIER();
	state->primask = __get_PRIMASK();
	state->control = __get_CONTROL();
#if FIBER_PORT_HAS_BASEPRI
	state->basepri = fiber_port_basepri_read();
#endif
#if FIBER_PORT_HAS_FAULTMASK
	state->faultmask = __get_FAULTMASK();
#endif
	__COMPILER_BARRIER();
}

static FIBER_GENERAL_REGS_ONLY
void fiber_internal_validate_scheduler_cpu_state(
		const FiberSchedulerCpuState *const before)
{
	FIBER_REQUIRE(before != 0, 'C');

	__COMPILER_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'r');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
#if FIBER_PORT_HAS_BASEPRI
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'B');
#endif
#if FIBER_PORT_HAS_FAULTMASK
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 't');
#endif
	__COMPILER_BARRIER();
}

void fiber_internal_port_scheduler_set_pick_next(FiberSchedulerPickNextFn pick_next,
                                                 void *user)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(fiber_internal_port_current_context == 0, 'k');
	FIBER_REQUIRE(fiber_internal_port_scheduler_selecting == 0u, 'k');
	FIBER_REQUIRE(pick_next != 0, 'K');

	__DMB();
	fiber_internal_port_scheduler_user = user;
	__DMB();
	fiber_internal_port_scheduler_pick_next = pick_next;
	__DMB();
}

FIBER_GENERAL_REGS_ONLY
void fiber_internal_require_schedule_current(void)
{
	__COMPILER_BARRIER();
	FIBER_REQUIRE(fiber_internal_port_current_context != 0, 'G');
	__COMPILER_BARRIER();
}

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_pick_first_from_start(void)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;
	__DMB();
	void *const user = fiber_internal_port_scheduler_user;

	FIBER_REQUIRE(pick_next != 0, 'K');

	__DMB();
	fiber_internal_port_scheduler_selecting = 1u;
	__DMB();

	const uint32_t critical_state = fiber_port_scheduler_critical_enter();
	FiberSchedulerCpuState cpu_state;
	fiber_internal_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const first = pick_next(0, user);

	fiber_internal_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(first);
	fiber_port_scheduler_critical_exit(critical_state);

	__DMB();
	fiber_internal_port_scheduler_selecting = 0u;
	__DMB();

	return first;
}

FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_internal_scheduler_pick_next_from_pendsv(FiberContext *current)
{
	FiberSchedulerPickNextFn const pick_next = fiber_internal_port_scheduler_pick_next;
	__DMB();
	void *const user = fiber_internal_port_scheduler_user;

	FIBER_REQUIRE(current != 0, 'C');
	FIBER_REQUIRE(pick_next != 0, 'K');
	fiber_port_context_validate_restore(current);

	FiberSchedulerCpuState cpu_state;
	fiber_internal_capture_scheduler_cpu_state(&cpu_state);
	FiberContext *const next = pick_next(current, user);

	fiber_internal_validate_scheduler_cpu_state(&cpu_state);
	fiber_port_context_validate_restore(next);

	__DMB();
	fiber_internal_port_current_context = next;
	__DMB();

	return next;
}
