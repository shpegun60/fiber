/*
 * Portable application fixture.
 *
 * This translation unit deliberately includes only the public fiber header and
 * uses only the five-function portable API. The compile matrix builds this
 * exact source against every selected profile.
 */

#include "fiber/fiber_core.h"

enum {
	PORTABLE_FIXTURE_STACK_SIZE = 2048
};

static _Alignas(8) unsigned char portable_fixture_stack_1[PORTABLE_FIXTURE_STACK_SIZE];
static _Alignas(8) unsigned char portable_fixture_stack_2[PORTABLE_FIXTURE_STACK_SIZE];
static FiberContext portable_fixture_context_1;
static FiberContext portable_fixture_context_2;

static FIBER_SCHEDULER_HOOK_ATTR
FiberContext *portable_fixture_pick_next(FiberContext *current, void *user)
{
	(void)user;
	return (current == &portable_fixture_context_1) ?
			&portable_fixture_context_2 : &portable_fixture_context_1;
}

static void portable_fixture_entry(void *arg)
{
	(void)arg;
	(void)fiber_current();
	fiber_schedule();

	for (;;) {
		fiber_schedule();
	}
}

FIBER_API_NORETURN
void fiber_portable_application_fixture(void)
{
	fiber_init(&portable_fixture_context_1,
			portable_fixture_stack_1,
			portable_fixture_stack_1 + sizeof(portable_fixture_stack_1),
			portable_fixture_entry,
			(void *)0);
	fiber_init(&portable_fixture_context_2,
			portable_fixture_stack_2,
			portable_fixture_stack_2 + sizeof(portable_fixture_stack_2),
			portable_fixture_entry,
			(void *)0);
	fiber_scheduler_set_pick_next(portable_fixture_pick_next, (void *)0);
	fiber_start();
}
