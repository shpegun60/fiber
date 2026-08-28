/* Cooperative implementation of the TF-M v2.0.0 mutex wrapper ABI. */

#include "fiber_port_private.h"
#include "fiber_port_tfm_os_wrapper.h"
#include "../../../fiber_api_decl.h"

typedef struct FiberPortTfmMutex {
	FiberContext *volatile owner;
	volatile uint32_t created;
} FiberPortTfmMutex;

static FiberPortTfmMutex fiber_port_tfm_mutex;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_tfm_primask_save_disable(void)
{
	uint32_t state;
	fiber_portASM volatile(
			"mrs %0, primask \n"
			"cpsid i         \n"
			: "=r"(state)
			:
			: "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	return state;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_tfm_primask_restore(const uint32_t state)
{
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portASM volatile("msr primask, %0" :: "r"(state) : "memory");
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	FIBER_REQUIRE(__get_PRIMASK() == state, 'r');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_tfm_require_unmasked_thread(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
FiberContext *fiber_port_tfm_require_running_fiber(void)
{
	fiber_port_tfm_require_unmasked_thread();
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 2u, 'l');
	FiberContext *const current = fiber_current();
	FIBER_REQUIRE(current != NULL, 'K');
	return current;
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
uint32_t fiber_port_tfm_mutex_handle_is_valid(const void *const handle)
{
	return (handle == (const void *)&fiber_port_tfm_mutex) &&
			(fiber_port_tfm_mutex.created == 1u);
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_tfm_mutex_state_check(void)
{
	FIBER_REQUIRE(fiber_port_tfm_mutex.created <= 1u, 'Q');
	if (fiber_port_tfm_mutex.created == 0u) {
		FIBER_REQUIRE(fiber_port_tfm_mutex.owner == NULL, 'Q');
	}
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
void *os_wrapper_mutex_create(void)
{
	fiber_port_tfm_require_unmasked_thread();
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 0u, 'l');
	const uint32_t primask = fiber_port_tfm_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');
	fiber_port_tfm_mutex_state_check();
	void *handle = NULL;
	if ((fiber_port_tfm_mutex.created == 0u) &&
			(fiber_port_tfm_mutex.owner == NULL)) {
		fiber_port_tfm_mutex.created = 1u;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
		handle = &fiber_port_tfm_mutex;
	}
	fiber_port_tfm_primask_restore(primask);
	return handle;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t os_wrapper_mutex_acquire(void *const handle,
		const uint32_t timeout)
{
	for (;;) {
		FiberContext *const current =
				fiber_port_tfm_require_running_fiber();
		const uint32_t primask = fiber_port_tfm_primask_save_disable();
		FIBER_REQUIRE(primask == 0u, 'p');
		fiber_port_tfm_mutex_state_check();
		if (fiber_port_tfm_mutex_handle_is_valid(handle) == 0u) {
			fiber_port_tfm_primask_restore(primask);
			return FIBER_PORT_TFM_OS_WRAPPER_ERROR;
		}
		if (fiber_port_tfm_mutex.owner == NULL) {
			fiber_port_tfm_mutex.owner = current;
			fiber_portDATA_SYNC_BARRIER();
			fiber_portINST_SYNC_BARRIER();
			fiber_portCOMPILER_BARRIER();
			FIBER_REQUIRE(fiber_port_tfm_mutex.owner == current, 'Q');
			fiber_port_tfm_primask_restore(primask);
			return FIBER_PORT_TFM_OS_WRAPPER_SUCCESS;
		}
		if (fiber_port_tfm_mutex.owner == current) {
			fiber_port_tfm_primask_restore(primask);
			return FIBER_PORT_TFM_OS_WRAPPER_ERROR;
		}
		fiber_port_tfm_primask_restore(primask);
		if (timeout != FIBER_PORT_TFM_OS_WRAPPER_WAIT_FOREVER) {
			return FIBER_PORT_TFM_OS_WRAPPER_ERROR;
		}
		fiber_port_runtime_schedule();
	}
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t os_wrapper_mutex_release(void *const handle)
{
	FiberContext *const current = fiber_port_tfm_require_running_fiber();
	const uint32_t primask = fiber_port_tfm_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');
	fiber_port_tfm_mutex_state_check();
	if ((fiber_port_tfm_mutex_handle_is_valid(handle) == 0u) ||
			(fiber_port_tfm_mutex.owner != current)) {
		fiber_port_tfm_primask_restore(primask);
		return FIBER_PORT_TFM_OS_WRAPPER_ERROR;
	}
	fiber_port_tfm_mutex.owner = NULL;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(fiber_port_tfm_mutex.owner == NULL, 'Q');
	fiber_port_tfm_primask_restore(primask);
	return FIBER_PORT_TFM_OS_WRAPPER_SUCCESS;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t os_wrapper_mutex_delete(void *const handle)
{
	fiber_port_tfm_require_unmasked_thread();
	const uint32_t control = __get_CONTROL() & 3u;
	FIBER_REQUIRE((control == 0u) || (control == 2u), 'l');
	const uint32_t primask = fiber_port_tfm_primask_save_disable();
	FIBER_REQUIRE(primask == 0u, 'p');
	fiber_port_tfm_mutex_state_check();
	if ((fiber_port_tfm_mutex_handle_is_valid(handle) == 0u) ||
			(fiber_port_tfm_mutex.owner != NULL)) {
		fiber_port_tfm_primask_restore(primask);
		return FIBER_PORT_TFM_OS_WRAPPER_ERROR;
	}
	fiber_port_tfm_mutex.created = 0u;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(fiber_port_tfm_mutex.created == 0u, 'Q');
	fiber_port_tfm_primask_restore(primask);
	return FIBER_PORT_TFM_OS_WRAPPER_SUCCESS;
}
