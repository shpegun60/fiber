/* ARM_CM33 TF-M Non-secure interface initialization. */

#include "fiber_port_private.h"
#include "fiber_port_tfm_abi.h"

/* Defined by TF-M v2.0.0 interface/src/os_wrapper/tfm_ns_interface_rtos.c. */
extern uint32_t tfm_ns_interface_init(void);

const unsigned char fiber_port_arm_cm33_tfm_integration_bundle_v1_anchor
		__attribute__((used)) = 1u;

enum FiberPortTfmInitializationState {
	fiber_portTFM_UNINITIALIZED = 0u,
	fiber_portTFM_INITIALIZING = 1u,
	fiber_portTFM_READY = 2u,
	fiber_portTFM_FAILED = 3u
};

typedef struct FiberPortTfmCpuState {
	uint32_t ipsr;
	uint32_t primask;
	uint32_t basepri;
	uint32_t faultmask;
	uint32_t control;
	uint32_t psplim;
} FiberPortTfmCpuState;

static volatile uint32_t fiber_port_tfm_initialization_state;

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_tfm_require_prestart_environment(void)
{
	FIBER_REQUIRE(__get_IPSR() == 0u, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == 0u, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == 0u, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == 0u, 'f');
	FIBER_REQUIRE((__get_CONTROL() & 3u) == 0u, 'l');
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_tfm_capture_cpu_state(FiberPortTfmCpuState *const state)
{
	FIBER_REQUIRE(state != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	state->ipsr = __get_IPSR();
	state->primask = __get_PRIMASK();
	state->basepri = fiber_port_basepri_read();
	state->faultmask = __get_FAULTMASK();
	state->control = __get_CONTROL();
	state->psplim = __get_PSPLIM();
	fiber_portCOMPILER_BARRIER();
}

static FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_tfm_validate_cpu_state(
		const FiberPortTfmCpuState *const before)
{
	FIBER_REQUIRE(before != NULL, 'C');
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(__get_IPSR() == before->ipsr, 'i');
	FIBER_REQUIRE(__get_PRIMASK() == before->primask, 'p');
	FIBER_REQUIRE(fiber_port_basepri_read() == before->basepri, 'b');
	FIBER_REQUIRE(__get_FAULTMASK() == before->faultmask, 'f');
	FIBER_REQUIRE(__get_CONTROL() == before->control, 'l');
	FIBER_REQUIRE(__get_PSPLIM() == before->psplim, 'L');
	fiber_portCOMPILER_BARRIER();
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY FIBER_API_THREAD_FUNCTION
uint32_t fiber_port_tfm_initialize(void)
{
	fiber_port_tfm_require_prestart_environment();
	const uint32_t state = fiber_port_tfm_initialization_state;
	if (state == fiber_portTFM_READY) {
		return FIBER_PORT_TFM_SUCCESS;
	}
	if (state != fiber_portTFM_UNINITIALIZED) {
		return FIBER_PORT_TFM_ERROR;
	}

	FiberPortTfmCpuState cpu_state;
	fiber_port_tfm_capture_cpu_state(&cpu_state);
	fiber_port_tfm_initialization_state = fiber_portTFM_INITIALIZING;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(fiber_port_tfm_initialization_state ==
			fiber_portTFM_INITIALIZING, 'Q');

	const uint32_t result = tfm_ns_interface_init();
	fiber_port_tfm_validate_cpu_state(&cpu_state);
	if (result != FIBER_PORT_TFM_SUCCESS) {
		fiber_port_tfm_initialization_state = fiber_portTFM_FAILED;
		fiber_portDATA_SYNC_BARRIER();
		fiber_portINST_SYNC_BARRIER();
		fiber_portCOMPILER_BARRIER();
		return FIBER_PORT_TFM_ERROR;
	}

	fiber_port_tfm_initialization_state = fiber_portTFM_READY;
	fiber_portDATA_SYNC_BARRIER();
	fiber_portINST_SYNC_BARRIER();
	fiber_portCOMPILER_BARRIER();
	FIBER_REQUIRE(fiber_port_tfm_initialization_state ==
			fiber_portTFM_READY, 'Q');
	return FIBER_PORT_TFM_SUCCESS;
}

FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
void fiber_port_tfm_require_initialized(void)
{
	FIBER_REQUIRE(fiber_port_tfm_initialize() ==
			FIBER_PORT_TFM_SUCCESS, 'Q');
}
