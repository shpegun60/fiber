/* Source-derived host test boundary: no target instruction execution claim. */
#ifndef C5TF_HOST_PORT_H
#define C5TF_HOST_PORT_H
#include <stddef.h>
#include <stdint.h>
#include "fiber_port_types.h"
#include "fiber_api_decl.h"
#include "tfm_v2_boundary.h"
extern uint32_t test_cpu[6];
extern unsigned test_barriers, test_mask_writes;
#define fiber_port_cpu_read_ipsr() (test_cpu[0])
#define fiber_port_cpu_read_primask() (test_cpu[1])
#define fiber_port_basepri_read() (test_cpu[2])
#define fiber_port_cpu_read_faultmask() (test_cpu[3])
#define fiber_port_cpu_read_control() (test_cpu[4])
#define fiber_port_cpu_read_psplim() (test_cpu[5])
#define fiber_portDATA_SYNC_BARRIER() ((void)++test_barriers)
#define fiber_portINST_SYNC_BARRIER() ((void)++test_barriers)
#define fiber_portCOMPILER_BARRIER() __asm__ volatile("" ::: "memory")
#define FIBER_REQUIRE(condition, code) do { if (!(condition)) fiber_panic(code); } while (0)
FIBER_API_NORETURN void fiber_panic(char code);
void fiber_port_runtime_schedule(void);
uint32_t fiber_port_tfm_initialize(void);
void fiber_port_tfm_require_initialized(void);
#endif
