/*
 * fiber_portmacro.h
 *
 * ARM_CM0_MPU dictionary through implementation slice 5. This exact Cortex-M0+
 * MPU profile freezes its protected layout/traits, linker-isolation contract,
 * construction/global-image contract, first-start SVC/MPU activation, and
 * protected Thumb-1 PendSV switching. It deliberately provides no selector
 * route, public forward runtime ABI, or public MPU extension ABI.
 */

#ifndef FIBER_PORT_ARM_CM0_MPU_FIBER_PORTMACRO_H_
#define FIBER_PORT_ARM_CM0_MPU_FIBER_PORTMACRO_H_

#include <stddef.h>
#include <stdint.h>

#ifdef FIBER_PORT_NAME
# error "[fiber]: ARM_CM0_MPU port name must not be predefined"
#endif
#define FIBER_PORT_NAME "ARM_CM0_MPU"

#include "../fiber_port_select.h"
#include "../fiber_settings.h"
#include "../fiber_compiler.h"
#include "fiber_port_types.h"

#ifndef fiber_portFORCE_INLINE
# if defined(__GNUC__) || defined(__clang__)
#  define fiber_portFORCE_INLINE static inline __attribute__((always_inline))
# else
#  define fiber_portFORCE_INLINE static inline
# endif
#endif

#ifndef fiber_portASM
# define fiber_portASM __asm
#endif

#if !FIBER_PORT_BUILD_SELECTED
# error "[fiber]: ARM_CM0_MPU is build-selected only"
#endif

#if !FIBER_PORT_ARMV6M
# error "[fiber]: ARM_CM0_MPU requires the ARMv6-M architecture result"
#endif

#if !defined(__ARM_ARCH_6M__)
# error "[fiber]: ARM_CM0_MPU requires an ARMv6-M compiler target"
#endif

#if !defined(__CORTEX_M) || (__CORTEX_M != 0)
# error "[fiber]: ARM_CM0_MPU manifest requires CMSIS __CORTEX_M == 0"
#endif

#if !defined(__MPU_PRESENT) || (__MPU_PRESENT != 1)
# error "[fiber]: ARM_CM0_MPU manifest requires __MPU_PRESENT == 1"
#endif

#if !defined(__VTOR_PRESENT) || \
		((__VTOR_PRESENT != 0) && (__VTOR_PRESENT != 1))
# error "[fiber]: ARM_CM0_MPU requires CMSIS __VTOR_PRESENT == 0 or 1"
#endif

#if !defined(__FPU_PRESENT) || (__FPU_PRESENT != 0)
# error "[fiber]: ARM_CM0_MPU manifest requires __FPU_PRESENT == 0"
#endif

#if !defined(__FPU_USED) || (__FPU_USED != 0)
# error "[fiber]: ARM_CM0_MPU requires __FPU_USED == 0"
#endif

#if !defined(__NVIC_PRIO_BITS) || (__NVIC_PRIO_BITS < 1) || \
		(__NVIC_PRIO_BITS > 8)
# error "[fiber]: ARM_CM0_MPU requires 1..8 implemented NVIC priority bits"
#endif

/* This is a staged compile-proof fact, not an application setting. */
#ifdef FIBER_PORT_RUNTIME_SELECTABLE
# error "[fiber]: ARM_CM0_MPU runtime-selectable state must not be predefined"
#endif
#define FIBER_PORT_RUNTIME_SELECTABLE 0

/* Exact ARMv6-M MPU profile facts. */
#define fiber_portSTACK_GROWTH (-1)
#define fiber_portBYTE_ALIGNMENT 8u
#define fiber_portINITIAL_XPSR 0x01000000u
#define fiber_portSTART_ADDRESS_MASK 0xFFFFFFFEu
#define fiber_portINITIAL_EXC_RETURN 0xFFFFFFFDu
#define fiber_portINITIAL_CONTROL_PRIVILEGED 0x00000002u
#define fiber_portINITIAL_CONTROL_UNPRIVILEGED 0x00000003u

/*
 * Port-owned SVC namespace. The values are part of the protected execution
 * ABI, therefore application code cannot override them. The protected runtime
 * owns start, yield, and task-return as one closed service family.
 */
#ifdef FIBER_SVC_START_NUMBER
# error "[fiber]: ARM_CM0_MPU owns its complete SVC namespace"
#endif
#define FIBER_SVC_START_NUMBER 70
#define fiber_portSVC_START FIBER_SVC_START_NUMBER
#define fiber_portSVC_YIELD 71
#define fiber_portSVC_RETURN 72

/* ARMv6-M system-control and MPU register dictionary. These raw definitions
 * keep the selected port independent from a particular CMSIS device header. */
#define fiber_portNVIC_INT_CTRL_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED04u))
#define fiber_portNVIC_PENDSVSET_BIT (1u << 28u)
#define fiber_portNVIC_PENDSVCLR_BIT (1u << 27u)
#define fiber_portNVIC_SHPR2_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED1Cu))
#define fiber_portNVIC_SHPR3_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED20u))
#define fiber_portSCB_VTOR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED08u))
#define fiber_portMPU_TYPE_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED90u))
#define fiber_portMPU_CTRL_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED94u))
#define fiber_portMPU_RNR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED98u))
#define fiber_portMPU_RBAR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000ED9Cu))
#define fiber_portMPU_RASR_REG \
	(*((volatile uint32_t *)(uintptr_t)0xE000EDA0u))

#define fiber_portNVIC_SVC_PRIORITY_SHIFT 24u
#define fiber_portNVIC_PENDSV_PRIORITY_SHIFT 16u
#define fiber_portNVIC_PRIORITY_BYTE_MASK 0xFFu
#define fiber_portVECTOR_INDEX_SVC 11u
#define fiber_portVECTOR_INDEX_PENDSV 14u
#define fiber_portVECTOR_ALIGNMENT 128u
#define fiber_portEXC_RETURN_THREAD_MSP 0xFFFFFFF9u
#define fiber_portXPSR_IPSR_MASK 0x000001FFu
#define fiber_portXPSR_STACK_ALIGN_BIT (1u << 9u)
#define fiber_portXPSR_THUMB_BIT (1u << 24u)

/*
 * The reference reserves region four for broad peripheral access. Fiber uses
 * that slot as one exact ARMv6-M minimum-region unprivileged-read-only
 * current-context aperture, so three configurable regions plus the stack
 * remain in each context image.
 */
#define fiber_portMPU_TOTAL_REGIONS 8u
#define fiber_portMPU_FIRST_CONFIGURABLE_REGION 0u
#define fiber_portMPU_LAST_CONFIGURABLE_REGION 2u
#define fiber_portMPU_CONFIGURABLE_REGION_COUNT 3u
#define fiber_portMPU_STACK_REGION 3u
#define fiber_portMPU_CONTEXT_REGION_COUNT 4u
#define fiber_portMPU_CURRENT_CONTEXT_REGION 4u
#define fiber_portMPU_UNPRIVILEGED_CODE_REGION 5u
#define fiber_portMPU_PRIVILEGED_CODE_REGION 6u
#define fiber_portMPU_PRIVILEGED_DATA_REGION 7u
#define fiber_portMPU_GLOBAL_REGION_COUNT 4u

/* Pinned FreeRTOS ARM_CM0 MPU register encodings. */
#define fiber_portMPU_EXPECTED_TYPE (8u << 8u)
#define fiber_portMPU_CTRL_ENABLE 0x00000001u
#define fiber_portMPU_CTRL_PRIVDEFENA 0x00000004u
#define fiber_portMPU_CTRL_REQUIRED \
	(fiber_portMPU_CTRL_ENABLE | fiber_portMPU_CTRL_PRIVDEFENA)
#define fiber_portMPU_RASR_AP_MASK (0x07u << 24u)
#define fiber_portMPU_RASR_S_C_B_MASK 0x07u
#define fiber_portMPU_RASR_S_C_B_LOCATION 16u
#define fiber_portMPU_RASR_MEMORY_MASK \
	(fiber_portMPU_RASR_S_C_B_MASK << fiber_portMPU_RASR_S_C_B_LOCATION)
#define fiber_portMPU_RASR_SIZE_MASK (0x1Fu << 1u)
#define fiber_portMPU_RASR_REGION_ENABLE 0x00000001u
#define fiber_portMPU_RBAR_ADDRESS_MASK 0xFFFFFF00u
#define fiber_portMPU_RBAR_REGION_VALID 0x00000010u
#define fiber_portMPU_RBAR_REGION_NUMBER_MASK 0x0000000Fu
#define fiber_portMPU_MIN_REGION_SIZE 256u
#define fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES \
	fiber_portMPU_MIN_REGION_SIZE
/* A 4GB MPU region has no representable exclusive end in a 32-bit range API.
 * The exact encoder therefore fails closed above 2GB instead of
 * rounding an arbitrary range up to 4GB. */
#define fiber_portMPU_MAX_EXACT_REGION_SIZE UINT32_C(0x80000000)

#define fiber_portMPU_REGION_SIZE_256B (0x07u << 1u)
#define fiber_portMPU_REGION_SIZE_512B (0x08u << 1u)
#define fiber_portMPU_REGION_SIZE_1KB (0x09u << 1u)
#define fiber_portMPU_REGION_SIZE_2KB (0x0Au << 1u)
#define fiber_portMPU_REGION_SIZE_4KB (0x0Bu << 1u)
#define fiber_portMPU_REGION_SIZE_8KB (0x0Cu << 1u)
#define fiber_portMPU_REGION_SIZE_16KB (0x0Du << 1u)
#define fiber_portMPU_REGION_SIZE_32KB (0x0Eu << 1u)
#define fiber_portMPU_REGION_SIZE_64KB (0x0Fu << 1u)
#define fiber_portMPU_REGION_SIZE_128KB (0x10u << 1u)
#define fiber_portMPU_REGION_SIZE_256KB (0x11u << 1u)
#define fiber_portMPU_REGION_SIZE_512KB (0x12u << 1u)
#define fiber_portMPU_REGION_SIZE_1MB (0x13u << 1u)
#define fiber_portMPU_REGION_SIZE_2MB (0x14u << 1u)
#define fiber_portMPU_REGION_SIZE_4MB (0x15u << 1u)
#define fiber_portMPU_REGION_SIZE_8MB (0x16u << 1u)
#define fiber_portMPU_REGION_SIZE_16MB (0x17u << 1u)
#define fiber_portMPU_REGION_SIZE_32MB (0x18u << 1u)
#define fiber_portMPU_REGION_SIZE_64MB (0x19u << 1u)
#define fiber_portMPU_REGION_SIZE_128MB (0x1Au << 1u)
#define fiber_portMPU_REGION_SIZE_256MB (0x1Bu << 1u)
#define fiber_portMPU_REGION_SIZE_512MB (0x1Cu << 1u)
#define fiber_portMPU_REGION_SIZE_1GB (0x1Du << 1u)
#define fiber_portMPU_REGION_SIZE_2GB (0x1Eu << 1u)
#define fiber_portMPU_REGION_SIZE_4GB (0x1Fu << 1u)

#define fiber_portMPU_REGION_STRONGLY_ORDERED_SHAREABLE (0x00u << 16u)
#define fiber_portMPU_REGION_DEVICE_SHAREABLE (0x01u << 16u)
#define fiber_portMPU_REGION_NORMAL_OIWTNOWA_NONSHARED (0x02u << 16u)
#define fiber_portMPU_REGION_NORMAL_OIWTNOWA_SHARED (0x06u << 16u)
#define fiber_portMPU_REGION_NORMAL_OIWBNOWA_NONSHARED (0x03u << 16u)
#define fiber_portMPU_REGION_NORMAL_OIWBNOWA_SHARED (0x07u << 16u)

#define fiber_portMPU_REGION_PRIV_NA_UNPRIV_NA (0x00u << 24u)
#define fiber_portMPU_REGION_PRIV_RW_UNPRIV_NA (0x01u << 24u)
#define fiber_portMPU_REGION_PRIV_RW_UNPRIV_RO (0x02u << 24u)
#define fiber_portMPU_REGION_PRIV_RW_UNPRIV_RW (0x03u << 24u)
#define fiber_portMPU_REGION_PRIV_RO_UNPRIV_NA (0x05u << 24u)
#define fiber_portMPU_REGION_PRIV_RO_UNPRIV_RO (0x06u << 24u)
#define fiber_portMPU_REGION_EXECUTE_NEVER (0x01u << 28u)

/* FreeRTOS defaults configS_C_B_SRAM to S=1, C=1, B=1. The initial Fiber
 * stack image pins that same normal/cacheable/bufferable policy. */
#define fiber_portMPU_DEFAULT_SRAM_MEMORY \
	fiber_portMPU_REGION_NORMAL_OIWBNOWA_SHARED
#define fiber_portMPU_DEFAULT_FLASH_MEMORY \
	fiber_portMPU_REGION_NORMAL_OIWBNOWA_SHARED
#define fiber_portMPU_DEFAULT_STACK_ATTRIBUTES \
	(fiber_portMPU_REGION_PRIV_RW_UNPRIV_RW | \
	 fiber_portMPU_DEFAULT_SRAM_MEMORY | \
	 fiber_portMPU_REGION_EXECUTE_NEVER)

/* Exact linker sections consumed by the ARM_CM0_MPU integration contract. */
#define fiber_portPRIVILEGED_FUNCTION \
	__attribute__((section(".fiber_port_privileged_functions")))
#define fiber_portUNPRIVILEGED_FUNCTION \
	__attribute__((section(".fiber_port_unprivileged_functions")))
#define fiber_portPRIVILEGED_DATA \
	__attribute__((section(".fiber_port_privileged_data")))

#define fiber_portPROTECTED_CONTEXT_WORDS 20u
#define fiber_portPROTECTED_RESTORE_WORDS 19u
#define fiber_portSTACK_FRAME_HAS_PADDING_FLAG (1u << 0u)
#define fiber_portTASK_IS_PRIVILEGED_FLAG (1u << 1u)
#define fiber_portSTACK_CANARY_VALUE UINT32_C(0xDEADBEEF)

#define FIBER_PORT_HAS_BASEPRI 0
#define FIBER_PORT_HAS_FAULTMASK 0
#if __VTOR_PRESENT == 1
# define FIBER_PORT_HAS_VTOR 1
#else
# define FIBER_PORT_HAS_VTOR 0
#endif
#define FIBER_PORT_HAS_PSPLIM 0
#define FIBER_PORT_HAS_FPU 0
#define FIBER_PORT_HAS_EXTENDED_FP_CONTEXT 0
#define FIBER_PORT_STACK_ALIGNMENT fiber_portBYTE_ALIGNMENT
#define FIBER_PORT_BOOT_CLEARS_FPCA 0
#define FIBER_PORT_HAS_MVE 0
#define FIBER_PORT_HAS_PAC 0
#define FIBER_PORT_HAS_BTI 0
#define FIBER_PORT_USES_PSPLIM_REGISTER 0
#define FIBER_PORT_INITIAL_EXC_RETURN fiber_portINITIAL_EXC_RETURN
#define FIBER_PORT_SCHEDULER_MASK_KIND FIBER_PORT_MASK_PRIMASK
#define FIBER_PORT_SUPPORTS_M7_R0P1_ERRATA_WORKAROUND 0
#define FIBER_PORT_ENABLE_M7_R0P1_ERRATA_WORKAROUND 0
#if FIBER_PORT_IS_V8M
# error "[fiber]: ARM_CM0_MPU cannot use an ARMv8-M profile"
#endif
#define FIBER_PORT_HAS_SECURITY_EXT 0
#define FIBER_PORT_RUNS_NONSECURE 0
#define FIBER_PORT_TARGETS_NS_BANK 0
#define FIBER_PORT_HAS_CONTROL_SLOT 1
#define FIBER_PORT_HAS_PSPLIM_SLOT 0
#define FIBER_PORT_HAS_SECURE_CONTEXT_SLOT 0
#define FIBER_PORT_HAS_PAC_KEY_SLOT 0

#ifndef FIBER_SCHEDULER_BASEPRI
# define FIBER_SCHEDULER_BASEPRI 0u
#endif
#if FIBER_SCHEDULER_BASEPRI != 0u
# error "[fiber]: ARM_CM0_MPU has no BASEPRI; FIBER_SCHEDULER_BASEPRI must be zero"
#endif
#ifdef FIBER_PORT_SCHEDULER_BASEPRI
# if FIBER_PORT_SCHEDULER_BASEPRI != 0u
#  error "[fiber]: ARM_CM0_MPU has no port BASEPRI threshold"
# endif
#endif

/* Exact selected layout identity. The port ID encodes \"CM0M\". */
#define FIBER_PORT_CONTEXT_ABI_PORT_ID 0x434D304Du
#define FIBER_PORT_CONTEXT_ABI_LAYOUT_VERSION 0x00010001u
#define FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT 0x00000004u
#define FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE 0x00000400u
#define FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME 0x00000800u
#define FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED 0x00001000u
#define FIBER_PORT_CONTEXT_ABI_FEATURE_MASK \
	(FIBER_PORT_CONTEXT_FEATURE_CONTROL_SLOT | \
	 FIBER_PORT_CONTEXT_FEATURE_MPU_IMAGE | \
	 FIBER_PORT_CONTEXT_FEATURE_PROTECTED_HW_FRAME | \
	 FIBER_PORT_CONTEXT_FEATURE_UNPRIVILEGED)

/*
 * Generic traits describe the complete logical restore transfer, excluding
 * cursor_limit. That image is privileged storage, not a software frame on the
 * unprivileged stack. The generic fiber_port_geometry.h model is therefore not
 * applicable to this profile; slices 2-5 use the explicit physical-PSP geometry
 * below for raw-stack admission.
 */
#define FIBER_PORT_EXC_BASE_BYTES (8u * 4u)
#define FIBER_PORT_EXC_FP_EXT_BYTES 0u
#define FIBER_PORT_EXC_PER_LEVEL_BYTES FIBER_PORT_EXC_BASE_BYTES
#define FIBER_PORT_SOFTWARE_FRAME_WORDS fiber_portPROTECTED_RESTORE_WORDS
#define FIBER_PORT_SOFTWARE_FRAME_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_WORDS * 4u)
#define FIBER_PORT_EXC_RETURN_WORD_INDEX 18u
#define FIBER_PORT_HIGH_FP_SOFTWARE_BYTES 0u
#define FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES 4u
#define FIBER_PORT_INITIAL_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_BASE_BYTES)
#define FIBER_PORT_MAX_SAVED_CONTEXT_BYTES \
	(FIBER_PORT_SOFTWARE_FRAME_BYTES + FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_SAVED_SP_MOD8 0u

/* Physical user-PSP geometry. PendSV copies the basic frame to and from
 * privileged storage, so this must not include the protected 19-word image. */
#define FIBER_PORT_CM0_MPU_PSP_INITIAL_FRAME_BYTES \
	FIBER_PORT_EXC_BASE_BYTES
#define FIBER_PORT_CM0_MPU_PSP_MAX_FRAME_BYTES \
	(FIBER_PORT_EXC_PER_LEVEL_BYTES + \
	 FIBER_PORT_EXCEPTION_ALIGNMENT_PAD_BYTES)
#define FIBER_PORT_CM0_MPU_STACK_REQUIRED_BYTES \
	((FIBER_PORT_CM0_MPU_PSP_MAX_FRAME_BYTES + \
	  FIBER_PORT_STACK_ALIGNMENT - 1u) & \
	 ~((uint32_t)FIBER_PORT_STACK_ALIGNMENT - 1u))

/* Frozen 32-bit GCC layout consumed by the later Thumb-1 assembly port. */
#define FIBER_PORT_CM0_MPU_REGION_RBAR_OFFSET 0u
#define FIBER_PORT_CM0_MPU_REGION_RASR_OFFSET 4u
#define FIBER_PORT_CM0_MPU_REGION_SIZE 8u

#define FIBER_PORT_CM0_MPU_PROTECTED_R4_OFFSET 0u
#define FIBER_PORT_CM0_MPU_PROTECTED_R5_OFFSET 4u
#define FIBER_PORT_CM0_MPU_PROTECTED_R6_OFFSET 8u
#define FIBER_PORT_CM0_MPU_PROTECTED_R7_OFFSET 12u
#define FIBER_PORT_CM0_MPU_PROTECTED_R8_OFFSET 16u
#define FIBER_PORT_CM0_MPU_PROTECTED_R9_OFFSET 20u
#define FIBER_PORT_CM0_MPU_PROTECTED_R10_OFFSET 24u
#define FIBER_PORT_CM0_MPU_PROTECTED_R11_OFFSET 28u
#define FIBER_PORT_CM0_MPU_PROTECTED_R0_OFFSET 32u
#define FIBER_PORT_CM0_MPU_PROTECTED_R1_OFFSET 36u
#define FIBER_PORT_CM0_MPU_PROTECTED_R2_OFFSET 40u
#define FIBER_PORT_CM0_MPU_PROTECTED_R3_OFFSET 44u
#define FIBER_PORT_CM0_MPU_PROTECTED_R12_OFFSET 48u
#define FIBER_PORT_CM0_MPU_PROTECTED_LR_OFFSET 52u
#define FIBER_PORT_CM0_MPU_PROTECTED_PC_OFFSET 56u
#define FIBER_PORT_CM0_MPU_PROTECTED_XPSR_OFFSET 60u
#define FIBER_PORT_CM0_MPU_PROTECTED_PSP_OFFSET 64u
#define FIBER_PORT_CM0_MPU_PROTECTED_CONTROL_OFFSET 68u
#define FIBER_PORT_CM0_MPU_PROTECTED_EXC_RETURN_OFFSET 72u
#define FIBER_PORT_CM0_MPU_PROTECTED_CURSOR_LIMIT_OFFSET 76u
#define FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_SIZE 80u

#define FIBER_PORT_CM0_MPU_CURSOR_OFFSET 0u
#define FIBER_PORT_CM0_MPU_REGIONS_OFFSET 4u
#define FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_OFFSET 36u
#define FIBER_PORT_CM0_MPU_RUNTIME_FLAGS_OFFSET 116u
#define FIBER_PORT_CM0_MPU_BOOT_OFFSET 120u
#define FIBER_PORT_CM0_MPU_CONTEXT_SIZE 208u
#define FIBER_PORT_CM0_MPU_CONTEXT_ALIGNMENT 8u

#define FIBER_PORT_CM0_MPU_BOOT_BEGIN_OFFSET 0u
#define FIBER_PORT_CM0_MPU_BOOT_END_OFFSET 4u
#define FIBER_PORT_CM0_MPU_BOOT_STACK_BASE_OFFSET 8u
#define FIBER_PORT_CM0_MPU_BOOT_STACK_TOP_OFFSET 12u
#define FIBER_PORT_CM0_MPU_BOOT_AVAIL_OFFSET 16u
#define FIBER_PORT_CM0_MPU_BOOT_ENTRY_OFFSET 20u
#define FIBER_PORT_CM0_MPU_BOOT_ARG_OFFSET 24u
#define FIBER_PORT_CM0_MPU_BOOT_PORT_ID_OFFSET 28u
#define FIBER_PORT_CM0_MPU_BOOT_LAYOUT_VERSION_OFFSET 32u
#define FIBER_PORT_CM0_MPU_BOOT_CONTEXT_SIZE_OFFSET 36u
#define FIBER_PORT_CM0_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET 40u
#define FIBER_PORT_CM0_MPU_BOOT_FEATURE_MASK_OFFSET 44u
#define FIBER_PORT_CM0_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET 48u
#define FIBER_PORT_CM0_MPU_BOOT_INITIAL_CONTROL_OFFSET 52u
#define FIBER_PORT_CM0_MPU_BOOT_TOTAL_REGIONS_OFFSET 56u
#define FIBER_PORT_CM0_MPU_BOOT_CONTEXT_REGIONS_OFFSET 60u
#define FIBER_PORT_CM0_MPU_BOOT_PROTECTED_WORDS_OFFSET 64u
#define FIBER_PORT_CM0_MPU_BOOT_MAGIC_OFFSET 68u
#define FIBER_PORT_CM0_MPU_BOOT_VERSION_OFFSET 72u
#define FIBER_PORT_CM0_MPU_BOOT_SEALED_OFFSET 74u
#define FIBER_PORT_CM0_MPU_BOOT_GUARD_LO_OFFSET 76u
#define FIBER_PORT_CM0_MPU_BOOT_GUARD_HI_OFFSET 80u
#define FIBER_PORT_CM0_MPU_BOOT_HASH_OFFSET 84u
#define FIBER_PORT_CM0_MPU_BOOT_SIZE 88u

/* Preserve an optional platform/static-base register in the synthetic first
 * context. This is the same Fiber ABI precaution used by the privileged
 * ARM_CM0 port; FreeRTOS uses diagnostic seed values instead. */
fiber_portFORCE_INLINE uint32_t fiber_port_read_r9(void)
{
	uint32_t value;
	fiber_portASM volatile("mov %0, r9" : "=r"(value));
	return value;
}

/* VTOR is optional on ARMv6-M. A no-VTOR profile is required to use the
 * architected/remapped vector base at address zero; its board policy is later
 * checked by the selected-port integration proof. */
fiber_portFORCE_INLINE uintptr_t fiber_port_vectors_base_addr(void)
{
#if FIBER_PORT_HAS_VTOR
	return (uintptr_t)fiber_portSCB_VTOR_REG &
		~((uintptr_t)fiber_portVECTOR_ALIGNMENT - 1u);
#else
	return 0u;
#endif
}

fiber_portFORCE_INLINE const uint32_t *fiber_port_vectors_base_ptr(void)
{
	return (const uint32_t *)fiber_port_vectors_base_addr();
}

/* On an ARMv6-M implementation without VTOR, address zero is the active
 * architecture/remapped vector base, not a C null object. Keep that fact out
 * of GCC's null-array analysis while retaining a volatile hardware read. */
fiber_portFORCE_INLINE uint32_t fiber_port_read_vector_slot(uint32_t index)
{
	uintptr_t base = fiber_port_vectors_base_addr();
#if !FIBER_PORT_HAS_VTOR
	fiber_portASM volatile("" : "+r"(base) :: "memory");
#endif
	return *(const volatile uint32_t *)(base +
			((uintptr_t)index * sizeof(uint32_t)));
}

FIBER_STATIC_ASSERT(sizeof(void *) == 4u,
		"[fiber]: ARM_CM0_MPU requires 32-bit pointers");
FIBER_STATIC_ASSERT(sizeof(size_t) == 4u,
		"[fiber]: ARM_CM0_MPU requires 32-bit size_t");
FIBER_STATIC_ASSERT(FIBER_PORT_RUNTIME_SELECTABLE == 0,
		"[fiber]: ARM_CM0_MPU must not activate runtime selection before its complete port proof");
FIBER_STATIC_ASSERT(fiber_portSVC_START <= 255u &&
		fiber_portSVC_YIELD <= 255u && fiber_portSVC_RETURN <= 255u,
		"[fiber]: ARM_CM0_MPU SVC services must fit imm8");
FIBER_STATIC_ASSERT(fiber_portSVC_START != fiber_portSVC_YIELD &&
		fiber_portSVC_START != fiber_portSVC_RETURN &&
		fiber_portSVC_YIELD != fiber_portSVC_RETURN,
		"[fiber]: ARM_CM0_MPU SVC services must be distinct");
FIBER_STATIC_ASSERT(fiber_portEXC_RETURN_THREAD_MSP == 0xFFFFFFF9u &&
		fiber_portINITIAL_EXC_RETURN == 0xFFFFFFFDu,
		"[fiber]: ARM_CM0_MPU exception-return encodings changed");
FIBER_STATIC_ASSERT(fiber_portVECTOR_INDEX_SVC == 11u &&
		fiber_portVECTOR_INDEX_PENDSV == 14u &&
		fiber_portVECTOR_ALIGNMENT == 128u,
		"[fiber]: ARM_CM0_MPU exception-vector facts changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_PORT_ID != 0x434D3030u,
		"[fiber]: ARM_CM0_MPU must not reuse privileged ARM_CM0 identity");
FIBER_STATIC_ASSERT(FIBER_PORT_CONTEXT_ABI_FEATURE_MASK == 0x00001C04u,
		"[fiber]: ARM_CM0_MPU feature identity changed");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_BASEPRI == 0 &&
		FIBER_PORT_HAS_FAULTMASK == 0,
		"[fiber]: ARM_CM0_MPU must retain the ARMv6-M mask model");
FIBER_STATIC_ASSERT(FIBER_PORT_SCHEDULER_MASK_KIND == FIBER_PORT_MASK_PRIMASK,
		"[fiber]: ARM_CM0_MPU must use PRIMASK scheduler masking");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_VTOR == __VTOR_PRESENT,
		"[fiber]: ARM_CM0_MPU VTOR trait must follow the selected CMSIS manifest");
FIBER_STATIC_ASSERT(FIBER_PORT_HAS_CONTROL_SLOT == 1,
		"[fiber]: ARM_CM0_MPU must preserve CONTROL per context");
FIBER_STATIC_ASSERT(fiber_portMPU_EXPECTED_TYPE == 0x00000800u,
		"[fiber]: ARM_CM0_MPU requires eight unified MPU regions");
FIBER_STATIC_ASSERT(fiber_portMPU_CTRL_REQUIRED == 0x00000005u,
		"[fiber]: ARM_CM0_MPU MPU control policy changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CONFIGURABLE_REGION_COUNT == 3u &&
		fiber_portMPU_CONTEXT_REGION_COUNT == 4u,
		"[fiber]: ARM_CM0_MPU per-context region geometry changed");
FIBER_STATIC_ASSERT(fiber_portMPU_STACK_REGION == 3u &&
		fiber_portMPU_CURRENT_CONTEXT_REGION == 4u &&
		fiber_portMPU_UNPRIVILEGED_CODE_REGION == 5u &&
		fiber_portMPU_PRIVILEGED_CODE_REGION == 6u &&
		fiber_portMPU_PRIVILEGED_DATA_REGION == 7u,
		"[fiber]: ARM_CM0_MPU global region roles changed");
FIBER_STATIC_ASSERT(fiber_portPROTECTED_CONTEXT_WORDS == 20u &&
		fiber_portPROTECTED_RESTORE_WORDS == 19u,
		"[fiber]: ARM_CM0_MPU protected context geometry changed");
FIBER_STATIC_ASSERT(fiber_portSTACK_CANARY_VALUE == UINT32_C(0xDEADBEEF),
		"[fiber]: ARM_CM0_MPU stack canary value changed");
FIBER_STATIC_ASSERT(FIBER_PORT_EXC_RETURN_WORD_INDEX == 18u &&
		FIBER_PORT_INITIAL_CONTEXT_BYTES == 108u &&
		FIBER_PORT_MAX_SAVED_CONTEXT_BYTES == 112u,
		"[fiber]: ARM_CM0_MPU logical restore geometry changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM0_MPU_PSP_INITIAL_FRAME_BYTES == 32u &&
		FIBER_PORT_CM0_MPU_PSP_MAX_FRAME_BYTES == 36u &&
		FIBER_PORT_CM0_MPU_STACK_REQUIRED_BYTES == 40u,
		"[fiber]: ARM_CM0_MPU physical PSP geometry changed");
FIBER_STATIC_ASSERT(fiber_portMPU_MIN_REGION_SIZE == 256u,
		"[fiber]: ARM_CM0_MPU minimum MPU region size changed");
FIBER_STATIC_ASSERT(fiber_portMPU_CURRENT_CONTEXT_APERTURE_BYTES == 256u,
		"[fiber]: ARM_CM0_MPU current-context aperture must be one MPU region");
FIBER_STATIC_ASSERT(fiber_portMPU_MAX_EXACT_REGION_SIZE ==
		UINT32_C(0x80000000),
		"[fiber]: ARM_CM0_MPU exact MPU range limit changed");
FIBER_STATIC_ASSERT(fiber_portMPU_RBAR_ADDRESS_MASK == 0xFFFFFF00u &&
		fiber_portMPU_RBAR_REGION_VALID == 0x10u &&
		fiber_portMPU_RASR_SIZE_MASK == 0x3Eu &&
		fiber_portMPU_RASR_MEMORY_MASK == 0x00070000u,
		"[fiber]: ARM_CM0_MPU register encodings changed");
FIBER_STATIC_ASSERT(fiber_portMPU_REGION_PRIV_RW_UNPRIV_RW == 0x03000000u &&
		fiber_portMPU_REGION_PRIV_RO_UNPRIV_NA == 0x05000000u &&
		fiber_portMPU_REGION_PRIV_RO_UNPRIV_RO == 0x06000000u &&
		fiber_portMPU_REGION_EXECUTE_NEVER == 0x10000000u &&
		fiber_portMPU_DEFAULT_STACK_ATTRIBUTES == 0x13070000u &&
		fiber_portMPU_DEFAULT_FLASH_MEMORY == 0x00070000u,
		"[fiber]: ARM_CM0_MPU permission encodings changed");

FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rbar) ==
		FIBER_PORT_CM0_MPU_REGION_RBAR_OFFSET,
		"[fiber]: ARM_CM0_MPU RBAR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortMpuRegionRegisters, rasr) ==
		FIBER_PORT_CM0_MPU_REGION_RASR_OFFSET,
		"[fiber]: ARM_CM0_MPU RASR offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortMpuRegionRegisters) ==
		FIBER_PORT_CM0_MPU_REGION_SIZE,
		"[fiber]: ARM_CM0_MPU region-pair size changed");

FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r4) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R4_OFFSET,
		"[fiber]: ARM_CM0_MPU r4 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r5) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R5_OFFSET,
		"[fiber]: ARM_CM0_MPU r5 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r6) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R6_OFFSET,
		"[fiber]: ARM_CM0_MPU r6 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r7) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R7_OFFSET,
		"[fiber]: ARM_CM0_MPU r7 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r8) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R8_OFFSET,
		"[fiber]: ARM_CM0_MPU r8 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r9) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R9_OFFSET,
		"[fiber]: ARM_CM0_MPU r9 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r10) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R10_OFFSET,
		"[fiber]: ARM_CM0_MPU r10 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r11) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R11_OFFSET,
		"[fiber]: ARM_CM0_MPU r11 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r0) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R0_OFFSET,
		"[fiber]: ARM_CM0_MPU r0 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r1) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R1_OFFSET,
		"[fiber]: ARM_CM0_MPU r1 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r2) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R2_OFFSET,
		"[fiber]: ARM_CM0_MPU r2 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r3) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R3_OFFSET,
		"[fiber]: ARM_CM0_MPU r3 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, r12) ==
		FIBER_PORT_CM0_MPU_PROTECTED_R12_OFFSET,
		"[fiber]: ARM_CM0_MPU r12 offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, lr) ==
		FIBER_PORT_CM0_MPU_PROTECTED_LR_OFFSET,
		"[fiber]: ARM_CM0_MPU LR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, pc) ==
		FIBER_PORT_CM0_MPU_PROTECTED_PC_OFFSET,
		"[fiber]: ARM_CM0_MPU PC offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, xpsr) ==
		FIBER_PORT_CM0_MPU_PROTECTED_XPSR_OFFSET,
		"[fiber]: ARM_CM0_MPU xPSR offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, psp) ==
		FIBER_PORT_CM0_MPU_PROTECTED_PSP_OFFSET,
		"[fiber]: ARM_CM0_MPU PSP offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, control) ==
		FIBER_PORT_CM0_MPU_PROTECTED_CONTROL_OFFSET,
		"[fiber]: ARM_CM0_MPU CONTROL offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, exc_return) ==
		FIBER_PORT_CM0_MPU_PROTECTED_EXC_RETURN_OFFSET,
		"[fiber]: ARM_CM0_MPU EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortProtectedContext, cursor_limit) ==
		FIBER_PORT_CM0_MPU_PROTECTED_CURSOR_LIMIT_OFFSET,
		"[fiber]: ARM_CM0_MPU cursor-limit offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortProtectedContext) ==
		FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_SIZE,
		"[fiber]: ARM_CM0_MPU protected context size changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM0_MPU_PROTECTED_CURSOR_LIMIT_OFFSET ==
		(FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_SIZE - 4u),
		"[fiber]: ARM_CM0_MPU cursor limit must remain final");

FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, begin) ==
		FIBER_PORT_CM0_MPU_BOOT_BEGIN_OFFSET,
		"[fiber]: ARM_CM0_MPU boot begin offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, end) ==
		FIBER_PORT_CM0_MPU_BOOT_END_OFFSET,
		"[fiber]: ARM_CM0_MPU boot end offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, stack_base) ==
		FIBER_PORT_CM0_MPU_BOOT_STACK_BASE_OFFSET,
		"[fiber]: ARM_CM0_MPU boot stack base offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, stack_top) ==
		FIBER_PORT_CM0_MPU_BOOT_STACK_TOP_OFFSET,
		"[fiber]: ARM_CM0_MPU boot stack top offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, avail) ==
		FIBER_PORT_CM0_MPU_BOOT_AVAIL_OFFSET,
		"[fiber]: ARM_CM0_MPU boot available-size offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, entry) ==
		FIBER_PORT_CM0_MPU_BOOT_ENTRY_OFFSET,
		"[fiber]: ARM_CM0_MPU boot entry offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, arg) ==
		FIBER_PORT_CM0_MPU_BOOT_ARG_OFFSET,
		"[fiber]: ARM_CM0_MPU boot argument offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_port_id) ==
		FIBER_PORT_CM0_MPU_BOOT_PORT_ID_OFFSET,
		"[fiber]: ARM_CM0_MPU boot port ID offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_layout_version) ==
		FIBER_PORT_CM0_MPU_BOOT_LAYOUT_VERSION_OFFSET,
		"[fiber]: ARM_CM0_MPU boot layout offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_context_size) ==
		FIBER_PORT_CM0_MPU_BOOT_CONTEXT_SIZE_OFFSET,
		"[fiber]: ARM_CM0_MPU boot context-size offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_context_alignment) ==
		FIBER_PORT_CM0_MPU_BOOT_CONTEXT_ALIGNMENT_OFFSET,
		"[fiber]: ARM_CM0_MPU boot context-alignment offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_feature_mask) ==
		FIBER_PORT_CM0_MPU_BOOT_FEATURE_MASK_OFFSET,
		"[fiber]: ARM_CM0_MPU boot feature-mask offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_initial_exc_return) ==
		FIBER_PORT_CM0_MPU_BOOT_INITIAL_EXC_RETURN_OFFSET,
		"[fiber]: ARM_CM0_MPU boot EXC_RETURN offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_initial_control) ==
		FIBER_PORT_CM0_MPU_BOOT_INITIAL_CONTROL_OFFSET,
		"[fiber]: ARM_CM0_MPU boot CONTROL offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_mpu_total_regions) ==
		FIBER_PORT_CM0_MPU_BOOT_TOTAL_REGIONS_OFFSET,
		"[fiber]: ARM_CM0_MPU boot total-region offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_mpu_context_regions) ==
		FIBER_PORT_CM0_MPU_BOOT_CONTEXT_REGIONS_OFFSET,
		"[fiber]: ARM_CM0_MPU boot context-region offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, abi_protected_context_words) ==
		FIBER_PORT_CM0_MPU_BOOT_PROTECTED_WORDS_OFFSET,
		"[fiber]: ARM_CM0_MPU boot protected-word offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, magic) ==
		FIBER_PORT_CM0_MPU_BOOT_MAGIC_OFFSET,
		"[fiber]: ARM_CM0_MPU boot magic offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, version) ==
		FIBER_PORT_CM0_MPU_BOOT_VERSION_OFFSET,
		"[fiber]: ARM_CM0_MPU boot version offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, sealed) ==
		FIBER_PORT_CM0_MPU_BOOT_SEALED_OFFSET,
		"[fiber]: ARM_CM0_MPU boot sealed offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, guard_lo) ==
		FIBER_PORT_CM0_MPU_BOOT_GUARD_LO_OFFSET,
		"[fiber]: ARM_CM0_MPU boot guard-low offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, guard_hi) ==
		FIBER_PORT_CM0_MPU_BOOT_GUARD_HI_OFFSET,
		"[fiber]: ARM_CM0_MPU boot guard-high offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberPortBoot, hash) ==
		FIBER_PORT_CM0_MPU_BOOT_HASH_OFFSET,
		"[fiber]: ARM_CM0_MPU boot hash offset changed");
FIBER_STATIC_ASSERT(sizeof(FiberPortBoot) == FIBER_PORT_CM0_MPU_BOOT_SIZE,
		"[fiber]: ARM_CM0_MPU boot record size changed");

FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context_cursor) ==
		FIBER_PORT_CM0_MPU_CURSOR_OFFSET,
		"[fiber]: ARM_CM0_MPU cursor must remain first");
FIBER_STATIC_ASSERT(offsetof(FiberContext, mpu_regions) ==
		FIBER_PORT_CM0_MPU_REGIONS_OFFSET,
		"[fiber]: ARM_CM0_MPU MPU image offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, protected_context) ==
		FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_OFFSET,
		"[fiber]: ARM_CM0_MPU protected context offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, runtime_flags) ==
		FIBER_PORT_CM0_MPU_RUNTIME_FLAGS_OFFSET,
		"[fiber]: ARM_CM0_MPU runtime flags offset changed");
FIBER_STATIC_ASSERT(offsetof(FiberContext, boot) ==
		FIBER_PORT_CM0_MPU_BOOT_OFFSET,
		"[fiber]: ARM_CM0_MPU boot record offset changed");
FIBER_STATIC_ASSERT(FIBER_PORT_CM0_MPU_REGIONS_OFFSET +
		(fiber_portMPU_CONTEXT_REGION_COUNT * FIBER_PORT_CM0_MPU_REGION_SIZE) ==
		FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_OFFSET,
		"[fiber]: ARM_CM0_MPU MPU image must be contiguous with protected context");
FIBER_STATIC_ASSERT(FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_OFFSET +
		FIBER_PORT_CM0_MPU_PROTECTED_CONTEXT_SIZE ==
		FIBER_PORT_CM0_MPU_RUNTIME_FLAGS_OFFSET,
		"[fiber]: ARM_CM0_MPU protected context must precede runtime flags");
FIBER_STATIC_ASSERT(FIBER_PORT_CM0_MPU_RUNTIME_FLAGS_OFFSET + 4u ==
		FIBER_PORT_CM0_MPU_BOOT_OFFSET,
		"[fiber]: ARM_CM0_MPU runtime flags must precede boot metadata");
FIBER_STATIC_ASSERT(sizeof(FiberContext) == FIBER_PORT_CM0_MPU_CONTEXT_SIZE,
		"[fiber]: ARM_CM0_MPU complete context size changed");

#if defined(__cplusplus)
# define fiber_portCM0_MPU_ALIGNOF(_type) alignof(_type)
#else
# define fiber_portCM0_MPU_ALIGNOF(_type) _Alignof(_type)
#endif

FIBER_STATIC_ASSERT(fiber_portCM0_MPU_ALIGNOF(FiberContext) ==
		FIBER_PORT_CM0_MPU_CONTEXT_ALIGNMENT,
		"[fiber]: ARM_CM0_MPU complete context alignment changed");

#include "../fiber_port_traits.h"
#include "../fiber_port_context_cohort.h"

#endif /* FIBER_PORT_ARM_CM0_MPU_FIBER_PORTMACRO_H_ */
