/*
 * ARM_CM0_MPU exact linker contract.
 *
 * Include this after the application linker script has placed the selected
 * input sections and defined all ten boundary symbols. It intentionally does
 * not choose STM32 memory addresses: the board linker script owns that policy.
 */

ASSERT(DEFINED(__fiber_mpu_unprivileged_code_start__),
	"[fiber]: ARM_CM0_MPU missing unprivileged-code start")
ASSERT(DEFINED(__fiber_mpu_unprivileged_code_end__),
	"[fiber]: ARM_CM0_MPU missing unprivileged-code end")
ASSERT(DEFINED(__fiber_mpu_privileged_code_start__),
	"[fiber]: ARM_CM0_MPU missing privileged-code start")
ASSERT(DEFINED(__fiber_mpu_privileged_code_end__),
	"[fiber]: ARM_CM0_MPU missing privileged-code end")
ASSERT(DEFINED(__fiber_mpu_privileged_data_start__),
	"[fiber]: ARM_CM0_MPU missing privileged-data start")
ASSERT(DEFINED(__fiber_mpu_privileged_data_end__),
	"[fiber]: ARM_CM0_MPU missing privileged-data end")
ASSERT(DEFINED(__fiber_mpu_current_context_slot_start__),
	"[fiber]: ARM_CM0_MPU missing current-slot start")
ASSERT(DEFINED(__fiber_mpu_current_context_slot_end__),
	"[fiber]: ARM_CM0_MPU missing current-slot end")
ASSERT(DEFINED(__fiber_mpu_unprivileged_ram_start__),
	"[fiber]: ARM_CM0_MPU missing unprivileged-RAM start")
ASSERT(DEFINED(__fiber_mpu_unprivileged_ram_end__),
	"[fiber]: ARM_CM0_MPU missing unprivileged-RAM end")

ASSERT((__fiber_mpu_current_context_slot_end__ -
	__fiber_mpu_current_context_slot_start__) == 0x100,
	"[fiber]: ARM_CM0_MPU current-slot aperture must be exactly 256 bytes")
ASSERT((__fiber_mpu_current_context_slot_start__ & 0xFF) == 0,
	"[fiber]: ARM_CM0_MPU current-slot aperture must be 256-byte aligned")
ASSERT(ADDR(.fiber_current_context_slot) ==
	__fiber_mpu_current_context_slot_start__,
	"[fiber]: ARM_CM0_MPU current-slot output section must begin at its aperture")
ASSERT(SIZEOF(.fiber_current_context_slot) == 0x100,
	"[fiber]: ARM_CM0_MPU current-slot output section must be exactly 256 bytes")

ASSERT((__fiber_mpu_unprivileged_code_end__ >
	__fiber_mpu_unprivileged_code_start__) &&
	((__fiber_mpu_unprivileged_code_end__ -
	__fiber_mpu_unprivileged_code_start__) >= 0x100) &&
	(((__fiber_mpu_unprivileged_code_end__ -
	__fiber_mpu_unprivileged_code_start__) &
	((__fiber_mpu_unprivileged_code_end__ -
	__fiber_mpu_unprivileged_code_start__) - 1)) == 0) &&
	((__fiber_mpu_unprivileged_code_start__ &
	((__fiber_mpu_unprivileged_code_end__ -
	__fiber_mpu_unprivileged_code_start__) - 1)) == 0),
	"[fiber]: ARM_CM0_MPU unprivileged code must be an exact MPU region")
ASSERT((__fiber_mpu_privileged_code_end__ >
	__fiber_mpu_privileged_code_start__) &&
	((__fiber_mpu_privileged_code_end__ -
	__fiber_mpu_privileged_code_start__) >= 0x100) &&
	(((__fiber_mpu_privileged_code_end__ -
	__fiber_mpu_privileged_code_start__) &
	((__fiber_mpu_privileged_code_end__ -
	__fiber_mpu_privileged_code_start__) - 1)) == 0) &&
	((__fiber_mpu_privileged_code_start__ &
	((__fiber_mpu_privileged_code_end__ -
	__fiber_mpu_privileged_code_start__) - 1)) == 0),
	"[fiber]: ARM_CM0_MPU privileged code must be an exact MPU region")
ASSERT((__fiber_mpu_privileged_data_end__ >
	__fiber_mpu_privileged_data_start__) &&
	((__fiber_mpu_privileged_data_end__ -
	__fiber_mpu_privileged_data_start__) >= 0x100) &&
	(((__fiber_mpu_privileged_data_end__ -
	__fiber_mpu_privileged_data_start__) &
	((__fiber_mpu_privileged_data_end__ -
	__fiber_mpu_privileged_data_start__) - 1)) == 0) &&
	((__fiber_mpu_privileged_data_start__ &
	((__fiber_mpu_privileged_data_end__ -
	__fiber_mpu_privileged_data_start__) - 1)) == 0),
	"[fiber]: ARM_CM0_MPU privileged data must be an exact MPU region")

ASSERT((__fiber_mpu_unprivileged_ram_end__ >
	__fiber_mpu_unprivileged_ram_start__) &&
	((__fiber_mpu_unprivileged_ram_start__ & 0xFF) == 0) &&
	((__fiber_mpu_unprivileged_ram_end__ & 0xFF) == 0),
	"[fiber]: ARM_CM0_MPU unprivileged RAM must be non-empty and 256-byte aligned")

ASSERT((__fiber_mpu_privileged_data_end__ <=
	__fiber_mpu_current_context_slot_start__) ||
	(__fiber_mpu_current_context_slot_end__ <=
	__fiber_mpu_privileged_data_start__),
	"[fiber]: ARM_CM0_MPU privileged data overlaps current-slot aperture")
ASSERT((__fiber_mpu_privileged_data_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_privileged_data_start__),
	"[fiber]: ARM_CM0_MPU privileged data overlaps unprivileged RAM")
ASSERT((__fiber_mpu_current_context_slot_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_current_context_slot_start__),
	"[fiber]: ARM_CM0_MPU current-slot aperture overlaps unprivileged RAM")
ASSERT((__fiber_mpu_current_context_slot_end__ <=
	__fiber_mpu_unprivileged_code_start__) ||
	(__fiber_mpu_unprivileged_code_end__ <=
	__fiber_mpu_current_context_slot_start__),
	"[fiber]: ARM_CM0_MPU current-slot aperture overlaps unprivileged code")
ASSERT((__fiber_mpu_current_context_slot_end__ <=
	__fiber_mpu_privileged_code_start__) ||
	(__fiber_mpu_privileged_code_end__ <=
	__fiber_mpu_current_context_slot_start__),
	"[fiber]: ARM_CM0_MPU current-slot aperture overlaps privileged code")
ASSERT((__fiber_mpu_unprivileged_code_end__ <=
	__fiber_mpu_privileged_data_start__) ||
	(__fiber_mpu_privileged_data_end__ <=
	__fiber_mpu_unprivileged_code_start__),
	"[fiber]: ARM_CM0_MPU unprivileged code overlaps privileged data")
ASSERT((__fiber_mpu_privileged_code_end__ <=
	__fiber_mpu_privileged_data_start__) ||
	(__fiber_mpu_privileged_data_end__ <=
	__fiber_mpu_privileged_code_start__),
	"[fiber]: ARM_CM0_MPU privileged code overlaps privileged data")
ASSERT((__fiber_mpu_unprivileged_code_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_unprivileged_code_start__),
	"[fiber]: ARM_CM0_MPU unprivileged code overlaps unprivileged RAM")
ASSERT((__fiber_mpu_privileged_code_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_privileged_code_start__),
	"[fiber]: ARM_CM0_MPU privileged code overlaps unprivileged RAM")

ASSERT(((__fiber_mpu_unprivileged_code_end__ <=
	__fiber_mpu_privileged_code_start__) ||
	(__fiber_mpu_privileged_code_end__ <=
	__fiber_mpu_unprivileged_code_start__) ||
	((__fiber_mpu_privileged_code_start__ >=
	__fiber_mpu_unprivileged_code_start__) &&
	(__fiber_mpu_privileged_code_end__ <=
	__fiber_mpu_unprivileged_code_end__))),
	"[fiber]: ARM_CM0_MPU privileged code may only be disjoint or nested in unprivileged code")
