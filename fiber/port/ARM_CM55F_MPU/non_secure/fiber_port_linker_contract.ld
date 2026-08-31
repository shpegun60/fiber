/*
 * ARM_CM55F_MPU/non_secure exact linker contract.
 *
 * Include this fragment after the board linker script has placed selected
 * input sections and defined every boundary below. It intentionally chooses no
 * STM32 addresses. The board linker script owns that hardware policy.
 */

ASSERT(DEFINED(__fiber_mpu_privileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU missing privileged-flash start")
ASSERT(DEFINED(__fiber_mpu_privileged_flash_end__),
	"[fiber]: ARM_CM55F_MPU missing privileged-flash end")
ASSERT(DEFINED(__fiber_mpu_unprivileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU missing unprivileged-flash start")
ASSERT(DEFINED(__fiber_mpu_unprivileged_flash_end__),
	"[fiber]: ARM_CM55F_MPU missing unprivileged-flash end")
ASSERT(DEFINED(__fiber_mpu_unprivileged_syscalls_start__),
	"[fiber]: ARM_CM55F_MPU missing syscall-flash start")
ASSERT(DEFINED(__fiber_mpu_unprivileged_syscalls_end__),
	"[fiber]: ARM_CM55F_MPU missing syscall-flash end")
ASSERT(DEFINED(__fiber_mpu_privileged_sram_start__),
	"[fiber]: ARM_CM55F_MPU missing privileged-SRAM start")
ASSERT(DEFINED(__fiber_mpu_privileged_sram_end__),
	"[fiber]: ARM_CM55F_MPU missing privileged-SRAM end")
ASSERT(DEFINED(__fiber_mpu_current_context_slot_start__),
	"[fiber]: ARM_CM55F_MPU missing current-slot start")
ASSERT(DEFINED(__fiber_mpu_current_context_slot_end__),
	"[fiber]: ARM_CM55F_MPU missing current-slot end")
ASSERT(DEFINED(__fiber_mpu_unprivileged_ram_start__),
	"[fiber]: ARM_CM55F_MPU missing unprivileged-RAM start")
ASSERT(DEFINED(__fiber_mpu_unprivileged_ram_end__),
	"[fiber]: ARM_CM55F_MPU missing unprivileged-RAM end")

ASSERT((__fiber_mpu_privileged_flash_end__ >
	__fiber_mpu_privileged_flash_start__) &&
	((__fiber_mpu_privileged_flash_start__ & 0x1F) == 0) &&
	((__fiber_mpu_privileged_flash_end__ & 0x1F) == 0),
	"[fiber]: ARM_CM55F_MPU privileged flash must be non-empty and 32-byte aligned")
ASSERT((__fiber_mpu_unprivileged_flash_end__ >
	__fiber_mpu_unprivileged_flash_start__) &&
	((__fiber_mpu_unprivileged_flash_start__ & 0x1F) == 0) &&
	((__fiber_mpu_unprivileged_flash_end__ & 0x1F) == 0),
	"[fiber]: ARM_CM55F_MPU unprivileged flash must be non-empty and 32-byte aligned")
ASSERT((__fiber_mpu_unprivileged_syscalls_end__ >
	__fiber_mpu_unprivileged_syscalls_start__) &&
	((__fiber_mpu_unprivileged_syscalls_start__ & 0x1F) == 0) &&
	((__fiber_mpu_unprivileged_syscalls_end__ & 0x1F) == 0),
	"[fiber]: ARM_CM55F_MPU syscall flash must be non-empty and 32-byte aligned")
ASSERT((__fiber_mpu_privileged_sram_end__ >
	__fiber_mpu_privileged_sram_start__) &&
	((__fiber_mpu_privileged_sram_start__ & 0x1F) == 0) &&
	((__fiber_mpu_privileged_sram_end__ & 0x1F) == 0),
	"[fiber]: ARM_CM55F_MPU privileged SRAM must be non-empty and 32-byte aligned")
ASSERT((__fiber_mpu_unprivileged_ram_end__ >
	__fiber_mpu_unprivileged_ram_start__) &&
	((__fiber_mpu_unprivileged_ram_start__ & 0x1F) == 0) &&
	((__fiber_mpu_unprivileged_ram_end__ & 0x1F) == 0),
	"[fiber]: ARM_CM55F_MPU unprivileged RAM must be non-empty and 32-byte aligned")

/* The common current slot is one pointer inside an exact 32-byte MPU aperture.
 * Each active context maps this range through RNR 5 as read-only/XN so an
 * unprivileged fiber can call fiber_current(). The normal privileged-SRAM
 * mapping contains the aperture; the higher-numbered context region overrides
 * it while the MPU is active. The startup BSS path must still zero all 32 bytes. */
ASSERT((__fiber_mpu_current_context_slot_end__ -
	__fiber_mpu_current_context_slot_start__) == 32,
	"[fiber]: ARM_CM55F_MPU current-slot aperture must be exactly 32 bytes")
ASSERT((__fiber_mpu_current_context_slot_start__ & 0x1F) == 0,
	"[fiber]: ARM_CM55F_MPU current-slot aperture must be 32-byte aligned")
ASSERT(ADDR(.fiber_current_context_slot) ==
	__fiber_mpu_current_context_slot_start__,
	"[fiber]: ARM_CM55F_MPU current-slot output section starts incorrectly")
ASSERT(SIZEOF(.fiber_current_context_slot) == 32,
	"[fiber]: ARM_CM55F_MPU current-slot output section must be one 32-byte aperture")
ASSERT((__fiber_mpu_current_context_slot_start__ >=
	__fiber_mpu_privileged_sram_start__) &&
	(__fiber_mpu_current_context_slot_end__ <=
	__fiber_mpu_privileged_sram_end__),
	"[fiber]: ARM_CM55F_MPU current slot must remain in privileged SRAM")

/* These selected-port output sections are owned by the application linker
 * script. Requiring their placement makes the source-level section attributes
 * a link-time proof rather than a convention. User task code may use ordinary
 * application sections, but it must still lie in unprivileged flash. */
ASSERT((ADDR(.fiber_port_privileged_code) >=
	__fiber_mpu_privileged_flash_start__) &&
	((ADDR(.fiber_port_privileged_code) +
	  SIZEOF(.fiber_port_privileged_code)) <=
	 __fiber_mpu_privileged_flash_end__),
	"[fiber]: ARM_CM55F_MPU protected port code escaped privileged flash")
ASSERT((ADDR(.fiber_port_unprivileged_code) >=
	__fiber_mpu_unprivileged_flash_start__) &&
	((ADDR(.fiber_port_unprivileged_code) +
	  SIZEOF(.fiber_port_unprivileged_code)) <=
	 __fiber_mpu_unprivileged_flash_end__),
	"[fiber]: ARM_CM55F_MPU unprivileged port code escaped unprivileged flash")
ASSERT((ADDR(.fiber_port_syscalls) >=
	__fiber_mpu_unprivileged_syscalls_start__) &&
	((ADDR(.fiber_port_syscalls) + SIZEOF(.fiber_port_syscalls)) <=
	 __fiber_mpu_unprivileged_syscalls_end__),
	"[fiber]: ARM_CM55F_MPU syscall veneer escaped syscall flash")
ASSERT((ADDR(.fiber_port_privileged_data) >=
	__fiber_mpu_privileged_sram_start__) &&
	((ADDR(.fiber_port_privileged_data) +
	  SIZEOF(.fiber_port_privileged_data)) <=
	 __fiber_mpu_privileged_sram_end__),
	"[fiber]: ARM_CM55F_MPU protected data escaped privileged SRAM")

/* The four global ARMv8.1-M MPU regions have fixed roles and no overlap. The
 * current-slot aperture is intentionally the only contained subrange and is
 * overlaid by every active per-context RNR 5 image. */
ASSERT((__fiber_mpu_privileged_flash_end__ <=
	__fiber_mpu_unprivileged_flash_start__) ||
	(__fiber_mpu_unprivileged_flash_end__ <=
	__fiber_mpu_privileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU privileged and unprivileged flash overlap")
ASSERT((__fiber_mpu_privileged_flash_end__ <=
	__fiber_mpu_unprivileged_syscalls_start__) ||
	(__fiber_mpu_unprivileged_syscalls_end__ <=
	__fiber_mpu_privileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU privileged flash and syscall flash overlap")
ASSERT((__fiber_mpu_unprivileged_flash_end__ <=
	__fiber_mpu_unprivileged_syscalls_start__) ||
	(__fiber_mpu_unprivileged_syscalls_end__ <=
	__fiber_mpu_unprivileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU unprivileged flash and syscall flash overlap")
ASSERT((__fiber_mpu_privileged_sram_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_privileged_sram_start__),
	"[fiber]: ARM_CM55F_MPU privileged SRAM and unprivileged RAM overlap")
ASSERT((__fiber_mpu_privileged_flash_end__ <=
	__fiber_mpu_privileged_sram_start__) ||
	(__fiber_mpu_privileged_sram_end__ <=
	__fiber_mpu_privileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU privileged flash and privileged SRAM overlap")
ASSERT((__fiber_mpu_privileged_flash_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_privileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU privileged flash and unprivileged RAM overlap")
ASSERT((__fiber_mpu_unprivileged_flash_end__ <=
	__fiber_mpu_privileged_sram_start__) ||
	(__fiber_mpu_privileged_sram_end__ <=
	__fiber_mpu_unprivileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU unprivileged flash and privileged SRAM overlap")
ASSERT((__fiber_mpu_unprivileged_flash_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_unprivileged_flash_start__),
	"[fiber]: ARM_CM55F_MPU unprivileged flash and unprivileged RAM overlap")
ASSERT((__fiber_mpu_unprivileged_syscalls_end__ <=
	__fiber_mpu_privileged_sram_start__) ||
	(__fiber_mpu_privileged_sram_end__ <=
	__fiber_mpu_unprivileged_syscalls_start__),
	"[fiber]: ARM_CM55F_MPU syscall flash and privileged SRAM overlap")
ASSERT((__fiber_mpu_unprivileged_syscalls_end__ <=
	__fiber_mpu_unprivileged_ram_start__) ||
	(__fiber_mpu_unprivileged_ram_end__ <=
	__fiber_mpu_unprivileged_syscalls_start__),
	"[fiber]: ARM_CM55F_MPU syscall flash and unprivileged RAM overlap")
