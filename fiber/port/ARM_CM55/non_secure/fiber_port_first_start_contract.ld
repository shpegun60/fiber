/* Board-owned INCLUDE after its SECTIONS, or an additional -T fragment.
 * Define all six half-open bounds in immutable NS flash / reserved NS RAM.
 * With multiple -T scripts pin .gnu.sgstubs explicitly in the Secure image;
 * this NS fragment chooses neither an NSC address nor board memory addresses.
 * 2048 is a baseline minimum, not a proof of all hooks/nesting stack depth. */
ASSERT(DEFINED(__fiber_c55s_ns_vector_start__) && DEFINED(__fiber_c55s_ns_vector_end__),
       "C55S first start requires immutable NS vector bounds")
ASSERT(DEFINED(__fiber_c55s_ns_start_code_start__) && DEFINED(__fiber_c55s_ns_start_code_end__),
       "C55S first start requires immutable NS code bounds")
ASSERT(DEFINED(__fiber_c55s_ns_msp_stack_start__) && DEFINED(__fiber_c55s_ns_msp_stack_end__),
       "C55S first start requires reserved NS MSP bounds")
ASSERT((__fiber_c55s_ns_vector_start__ & 127) == 0 &&
       __fiber_c55s_ns_vector_start__ != 0 &&
       __fiber_c55s_ns_vector_end__ >= __fiber_c55s_ns_vector_start__ + 64,
       "C55S first start requires aligned complete core vectors")
ASSERT(__fiber_c55s_ns_start_code_end__ > __fiber_c55s_ns_start_code_start__ &&
       ((__fiber_c55s_ns_start_code_start__ | __fiber_c55s_ns_start_code_end__) & 1) == 0,
       "C55S first start requires a halfword-aligned code map")
ASSERT(__fiber_c55s_ns_msp_stack_end__ > __fiber_c55s_ns_msp_stack_start__ &&
       ((__fiber_c55s_ns_msp_stack_start__ | __fiber_c55s_ns_msp_stack_end__) & 7) == 0 &&
       __fiber_c55s_ns_msp_stack_end__ - __fiber_c55s_ns_msp_stack_start__ >= 2048,
       "C55S first start requires at least 2048 reserved MSP bytes")
ASSERT((__fiber_c55s_ns_msp_stack_end__ <= __fiber_c55s_ns_start_code_start__ ||
        __fiber_c55s_ns_msp_stack_start__ >= __fiber_c55s_ns_start_code_end__) &&
       (__fiber_c55s_ns_msp_stack_end__ <= __fiber_c55s_ns_vector_start__ ||
        __fiber_c55s_ns_msp_stack_start__ >= __fiber_c55s_ns_vector_end__),
       "C55S first-start MSP must be disjoint from code and vectors")
ASSERT(DEFINED(fiber_port_arm_cm55_secure_context_first_start_component_v1_anchor) &&
       DEFINED(SVC_Handler) && DEFINED(fiber_port_c55s_first_start_svc_return),
       "C55S first start requires its strong owned SVC component")
ASSERT((SVC_Handler & ~1) >= __fiber_c55s_ns_start_code_start__ &&
       (SVC_Handler & ~1) + 2 <= __fiber_c55s_ns_start_code_end__ &&
       fiber_port_c55s_first_start_svc_return >= __fiber_c55s_ns_start_code_start__ + 2 &&
       fiber_port_c55s_first_start_svc_return <= __fiber_c55s_ns_start_code_end__,
       "C55S first-start SVC must be inside the approved code map")
