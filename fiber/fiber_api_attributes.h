/*
 * fiber_api_attributes.h
 *
 * Compiler-only attributes required by the public fiber API. This header must
 * not select a port or include CMSIS.
 */

#ifndef FIBER_FIBER_API_ATTRIBUTES_H_
#define FIBER_FIBER_API_ATTRIBUTES_H_

/* Keep this header independent of CMSIS. It is shared by the public API and
 * the common runtime, while selected ports own all CPU intrinsics. */
#ifndef FIBER_API_HAS_ATTRIBUTE
# if defined(__has_attribute)
#  define FIBER_API_HAS_ATTRIBUTE(x) __has_attribute(x)
# else
#  define FIBER_API_HAS_ATTRIBUTE(x) 0
# endif
#endif

#ifndef FIBER_API_NORETURN
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_NORETURN __attribute__((noreturn))
# elif defined(__cplusplus)
#  define FIBER_API_NORETURN [[noreturn]]
# else
#  define FIBER_API_NORETURN _Noreturn
# endif
#endif

#ifndef FIBER_API_WEAK
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_WEAK __attribute__((weak))
# else
#  define FIBER_API_WEAK
# endif
#endif

#ifndef FIBER_API_NOINLINE
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_NOINLINE __attribute__((noinline))
# else
#  define FIBER_API_NOINLINE
# endif
#endif

/* Prevent interprocedural cloning/folding from changing the shape or identity
 * of control-transfer-sensitive runtime functions. GCC's noipa is the
 * strongest available contract and implies noinline, noclone, and no_icf;
 * the narrower mappings remain useful on compilers without noipa. */
#ifndef FIBER_API_NOIPA
# if (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ >= 8)) || \
		FIBER_API_HAS_ATTRIBUTE(noipa)
#  define FIBER_API_NOIPA __attribute__((noipa))
# else
#  define FIBER_API_NOIPA
# endif
#endif

#ifndef FIBER_API_NOCLONE
# if FIBER_API_HAS_ATTRIBUTE(noclone)
#  define FIBER_API_NOCLONE __attribute__((noclone))
# else
#  define FIBER_API_NOCLONE
# endif
#endif

#ifndef FIBER_API_NOICF
# if FIBER_API_HAS_ATTRIBUTE(no_icf)
#  define FIBER_API_NOICF __attribute__((no_icf))
# else
#  define FIBER_API_NOICF
# endif
#endif

#ifndef FIBER_API_USED
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_USED __attribute__((used))
# else
#  define FIBER_API_USED
# endif
#endif

#ifndef FIBER_API_NOINSTR
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_NOINSTR __attribute__((no_instrument_function))
# else
#  define FIBER_API_NOINSTR
# endif
#endif

#ifndef FIBER_API_NOSSP
# if FIBER_API_HAS_ATTRIBUTE(no_stack_protector)
#  define FIBER_API_NOSSP __attribute__((no_stack_protector))
# else
#  define FIBER_API_NOSSP
# endif
#endif

#ifndef FIBER_API_NOSAN
# if FIBER_API_HAS_ATTRIBUTE(no_sanitize)
#  define FIBER_API_NOSAN __attribute__((no_sanitize("address", "undefined", "thread")))
# else
#  define FIBER_API_NOSAN
# endif
#endif

#ifndef FIBER_API_NOPROF
# if FIBER_API_HAS_ATTRIBUTE(no_profile_instrument_function)
#  define FIBER_API_NOPROF __attribute__((no_profile_instrument_function))
# else
#  define FIBER_API_NOPROF
# endif
#endif

#ifndef FIBER_API_NOCOVERAGE
# if FIBER_API_HAS_ATTRIBUTE(no_sanitize_coverage)
#  define FIBER_API_NOCOVERAGE __attribute__((no_sanitize_coverage))
# else
#  define FIBER_API_NOCOVERAGE
# endif
#endif

#ifndef FIBER_API_ATTR_SENSITIVE
# define FIBER_API_ATTR_SENSITIVE \
		FIBER_API_NOINLINE FIBER_API_NOIPA FIBER_API_NOCLONE \
		FIBER_API_NOICF FIBER_API_USED FIBER_API_NOINSTR \
		FIBER_API_NOSSP FIBER_API_NOSAN FIBER_API_NOPROF \
		FIBER_API_NOCOVERAGE
#endif

/* CPU-neutral placement marker for the minimal common call chain that may run
 * directly from Thread mode. Non-MPU linkers may collect it with ordinary
 * text. MPU linkers map it to the application-executable code region. An
 * explicit section attribute is required because -ffunction-sections names do
 * not survive whole-program LTO reliably. */
#ifndef FIBER_API_THREAD_FUNCTION
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_THREAD_FUNCTION \
		__attribute__((section(".text.fiber_runtime_thread_functions")))
# else
#  define FIBER_API_THREAD_FUNCTION
# endif
#endif

#ifndef FIBER_API_UNREACHABLE
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_UNREACHABLE() __builtin_unreachable()
# else
#  define FIBER_API_UNREACHABLE() do { } while (0)
# endif
#endif

/*
 * PendSV and SVC bridges must not acquire an implicit FP ABI dependency.
 * GCC does not propagate this through an indirect callback pointer, so the
 * scheduler hook and its complete call graph remain an integration contract.
 */
#ifndef FIBER_GENERAL_REGS_ONLY
# if defined(__GNUC__) && !defined(__clang__) && \
		(defined(__arm__) || defined(__thumb__))
#  define FIBER_GENERAL_REGS_ONLY __attribute__((target("general-regs-only")))
# else
#  define FIBER_GENERAL_REGS_ONLY
# endif
#endif

#ifndef FIBER_SCHEDULER_HOOK_ATTR
# define FIBER_SCHEDULER_HOOK_ATTR \
		FIBER_API_ATTR_SENSITIVE FIBER_GENERAL_REGS_ONLY
#endif

#endif /* FIBER_FIBER_API_ATTRIBUTES_H_ */
