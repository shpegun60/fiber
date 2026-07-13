/*
 * fiber_api_attributes.h
 *
 * Compiler-only attributes required by the public fiber API. This header must
 * not select a port or include CMSIS.
 */

#ifndef FIBER_FIBER_API_ATTRIBUTES_H_
#define FIBER_FIBER_API_ATTRIBUTES_H_

#ifndef FIBER_API_NORETURN
# if defined(__GNUC__) || defined(__clang__)
#  define FIBER_API_NORETURN __attribute__((noreturn))
# elif defined(__cplusplus)
#  define FIBER_API_NORETURN [[noreturn]]
# else
#  define FIBER_API_NORETURN _Noreturn
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
# define FIBER_SCHEDULER_HOOK_ATTR FIBER_GENERAL_REGS_ONLY
#endif

#endif /* FIBER_FIBER_API_ATTRIBUTES_H_ */
