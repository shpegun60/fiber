/*
 * fiber_static_assert.h
 *
 * Fiber-owned compile-time assertion macro.
 *
 * This header intentionally does not depend on basic_types.h. The fiber runtime
 * and selected ports must not rely on project utility assertion macros being
 * present.
 */

#ifndef FIBER_FIBER_STATIC_ASSERT_H_
#define FIBER_FIBER_STATIC_ASSERT_H_

#ifndef FIBER_STATIC_ASSERT
# if defined(__cplusplus)
#  define FIBER_STATIC_ASSERT(cond, msg) static_assert((cond), msg)
# elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
#  define FIBER_STATIC_ASSERT(cond, msg) _Static_assert((cond), msg)
# else
#  define FIBER_STATIC_ASSERT_CAT_(a, b) a##b
#  define FIBER_STATIC_ASSERT_CAT(a, b) FIBER_STATIC_ASSERT_CAT_(a, b)
#  define FIBER_STATIC_ASSERT(cond, msg) \
	typedef char FIBER_STATIC_ASSERT_CAT(fiber_static_assert_failed_at_line_, \
			__LINE__)[(cond) ? 1 : -1]
# endif
#endif

#endif /* FIBER_FIBER_STATIC_ASSERT_H_ */
