#include <stdbool.h>

/** Define a proposition as likely true.
 * @param prop Proposition
 **/
#undef likely
#ifdef __GNUC__
#define likely(prop)                                                           \
  __builtin_expect((prop) ? true : false, true /* likely    \
                                                                   */)
#else
#define likely(prop) (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
 **/
#undef unlikely
#ifdef __GNUC__
#define unlikely(prop)                                                         \
  __builtin_expect((prop) ? true : false, false /* unlikely */)
#else
#define unlikely(prop) (prop)
#endif

/** Define a variable as unused.
 **/
#undef unused
#ifdef __GNUC__
#define unused(variable) variable __attribute__((unused))
#else
#define unused(variable)
#warning This compiler has no support for GCC attributes
#endif

// =============
