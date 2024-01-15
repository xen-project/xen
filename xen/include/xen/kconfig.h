#ifndef __XEN_KCONFIG_H
#define __XEN_KCONFIG_H

#include <generated/autoconf.h>

/*
 * Helper macros to use CONFIG_ options in C/CPP expressions. Note that
 * these only work with boolean option.
 */

/* cppcheck is failing to parse the macro so use a dummy one */
#ifdef CPPCHECK
#define IS_ENABLED(option) option
#define STATIC_IF(option) option
#define STATIC_IF_NOT(option) option
#else
/*
 * Getting something that works in C and CPP for an arg that may or may
 * not be defined is tricky.  Here, if we have "#define CONFIG_BOOGER 1"
 * we match on the placeholder define, insert the "0," for arg1 and generate
 * the triplet (0, 1, 0).  Then the last step cherry picks the 2nd arg (a one).
 * When CONFIG_BOOGER is not defined, we generate a (... 1, 0) pair, and when
 * the last step cherry picks the 2nd arg, we get a zero.
 */
#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

/*
 * IS_ENABLED(CONFIG_FOO) evaluates to 1 if CONFIG_FOO is set to 'y', 0
 * otherwise.
 */
#define IS_ENABLED(option) config_enabled(option)

/* Use similar trickery for conditionally inserting "static". */
#define static_if(value) _static_if(__ARG_PLACEHOLDER_##value)
#define _static_if(arg1_or_junk) ___config_enabled(arg1_or_junk static,)

#define STATIC_IF(option) static_if(option)

#define static_if_not(value) _static_if_not(__ARG_PLACEHOLDER_##value)
#define _static_if_not(arg1_or_junk) ___config_enabled(arg1_or_junk, static)

#define STATIC_IF_NOT(option) static_if_not(option)
#endif

#endif /* __XEN_KCONFIG_H */
