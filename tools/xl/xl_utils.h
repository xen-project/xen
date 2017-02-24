/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#ifndef XL_UTILS_H
#define XL_UTILS_H

#include <getopt.h>

/* For calls which return an errno on failure */
#define CHK_ERRNOVAL( call ) ({                                         \
        int chk_errnoval = (call);                                      \
        if (chk_errnoval < 0)                                           \
            abort();                                                    \
        else if (chk_errnoval > 0) {                                    \
            fprintf(stderr,"xl: fatal error: %s:%d: %s: %s\n",          \
                    __FILE__,__LINE__, strerror(chk_errnoval), #call);  \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
    })

/* For calls which return -1 and set errno on failure */
#define CHK_SYSCALL( call ) ({                                          \
        if ((call) == -1) {                                             \
            fprintf(stderr,"xl: fatal error: %s:%d: %s: %s\n",          \
                    __FILE__,__LINE__, strerror(errno), #call);         \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
    })

#define MUST( call ) ({                                                 \
        int must_rc = (call);                                           \
        if (must_rc < 0) {                                              \
            fprintf(stderr,"xl: fatal error: %s:%d, rc=%d: %s\n",       \
                    __FILE__,__LINE__, must_rc, #call);                 \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
    })

#define STR_HAS_PREFIX( a, b )  \
    ( strncmp(a, b, strlen(b)) == 0 )
#define STR_SKIP_PREFIX( a, b ) \
    ( STR_HAS_PREFIX(a, b) ? ((a) += strlen(b), 1) : 0 )

#define INVALID_DOMID ~0

#define LOG(_f, _a...)   dolog(__FILE__, __LINE__, __func__, _f "\n", ##_a)

/*
 * Wraps def_getopt into a convenient loop+switch to process all
 * arguments. This macro is intended to be called from main_XXX().
 *
 *   SWITCH_FOREACH_OPT(int *opt, "OPTS",
 *                      const struct option *longopts,
 *                      const char *commandname,
 *                      int num_opts_req) { ...
 *
 * opt:               pointer to an int variable, holds the current option
 *                    during processing.
 * OPTS:              short options, as per getopt_long(3)'s optstring argument.
 *                    do not include "h"; will be provided automatically
 * longopts:          long options, as per getopt_long(3)'s longopts argument.
 *                    May be null.
 * commandname:       name of this command, for usage string.
 * num_required_opts: number of non-option command line parameters
 *                    which are required.
 *
 * In addition the calling context is expected to contain variables
 * "argc" and "argv" in the conventional C-style:
 *   main(int argc, char **argv)
 * manner.
 *
 * Callers should treat SWITCH_FOREACH_OPT as they would a switch
 * statement over the value of `opt`. Each option given in `opts` (or
 * `lopts`) should be handled by a case statement as if it were inside
 * a switch statement.
 *
 * In addition to the options provided in opts the macro will handle
 * the "help" option and enforce a minimum number of non-option
 * command line pearameters as follows:
 *  -- if the user passes a -h or --help option. help will be printed,
 *     and the macro will cause the process to exit with code 0.
 *  -- if the user does not provided `num_required_opts` non-option
 *     arguments, the macro will cause the process to exit with code 2.
 *
 * Example:
 *
 * int main_foo(int argc, char **argv) {
 *     int opt;
 *
 *     SWITCH_FOREACH_OPT(opt, "blah", NULL, "foo", 0) {
 *      case 'b':
 *          ... handle b option...
 *          break;
 *      case 'l':
 *          ... handle l option ...
 *          break;
 *      case etc etc...
 *      }
 *      ... do something useful with the options ...
 * }
 */
#define SWITCH_FOREACH_OPT(opt, opts, longopts,                         \
                           commandname, num_required_opts)              \
    while (((opt) = def_getopt(argc, argv, "h" opts, (longopts),        \
                               (commandname), (num_required_opts))) != -1) \
        switch (opt)

/* Must be last in list */
#define COMMON_LONG_OPTS {"help", 0, 0, 'h'}, \
                         {0, 0, 0, 0}

int def_getopt(int argc, char * const argv[],
               const char *optstring,
               const struct option *longopts,
               const char* helpstr, int reqargs);

void dolog(const char *file, int line, const char *func, char *fmt, ...)
	__attribute__((format(printf,4,5)));

void xvasprintf(char **strp, const char *fmt, va_list ap)
	__attribute__((format(printf,2,0)));

void xasprintf(char **strp, const char *fmt, ...)
	__attribute__((format(printf,2,3)));

void *xmalloc(size_t sz);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *ptr, size_t sz);
char *xstrdup(const char *x);
void string_realloc_append(char **accumulate, const char *more);

void flush_stream(FILE *fh);
uint32_t find_domain(const char *p) __attribute__((warn_unused_result));

void print_bitmap(uint8_t *map, int maplen, FILE *stream);

int do_daemonize(char *name, const char *pidfile);
#endif /* XL_UTILS_H */

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
