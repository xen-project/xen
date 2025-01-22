#ifndef __LIB_H__
#define __LIB_H__

#include <xen/macros.h>

#ifndef __ASSEMBLY__

#include <xen/inttypes.h>
#include <xen/stdarg.h>
#include <xen/types.h>
#include <xen/xmalloc.h>
#include <xen/string.h>
#include <xen/sections.h>

#define __ACCESS_ONCE(x) ({                             \
            (void)(typeof(x))0; /* Scalar typecheck. */ \
            (volatile typeof(x) *)&(x); })
#define ACCESS_ONCE(x) (*__ACCESS_ONCE(x))

struct domain;

void cmdline_parse(const char *cmdline);
int parse_bool(const char *s, const char *e);

/**
 * Given a specific name, parses a string of the form:
 *   [no-]$NAME[=...]
 * returning 0 or 1 for a recognised boolean.  Returns -1 for general errors,
 * and -2 for "not a boolean, but $NAME= matches".
 */
int parse_boolean(const char *name, const char *s, const char *e);

/**
 * Given a specific name, parses a string of the form:
 *   $NAME=<integer number>
 * returning 0 and a value in val, for a recognised integer.
 * Returns -1 for name not found, general errors, or -2 if name is found but
 * not recognised number.
 */
int parse_signed_integer(const char *name, const char *s, const char *e,
                         long long *val);

/**
 * Very similar to strcmp(), but will declare a match if the NUL in 'name'
 * lines up with comma, colon, semicolon or equals in 'frag'.  Designed for
 * picking exact string matches out of a delimited command line list.
 */
int cmdline_strcmp(const char *frag, const char *name);

#ifdef CONFIG_DEBUG_TRACE
extern void debugtrace_dump(void);
extern void debugtrace_printk(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));
#else
static inline void debugtrace_dump(void) {}
static inline void
 __attribute__ ((format (printf, 1, 2)))
debugtrace_printk(const char *fmt, ...) {}
#endif

extern void printk(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2), cold));
void vprintk(const char *fmt, va_list args)
    __attribute__ ((format (printf, 1, 0), cold));

#define printk_once(fmt, args...)               \
({                                              \
    static bool __read_mostly once_;            \
    if ( unlikely(!once_) )                     \
    {                                           \
        once_ = true;                           \
        printk(fmt, ## args);                   \
    }                                           \
})

extern void guest_printk(const struct domain *d, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));
extern void noreturn panic(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));
extern int __printk_ratelimit(int ratelimit_ms, int ratelimit_burst);
extern int printk_ratelimit(void);

#define gprintk(lvl, fmt, args...) \
    printk(XENLOG_GUEST lvl "%pv " fmt, current, ## args)

#ifdef NDEBUG

static inline void
__attribute__ ((__format__ (__printf__, 2, 3)))
dprintk(const char *lvl, const char *fmt, ...) {}

static inline void
__attribute__ ((__format__ (__printf__, 2, 3)))
gdprintk(const char *lvl, const char *fmt, ...) {}

#else

#define dprintk(lvl, fmt, args...) \
    printk(lvl "%s:%d: " fmt, __FILE__, __LINE__, ## args)
#define gdprintk(lvl, fmt, args...) \
    printk(XENLOG_GUEST lvl "%s:%d:%pv " fmt, \
           __FILE__, __LINE__, current, ## args)

#endif

/* vsprintf.c */
#define sprintf __xen_has_no_sprintf__
#define vsprintf __xen_has_no_vsprintf__
extern int snprintf(char * buf, size_t size, const char * fmt, ...)
    __attribute__ ((format (printf, 3, 4)));
extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)));
extern int scnprintf(char * buf, size_t size, const char * fmt, ...)
    __attribute__ ((format (printf, 3, 4)));
extern int vscnprintf(char *buf, size_t size, const char *fmt, va_list args)
    __attribute__ ((format (printf, 3, 0)));
extern int xasprintf(char **bufp, const char *fmt, ...)
    __attribute__ ((format (printf, 2, 3)));
extern int xvasprintf(char **bufp, const char *fmt, va_list args)
    __attribute__ ((format (printf, 2, 0)));

long simple_strtol(
    const char *cp,const char **endp, unsigned int base);
unsigned long simple_strtoul(
    const char *cp,const char **endp, unsigned int base);
long long simple_strtoll(
    const char *cp,const char **endp, unsigned int base);
unsigned long long simple_strtoull(
    const char *cp,const char **endp, unsigned int base);

unsigned long long parse_size_and_unit(const char *s, const char **ps);

uint64_t muldiv64(uint64_t a, uint32_t b, uint32_t c);

/*
 * A slightly more typesafe variant of cmpxchg() when the entities dealt with
 * are pointers.
 */
#define cmpxchgptr(ptr, o, n) ({                                        \
    __typeof__(**(ptr)) *const o_ = (o);                                \
    __typeof__(**(ptr)) *n_ = (n);                                      \
    ((__typeof__(*(ptr)))__cmpxchg(ptr, (unsigned long)o_,              \
                                   (unsigned long)n_, sizeof(*(ptr)))); \
})

#define TAINT_SYNC_CONSOLE              (1u << 0)
#define TAINT_MACHINE_CHECK             (1u << 1)
#define TAINT_ERROR_INJECT              (1u << 2)
#define TAINT_HVM_FEP                   (1u << 3)
#define TAINT_MACHINE_INSECURE          (1u << 4)
#define TAINT_CPU_OUT_OF_SPEC           (1u << 5)
extern unsigned int tainted;
#define TAINT_STRING_MAX_LEN            20
extern char *print_tainted(char *str);
extern void add_taint(unsigned int taint);

struct cpu_user_regs;
void cf_check dump_execstate(const struct cpu_user_regs *regs);

void init_constructors(void);

/*
 * bsearch - binary search an array of elements
 * @key: pointer to item being searched for
 * @base: pointer to first element to search
 * @num: number of elements
 * @size: size of each element
 * @cmp: pointer to comparison function
 *
 * This function does a binary search on the given array.  The
 * contents of the array should already be in ascending sorted order
 * under the provided comparison function.
 *
 * Note that the key need not have the same type as the elements in
 * the array, e.g. key could be a string and the comparison function
 * could compare the string with the struct's name field.  However, if
 * the key and elements in the array are of the same type, you can use
 * the same comparison function for both sort() and bsearch().
 */
#ifndef BSEARCH_IMPLEMENTATION
extern gnu_inline
#endif
void *bsearch(const void *key, const void *base, size_t num, size_t size,
              int (*cmp)(const void *key, const void *elt))
{
    size_t start = 0, end = num;
    int result;

    while ( start < end )
    {
        size_t mid = start + (end - start) / 2;

        result = cmp(key, base + mid * size);
        if ( result < 0 )
            end = mid;
        else if ( result > 0 )
            start = mid + 1;
        else
            return (void *)base + mid * size;
    }

    return NULL;
}

#endif /* __ASSEMBLY__ */

#endif /* __LIB_H__ */
