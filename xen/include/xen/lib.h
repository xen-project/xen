#ifndef __LIB_H__
#define __LIB_H__

#include <xen/inttypes.h>
#include <xen/stdarg.h>
#include <xen/types.h>
#include <xen/xmalloc.h>
#include <xen/string.h>
#include <asm/bug.h>

#define BUG_ON(p)  do { if (unlikely(p)) BUG();  } while (0)
#define WARN_ON(p) do { if (unlikely(p)) WARN(); } while (0)

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)
/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(cond) ({ _Static_assert(!(cond), "!(" #cond ")"); })

/* Force a compilation error if condition is true, but also produce a
   result (of value 0 and type size_t), so the expression can be used
   e.g. in a structure initializer (or where-ever else comma expressions
   aren't permitted). */
#define BUILD_BUG_ON_ZERO(cond) \
    sizeof(struct { _Static_assert(!(cond), "!(" #cond ")"); })
#else
#define BUILD_BUG_ON_ZERO(cond) sizeof(struct { int:-!!(cond); })
#define BUILD_BUG_ON(cond) ((void)BUILD_BUG_ON_ZERO(cond))
#endif

#ifdef CONFIG_GCOV
#define gcov_string "gcov=y"
#else
#define gcov_string ""
#endif

#ifndef NDEBUG
#define ASSERT(p) \
    do { if ( unlikely(!(p)) ) assert_failed(#p); } while (0)
#define ASSERT_UNREACHABLE() assert_failed("unreachable")
#define debug_build() 1
#else
#define ASSERT(p) do { if ( 0 && (p) ) {} } while (0)
#define ASSERT_UNREACHABLE() do { } while (0)
#define debug_build() 0
#endif

#define ABS(_x) ({                              \
    typeof(_x) __x = (_x);                      \
    (__x < 0) ? -__x : __x;                     \
})

#define SWAP(_a, _b) \
   do { typeof(_a) _t = (_a); (_a) = (_b); (_b) = _t; } while ( 0 )

#define DIV_ROUND(n, d) (((n) + (d) / 2) / (d))
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]) + __must_be_array(x))

#define __ACCESS_ONCE(x) ({                             \
            (void)(typeof(x))0; /* Scalar typecheck. */ \
            (volatile typeof(x) *)&(x); })
#define ACCESS_ONCE(x) (*__ACCESS_ONCE(x))

#define MASK_EXTR(v, m) (((v) & (m)) / ((m) & -(m)))
#define MASK_INSR(v, m) (((v) * ((m) & -(m))) & (m))

#define ROUNDUP(x, a) (((x) + (a) - 1) & ~((a) - 1))

#define count_args_(dot, a1, a2, a3, a4, a5, a6, a7, a8, x, ...) x
#define count_args(args...) \
    count_args_(., ## args, 8, 7, 6, 5, 4, 3, 2, 1, 0)

struct domain;

void cmdline_parse(const char *cmdline);
int runtime_parse(const char *line);
int parse_bool(const char *s, const char *e);

/**
 * Given a specific name, parses a string of the form:
 *   [no-]$NAME[=...]
 * returning 0 or 1 for a recognised boolean, or -1 for an error.
 */
int parse_boolean(const char *name, const char *s, const char *e);

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

/* Allows us to use '%p' as general-purpose machine-word format char. */
#define _p(_x) ((void *)(unsigned long)(_x))
extern void printk(const char *format, ...)
    __attribute__ ((format (printf, 1, 2)));

#define printk_once(fmt, args...)               \
({                                              \
    static bool __read_mostly once_;            \
    if ( unlikely(!once_) )                     \
    {                                           \
        once_ = true;                           \
        printk(fmt, ## args);                   \
    }                                           \
})

extern void guest_printk(const struct domain *d, const char *format, ...)
    __attribute__ ((format (printf, 2, 3)));
extern void noreturn panic(const char *format, ...)
    __attribute__ ((format (printf, 1, 2)));
extern long vm_assist(struct domain *, unsigned int cmd, unsigned int type,
                      unsigned long valid);
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
extern int asprintf(char ** bufp, const char * fmt, ...)
    __attribute__ ((format (printf, 2, 3)));
extern int vasprintf(char ** bufp, const char * fmt, va_list args)
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

#define TAINT_SYNC_CONSOLE              (1u << 0)
#define TAINT_MACHINE_CHECK             (1u << 1)
#define TAINT_ERROR_INJECT              (1u << 2)
#define TAINT_HVM_FEP                   (1u << 3)
extern unsigned int tainted;
#define TAINT_STRING_MAX_LEN            20
extern char *print_tainted(char *str);
extern void add_taint(unsigned int taint);

struct cpu_user_regs;
void dump_execstate(struct cpu_user_regs *);

void init_constructors(void);

void *bsearch(const void *key, const void *base, size_t num, size_t size,
              int (*cmp)(const void *key, const void *elt));

#endif /* __LIB_H__ */
