#ifndef __LIB_H__
#define __LIB_H__

#include <stdarg.h>
#include <xen/config.h>
#include <xen/types.h>
#include <xen/string.h>

#define BUG() do {					\
    debugtrace_dump(0);                                 \
    printk("BUG at %s:%d\n", __FILE__, __LINE__);	\
    FORCE_CRASH();                                      \
} while ( 0 )

#ifndef NDEBUG
#define ASSERT(_p) if ( !(_p) ) { printk("Assertion '%s' failed, line %d, file %s\n", #_p , __LINE__, __FILE__); BUG(); }
#else
#define ASSERT(_p) ((void)0)
#endif

#define SWAP(_a, _b) \
   do { typeof(_a) _t = (_a); (_a) = (_b); (_b) = _t; } while ( 0 )

#define reserve_bootmem(_p,_l) ((void)0)

struct domain;

void cmdline_parse(char *cmdline);

#ifndef NDEBUG
extern void debugtrace_reset(int send_to_console);
extern void debugtrace_dump(int send_to_console);
extern void debugtrace_printk(const char *fmt, ...);
#else
#define debugtrace_reset(_send_to_console) ((void)0)
#define debugtrace_dump(_send_to_console)  ((void)0)
#define debugtrace_printk(_f, ...)         ((void)0)
#endif

#define printk printf
void printf(const char *format, ...);
void panic(const char *format, ...);
long vm_assist(struct domain *, unsigned int, unsigned int);

/* vsprintf.c */
extern int sprintf(char * buf, const char * fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern int vsprintf(char *buf, const char *, va_list);
extern int snprintf(char * buf, size_t size, const char * fmt, ...)
	__attribute__ ((format (printf, 3, 4)));
extern int vsnprintf(char *buf, size_t size, const char *fmt, va_list args);

long simple_strtol(const char *cp,char **endp,unsigned int base);
unsigned long simple_strtoul(const char *cp,char **endp,unsigned int base);
long long simple_strtoll(const char *cp,char **endp,unsigned int base);

#endif /* __LIB_H__ */
