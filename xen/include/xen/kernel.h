#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

/*
 * 'kernel.h' contains some often-used function prototypes etc
 */

#include <xen/types.h>

/*
 * min()/max() macros that also do
 * strict type-checking.. See the
 * "unnecessary" pointer comparison.
 */
#define min(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x < _y ? _x : _y; })

#define max(x,y) ({ \
        const typeof(x) _x = (x);       \
        const typeof(y) _y = (y);       \
        (void) (&_x == &_y);            \
        _x > _y ? _x : _y; })

/*
 * ..and if you can't take the strict
 * types, you can specify one yourself.
 *
 * Or not use min/max at all, of course.
 */
#define min_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
        ({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

/*
 * pre-processor, array size, and bit field width suitable variants;
 * please don't use in "normal" expressions.
 */
#define MIN(x,y) ((x) < (y) ? (x) : (y))
#define MAX(x,y) ((x) > (y) ? (x) : (y))

/**
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        typeof( ((type *)0)->member ) *__mptr = (ptr);          \
        (type *)( (char *)__mptr - offsetof(type,member) );})

/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x)                       \
({	type __dummy;                           \
	typeof(x) __dummy2;                     \
	(void)(&__dummy == &__dummy2);          \
	1;                                      \
})

extern char _start[], _end[], start[];
#define is_kernel(p) ({                         \
    char *__p = (char *)(unsigned long)(p);     \
    (__p >= _start) && (__p < _end);            \
})

extern char _stext[], _etext[];
#define is_kernel_text(p) ({                    \
    char *__p = (char *)(unsigned long)(p);     \
    (__p >= _stext) && (__p < _etext);          \
})

extern const char _srodata[], _erodata[];
#define is_kernel_rodata(p) ({                  \
    const char *__p = (const char *)(unsigned long)(p);     \
    (__p >= _srodata) && (__p < _erodata);      \
})

extern char _sinittext[], _einittext[];
#define is_kernel_inittext(p) ({                \
    char *__p = (char *)(unsigned long)(p);     \
    (__p >= _sinittext) && (__p < _einittext);  \
})

extern enum system_state {
    SYS_STATE_early_boot,
    SYS_STATE_boot,
    SYS_STATE_smp_boot,
    SYS_STATE_active,
    SYS_STATE_suspend,
    SYS_STATE_resume
} system_state;

bool_t is_active_kernel_text(unsigned long addr);

extern const char xen_config_data[];
extern const unsigned int xen_config_data_size;

#endif /* _LINUX_KERNEL_H */

