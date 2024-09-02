#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

/*
 * 'kernel.h' contains some often-used function prototypes etc
 */

#include <xen/macros.h>
#include <xen/types.h>

/**
 * container_of - cast a member of a structure out to the containing structure
 *
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({                      \
        typeof_field(type, member) *__mptr = (ptr);             \
        (type *)( (char *)__mptr - offsetof(type,member) );})

/**
 * __struct_group() - Create a mirrored named and anonyomous struct
 *
 * @TAG: The tag name for the named sub-struct (usually empty)
 * @NAME: The identifier name of the mirrored sub-struct
 * @ATTRS: Any struct attributes (usually empty)
 * @MEMBERS: The member declarations for the mirrored structs
 *
 * Used to create an anonymous union of two structs with identical layout
 * and size: one anonymous and one named. The former's members can be used
 * normally without sub-struct naming, and the latter can be used to
 * reason about the start, end, and size of the group of struct members.
 * The named struct can also be explicitly tagged for layer reuse, as well
 * as both having struct attributes appended.
 */
#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
    union { \
        struct { MEMBERS } ATTRS; \
        struct TAG { MEMBERS } ATTRS NAME; \
    } ATTRS

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

/* SAF-0-safe */
extern char _start[], _end[];
#define is_kernel(p) ({                         \
    char *__p = (char *)(unsigned long)(p);     \
    (__p >= _start) && (__p < _end);            \
})

/* SAF-0-safe */
extern char _stext[], _etext[];
#define is_kernel_text(p) ({                    \
    char *__p = (char *)(unsigned long)(p);     \
    (__p >= _stext) && (__p < _etext);          \
})

/* SAF-0-safe */
extern const char _srodata[], _erodata[];
#define is_kernel_rodata(p) ({                  \
    const char *__p = (const char *)(unsigned long)(p);     \
    (__p >= _srodata) && (__p < _erodata);      \
})

/* SAF-0-safe */
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

bool is_active_kernel_text(unsigned long addr);

extern const char xen_config_data[];
extern const unsigned int xen_config_data_size;

struct cpu_user_regs;
struct vcpu;

void cf_check show_execution_state(const struct cpu_user_regs *regs);
void vcpu_show_execution_state(struct vcpu *v);

#endif /* _LINUX_KERNEL_H */

