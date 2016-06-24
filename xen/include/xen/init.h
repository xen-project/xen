#ifndef _LINUX_INIT_H
#define _LINUX_INIT_H

#include <asm/init.h>

/*
 * Mark functions and data as being only used at initialization
 * or exit time.
 */
#define __init            __text_section(".init.text")
#define __exit            __text_section(".exit.text")
#define __initdata        __section(".init.data")
#define __initconst       __section(".init.rodata")
#define __initconstrel    __section(".init.rodata.rel")
#define __exitdata        __used_section(".exit.data")
#define __initsetup       __used_section(".init.setup")
#define __init_call(lvl)  __used_section(".initcall" lvl ".init")
#define __exit_call       __used_section(".exitcall.exit")

/* These macros are used to mark some functions or 
 * initialized data (doesn't apply to uninitialized data)
 * as `initialization' functions. The kernel can take this
 * as hint that the function is used only during the initialization
 * phase and free up used memory resources after
 *
 * Usage:
 * For functions:
 * 
 * You should add __init immediately before the function name, like:
 *
 * static void __init initme(int x, int y)
 * {
 *    extern int z; z = x * y;
 * }
 *
 * If the function has a prototype somewhere, you can also add
 * __init between closing brace of the prototype and semicolon:
 *
 * extern int initialize_foobar_device(int, int, int) __init;
 *
 * For initialized data:
 * You should insert __initdata between the variable name and equal
 * sign followed by value, e.g.:
 *
 * static int init_variable __initdata = 0;
 * static char linux_logo[] __initdata = { 0x32, 0x36, ... };
 *
 * Don't forget to initialize data not at file scope, i.e. within a function,
 * as gcc otherwise puts the data into the bss section and not into the init
 * section.
 * 
 * Also note, that this data cannot be "const".
 */

#ifndef __ASSEMBLY__

/*
 * Used for initialization calls..
 */
typedef int (*initcall_t)(void);
typedef void (*exitcall_t)(void);

#define presmp_initcall(fn) \
    const static initcall_t __initcall_##fn __init_call("presmp") = fn
#define __initcall(fn) \
    const static initcall_t __initcall_##fn __init_call("1") = fn
#define __exitcall(fn) \
    static exitcall_t __exitcall_##fn __exit_call = fn

void do_presmp_initcalls(void);
void do_initcalls(void);

/*
 * Used for kernel command line parameter setup
 */
struct kernel_param {
    const char *name;
    enum {
        OPT_STR,
        OPT_UINT,
        OPT_BOOL,
        OPT_SIZE,
        OPT_CUSTOM
    } type;
    unsigned int len;
    void *var;
};

extern const struct kernel_param __setup_start[], __setup_end[];

#define __setup_str static const __initconst \
    __attribute__((__aligned__(1))) char
#define __kparam static const __initsetup \
    __attribute__((__aligned__(sizeof(void *)))) struct kernel_param

#define custom_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = { __setup_str_##_var, OPT_CUSTOM, 0, _var }
#define boolean_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { __setup_str_##_var, OPT_BOOL, sizeof(_var), &_var }
#define integer_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { __setup_str_##_var, OPT_UINT, sizeof(_var), &_var }
#define size_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { __setup_str_##_var, OPT_SIZE, sizeof(_var), &_var }
#define string_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { __setup_str_##_var, OPT_STR, sizeof(_var), &_var }

#endif /* __ASSEMBLY__ */

#ifdef CONFIG_LATE_HWDOM
#define __hwdom_init
#define __hwdom_initdata  __read_mostly
#else
#define __hwdom_init      __init
#define __hwdom_initdata  __initdata
#endif

#endif /* _LINUX_INIT_H */
