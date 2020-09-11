#ifndef _XEN_PARAM_H
#define _XEN_PARAM_H

#include <xen/hypfs.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/stdbool.h>

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
        OPT_CUSTOM,
        OPT_IGNORE,
    } type;
    unsigned int len;
    union {
        void *var;
        int (*func)(const char *);
    } par;
};

/* Maximum length of a single parameter string. */
#define MAX_PARAM_SIZE 128

extern const struct kernel_param __setup_start[], __setup_end[];

#define __param(att)      static const att \
    __attribute__((__aligned__(sizeof(void *)))) struct kernel_param

#define __setup_str static const __initconst \
    __attribute__((__aligned__(1))) char
#define __kparam          __param(__initsetup)

/* Only for use with .init data, to avoid creating livepatch problems. */
#define __TEMP_NAME(base, line) base ## _ ## line
#define _TEMP_NAME(base, line) __TEMP_NAME(base, line)
#define TEMP_NAME(base) _TEMP_NAME(base, __LINE__)

#define custom_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { .name = __setup_str_##_var, \
          .type = OPT_CUSTOM, \
          .par.func = _var }
#define boolean_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { .name = __setup_str_##_var, \
          .type = OPT_BOOL, \
          .len = sizeof(_var) + \
                 BUILD_BUG_ON_ZERO(sizeof(_var) != sizeof(bool)), \
          .par.var = &_var }
#define integer_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { .name = __setup_str_##_var, \
          .type = OPT_UINT, \
          .len = sizeof(_var), \
          .par.var = &_var }
#define size_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { .name = __setup_str_##_var, \
          .type = OPT_SIZE, \
          .len = sizeof(_var), \
          .par.var = &_var }
#define string_param(_name, _var) \
    __setup_str __setup_str_##_var[] = _name; \
    __kparam __setup_##_var = \
        { .name = __setup_str_##_var, \
          .type = OPT_STR, \
          .len = sizeof(_var), \
          .par.var = &_var }
#define ignore_param(_name)                 \
    __setup_str TEMP_NAME(__setup_str_ign)[] = _name;    \
    __kparam TEMP_NAME(__setup_ign) =                    \
        { .name = TEMP_NAME(__setup_str_ign),            \
          .type = OPT_IGNORE }

#ifdef CONFIG_HYPFS

struct param_hypfs {
    struct hypfs_entry_leaf hypfs;
    void (*init_leaf)(struct param_hypfs *par);
    int (*func)(const char *);
};

extern struct param_hypfs __paramhypfs_start[], __paramhypfs_end[];

#define __paramhypfs      __used_section(".data.paramhypfs")

#define __paramfs         static __paramhypfs  \
    __attribute__((__aligned__(sizeof(void *)))) struct param_hypfs

#define custom_runtime_set_var_sz(parfs, var, sz) \
    { \
        (parfs)->hypfs.u.content = var; \
        (parfs)->hypfs.e.max_size = sz; \
        (parfs)->hypfs.e.size = strlen(var) + 1; \
    }
#define custom_runtime_set_var(parfs, var) \
    custom_runtime_set_var_sz(parfs, var, sizeof(var))

#define param_2_parfs(par) &__parfs_##par

/* initfunc needs to set size and content, e.g. via custom_runtime_set_var(). */
#define custom_runtime_only_param(nam, variable, initfunc) \
    __paramfs __parfs_##variable = \
        { .hypfs.e.type = XEN_HYPFS_TYPE_STRING, \
          .hypfs.e.encoding = XEN_HYPFS_ENC_PLAIN, \
          .hypfs.e.name = (nam), \
          .hypfs.e.read = hypfs_read_leaf, \
          .hypfs.e.write = hypfs_write_custom, \
          .init_leaf = (initfunc), \
          .func = (variable) }
#define boolean_runtime_only_param(nam, variable) \
    __paramfs __parfs_##variable = \
        { .hypfs.e.type = XEN_HYPFS_TYPE_BOOL, \
          .hypfs.e.encoding = XEN_HYPFS_ENC_PLAIN, \
          .hypfs.e.name = (nam), \
          .hypfs.e.size = sizeof(variable), \
          .hypfs.e.max_size = sizeof(variable), \
          .hypfs.e.read = hypfs_read_leaf, \
          .hypfs.e.write = hypfs_write_bool, \
          .hypfs.u.content = &(variable) }
#define integer_runtime_only_param(nam, variable) \
    __paramfs __parfs_##variable = \
        { .hypfs.e.type = XEN_HYPFS_TYPE_UINT, \
          .hypfs.e.encoding = XEN_HYPFS_ENC_PLAIN, \
          .hypfs.e.name = (nam), \
          .hypfs.e.size = sizeof(variable), \
          .hypfs.e.max_size = sizeof(variable), \
          .hypfs.e.read = hypfs_read_leaf, \
          .hypfs.e.write = hypfs_write_leaf, \
          .hypfs.u.content = &(variable) }
#define size_runtime_only_param(nam, variable) \
    __paramfs __parfs_##variable = \
        { .hypfs.e.type = XEN_HYPFS_TYPE_UINT, \
          .hypfs.e.encoding = XEN_HYPFS_ENC_PLAIN, \
          .hypfs.e.name = (nam), \
          .hypfs.e.size = sizeof(variable), \
          .hypfs.e.max_size = sizeof(variable), \
          .hypfs.e.read = hypfs_read_leaf, \
          .hypfs.e.write = hypfs_write_leaf, \
          .hypfs.u.content = &(variable) }
#define string_runtime_only_param(nam, variable) \
    __paramfs __parfs_##variable = \
        { .hypfs.e.type = XEN_HYPFS_TYPE_STRING, \
          .hypfs.e.encoding = XEN_HYPFS_ENC_PLAIN, \
          .hypfs.e.name = (nam), \
          .hypfs.e.size = 0, \
          .hypfs.e.max_size = sizeof(variable), \
          .hypfs.e.read = hypfs_read_leaf, \
          .hypfs.e.write = hypfs_write_leaf, \
          .hypfs.u.content = &(variable) }

#else

#define custom_runtime_only_param(nam, var, initfunc)
#define boolean_runtime_only_param(nam, var)
#define integer_runtime_only_param(nam, var)
#define size_runtime_only_param(nam, var)
#define string_runtime_only_param(nam, var)

#define custom_runtime_set_var(parfs, var)

#endif

#define custom_runtime_param(_name, _var, initfunc) \
    custom_param(_name, _var); \
    custom_runtime_only_param(_name, _var, initfunc)
#define boolean_runtime_param(_name, _var) \
    boolean_param(_name, _var); \
    boolean_runtime_only_param(_name, _var)
#define integer_runtime_param(_name, _var) \
    integer_param(_name, _var); \
    integer_runtime_only_param(_name, _var)
#define size_runtime_param(_name, _var) \
    size_param(_name, _var); \
    size_runtime_only_param(_name, _var)
#define string_runtime_param(_name, _var) \
    string_param(_name, _var); \
    string_runtime_only_param(_name, _var)

static inline void no_config_param(const char *cfg, const char *param,
                                   const char *s, const char *e)
{
    int len = e ? ({ ASSERT(e >= s); e - s; }) : strlen(s);

    printk(XENLOG_INFO "CONFIG_%s disabled - ignoring '%s=%*s' setting\n",
           cfg, param, len, s);
}

#endif /* _XEN_PARAM_H */
