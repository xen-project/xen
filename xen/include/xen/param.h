#ifndef _XEN_PARAM_H
#define _XEN_PARAM_H

#include <xen/init.h>

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

extern const struct kernel_param __setup_start[], __setup_end[];
extern const struct kernel_param __param_start[], __param_end[];

#define __dataparam       __used_section(".data.param")

#define __param(att)      static const att \
    __attribute__((__aligned__(sizeof(void *)))) struct kernel_param

#define __setup_str static const __initconst \
    __attribute__((__aligned__(1))) char
#define __kparam          __param(__initsetup)

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
          .len = sizeof(_var), \
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
    __setup_str setup_str_ign[] = _name;    \
    __kparam setup_ign =                    \
        { .name = setup_str_ign,            \
          .type = OPT_IGNORE }

#define __rtparam         __param(__dataparam)

#define custom_runtime_only_param(_name, _var) \
    __rtparam __rtpar_##_var = \
      { .name = _name, \
          .type = OPT_CUSTOM, \
          .par.func = _var }
#define boolean_runtime_only_param(_name, _var) \
    __rtparam __rtpar_##_var = \
        { .name = _name, \
          .type = OPT_BOOL, \
          .len = sizeof(_var), \
          .par.var = &_var }
#define integer_runtime_only_param(_name, _var) \
    __rtparam __rtpar_##_var = \
        { .name = _name, \
          .type = OPT_UINT, \
          .len = sizeof(_var), \
          .par.var = &_var }
#define size_runtime_only_param(_name, _var) \
    __rtparam __rtpar_##_var = \
        { .name = _name, \
          .type = OPT_SIZE, \
          .len = sizeof(_var), \
          .par.var = &_var }
#define string_runtime_only_param(_name, _var) \
    __rtparam __rtpar_##_var = \
        { .name = _name, \
          .type = OPT_STR, \
          .len = sizeof(_var), \
          .par.var = &_var }

#define custom_runtime_param(_name, _var) \
    custom_param(_name, _var); \
    custom_runtime_only_param(_name, _var)
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

#endif /* _XEN_PARAM_H */
