#ifndef __LINKAGE_H__
#define __LINKAGE_H__

#ifdef __ASSEMBLY__

#include <xen/macros.h>

#ifndef CODE_FILL
# define CODE_FILL ~0
#endif

#ifndef DATA_ALIGN
# define DATA_ALIGN 0
#endif
#ifndef DATA_FILL
# define DATA_FILL ~0
#endif

#define SYM_ALIGN(align...) .balign align

#define SYM_L_GLOBAL(name) .globl name; .hidden name
#define SYM_L_WEAK(name)   .weak name
#define SYM_L_LOCAL(name)  /* nothing */

#define SYM_T_FUNC         STT_FUNC
#define SYM_T_DATA         STT_OBJECT
#define SYM_T_NONE         STT_NOTYPE

#define SYM(name, typ, linkage, align...)         \
        .type name, SYM_T_ ## typ;                \
        SYM_L_ ## linkage(name);                  \
        SYM_ALIGN(align);                         \
        name:

#define END(name) .size name, . - name

/*
 * CODE_FILL in particular may need to expand to nothing (e.g. for RISC-V), in
 * which case we also need to get rid of the comma in the .balign directive.
 */
#define count_args_exp(args...) count_args(args)
#if count_args_exp(CODE_FILL)
# define DO_CODE_ALIGN(align...) LASTARG(CONFIG_FUNCTION_ALIGNMENT, ## align), \
                                 CODE_FILL
#else
# define DO_CODE_ALIGN(align...) LASTARG(CONFIG_FUNCTION_ALIGNMENT, ## align)
#endif

#define FUNC(name, align...) \
        SYM(name, FUNC, GLOBAL, DO_CODE_ALIGN(align))
#define LABEL(name, align...) \
        SYM(name, NONE, GLOBAL, DO_CODE_ALIGN(align))
#define DATA(name, align...) \
        SYM(name, DATA, GLOBAL, LASTARG(DATA_ALIGN, ## align), DATA_FILL)

#define FUNC_LOCAL(name, align...) \
        SYM(name, FUNC, LOCAL, DO_CODE_ALIGN(align))
#define LABEL_LOCAL(name, align...) \
        SYM(name, NONE, LOCAL, DO_CODE_ALIGN(align))
#define DATA_LOCAL(name, align...) \
        SYM(name, DATA, LOCAL, LASTARG(DATA_ALIGN, ## align), DATA_FILL)

#define ASM_INT(label, val)    DATA(label, 4) .long (val); END(label)

#endif /*  __ASSEMBLY__ */

#endif /* __LINKAGE_H__ */
