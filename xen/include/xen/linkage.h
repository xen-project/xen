#ifndef __LINKAGE_H__
#define __LINKAGE_H__

#ifdef __ASSEMBLY__

#include <xen/macros.h>

/* CODE_ALIGN needs to be specified by every architecture. */
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

#define FUNC(name, align...) \
        SYM(name, FUNC, GLOBAL, LASTARG(CODE_ALIGN, ## align), CODE_FILL)
#define LABEL(name, align...) \
        SYM(name, NONE, GLOBAL, LASTARG(CODE_ALIGN, ## align), CODE_FILL)
#define DATA(name, align...) \
        SYM(name, DATA, GLOBAL, LASTARG(DATA_ALIGN, ## align), DATA_FILL)

#define FUNC_LOCAL(name, align...) \
        SYM(name, FUNC, LOCAL, LASTARG(CODE_ALIGN, ## align), CODE_FILL)
#define LABEL_LOCAL(name, align...) \
        SYM(name, NONE, LOCAL, LASTARG(CODE_ALIGN, ## align), CODE_FILL)
#define DATA_LOCAL(name, align...) \
        SYM(name, DATA, LOCAL, LASTARG(DATA_ALIGN, ## align), DATA_FILL)

#endif /*  __ASSEMBLY__ */

#endif /* __LINKAGE_H__ */
