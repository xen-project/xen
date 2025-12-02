#ifndef __XEN_ERRNO_H__
#define __XEN_ERRNO_H__

#ifndef __ASSEMBLER__

#define XEN_ERRNO(name, value) name = (value),
enum {
#include <public/errno.h>
};

#else /* !__ASSEMBLER__ */

#define XEN_ERRNO(name, value) .equ name, value
#include <public/errno.h>

#endif /* __ASSEMBLER__ */

#endif /*  __XEN_ERRNO_H__ */
