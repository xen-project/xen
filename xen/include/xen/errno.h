#ifndef __XEN_ERRNO_H__
#define __XEN_ERRNO_H__

#include <public/errno.h>

#ifndef __ASSEMBLY__

#define XEN_ERRNO(name, value) name = XEN_##name,
enum {
#include <public/errno.h>
};

#else /* !__ASSEMBLY__ */

#define XEN_ERRNO(name, value) .equ name, XEN_##name
#include <public/errno.h>

#endif /* __ASSEMBLY__ */

#endif /*  __XEN_ERRNO_H__ */
