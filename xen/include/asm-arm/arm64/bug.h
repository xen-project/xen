#ifndef __ARM_ARM64_BUG_H__
#define __ARM_ARM64_BUG_H__

#include <xen/stringify.h>

#define BRK_BUG_FRAME 1

#define BUG_INSTR "brk " __stringify(BRK_BUG_FRAME)

#endif /* __ARM_ARM64_BUG_H__ */
