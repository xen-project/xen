#ifndef __ARM_ARM64_BUG_H__
#define __ARM_ARM64_BUG_H__

#include <xen/stringify.h>
#include <asm/arm64/brk.h>

#define BUG_INSTR "brk " __stringify(BRK_BUG_FRAME_IMM)

#endif /* __ARM_ARM64_BUG_H__ */
