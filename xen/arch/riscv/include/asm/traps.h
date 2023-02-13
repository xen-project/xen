#ifndef __ASM_TRAPS_H__
#define __ASM_TRAPS_H__

#include <asm/processor.h>

#ifndef __ASSEMBLY__

void do_trap(struct cpu_user_regs *cpu_regs);
void handle_trap(void);

#endif /* __ASSEMBLY__ */

#endif /* __ASM_TRAPS_H__ */
