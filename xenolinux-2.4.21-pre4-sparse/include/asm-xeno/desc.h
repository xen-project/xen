#ifndef __ARCH_DESC_H
#define __ARCH_DESC_H

#include <asm/ldt.h>

#define __LDT(_X)     (0)

#define clear_LDT()   ((void)0)
#define load_LDT(_mm) ((void)0)

#endif
