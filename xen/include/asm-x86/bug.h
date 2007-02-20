#ifndef __X86_BUG_H__
#define __X86_BUG_H__

#ifdef __x86_64__
#include <asm/x86_64/bug.h>
#else
#include <asm/x86_32/bug.h>
#endif

#define BUG()                  __BUG(__FILE__, __LINE__)
#define dump_execution_state() __BUG(__FILE__, __LINE__ | 0x8000)

#endif /* __X86_BUG_H__ */
