
#ifndef __X86_UACCESS_H__
#define __X86_UACCESS_H__

#ifdef __x86_64__
#include <asm/x86_64/uaccess.h>
#else
#include <asm/x86_32/uaccess.h>
#endif

/*
 * The exception table consists of pairs of addresses: the first is the
 * address of an instruction that is allowed to fault, and the second is
 * the address at which the program should continue.  No registers are
 * modified, so it is entirely up to the continuation code to figure out
 * what to do.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */

struct exception_table_entry
{
	unsigned long insn, fixup;
};

extern unsigned long search_exception_table(unsigned long);
extern void sort_exception_tables(void);

#endif /* __X86_UACCESS_H__ */
