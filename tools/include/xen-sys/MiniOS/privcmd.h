#ifndef __MINIOS_PUBLIC_PRIVCMD_H__
#define __MINIOS_PUBLIC_PRIVCMD_H__

#include <sys/types.h>

typedef struct privcmd_hypercall
{
	u64 op;
	u64 arg[5];
} privcmd_hypercall_t;

typedef struct privcmd_mmap_entry {
	u64 va;
	u64 mfn;
	u64 npages;
} privcmd_mmap_entry_t; 

#endif /* __MINIOS_PUBLIC_PRIVCMD_H__ */
