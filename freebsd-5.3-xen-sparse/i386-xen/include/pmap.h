/*
 * Copyright (c) 1991 Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department and William Jolitz of UUNET Technologies Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Derived from hp300 version by Mike Hibler, this version by William
 * Jolitz uses a recursive map [a pde points to the page directory] to
 * map the page tables using the pagetables themselves. This is done to
 * reduce the impact on kernel virtual memory for lots of sparse address
 * space, and to reduce the cost of memory to each process.
 *
 *	from: hp300: @(#)pmap.h	7.2 (Berkeley) 12/16/90
 *	from: @(#)pmap.h	7.4 (Berkeley) 5/12/91
 * $FreeBSD: src/sys/i386/include/pmap.h,v 1.103 2003/11/08 03:01:26 alc Exp $
 */

#ifndef _MACHINE_PMAP_H_
#define	_MACHINE_PMAP_H_

/*
 * Page-directory and page-table entires follow this format, with a few
 * of the fields not present here and there, depending on a lot of things.
 */
				/* ---- Intel Nomenclature ---- */
#define	PG_V		0x001	/* P	Valid			*/
#define PG_RW		0x002	/* R/W	Read/Write		*/
#define PG_U		0x004	/* U/S  User/Supervisor		*/
#define	PG_NC_PWT	0x008	/* PWT	Write through		*/
#define	PG_NC_PCD	0x010	/* PCD	Cache disable		*/
#define PG_A		0x020	/* A	Accessed		*/
#define	PG_M		0x040	/* D	Dirty			*/
#define	PG_PS		0x080	/* PS	Page size (0=4k,1=4M)	*/
#define	PG_G		0x100	/* G	Global			*/
#define	PG_AVAIL1	0x200	/*    /	Available for system	*/
#define	PG_AVAIL2	0x400	/*   <	programmers use		*/
#define	PG_AVAIL3	0x800	/*    \				*/


/* Our various interpretations of the above */
#define PG_W		PG_AVAIL1	/* "Wired" pseudoflag */
#define	PG_MANAGED	PG_AVAIL2
#define	PG_FRAME	(~((vm_paddr_t)PAGE_MASK))
#define	PG_PROT		(PG_RW|PG_U)	/* all protection bits . */
#define PG_N		(PG_NC_PWT|PG_NC_PCD)	/* Non-cacheable */

#define PG_KERNEL         (PG_V | PG_RW | PG_M | PG_A)
#define PG_KERNEL_NC      (PG_KERNEL | PG_N)
#define PG_KERNEL_RO      (PG_VALID | PG_M | PG_A)

/*
 * Page Protection Exception bits
 */

#define PGEX_P		0x01	/* Protection violation vs. not present */
#define PGEX_W		0x02	/* during a Write cycle */
#define PGEX_U		0x04	/* access from User mode (UPL) */
#define XEN_PAGES       16

/*
 * Size of Kernel address space.  This is the number of page table pages
 * (4MB each) to use for the kernel.  256 pages == 1 Gigabyte.
 * This **MUST** be a multiple of 4 (eg: 252, 256, 260, etc).
 */

#ifndef KVA_PAGES
#ifdef PAE
#define KVA_PAGES	512 
#else
#define KVA_PAGES	256
#endif
#endif

/*
 * Pte related macros
 */
#define VADDR(pdi, pti) ((vm_offset_t)(((pdi)<<PDRSHIFT)|((pti)<<PAGE_SHIFT)))

#ifndef NKPT
#ifdef PAE
#define	NKPT		120	/* actual number of kernel page tables */
#else
#define	NKPT		30	/* actual number of kernel page tables */
#endif
#endif

/* 
 * XEN NOTE: Xen consumes 64MB of memory, so subtract that from the number 
 * of page available to the kernel virutal address space.
 */
#ifndef NKPDE
#ifdef SMP
#define NKPDE	(KVA_PAGES - 1 - XEN_PAGES) /* number of page tables/pde's */
#else
#define NKPDE	(KVA_PAGES - XEN_PAGES)	/* number of page tables/pde's */
#endif
#endif

/*
 * The *PTDI values control the layout of virtual memory
 *
 * XXX This works for now, but I am not real happy with it, I'll fix it
 * right after I fix locore.s and the magic 28K hole
 *
 * SMP_PRIVPAGES: The per-cpu address space is 0xff80000 -> 0xffbfffff
 */

/*
 * XEN NOTE: We need to shift down the start of KVA by 64MB to account for
 * Xen using the upper 64MB.  
 *
 * The layout of VA for XenoBSD is:
 * | 	USER 	|  PTDPTDI   |    KVA     |          XEN          |
 * | 0x00000000 | 0xbfc00000 | 0xc0000000 | 0xfc000000 - 0xffffffff|
 *
 * Normally it is just:
 * | 	USER 	|  PTDPTDI   |          KVA            |
 * | 0x00000000 | 0xbfc00000 | 0xc0000000 - 0xffffffff |
 */

#ifdef SMP
#define MPPTDI	(NPDEPTD-1)	  	  /* per cpu ptd entry */
#define	KPTDI 	(MPPTDI-NKPDE-XEN_PAGES	  /* start of kernel virtual pde's */
#else
#define	KPTDI	(NPDEPTD-NKPDE-XEN_PAGES) /* start of kernel virtual pde's */
#endif	/* SMP */

#define	PTDPTDI	(KPTDI-NPGPTD)	  	  /* ptd entry that points to ptd! */

/*
 * XXX doesn't really belong here I guess...
 */
#define ISA_HOLE_START    0xa0000
#define ISA_HOLE_LENGTH (0x100000-ISA_HOLE_START)

#ifndef LOCORE

#include <sys/queue.h>
#include <sys/_lock.h>
#include <sys/_mutex.h>


typedef uint32_t pd_entry_t;
typedef uint32_t pt_entry_t;

#define	PTESHIFT	(2)
#define	PDESHIFT	(2)


/*
 * Address of current and alternate address space page table maps
 * and directories.
 */
#ifdef _KERNEL
extern pt_entry_t PTmap[];
extern pd_entry_t PTD[];
extern pd_entry_t PTDpde[];

extern pd_entry_t *IdlePTD;	/* physical address of "Idle" state directory */

#include <machine/xen-os.h>
#include <machine/xenvar.h>
#include <machine/xenpmap.h>


/*
 * virtual address to page table entry and
 * to physical address. Likewise for alternate address space.
 * Note: these work recursively, thus vtopte of a pte will give
 * the corresponding pde that in turn maps it.
 */
#define	vtopte(va)	(PTmap + i386_btop(va))

/*
 * Given a virtual address, return the machine address of its PTE 
 *
 */
#define vtoptema(va) pmap_kextract_ma((vm_offset_t) vtopte(va))

/*
 *	Routine:	pmap_kextract/pmap_kextract_ma
 *	Function:
 *		Extract the physical/machine page address associated
 *		kernel virtual address.
 */

static __inline vm_paddr_t
pmap_kextract_ma(vm_offset_t va)
{
	vm_paddr_t ma;
	if ((ma = PTD[va >> PDRSHIFT]) & PG_PS) {
		ma = (ma & ~(NBPDR - 1)) | (va & (NBPDR - 1));
	} else {
		ma = (*vtopte(va) & PG_FRAME) | (va & PAGE_MASK);
	}
	return ma;
}

static __inline vm_paddr_t
pmap_kextract(vm_offset_t va)
{
	return xpmap_mtop(pmap_kextract_ma(va));
}

#define	vtophys(va)	pmap_kextract(((vm_offset_t) (va)))
#define vtomach(va)     pmap_kextract_ma(((vm_offset_t) (va)))

static __inline pt_entry_t
pte_load_clear(pt_entry_t *ptep)
{
	pt_entry_t r;

	r = PT_GET(ptep);
	PT_CLEAR_VA(ptep, TRUE);
	return (r);
}
static __inline pt_entry_t
pte_load_store(pt_entry_t *ptep, pt_entry_t v)
{
	pt_entry_t r;
	r = PT_GET(ptep);
	PT_SET_VA_MA(ptep, v, TRUE);
	return (r);
}

#define	pte_store(ptep, pte)	PT_SET_VA_MA(ptep, pte, TRUE);
#define pte_clear(pte)          PT_CLEAR_VA(pte, TRUE);


#endif /* _KERNEL */

/*
 * Pmap stuff
 */
struct	pv_entry;

struct md_page {
	int pv_list_count;
	TAILQ_HEAD(,pv_entry)	pv_list;
};

struct pmap {
	struct mtx               pm_mtx;
	pd_entry_t		*pm_pdir;	/* KVA of page directory */
	TAILQ_HEAD(,pv_entry)	pm_pvlist;	/* list of mappings in pmap */
	u_int			pm_active;	/* active on cpus */
	struct pmap_statistics	pm_stats;	/* pmap statistics */
	LIST_ENTRY(pmap) 	pm_list;	/* List of all pmaps */
};


typedef struct pmap	*pmap_t;

#ifdef _KERNEL
extern struct pmap	kernel_pmap_store;
#define kernel_pmap	(&kernel_pmap_store)

#define PMAP_LOCK(pmap)mtx_lock(&(pmap)->pm_mtx)
#define PMAP_LOCK_ASSERT(pmap, type) \
mtx_assert(&(pmap)->pm_mtx, (type))
#define PMAP_LOCK_DESTROY(pmap)mtx_destroy(&(pmap)->pm_mtx)
#define PMAP_LOCK_INIT(pmap)mtx_init(&(pmap)->pm_mtx, "pmap", \
    NULL, MTX_DEF | MTX_DUPOK)
#define PMAP_LOCKED(pmap)mtx_owned(&(pmap)->pm_mtx)
#define PMAP_MTX(pmap)(&(pmap)->pm_mtx)
#define PMAP_TRYLOCK(pmap)mtx_trylock(&(pmap)->pm_mtx)
#define PMAP_UNLOCK(pmap)mtx_unlock(&(pmap)->pm_mtx)

#endif

/*
 * For each vm_page_t, there is a list of all currently valid virtual
 * mappings of that page.  An entry is a pv_entry_t, the list is pv_table.
 */
typedef struct pv_entry {
	pmap_t		pv_pmap;	/* pmap where mapping lies */
	vm_offset_t	pv_va;		/* virtual address for mapping */
	TAILQ_ENTRY(pv_entry)	pv_list;
	TAILQ_ENTRY(pv_entry)	pv_plist;
} *pv_entry_t;

#ifdef	_KERNEL

#define NPPROVMTRR		8
#define PPRO_VMTRRphysBase0	0x200
#define PPRO_VMTRRphysMask0	0x201
struct ppro_vmtrr {
	u_int64_t base, mask;
};
extern struct ppro_vmtrr PPro_vmtrr[NPPROVMTRR];

extern caddr_t	CADDR1;
extern pt_entry_t *CMAP1;
extern vm_paddr_t avail_end;
extern vm_paddr_t phys_avail[];
extern int pseflag;
extern int pgeflag;
extern char *ptvmmap;		/* poor name! */
extern vm_offset_t virtual_avail;
extern vm_offset_t virtual_end;

#define pmap_page_is_mapped(m)(!TAILQ_EMPTY(&(m)->md.pv_list))

void	pmap_bootstrap(vm_paddr_t, vm_paddr_t);
void	pmap_kenter(vm_offset_t va, vm_paddr_t pa);
void	pmap_kenter_ma(vm_offset_t va, vm_paddr_t pa);
void   *pmap_kenter_temporary(vm_paddr_t pa, int i);
void	pmap_kremove(vm_offset_t);
void	*pmap_mapdev(vm_paddr_t, vm_size_t);
void	pmap_unmapdev(vm_offset_t, vm_size_t);
pt_entry_t *pmap_pte(pmap_t, vm_offset_t) __pure2;
void	pmap_set_pg(void);
void	pmap_invalidate_page(pmap_t, vm_offset_t);
void	pmap_invalidate_range(pmap_t, vm_offset_t, vm_offset_t);
void	pmap_invalidate_all(pmap_t);

void pmap_map_readonly(pmap_t pmap, vm_offset_t va, int len);
void pmap_map_readwrite(pmap_t pmap, vm_offset_t va, int len);


#endif /* _KERNEL */

#endif /* !LOCORE */

#endif /* !_MACHINE_PMAP_H_ */
