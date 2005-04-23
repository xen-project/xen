/*
 *
 * Copyright (c) 2004 Christian Limpach.
 * Copyright (c) 2004,2005 Kip Macy
 * All rights reserved.
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
 *      This product includes software developed by Christian Limpach.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef _XEN_XENPMAP_H_
#define _XEN_XENPMAP_H_
#include <machine/xenvar.h>
void xen_invlpg(vm_offset_t);
void xen_queue_pt_update(vm_paddr_t, vm_paddr_t);
void xen_pt_switch(uint32_t);
void xen_set_ldt(unsigned long, unsigned long);
void xen_tlb_flush(void);
void xen_pgd_pin(unsigned long);
void xen_pgd_unpin(unsigned long);
void xen_pt_pin(unsigned long);
void xen_pt_unpin(unsigned long);
void xen_flush_queue(void);
void pmap_ref(pt_entry_t *pte, unsigned long ma);


#ifdef PMAP_DEBUG
#define PMAP_REF pmap_ref
#define PMAP_DEC_REF_PAGE pmap_dec_ref_page
#define PMAP_MARK_PRIV pmap_mark_privileged
#define PMAP_MARK_UNPRIV pmap_mark_unprivileged
#else 
#define PMAP_MARK_PRIV(a)
#define PMAP_MARK_UNPRIV(a)
#define PMAP_REF(a, b)
#define PMAP_DEC_REF_PAGE(a)
#endif

#define WRITABLE_PAGETABLES
#define ALWAYS_SYNC 0

#ifdef PT_DEBUG
#define PT_LOG() printk("WP PT_SET %s:%d\n", __FILE__, __LINE__) 
#else
#define PT_LOG()
#endif

#define pmap_valid_entry(E)           ((E) & PG_V) /* is PDE or PTE valid? */

#define SH_PD_SET_VA        1
#define SH_PD_SET_VA_MA     2
#define SH_PD_SET_VA_CLEAR  3

struct pmap;
void pd_set(struct pmap *pmap, vm_paddr_t *ptr, vm_paddr_t val, int type);

#define	PT_GET(_ptp)						\
	(pmap_valid_entry(*(_ptp)) ? xpmap_mtop(*(_ptp)) : *(_ptp))

#ifdef WRITABLE_PAGETABLES
#define PT_SET_VA(_ptp,_npte,sync) do {				\
        PMAP_REF((_ptp), xpmap_ptom(_npte));                    \
        PT_LOG();                                               \
        *(_ptp) = xpmap_ptom((_npte));                          \
} while (/*CONSTCOND*/0)
#define PT_SET_VA_MA(_ptp,_npte,sync) do {		        \
        PMAP_REF((_ptp), (_npte));                              \
        PT_LOG();                                               \
        *(_ptp) = (_npte);                                      \
} while (/*CONSTCOND*/0)
#define PT_CLEAR_VA(_ptp, sync) do {				\
        PMAP_REF((pt_entry_t *)(_ptp), 0);                      \
        PT_LOG();                                               \
        *(_ptp) = 0;                                            \
} while (/*CONSTCOND*/0)

#define PD_SET_VA(_pmap, _ptp, _npte, sync) do {			\
        PMAP_REF((_ptp), xpmap_ptom(_npte));                    \
        pd_set((_pmap),(_ptp),(_npte), SH_PD_SET_VA);           \
	if (sync || ALWAYS_SYNC) xen_flush_queue();     	\
} while (/*CONSTCOND*/0)
#define PD_SET_VA_MA(_pmap, _ptp, _npte, sync) do {		\
        PMAP_REF((_ptp), (_npte));                              \
        pd_set((_pmap),(_ptp),(_npte), SH_PD_SET_VA_MA);        \
	if (sync || ALWAYS_SYNC) xen_flush_queue();		\
} while (/*CONSTCOND*/0)
#define PD_CLEAR_VA(_pmap, _ptp, sync) do {			\
        PMAP_REF((pt_entry_t *)(_ptp), 0);                      \
        pd_set((_pmap),(_ptp), 0, SH_PD_SET_VA_CLEAR);     \
	if (sync || ALWAYS_SYNC) xen_flush_queue();		\
} while (/*CONSTCOND*/0)


#else /* !WRITABLE_PAGETABLES */

#define PT_SET_VA(_ptp,_npte,sync) do {				\
        PMAP_REF((_ptp), xpmap_ptom(_npte));                    \
	xen_queue_pt_update((pt_entry_t *)vtomach(_ptp), 	\
			    xpmap_ptom(_npte)); 		\
	if (sync || ALWAYS_SYNC) xen_flush_queue();		\
} while (/*CONSTCOND*/0)
#define PT_SET_VA_MA(_ptp,_npte,sync) do {		        \
        PMAP_REF((_ptp), (_npte));                              \
	xen_queue_pt_update((pt_entry_t *)vtomach(_ptp), _npte);\
	if (sync || ALWAYS_SYNC) xen_flush_queue();		\
} while (/*CONSTCOND*/0)
#define PT_CLEAR_VA(_ptp, sync) do {				\
        PMAP_REF((pt_entry_t *)(_ptp), 0);                      \
	xen_queue_pt_update((pt_entry_t *)vtomach(_ptp), 0);	\
	if (sync || ALWAYS_SYNC)				\
		xen_flush_queue();				\
} while (/*CONSTCOND*/0)

#define PD_SET_VA(_pmap, _ptp,_npte,sync) do {			\
        PMAP_REF((_ptp), xpmap_ptom(_npte));                    \
        pd_set((_pmap),(_ptp),(_npte), SH_PD_SET_VA);           \
	if (sync || ALWAYS_SYNC) xen_flush_queue();     	\
} while (/*CONSTCOND*/0)
#define PD_SET_VA_MA(_pmap, _ptp,_npte,sync) do {		\
        PMAP_REF((_ptp), (_npte));                              \
        pd_set((_pmap),(_ptp),(_npte), SH_PD_SET_VA_MA);        \
	if (sync || ALWAYS_SYNC) xen_flush_queue();		\
} while (/*CONSTCOND*/0)
#define PD_CLEAR_VA(_pmap, _ptp, sync) do {			\
        PMAP_REF((pt_entry_t *)(_ptp), 0);                      \
        pd_set((_pmap),(_ptp), 0, SH_PD_SET_VA_CLEAR);          \
	if (sync || ALWAYS_SYNC) xen_flush_queue();		\
} while (/*CONSTCOND*/0)

#endif

#define PT_SET_MA(_va, _ma) \
   HYPERVISOR_update_va_mapping(((unsigned long)_va),  \
                                ((unsigned long)_ma), \
                                UVMF_INVLPG| UVMF_LOCAL)\

#define	PT_UPDATES_FLUSH() do {				        \
        xen_flush_queue();                                      \
} while (/*CONSTCOND*/0)


static __inline uint32_t
xpmap_mtop(uint32_t mpa)
{
    return (((xen_machine_phys[(mpa >> PAGE_SHIFT)]) << PAGE_SHIFT) 
		| (mpa & ~PG_FRAME));
}

static __inline vm_paddr_t
xpmap_ptom(uint32_t ppa)
{
    return phystomach(ppa) | (ppa & ~PG_FRAME);
}

#endif /* _XEN_XENPMAP_H_ */
