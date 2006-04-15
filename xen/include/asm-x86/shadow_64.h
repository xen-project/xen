/******************************************************************************
 * include/asm-x86/shadow_64.h
 * 
 * Copyright (c) 2005 Michael A Fetterman
 * Based on an earlier implementation by Ian Pratt et al
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
/*
 * Jun Nakajima <jun.nakajima@intel.com>
 * Chengyuan Li <chengyuan.li@intel.com>
 *
 * Extended to support 64-bit guests.
 */
#ifndef _XEN_SHADOW_64_H
#define _XEN_SHADOW_64_H
#include <asm/shadow.h>
#include <asm/shadow_ops.h>
#include <asm/hvm/hvm.h>

/*
 * The naming convention of the shadow_ops:
 * MODE_<pgentry size>_<guest paging levels>_HANDLER
 */
extern struct shadow_ops MODE_64_2_HANDLER;
extern struct shadow_ops MODE_64_3_HANDLER;
#if CONFIG_PAGING_LEVELS == 4
extern struct shadow_ops MODE_64_4_HANDLER;
extern struct shadow_ops MODE_64_PAE_HANDLER;
#endif

#if CONFIG_PAGING_LEVELS == 3
#define L4_PAGETABLE_SHIFT      39
#define L4_PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)
typedef struct { intpte_t l4; } l4_pgentry_t;
#define is_guest_l4_slot(_s) (1)
#endif

#define READ_FAULT  0
#define WRITE_FAULT 1

#define ERROR_P     1
#define ERROR_W     2
#define ERROR_U     4
#define ERROR_I     (1 << 4)

#define X86_64_SHADOW_DEBUG 0

#if X86_64_SHADOW_DEBUG
#define ESH_LOG(_f, _a...)              \
        printk(_f, ##_a)
#else
#define ESH_LOG(_f, _a...) ((void)0)
#endif

#define PAGING_L4      4UL
#define PAGING_L3      3UL
#define PAGING_L2      2UL
#define PAGING_L1      1UL
#define L_MASK  0xff

#define PAE_PAGING_LEVELS   3

#define ROOT_LEVEL_64   PAGING_L4
#define ROOT_LEVEL_32   PAGING_L2

#define DIRECT_ENTRY    (4UL << 16)
#define SHADOW_ENTRY    (2UL << 16)
#define GUEST_ENTRY     (1UL << 16)

#define GET_ENTRY   (2UL << 8)
#define SET_ENTRY   (1UL << 8)

#define PAGETABLE_ENTRIES    (1<<PAGETABLE_ORDER)

/* For 32-bit VMX guest to allocate shadow L1 & L2*/
#define SL1_ORDER   1
#define SL2_ORDER   2

typedef struct { intpte_t lo; } pgentry_64_t;
#define shadow_level_to_type(l)    (l << 29)
#define shadow_type_to_level(t)    (t >> 29)

#define entry_get_value(_x)         ((_x).lo)
#define entry_get_pfn(_x)           \
      (((_x).lo & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT)
#define entry_get_paddr(_x)          (((_x).lo & (PADDR_MASK&PAGE_MASK)))
#define entry_get_flags(_x)         (get_pte_flags((_x).lo))

#define entry_empty()           ((pgentry_64_t) { 0 })
#define entry_from_pfn(pfn, flags)  \
    ((pgentry_64_t) { ((intpte_t)(pfn) << PAGE_SHIFT) | put_pte_flags(flags) })
#define entry_from_page(page, flags) (entry_from_pfn(page_to_mfn(page),(flags)))
#define entry_add_flags(x, flags)    ((x).lo |= put_pte_flags(flags))
#define entry_remove_flags(x, flags) ((x).lo &= ~put_pte_flags(flags))
#define entry_has_changed(x,y,flags) \
        ( !!(((x).lo ^ (y).lo) & ((PADDR_MASK&PAGE_MASK)|put_pte_flags(flags))) )

#define PAE_SHADOW_SELF_ENTRY   259
#define PAE_L3_PAGETABLE_ENTRIES   4

/******************************************************************************/
/*
 * The macro and inlines are for 32-bit PAE guest on 64-bit host
 */
#define PAE_CR3_ALIGN       5
#define PAE_CR3_IDX_MASK    0x7f
#define PAE_CR3_IDX_NO      128

#define PAE_PDPT_RESERVED   0x1e6 /* [8:5], [2,1] */

/******************************************************************************/
static inline int  table_offset_64(unsigned long va, int level)
{
    switch(level) {
        case 1:
            return  (((va) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1));
        case 2:
            return  (((va) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1));
        case 3:
            return  (((va) >> L3_PAGETABLE_SHIFT) & (L3_PAGETABLE_ENTRIES - 1));
#if CONFIG_PAGING_LEVELS == 3
        case 4:
            return PAE_SHADOW_SELF_ENTRY;
#endif

#if CONFIG_PAGING_LEVELS >= 4
#ifndef GUEST_PGENTRY_32
#ifndef GUEST_32PAE
        case 4:
            return  (((va) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1));
#else
        case 4:
            return PAE_SHADOW_SELF_ENTRY;
#endif
#else
        case 4:
            return PAE_SHADOW_SELF_ENTRY; 
#endif
#endif
        default:
            return -1;
    }
}

/*****************************************************************************/

#if defined( GUEST_32PAE )
static inline int guest_table_offset_64(unsigned long va, int level, unsigned int index)
{
    switch(level) {
        case 1:
            return  (((va) >> L1_PAGETABLE_SHIFT) & (L1_PAGETABLE_ENTRIES - 1));
        case 2:
            return  (((va) >> L2_PAGETABLE_SHIFT) & (L2_PAGETABLE_ENTRIES - 1));
        case 3:
            return  (index * 4 + ((va) >> L3_PAGETABLE_SHIFT));
#if CONFIG_PAGING_LEVELS == 3
        case 4:
            return PAE_SHADOW_SELF_ENTRY;
#endif

#if CONFIG_PAGING_LEVELS >= 4
#ifndef GUEST_PGENTRY_32
        case 4:
            return  (((va) >> L4_PAGETABLE_SHIFT) & (L4_PAGETABLE_ENTRIES - 1));
#else
        case 4:
            return PAE_SHADOW_SELF_ENTRY;
#endif
#endif
        default:
            return -1;
    }
}

static inline unsigned long get_cr3_idxval(struct vcpu *v)
{
    unsigned long pae_cr3 = hvm_get_guest_ctrl_reg(v, 3); /* get CR3 */

    return (pae_cr3 >> PAE_CR3_ALIGN) & PAE_CR3_IDX_MASK;
}


#define SH_GUEST_32PAE 1
#else 
#define guest_table_offset_64(va, level, index) \
            table_offset_64((va),(level))
#define get_cr3_idxval(v) 0
#define SH_GUEST_32PAE 0
#endif

/********************************************************************************/

static inline void free_out_of_sync_state(struct domain *d)
{
    struct out_of_sync_entry *entry;

    // NB: Be careful not to call something that manipulates this list
    //     while walking it.  Remove one item at a time, and always
    //     restart from start of list.
    //
    while ( (entry = d->arch.out_of_sync) )
    {
        d->arch.out_of_sync = entry->next;
        release_out_of_sync_entry(d, entry);

        entry->next = d->arch.out_of_sync_free;
        d->arch.out_of_sync_free = entry;
    }
}

static inline int __entry(
    struct vcpu *v, unsigned long va, pgentry_64_t *e_p, u32 flag)
{
    int i;
    pgentry_64_t *le_e;
    pgentry_64_t *le_p = NULL;
    pgentry_64_t *phys_vtable = NULL;
    unsigned long mfn;
    int index;
    u32 level = flag & L_MASK;
    struct domain *d = v->domain;
    int root_level;
    unsigned int base_idx;

    base_idx = get_cr3_idxval(v);

    if ( flag & SHADOW_ENTRY )
    {
        root_level =  ROOT_LEVEL_64;
        index = table_offset_64(va, root_level);
        le_e = (pgentry_64_t *)&v->arch.shadow_vtable[index];
    }
    else if ( flag & GUEST_ENTRY )
    {
        root_level = v->domain->arch.ops->guest_paging_levels;
        if ( root_level == PAGING_L3 )
            index = guest_table_offset_64(va, PAGING_L3, base_idx);
        else
            index = guest_table_offset_64(va, root_level, base_idx);
        le_e = (pgentry_64_t *)&v->arch.guest_vtable[index];
    }
    else /* direct mode */
    {
        root_level = PAE_PAGING_LEVELS;
        index = table_offset_64(va, root_level);
        phys_vtable = (pgentry_64_t *)map_domain_page(
            pagetable_get_pfn(v->domain->arch.phys_table));
        le_e = &phys_vtable[index];
    }

    /*
     * If it's not external mode, then mfn should be machine physical.
     */
    for ( i = root_level - level; i > 0; i-- )
    {
        if ( unlikely(!(entry_get_flags(*le_e) & _PAGE_PRESENT)) )
        {
            if ( le_p )
                unmap_domain_page(le_p);

            if ( phys_vtable )
                unmap_domain_page(phys_vtable);

            return 0;
        }

        mfn = entry_get_pfn(*le_e);
        if ( (flag & GUEST_ENTRY) && shadow_mode_translate(d) )
            mfn = get_mfn_from_gpfn(mfn);

        if ( le_p )
            unmap_domain_page(le_p);
        le_p = (pgentry_64_t *)map_domain_page(mfn);

        if ( flag & SHADOW_ENTRY )
            index = table_offset_64(va, (level + i - 1));
        else
            index = guest_table_offset_64(va, (level + i - 1), base_idx);
        le_e = &le_p[index];
    }

    if ( flag & SET_ENTRY )
        *le_e = *e_p;
    else
        *e_p = *le_e;

    if ( le_p )
        unmap_domain_page(le_p);

    if ( phys_vtable )
        unmap_domain_page(phys_vtable);

    return 1;
}

static inline int __rw_entry(
    struct vcpu *v, unsigned long va, void *e_p, u32 flag)
{
    pgentry_64_t *e = (pgentry_64_t *)e_p;

    if (e) {
        return __entry(v, va, e, flag);
    }

    return 0;
}

#define __shadow_set_l4e(v, va, value) \
  __rw_entry(v, va, value, SHADOW_ENTRY | SET_ENTRY | PAGING_L4)
#define __shadow_get_l4e(v, va, sl4e) \
  __rw_entry(v, va, sl4e, SHADOW_ENTRY | GET_ENTRY | PAGING_L4)
#define __shadow_set_l3e(v, va, value) \
  __rw_entry(v, va, value, SHADOW_ENTRY | SET_ENTRY | PAGING_L3)
#define __shadow_get_l3e(v, va, sl3e) \
  __rw_entry(v, va, sl3e, SHADOW_ENTRY | GET_ENTRY | PAGING_L3)
#define __shadow_set_l2e(v, va, value) \
  __rw_entry(v, va, value, SHADOW_ENTRY | SET_ENTRY | PAGING_L2)
#define __shadow_get_l2e(v, va, sl2e) \
  __rw_entry(v, va, sl2e, SHADOW_ENTRY | GET_ENTRY | PAGING_L2)
#define __shadow_set_l1e(v, va, value) \
  __rw_entry(v, va, value, SHADOW_ENTRY | SET_ENTRY | PAGING_L1)
#define __shadow_get_l1e(v, va, sl1e) \
  __rw_entry(v, va, sl1e, SHADOW_ENTRY | GET_ENTRY | PAGING_L1)

#define __guest_set_l4e(v, va, value) \
  __rw_entry(v, va, value, GUEST_ENTRY | SET_ENTRY | PAGING_L4)
#define __guest_get_l4e(v, va, gl4e) \
  __rw_entry(v, va, gl4e, GUEST_ENTRY | GET_ENTRY | PAGING_L4)
#define __guest_set_l3e(v, va, value) \
  __rw_entry(v, va, value, GUEST_ENTRY | SET_ENTRY | PAGING_L3)
#define __guest_get_l3e(v, va, sl3e) \
  __rw_entry(v, va, gl3e, GUEST_ENTRY | GET_ENTRY | PAGING_L3)

#define __direct_set_l3e(v, va, value) \
  __rw_entry(v, va, value, DIRECT_ENTRY | SET_ENTRY | PAGING_L3)
#define __direct_get_l3e(v, va, sl3e) \
  __rw_entry(v, va, sl3e, DIRECT_ENTRY | GET_ENTRY | PAGING_L3)
#define __direct_set_l2e(v, va, value) \
  __rw_entry(v, va, value, DIRECT_ENTRY | SET_ENTRY | PAGING_L2)
#define __direct_get_l2e(v, va, sl2e) \
  __rw_entry(v, va, sl2e, DIRECT_ENTRY | GET_ENTRY | PAGING_L2)
#define __direct_set_l1e(v, va, value) \
  __rw_entry(v, va, value, DIRECT_ENTRY | SET_ENTRY | PAGING_L1)
#define __direct_get_l1e(v, va, sl1e) \
  __rw_entry(v, va, sl1e, DIRECT_ENTRY | GET_ENTRY | PAGING_L1)


static inline int  __guest_set_l2e(
    struct vcpu *v, unsigned long va, void *value, int size)
{
    switch(size) {
        case 4:
            // 32-bit guest
            {
                l2_pgentry_32_t *l2va;

                l2va = (l2_pgentry_32_t *)v->arch.guest_vtable;
                if (value)
                    l2va[l2_table_offset_32(va)] = *(l2_pgentry_32_t *)value;
                return 1;
            }
        case 8:
            return __rw_entry(v, va, value, GUEST_ENTRY | SET_ENTRY | PAGING_L2);
        default:
            BUG();
            return 0;
    }
    return 0;
}

#define __guest_set_l2e(v, va, value) \
    __guest_set_l2e(v, (unsigned long)va, value, sizeof(*value))

static inline int  __guest_get_l2e(
  struct vcpu *v, unsigned long va, void *gl2e, int size)
{
    switch(size) {
        case 4:
            // 32-bit guest
            {
                l2_pgentry_32_t *l2va;
                l2va = (l2_pgentry_32_t *)v->arch.guest_vtable;
                if (gl2e)
                    *(l2_pgentry_32_t *)gl2e = l2va[l2_table_offset_32(va)];
                return 1;
            }
        case 8:
            return __rw_entry(v, va, gl2e, GUEST_ENTRY | GET_ENTRY | PAGING_L2);
        default:
            BUG();
            return 0;
    }
    return 0;
}

#define __guest_get_l2e(v, va, gl2e) \
    __guest_get_l2e(v, (unsigned long)va, gl2e, sizeof(*gl2e))

static inline int  __guest_set_l1e(
  struct vcpu *v, unsigned long va, void *value, int size)
{
    switch(size) {
        case 4:
            // 32-bit guest
            {
                l2_pgentry_32_t gl2e;
                l1_pgentry_32_t *l1va;
                unsigned long l1mfn;

                if (!__guest_get_l2e(v, va, &gl2e))
                    return 0;
                if (unlikely(!(l2e_get_flags_32(gl2e) & _PAGE_PRESENT)))
                    return 0;

                l1mfn = get_mfn_from_gpfn(
                  l2e_get_pfn(gl2e));

                l1va = (l1_pgentry_32_t *)map_domain_page(l1mfn);
                if (value)
                    l1va[l1_table_offset_32(va)] = *(l1_pgentry_32_t *)value;
                unmap_domain_page(l1va);

                return 1;
            }

        case 8:
            return __rw_entry(v, va, value, GUEST_ENTRY | SET_ENTRY | PAGING_L1);
        default:
            BUG();
            return 0;
    }
    return 0;
}

#define __guest_set_l1e(v, va, value) \
     __guest_set_l1e(v, (unsigned long)va, value, sizeof(*value))

static inline int  __guest_get_l1e(
  struct vcpu *v, unsigned long va, void *gl1e, int size)
{
    switch(size) {
        case 4:
            // 32-bit guest
            {
                l2_pgentry_32_t gl2e;
                l1_pgentry_32_t *l1va;
                unsigned long l1mfn;

                if (!(__guest_get_l2e(v, va, &gl2e)))
                    return 0;


                if (unlikely(!(l2e_get_flags_32(gl2e) & _PAGE_PRESENT)))
                    return 0;


                l1mfn = get_mfn_from_gpfn(
                  l2e_get_pfn(gl2e));
                l1va = (l1_pgentry_32_t *) map_domain_page(l1mfn);
                if (gl1e)
                    *(l1_pgentry_32_t *)gl1e = l1va[l1_table_offset_32(va)];
                unmap_domain_page(l1va);
                return 1;
            }
        case 8:
            // 64-bit guest
            return __rw_entry(v, va, gl1e, GUEST_ENTRY | GET_ENTRY | PAGING_L1);
        default:
            BUG();
            return 0;
    }
    return 0;
}

#define __guest_get_l1e(v, va, gl1e) \
    __guest_get_l1e(v, (unsigned long)va, gl1e, sizeof(*gl1e))

static inline void entry_general(
  struct domain *d,
  pgentry_64_t *gle_p,
  pgentry_64_t *sle_p,
  unsigned long smfn, u32 level)

{
    pgentry_64_t gle = *gle_p;
    pgentry_64_t sle;

    sle = entry_empty();
    if ( (entry_get_flags(gle) & _PAGE_PRESENT) && (smfn != 0) )
    {
        if ((entry_get_flags(gle) & _PAGE_PSE) && level == PAGING_L2) {
            sle = entry_from_pfn(smfn, entry_get_flags(gle));
            entry_remove_flags(sle, _PAGE_PSE);

            if ( shadow_mode_log_dirty(d) ||
                 !(entry_get_flags(gle) & _PAGE_DIRTY) )
            {
                pgentry_64_t *l1_p;
                int i;

                l1_p =(pgentry_64_t *)map_domain_page(smfn);
                for (i = 0; i < L1_PAGETABLE_ENTRIES; i++)
                    entry_remove_flags(l1_p[i], _PAGE_RW);

                unmap_domain_page(l1_p);
            }
        } else {
            if (d->arch.ops->guest_paging_levels <= PAGING_L3
                    && level == PAGING_L3) {
                sle = entry_from_pfn(smfn, entry_get_flags(gle));
            } else {

                sle = entry_from_pfn(
                  smfn,
                  (entry_get_flags(gle) | _PAGE_RW | _PAGE_ACCESSED) & ~_PAGE_AVAIL);
                entry_add_flags(gle, _PAGE_ACCESSED);
            }
        }
        // XXX mafetter: Hmm...
        //     Shouldn't the dirty log be checked/updated here?
        //     Actually, it needs to be done in this function's callers.
        //
        *gle_p = gle;
    }

    if ( entry_get_value(sle) || entry_get_value(gle) )
        SH_VVLOG("%s: gpde=%lx, new spde=%lx", __func__,
          entry_get_value(gle), entry_get_value(sle));

    *sle_p = sle;
}

static inline void entry_propagate_from_guest(
  struct domain *d, pgentry_64_t *gle_p, pgentry_64_t *sle_p, u32 level)
{
    pgentry_64_t gle = *gle_p;
    unsigned long smfn = 0;

    if ( entry_get_flags(gle) & _PAGE_PRESENT ) {
        if ((entry_get_flags(gle) & _PAGE_PSE) && level == PAGING_L2) {
            smfn =  __shadow_status(d, entry_get_pfn(gle), PGT_fl1_shadow);
        } else {
            smfn =  __shadow_status(d, entry_get_pfn(gle), 
              shadow_level_to_type((level -1 )));
        }
    }
    entry_general(d, gle_p, sle_p, smfn, level);

}

static int inline
validate_entry_change(
  struct domain *d,
  pgentry_64_t *new_gle_p,
  pgentry_64_t *shadow_le_p,
  u32 level)
{
    pgentry_64_t old_sle, new_sle;
    pgentry_64_t new_gle = *new_gle_p;

    old_sle = *shadow_le_p;
    entry_propagate_from_guest(d, &new_gle, &new_sle, level);

    ESH_LOG("old_sle: %lx, new_gle: %lx, new_sle: %lx\n",
      entry_get_value(old_sle), entry_get_value(new_gle),
      entry_get_value(new_sle));

    if ( ((entry_get_value(old_sle) | entry_get_value(new_sle)) & _PAGE_PRESENT) &&
      entry_has_changed(old_sle, new_sle, _PAGE_PRESENT) )
    {
        perfc_incrc(validate_entry_changes);

        if ( (entry_get_flags(new_sle) & _PAGE_PRESENT) &&
          !get_shadow_ref(entry_get_pfn(new_sle)) )
            BUG();
        if ( entry_get_flags(old_sle) & _PAGE_PRESENT )
            put_shadow_ref(entry_get_pfn(old_sle));
    }

    *shadow_le_p = new_sle;

    return 1;
}

#endif


