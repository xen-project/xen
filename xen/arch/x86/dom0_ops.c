/******************************************************************************
 * Arch-specific dom0_ops.c
 * 
 * Process command requests from domain-0 guest OS.
 * 
 * Copyright (c) 2002, K A Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <public/dom0_ops.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <asm/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <asm/shadow.h>
#include <public/sched_ctl.h>

#include <asm/mtrr.h>
#include "mtrr/mtrr.h"

#define TRC_DOM0OP_ENTER_BASE  0x00020000
#define TRC_DOM0OP_LEAVE_BASE  0x00030000

extern unsigned int alloc_new_dom_mem(struct domain *, unsigned int);

static int msr_cpu_mask;
static unsigned long msr_addr;
static unsigned long msr_lo;
static unsigned long msr_hi;

static void write_msr_for(void *unused)
{
    if (((1 << current->processor) & msr_cpu_mask))
        wrmsr(msr_addr, msr_lo, msr_hi);
}

static void read_msr_for(void *unused)
{
    if (((1 << current->processor) & msr_cpu_mask))
        rdmsr(msr_addr, msr_lo, msr_hi);
}

long arch_do_dom0_op(dom0_op_t *op, dom0_op_t *u_dom0_op)
{
    long ret = 0;

    if ( !IS_PRIV(current->domain) )
        return -EPERM;

    switch ( op->cmd )
    {

    case DOM0_MSR:
    {
        if ( op->u.msr.write )
        {
            msr_cpu_mask = op->u.msr.cpu_mask;
            msr_addr = op->u.msr.msr;
            msr_lo = op->u.msr.in1;
            msr_hi = op->u.msr.in2;
            smp_call_function(write_msr_for, NULL, 1, 1);
            write_msr_for(NULL);
        }
        else
        {
            msr_cpu_mask = op->u.msr.cpu_mask;
            msr_addr = op->u.msr.msr;
            smp_call_function(read_msr_for, NULL, 1, 1);
            read_msr_for(NULL);

            op->u.msr.out1 = msr_lo;
            op->u.msr.out2 = msr_hi;
            copy_to_user(u_dom0_op, op, sizeof(*op));
        }
        ret = 0;
    }
    break;

    case DOM0_SHADOW_CONTROL:
    {
        struct domain *d; 
        ret = -ESRCH;
        d = find_domain_by_id(op->u.shadow_control.domain);
        if ( d != NULL )
        {
            ret = shadow_mode_control(d, &op->u.shadow_control);
            put_domain(d);
            copy_to_user(u_dom0_op, op, sizeof(*op));
        } 
    }
    break;

    case DOM0_ADD_MEMTYPE:
    {
        ret = mtrr_add_page(
            op->u.add_memtype.pfn,
            op->u.add_memtype.nr_pfns,
            op->u.add_memtype.type,
            1);
    }
    break;

    case DOM0_DEL_MEMTYPE:
    {
        ret = mtrr_del_page(op->u.del_memtype.reg, 0, 0);
    }
    break;

    case DOM0_READ_MEMTYPE:
    {
        unsigned long pfn;
        unsigned int  nr_pfns;
        mtrr_type     type;

        ret = -EINVAL;
        if ( op->u.read_memtype.reg < num_var_ranges )
        {
            mtrr_if->get(op->u.read_memtype.reg, &pfn, &nr_pfns, &type);
            (void)__put_user(pfn, &u_dom0_op->u.read_memtype.pfn);
            (void)__put_user(nr_pfns, &u_dom0_op->u.read_memtype.nr_pfns);
            (void)__put_user(type, &u_dom0_op->u.read_memtype.type);
            ret = 0;
        }
    }
    break;

    case DOM0_MICROCODE:
    {
        extern int microcode_update(void *buf, unsigned long len);
        ret = microcode_update(op->u.microcode.data, op->u.microcode.length);
    }
    break;

    case DOM0_IOPL:
    {
        extern long do_iopl(domid_t, unsigned int);
        ret = do_iopl(op->u.iopl.domain, op->u.iopl.iopl);
    }
    break;

    case DOM0_PHYSINFO:
    {
        dom0_physinfo_t *pi = &op->u.physinfo;

        pi->ht_per_core = opt_noht ? 1 : ht_per_core;
        pi->cores       = smp_num_cpus / pi->ht_per_core;
        pi->total_pages = max_page;
        pi->free_pages  = avail_domheap_pages();
        pi->cpu_khz     = cpu_khz;

        copy_to_user(u_dom0_op, op, sizeof(*op));
        ret = 0;
    }
    break;
    
    case DOM0_GETPAGEFRAMEINFO:
    {
        struct pfn_info *page;
        unsigned long pfn = op->u.getpageframeinfo.pfn;
        domid_t dom = op->u.getpageframeinfo.domain;
        struct domain *d;

        ret = -EINVAL;

        if ( unlikely(pfn >= max_page) || 
             unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        page = &frame_table[pfn];

        if ( likely(get_page(page, d)) )
        {
            ret = 0;

            op->u.getpageframeinfo.type = NOTAB;

            if ( (page->u.inuse.type_info & PGT_count_mask) != 0 )
            {
                switch ( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                    op->u.getpageframeinfo.type = L1TAB;
                    break;
                case PGT_l2_page_table:
                    op->u.getpageframeinfo.type = L2TAB;
                    break;
                case PGT_l3_page_table:
                    op->u.getpageframeinfo.type = L3TAB;
                    break;
                case PGT_l4_page_table:
                    op->u.getpageframeinfo.type = L4TAB;
                    break;
                }
            }
            
            put_page(page);
        }

        put_domain(d);

        copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    case DOM0_GETPAGEFRAMEINFO2:
    {
#define GPF2_BATCH 128
        int n,j;
        int num = op->u.getpageframeinfo2.num;
        domid_t dom = op->u.getpageframeinfo2.domain;
        unsigned long *s_ptr = (unsigned long*) op->u.getpageframeinfo2.array;
        struct domain *d;
        unsigned long *l_arr;
        ret = -ESRCH;

        if ( unlikely((d = find_domain_by_id(dom)) == NULL) )
            break;

        if ( unlikely(num > 1024) )
        {
            ret = -E2BIG;
            break;
        }

        l_arr = (unsigned long *)alloc_xenheap_page();
 
        ret = 0;
        for( n = 0; n < num; )
        {
            int k = ((num-n)>GPF2_BATCH)?GPF2_BATCH:(num-n);

            if ( copy_from_user(l_arr, &s_ptr[n], k*sizeof(unsigned long)) )
            {
                ret = -EINVAL;
                break;
            }
     
            for( j = 0; j < k; j++ )
            {      
                struct pfn_info *page;
                unsigned long mfn = l_arr[j];

                if ( unlikely(mfn >= max_page) )
                    goto e2_err;

                page = &frame_table[mfn];
  
                if ( likely(get_page(page, d)) )
                {
                    unsigned long type = 0;

                    switch( page->u.inuse.type_info & PGT_type_mask )
                    {
                    case PGT_l1_page_table:
                        type = L1TAB;
                        break;
                    case PGT_l2_page_table:
                        type = L2TAB;
                        break;
                    case PGT_l3_page_table:
                        type = L3TAB;
                        break;
                    case PGT_l4_page_table:
                        type = L4TAB;
                        break;
                    }

                    if ( page->u.inuse.type_info & PGT_pinned )
                        type |= LPINTAB;
                    l_arr[j] |= type;
                    put_page(page);
                }
                else
                {
                e2_err:
                    l_arr[j] |= XTAB;
                }

            }

            if ( copy_to_user(&s_ptr[n], l_arr, k*sizeof(unsigned long)) )
            {
                ret = -EINVAL;
                break;
            }

            n += j;
        }

        free_xenheap_page((unsigned long)l_arr);

        put_domain(d);
    }
    break;

    case DOM0_GETMEMLIST:
    {
        int i;
        struct domain *d = find_domain_by_id(op->u.getmemlist.domain);
        unsigned long max_pfns = op->u.getmemlist.max_pfns;
        unsigned long pfn;
        unsigned long *buffer = op->u.getmemlist.buffer;
        struct list_head *list_ent;

        ret = -EINVAL;
        if ( d != NULL )
        {
            ret = 0;

            spin_lock(&d->page_alloc_lock);
            list_ent = d->page_list.next;
            for ( i = 0; (i < max_pfns) && (list_ent != &d->page_list); i++ )
            {
                pfn = list_entry(list_ent, struct pfn_info, list) - 
                    frame_table;
                if ( put_user(pfn, buffer) )
                {
                    ret = -EFAULT;
                    break;
                }
                buffer++;
                list_ent = frame_table[pfn].list.next;
            }
            spin_unlock(&d->page_alloc_lock);

            op->u.getmemlist.num_pfns = i;
            copy_to_user(u_dom0_op, op, sizeof(*op));
            
            put_domain(d);
        }
    }
    break;

    default:
        ret = -ENOSYS;

    }

    return ret;
}

void arch_getdomaininfo_ctxt(
    struct exec_domain *ed, full_execution_context_t *c)
{ 
    int i;

    c->flags = 0;
    memcpy(&c->cpu_ctxt, 
           &ed->arch.user_ctxt,
           sizeof(ed->arch.user_ctxt));
    if ( test_bit(EDF_DONEFPUINIT, &ed->ed_flags) )
        c->flags |= ECF_I387_VALID;
    memcpy(&c->fpu_ctxt,
           &ed->arch.i387,
           sizeof(ed->arch.i387));
    memcpy(&c->trap_ctxt,
           ed->arch.traps,
           sizeof(ed->arch.traps));
#ifdef ARCH_HAS_FAST_TRAP
    if ( (ed->arch.fast_trap_desc.a == 0) &&
         (ed->arch.fast_trap_desc.b == 0) )
        c->fast_trap_idx = 0;
    else
        c->fast_trap_idx = 
            ed->arch.fast_trap_idx;
#endif
    c->ldt_base = ed->arch.ldt_base;
    c->ldt_ents = ed->arch.ldt_ents;
    c->gdt_ents = 0;
    if ( GET_GDT_ADDRESS(ed) == GDT_VIRT_START(ed) )
    {
        for ( i = 0; i < 16; i++ )
            c->gdt_frames[i] = 
                l1_pgentry_to_pfn(ed->arch.perdomain_ptes[i]);
        c->gdt_ents = GET_GDT_ENTRIES(ed);
    }
    c->guestos_ss  = ed->arch.guestos_ss;
    c->guestos_esp = ed->arch.guestos_sp;
    c->pt_base   = 
        pagetable_val(ed->arch.pagetable);
    memcpy(c->debugreg, 
           ed->arch.debugreg, 
           sizeof(ed->arch.debugreg));
    c->event_callback_cs     = ed->arch.event_selector;
    c->event_callback_eip    = ed->arch.event_address;
    c->failsafe_callback_cs  = ed->arch.failsafe_selector;
    c->failsafe_callback_eip = ed->arch.failsafe_address;
}
