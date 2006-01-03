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
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <asm/shadow.h>
#include <asm/irq.h>
#include <asm/processor.h>
#include <public/sched_ctl.h>

#include <asm/mtrr.h>
#include "mtrr/mtrr.h"

#define TRC_DOM0OP_ENTER_BASE  0x00020000
#define TRC_DOM0OP_LEAVE_BASE  0x00030000

static int msr_cpu_mask;
static unsigned long msr_addr;
static unsigned long msr_lo;
static unsigned long msr_hi;

static void write_msr_for(void *unused)
{
    if ( ((1 << current->processor) & msr_cpu_mask) )
        (void)wrmsr_user(msr_addr, msr_lo, msr_hi);
}

static void read_msr_for(void *unused)
{
    if ( ((1 << current->processor) & msr_cpu_mask) )
        (void)rdmsr_user(msr_addr, msr_lo, msr_hi);
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

    case DOM0_IOPORT_PERMISSION:
    {
        struct domain *d;
        unsigned int fp = op->u.ioport_permission.first_port;
        unsigned int np = op->u.ioport_permission.nr_ports;

        ret = -EINVAL;
        if ( (fp + np) > 65536 )
            break;

        ret = -ESRCH;
        if ( unlikely((d = find_domain_by_id(
            op->u.ioport_permission.domain)) == NULL) )
            break;

        if ( np == 0 )
            ret = 0;
        else if ( op->u.ioport_permission.allow_access )
            ret = ioports_permit_access(d, fp, fp + np - 1);
        else
            ret = ioports_deny_access(d, fp, fp + np - 1);

        put_domain(d);
    }
    break;

    case DOM0_PHYSINFO:
    {
        dom0_physinfo_t *pi = &op->u.physinfo;

        pi->threads_per_core = smp_num_siblings;
        pi->cores_per_socket = boot_cpu_data.x86_num_cores;
        pi->sockets_per_node = 
            num_online_cpus() / (pi->threads_per_core * pi->cores_per_socket);
        pi->nr_nodes         = 1;
        pi->total_pages      = total_pages;
        pi->free_pages       = avail_domheap_pages();
        pi->cpu_khz          = cpu_khz;
        memset(pi->hw_cap, 0, sizeof(pi->hw_cap));
        memcpy(pi->hw_cap, boot_cpu_data.x86_capability, NCAPINTS*4);
        ret = 0;
        if ( copy_to_user(u_dom0_op, op, sizeof(*op)) )
	    ret = -EFAULT;
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

        page = pfn_to_page(pfn);

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
#define GPF2_BATCH (PAGE_SIZE / sizeof(unsigned long)) 
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
            put_domain(d);
            break;
        }

        l_arr = alloc_xenheap_page();
 
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

                page = pfn_to_page(mfn);

                if ( likely(pfn_valid(mfn) && get_page(page, d)) ) 
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
                    l_arr[j] |= XTAB;

            }

            if ( copy_to_user(&s_ptr[n], l_arr, k*sizeof(unsigned long)) )
            {
                ret = -EINVAL;
                break;
            }

            n += k;
        }

        free_xenheap_page(l_arr);

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
                pfn = page_to_pfn(list_entry(list_ent, struct pfn_info, list));
                if ( put_user(pfn, buffer) )
                {
                    ret = -EFAULT;
                    break;
                }
                buffer++;
                list_ent = pfn_to_page(pfn)->list.next;
            }
            spin_unlock(&d->page_alloc_lock);

            op->u.getmemlist.num_pfns = i;
            copy_to_user(u_dom0_op, op, sizeof(*op));
            
            put_domain(d);
        }
    }
    break;

    case DOM0_PLATFORM_QUIRK:
    {
        extern int opt_noirqbalance;
        switch ( op->u.platform_quirk.quirk_id )
        {
        case QUIRK_NOIRQBALANCING:
            printk("Platform quirk -- Disabling IRQ balancing/affinity.\n");
            opt_noirqbalance = 1;
            setup_ioapic_dest();
            break;
        default:
            ret = -EINVAL;
            break;
        }
    }
    break;

    case DOM0_PHYSICAL_MEMORY_MAP:
    {
        struct dom0_memory_map_entry entry;
        int i;

        for ( i = 0; i < e820.nr_map; i++ )
        {
            if ( i >= op->u.physical_memory_map.max_map_entries )
                break;
            entry.start  = e820.map[i].addr;
            entry.end    = e820.map[i].addr + e820.map[i].size;
            entry.is_ram = (e820.map[i].type == E820_RAM);
            (void)copy_to_user(
                &op->u.physical_memory_map.memory_map[i],
                &entry, sizeof(entry));
        }

        op->u.physical_memory_map.nr_map_entries = i;
        (void)copy_to_user(u_dom0_op, op, sizeof(*op));
    }
    break;

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

void arch_getdomaininfo_ctxt(
    struct vcpu *v, struct vcpu_guest_context *c)
{
    extern void save_vmx_cpu_user_regs(struct cpu_user_regs *);

    memcpy(c, &v->arch.guest_context, sizeof(*c));

    if ( VMX_DOMAIN(v) )
    {
        save_vmx_cpu_user_regs(&c->user_regs);
        __vmread(CR0_READ_SHADOW, &c->ctrlreg[0]);
        __vmread(CR4_READ_SHADOW, &c->ctrlreg[4]);
    }
    else
    {
        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c->user_regs.eflags & EF_IOPL) != 0);
        c->user_regs.eflags |= v->arch.iopl << 12;
    }

    c->flags = 0;
    if ( test_bit(_VCPUF_fpu_initialised, &v->vcpu_flags) )
        c->flags |= VGCF_I387_VALID;
    if ( KERNEL_MODE(v, &v->arch.guest_context.user_regs) )
        c->flags |= VGCF_IN_KERNEL;
    if (VMX_DOMAIN(v))
        c->flags |= VGCF_VMX_GUEST;

    c->ctrlreg[3] = pagetable_get_paddr(v->arch.guest_table);

    c->vm_assist = v->domain->vm_assist;
}
