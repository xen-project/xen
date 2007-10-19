/******************************************************************************
 * Arch-specific sysctl.c
 * 
 * System management operations. For use by node control stack.
 * 
 * Copyright (c) 2002-2006, K Fraser
 */

#include <xen/config.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>
#include <xen/sched.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <asm/irq.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/processor.h>
#include <asm/numa.h>
#include <xen/nodemask.h>
#include <xsm/xsm.h>

#define get_xen_guest_handle(val, hnd)  do { val = (hnd).p; } while (0)

long arch_do_sysctl(
    struct xen_sysctl *sysctl, XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl)
{
    long ret = 0;

    switch ( sysctl->cmd )
    {

    case XEN_SYSCTL_physinfo:
    {
        uint32_t i, max_array_ent;

        xen_sysctl_physinfo_t *pi = &sysctl->u.physinfo;

        ret = xsm_physinfo();
        if ( ret )
            break;

        pi->threads_per_core =
            cpus_weight(cpu_sibling_map[0]);
        pi->cores_per_socket =
            cpus_weight(cpu_core_map[0]) / pi->threads_per_core;
        pi->nr_cpus = (u32)num_online_cpus();
        pi->nr_nodes = num_online_nodes();
        pi->total_pages      = total_pages;
        pi->free_pages       = avail_domheap_pages();
        pi->scrub_pages      = avail_scrub_pages();
        pi->cpu_khz          = cpu_khz;
        memset(pi->hw_cap, 0, sizeof(pi->hw_cap));
        memcpy(pi->hw_cap, boot_cpu_data.x86_capability, NCAPINTS*4);

        max_array_ent = pi->max_cpu_id;
        pi->max_cpu_id = last_cpu(cpu_online_map);
        max_array_ent = min_t(uint32_t, max_array_ent, pi->max_cpu_id);

        ret = -EFAULT;
        if ( !guest_handle_is_null(pi->cpu_to_node) )
        {
            for ( i = 0; i <= max_array_ent; i++ )
            {
                uint32_t node = cpu_online(i) ? cpu_to_node(i) : ~0u;
                if ( copy_to_guest_offset(pi->cpu_to_node, i, &node, 1) )
                    break;
            }
        }

        ret = copy_to_guest(u_sysctl, sysctl, 1) ? -EFAULT : 0;
    }
    break;
    

    default:
        ret = -ENOSYS;
        break;
    }

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
