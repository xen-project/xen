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

static long cpu_down_helper(void *data)
{
    int cpu = (unsigned long)data;
    return cpu_down(cpu);
}

extern int __node_distance(int a, int b);

long arch_do_sysctl(
    struct xen_sysctl *sysctl, XEN_GUEST_HANDLE(xen_sysctl_t) u_sysctl)
{
    long ret = 0, status;

    switch ( sysctl->cmd )
    {

    case XEN_SYSCTL_physinfo:
    {
        xen_sysctl_physinfo_t *pi = &sysctl->u.physinfo;

        ret = xsm_physinfo();
        if ( ret )
            break;


        memset(pi, 0, sizeof(*pi));
        pi->threads_per_core =
            cpus_weight(per_cpu(cpu_sibling_map, 0));
        pi->cores_per_socket =
            cpus_weight(per_cpu(cpu_core_map, 0)) / pi->threads_per_core;
        pi->nr_cpus = num_online_cpus();
        pi->nr_nodes = num_online_nodes();
        pi->max_node_id = last_node(node_online_map);
        pi->max_cpu_id = last_cpu(cpu_online_map);
        pi->total_pages = total_pages;
        pi->free_pages = avail_domheap_pages();
        pi->scrub_pages = 0;
        pi->cpu_khz = cpu_khz;
        memcpy(pi->hw_cap, boot_cpu_data.x86_capability, NCAPINTS*4);
        if ( hvm_enabled )
            pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm;
        if ( iommu_enabled )
            pi->capabilities |= XEN_SYSCTL_PHYSCAP_hvm_directio;

        if ( copy_to_guest(u_sysctl, sysctl, 1) )
            ret = -EFAULT;
    }
    break;
        
    case XEN_SYSCTL_topologyinfo:
    {
        uint32_t i, max_cpu_index, last_online_cpu;
        xen_sysctl_topologyinfo_t *ti = &sysctl->u.topologyinfo;

        last_online_cpu = last_cpu(cpu_online_map);
        max_cpu_index = min_t(uint32_t, ti->max_cpu_index, last_online_cpu);
        ti->max_cpu_index = last_online_cpu;

        for ( i = 0; i <= max_cpu_index; i++ )
        {
            if ( !guest_handle_is_null(ti->cpu_to_core) )
            {
                uint32_t core = cpu_online(i) ? cpu_to_core(i) : ~0u;
                if ( copy_to_guest_offset(ti->cpu_to_core, i, &core, 1) )
                    break;
            }
            if ( !guest_handle_is_null(ti->cpu_to_socket) )
            {
                uint32_t socket = cpu_online(i) ? cpu_to_socket(i) : ~0u;
                if ( copy_to_guest_offset(ti->cpu_to_socket, i, &socket, 1) )
                    break;
            }
            if ( !guest_handle_is_null(ti->cpu_to_node) )
            {
                uint32_t node = cpu_online(i) ? cpu_to_node(i) : ~0u;
                if ( copy_to_guest_offset(ti->cpu_to_node, i, &node, 1) )
                    break;
            }
        }

        ret = ((i <= max_cpu_index) || copy_to_guest(u_sysctl, sysctl, 1))
            ? -EFAULT : 0;
    }
    break;

    case XEN_SYSCTL_numainfo:
    {
        uint32_t i, j, max_node_index, last_online_node;
        xen_sysctl_numainfo_t *ni = &sysctl->u.numainfo;

        last_online_node = last_node(node_online_map);
        max_node_index = min_t(uint32_t, ni->max_node_index, last_online_node);
        ni->max_node_index = last_online_node;

        for ( i = 0; i <= max_node_index; i++ )
        {
            if ( !guest_handle_is_null(ni->node_to_memsize) )
            {
                uint64_t memsize = node_online(i) ? 
                                   node_spanned_pages(i) << PAGE_SHIFT : 0ul;
                if ( copy_to_guest_offset(ni->node_to_memsize, i, &memsize, 1) )
                    break;
            }
            if ( !guest_handle_is_null(ni->node_to_memfree) )
            {
                uint64_t memfree = node_online(i) ? 
                                   avail_node_heap_pages(i) << PAGE_SHIFT : 0ul;
                if ( copy_to_guest_offset(ni->node_to_memfree, i, &memfree, 1) )
                    break;
            }

            if ( !guest_handle_is_null(ni->node_to_node_distance) )
            {
                for ( j = 0; j <= max_node_index; j++)
                {
                    uint32_t distance = ~0u;
                    if ( node_online(i) && node_online(j) )
                        distance = __node_distance(i, j);
                    if ( copy_to_guest_offset(
                        ni->node_to_node_distance, 
                        i*(max_node_index+1) + j, &distance, 1) )
                        break;
                }
                if ( j <= max_node_index )
                    break;
            }
        }

        ret = ((i <= max_node_index) || copy_to_guest(u_sysctl, sysctl, 1))
            ? -EFAULT : 0;
    }
    break;
    
    case XEN_SYSCTL_cpu_hotplug:
    {
        unsigned int cpu = sysctl->u.cpu_hotplug.cpu;

        if (cpu_present(cpu)) {
            status = cpu_online(cpu) ? XEN_CPU_HOTPLUG_STATUS_ONLINE :
                XEN_CPU_HOTPLUG_STATUS_OFFLINE;
        } else {
            status = -EINVAL;
        }

        switch ( sysctl->u.cpu_hotplug.op )
        {
        case XEN_SYSCTL_CPU_HOTPLUG_ONLINE:
            ret = cpu_up(cpu);
            /*
             * In the case of a true hotplug, this CPU wasn't present
             * before, so return the 'new' status for it.
             */
            if (ret == 0 && status == -EINVAL)
                status = XEN_CPU_HOTPLUG_STATUS_NEW;
            break;
        case XEN_SYSCTL_CPU_HOTPLUG_OFFLINE:
            ret = continue_hypercall_on_cpu(
                0, cpu_down_helper, (void *)(unsigned long)cpu);
            break;
        case XEN_SYSCTL_CPU_HOTPLUG_STATUS:
            ret = 0;
            break;
        default:
            ret = -EINVAL;
            break;
        }

        /*
         * If the operation was successful, return the old status.
         */
        if (ret >= 0)
            ret = status;
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
