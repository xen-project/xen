/******************************************************************************
 * compat/domctl.c
 */

#include <xen/config.h>
#include <compat/domctl.h>
#include <xen/sched.h>
#include <xen/cpumask.h>
#include <asm/uaccess.h>

DEFINE_XEN_GUEST_HANDLE(compat_domctl_t);
#define xen_domctl                     compat_domctl
#define xen_domctl_t                   compat_domctl_t
#define do_domctl(h)                   compat_domctl(_##h)
#define arch_do_domctl(x, h)           arch_compat_domctl(x, _##h)

#define xen_domain_handle_t            compat_domain_handle_t

#define xen_domctl_vcpucontext         compat_domctl_vcpucontext
#define xen_domctl_vcpucontext_t       compat_domctl_vcpucontext_t

#define xen_domctl_createdomain        compat_domctl_createdomain
#define xen_domctl_createdomain_t      compat_domctl_createdomain_t

#define xen_domctl_max_vcpus           compat_domctl_max_vcpus
#define xen_domctl_max_vcpus_t         compat_domctl_max_vcpus_t

static void cpumask_to_compat_ctl_cpumap(
    struct compat_ctl_cpumap *cmpctl_cpumap, cpumask_t *cpumask)
{
    unsigned int guest_bytes, copy_bytes, i;
    /*static const*/ uint8_t zero = 0;

    if ( compat_handle_is_null(cmpctl_cpumap->bitmap) )
        return;

    guest_bytes = (cmpctl_cpumap->nr_cpus + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, (NR_CPUS + 7) / 8);

    copy_to_compat(cmpctl_cpumap->bitmap,
                   (uint8_t *)cpus_addr(*cpumask),
                   copy_bytes);

    for ( i = copy_bytes; i < guest_bytes; i++ )
        copy_to_compat_offset(cmpctl_cpumap->bitmap, i, &zero, 1);
}
#define cpumask_to_xenctl_cpumap       cpumask_to_compat_ctl_cpumap

void compat_ctl_cpumap_to_cpumask(
    cpumask_t *cpumask, struct compat_ctl_cpumap *cmpctl_cpumap)
{
    unsigned int guest_bytes, copy_bytes;

    guest_bytes = (cmpctl_cpumap->nr_cpus + 7) / 8;
    copy_bytes  = min_t(unsigned int, guest_bytes, (NR_CPUS + 7) / 8);

    cpus_clear(*cpumask);

    if ( compat_handle_is_null(cmpctl_cpumap->bitmap) )
        return;

    copy_from_compat((uint8_t *)cpus_addr(*cpumask),
                     cmpctl_cpumap->bitmap,
                     copy_bytes);
}
#define xenctl_cpumap_to_cpumask       compat_ctl_cpumap_to_cpumask

#define xen_domctl_vcpuaffinity        compat_domctl_vcpuaffinity
#define xen_domctl_vcpuaffinity_t      compat_domctl_vcpuaffinity_t

static int compat_sched_adjust(struct domain *d,
                               struct compat_domctl_scheduler_op *cop)
{
    struct xen_domctl_scheduler_op nop;
    int ret;
    enum XLAT_domctl_scheduler_op_u u;

    switch ( cop->sched_id )
    {
    case XEN_SCHEDULER_SEDF:   u = XLAT_domctl_scheduler_op_u_sedf;   break;
    case XEN_SCHEDULER_CREDIT: u = XLAT_domctl_scheduler_op_u_credit; break;
    default: return -EINVAL;
    }
    XLAT_domctl_scheduler_op(&nop, cop);
    ret = sched_adjust(d, &nop);
    XLAT_domctl_scheduler_op(cop, &nop);

    return ret;
}
#define sched_adjust(d, op)            compat_sched_adjust(d, op)
#define xen_domctl_scheduler_op        compat_domctl_scheduler_op
#define xen_domctl_scheduler_op_t      compat_domctl_scheduler_op_t

#define xen_domctl_getdomaininfo       compat_domctl_getdomaininfo
#define xen_domctl_getdomaininfo_t     compat_domctl_getdomaininfo_t
#define getdomaininfo(d, i)            compat_getdomaininfo(d, i)

#define xen_domctl_getvcpuinfo         compat_domctl_getvcpuinfo
#define xen_domctl_getvcpuinfo_t       compat_domctl_getvcpuinfo_t

#define xen_domctl_max_mem             compat_domctl_max_mem
#define xen_domctl_max_mem_t           compat_domctl_max_mem_t

#define xen_domctl_setdomainhandle     compat_domctl_setdomainhandle
#define xen_domctl_setdomainhandle_t   compat_domctl_setdomainhandle_t

#define xen_domctl_setdebugging        compat_domctl_setdebugging
#define xen_domctl_setdebugging_t      compat_domctl_setdebugging_t

#define xen_domctl_irq_permission      compat_domctl_irq_permission
#define xen_domctl_irq_permission_t    compat_domctl_irq_permission_t

#define xen_domctl_iomem_permission    compat_domctl_iomem_permission
#define xen_domctl_iomem_permission_t  compat_domctl_iomem_permission_t

#define xen_domctl_settimeoffset       compat_domctl_settimeoffset
#define xen_domctl_settimeoffset_t     compat_domctl_settimeoffset_t

#define COMPAT
#define _XEN_GUEST_HANDLE(t)           XEN_GUEST_HANDLE(t)
#define _u_domctl                      u_domctl
//#undef guest_handle_cast
//#define guest_handle_cast              compat_handle_cast
//#define copy_to_xxx_offset             copy_to_compat_offset
typedef int ret_t;

#include "../domctl.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
