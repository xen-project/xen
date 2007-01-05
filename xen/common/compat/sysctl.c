/******************************************************************************
 * compat/sysctl.c
 */

#include <xen/config.h>
#include <compat/sysctl.h>
#include <xen/domain.h>
#include <xen/guest_access.h>
#include <xen/perfc.h>
#include <xen/trace.h>

DEFINE_XEN_GUEST_HANDLE(compat_sysctl_t);
#define xen_sysctl                     compat_sysctl
#define xen_sysctl_t                   compat_sysctl_t
#define do_sysctl(h)                   compat_sysctl(_##h)
#define arch_do_sysctl(x, h)           arch_compat_sysctl(x, _##h)

#define xen_sysctl_readconsole         compat_sysctl_readconsole
#define xen_sysctl_readconsole_t       compat_sysctl_readconsole_t

static int compat_tb_control(struct compat_sysctl_tbuf_op *cmp_tbc)
{
    struct xen_sysctl_tbuf_op nat_tbc;
    int ret;

#define XLAT_ctl_cpumap_HNDL_bitmap(_d_, _s_) \
    guest_from_compat_handle((_d_)->bitmap, (_s_)->bitmap)
    XLAT_sysctl_tbuf_op(&nat_tbc, cmp_tbc);
#undef XLAT_ctl_cpumap_HNDL_bitmap
    ret = tb_control(&nat_tbc);
#define XLAT_ctl_cpumap_HNDL_bitmap(_d_, _s_) ((void)0)
    XLAT_sysctl_tbuf_op(cmp_tbc, &nat_tbc);
#undef XLAT_ctl_cpumap_HNDL_bitmap
    return ret;
}
#define xen_sysctl_tbuf_op             compat_sysctl_tbuf_op
#define xen_sysctl_tbuf_op_t           compat_sysctl_tbuf_op_t
#define tb_control(p)                  compat_tb_control(p)

#define xen_sysctl_sched_id            compat_sysctl_sched_id
#define xen_sysctl_sched_id_t          compat_sysctl_sched_id_t

#define xen_sysctl_getdomaininfolist   compat_sysctl_getdomaininfolist
#define xen_sysctl_getdomaininfolist_t compat_sysctl_getdomaininfolist_t
#define xen_domctl_getdomaininfo       compat_domctl_getdomaininfo
#define xen_domctl_getdomaininfo_t     compat_domctl_getdomaininfo_t
#define getdomaininfo(d, i)            compat_getdomaininfo(d, i)

#ifdef PERF_COUNTERS
static int compat_perfc_control(struct compat_sysctl_perfc_op *cmp_pc)
{
    CHECK_sysctl_perfc_desc;
    CHECK_TYPE(sysctl_perfc_val);
    struct xen_sysctl_perfc_op nat_pc;
    int ret;

#define XLAT_sysctl_perfc_op_HNDL_desc(_d_, _s_) \
    guest_from_compat_handle((_d_)->desc, (_s_)->desc)
#define XLAT_sysctl_perfc_op_HNDL_val(_d_, _s_) \
    guest_from_compat_handle((_d_)->val, (_s_)->val)
    XLAT_sysctl_perfc_op(&nat_pc, cmp_pc);
#undef XLAT_sysctl_perfc_op_HNDL_val
#undef XLAT_sysctl_perfc_op_HNDL_desc
    ret = perfc_control(&nat_pc);
#define XLAT_sysctl_perfc_op_HNDL_desc(_d_, _s_)
#define XLAT_sysctl_perfc_op_HNDL_val(_d_, _s_)
    XLAT_sysctl_perfc_op(cmp_pc, &nat_pc);
#undef XLAT_sysctl_perfc_op_HNDL_val
#undef XLAT_sysctl_perfc_op_HNDL_desc
    return ret;
}
#define xen_sysctl_perfc_op            compat_sysctl_perfc_op
#define xen_sysctl_perfc_op_t          compat_sysctl_perfc_op_t
#define perfc_control(p)               compat_perfc_control(p)
#endif

#define COMPAT
#define _XEN_GUEST_HANDLE(t)           XEN_GUEST_HANDLE(t)
#define _u_sysctl                      u_sysctl
#undef guest_handle_cast
#define guest_handle_cast              compat_handle_cast
#define copy_to_xxx_offset             copy_to_compat_offset
typedef int ret_t;

#include "../sysctl.c"

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
