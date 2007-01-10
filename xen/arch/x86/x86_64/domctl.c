/******************************************************************************
 * Arch-specific compatibility domctl.c
 */

#include <xen/config.h>
#include <compat/domctl.h>
#include <xen/guest_access.h>
#include <asm/shadow.h>

DEFINE_XEN_GUEST_HANDLE(compat_domctl_t);
#define xen_domctl                     compat_domctl
#define xen_domctl_t                   compat_domctl_t
#define arch_do_domctl(x, h)           arch_compat_domctl(x, _##h)

static int compat_shadow_domctl(struct domain *d,
                                compat_domctl_shadow_op_t *csc,
                                XEN_GUEST_HANDLE(void) u_domctl)
{
    xen_domctl_shadow_op_t nsc;
    int rc, mode;

#define XLAT_domctl_shadow_op_HNDL_dirty_bitmap(_d_, _s_) \
    do \
    { \
        if ( (_s_)->op != XEN_DOMCTL_SHADOW_OP_CLEAN \
             && (_s_)->op != XEN_DOMCTL_SHADOW_OP_PEEK ) \
        { \
            set_xen_guest_handle((_d_)->dirty_bitmap, NULL); \
            mode = -1; \
        } \
        else if ( compat_handle_is_null((_s_)->dirty_bitmap) \
                  || (((_s_)->pages - 1) \
                      & (BITS_PER_LONG - COMPAT_BITS_PER_LONG)) \
                     == BITS_PER_LONG - COMPAT_BITS_PER_LONG ) \
        { \
            XEN_GUEST_HANDLE(void) tmp; \
            guest_from_compat_handle(tmp, (_s_)->dirty_bitmap); \
            (_d_)->dirty_bitmap = guest_handle_cast(tmp, ulong); \
            mode = 0; \
        } \
        else if ( (_s_)->pages > COMPAT_ARG_XLAT_SIZE * 8 ) \
        { \
            printk("Cannot translate compatibility mode XEN_DOMCTL_SHADOW_OP_{CLEAN,PEEK} (0x%lX)\n", \
                   (_s_)->pages); \
            return -E2BIG; \
        } \
        else \
        { \
            set_xen_guest_handle((_d_)->dirty_bitmap, \
                                 (void *)COMPAT_ARG_XLAT_VIRT_START(current->vcpu_id)); \
            mode = 1; \
        } \
    } while (0)
    XLAT_domctl_shadow_op(&nsc, csc);
#undef XLAT_domctl_shadow_op_HNDL_dirty_bitmap
    rc = shadow_domctl(d, &nsc, u_domctl);
    if ( rc != __HYPERVISOR_domctl )
    {
        BUG_ON(rc > 0);
#define XLAT_domctl_shadow_op_HNDL_dirty_bitmap(_d_, _s_) \
        do \
        { \
            if ( rc == 0 \
                 && mode > 0 \
                 && copy_to_compat((_d_)->dirty_bitmap, \
                                   (unsigned int *)(_s_)->dirty_bitmap.p, \
                                   ((_s_)->pages + COMPAT_BITS_PER_LONG - 1) / COMPAT_BITS_PER_LONG) ) \
                rc = -EFAULT; \
        } while (0)
        XLAT_domctl_shadow_op(csc, &nsc);
#undef XLAT_domctl_shadow_op_HNDL_dirty_bitmap
    }
    return rc;
}
#define xen_domctl_shadow_op           compat_domctl_shadow_op
#define xen_domctl_shadow_op_t         compat_domctl_shadow_op_t
#define shadow_domctl(d, sc, u)        compat_shadow_domctl(d, sc, u)

#define xen_domctl_ioport_permission   compat_domctl_ioport_permission
#define xen_domctl_ioport_permission_t compat_domctl_ioport_permission_t

#define xen_domctl_getpageframeinfo    compat_domctl_getpageframeinfo
#define xen_domctl_getpageframeinfo_t  compat_domctl_getpageframeinfo_t

#define xen_domctl_getpageframeinfo2   compat_domctl_getpageframeinfo2
#define xen_domctl_getpageframeinfo2_t compat_domctl_getpageframeinfo2_t

#define xen_domctl_getmemlist          compat_domctl_getmemlist
#define xen_domctl_getmemlist_t        compat_domctl_getmemlist_t
#define xen_pfn_t                      compat_pfn_t

#define xen_domctl_hypercall_init      compat_domctl_hypercall_init
#define xen_domctl_hypercall_init_t    compat_domctl_hypercall_init_t

#define COMPAT
#define _XEN_GUEST_HANDLE(t)           XEN_GUEST_HANDLE(t)
#define _long                          int
#define copy_from_xxx_offset           copy_from_compat_offset
#define copy_to_xxx_offset             copy_to_compat_offset

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
