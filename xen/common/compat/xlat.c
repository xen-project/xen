/******************************************************************************
 * xlat.c
 */

#include <xen/compat.h>
#include <xen/lib.h>
#include <compat/xen.h>
#include <compat/event_channel.h>
#include <compat/vcpu.h>

/* In-place translation functons: */
void xlat_start_info(struct start_info *native,
                     enum XLAT_start_info_console console)
{
    struct compat_start_info *compat = (void *)native;

    BUILD_BUG_ON(sizeof(*native) < sizeof(*compat));
    XLAT_start_info(compat, native);
}

void xlat_vcpu_runstate_info(struct vcpu_runstate_info *native)
{
    struct compat_vcpu_runstate_info *compat = (void *)native;

    BUILD_BUG_ON(sizeof(*native) < sizeof(*compat));
    XLAT_vcpu_runstate_info(compat, native);
}

#define xen_dom0_vga_console_info dom0_vga_console_info
CHECK_dom0_vga_console_info;
#undef dom0_vga_console_info

#define xen_evtchn_alloc_unbound evtchn_alloc_unbound
#define xen_evtchn_bind_interdomain evtchn_bind_interdomain
#define xen_evtchn_bind_ipi evtchn_bind_ipi
#define xen_evtchn_bind_pirq evtchn_bind_pirq
#define xen_evtchn_bind_vcpu evtchn_bind_vcpu
#define xen_evtchn_bind_virq evtchn_bind_virq
#define xen_evtchn_close evtchn_close
#define xen_evtchn_op evtchn_op
#define xen_evtchn_send evtchn_send
#define xen_evtchn_status evtchn_status
#define xen_evtchn_unmask evtchn_unmask
CHECK_evtchn_op;
#undef xen_evtchn_alloc_unbound
#undef xen_evtchn_bind_interdomain
#undef xen_evtchn_bind_ipi
#undef xen_evtchn_bind_pirq
#undef xen_evtchn_bind_vcpu
#undef xen_evtchn_bind_virq
#undef xen_evtchn_close
#undef xen_evtchn_op
#undef xen_evtchn_send
#undef xen_evtchn_status
#undef xen_evtchn_unmask

#define xen_mmu_update mmu_update
CHECK_mmu_update;
#undef xen_mmu_update

#define xen_vcpu_time_info vcpu_time_info
CHECK_vcpu_time_info;
#undef xen_vcpu_time_info

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
