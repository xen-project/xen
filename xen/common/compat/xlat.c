/******************************************************************************
 * xlat.c
 */

#include <xen/compat.h>
#include <xen/lib.h>
#include <public/xen.h>
#include <compat/xen.h>

/* In-place translation functons: */
void xlat_start_info(struct start_info *native,
                     enum XLAT_start_info_console console)
{
    struct compat_start_info *compat = (void *)native;

    BUILD_BUG_ON(sizeof(*native) < sizeof(*compat));
    XLAT_start_info(compat, native);
}

#define xen_dom0_vga_console_info dom0_vga_console_info
CHECK_dom0_vga_console_info;
#undef dom0_vga_console_info

#define xen_vcpu_time_info vcpu_time_info
CHECK_vcpu_time_info;
#undef xen_vcpu_time_info

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
