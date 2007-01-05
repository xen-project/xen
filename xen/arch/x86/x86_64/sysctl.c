/******************************************************************************
 * Arch-specific compatibility sysctl.c
 */

#include <xen/config.h>
#include <compat/sysctl.h>

DEFINE_XEN_GUEST_HANDLE(compat_sysctl_t);
#define xen_sysctl                    compat_sysctl
#define xen_sysctl_t                  compat_sysctl_t
#define arch_do_sysctl(x, h)          arch_compat_sysctl(x, _##h)

#define xen_sysctl_physinfo           compat_sysctl_physinfo
#define xen_sysctl_physinfo_t         compat_sysctl_physinfo_t

#define xen_sysctl_ioport_emulation   compat_sysctl_ioport_emulation
#define xen_sysctl_ioport_emulation_t compat_sysctl_ioport_emulation_t

#define COMPAT
#define _XEN_GUEST_HANDLE(t)          XEN_GUEST_HANDLE(t)
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
