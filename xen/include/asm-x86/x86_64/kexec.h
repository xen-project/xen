#ifndef __X86_64_KEXEC_H__
#define __X86_64_KEXEC_H__

#include <xen/lib.h>       /* for printk() used in stub */
#include <xen/types.h>
#include <public/xen.h>
#include <xen/kexec.h>

static inline void machine_kexec(xen_kexec_image_t *image)
{
    printk("STUB: " __FILE__ ": %s: not implemented\n", __FUNCTION__);
}

#endif /* __X86_64_KEXEC_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
