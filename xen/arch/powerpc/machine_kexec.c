#include <xen/lib.h>       /* for printk() used in stubs */
#include <xen/types.h>
#include <xen/kexec.h>
#include <public/kexec.h>

int machine_kexec_load(int type, int slot, xen_kexec_image_t *image)
{
    printk("STUB: " __FILE__ ": %s: not implemented\n", __FUNCTION__);
    return -1;
}

void machine_kexec_unload(int type, int slot, xen_kexec_image_t *image)
{
    printk("STUB: " __FILE__ ": %s: not implemented\n", __FUNCTION__);
}

void machine_reboot_kexec(xen_kexec_image_t *image)
{
    printk("STUB: " __FILE__ ": %s: not implemented\n", __FUNCTION__);
}

void machine_kexec(xen_kexec_image_t *image)
{
    printk("STUB: " __FILE__ ": %s: not implemented\n", __FUNCTION__);
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
