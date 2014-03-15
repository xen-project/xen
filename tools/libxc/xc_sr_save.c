#include "xc_sr_common.h"

int xc_domain_save2(xc_interface *xch, int io_fd, uint32_t dom,
                    uint32_t max_iters, uint32_t max_factor, uint32_t flags,
                    struct save_callbacks* callbacks, int hvm)
{
    IPRINTF("In experimental %s", __func__);
    return -1;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
