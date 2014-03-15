#include "xc_sr_common.h"

int xc_domain_restore2(xc_interface *xch, int io_fd, uint32_t dom,
                       unsigned int store_evtchn, unsigned long *store_mfn,
                       domid_t store_domid, unsigned int console_evtchn,
                       unsigned long *console_mfn, domid_t console_domid,
                       unsigned int hvm, unsigned int pae, int superpages,
                       int checkpointed_stream,
                       struct restore_callbacks *callbacks)
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
