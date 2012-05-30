#include "libxl_internal.h"
#include "libxl_arch.h"

int libxl__arch_domain_create(libxl__gc *gc, libxl_domain_config *d_config,
        uint32_t domid)
{
    int ret = 0;
    if (d_config->c_info.type == LIBXL_DOMAIN_TYPE_PV &&
            libxl_defbool_val(d_config->b_info.u.pv.e820_host)) {
        ret = libxl__e820_alloc(gc, domid, d_config);
        if (ret) {
            LIBXL__LOG_ERRNO(gc->owner, LIBXL__LOG_ERROR,
                    "Failed while collecting E820 with: %d (errno:%d)\n",
                    ret, errno);
        }
    }

    return ret;
}
