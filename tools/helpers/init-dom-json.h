#ifndef __INIT_DOM_JSON_H
#define __INIT_DOM_JSON_H

#include <libxl.h>
/*
 * Generate a stub JSON config for a domain with the given domid.
 */
int gen_stub_json_config(uint32_t domid, libxl_uuid *uuid);

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
