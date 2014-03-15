#ifndef __COMMON__H
#define __COMMON__H

#include "xg_private.h"

#include "xc_sr_stream_format.h"

/* String representation of Domain Header types. */
const char *dhdr_type_to_str(uint32_t type);

/* String representation of Record types. */
const char *rec_type_to_str(uint32_t type);

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
