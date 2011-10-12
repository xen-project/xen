#ifndef LIBXLU_DISK_I_H
#define LIBXLU_DISK_I_H

#include "libxlu_internal.h"


typedef struct {
    XLU_Config *cfg;
    int err;
    void *scanner;
    YY_BUFFER_STATE buf;
    libxl_device_disk *disk;
    int access_set, had_depr_prefix;
    const char *spec;
} DiskParseContext;

void xlu__disk_err(DiskParseContext *dpc, const char *erroneous,
                   const char *message);


#endif /*LIBXLU_DISK_I_H*/

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
