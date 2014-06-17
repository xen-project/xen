#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxlu_internal.h"
#include "libxlu_disk_l.h"
#include "libxlu_disk_i.h"
#include "libxlu_cfg_i.h"

void xlu__disk_err(DiskParseContext *dpc, const char *erroneous,
                   const char *message) {
    fprintf(dpc->cfg->report,
            "%s: config parsing error in disk specification: %s"
            "%s%s%s"
            " in `%s'\n",
            dpc->cfg->config_source, message,
            erroneous?": near `":"", erroneous?erroneous:"", erroneous?"'":"",
            dpc->spec);
    if (!dpc->err) dpc->err= EINVAL;
}

static int dpc_prep(DiskParseContext *dpc, const char *spec) {
    int e;

    dpc->spec = spec;

    e = xlu__disk_yylex_init_extra(dpc, &dpc->scanner);
    if (e) goto fail;

    dpc->buf = xlu__disk_yy_scan_bytes(spec, strlen(spec), dpc->scanner);
    if (!dpc->buf) { e = ENOMEM; goto fail; }

    return 0;

 fail:
    fprintf(dpc->cfg->report, "cannot init disk scanner: %s\n",
            strerror(errno));
    return e;
}

static void dpc_dispose(DiskParseContext *dpc) {
    if (dpc->buf) {
        xlu__disk_yy_delete_buffer(dpc->buf, dpc->scanner);
        dpc->buf = 0;
    }
    if (dpc->scanner) {
        xlu__disk_yylex_destroy(dpc->scanner);
        dpc->scanner = 0;
    }
}

int xlu_disk_parse(XLU_Config *cfg,
                   int nspecs, const char *const *specs,
                   libxl_device_disk *disk) {
    DiskParseContext dpc;
    int i, e;

    memset(&dpc,0,sizeof(dpc));
    dpc.cfg = cfg;
    dpc.scanner = 0;
    dpc.disk = disk;

    disk->readwrite = 1;

    for (i=0; i<nspecs; i++) {
        e = dpc_prep(&dpc, specs[i]);
        if (e) { dpc.err = e; goto x_err; }

        xlu__disk_yylex(dpc.scanner);
        assert(!e);
        if (dpc.err) goto x_err;

        dpc_dispose(&dpc);
    }

    if (disk->format == LIBXL_DISK_FORMAT_UNKNOWN) {
        disk->format = LIBXL_DISK_FORMAT_RAW;
    }
    if (disk->is_cdrom) {
        disk->removable = 1;
        disk->readwrite = 0;
        if (!disk->pdev_path || !strcmp(disk->pdev_path, ""))
            disk->format = LIBXL_DISK_FORMAT_EMPTY;
    }

    if (!disk->vdev) {
        xlu__disk_err(&dpc,0, "no vdev specified");
        goto x_err;
    }
    if (!disk->pdev_path && !disk->removable) {
        xlu__disk_err(&dpc,0,"no target specified (and device not removable)");
        goto x_err;
    }

 x_err:
    dpc_dispose(&dpc);
    return dpc.err;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
