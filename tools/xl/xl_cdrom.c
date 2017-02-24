/*
 * Copyright 2009-2017 Citrix Ltd and other contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

static int cd_insert(uint32_t domid, const char *virtdev, char *phys)
{
    libxl_device_disk disk;
    char *buf = NULL;
    XLU_Config *config = 0;
    struct stat b;
    int r;

    xasprintf(&buf, "vdev=%s,access=r,devtype=cdrom,target=%s",
              virtdev, phys ? phys : "");

    parse_disk_config(&config, buf, &disk);

    /* ATM the existence of the backing file is not checked for qdisk
     * in libxl_cdrom_insert() because RAW is used for remote
     * protocols as well as plain files.  This will ideally be changed
     * for 4.4, but this work-around fixes the problem of "cd-insert"
     * returning success for non-existent files. */
    if (disk.format != LIBXL_DISK_FORMAT_EMPTY
        && stat(disk.pdev_path, &b)) {
        fprintf(stderr, "Cannot stat file: %s\n",
                disk.pdev_path);
        r = 1;
        goto out;
    }

    if (libxl_cdrom_insert(ctx, domid, &disk, NULL)) {
        r = 1;
        goto out;
    }

    r = 0;

out:
    libxl_device_disk_dispose(&disk);
    free(buf);

    return r;
}

int main_cd_eject(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    const char *virtdev;

    SWITCH_FOREACH_OPT(opt, "", NULL, "cd-eject", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    virtdev = argv[optind + 1];

    if (cd_insert(domid, virtdev, NULL))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int main_cd_insert(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    const char *virtdev;
    char *file = NULL; /* modified by cd_insert tokenising it */

    SWITCH_FOREACH_OPT(opt, "", NULL, "cd-insert", 3) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    virtdev = argv[optind + 1];
    file = argv[optind + 2];

    if (cd_insert(domid, virtdev, file))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
