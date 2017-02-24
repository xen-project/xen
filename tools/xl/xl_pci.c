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

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

static void pcilist(uint32_t domid)
{
    libxl_device_pci *pcidevs;
    int num, i;

    pcidevs = libxl_device_pci_list(ctx, domid, &num);
    if (pcidevs == NULL)
        return;
    printf("Vdev Device\n");
    for (i = 0; i < num; i++) {
        printf("%02x.%01x %04x:%02x:%02x.%01x\n",
               (pcidevs[i].vdevfn >> 3) & 0x1f, pcidevs[i].vdevfn & 0x7,
               pcidevs[i].domain, pcidevs[i].bus, pcidevs[i].dev, pcidevs[i].func);
        libxl_device_pci_dispose(&pcidevs[i]);
    }
    free(pcidevs);
}

int main_pcilist(int argc, char **argv)
{
    uint32_t domid;
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-list", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind]);

    pcilist(domid);
    return 0;
}

static int pcidetach(uint32_t domid, const char *bdf, int force)
{
    libxl_device_pci pcidev;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_inig"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-detach: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }
    if (force) {
        if (libxl_device_pci_destroy(ctx, domid, &pcidev, 0))
            r = 1;
    } else {
        if (libxl_device_pci_remove(ctx, domid, &pcidev, 0))
            r = 1;
    }

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);

    return r;
}

int main_pcidetach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    int force = 0;
    const char *bdf = NULL;

    SWITCH_FOREACH_OPT(opt, "f", NULL, "pci-detach", 2) {
    case 'f':
        force = 1;
        break;
    }

    domid = find_domain(argv[optind]);
    bdf = argv[optind + 1];

    if (pcidetach(domid, bdf, force))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static int pciattach(uint32_t domid, const char *bdf, const char *vs)
{
    libxl_device_pci pcidev;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_inig"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-attach: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }

    if (libxl_device_pci_add(ctx, domid, &pcidev, 0))
        r = 1;

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);

    return r;
}

int main_pciattach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *bdf = NULL, *vs = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-attach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    bdf = argv[optind + 1];

    if (optind + 1 < argc)
        vs = argv[optind + 2];

    if (pciattach(domid, bdf, vs))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static void pciassignable_list(void)
{
    libxl_device_pci *pcidevs;
    int num, i;

    pcidevs = libxl_device_pci_assignable_list(ctx, &num);

    if ( pcidevs == NULL )
        return;
    for (i = 0; i < num; i++) {
        printf("%04x:%02x:%02x.%01x\n",
               pcidevs[i].domain, pcidevs[i].bus, pcidevs[i].dev, pcidevs[i].func);
        libxl_device_pci_dispose(&pcidevs[i]);
    }
    free(pcidevs);
}

int main_pciassignable_list(int argc, char **argv)
{
    int opt;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-assignable-list", 0) {
        /* No options */
    }

    pciassignable_list();
    return 0;
}

static int pciassignable_add(const char *bdf, int rebind)
{
    libxl_device_pci pcidev;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_init"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-assignable-add: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }

    if (libxl_device_pci_assignable_add(ctx, &pcidev, rebind))
        r = 1;

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);

    return r;
}

int main_pciassignable_add(int argc, char **argv)
{
    int opt;
    const char *bdf = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-assignable-add", 1) {
        /* No options */
    }

    bdf = argv[optind];

    if (pciassignable_add(bdf, 1))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static int pciassignable_remove(const char *bdf, int rebind)
{
    libxl_device_pci pcidev;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pcidev);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_init"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pcidev, bdf)) {
        fprintf(stderr, "pci-assignable-remove: malformed BDF specification \"%s\"\n", bdf);
        exit(2);
    }

    if (libxl_device_pci_assignable_remove(ctx, &pcidev, rebind))
        r = 1;

    libxl_device_pci_dispose(&pcidev);
    xlu_cfg_destroy(config);

    return r;
}

int main_pciassignable_remove(int argc, char **argv)
{
    int opt;
    const char *bdf = NULL;
    int rebind = 0;

    SWITCH_FOREACH_OPT(opt, "r", NULL, "pci-assignable-remove", 1) {
    case 'r':
        rebind=1;
        break;
    }

    bdf = argv[optind];

    if (pciassignable_remove(bdf, rebind))
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
