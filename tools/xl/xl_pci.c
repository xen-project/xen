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
    libxl_device_pci *pcis;
    int num, i;

    pcis = libxl_device_pci_list(ctx, domid, &num);
    if (pcis == NULL)
        return;
    printf("Vdev Device\n");
    for (i = 0; i < num; i++) {
        printf("%02x.%01x %04x:%02x:%02x.%01x\n",
               (pcis[i].vdevfn >> 3) & 0x1f, pcis[i].vdevfn & 0x7,
               pcis[i].bdf.domain, pcis[i].bdf.bus, pcis[i].bdf.dev,
               pcis[i].bdf.func);
    }
    libxl_device_pci_list_free(pcis, num);
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

static int pcidetach(uint32_t domid, const char *spec_string, int force)
{
    libxl_device_pci pci;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pci);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_inig"); exit(-1); }

    if (xlu_pci_parse_spec_string(config, &pci, spec_string)) {
        fprintf(stderr, "pci-detach: malformed PCI_SPEC_STRING \"%s\"\n",
                spec_string);
        exit(2);
    }
    if (force) {
        if (libxl_device_pci_destroy(ctx, domid, &pci, 0))
            r = 1;
    } else {
        if (libxl_device_pci_remove(ctx, domid, &pci, 0))
            r = 1;
    }

    libxl_device_pci_dispose(&pci);
    xlu_cfg_destroy(config);

    return r;
}

int main_pcidetach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    int force = 0;
    const char *spec_string = NULL;

    SWITCH_FOREACH_OPT(opt, "f", NULL, "pci-detach", 2) {
    case 'f':
        force = 1;
        break;
    }

    domid = find_domain(argv[optind]);
    spec_string = argv[optind + 1];

    if (pcidetach(domid, spec_string, force))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static int pciattach(uint32_t domid, const char *spec_string)
{
    libxl_device_pci pci;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pci);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_inig"); exit(-1); }

    if (xlu_pci_parse_spec_string(config, &pci, spec_string)) {
        fprintf(stderr, "pci-attach: malformed PCI_SPEC_STRING \"%s\"\n",
                spec_string);
        exit(2);
    }

    if (libxl_device_pci_add(ctx, domid, &pci, 0))
        r = 1;

    libxl_device_pci_dispose(&pci);
    xlu_cfg_destroy(config);

    return r;
}

int main_pciattach(int argc, char **argv)
{
    uint32_t domid;
    int opt;
    const char *spec_string = NULL;

    SWITCH_FOREACH_OPT(opt, "", NULL, "pci-attach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    spec_string = argv[optind + 1];

    if (pciattach(domid, spec_string))
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static void pciassignable_list(void)
{
    libxl_device_pci *pcis;
    int num, i;

    pcis = libxl_device_pci_assignable_list(ctx, &num);

    if ( pcis == NULL )
        return;
    for (i = 0; i < num; i++) {
        printf("%04x:%02x:%02x.%01x\n",
               pcis[i].bdf.domain, pcis[i].bdf.bus, pcis[i].bdf.dev,
               pcis[i].bdf.func);
    }
    libxl_device_pci_assignable_list_free(pcis, num);
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
    libxl_device_pci pci;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pci);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_init"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pci.bdf, bdf)) {
        fprintf(stderr, "pci-assignable-add: malformed BDF \"%s\"\n", bdf);
        exit(2);
    }

    if (libxl_device_pci_assignable_add(ctx, &pci, rebind))
        r = 1;

    libxl_device_pci_dispose(&pci);
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
    libxl_device_pci pci;
    XLU_Config *config;
    int r = 0;

    libxl_device_pci_init(&pci);

    config = xlu_cfg_init(stderr, "command line");
    if (!config) { perror("xlu_cfg_init"); exit(-1); }

    if (xlu_pci_parse_bdf(config, &pci.bdf, bdf)) {
        fprintf(stderr, "pci-assignable-remove: malformed BDF \"%s\"\n", bdf);
        exit(2);
    }

    if (libxl_device_pci_assignable_remove(ctx, &pci, rebind))
        r = 1;

    libxl_device_pci_dispose(&pci);
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
