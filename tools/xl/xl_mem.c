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

static int set_memory_max(uint32_t domid, const char *mem)
{
    int64_t memorykb;

    memorykb = parse_mem_size_kb(mem);
    if (memorykb == -1) {
        fprintf(stderr, "invalid memory size: %s\n", mem);
        return EXIT_FAILURE;
    }

    if (libxl_domain_setmaxmem(ctx, domid, memorykb)) {
        fprintf(stderr, "cannot set domid %u static max memory to : %s\n", domid, mem);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main_memmax(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    char *mem;

    SWITCH_FOREACH_OPT(opt, "", NULL, "mem-max", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    mem = argv[optind + 1];

    return set_memory_max(domid, mem);
}

static int set_memory_target(uint32_t domid, const char *mem)
{
    int64_t memorykb;

    memorykb = parse_mem_size_kb(mem);
    if (memorykb == -1)  {
        fprintf(stderr, "invalid memory size: %s\n", mem);
        return EXIT_FAILURE;
    }

    if (libxl_set_memory_target(ctx, domid, memorykb, 0, /* enforce */ 1)) {
        fprintf(stderr, "cannot set domid %u dynamic max memory to : %s\n", domid, mem);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int main_memset(int argc, char **argv)
{
    uint32_t domid;
    int opt = 0;
    const char *mem;

    SWITCH_FOREACH_OPT(opt, "", NULL, "mem-set", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind]);
    mem = argv[optind + 1];

    return set_memory_target(domid, mem);
}

static void sharing(const libxl_dominfo *info, int nb_domain)
{
    int i;

    printf("Name                                        ID   Mem Shared\n");

    for (i = 0; i < nb_domain; i++) {
        char *domname;
        unsigned shutdown_reason;
        domname = libxl_domid_to_name(ctx, info[i].domid);
        shutdown_reason = info[i].shutdown ? info[i].shutdown_reason : 0;
        printf("%-40s %5d %5lu  %5lu\n",
                domname,
                info[i].domid,
                (unsigned long) ((info[i].current_memkb +
                    info[i].outstanding_memkb) / 1024),
                (unsigned long) (info[i].shared_memkb / 1024));
        free(domname);
    }
}

int main_sharing(int argc, char **argv)
{
    int opt = 0;
    libxl_dominfo info_buf;
    libxl_dominfo *info, *info_free = NULL;
    int nb_domain, rc;

    SWITCH_FOREACH_OPT(opt, "", NULL, "sharing", 0) {
        /* No options */
    }

    if (optind >= argc) {
        info = libxl_list_domain(ctx, &nb_domain);
        if (!info) {
            fprintf(stderr, "libxl_list_domain failed.\n");
            return EXIT_FAILURE;
        }
        info_free = info;
    } else if (optind == argc-1) {
        uint32_t domid = find_domain(argv[optind]);
        rc = libxl_domain_info(ctx, &info_buf, domid);
        if (rc == ERROR_DOMAIN_NOTFOUND) {
            fprintf(stderr, "Error: Domain \'%s\' does not exist.\n",
                argv[optind]);
            return EXIT_FAILURE;
        }
        if (rc) {
            fprintf(stderr, "libxl_domain_info failed (code %d).\n", rc);
            return EXIT_FAILURE;
        }
        info = &info_buf;
        nb_domain = 1;
    } else {
        help("sharing");
        return EXIT_FAILURE;
    }

    sharing(info, nb_domain);

    if (info_free)
        libxl_dominfo_list_free(info_free, nb_domain);
    else
        libxl_dominfo_dispose(info);

    return EXIT_SUCCESS;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
