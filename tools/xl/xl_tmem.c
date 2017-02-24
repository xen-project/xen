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
#include <unistd.h>

#include <libxl.h>

#include "xl.h"
#include "xl_utils.h"

int main_tmem_list(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    char *buf = NULL;
    int use_long = 0;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "al", NULL, "tmem-list", 0) {
    case 'l':
        use_long = 1;
        break;
    case 'a':
        all = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-list");
        return 1;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    buf = libxl_tmem_list(ctx, domid, use_long);
    if (buf == NULL)
        return EXIT_FAILURE;

    printf("%s\n", buf);
    free(buf);
    return EXIT_SUCCESS;
}

int main_tmem_freeze(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "a", NULL, "tmem-freeze", 0) {
    case 'a':
        all = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-freeze");
        return EXIT_FAILURE;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    if (libxl_tmem_freeze(ctx, domid) < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int main_tmem_thaw(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "a", NULL, "tmem-thaw", 0) {
    case 'a':
        all = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-thaw");
        return EXIT_FAILURE;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    if (libxl_tmem_thaw(ctx, domid) < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int main_tmem_set(int argc, char **argv)
{
    uint32_t domid;
    const char *dom = NULL;
    uint32_t weight = 0, cap = 0, compress = 0;
    int opt_w = 0, opt_c = 0, opt_p = 0;
    int all = 0;
    int opt;
    int rc = 0;

    SWITCH_FOREACH_OPT(opt, "aw:c:p:", NULL, "tmem-set", 0) {
    case 'a':
        all = 1;
        break;
    case 'w':
        weight = strtol(optarg, NULL, 10);
        opt_w = 1;
        break;
    case 'c':
        cap = strtol(optarg, NULL, 10);
        opt_c = 1;
        break;
    case 'p':
        compress = strtol(optarg, NULL, 10);
        opt_p = 1;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-set");
        return EXIT_FAILURE;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    if (!opt_w && !opt_c && !opt_p) {
        fprintf(stderr, "No set value specified.\n\n");
        help("tmem-set");
        return EXIT_FAILURE;
    }

    if (opt_w)
        rc = libxl_tmem_set(ctx, domid, "weight", weight);
    if (opt_c)
        rc = libxl_tmem_set(ctx, domid, "cap", cap);
    if (opt_p)
        rc = libxl_tmem_set(ctx, domid, "compress", compress);

    if (rc < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int main_tmem_shared_auth(int argc, char **argv)
{
    uint32_t domid;
    const char *autharg = NULL;
    char *endptr = NULL;
    const char *dom = NULL;
    char *uuid = NULL;
    int auth = -1;
    int all = 0;
    int opt;

    SWITCH_FOREACH_OPT(opt, "au:A:", NULL, "tmem-shared-auth", 0) {
    case 'a':
        all = 1;
        break;
    case 'u':
        uuid = optarg;
        break;
    case 'A':
        autharg = optarg;
        break;
    }

    dom = argv[optind];
    if (!dom && all == 0) {
        fprintf(stderr, "You must specify -a or a domain id.\n\n");
        help("tmem-shared-auth");
        return EXIT_FAILURE;
    }

    if (all)
        domid = INVALID_DOMID;
    else
        domid = find_domain(dom);

    if (uuid == NULL || autharg == NULL) {
        fprintf(stderr, "No uuid or auth specified.\n\n");
        help("tmem-shared-auth");
        return EXIT_FAILURE;
    }

    auth = strtol(autharg, &endptr, 10);
    if (*endptr != '\0') {
        fprintf(stderr, "Invalid auth, valid auth are <0|1>.\n\n");
        return EXIT_FAILURE;
    }

    if (libxl_tmem_shared_auth(ctx, domid, uuid, auth) < 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

int main_tmem_freeable(int argc, char **argv)
{
    int opt;
    int mb;

    SWITCH_FOREACH_OPT(opt, "", NULL, "tmem-freeable", 0) {
        /* No options */
    }

    mb = libxl_tmem_freeable(ctx);
    if (mb == -1)
        return EXIT_FAILURE;

    printf("%d\n", mb);
    return EXIT_SUCCESS;
}
