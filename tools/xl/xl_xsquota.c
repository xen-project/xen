/* SPDX-License-Identifier: LGPL-2.1-only */

#include <stdio.h>
#include <stdlib.h>
#include <libxl.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_xsquota_get(int argc, char **argv)
{
    libxl_xs_quota_list q;
    unsigned int i;
    int rc;

    if (argc != 2) {
        fprintf(stderr, "Domain or \"-g\" must be specified.\n");
        return EXIT_FAILURE;
    }

    libxl_xs_quota_list_init(&q);

    if (!strcmp(argv[1], "-g")) {
        rc = libxl_xs_quota_global_get(ctx, &q);
    } else {
        uint32_t domid = find_domain(argv[1]);

        rc = libxl_xs_quota_domain_get(ctx, domid, &q);
    }

    if (rc) {
        libxl_xs_quota_list_dispose(&q);
        fprintf(stderr, "Quota could not be obtained.\n");
        return EXIT_FAILURE;
    }

    printf("Quota name           Quota value\n");
    printf("--------------------------------\n");
    for (i = 0; i < q.num_quota; i++)
        printf("%-20s %8u\n", q.quota[i].name, q.quota[i].val);

    libxl_xs_quota_list_dispose(&q);

    return EXIT_SUCCESS;
}

int main_xsquota_set(int argc, char **argv)
{
    unsigned int i;
    libxl_xs_quota_list q;
    int rc = EXIT_FAILURE;

    if (argc < 3) {
        fprintf(stderr, "Not enough parameters.\n");
        help("xenstore-quota-set");
        return EXIT_FAILURE;
    }

    libxl_xs_quota_list_init(&q);

    q.num_quota = argc - 2;
    q.quota = xcalloc(q.num_quota, sizeof(*q.quota));

    for (i = 2; i < argc; i++) {
        if (parse_xsquota_item(argv[i], q.quota + i - 2))
            goto err;
    }

    if (!strcmp(argv[1], "-g")) {
         rc = libxl_xs_quota_global_set(ctx, &q);
    } else {
        uint32_t domid = find_domain(argv[1]);

        rc = libxl_xs_quota_domain_set(ctx, domid, &q);
    }

    if (rc) {
        fprintf(stderr, "Quota could not be set.\n");
        rc = EXIT_FAILURE;
    } else {
        rc = EXIT_SUCCESS;
    }

 err:
    libxl_xs_quota_list_dispose(&q);

    return rc;
}
