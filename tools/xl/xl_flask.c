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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libxl.h>

#include "xl.h"

int main_getenforce(int argc, char **argv)
{
    int ret;

    ret = libxl_flask_getenforce(ctx);

    if (ret < 0) {
        if (errno == ENOSYS)
            printf("Flask XSM Disabled\n");
        else
            fprintf(stderr, "Failed to get enforcing mode\n");
    }
    else if (ret == 1)
        printf("Enforcing\n");
    else if (ret == 0)
        printf("Permissive\n");

    return ret;
}

int main_setenforce(int argc, char **argv)
{
    int ret, mode;
    const char *p = NULL;

    if (optind >= argc) {
        help("setenforce");
        return 2;
    }

    p = argv[optind];

    if (!strcmp(p, "0"))
        mode = 0;
    else if (!strcmp(p, "1"))
        mode = 1;
    else if (!strcasecmp(p, "permissive"))
        mode = 0;
    else if (!strcasecmp(p, "enforcing"))
        mode = 1;
    else {
        help("setenforce");
        return 2;
    }

    ret = libxl_flask_setenforce(ctx, mode);

    if (ret) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Flask XSM disabled\n");
        }
        else
            fprintf(stderr, "error occured while setting enforcing mode (%i)\n", ret);
    }

    return ret;
}

int main_loadpolicy(int argc, char **argv)
{
    const char *polFName;
    int polFd = -1;
    void *polMemCp = NULL;
    struct stat info;
    int ret;

    if (optind >= argc) {
        help("loadpolicy");
        return 2;
    }

    polFName = argv[optind];
    polFd = open(polFName, O_RDONLY);
    if (polFd < 0) {
        fprintf(stderr, "Error occurred opening policy file '%s': %s\n",
                polFName, strerror(errno));
        ret = -1;
        goto done;
    }

    ret = stat(polFName, &info);
    if (ret < 0) {
        fprintf(stderr, "Error occurred retrieving information about"
                "policy file '%s': %s\n", polFName, strerror(errno));
        goto done;
    }

    polMemCp = malloc(info.st_size);

    ret = read(polFd, polMemCp, info.st_size);
    if ( ret < 0 ) {
        fprintf(stderr, "Unable to read new Flask policy file: %s\n",
                strerror(errno));
        goto done;
    }

    ret = libxl_flask_loadpolicy(ctx, polMemCp, info.st_size);

    if (ret < 0) {
        if (errno == ENOSYS) {
            fprintf(stderr, "Flask XSM disabled\n");
        } else {
            errno = -ret;
            fprintf(stderr, "Unable to load new Flask policy: %s\n",
                    strerror(errno));
            ret = -1;
        }
    } else {
        printf("Successfully loaded policy.\n");
    }

done:
    free(polMemCp);
    if (polFd >= 0)
        close(polFd);

    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
