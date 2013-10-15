/*
 *
 *  Authors:  Michael LeMay, <mdlemay@epoch.ncsc.mil>
 *            George Coker, <gscoker@alpha.ncsc.mil>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License version 2,
 *      as published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <xenctrl.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#define USE_MMAP

static void usage (int argCnt, const char *args[])
{
    fprintf(stderr, "Usage: %s <policy.file>\n", args[0]);
    exit(1);
}

int main (int argCnt, const char *args[])
{
    const char *polFName;
    int polFd = 0;
    void *polMem = NULL;
    void *polMemCp = NULL;
    struct stat info;
    int ret;
    xc_interface *xch = 0;

    if (argCnt != 2)
        usage(argCnt, args);

    polFName = args[1];
    polFd = open(polFName, O_RDONLY);
    if ( polFd < 0 )
    {
        fprintf(stderr, "Error occurred opening policy file '%s': %s\n",
                polFName, strerror(errno));
        ret = -1;
        goto cleanup;
    }
    
    ret = stat(polFName, &info);
    if ( ret < 0 )
    {
        fprintf(stderr, "Error occurred retrieving information about"
                "policy file '%s': %s\n", polFName, strerror(errno));
        goto cleanup;
    }

    polMemCp = malloc(info.st_size);

#ifdef USE_MMAP
    polMem = mmap(NULL, info.st_size, PROT_READ, MAP_SHARED, polFd, 0);
    if ( !polMem )
    {
        fprintf(stderr, "Error occurred mapping policy file in memory: %s\n",
                strerror(errno));
        ret = -1;
        goto cleanup;
    }

    xch = xc_interface_open(0,0,0);
    if ( !xch )
    {
        fprintf(stderr, "Unable to create interface to xenctrl: %s\n",
                strerror(errno));
        ret = -1;
        goto cleanup;
    }

    memcpy(polMemCp, polMem, info.st_size);
#else
    ret = read(polFd, polMemCp, info.st_size);
    if ( ret < 0 )
    {
        fprintf(stderr, "Unable to read new Flask policy file: %s\n",
                strerror(errno));
        goto cleanup;
    }
    else
    {
        printf("Read %d bytes from policy file '%s'.\n", ret, polFName);
    }
#endif

    ret = xc_flask_load(xch, polMemCp, info.st_size);
    if ( ret < 0 )
    {
        errno = -ret;
        fprintf(stderr, "Unable to load new Flask policy: %s\n",
                strerror(errno));
        ret = -1;
        goto cleanup;
    }
    else
    {
        printf("Successfully loaded policy.\n");
    }

done:
    free(polMemCp);
    if ( polMem )
    {
        ret = munmap(polMem, info.st_size);
        if ( ret < 0 )
            fprintf(stderr, "Unable to unmap policy memory: %s\n", strerror(errno));
    }
    if ( polFd )
        close(polFd);
    if ( xch )
        xc_interface_close(xch);

    return ret;

cleanup:
    goto done;
}
