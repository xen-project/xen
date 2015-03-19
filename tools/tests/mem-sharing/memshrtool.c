/*
 * memshrtool.c
 *
 * Copyright 2011 GridCentric Inc. (Adin Scannell, Andres Lagar-Cavilla)
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include "xenctrl.h"

static int usage(const char* prog)
{
    printf("usage: %s <command> [args...]\n", prog);
    printf("where <command> may be:\n");
    printf("  info                    - Display total sharing info.\n");
    printf("  enable                  - Enable sharing on a domain.\n");
    printf("  disable                 - Disable sharing on a domain.\n");
    printf("  nominate <domid> <gfn>  - Nominate a page for sharing.\n");
    printf("  share <domid> <gfn> <handle> <source> <source-gfn> <source-handle>\n");
    printf("                          - Share two pages.\n");
    printf("  unshare <domid> <gfn>   - Unshare a page by grabbing a writable map.\n");
    printf("  add-to-physmap <domid> <gfn> <source> <source-gfn> <source-handle>\n");
    printf("                          - Populate a page in a domain with a shared page.\n");
    printf("  debug-gfn <domid> <gfn> - Debug a particular domain and gfn.\n");
    printf("  audit                   - Audit the sharing subsytem in Xen.\n");
    return 1;
}

#define R(f) do { \
    int rc = f; \
    if ( rc < 0 ) { \
        printf("error executing %s: %s\n", #f, \
                ((errno * -1) == XENMEM_SHARING_OP_S_HANDLE_INVALID) ? \
                "problem with client handle" :\
                ((errno * -1) == XENMEM_SHARING_OP_C_HANDLE_INVALID) ? \
                "problem with source handle" : strerror(errno)); \
        return rc; \
    } \
} while(0)

int main(int argc, const char** argv)
{
    const char* cmd = NULL;
    xc_interface *xch = xc_interface_open(0, 0, 0);

    if( argc < 2 )
        return usage(argv[0]);

    cmd = argv[1];

    if( !strcasecmp(cmd, "info") )
    {
        long rc;
        if( argc != 2 )
            return usage(argv[0]);

        rc = xc_sharing_freed_pages(xch);
        if ( rc < 0 )
            return 1;

        printf("used = %ld\n", rc);
        rc = xc_sharing_used_frames(xch);
        if ( rc < 0 )
            return 1;
        printf("freed = %ld\n", rc);
    }
    else if( !strcasecmp(cmd, "enable") )
    {
        domid_t domid;

        if( argc != 3 )
            return usage(argv[0]);

        domid = strtol(argv[2], NULL, 0);
        R(xc_memshr_control(xch, domid, 1));
    }
    else if( !strcasecmp(cmd, "disable") )
    {
        domid_t domid;

        if( argc != 3 )
            return usage(argv[0]);

        domid = strtol(argv[2], NULL, 0);
        R(xc_memshr_control(xch, domid, 0));
    }
    else if( !strcasecmp(cmd, "nominate") )
    {
        domid_t domid;
        unsigned long gfn;
        uint64_t handle;

        if( argc != 4 )
            return usage(argv[0]);

        domid = strtol(argv[2], NULL, 0);
        gfn = strtol(argv[3], NULL, 0);
        R(xc_memshr_nominate_gfn(xch, domid, gfn, &handle));
        printf("handle = 0x%08llx\n", (unsigned long long) handle);
    }
    else if( !strcasecmp(cmd, "share") )
    {
        domid_t domid;
        unsigned long gfn;
        uint64_t handle;
        domid_t source_domid;
        unsigned long source_gfn;
        uint64_t source_handle;

        if( argc != 8 )
            return usage(argv[0]);

        domid = strtol(argv[2], NULL, 0);
        gfn = strtol(argv[3], NULL, 0);
        handle = strtol(argv[4], NULL, 0);
        source_domid = strtol(argv[5], NULL, 0);
        source_gfn = strtol(argv[6], NULL, 0);
        source_handle = strtol(argv[7], NULL, 0);
        R(xc_memshr_share_gfns(xch, source_domid, source_gfn, source_handle, domid, gfn, handle));
    }
    else if( !strcasecmp(cmd, "unshare") )
    {
        domid_t domid;
        unsigned long gfn;
        void *map;

        if( argc != 4 )
            return usage(argv[0]);

        domid = strtol(argv[2], NULL, 0);
        gfn = strtol(argv[3], NULL, 0);
        map = xc_map_foreign_range(xch, domid, 4096, PROT_WRITE, gfn);
        if( map )
            munmap(map, 4096);
        R((int)!map);
    }
    else if( !strcasecmp(cmd, "add-to-physmap") )
    {
        domid_t domid;
        unsigned long gfn;
        domid_t source_domid;
        unsigned long source_gfn;
        uint64_t source_handle;

        if( argc != 7 )
            return usage(argv[0]);

        domid = strtol(argv[2], NULL, 0);
        gfn = strtol(argv[3], NULL, 0);
        source_domid = strtol(argv[4], NULL, 0);
        source_gfn = strtol(argv[5], NULL, 0);
        source_handle = strtol(argv[6], NULL, 0);
        R(xc_memshr_add_to_physmap(xch, source_domid, source_gfn, source_handle, domid, gfn));
    }
    else if( !strcasecmp(cmd, "debug-gfn") )
    {
        domid_t domid;
        unsigned long gfn;

        if( argc != 4 )
            return usage(argv[0]);

        domid = strtol(argv[2], NULL, 0);
        gfn = strtol(argv[3], NULL, 0);
        R(xc_memshr_debug_gfn(xch, domid, gfn));
    }
    else if( !strcasecmp(cmd, "audit") )
    {
        int rc = xc_memshr_audit(xch);
        if ( rc < 0 )
        {
            printf("error executing xc_memshr_audit: %s\n", strerror(errno));
            return rc;
        }
        printf("Audit returned %d errors.\n", rc);
    }

    return 0;
}
