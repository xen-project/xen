/******************************************************************************
 * kernel.c
 * 
 * This file should contain architecture-independent bootstrap and low-level
 * help routines. It's a bit x86/PC specific right now!
 * 
 * Copyright (c) 2002-2003 K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/compile.h>
#include <xen/sched.h>
#include <asm/current.h>

void cmdline_parse(char *cmdline)
{
    char opt[100], *optval, *p = cmdline, *q;
    struct kernel_param *param;
    
    if ( p == NULL )
        return;

    /* Skip whitespace and the image name. */
    while ( *p == ' ' )
        p++;
    if ( (p = strchr(p, ' ')) == NULL )
        return;

    for ( ; ; )
    {
        /* Skip whitespace. */
        while ( *p == ' ' )
            p++;
        if ( *p == '\0' )
            break;

        /* Grab the next whitespace-delimited option. */
        q = opt;
        while ( (*p != ' ') && (*p != '\0') )
            *q++ = *p++;
        *q = '\0';

        /* Search for value part of a key=value option. */
        optval = strchr(opt, '=');
        if ( optval != NULL )
            *optval++ = '\0';

        for ( param = &__setup_start; param != &__setup_end; param++ )
        {
            if ( strcmp(param->name, opt ) != 0 )
                continue;

            switch ( param->type )
            {
            case OPT_STR:
                if ( optval != NULL )
                {
                    strncpy(param->var, optval, param->len);
                    ((char *)param->var)[param->len-1] = '\0';
                }
                break;
            case OPT_UINT:
                if ( optval != NULL )
                    *(unsigned int *)param->var =
                        simple_strtol(optval, (char **)&optval, 0);
                break;
            case OPT_BOOL:
                *(int *)param->var = 1;
                break;
            case OPT_CUSTOM:
                if ( optval != NULL )
                    ((void (*)(char *))param->var)(optval);
                break;
            }
        }
    }
}

/*
 * Simple hypercalls.
 */

long do_xen_version(int cmd)
{
    if ( cmd != 0 )
        return -ENOSYS;
    return (XEN_VERSION<<16) | (XEN_SUBVERSION);
}

long do_vm_assist(unsigned int cmd, unsigned int type)
{
    return vm_assist(current->domain, cmd, type);
}

long do_ni_hypercall(void)
{
    /* No-op hypercall. */
    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
