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

void cmdline_parse(char *cmdline)
{
    unsigned char *opt_end, *opt;
    struct kernel_param *param;
    
    if ( cmdline == NULL )
        return;

    while ( *cmdline == ' ' )
        cmdline++;
    cmdline = strchr(cmdline, ' '); /* skip the image name */
    while ( cmdline != NULL )
    {
        while ( *cmdline == ' ' )
            cmdline++;
        if ( *cmdline == '\0' )
            break;
        opt_end = strchr(cmdline, ' ');
        if ( opt_end != NULL )
            *opt_end++ = '\0';
        opt = strchr(cmdline, '=');
        if ( opt != NULL )
            *opt++ = '\0';
        for ( param = &__setup_start; param != &__setup_end; param++ )
        {
            if ( strcmp(param->name, cmdline ) != 0 )
                continue;
            switch ( param->type )
            {
            case OPT_STR:
                if ( opt != NULL )
                {
                    strncpy(param->var, opt, param->len);
                    ((char *)param->var)[param->len-1] = '\0';
                }
                break;
            case OPT_UINT:
                if ( opt != NULL )
                    *(unsigned int *)param->var =
                        simple_strtol(opt, (char **)&opt, 0);
                break;
            case OPT_BOOL:
                *(int *)param->var = 1;
                break;
            }
        }
        cmdline = opt_end;
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

vm_assist_info_t vm_assist_info[MAX_VMASST_TYPE + 1];
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
 */
