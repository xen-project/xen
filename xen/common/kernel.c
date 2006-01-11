/******************************************************************************
 * kernel.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/compile.h>
#include <xen/sched.h>
#include <asm/current.h>
#include <public/nmi.h>
#include <public/version.h>

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

        for ( param = &__setup_start; param <= &__setup_end; param++ )
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

long do_xen_version(int cmd, void *arg)
{
    switch ( cmd )
    {
    case XENVER_version:
    {
        return (XEN_VERSION<<16) | (XEN_SUBVERSION);
    }

    case XENVER_extraversion:
    {
        xen_extraversion_t extraversion;
        safe_strcpy(extraversion, XEN_EXTRAVERSION);
        if ( copy_to_user(arg, extraversion, sizeof(extraversion)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_compile_info:
    {
        struct xen_compile_info info;
        safe_strcpy(info.compiler,       XEN_COMPILER);
        safe_strcpy(info.compile_by,     XEN_COMPILE_BY);
        safe_strcpy(info.compile_domain, XEN_COMPILE_DOMAIN);
        safe_strcpy(info.compile_date,   XEN_COMPILE_DATE);
        if ( copy_to_user(arg, &info, sizeof(info)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_capabilities:
    {
        xen_capabilities_info_t info;
        extern void arch_get_xen_caps(xen_capabilities_info_t info);

        memset(info, 0, sizeof(info));
        arch_get_xen_caps(info);

        if ( copy_to_user(arg, info, sizeof(info)) )
            return -EFAULT;
        return 0;
    }
    
    case XENVER_platform_parameters:
    {
        xen_platform_parameters_t params = {
            .virt_start = HYPERVISOR_VIRT_START
        };
        if ( copy_to_user(arg, &params, sizeof(params)) )
            return -EFAULT;
        return 0;
        
    }
    
    case XENVER_changeset:
    {
        xen_changeset_info_t chgset;
        safe_strcpy(chgset, XEN_CHANGESET);
        if ( copy_to_user(arg, chgset, sizeof(chgset)) )
            return -EFAULT;
        return 0;
    }
    }

    return -ENOSYS;
}

long do_nmi_op(unsigned int cmd, void *arg)
{
    long rc = 0;

    switch ( cmd )
    {
    case XENNMI_register_callback:
        if ( (current->domain->domain_id != 0) || (current->vcpu_id != 0) )
            rc = -EINVAL;
        else
            current->nmi_addr = (unsigned long)arg;
        printk("***** NMI handler at 0x%lx\n", current->nmi_addr);
        break;
    case XENNMI_unregister_callback:
        current->nmi_addr = 0;
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
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
