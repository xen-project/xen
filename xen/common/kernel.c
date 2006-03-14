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
#include <xen/shadow.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <public/nmi.h>
#include <public/version.h>

int tainted;

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

/**
 *      print_tainted - return a string to represent the kernel taint state.
 *
 *  'S' - SMP with CPUs not designed for SMP.
 *  'M' - Machine had a machine check experience.
 *  'B' - System has hit bad_page.
 *
 *      The string is overwritten by the next call to print_taint().
 */
char *print_tainted(char *str)
{
    if ( tainted )
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Tainted: %c%c%c",
                 tainted & TAINT_UNSAFE_SMP ? 'S' : ' ',
                 tainted & TAINT_MACHINE_CHECK ? 'M' : ' ',
                 tainted & TAINT_BAD_PAGE ? 'B' : ' ');
    }
    else
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Not tainted");
    }

    return str;
}

void add_taint(unsigned flag)
{
    tainted |= flag;
}

/*
 * Simple hypercalls.
 */

long do_xen_version(int cmd, GUEST_HANDLE(void) arg)
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
        if ( copy_to_guest(arg, (char *)extraversion, sizeof(extraversion)) )
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
        if ( copy_to_guest(arg, &info, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_capabilities:
    {
        xen_capabilities_info_t info;
        extern void arch_get_xen_caps(xen_capabilities_info_t info);

        memset(info, 0, sizeof(info));
        arch_get_xen_caps(info);

        if ( copy_to_guest(arg, (char *)info, sizeof(info)) )
            return -EFAULT;
        return 0;
    }
    
    case XENVER_platform_parameters:
    {
        xen_platform_parameters_t params = {
            .virt_start = HYPERVISOR_VIRT_START
        };
        if ( copy_to_guest(arg, &params, 1) )
            return -EFAULT;
        return 0;
        
    }
    
    case XENVER_changeset:
    {
        xen_changeset_info_t chgset;
        safe_strcpy(chgset, XEN_CHANGESET);
        if ( copy_to_guest(arg, (char *)chgset, sizeof(chgset)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_get_features:
    {
        xen_feature_info_t fi;

        if ( copy_from_guest(&fi, arg, 1) )
            return -EFAULT;

        switch ( fi.submap_idx )
        {
        case 0:
            fi.submap = 0;
            if ( shadow_mode_translate(current->domain) )
                fi.submap |= 
                    (1U << XENFEAT_writable_page_tables) |
                    (1U << XENFEAT_auto_translated_physmap) |
                    (1U << XENFEAT_pae_pgdir_above_4gb);
            if ( supervisor_mode_kernel )
                fi.submap |= 1U << XENFEAT_supervisor_mode_kernel;
            break;
        default:
            return -EINVAL;
        }

        if ( copy_to_guest(arg, &fi, 1) )
            return -EFAULT;
        return 0;
    }

    }

    return -ENOSYS;
}

long do_nmi_op(unsigned int cmd, GUEST_HANDLE(void) arg)
{
    struct vcpu *v = current;
    struct domain *d = current->domain;
    struct xennmi_callback cb;
    long rc = 0;

    switch ( cmd )
    {
    case XENNMI_register_callback:
        rc = -EINVAL;
        if ( (d->domain_id != 0) || (v->vcpu_id != 0) )
            break;

        rc = -EFAULT;
        if ( copy_from_guest(&cb, arg, 1) )
            break;

        v->nmi_addr = cb.handler_address;
#ifdef CONFIG_X86
        /*
         * If no handler was registered we can 'lose the NMI edge'. Re-assert 
         * it now.
         */
        if ( d->shared_info->arch.nmi_reason != 0 )
            set_bit(_VCPUF_nmi_pending, &v->vcpu_flags);
#endif
        rc = 0;
        break;
    case XENNMI_unregister_callback:
        v->nmi_addr = 0;
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
