/******************************************************************************
 * kernel.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/version.h>
#include <xen/sched.h>
#include <xen/shadow.h>
#include <xen/nmi.h>
#include <xen/guest_access.h>
#include <asm/current.h>
#include <public/nmi.h>
#include <public/version.h>
#ifdef CONFIG_X86
#include <asm/shared.h>
#endif

#ifndef COMPAT

int tainted;

void cmdline_parse(char *cmdline)
{
    char opt[100], *optval, *q;
    const char *p = cmdline;
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
        {
            if ( (q-opt) < (sizeof(opt)-1) ) /* avoid overflow */
                *q++ = *p;
            p++;
        }
        *q = '\0';

        /* Search for value part of a key=value option. */
        optval = strchr(opt, '=');
        if ( optval != NULL )
            *optval++ = '\0'; /* nul-terminate the option value */
        else
            optval = q;       /* default option value is empty string */

        for ( param = &__setup_start; param <= &__setup_end; param++ )
        {
            if ( strcmp(param->name, opt ) != 0 )
                continue;

            switch ( param->type )
            {
            case OPT_STR:
                strlcpy(param->var, optval, param->len);
                break;
            case OPT_UINT:
                *(unsigned int *)param->var =
                    simple_strtol(optval, (const char **)&optval, 0);
                break;
            case OPT_BOOL:
                *(int *)param->var = 1;
                break;
            case OPT_CUSTOM:
                ((void (*)(const char *))param->var)(optval);
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
        snprintf(str, TAINT_STRING_MAX_LEN, "Tainted: %c%c%c%c",
                 tainted & TAINT_UNSAFE_SMP ? 'S' : ' ',
                 tainted & TAINT_MACHINE_CHECK ? 'M' : ' ',
                 tainted & TAINT_BAD_PAGE ? 'B' : ' ',
                 tainted & TAINT_SYNC_CONSOLE ? 'C' : ' ');
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

# define DO(fn) long do_##fn

#endif

/*
 * Simple hypercalls.
 */

DO(xen_version)(int cmd, XEN_GUEST_HANDLE(void) arg)
{
    switch ( cmd )
    {
    case XENVER_version:
    {
        return (xen_major_version() << 16) | xen_minor_version();
    }

    case XENVER_extraversion:
    {
        xen_extraversion_t extraversion;
        safe_strcpy(extraversion, xen_extra_version());
        if ( copy_to_guest(arg, (char *)extraversion, sizeof(extraversion)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_compile_info:
    {
        struct xen_compile_info info;
        safe_strcpy(info.compiler,       xen_compiler());
        safe_strcpy(info.compile_by,     xen_compile_by());
        safe_strcpy(info.compile_domain, xen_compile_domain());
        safe_strcpy(info.compile_date,   xen_compile_date());
        if ( copy_to_guest(arg, &info, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_capabilities:
    {
        xen_capabilities_info_t info;
        extern void arch_get_xen_caps(xen_capabilities_info_t *info);

        memset(info, 0, sizeof(info));
        arch_get_xen_caps(&info);

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
        safe_strcpy(chgset, xen_changeset());
        if ( copy_to_guest(arg, (char *)chgset, sizeof(chgset)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_get_features:
    {
        xen_feature_info_t fi;
        struct domain *d = current->domain;

        if ( copy_from_guest(&fi, arg, 1) )
            return -EFAULT;

        switch ( fi.submap_idx )
        {
        case 0:
            fi.submap = 0;
            if ( VM_ASSIST(d, VMASST_TYPE_pae_extended_cr3) )
                fi.submap |= (1U << XENFEAT_pae_pgdir_above_4gb);
            if ( shadow_mode_translate(current->domain) )
                fi.submap |= 
                    (1U << XENFEAT_writable_page_tables) |
                    (1U << XENFEAT_auto_translated_physmap);
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

    case XENVER_pagesize:
    {
        return (!guest_handle_is_null(arg) ? -EINVAL : PAGE_SIZE);
    }

    case XENVER_guest_handle:
    {
        if ( copy_to_guest(arg, (char *)current->domain->handle,
                           sizeof(current->domain->handle)) )
            return -EFAULT;
        return 0;
    }    
    }

    return -ENOSYS;
}

#ifndef COMPAT

long register_guest_nmi_callback(unsigned long address)
{
    struct vcpu *v = current;
    struct domain *d = current->domain;

    if ( (d->domain_id != 0) || (v->vcpu_id != 0) )
        return -EINVAL;

    v->nmi_addr = address;
#ifdef CONFIG_X86
    /*
     * If no handler was registered we can 'lose the NMI edge'. Re-assert it
     * now.
     */
    if ( arch_get_nmi_reason(d) != 0 )
        v->nmi_pending = 1;
#endif

    return 0;
}

long unregister_guest_nmi_callback(void)
{
    struct vcpu *v = current;

    v->nmi_addr = 0;

    return 0;
}

#endif

DO(nmi_op)(unsigned int cmd, XEN_GUEST_HANDLE(void) arg)
{
    struct xennmi_callback cb;
    long rc = 0;

    switch ( cmd )
    {
    case XENNMI_register_callback:
        rc = -EFAULT;
        if ( copy_from_guest(&cb, arg, 1) )
            break;
        rc = register_guest_nmi_callback(cb.handler_address);
        break;
    case XENNMI_unregister_callback:
        rc = unregister_guest_nmi_callback();
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

DO(vm_assist)(unsigned int cmd, unsigned int type)
{
    return vm_assist(current->domain, cmd, type);
}

DO(ni_hypercall)(void)
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
