/******************************************************************************
 * kernel.c
 *
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/param.h>
#include <xen/version.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xen/hypfs.h>
#include <xsm/xsm.h>
#include <asm/current.h>
#include <public/version.h>

#ifdef CONFIG_COMPAT
#include <compat/version.h>

CHECK_build_id;
CHECK_compile_info;
CHECK_feature_info;
CHECK_varbuf;
#endif

enum system_state system_state = SYS_STATE_early_boot;

#ifdef CONFIG_HAS_DIT
bool __ro_after_init opt_dit = IS_ENABLED(CONFIG_DIT_DEFAULT);
boolean_param("dit", opt_dit);
#endif

static xen_commandline_t saved_cmdline;
static const char __initconst opt_builtin_cmdline[] = CONFIG_CMDLINE;
char __ro_after_init xen_cap_info[128];

static int assign_integer_param(const struct kernel_param *param, uint64_t val)
{
    switch ( param->len )
    {
    case sizeof(uint8_t):
        if ( val > UINT8_MAX && val < (uint64_t)INT8_MIN )
            return -EOVERFLOW;
        *(uint8_t *)param->par.var = val;
        break;
    case sizeof(uint16_t):
        if ( val > UINT16_MAX && val < (uint64_t)INT16_MIN )
            return -EOVERFLOW;
        *(uint16_t *)param->par.var = val;
        break;
    case sizeof(uint32_t):
        if ( val > UINT32_MAX && val < (uint64_t)INT32_MIN )
            return -EOVERFLOW;
        *(uint32_t *)param->par.var = val;
        break;
    case sizeof(uint64_t):
        *(uint64_t *)param->par.var = val;
        break;
    default:
        BUG();
    }

    return 0;
}

static int parse_params(const char *cmdline, const struct kernel_param *start,
                        const struct kernel_param *end)
{
    char opt[MAX_PARAM_SIZE], *optval, *optkey, *q;
    const char *p = cmdline, *key;
    const struct kernel_param *param;
    int rc, final_rc = 0;
    bool bool_assert, found;

    for ( ; ; )
    {
        /* Skip whitespace. */
        while ( *p == ' ' )
            p++;
        if ( *p == '\0' )
            break;

        /* Grab the next whitespace-delimited option. */
        q = optkey = opt;
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
        {
            *optval++ = '\0'; /* nul-terminate the option value */
            q = strpbrk(opt, "([{<");
        }
        else
        {
            optval = q;       /* default option value is empty string */
            q = NULL;
        }

        /* Boolean parameters can be inverted with 'no-' prefix. */
        key = optkey;
        bool_assert = !!strncmp("no-", optkey, 3);
        if ( !bool_assert )
            optkey += 3;

        rc = 0;
        found = false;
        for ( param = start; param < end; param++ )
        {
            int rctmp;
            const char *s;

            if ( strcmp(param->name, optkey) )
            {
                if ( param->type == OPT_CUSTOM && q &&
                     strlen(param->name) == q + 1 - opt &&
                     !strncmp(param->name, opt, q + 1 - opt) )
                {
                    found = true;
                    optval[-1] = '=';
                    rctmp = param->par.func(q);
                    optval[-1] = '\0';
                    if ( !rc )
                        rc = rctmp;
                }
                continue;
            }

            rctmp = 0;
            found = true;
            switch ( param->type )
            {
            case OPT_STR:
                strlcpy(param->par.var, optval, param->len);
                break;
            case OPT_UINT:
                rctmp = assign_integer_param(
                    param,
                    simple_strtoll(optval, &s, 0));
                if ( *s )
                    rctmp = -EINVAL;
                break;
            case OPT_BOOL:
                rctmp = *optval ? parse_bool(optval, NULL) : 1;
                if ( rctmp < 0 )
                    break;
                if ( !rctmp )
                    bool_assert = !bool_assert;
                rctmp = 0;
                assign_integer_param(param, bool_assert);
                break;
            case OPT_SIZE:
                rctmp = assign_integer_param(
                    param,
                    parse_size_and_unit(optval, &s));
                if ( *s )
                    rctmp = -EINVAL;
                break;
            case OPT_CUSTOM:
                rctmp = -EINVAL;
                if ( !bool_assert )
                {
                    if ( *optval )
                        break;
                    safe_strcpy(opt, "no");
                    optval = opt;
                }
                rctmp = param->par.func(optval);
                break;
            case OPT_IGNORE:
                break;
            default:
                BUG();
                break;
            }

            if ( !rc )
                rc = rctmp;
        }

        if ( rc )
        {
            printk("parameter \"%s\" has invalid value \"%s\", rc=%d!\n",
                    key, optval, rc);
            final_rc = rc;
        }
        if ( !found )
        {
            printk("parameter \"%s\" unknown!\n", key);
            final_rc = -EINVAL;
        }
    }

    return final_rc;
}

static void __init _cmdline_parse(const char *cmdline)
{
    parse_params(cmdline, __setup_start, __setup_end);
}

/**
 *    cmdline_parse -- parses the xen command line.
 * If CONFIG_CMDLINE is set, it would be parsed prior to @cmdline.
 * But if CONFIG_CMDLINE_OVERRIDE is set to y, @cmdline will be ignored.
 */
void __init cmdline_parse(const char *cmdline)
{
    if ( opt_builtin_cmdline[0] )
    {
        printk("Built-in command line: %s\n", opt_builtin_cmdline);
        _cmdline_parse(opt_builtin_cmdline);
    }

#ifndef CONFIG_CMDLINE_OVERRIDE
    if ( cmdline == NULL )
        return;

    safe_strcpy(saved_cmdline, cmdline);
    _cmdline_parse(cmdline);
#endif
}

int parse_bool(const char *s, const char *e)
{
    size_t len = e ? ({ ASSERT(e >= s); e - s; }) : strlen(s);

    switch ( len )
    {
    case 1:
        if ( *s == '1' )
            return 1;
        if ( *s == '0' )
            return 0;
        break;

    case 2:
        if ( !strncmp("on", s, 2) )
            return 1;
        if ( !strncmp("no", s, 2) )
            return 0;
        break;

    case 3:
        if ( !strncmp("yes", s, 3) )
            return 1;
        if ( !strncmp("off", s, 3) )
            return 0;
        break;

    case 4:
        if ( !strncmp("true", s, 4) )
            return 1;
        break;

    case 5:
        if ( !strncmp("false", s, 5) )
            return 0;
        break;

    case 6:
        if ( !strncmp("enable", s, 6) )
            return 1;
        break;

    case 7:
        if ( !strncmp("disable", s, 7) )
            return 0;
        break;
    }

    return -1;
}

int parse_boolean(const char *name, const char *s, const char *e)
{
    size_t slen, nlen;
    bool has_neg_prefix = !strncmp(s, "no-", 3);

    if ( has_neg_prefix )
        s += 3;

    slen = e ? ({ ASSERT(e >= s); e - s; }) : strlen(s);
    nlen = strlen(name);

    /* Does s now start with name? */
    if ( slen < nlen || strncmp(s, name, nlen) )
        return -1;

    /* Exact, unadorned name?  Result depends on the 'no-' prefix. */
    if ( slen == nlen )
        return !has_neg_prefix;

    /* Inexact match with a 'no-' prefix?  Not valid. */
    if ( has_neg_prefix )
        return -1;

    /* =$SOMETHING?  Defer to the regular boolean parsing. */
    if ( s[nlen] == '=' )
    {
        int b = parse_bool(&s[nlen + 1], e);

        if ( b >= 0 )
            return b;

        /* Not a boolean, but the name matched.  Signal specially. */
        return -2;
    }

    /* Unrecognised.  Give up. */
    return -1;
}

int __init parse_signed_integer(const char *name, const char *s, const char *e,
                                long long *val)
{
    size_t slen, nlen;
    const char *str;
    long long pval;

    slen = e ? ({ ASSERT(e >= s); e - s; }) : strlen(s);
    nlen = strlen(name);

    if ( !e )
        e = s + slen;

    /* Check that this is the name we're looking for and a value was provided */
    if ( slen <= nlen || strncmp(s, name, nlen) || s[nlen] != '=' )
        return -1;

    pval = simple_strtoll(&s[nlen + 1], &str, 10);

    /* Number not recognised */
    if ( str != e )
        return -2;

    *val = pval;

    return 0;
}

int cmdline_strcmp(const char *frag, const char *name)
{
    for ( ; ; frag++, name++ )
    {
        unsigned char f = *frag, n = *name;
        int res = f - n;

        if ( res || n == '\0' )
        {
            /*
             * NUL in 'name' matching a comma, colon, semicolon or equals in
             * 'frag' implies success.
             */
            if ( n == '\0' && (f == ',' || f == ':' || f == ';' || f == '=') )
                res = 0;

            return res;
        }
    }
}

unsigned int tainted;

/**
 *      print_tainted - return a string to represent the kernel taint state.
 *
 *  'C' - Console output is synchronous.
 *  'E' - An error (e.g. a machine check exceptions) has been injected.
 *  'H' - HVM forced emulation prefix is permitted.
 *  'I' - Platform is insecure (usually due to an errata on the platform).
 *  'M' - Machine had a machine check experience.
 *  'S' - Out of spec CPU (Incompatible features on one or more cores).
 *
 *      The string is overwritten by the next call to print_taint().
 */
char *print_tainted(char *str)
{
    if ( tainted )
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Tainted: %c%c%c%c%c%c",
                 tainted & TAINT_MACHINE_INSECURE ? 'I' : ' ',
                 tainted & TAINT_MACHINE_CHECK ? 'M' : ' ',
                 tainted & TAINT_SYNC_CONSOLE ? 'C' : ' ',
                 tainted & TAINT_ERROR_INJECT ? 'E' : ' ',
                 tainted & TAINT_HVM_FEP ? 'H' : ' ',
                 tainted & TAINT_CPU_OUT_OF_SPEC ? 'S' : ' ');
    }
    else
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Not tainted");
    }

    return str;
}

void add_taint(unsigned int taint)
{
    tainted |= taint;
}

extern const initcall_t __initcall_start[], __presmp_initcall_end[],
    __initcall_end[];

void __init do_presmp_initcalls(void)
{
    const initcall_t *call;
    for ( call = __initcall_start; call < __presmp_initcall_end; call++ )
        (*call)();
}

void __init do_initcalls(void)
{
    const initcall_t *call;
    for ( call = __presmp_initcall_end; call < __initcall_end; call++ )
        (*call)();
}

#ifdef CONFIG_HYPFS
static unsigned int __read_mostly major_version;
static unsigned int __read_mostly minor_version;

static HYPFS_DIR_INIT(buildinfo, "buildinfo");
static HYPFS_DIR_INIT(compileinfo, "compileinfo");
static HYPFS_DIR_INIT(version, "version");
static HYPFS_UINT_INIT(major, "major", major_version);
static HYPFS_UINT_INIT(minor, "minor", minor_version);
static HYPFS_STRING_INIT(changeset, "changeset");
static HYPFS_STRING_INIT(compiler, "compiler");
static HYPFS_STRING_INIT(compile_by, "compile_by");
static HYPFS_STRING_INIT(compile_date, "compile_date");
static HYPFS_STRING_INIT(compile_domain, "compile_domain");
static HYPFS_STRING_INIT(extra, "extra");

#ifdef CONFIG_HYPFS_CONFIG
static HYPFS_STRING_INIT(config, "config");
#endif

static int __init cf_check buildinfo_init(void)
{
    hypfs_add_dir(&hypfs_root, &buildinfo, true);

    hypfs_string_set_reference(&changeset, xen_changeset());
    hypfs_add_leaf(&buildinfo, &changeset, true);

    hypfs_add_dir(&buildinfo, &compileinfo, true);
    hypfs_string_set_reference(&compiler, xen_compiler());
    hypfs_string_set_reference(&compile_by, xen_compile_by());
    hypfs_string_set_reference(&compile_date, xen_compile_date());
    hypfs_string_set_reference(&compile_domain, xen_compile_domain());
    hypfs_add_leaf(&compileinfo, &compiler, true);
    hypfs_add_leaf(&compileinfo, &compile_by, true);
    hypfs_add_leaf(&compileinfo, &compile_date, true);
    hypfs_add_leaf(&compileinfo, &compile_domain, true);

    major_version = xen_major_version();
    minor_version = xen_minor_version();
    hypfs_add_dir(&buildinfo, &version, true);
    hypfs_string_set_reference(&extra, xen_extra_version());
    hypfs_add_leaf(&version, &extra, true);
    hypfs_add_leaf(&version, &major, true);
    hypfs_add_leaf(&version, &minor, true);

#ifdef CONFIG_HYPFS_CONFIG
    config.e.encoding = XEN_HYPFS_ENC_GZIP;
    config.e.size = xen_config_data_size;
    config.u.content = xen_config_data;
    hypfs_add_leaf(&buildinfo, &config, true);
#endif

    return 0;
}
__initcall(buildinfo_init);

static HYPFS_DIR_INIT(params, "params");

static int __init cf_check param_init(void)
{
    struct param_hypfs *param;

    hypfs_add_dir(&hypfs_root, &params, true);

    for ( param = __paramhypfs_start; param < __paramhypfs_end; param++ )
    {
        if ( param->init_leaf )
            param->init_leaf(param);
        else if ( param->hypfs.e.type == XEN_HYPFS_TYPE_STRING )
            param->hypfs.e.size = strlen(param->hypfs.u.content) + 1;
        hypfs_add_leaf(&params, &param->hypfs, true);
    }

    return 0;
}
__initcall(param_init);
#endif

static long xenver_varbuf_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xen_varbuf user_str;
    const char *str = NULL;
    size_t sz;
    int rc;

    switch ( cmd )
    {
    case XENVER_build_id:
    {
        unsigned int local_sz;

        rc = xen_build_id((const void **)&str, &local_sz);
        if ( rc )
            return rc;

        sz = local_sz;
        goto have_len;
    }

    case XENVER_extraversion2:
        str = xen_extra_version();
        break;

    case XENVER_changeset2:
        str = xen_changeset();
        break;

    case XENVER_commandline2:
        str = saved_cmdline;
        break;

    case XENVER_capabilities2:
        str = xen_cap_info;
        break;

    default:
        ASSERT_UNREACHABLE();
        return -ENODATA;
    }

    sz = strlen(str);

 have_len:
    if ( sz > KB(64) ) /* Arbitrary limit.  Avoid long-running operations. */
        return -E2BIG;

    if ( guest_handle_is_null(arg) ) /* Length request */
        return sz;

    if ( copy_from_guest(&user_str, arg, 1) )
        return -EFAULT;

    if ( sz > user_str.len )
        return -ENOBUFS;

    if ( copy_to_guest_offset(arg, offsetof(struct xen_varbuf, buf),
                              str, sz) )
        return -EFAULT;

    return sz;
}

long do_xen_version(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    bool deny = xsm_xen_version(XSM_OTHER, cmd);

    switch ( cmd )
    {
    case XENVER_version:
        return (xen_major_version() << 16) | xen_minor_version();

    case XENVER_extraversion:
    {
        xen_extraversion_t extraversion;

        memset(extraversion, 0, sizeof(extraversion));
        safe_strcpy(extraversion, deny ? xen_deny() : xen_extra_version());
        if ( copy_to_guest(arg, extraversion, ARRAY_SIZE(extraversion)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_compile_info:
    {
        xen_compile_info_t info;

        memset(&info, 0, sizeof(info));
        safe_strcpy(info.compiler,       deny ? xen_deny() : xen_compiler());
        safe_strcpy(info.compile_by,     deny ? xen_deny() : xen_compile_by());
        safe_strcpy(info.compile_domain, deny ? xen_deny() : xen_compile_domain());
        safe_strcpy(info.compile_date,   deny ? xen_deny() : xen_compile_date());
        if ( copy_to_guest(arg, &info, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_capabilities:
    {
        xen_capabilities_info_t info;

        memset(info, 0, sizeof(info));
        if ( !deny )
            safe_strcpy(info, xen_cap_info);

        if ( copy_to_guest(arg, info, ARRAY_SIZE(info)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_platform_parameters:
    {
        const struct vcpu *curr = current;

#ifdef CONFIG_COMPAT
        if ( curr->hcall_compat )
        {
            compat_platform_parameters_t params = {
                .virt_start = is_pv_vcpu(curr)
                            ? HYPERVISOR_COMPAT_VIRT_START(curr->domain)
                            : 0,
            };

            if ( copy_to_guest(arg, &params, 1) )
                return -EFAULT;
        }
        else
#endif
        {
            xen_platform_parameters_t params = {
                /*
                 * Out of an abundance of caution, retain the useless return
                 * value for 64bit PV guests, but in release builds only.
                 *
                 * This is not expected to cause any problems, but if it does,
                 * the developer impacted will be the one best suited to fix
                 * the caller not to issue this hypercall.
                 */
                .virt_start = !IS_ENABLED(CONFIG_DEBUG) && is_pv_vcpu(curr)
                              ? HYPERVISOR_VIRT_START
                              : 0,
            };

            if ( copy_to_guest(arg, &params, 1) )
                return -EFAULT;
        }

        return 0;
    }

    case XENVER_changeset:
    {
        xen_changeset_info_t chgset;

        memset(chgset, 0, sizeof(chgset));
        safe_strcpy(chgset, deny ? xen_deny() : xen_changeset());
        if ( copy_to_guest(arg, chgset, ARRAY_SIZE(chgset)) )
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
            fi.submap = (1U << XENFEAT_memory_op_vnode_supported) |
#ifdef CONFIG_X86
                        (1U << XENFEAT_vcpu_time_phys_area) |
#endif
                        (1U << XENFEAT_runstate_phys_area);
            if ( VM_ASSIST(d, pae_extended_cr3) )
                fi.submap |= (1U << XENFEAT_pae_pgdir_above_4gb);
            if ( paging_mode_translate(d) )
                fi.submap |=
                    (1U << XENFEAT_writable_page_tables) |
                    (1U << XENFEAT_auto_translated_physmap);
            if ( is_hardware_domain(d) )
                fi.submap |= 1U << XENFEAT_dom0;
#ifdef CONFIG_ARM
            fi.submap |= (1U << XENFEAT_ARM_SMCCC_supported);
#endif
#ifdef CONFIG_X86
            if ( is_pv_domain(d) )
                fi.submap |= (1U << XENFEAT_mmu_pt_update_preserve_ad) |
                             (1U << XENFEAT_highmem_assist) |
                             (1U << XENFEAT_gnttab_map_avail_bits);
            else
                fi.submap |= (1U << XENFEAT_hvm_safe_pvclock) |
                             (1U << XENFEAT_hvm_callback_vector) |
                             (has_pirq(d) ? (1U << XENFEAT_hvm_pirqs) : 0);
            fi.submap |= (1U << XENFEAT_dm_msix_all_writes);
#endif
            if ( !paging_mode_translate(d) || is_domain_direct_mapped(d) )
                fi.submap |= (1U << XENFEAT_direct_mapped);
            else
                fi.submap |= (1U << XENFEAT_not_direct_mapped);
            break;
        default:
            return -EINVAL;
        }

        if ( __copy_to_guest(arg, &fi, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_pagesize:
        if ( deny )
            return 0;
        return (!guest_handle_is_null(arg) ? -EINVAL : PAGE_SIZE);

    case XENVER_guest_handle:
    {
        xen_domain_handle_t hdl;

        if ( deny )
            memset(&hdl, 0, ARRAY_SIZE(hdl));

        BUILD_BUG_ON(ARRAY_SIZE(current->domain->handle) != ARRAY_SIZE(hdl));

        if ( copy_to_guest(arg, deny ? hdl : current->domain->handle,
                           ARRAY_SIZE(hdl) ) )
            return -EFAULT;
        return 0;
    }

    case XENVER_commandline:
    {
        size_t len = ARRAY_SIZE(saved_cmdline);

        if ( deny )
            len = strlen(xen_deny()) + 1;

        if ( copy_to_guest(arg, deny ? xen_deny() : saved_cmdline, len) )
            return -EFAULT;
        return 0;
    }

    case XENVER_build_id:
    case XENVER_extraversion2:
    case XENVER_capabilities2:
    case XENVER_changeset2:
    case XENVER_commandline2:
        if ( deny )
            return -EPERM;
        return xenver_varbuf_op(cmd, arg);
    }

    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
