/*
 * TSX settings and consistency tests
 *
 * This tests various behaviours and invariants with regards to TSX.  It
 * ideally wants running for several microcode versions, and all applicable
 * tsx= commandline settings, on a single CPU, including after an S3
 * suspend/resume event.
 *
 * It tests specifically:
 *  - The consistency of MSR_TSX_CTRL/MSR_TSX_FORCE_ABORT values across the
 *    system, and their accessibility WRT data in the host CPU policy.
 *  - The actual behaviour of RTM on the system.
 *  - Cross-check the default/max policies based on the actual RTM behaviour.
 *  - Create some guests, check their defaults, and check that the defaults
 *    can be changed.
 */

#define _GNU_SOURCE

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>

#include <xenctrl.h>
#include <xenguest.h>
#include <xen-tools/common-macros.h>

#include "xg_private.h"

enum {
#define XEN_CPUFEATURE(name, value) X86_FEATURE_##name = value,
#include <xen/arch-x86/cpufeatureset.h>
};
#define bitmaskof(idx)      (1u << ((idx) & 31))

#define MSR_ARCH_CAPABILITIES               0x0000010a
#define  ARCH_CAPS_TSX_CTRL                 (1 <<  7)
#define MSR_TSX_FORCE_ABORT                 0x0000010f
#define MSR_TSX_CTRL                        0x00000122
#define MSR_MCU_OPT_CTRL                    0x00000123

static unsigned int nr_failures;
#define fail(fmt, ...)                          \
({                                              \
    nr_failures++;                              \
    (void)printf(fmt, ##__VA_ARGS__);           \
})

static xc_interface *xch;

/*
 * Policies, arranged as an array for easy collection of all of them.  We
 * don't care about the raw policy (index 0) so reuse that for the guest
 * policy.
 */
static struct xc_cpu_policy policies[6];
#define guest_policy policies[0]
#define host         policies[XEN_SYSCTL_cpu_policy_host]
#define pv_max       policies[XEN_SYSCTL_cpu_policy_pv_max]
#define hvm_max      policies[XEN_SYSCTL_cpu_policy_hvm_max]
#define pv_default   policies[XEN_SYSCTL_cpu_policy_pv_default]
#define hvm_default  policies[XEN_SYSCTL_cpu_policy_hvm_default]

static bool xen_has_pv = true, xen_has_hvm = true;

static xc_physinfo_t physinfo;

static enum rtm_behaviour {
    RTM_UD,
    RTM_OK,
    RTM_ABORT,
} rtm_behaviour;

/*
 * Test a specific TSX MSR for consistency across the system, taking into
 * account whether it ought to be accessible or not.
 *
 * We can't query offline CPUs, so skip those if encountered.  We don't care
 * particularly for the exact MSR value, but we do care that it is the same
 * everywhere.
 */
static void test_tsx_msr_consistency(unsigned int msr, bool accessible)
{
    uint64_t cpu0_val = ~0;

    for ( unsigned int cpu = 0; cpu <= physinfo.max_cpu_id; ++cpu )
    {
        xc_resource_entry_t ent = {
            .u.cmd = XEN_RESOURCE_OP_MSR_READ,
            .idx = msr,
        };
        xc_resource_op_t op = {
            .cpu = cpu,
            .entries = &ent,
            .nr_entries = 1,
        };
        int rc = xc_resource_op(xch, 1, &op);

        if ( rc < 0 )
        {
            /* Don't emit a message for offline CPUs */
            if ( errno != ENODEV )
                fail("  xc_resource_op() for CPU%u failed: rc %d, errno %d - %s\n",
                     cpu, rc, errno, strerror(errno));
            continue;
        }

        if ( accessible )
        {
            if ( rc != 1 )
            {
                fail("  Expected 1 result, got %d\n", rc);
                continue;
            }
            if ( ent.u.ret != 0 )
            {
                fail("  Expected ok, got %d\n", ent.u.ret);
                continue;
            }
        }
        else
        {
            if ( rc != 0 )
                fail("  Expected 0 results, got %u\n", rc);
            else if ( ent.u.ret != -EPERM )
                fail("  Expected -EPERM, got %d\n", ent.u.ret);
            continue;
        }

        if ( cpu == 0 )
        {
            cpu0_val = ent.val;
            printf("  CPU0 val %#"PRIx64"\n", cpu0_val);
        }
        else if ( ent.val != cpu0_val )
            fail("  CPU%u val %#"PRIx64" differs from CPU0 %#"PRIx64"\n",
                 cpu, ent.val, cpu0_val);
    }
}

/*
 * Check all TSX MSRs, and in particular that their accessibility matches what
 * is expressed in the host CPU policy.
 */
static void test_tsx_msrs(void)
{
    printf("Testing MSR_TSX_FORCE_ABORT consistency\n");
    test_tsx_msr_consistency(
        MSR_TSX_FORCE_ABORT, host.policy.feat.tsx_force_abort);

    printf("Testing MSR_TSX_CTRL consistency\n");
    test_tsx_msr_consistency(
        MSR_TSX_CTRL, host.policy.arch_caps.tsx_ctrl);

    printf("Testing MSR_MCU_OPT_CTRL consistency\n");
    test_tsx_msr_consistency(
        MSR_MCU_OPT_CTRL, host.policy.feat.srbds_ctrl);
}

/*
 * Probe for how RTM behaves, deliberately not inspecting CPUID.
 * Distinguishes between "no support at all" (i.e. XBEGIN suffers #UD),
 * working ok, and appearing to always abort.
 */
static enum rtm_behaviour probe_rtm_behaviour(void)
{
    for ( unsigned int i = 0; i < 1000; ++i )
    {
        /*
         * Opencoding the RTM infrastructure from immintrin.h, because we
         * still support older versions of GCC.  Also so we can include #UD
         * detection logic.
         */
#define XBEGIN_STARTED -1
#define XBEGIN_UD      -2
        unsigned int status = XBEGIN_STARTED;

        asm volatile ( ".Lxbegin: .byte 0xc7,0xf8,0,0,0,0" /* XBEGIN 1f; 1: */
                       : "+a" (status) :: "memory" );
        if ( status == XBEGIN_STARTED )
        {
            asm volatile ( ".byte 0x0f,0x01,0xd5" ::: "memory" ); /* XEND */
            return RTM_OK;
        }
        else if ( status == XBEGIN_UD )
            return RTM_UD;
    }

    return RTM_ABORT;
}

static struct sigaction old_sigill;

static void sigill_handler(int signo, siginfo_t *info, void *extra)
{
    extern const char xbegin_label[] asm(".Lxbegin");

    if ( info->si_addr == xbegin_label &&
         memcmp(info->si_addr, "\xc7\xf8\x00\x00\x00\x00", 6) == 0 )
    {
        ucontext_t *context = extra;

        /*
         * Found the XBEGIN instruction.  Step over it, and update `status` to
         * signal #UD.
         */
#if defined(__linux__)
# ifdef __x86_64__
        context->uc_mcontext.gregs[REG_RIP] += 6;
        context->uc_mcontext.gregs[REG_RAX] = XBEGIN_UD;
# else
        context->uc_mcontext.gregs[REG_EIP] += 6;
        context->uc_mcontext.gregs[REG_EAX] = XBEGIN_UD;
# endif

#elif defined(__FreeBSD__)
# ifdef __x86_64__
        context->uc_mcontext.mc_rip += 6;
        context->uc_mcontext.mc_rax = XBEGIN_UD;
# else
        context->uc_mcontext.mc_eip += 6;
        context->uc_mcontext.mc_eax = XBEGIN_UD;
# endif

#elif defined(__NetBSD__)
# ifdef __x86_64__
        context->uc_mcontext.__gregs[_REG_RIP] += 6;
        context->uc_mcontext.__gregs[_REG_RAX] = XBEGIN_UD;
# else
        context->uc_mcontext.__gregs[_REG_EIP] += 6;
        context->uc_mcontext.__gregs[_REG_EAX] = XBEGIN_UD;
# endif

#else
# error Unknown environment - please adjust
#endif
    }
    else
    {
        /*
         * Not the SIGILL we're looking for...  Restore the old handler and
         * try again.  Will likely coredump as a result.
         */
        sigaction(SIGILL, &old_sigill, NULL);
    }
}

static void test_rtm_behaviour(void)
{
    struct sigaction new_sigill = {
        .sa_flags = SA_SIGINFO,
        .sa_sigaction = sigill_handler,
    };
    const char *str;

    printf("Testing RTM behaviour\n");

    /*
     * Install a custom SIGILL handler while probing for RTM behaviour, as the
     * XBEGIN instruction might suffer #UD.
     */
    sigaction(SIGILL, &new_sigill, &old_sigill);
    rtm_behaviour = probe_rtm_behaviour();
    sigaction(SIGILL, &old_sigill, NULL);

    switch ( rtm_behaviour )
    {
    case RTM_UD:    str = "#UD";   break;
    case RTM_OK:    str = "OK";    break;
    case RTM_ABORT: str = "Abort"; break;
    default:        str = NULL;    break;
    }

    if ( str )
        printf("  Got %s\n", str);
    else
        return fail("  Got unexpected behaviour %d\n", rtm_behaviour);

    if ( host.policy.feat.rtm )
    {
        if ( rtm_behaviour == RTM_UD )
            fail("  Host reports RTM, but appears unavailable\n");
    }
    else
    {
        if ( rtm_behaviour != RTM_UD )
            fail("  Host reports no RTM, but appears available\n");
    }
}

static void dump_tsx_details(const struct cpu_policy *p, const char *pref)
{
    printf("  %s RTM %u, HLE %u, TSX_FORCE_ABORT %u, RTM_ALWAYS_ABORT %u, TSX_CTRL %u\n",
           pref,
           p->feat.rtm,
           p->feat.hle,
           p->feat.tsx_force_abort,
           p->feat.rtm_always_abort,
           p->arch_caps.tsx_ctrl);
}

/* Sanity test various invariants we expect in the default/max policies. */
static void test_guest_policies(const struct cpu_policy *max,
                                const struct cpu_policy *def)
{
    dump_tsx_details(max, "Max:");
    dump_tsx_details(def, "Def:");

    if ( max->feat.tsx_force_abort || def->feat.tsx_force_abort ||
         max->feat.srbds_ctrl      || def->feat.srbds_ctrl ||
         max->arch_caps.tsx_ctrl   || def->arch_caps.tsx_ctrl )
        fail("  Xen-only TSX controls offered to guest\n");

    switch ( rtm_behaviour )
    {
    case RTM_UD:
        if ( max->feat.hle              || def->feat.hle ||
             max->feat.rtm              || def->feat.rtm ||
             max->feat.rtm_always_abort || def->feat.rtm_always_abort )
            fail("  HLE/RTM/RTM_AA offered to guests despite not being available\n");
        break;

    case RTM_ABORT:
        if ( def->feat.hle || def->feat.rtm )
             fail("  HLE/RTM offered to guests by default despite not being usable\n");
        if ( !def->feat.rtm_always_abort )
             fail("  RTM_AA not offered to guests by default despite being available\n");
        break;

    case RTM_OK:
        if ( !max->feat.rtm || !def->feat.rtm )
             fail("  RTM not offered to guests despite being available\n");
        break;
    }

    if ( def->feat.hle )
        fail("  Fail: HLE offered in default policy\n");

    if ( def->feat.rtm && def->feat.rtm_always_abort )
        fail("  Fail: Both RTM and RTM_AA offered in default policy\n");
}

static void test_def_max_policies(void)
{
    if ( xen_has_pv )
    {
        printf("Testing PV default/max policies\n");
        test_guest_policies(&pv_max.policy, &pv_default.policy);
    }

    if ( xen_has_hvm )
    {
        printf("Testing HVM default/max policies\n");
        test_guest_policies(&hvm_max.policy, &hvm_default.policy);
    }
}

static void test_guest(struct xen_domctl_createdomain *c)
{
    uint32_t domid = 0;
    int rc;

    rc = xc_domain_create(xch, &domid, c);
    if ( rc )
        return fail("  Domain create failure: %d - %s\n",
                    errno, strerror(errno));

    printf("  Created d%u\n", domid);

    rc = xc_cpu_policy_get_domain(xch, domid, &guest_policy);
    if ( rc )
    {
        fail("  Failed to obtain domain policy: %d - %s\n",
             errno, strerror(errno));
        goto out;
    }

    dump_tsx_details(&guest_policy.policy, "Cur:");

    /*
     * Check defaults given to the guest.
     */
    if ( guest_policy.policy.feat.rtm != (rtm_behaviour == RTM_OK) )
        fail("  RTM %u in guest, despite rtm behaviour\n",
             guest_policy.policy.feat.rtm);

    if ( guest_policy.policy.feat.hle ||
         guest_policy.policy.feat.tsx_force_abort ||
         guest_policy.policy.feat.srbds_ctrl ||
         guest_policy.policy.arch_caps.tsx_ctrl )
        fail("  Unexpected features advertised\n");

    if ( host.policy.feat.rtm )
    {
        unsigned int _7b0, _7d0;

        /*
         * If host RTM is available, all combinations of guest flags should be
         * possible.  Flip both HLE/RTM to check non-default settings.
         */
        _7b0 = (guest_policy.policy.feat.raw[0].b ^=
                (bitmaskof(X86_FEATURE_HLE) | bitmaskof(X86_FEATURE_RTM)));
        _7d0 = (guest_policy.policy.feat.raw[0].d ^=
                bitmaskof(X86_FEATURE_RTM_ALWAYS_ABORT));

        /* Set the new policy. */
        rc = xc_cpu_policy_set_domain(xch, domid, &guest_policy);
        if ( rc )
        {
            fail("  Failed to set domain policy: %d - %s\n",
                 errno, strerror(errno));
            goto out;
        }

        /* Re-get the new policy. */
        rc = xc_cpu_policy_get_domain(xch, domid, &guest_policy);
        if ( rc )
        {
            fail("  Failed to obtain domain policy: %d - %s\n",
                 errno, strerror(errno));
            goto out;
        }

        dump_tsx_details(&guest_policy.policy, "Cur:");

        if ( guest_policy.policy.feat.raw[0].b != _7b0 )
        {
            fail("  Expected CPUID.7[0].b 0x%08x differs from actual 0x%08x\n",
                 _7b0, guest_policy.policy.feat.raw[0].b);
            goto out;
        }

        if ( guest_policy.policy.feat.raw[0].d != _7d0 )
        {
            fail("  Expected CPUID.7[0].d 0x%08x differs from actual 0x%08x\n",
                 _7d0, guest_policy.policy.feat.raw[0].d);
            goto out;
        }
    }

 out:
    rc = xc_domain_destroy(xch, domid);
    if ( rc )
        fail("  Failed to destroy domain: %d - %s\n",
             errno, strerror(errno));
}

static void test_guests(void)
{
    if ( xen_has_pv )
    {
        struct xen_domctl_createdomain c = {
            .max_vcpus = 1,
            .max_grant_frames = 1,
            .grant_opts = XEN_DOMCTL_GRANT_version(1),
        };

        printf("Testing PV guest\n");
        test_guest(&c);
    }

    if ( xen_has_hvm )
    {
        struct xen_domctl_createdomain c = {
            .flags = XEN_DOMCTL_CDF_hvm,
            .max_vcpus = 1,
            .max_grant_frames = 1,
            .grant_opts = XEN_DOMCTL_GRANT_version(1),
            .arch = {
                .emulation_flags = XEN_X86_EMU_LAPIC,
            },
        };

        if ( physinfo.capabilities & XEN_SYSCTL_PHYSCAP_hap )
            c.flags |= XEN_DOMCTL_CDF_hap;
        else if ( !(physinfo.capabilities & XEN_SYSCTL_PHYSCAP_shadow) )
            return fail("  HVM available, but neither HAP nor Shadow\n");

        printf("Testing HVM guest\n");
        test_guest(&c);
    }
}

/* Obtain some general data, then run the tests. */
static void test_tsx(void)
{
    int rc;

    /* Read all policies except raw. */
    for ( unsigned int i = XEN_SYSCTL_cpu_policy_host;
          i <= XEN_SYSCTL_cpu_policy_hvm_default; ++i )
    {
        rc = xc_cpu_policy_get_system(xch, i, &policies[i]);

        if ( rc == -1 && errno == EOPNOTSUPP )
        {
            /*
             * Use EOPNOTSUPP to spot Xen missing CONFIG_{PV,HVM}, and adjust
             * later testing accordingly.
             */
            switch ( i )
            {
            case XEN_SYSCTL_cpu_policy_pv_max:
            case XEN_SYSCTL_cpu_policy_pv_default:
                if ( xen_has_pv )
                    printf("  Xen doesn't support PV\n");
                xen_has_pv = false;
                continue;

            case XEN_SYSCTL_cpu_policy_hvm_max:
            case XEN_SYSCTL_cpu_policy_hvm_default:
                if ( xen_has_hvm )
                    printf("  Xen doesn't support HVM\n");
                xen_has_hvm = false;
                continue;
            }
        }
        if ( rc )
            return fail("Failed to obtain policy[%u]: %d - %s\n",
                        i, errno, strerror(errno));
    }

    dump_tsx_details(&host.policy, "Host:");

    rc = xc_physinfo(xch, &physinfo);
    if ( rc )
        return fail("Failed to obtain physinfo: %d - %s\n",
                    errno, strerror(errno));

    printf("  Got %u CPUs\n", physinfo.max_cpu_id + 1);

    test_tsx_msrs();
    test_rtm_behaviour();
    test_def_max_policies();
    test_guests();
}

int main(int argc, char **argv)
{
    printf("TSX tests\n");

    xch = xc_interface_open(NULL, NULL, 0);

    if ( !xch )
        err(1, "xc_interface_open");

    test_tsx();

    return !!nr_failures;
}
