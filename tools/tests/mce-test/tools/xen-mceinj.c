/*
 * xen-mceinj.c: utilities to inject fake MCE for x86.
 * Copyright (c) 2010, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * Authors: Yunhong Jiang <yunhong.jiang@intel.com>
 *          Haicheng Li <haicheng.li@intel.com>
 *          Xudong Hao <xudong.hao@intel.com>
 */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>

#define XC_WANT_COMPAT_MAP_FOREIGN_API
#include <xenctrl.h>
#include <xenguest.h>
#include <inttypes.h>
#include <sys/time.h>
#include <xen/arch-x86/xen-mca.h>
#include <xenstore.h>

#define MCi_type_CTL        0x0
#define MCi_type_STATUS     0x1
#define MCi_type_ADDR       0x2
#define MCi_type_MISC       0x3
#define MCi_type_CTL2       0x4

#define INVALID_MSR         ~0UL

/* Intel MSRs */
#define MSR_IA32_MCG_CAP         0x00000179
#define MSR_IA32_MCG_STATUS      0x0000017a
#define MSR_IA32_MCG_CTL         0x0000017b
#define MSR_IA32_MC0_CTL         0x00000400
#define MSR_IA32_MC0_STATUS      0x00000401
#define MSR_IA32_MC0_ADDR        0x00000402
#define MSR_IA32_MC0_MISC        0x00000403
#define MSR_IA32_MC0_CTL2        0x00000280

struct mce_info {
    const char *description;
    uint8_t mcg_stat;
    unsigned int bank;
    uint64_t mci_stat;
    uint64_t mci_misc;
    bool cmci;
};

static struct mce_info mce_table[] = {
    /* LLC (Last Level Cache) EWB (Explicit Write Back) SRAO MCE */
    {
        .description = "MCE_SRAO_MEM",
        .mcg_stat = 0x5,
        .bank = 7,
        .mci_stat = 0xBD2000008000017Aull,
        .mci_misc = 0x86ull,
    },
    /* Memory Patrol Scrub SRAO MCE */
    {
        .description = "MCE_SRAO_LLC",
        .mcg_stat = 0x5,
        .bank = 8,
        .mci_stat = 0xBD000000004000CFull,
        .mci_misc = 0x86ull,
    },
    /* LLC EWB UCNA Error */
    {
        .description = "CMCI_UCNA_LLC",
        .mcg_stat = 0x0,
        .bank = 9,
        .mci_stat = 0xBC20000080000136ull,
        .mci_misc = 0x86ull,
        .cmci = true,
    },
    /* AMD L1 instruction cache data or tag parity. */
    {
        .description = "AMD L1 icache parity",
        .mcg_stat = 0x5,
        .bank = 1,
        .mci_stat = 0x9400000000000151ull,
        .mci_misc = 0x86ull,
    },
    /* LLC (Last Level Cache) EWB (Explicit Write Back) SRAO MCE */
    {
        .description = "MCE_SRAO_MEM (Fatal)",
        .mcg_stat = 0x5,
        .bank = 7,
        .mci_stat = 0xBF2000008000017Aull,
        .mci_misc = 0x86ull,
    },
};
#define MCE_TABLE_SIZE (sizeof(mce_table)/sizeof(mce_table[0]))

#define LOGFILE stdout

int dump;
struct xen_mc_msrinject msr_inj;

static void Lprintf(const char *fmt, ...)
{
    char *buf;
    va_list args;

    va_start(args, fmt);
    if (vasprintf(&buf, fmt, args) < 0)
        abort();
    fprintf(LOGFILE, "%s\n", buf);
    va_end(args);
    free(buf);
}

static void err(xc_interface *xc_handle, const char *fmt, ...)
{
    char *buf;
    va_list args;

    va_start(args, fmt);
    if (vasprintf(&buf, fmt, args) < 0)
        abort();
    perror(buf);
    va_end(args);
    free(buf);

    if ( xc_handle )
        xc_interface_close(xc_handle);
    exit(EXIT_FAILURE);
}

static void init_msr_inj(void)
{
    memset(&msr_inj, 0, sizeof(msr_inj));
}

static int flush_msr_inj(xc_interface *xc_handle)
{
    struct xen_mc mc;

    mc.cmd = XEN_MC_msrinject;
    mc.interface_version = XEN_MCA_INTERFACE_VERSION;
    mc.u.mc_msrinject = msr_inj;

    return xc_mca_op(xc_handle, &mc);
}

static int mca_cpuinfo(xc_interface *xc_handle)
{
    struct xen_mc mc;

    memset(&mc, 0, sizeof(struct xen_mc));

    mc.cmd = XEN_MC_physcpuinfo;
    mc.interface_version = XEN_MCA_INTERFACE_VERSION;

    if (!xc_mca_op(xc_handle, &mc))
        return mc.u.mc_physcpuinfo.ncpus;
    else
        return 0;
}

static int inject_cmci(xc_interface *xc_handle, int cpu_nr)
{
    struct xen_mc mc;
    int nr_cpus;

    memset(&mc, 0, sizeof(struct xen_mc));

    nr_cpus = mca_cpuinfo(xc_handle);
    if (!nr_cpus)
        err(xc_handle, "Failed to get mca_cpuinfo");

    mc.cmd = XEN_MC_inject_v2;
    mc.interface_version = XEN_MCA_INTERFACE_VERSION;

    mc.u.mc_inject_v2.flags |= XEN_MC_INJECT_CPU_BROADCAST;
    mc.u.mc_inject_v2.flags |= XEN_MC_INJECT_TYPE_CMCI;
    mc.u.mc_inject_v2.cpumap.nr_bits = nr_cpus;

    return xc_mca_op(xc_handle, &mc);
}

static int inject_mce(xc_interface *xc_handle, int cpu_nr)
{
    struct xen_mc mc;

    memset(&mc, 0, sizeof(struct xen_mc));

    mc.cmd = XEN_MC_mceinject;
    mc.interface_version = XEN_MCA_INTERFACE_VERSION;
    mc.u.mc_mceinject.mceinj_cpunr = cpu_nr;

    return xc_mca_op(xc_handle, &mc);
}

static uint64_t bank_addr(int bank, int type)
{
    uint64_t addr;

    switch ( type )
    {
    case MCi_type_CTL:
    case MCi_type_STATUS:
    case MCi_type_ADDR:
    case MCi_type_MISC:
        addr = MSR_IA32_MC0_CTL + (bank * 4) + type;
        break;
    case MCi_type_CTL2:
        addr = MSR_IA32_MC0_CTL2 + bank;
        break;
    default:
        addr = INVALID_MSR;
        break;
    }

    return addr;
}

static int add_msr_intpose(xc_interface *xc_handle,
                           uint32_t cpu_nr,
                           uint32_t flags,
                           uint64_t msr,
                           uint64_t val,
                           domid_t domid)
{
    uint32_t count;

    if ( (msr_inj.mcinj_count &&
          (cpu_nr != msr_inj.mcinj_cpunr || flags != msr_inj.mcinj_flags ||
           domid != msr_inj.mcinj_domid)) ||
         msr_inj.mcinj_count == MC_MSRINJ_MAXMSRS )
    {
        flush_msr_inj(xc_handle);
        init_msr_inj();
    }
    count= msr_inj.mcinj_count;

    if ( !count )
    {
        msr_inj.mcinj_cpunr = cpu_nr;
        msr_inj.mcinj_flags = flags;
        msr_inj.mcinj_domid = domid;
    }
    msr_inj.mcinj_msr[count].reg = msr;
    msr_inj.mcinj_msr[count].value = val;
    msr_inj.mcinj_count++;

    return 0;
}

static int add_msr_bank_intpose(xc_interface *xc_handle,
                                uint32_t cpu_nr,
                                uint32_t flags,
                                uint32_t type,
                                uint32_t bank,
                                uint64_t val,
                                domid_t domid)
{
    uint64_t msr;

    msr = bank_addr(bank, type);
    if ( msr == INVALID_MSR )
        return -1;
    return add_msr_intpose(xc_handle, cpu_nr, flags, msr, val, domid);
}

static int inject_mcg_status(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint64_t val,
                             domid_t domid)
{
    return add_msr_intpose(xc_handle, cpu_nr, MC_MSRINJ_F_INTERPOSE,
                           MSR_IA32_MCG_STATUS, val, domid);
}

static int inject_mci_status(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint64_t bank,
                             uint64_t val,
                             domid_t domid)
{
    return add_msr_bank_intpose(xc_handle, cpu_nr, MC_MSRINJ_F_INTERPOSE,
                                MCi_type_STATUS, bank, val, domid);
}

static int inject_mci_misc(xc_interface *xc_handle,
                           uint32_t cpu_nr,
                           uint64_t bank,
                           uint64_t val,
                           domid_t domid)
{
    return add_msr_bank_intpose(xc_handle, cpu_nr, MC_MSRINJ_F_INTERPOSE,
                                MCi_type_MISC, bank, val, domid);
}

static int inject_mci_addr(xc_interface *xc_handle,
                           uint32_t cpu_nr,
                           uint64_t bank,
                           uint64_t val,
                           domid_t domid)
{
    return add_msr_bank_intpose(xc_handle, cpu_nr,
                                MC_MSRINJ_F_INTERPOSE |
                                ((domid >= DOMID_FIRST_RESERVED &&
                                  domid != DOMID_SELF) ?
                                 0 : MC_MSRINJ_F_GPADDR),
                                MCi_type_ADDR, bank, val, domid);
}

static int inject(xc_interface *xc_handle, struct mce_info *mce,
                  uint32_t cpu_nr, uint32_t domain, uint64_t gaddr)
{
    int ret = 0;

    ret = inject_mcg_status(xc_handle, cpu_nr, mce->mcg_stat, domain);
    if ( ret )
        err(xc_handle, "Failed to inject MCG_STATUS MSR");

    ret = inject_mci_status(xc_handle, cpu_nr,
                            mce->bank, mce->mci_stat, domain);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_STATUS MSR");

    ret = inject_mci_misc(xc_handle, cpu_nr,
                          mce->bank, mce->mci_misc, domain);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_MISC MSR");

    ret = inject_mci_addr(xc_handle, cpu_nr, mce->bank, gaddr, domain);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_ADDR MSR");

    ret = flush_msr_inj(xc_handle);
    if ( ret )
        err(xc_handle, "Failed to inject MSR");
    if ( mce->cmci )
        ret = inject_cmci(xc_handle, cpu_nr);
    else
        ret = inject_mce(xc_handle, cpu_nr);
    if ( ret )
        err(xc_handle, "Failed to inject MCE error");

    return 0;
}

static long xs_get_dom_mem(int domid)
{
    char path[128];
    char *memstr;
    uint64_t mem;
    unsigned int plen;
    struct xs_handle *xs;

    xs = xs_daemon_open();
    if (!xs)
        return -1;

    sprintf(path, "/local/domain/%d/memory/target", domid);
    memstr = xs_read(xs, XBT_NULL, path, &plen);
    xs_daemon_close(xs);

    if (!memstr || !plen)
        return -1;

    mem = atoll(memstr)*1024;
    free(memstr);

    return mem;
}

static struct option opts[] = {
    {"cpu", 0, 0, 'c'},
    {"domain", 0, 0, 'd'},
    {"dump", 0, 0, 'D'},
    {"help", 0, 0, 'h'},
    {"page", 0, 0, 'p'},
    {"", 0, 0, '\0'}
};

static void help(void)
{
    unsigned int i;

    printf("Usage: xen-mceinj [OPTION]...\n"
           "\n"
           "Mandatory arguments to long options are mandatory"
           "for short options too.\n"
           "  -D, --dump           dump addr info without error injection\n"
           "  -c, --cpu=CPU        target CPU\n"
           "  -d, --domain=DOMID   target domain, the default is Xen itself\n"
           "  -h, --help           print this page\n"
           "  -p, --page=ADDR      physical address to report\n"
           "  -t, --type=ERROR     error type\n");

    for ( i = 0; i < MCE_TABLE_SIZE; i++ )
        printf("                       %2d : %s\n",
               i, mce_table[i].description);
}

int main(int argc, char *argv[])
{
    int type = 0;
    int c, opt_index;
    uint32_t domid;
    xc_interface *xc_handle;
    int cpu_nr;
    uint64_t gaddr, max_gpa;

    /* Default Value */
    domid = DOMID_XEN;
    gaddr = 0x180020;
    cpu_nr = 0;

    init_msr_inj();
    xc_handle = xc_interface_open(0, 0, 0);
    if ( !xc_handle ) {
        Lprintf("Failed to get xc interface");
        exit(EXIT_FAILURE);
    }

    while ( 1 ) {
        c = getopt_long(argc, argv, "c:Dd:t:hp:", opts, &opt_index);
        if ( c == -1 )
            break;
        switch ( c ) {
        case 'D':
            dump=1;
            break;
        case 'c':
            cpu_nr = strtol(optarg, &optarg, 10);
            if ( strlen(optarg) != 0 )
                err(xc_handle, "Please input a digit parameter for CPU");
            break;
        case 'd':
            domid = strtol(optarg, &optarg, 10);
            if ( strlen(optarg) != 0 )
                err(xc_handle, "Please input a digit parameter for domain");
            break;
        case 'p':
            gaddr = strtol(optarg, &optarg, 0);
            if ( strlen(optarg) != 0 )
                err(xc_handle, "Please input correct page address");
            break;
        case 't':
            type = strtol(optarg, NULL, 0);
            break;
        case 'h':
        default:
            help();
            return 0;
        }
    }

    if ( domid != DOMID_XEN ) {
        max_gpa = xs_get_dom_mem(domid);
        Lprintf("get domain %d max gpa is: 0x%lx", domid, max_gpa);
        if ( gaddr >= max_gpa )
            err(xc_handle, "Fail: gaddr exceeds max_gpa 0x%lx", max_gpa);
    }
    Lprintf("get gaddr of error inject is: 0x%lx", gaddr);

    if ( dump ) {
        if ( domid == DOMID_XEN )
            Lprintf("Xen: gaddr=0x%lx", gaddr);
        else
            Lprintf("Dom%d: gaddr=0x%lx", domid, gaddr);
        goto out;
    }

    if ( type < 0 || type >= MCE_TABLE_SIZE ) {
        err(xc_handle, "Unsupported error type");
        goto out;
    }

    inject(xc_handle, &mce_table[type], cpu_nr, domid, gaddr);

 out:
    xc_interface_close(xc_handle);
    return 0;
}
