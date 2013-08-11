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
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
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

#include <xenctrl.h>
#include <xg_private.h>
#include <xenguest.h>
#include <inttypes.h>
#include <sys/time.h>
#include <xen/arch-x86/xen-mca.h>
#include <xg_save_restore.h>
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

/* LLC (Last Level Cache) EWB (Explicit Write Back) SRAO MCE */
#define MCG_STATUS_SRAO_LLC_VAL  0x5
#define MCE_SRAO_LLC_BANK        0x7
#define MCi_STATUS_SRAO_LLC_VAL  0xBD2000008000017AUL
#define MCi_MISC_SRAO_LLC_VAL    0x86UL

/* Memory Patrol Scrub SRAO MCE */
#define MCG_STATUS_SRAO_MEM_VAL  0x5
#define MCE_SRAO_MEM_BANK        0x8
#define MCi_STATUS_SRAO_MEM_VAL  0xBD000000004000CFUL
#define MCi_MISC_SRAO_MEM_VAL    0x86UL

/* LLC EWB UCNA Error */
#define MCG_STATUS_UCNA_LLC_VAL  0x0
#define CMCI_UCNA_LLC_BANK       0x9
#define MCi_STATUS_UCNA_LLC_VAL  0xBC20000080000136UL
#define MCi_MISC_UCNA_LLC_VAL    0x86UL

/* Error Types */
#define MCE_SRAO_MEM        0x0
#define MCE_SRAO_LLC        0x1
#define CMCI_UCNA_LLC       0x2

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
    fprintf(LOGFILE, "%s", buf);
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
        err(xc_handle, "Failed to get mca_cpuinfo\n");

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
                           uint64_t val)
{
    uint32_t count;

    if ( (msr_inj.mcinj_count &&
         (cpu_nr != msr_inj.mcinj_cpunr || flags != msr_inj.mcinj_flags)) ||
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
                                uint64_t val)
{
    uint64_t msr;

    msr = bank_addr(bank, type);
    if ( msr == INVALID_MSR )
        return -1;
    return add_msr_intpose(xc_handle, cpu_nr, flags, msr, val);
}

#define MCE_INVALID_MFN ~0UL
#define mfn_valid(_mfn) (_mfn != MCE_INVALID_MFN)
#define mfn_to_pfn(_mfn) (live_m2p[(_mfn)])
static uint64_t guest_mfn(xc_interface *xc_handle,
                               uint32_t domain,
                               uint64_t gpfn)
{
    xen_pfn_t *live_m2p = NULL;
    int ret;
    unsigned long hvirt_start;
    unsigned int pt_levels;
    uint64_t * pfn_buf = NULL;
    unsigned long max_mfn = 0; /* max mfn of the whole machine */
    unsigned long m2p_mfn0;
    unsigned int guest_width;
    long max_gpfn,i;
    uint64_t mfn = MCE_INVALID_MFN;

    if ( domain > DOMID_FIRST_RESERVED )
        return MCE_INVALID_MFN;

    /* Get max gpfn */
    max_gpfn = do_memory_op(xc_handle, XENMEM_maximum_gpfn, &domain, 
                               sizeof(domain)) + 1;
    if ( max_gpfn <= 0 )
        err(xc_handle, "Failed to get max_gpfn 0x%lx\n", max_gpfn);

    Lprintf("Maxium gpfn for dom %d is 0x%lx\n", domain, max_gpfn);

    /* Get max mfn */
    if ( !get_platform_info(xc_handle, domain,
                            &max_mfn, &hvirt_start,
                            &pt_levels, &guest_width) )
        err(xc_handle, "Failed to get platform information\n");

    /* Get guest's pfn list */
    pfn_buf = malloc(sizeof(uint64_t) * max_gpfn);
    if ( !pfn_buf )
        err(xc_handle, "Failed to alloc pfn buf\n");
    memset(pfn_buf, 0, sizeof(uint64_t) * max_gpfn);

    ret = xc_get_pfn_list(xc_handle, domain, pfn_buf, max_gpfn);
    if ( ret < 0 ) {
        free(pfn_buf);
        err(xc_handle, "Failed to get pfn list %x\n", ret);
    }

    /* Now get the m2p table */
    live_m2p = xc_map_m2p(xc_handle, max_mfn, PROT_READ, &m2p_mfn0);
    if ( !live_m2p )
        err(xc_handle, "Failed to map live M2P table\n");

    /* match the mapping */
    for ( i = 0; i < max_gpfn; i++ )
    {
        uint64_t tmp;
        tmp = pfn_buf[i];

        if (mfn_valid(tmp) &&  (mfn_to_pfn(tmp) == gpfn))
        {
            mfn = tmp;
            Lprintf("We get the mfn 0x%lx for this injection\n", mfn);
            break;
        }
    }

    munmap(live_m2p, M2P_SIZE(max_mfn));

    free(pfn_buf);
    return mfn;
}

static uint64_t mca_gpfn_to_mfn(xc_interface *xc_handle,
                                uint32_t domain,
                                uint64_t gfn)
{
    uint64_t index;
    long max_gpfn;

    /* If domain is xen, means we want pass index directly */
    if ( domain == DOMID_XEN )
        return gfn;

    max_gpfn = do_memory_op(xc_handle, XENMEM_maximum_gpfn, &domain, 
                               sizeof(domain)) + 1;
    if ( max_gpfn <= 0 )
        err(xc_handle, "Failed to get max_gpfn 0x%lx\n", max_gpfn);
    index = gfn % max_gpfn;

    return guest_mfn(xc_handle, domain, index);
}

static int inject_mcg_status(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint64_t val)
{
    return add_msr_intpose(xc_handle, cpu_nr, MC_MSRINJ_F_INTERPOSE,
                               MSR_IA32_MCG_STATUS, val);
}

static int inject_mci_status(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint64_t bank,
                             uint64_t val)
{
    return add_msr_bank_intpose(xc_handle, cpu_nr, MC_MSRINJ_F_INTERPOSE,
                                    MCi_type_STATUS, bank, val); 
}

static int inject_mci_misc(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint64_t bank,
                             uint64_t val)
{
    return add_msr_bank_intpose(xc_handle, cpu_nr, MC_MSRINJ_F_INTERPOSE,
                                    MCi_type_MISC, bank, val); 
}

static int inject_mci_addr(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint64_t bank,
                             uint64_t val)
{
    return add_msr_bank_intpose(xc_handle, cpu_nr, MC_MSRINJ_F_INTERPOSE,
                                    MCi_type_ADDR, bank, val); 
}

static int inject_llc_srao(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint32_t domain,
                             uint64_t gaddr)
{
    uint64_t gpfn, mfn, haddr;
    int ret = 0;

    ret = inject_mcg_status(xc_handle, cpu_nr, MCG_STATUS_SRAO_LLC_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCG_STATUS MSR\n");

    ret = inject_mci_status(xc_handle, cpu_nr,
                            MCE_SRAO_LLC_BANK, MCi_STATUS_SRAO_LLC_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_STATUS MSR\n");

    ret = inject_mci_misc(xc_handle, cpu_nr,
                          MCE_SRAO_LLC_BANK, MCi_MISC_SRAO_LLC_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_MISC MSR\n");

    gpfn = gaddr >> PAGE_SHIFT;
    mfn = mca_gpfn_to_mfn(xc_handle, domain, gpfn);
    if (!mfn_valid(mfn))
        err(xc_handle, "The MFN is not valid\n");
    haddr = (mfn << PAGE_SHIFT) | (gaddr & (PAGE_SIZE - 1));
    ret = inject_mci_addr(xc_handle, cpu_nr, MCE_SRAO_LLC_BANK, haddr);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_ADDR MSR\n");

    ret = flush_msr_inj(xc_handle);
    if ( ret )
        err(xc_handle, "Failed to inject MSR\n");
    ret = inject_mce(xc_handle, cpu_nr);
    if ( ret )
        err(xc_handle, "Failed to inject MCE error\n");

    return 0;
}

static int inject_mem_srao(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint32_t domain,
                             uint64_t gaddr)
{
    uint64_t gpfn, mfn, haddr;
    int ret = 0;

    ret = inject_mcg_status(xc_handle, cpu_nr, MCG_STATUS_SRAO_MEM_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCG_STATUS MSR\n");

    ret = inject_mci_status(xc_handle, cpu_nr,
                            MCE_SRAO_MEM_BANK, MCi_STATUS_SRAO_MEM_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_STATUS MSR\n");

    ret = inject_mci_misc(xc_handle, cpu_nr,
                          MCE_SRAO_MEM_BANK, MCi_MISC_SRAO_MEM_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_MISC MSR\n");

    gpfn = gaddr >> PAGE_SHIFT;
    mfn = mca_gpfn_to_mfn(xc_handle, domain, gpfn);
    if (!mfn_valid(mfn))
        err(xc_handle, "The MFN is not valid\n");
    haddr = (mfn << PAGE_SHIFT) | (gaddr & (PAGE_SIZE - 1));
    ret = inject_mci_addr(xc_handle, cpu_nr, MCE_SRAO_MEM_BANK, haddr);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_ADDR MSR\n");

    ret = flush_msr_inj(xc_handle);
    if ( ret )
        err(xc_handle, "Failed to inject MSR\n");
    ret = inject_mce(xc_handle, cpu_nr);
    if ( ret )
        err(xc_handle, "Failed to inject MCE error\n");

    return 0;
}

static int inject_llc_ucna(xc_interface *xc_handle,
                             uint32_t cpu_nr,
                             uint32_t domain,
                             uint64_t gaddr)
{
    uint64_t gpfn, mfn, haddr;
    int ret = 0;

    ret = inject_mcg_status(xc_handle, cpu_nr, MCG_STATUS_UCNA_LLC_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCG_STATUS MSR\n");

    ret = inject_mci_status(xc_handle, cpu_nr,
                            CMCI_UCNA_LLC_BANK, MCi_STATUS_UCNA_LLC_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_STATUS MSR\n");

    ret = inject_mci_misc(xc_handle, cpu_nr,
                          CMCI_UCNA_LLC_BANK, MCi_MISC_UCNA_LLC_VAL);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_MISC MSR\n");

    gpfn = gaddr >> PAGE_SHIFT;
    mfn = mca_gpfn_to_mfn(xc_handle, domain, gpfn);
    if (!mfn_valid(mfn))
        err(xc_handle, "The MFN is not valid\n");
    haddr = (mfn << PAGE_SHIFT) | (gaddr & (PAGE_SIZE - 1));
    ret = inject_mci_addr(xc_handle, cpu_nr, CMCI_UCNA_LLC_BANK, haddr);
    if ( ret )
        err(xc_handle, "Failed to inject MCi_ADDR MSR\n");

    ret = flush_msr_inj(xc_handle);
    if ( ret )
        err(xc_handle, "Failed to inject MSR\n");
    ret = inject_cmci(xc_handle, cpu_nr);
    if ( ret )
        err(xc_handle, "Failed to inject MCE error\n");

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
    {"log", 0, 0, 'l'},
    {"page", 0, 0, 'p'},
    {"", 0, 0, '\0'}
};

static void help(void)
{
    printf("Usage: xen-mceinj [OPTION]...\n"
           "\n"
           "Mandatory arguments to long options are mandatory"
           "for short options too.\n"
           "  -D, --dump           dump addr info without error injection\n"
           "  -c, --cpu=CPU_ID     target CPU\n"
           "  -d, --domain=DomID   target domain, the default is Xen itself\n"
           "  -h, --help           print this page\n"
           "  -p, --phyaddr        physical address\n"
           "  -t, --type=error     error type\n"
           "                        0 : MCE_SRAO_MEM\n"
           "                        1 : MCE_SRAO_LLC\n"
           "                        2 : CMCI_UCNA_LLC\n"
           "\n"
           );
}

int main(int argc, char *argv[])
{
    int type = MCE_SRAO_MEM;
    int c, opt_index;
    uint32_t domid;
    xc_interface *xc_handle;
    int cpu_nr;
    int64_t gaddr, gpfn, mfn, haddr, max_gpa;

    /* Default Value */
    domid = DOMID_XEN;
    gaddr = 0x180020;
    cpu_nr = 0;

    init_msr_inj();
    xc_handle = xc_interface_open(0, 0, 0);
    if ( !xc_handle ) {
        Lprintf("Failed to get xc interface\n");
        exit(EXIT_FAILURE);
    }

    while ( 1 ) {
        c = getopt_long(argc, argv, "c:Dd:t:hp:r", opts, &opt_index);
        if ( c == -1 )
            break;
        switch ( c ) {
        case 'D':
            dump=1;
            break;
        case 'c':
            cpu_nr = strtol(optarg, &optarg, 10);
            if ( strlen(optarg) != 0 )
                err(xc_handle, "Please input a digit parameter for CPU\n");
            break;
        case 'd':
            domid = strtol(optarg, &optarg, 10);
            if ( strlen(optarg) != 0 )
                err(xc_handle, "Please input a digit parameter for domain\n");
            break;
        case 'p':
            gaddr = strtol(optarg, &optarg, 0);
            if ( strlen(optarg) != 0 )
                err(xc_handle, "Please input correct page address\n");
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
        Lprintf("get domain %d max gpa is: 0x%lx \n", domid, max_gpa);
        if ( gaddr >= max_gpa )
            err(xc_handle, "Fail: gaddr exceeds max_gpa 0x%lx\n", max_gpa);
    }
    Lprintf("get gaddr of error inject is: 0x%lx \n", gaddr);

    if ( dump ) {
        gpfn = gaddr >> PAGE_SHIFT;
        mfn = mca_gpfn_to_mfn(xc_handle, domid, gpfn);
        if (!mfn_valid(mfn))
            err(xc_handle, "The MFN is not valid\n");
        haddr = (mfn << PAGE_SHIFT) | (gaddr & (PAGE_SIZE - 1));
        if ( domid == DOMID_XEN )
            Lprintf("Xen: mfn=0x%lx, haddr=0x%lx\n", mfn, haddr);
        else 
            Lprintf("Dom%d: gaddr=0x%lx, gpfn=0x%lx,"
                    "mfn=0x%lx, haddr=0x%lx\n",
                    domid, gaddr, gpfn, mfn, haddr);
        goto out;
    }

    switch ( type )
    {
    case MCE_SRAO_MEM:
        inject_mem_srao(xc_handle, cpu_nr, domid, gaddr);
        break;
    case MCE_SRAO_LLC:
        inject_llc_srao(xc_handle, cpu_nr, domid, gaddr);
        break;
    case CMCI_UCNA_LLC:
        inject_llc_ucna(xc_handle, cpu_nr, domid, gaddr);
        break;
    default:
        err(xc_handle, "Unsupported error type\n");
        break;
    }

out:
    xc_interface_close(xc_handle);
    return 0;
}
