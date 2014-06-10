#include <xenctrl.h>
#include <xc_private.h>
#include <xc_core.h>
#include <unistd.h>
#include <inttypes.h>

#include "xg_save_restore.h"

#undef ARRAY_SIZE /* We shouldn't be including xc_private.h */
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

static xc_interface *xch;

int help_func(int argc, char *argv[])
{
    fprintf(stderr,
            "Usage: xen-mfndump <command> [args]\n"
            "Commands:\n"
            "  help                      show this help\n"
            "  dump-m2p                  show M2P\n"
            "  dump-p2m    <domid>       show P2M of <domid>\n"
            "  dump-ptes   <domid> <mfn> show the PTEs in <mfn>\n"
            "  lookup-pte  <domid> <mfn> find the PTE mapping <mfn>\n"
            "  memcmp-mfns <domid1> <mfn1> <domid2> <mfn2>\n"
            "                            compare content of <mfn1> & <mfn2>\n"
           );

    return 0;
}

int dump_m2p_func(int argc, char *argv[])
{
    unsigned long i;
    long max_mfn;
    xen_pfn_t *m2p_table;

    if ( argc > 0 )
    {
        help_func(0, NULL);
        return 1;
    }

    /* Map M2P and obtain gpfn */
    max_mfn = xc_maximum_ram_page(xch);
    if ( max_mfn < 0 )
    {
        ERROR("Failed to get the maximum mfn");
        return -1;
    }

    if ( !(m2p_table = xc_map_m2p(xch, max_mfn, PROT_READ, NULL)) )
    {
        ERROR("Failed to map live M2P table");
        return -1;
    }

    printf(" --- Dumping M2P ---\n");
    printf(" Max MFN: %lu\n", max_mfn);
    for ( i = 0; i < max_mfn; i++ )
    {
        printf("  mfn=0x%lx ==> pfn=0x%lx\n", i, m2p_table[i]);
    }
    printf(" --- End of M2P ---\n");

    munmap(m2p_table, M2P_SIZE(max_mfn));
    return 0;
}

int dump_p2m_func(int argc, char *argv[])
{
    struct xc_domain_meminfo minfo;
    xc_dominfo_t info;
    unsigned long i;
    int domid;

    if ( argc < 1 )
    {
        help_func(0, NULL);
        return 1;
    }
    domid = atoi(argv[0]);

    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 ||
         info.domid != domid )
    {
        ERROR("Failed to obtain info for domain %d\n", domid);
        return -1;
    }

    /* Retrieve all the info about the domain's memory */
    memset(&minfo, 0, sizeof(minfo));
    if ( xc_map_domain_meminfo(xch, domid, &minfo) )
    {
        ERROR("Could not map domain %d memory information\n", domid);
        return -1;
    }

    printf(" --- Dumping P2M for domain %d ---\n", domid);
    printf(" Guest Width: %u, PT Levels: %u P2M size: = %lu\n",
           minfo.guest_width, minfo.pt_levels, minfo.p2m_size);
    for ( i = 0; i < minfo.p2m_size; i++ )
    {
        unsigned long pagetype = minfo.pfn_type[i] &
                                     XEN_DOMCTL_PFINFO_LTAB_MASK;
        xen_pfn_t mfn;

        if ( minfo.guest_width == sizeof(uint64_t) )
            mfn = ((uint64_t*)minfo.p2m_table)[i];
        else
        {
            mfn = ((uint32_t*)minfo.p2m_table)[i];
#ifdef __x86_64__
            if ( mfn == ~0U ) /* Expand a 32bit guest's idea of INVALID_MFN */
                mfn = ~0UL;
#endif
        }

        printf("  pfn=0x%lx ==> mfn=0x%lx (type 0x%lx)", i, mfn,
               pagetype >> XEN_DOMCTL_PFINFO_LTAB_SHIFT);

        switch ( pagetype >> XEN_DOMCTL_PFINFO_LTAB_SHIFT )
        {
        case 0x0: /* NOTAB */
            printf("\n");
            break;
        case 0x1 ... 0x4: /* L1 -> L4 */
            printf(" L%lu\n", pagetype >> XEN_DOMCTL_PFINFO_LTAB_SHIFT);
            break;
        case 0x9 ... 0xc: /* Pinned L1 -> L4 */
            printf(" pinned L%lu\n",
                   (pagetype >> XEN_DOMCTL_PFINFO_LTAB_SHIFT) & 7);
            break;
        case 0xd: /* BROKEN */
            printf(" broken\n");
            break;
        case 0xe: /* XALLOC */
            printf(" xalloc\n");
            break;
        case 0xf: /* XTAB */
            printf(" invalid\n");
            break;
        default:
            printf(" <invalid type>\n");
            break;
        }
    }
    printf(" --- End of P2M for domain %d ---\n", domid);

    xc_unmap_domain_meminfo(xch, &minfo);
    return 0;
}

int dump_ptes_func(int argc, char *argv[])
{
    struct xc_domain_meminfo minfo;
    xc_dominfo_t info;
    void *page = NULL;
    unsigned long i, max_mfn;
    int domid, pte_num, rc = 0;
    xen_pfn_t pfn, mfn, *m2p_table;

    if ( argc < 2 )
    {
        help_func(0, NULL);
        return 1;
    }
    domid = atoi(argv[0]);
    mfn = strtoul(argv[1], NULL, 16);

    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 ||
         info.domid != domid )
    {
        ERROR("Failed to obtain info for domain %d\n", domid);
        return -1;
    }

    /* Retrieve all the info about the domain's memory */
    memset(&minfo, 0, sizeof(minfo));
    if ( xc_map_domain_meminfo(xch, domid, &minfo) )
    {
        ERROR("Could not map domain %d memory information\n", domid);
        return -1;
    }

    /* Map M2P and obtain gpfn */
    max_mfn = xc_maximum_ram_page(xch);
    if ( (mfn > max_mfn) ||
         !(m2p_table = xc_map_m2p(xch, max_mfn, PROT_READ, NULL)) )
    {
        xc_unmap_domain_meminfo(xch, &minfo);
        ERROR("Failed to map live M2P table");
        return -1;
    }

    pfn = m2p_table[mfn];
    if ( pfn >= minfo.p2m_size )
    {
        ERROR("pfn 0x%lx out of range for domain %d\n", pfn, domid);
        rc = -1;
        goto out;
    }

    if ( !(minfo.pfn_type[pfn] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) )
    {
        ERROR("pfn 0x%lx for domain %d is not a PT\n", pfn, domid);
        rc = -1;
        goto out;
    }

    page = xc_map_foreign_range(xch, domid, PAGE_SIZE, PROT_READ,
                                minfo.p2m_table[pfn]);
    if ( !page )
    {
        ERROR("Failed to map 0x%lx\n", minfo.p2m_table[pfn]);
        rc = -1;
        goto out;
    }

    pte_num = PAGE_SIZE / 8;

    printf(" --- Dumping %d PTEs for domain %d ---\n", pte_num, domid);
    printf(" Guest Width: %u, PT Levels: %u P2M size: = %lu\n",
           minfo.guest_width, minfo.pt_levels, minfo.p2m_size);
    printf(" pfn: 0x%lx, mfn: 0x%lx",
           pfn, minfo.p2m_table[pfn]);
    switch ( minfo.pfn_type[pfn] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
    {
        case XEN_DOMCTL_PFINFO_L1TAB:
            printf(", L1 table");
            break;
        case XEN_DOMCTL_PFINFO_L2TAB:
            printf(", L2 table");
            break;
        case XEN_DOMCTL_PFINFO_L3TAB:
            printf(", L3 table");
            break;
        case XEN_DOMCTL_PFINFO_L4TAB:
            printf(", L4 table");
            break;
    }
    if ( minfo.pfn_type[pfn] & XEN_DOMCTL_PFINFO_LPINTAB )
        printf (" [pinned]");
    if ( is_mapped(minfo.p2m_table[pfn]) )
        printf(" [mapped]");
    printf("\n");

    for ( i = 0; i < pte_num; i++ )
        printf("  pte[%lu]: 0x%"PRIx64"\n", i, ((const uint64_t*)page)[i]);

    printf(" --- End of PTEs for domain %d, pfn=0x%lx (mfn=0x%lx) ---\n",
           domid, pfn, minfo.p2m_table[pfn]);

 out:
    if ( page )
        munmap(page, PAGE_SIZE);
    xc_unmap_domain_meminfo(xch, &minfo);
    munmap(m2p_table, M2P_SIZE(max_mfn));
    return rc;
}

int lookup_pte_func(int argc, char *argv[])
{
    struct xc_domain_meminfo minfo;
    xc_dominfo_t info;
    void *page = NULL;
    unsigned long i, j;
    int domid, pte_num;
    xen_pfn_t mfn;

    if ( argc < 2 )
    {
        help_func(0, NULL);
        return 1;
    }
    domid = atoi(argv[0]);
    mfn = strtoul(argv[1], NULL, 16);

    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 ||
         info.domid != domid )
    {
        ERROR("Failed to obtain info for domain %d\n", domid);
        return -1;
    }

    /* Retrieve all the info about the domain's memory */
    memset(&minfo, 0, sizeof(minfo));
    if ( xc_map_domain_meminfo(xch, domid, &minfo) )
    {
        ERROR("Could not map domain %d memory information\n", domid);
        return -1;
    }

    pte_num = PAGE_SIZE / 8;

    printf(" --- Lookig for PTEs mapping mfn 0x%lx for domain %d ---\n",
           mfn, domid);
    printf(" Guest Width: %u, PT Levels: %u P2M size: = %lu\n",
           minfo.guest_width, minfo.pt_levels, minfo.p2m_size);

    for ( i = 0; i < minfo.p2m_size; i++ )
    {
        if ( !(minfo.pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) )
            continue;

        page = xc_map_foreign_range(xch, domid, PAGE_SIZE, PROT_READ,
                                    minfo.p2m_table[i]);
        if ( !page )
            continue;

        for ( j = 0; j < pte_num; j++ )
        {
            uint64_t pte = ((const uint64_t*)page)[j];

#define __MADDR_BITS_X86  ((minfo.guest_width == 8) ? 52 : 44)
#define __MFN_MASK_X86    ((1ULL << (__MADDR_BITS_X86 - PAGE_SHIFT_X86)) - 1)
            if ( ((pte >> PAGE_SHIFT_X86) & __MFN_MASK_X86) == mfn)
                printf("  0x%lx <-- [0x%lx][%lu]: 0x%"PRIx64"\n",
                       mfn, minfo.p2m_table[i], j, pte);
#undef __MADDR_BITS_X86
#undef __MFN_MASK_X8
        }

        munmap(page, PAGE_SIZE);
        page = NULL;
    }

    xc_unmap_domain_meminfo(xch, &minfo);

    return 1;
}

int memcmp_mfns_func(int argc, char *argv[])
{
    xc_dominfo_t info1, info2;
    void *page1 = NULL, *page2 = NULL;
    int domid1, domid2;
    xen_pfn_t mfn1, mfn2;
    int rc = 0;

    if ( argc < 4 )
    {
        help_func(0, NULL);
        return 1;
    }
    domid1 = atoi(argv[0]);
    domid2 = atoi(argv[2]);
    mfn1 = strtoul(argv[1], NULL, 16);
    mfn2 = strtoul(argv[3], NULL, 16);

    if ( xc_domain_getinfo(xch, domid1, 1, &info1) != 1 ||
         xc_domain_getinfo(xch, domid2, 1, &info2) != 1 ||
         info1.domid != domid1 || info2.domid != domid2)
    {
        ERROR("Failed to obtain info for domains\n");
        return -1;
    }

    page1 = xc_map_foreign_range(xch, domid1, PAGE_SIZE, PROT_READ, mfn1);
    page2 = xc_map_foreign_range(xch, domid2, PAGE_SIZE, PROT_READ, mfn2);
    if ( !page1 || !page2 )
    {
        ERROR("Failed to map either 0x%lx[dom %d] or 0x%lx[dom %d]\n",
              mfn1, domid1, mfn2, domid2);
        rc = -1;
        goto out;
    }

    printf(" --- Comparing the content of 2 MFNs ---\n");
    printf(" 1: 0x%lx[dom %d], 2: 0x%lx[dom %d]\n",
           mfn1, domid1, mfn2, domid2);
    printf("  memcpy(1, 2) = %d\n", memcmp(page1, page2, PAGE_SIZE));

 out:
    if ( page1 )
        munmap(page1, PAGE_SIZE);
    if ( page2 )
        munmap(page2, PAGE_SIZE);
    return rc;
}



struct {
    const char *name;
    int (*func)(int argc, char *argv[]);
} opts[] = {
    { "help", help_func },
    { "dump-m2p", dump_m2p_func },
    { "dump-p2m", dump_p2m_func },
    { "dump-ptes", dump_ptes_func },
    { "lookup-pte", lookup_pte_func },
    { "memcmp-mfns", memcmp_mfns_func},
};

int main(int argc, char *argv[])
{
    int i, ret;

    if (argc < 2)
    {
        help_func(0, NULL);
        return 1;
    }

    xch = xc_interface_open(0, 0, 0);
    if ( !xch )
    {
        fprintf(stderr, "Failed to open an xc handler");
        return 1;
    }

    for ( i = 0; i < ARRAY_SIZE(opts); i++ )
    {
        if ( !strncmp(opts[i].name, argv[1], strlen(argv[1])) )
            break;
    }

    if ( i == ARRAY_SIZE(opts) )
    {
        fprintf(stderr, "Unknown option '%s'", argv[1]);
        help_func(0, NULL);
        return 1;
    }

    ret = opts[i].func(argc - 2, argv + 2);

    xc_interface_close(xch);

    return !!ret;
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
