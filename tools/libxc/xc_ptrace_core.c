#define XC_PTRACE_PRIVATE

#include <sys/ptrace.h>
#include <sys/wait.h>
#include "xc_private.h"
#include "xc_ptrace.h"
#include <time.h>

/* XXX application state */

static long   nr_pages = 0;
static unsigned long  *p2m_array = NULL;
static unsigned long  *m2p_array = NULL;
static unsigned long            pages_offset;
static unsigned long            cr3[MAX_VIRT_CPUS];

/* --------------------- */

static unsigned long
map_mtop_offset(unsigned long ma)
{
    return pages_offset + (m2p_array[ma >> PAGE_SHIFT] << PAGE_SHIFT);
    return 0;
}


void *
map_domain_va_core(unsigned long domfd, int cpu, void * guest_va,
                        vcpu_guest_context_t *ctxt)
{
    unsigned long pde, page;
    unsigned long va = (unsigned long)guest_va;
    void *v;

    static unsigned long  cr3_phys[MAX_VIRT_CPUS];
    static unsigned long *cr3_virt[MAX_VIRT_CPUS];
    static unsigned long  pde_phys[MAX_VIRT_CPUS];
    static unsigned long *pde_virt[MAX_VIRT_CPUS];
    static unsigned long  page_phys[MAX_VIRT_CPUS];
    static unsigned long *page_virt[MAX_VIRT_CPUS];

    if (cr3[cpu] != cr3_phys[cpu]) 
    {
        cr3_phys[cpu] = cr3[cpu];
        if (cr3_virt[cpu])
            munmap(cr3_virt[cpu], PAGE_SIZE);
        v = mmap(
            NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, domfd,
            map_mtop_offset(cr3_phys[cpu]));
        if (v == MAP_FAILED)
        {
            perror("mmap failed");
            return NULL;
        }
        cr3_virt[cpu] = v;
    } 
    if ((pde = cr3_virt[cpu][vtopdi(va)]) == 0) /* logical address */
        return NULL;
    if (ctxt[cpu].flags & VGCF_HVM_GUEST)
        pde = p2m_array[pde >> PAGE_SHIFT] << PAGE_SHIFT;
    if (pde != pde_phys[cpu]) 
    {
        pde_phys[cpu] = pde;
        if (pde_virt[cpu])
            munmap(pde_virt[cpu], PAGE_SIZE);
        v = mmap(
            NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, domfd,
            map_mtop_offset(pde_phys[cpu]));
        if (v == MAP_FAILED)
            return NULL;
        pde_virt[cpu] = v;
    }
    if ((page = pde_virt[cpu][vtopti(va)]) == 0) /* logical address */
        return NULL;
    if (ctxt[cpu].flags & VGCF_HVM_GUEST)
        page = p2m_array[page >> PAGE_SHIFT] << PAGE_SHIFT;
    if (page != page_phys[cpu]) 
    {
        page_phys[cpu] = page;
        if (page_virt[cpu])
            munmap(page_virt[cpu], PAGE_SIZE);
        v = mmap(
            NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE, domfd,
            map_mtop_offset(page_phys[cpu]));
        if (v == MAP_FAILED)
        {
            printf("cr3 %lx pde %lx page %lx pti %lx\n", cr3[cpu], pde, page, vtopti(va));
            page_phys[cpu] = 0;
            return NULL;
        }
        page_virt[cpu] = v;
    } 
    return (void *)(((unsigned long)page_virt[cpu]) | (va & BSD_PAGE_MASK));
}

int 
xc_waitdomain_core(
    int xc_handle,
    int domfd,
    int *status,
    int options,
    vcpu_guest_context_t *ctxt)
{
    int nr_vcpus;
    int i;
    xc_core_header_t header;

    if (nr_pages == 0)
    {

        if (read(domfd, &header, sizeof(header)) != sizeof(header))
            return -1;

        nr_pages = header.xch_nr_pages;
        nr_vcpus = header.xch_nr_vcpus;
        pages_offset = header.xch_pages_offset;

        if (read(domfd, ctxt, sizeof(vcpu_guest_context_t)*nr_vcpus) != 
            sizeof(vcpu_guest_context_t)*nr_vcpus)
            return -1;

        for (i = 0; i < nr_vcpus; i++) {
            cr3[i] = ctxt[i].ctrlreg[3];
        }
        if ((p2m_array = malloc(nr_pages * sizeof(unsigned long))) == NULL)
        {
            printf("Could not allocate p2m_array\n");
            return -1;
        }
        if (read(domfd, p2m_array, sizeof(unsigned long)*nr_pages) != 
            sizeof(unsigned long)*nr_pages)
            return -1;

        if ((m2p_array = malloc((1<<20) * sizeof(unsigned long))) == NULL)
        {
            printf("Could not allocate m2p array\n");
            return -1;
        }
        bzero(m2p_array, sizeof(unsigned long)* 1 << 20);

        for (i = 0; i < nr_pages; i++) {
            m2p_array[p2m_array[i]] = i;
        }

    }
    return 0;
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
