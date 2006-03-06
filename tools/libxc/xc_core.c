#include "xg_private.h"
#define ELFSIZE 32
#include "xc_elf.h"
#include <stdlib.h>
#include <unistd.h>
#include <zlib.h>

/* number of pages to write at a time */
#define DUMP_INCREMENT 4 * 1024
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

static int
copy_from_domain_page(int xc_handle,
                      uint32_t domid,
                      unsigned long *page_array,
                      unsigned long src_pfn,
                      void *dst_page)
{
    void *vaddr = xc_map_foreign_range(
        xc_handle, domid, PAGE_SIZE, PROT_READ, page_array[src_pfn]);
    if ( vaddr == NULL )
        return -1;
    memcpy(dst_page, vaddr, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

int 
xc_domain_dumpcore(int xc_handle,
                   uint32_t domid,
                   const char *corename)
{
    unsigned long nr_pages;
    unsigned long *page_array;
    xc_dominfo_t info;
    int i, nr_vcpus = 0, dump_fd;
    char *dump_mem, *dump_mem_start = NULL;
    struct xc_core_header header;
    vcpu_guest_context_t  ctxt[MAX_VIRT_CPUS];

 
    if ((dump_fd = open(corename, O_CREAT|O_RDWR, S_IWUSR|S_IRUSR)) < 0) {
        PERROR("Could not open corefile %s: %s", corename, strerror(errno));
        goto error_out;
    }
 
    if ((dump_mem_start = malloc(DUMP_INCREMENT*PAGE_SIZE)) == NULL) {
        PERROR("Could not allocate dump_mem");
        goto error_out;
    }
 
    if (xc_domain_getinfo(xc_handle, domid, 1, &info) != 1) {
        PERROR("Could not get info for domain");
        goto error_out;
    }
 
    for (i = 0; i < info.max_vcpu_id; i++)
        if (xc_vcpu_getcontext(xc_handle, domid,
                                       i, &ctxt[nr_vcpus]) == 0)
            nr_vcpus++;
 
    nr_pages = info.nr_pages;

    header.xch_magic = XC_CORE_MAGIC;
    header.xch_nr_vcpus = nr_vcpus;
    header.xch_nr_pages = nr_pages;
    header.xch_ctxt_offset = sizeof(struct xc_core_header);
    header.xch_index_offset = sizeof(struct xc_core_header) +
        sizeof(vcpu_guest_context_t)*nr_vcpus;
    header.xch_pages_offset = round_pgup(sizeof(struct xc_core_header) +
                                         (sizeof(vcpu_guest_context_t) * nr_vcpus) +
                                         (nr_pages * sizeof(unsigned long)));

    if (write(dump_fd, &header, sizeof(struct xc_core_header)) < 0 ||
        write(dump_fd, &ctxt, sizeof(ctxt[0]) * nr_vcpus) < 0)
    {
        PERROR("write failed");
        goto error_out;
    }

    if ((page_array = malloc(nr_pages * sizeof(unsigned long))) == NULL) {
        printf("Could not allocate memory\n");
        goto error_out;
    }
    if (xc_get_pfn_list(xc_handle, domid, page_array, nr_pages) != nr_pages) {
        printf("Could not get the page frame list\n");
        goto error_out;
    }
    if (write(dump_fd, page_array, nr_pages * sizeof(unsigned long)) < 0)
    {
        PERROR("write failed");
        goto error_out;
    }
    lseek(dump_fd, header.xch_pages_offset, SEEK_SET);
    for (dump_mem = dump_mem_start, i = 0; i < nr_pages; i++) {
        copy_from_domain_page(xc_handle, domid, page_array, i, dump_mem);
        dump_mem += PAGE_SIZE;
        if (((i + 1) % DUMP_INCREMENT == 0) || (i + 1) == nr_pages) {
            if (write(dump_fd, dump_mem_start, dump_mem - dump_mem_start) < 
                dump_mem - dump_mem_start) {
                PERROR("Partial write, file system full?");
                goto error_out;
            }
            dump_mem = dump_mem_start;
        }
    }

    close(dump_fd);
    free(dump_mem_start);
    return 0;
 error_out:
    if (dump_fd != -1)
        close(dump_fd);
    free(dump_mem_start);
    return -1;
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
