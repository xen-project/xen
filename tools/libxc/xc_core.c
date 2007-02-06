#include "xg_private.h"
#include <stdlib.h>
#include <unistd.h>

/* number of pages to write at a time */
#define DUMP_INCREMENT (4 * 1024)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

static int
copy_from_domain_page(int xc_handle,
                      uint32_t domid,
                      unsigned long mfn,
                      void *dst_page)
{
    void *vaddr = xc_map_foreign_range(
        xc_handle, domid, PAGE_SIZE, PROT_READ, mfn);
    if ( vaddr == NULL )
        return -1;
    memcpy(dst_page, vaddr, PAGE_SIZE);
    munmap(vaddr, PAGE_SIZE);
    return 0;
}

int
xc_domain_dumpcore_via_callback(int xc_handle,
                                uint32_t domid,
                                void *args,
                                dumpcore_rtn_t dump_rtn)
{
    unsigned long nr_pages;
    uint64_t *page_array = NULL;
    xc_dominfo_t info;
    int i, nr_vcpus = 0;
    char *dump_mem, *dump_mem_start = NULL;
    struct xc_core_header header;
    vcpu_guest_context_t  ctxt[MAX_VIRT_CPUS];
    char dummy[PAGE_SIZE];
    int dummy_len;
    int sts;

    if ( (dump_mem_start = malloc(DUMP_INCREMENT*PAGE_SIZE)) == NULL )
    {
        PERROR("Could not allocate dump_mem");
        goto error_out;
    }

    if ( xc_domain_getinfo(xc_handle, domid, 1, &info) != 1 )
    {
        PERROR("Could not get info for domain");
        goto error_out;
    }

    if ( domid != info.domid )
    {
        PERROR("Domain %d does not exist", domid);
        goto error_out;
    }

    for ( i = 0; i <= info.max_vcpu_id; i++ )
        if ( xc_vcpu_getcontext(xc_handle, domid, i, &ctxt[nr_vcpus]) == 0)
            nr_vcpus++;

    nr_pages = info.nr_pages;

    header.xch_magic = info.hvm ? XC_CORE_MAGIC_HVM : XC_CORE_MAGIC;
    header.xch_nr_vcpus = nr_vcpus;
    header.xch_nr_pages = nr_pages;
    header.xch_ctxt_offset = sizeof(struct xc_core_header);
    header.xch_index_offset = sizeof(struct xc_core_header) +
        sizeof(vcpu_guest_context_t)*nr_vcpus;
    dummy_len = (sizeof(struct xc_core_header) +
                 (sizeof(vcpu_guest_context_t) * nr_vcpus) +
                 (nr_pages * sizeof(*page_array)));
    header.xch_pages_offset = round_pgup(dummy_len);

    sts = dump_rtn(args, (char *)&header, sizeof(struct xc_core_header));
    if ( sts != 0 )
        goto error_out;

    sts = dump_rtn(args, (char *)&ctxt, sizeof(ctxt[0]) * nr_vcpus);
    if ( sts != 0 )
        goto error_out;

    if ( (page_array = malloc(nr_pages * sizeof(*page_array))) == NULL )
    {
        IPRINTF("Could not allocate memory\n");
        goto error_out;
    }
    if ( xc_get_pfn_list(xc_handle, domid, page_array, nr_pages) != nr_pages )
    {
        IPRINTF("Could not get the page frame list\n");
        goto error_out;
    }
    sts = dump_rtn(args, (char *)page_array, nr_pages * sizeof(*page_array));
    if ( sts != 0 )
        goto error_out;

    /* Pad the output data to page alignment. */
    memset(dummy, 0, PAGE_SIZE);
    sts = dump_rtn(args, dummy, header.xch_pages_offset - dummy_len);
    if ( sts != 0 )
        goto error_out;

    for ( dump_mem = dump_mem_start, i = 0; i < nr_pages; i++ )
    {
        copy_from_domain_page(xc_handle, domid, page_array[i], dump_mem);
        dump_mem += PAGE_SIZE;
        if ( ((i + 1) % DUMP_INCREMENT == 0) || ((i + 1) == nr_pages) )
        {
            sts = dump_rtn(args, dump_mem_start, dump_mem - dump_mem_start);
            if ( sts != 0 )
                goto error_out;
            dump_mem = dump_mem_start;
        }
    }

    free(dump_mem_start);
    free(page_array);
    return 0;

 error_out:
    free(dump_mem_start);
    free(page_array);
    return -1;
}

/* Callback args for writing to a local dump file. */
struct dump_args {
    int     fd;
};

/* Callback routine for writing to a local dump file. */
static int local_file_dump(void *args, char *buffer, unsigned int length)
{
    struct dump_args *da = args;
    int bytes, offset;

    for ( offset = 0; offset < length; offset += bytes )
    {
        bytes = write(da->fd, &buffer[offset], length-offset);
        if ( bytes <= 0 )
        {
            PERROR("Failed to write buffer");
            return -errno;
        }
    }

    return 0;
}

int
xc_domain_dumpcore(int xc_handle,
                   uint32_t domid,
                   const char *corename)
{
    struct dump_args da;
    int sts;

    if ( (da.fd = open(corename, O_CREAT|O_RDWR, S_IWUSR|S_IRUSR)) < 0 )
    {
        PERROR("Could not open corefile %s", corename);
        return -errno;
    }

    sts = xc_domain_dumpcore_via_callback(
        xc_handle, domid, &da, &local_file_dump);

    close(da.fd);

    return sts;
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
