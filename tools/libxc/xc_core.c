#include "xg_private.h"
#include <stdlib.h>
#include <unistd.h>

/* number of pages to write at a time */
#define DUMP_INCREMENT (4 * 1024)
#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)

/* Callback args for writing to a local dump file. */
struct dump_args {
    int     fd;
    int     incomp_fd;
};

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
    unsigned long n, nr_pages;
    xen_pfn_t *page_array = NULL;
    xc_dominfo_t info;
    int i, nr_vcpus = 0;
    char *dump_mem, *dump_mem_start = NULL;
    struct xc_core_header header;
    vcpu_guest_context_t  ctxt[MAX_VIRT_CPUS];
    char dummy[PAGE_SIZE];
    int dummy_len;
    int sts;
    unsigned int cpy_err_cnt = 0;
    struct dump_args *da = args;
    int fd = da->fd;
    int incomp_fd = da->incomp_fd;
    char cpy_err_mesg[64];
    int mesg_bytes;

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

    header.xch_magic = XC_CORE_MAGIC;
    header.xch_nr_vcpus = nr_vcpus;
    header.xch_nr_pages = nr_pages;
    header.xch_ctxt_offset = sizeof(struct xc_core_header);
    header.xch_index_offset = sizeof(struct xc_core_header) +
        sizeof(vcpu_guest_context_t)*nr_vcpus;
    dummy_len = (sizeof(struct xc_core_header) +
                 (sizeof(vcpu_guest_context_t) * nr_vcpus) +
                 (nr_pages * sizeof(xen_pfn_t)));
    header.xch_pages_offset = round_pgup(dummy_len);

    sts = dump_rtn(fd, (char *)&header, sizeof(struct xc_core_header));
    if ( sts != 0 )
        goto error_out;

    sts = dump_rtn(fd, (char *)&ctxt, sizeof(ctxt[0]) * nr_vcpus);
    if ( sts != 0 )
        goto error_out;

    if ( (page_array = malloc(nr_pages * sizeof(xen_pfn_t))) == NULL )
    {
        IPRINTF("Could not allocate memory\n");
        goto error_out;
    }
    if ( xc_get_pfn_list(xc_handle, domid, page_array, nr_pages) != nr_pages )
    {
        IPRINTF("Could not get the page frame list\n");
        goto error_out;
    }
    sts = dump_rtn(fd, (char *)page_array, nr_pages * sizeof(xen_pfn_t));
    if ( sts != 0 )
        goto error_out;

    /* Pad the output data to page alignment. */
    memset(dummy, 0, PAGE_SIZE);
    sts = dump_rtn(fd, dummy, header.xch_pages_offset - dummy_len);
    if ( sts != 0 )
        goto error_out;

    for ( dump_mem = dump_mem_start, n = 0; n < nr_pages; n++ )
    {
        sts = copy_from_domain_page(xc_handle, domid, page_array[i], dump_mem);
        if( sts != 0 ){
            memset(dump_mem, 0, PAGE_SIZE);
            cpy_err_cnt++;
            memset(cpy_err_mesg, 0, sizeof(cpy_err_mesg));
            mesg_bytes = sprintf(cpy_err_mesg, "Cannot copy_from_domain_page (%lu)\n", n);
            dump_rtn(incomp_fd, (char *)cpy_err_mesg, mesg_bytes);
        }

        dump_mem += PAGE_SIZE;
        if ( ((n + 1) % DUMP_INCREMENT == 0) || ((n + 1) == nr_pages) )
        {
            sts = dump_rtn(fd, dump_mem_start, dump_mem - dump_mem_start);
            if ( sts != 0 )
                goto error_out;
            dump_mem = dump_mem_start;
        }
    }
    if( cpy_err_cnt != 0 ){
        IPRINTF("Could not copy from domid=%d (%d)pages\n", domid, cpy_err_cnt);
        goto error_out;
    }

    free(dump_mem_start);
    free(page_array);
    return 0;

 error_out:
    free(dump_mem_start);
    free(page_array);
    return -1;
}

/* Callback routine for writing to a local dump file. */
static int local_file_dump(int fd, char *buffer, unsigned int length)
{
    int bytes, offset;

    for ( offset = 0; offset < length; offset += bytes )
    {
        bytes = write(fd, &buffer[offset], length-offset);
        if ( bytes <= 0 )
        {
            PERROR("Failed to write buffer: %s", strerror(errno));
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
    char *incomp_file;
    int sts;

    if ( (da.fd = open(corename, O_CREAT|O_RDWR, S_IWUSR|S_IRUSR)) < 0 )
    {
        PERROR("Could not open corefile %s: %s", corename, strerror(errno));
        return -errno;
    }

    
    if ( (incomp_file = (char *)malloc(sizeof(corename) + 12)) == NULL )
    {
        PERROR("Could not allocate incomp_file");
        return -errno;
    }

    sprintf(incomp_file, "%s-incomp.list", corename);
    if ( (da.incomp_fd = open(incomp_file, O_CREAT|O_RDWR, S_IWUSR|S_IRUSR)) < 0 )
    {
        PERROR("Could not open corefile %s: %s", incomp_file, strerror(errno));
        return -errno;
    }

    sts = xc_domain_dumpcore_via_callback(
        xc_handle, domid, &da, &local_file_dump);

    close(da.fd);
    close(da.incomp_fd);

    if( sts == 0)
        unlink(incomp_file);

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
