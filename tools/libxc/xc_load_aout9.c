
#include "xg_private.h"
#include "xc_aout9.h"

#if defined(__i386__)
  #define A9_MAGIC I_MAGIC
#elif defined(__x86_64__)
  #define A9_MAGIC S_MAGIC
#elif defined(__ia64__)
  #define A9_MAGIC 0
#else
#error "Unsupported architecture"
#endif

#define round_pgup(_p)    (((_p)+(PAGE_SIZE-1))&PAGE_MASK)
#define KZERO             0x80000000
#define KOFFSET(_p)       ((_p)&~KZERO)

static int parseaout9image(const char *, unsigned long, struct domain_setup_info *);
static int loadaout9image(const char *, unsigned long, int, uint32_t, unsigned long *, struct domain_setup_info *);
static void copyout(int, uint32_t, unsigned long *, unsigned long, const char *, int);
struct Exec *get_header(const char *, unsigned long, struct Exec *);


int 
probe_aout9(
    const char *image,
    unsigned long image_size,
    struct load_funcs *load_funcs)
{
    struct Exec ehdr;

    if (!get_header(image, image_size, &ehdr)) {
        ERROR("Kernel image does not have a a.out9 header.");
        return -EINVAL;
    }

    load_funcs->parseimage = parseaout9image;
    load_funcs->loadimage = loadaout9image;
    return 0;
}

static int 
parseaout9image(
    const char *image,
    unsigned long image_size,
    struct domain_setup_info *dsi)
{
    struct Exec ehdr;
    unsigned long start, dstart, end;

    if (!get_header(image, image_size, &ehdr)) {
        ERROR("Kernel image does not have a a.out9 header.");
        return -EINVAL;
    }

    if (sizeof ehdr + ehdr.text + ehdr.data > image_size) {
        ERROR("a.out program extends past end of image.");
        return -EINVAL;
    }

    start = ehdr.entry;
    dstart = round_pgup(start + ehdr.text);
    end = dstart + ehdr.data + ehdr.bss;

    dsi->v_start     = KZERO;
    dsi->v_kernstart = start;
    dsi->v_kernend   = end;
    dsi->v_kernentry = ehdr.entry;
    dsi->v_end       = end;

    /* XXX load symbols */

    return 0;
}

static int 
loadaout9image(
    const char *image,
    unsigned long image_size,
    int xch, uint32_t dom,
    unsigned long *parray,
    struct domain_setup_info *dsi)
{
    struct Exec ehdr;
    unsigned long start, dstart;

    if (!get_header(image, image_size, &ehdr)) {
        ERROR("Kernel image does not have a a.out9 header.");
        return -EINVAL;
    }

    start = ehdr.entry;
    dstart = round_pgup(start + ehdr.text);
    copyout(xch, dom, parray, start, image + sizeof ehdr, ehdr.text);
    copyout(xch, dom, parray, dstart,
            image + sizeof ehdr + ehdr.text, ehdr.data);

    /* XXX load symbols */

    return 0;
}

/*
 * copyout data to the domain given an offset to the start
 * of its memory region described by parray.
 */
static void
copyout(
    int xch, uint32_t dom,
    unsigned long *parray,
    unsigned long addr,
    const char *buf,
    int sz)
{
    unsigned long pgoff, chunksz, off;
    void *pg;

    off = KOFFSET(addr);
    while (sz > 0) {
        pgoff = off & (PAGE_SIZE-1);
        chunksz = sz;
        if(chunksz > PAGE_SIZE - pgoff)
            chunksz = PAGE_SIZE - pgoff;

        pg = xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_WRITE, 
                                  parray[off>>PAGE_SHIFT]);
        memcpy(pg + pgoff, buf, chunksz);
        munmap(pg, PAGE_SIZE);

        off += chunksz;
        buf += chunksz;
        sz -= chunksz;
    }
}

#define swap16(_v) ((((uint16_t)(_v)>>8)&0xff)|(((uint16_t)(_v)&0xff)<<8))
#define swap32(_v) (((uint32_t)swap16((uint16_t)(_v))<<16)|(uint32_t)swap16((uint32_t)((_v)>>16)))

/*
 * Decode the header from the start of image and return it.
 */
struct Exec *
get_header(
    const char *image,
    unsigned long image_size,
    struct Exec *ehdr)
{
    uint32_t *v, x;
    int i;

    if (A9_MAGIC == 0)
        return 0;

    if (image_size < sizeof ehdr)
        return 0;

    /* ... all big endian words */
    v = (uint32_t *)ehdr;
    for (i = 0; i < sizeof(*ehdr); i += 4) {
        x = *(uint32_t *)&image[i];
        v[i/4] = swap32(x);
    }

    if(ehdr->magic != A9_MAGIC)
        return 0;
    return ehdr;
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
