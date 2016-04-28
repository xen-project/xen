#include <xen/compile.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/elf.h>
#include <xen/version.h>

#include <asm/cache.h>

const char *xen_compile_date(void)
{
    return XEN_COMPILE_DATE;
}

const char *xen_compile_time(void)
{
    return XEN_COMPILE_TIME;
}

const char *xen_compile_by(void)
{
    return XEN_COMPILE_BY;
}

const char *xen_compile_domain(void)
{
    return XEN_COMPILE_DOMAIN;
}

const char *xen_compile_host(void)
{
    return XEN_COMPILE_HOST;
}

const char *xen_compiler(void)
{
    return XEN_COMPILER;
}

unsigned int xen_major_version(void)
{
    return XEN_VERSION;
}

unsigned int xen_minor_version(void)
{
    return XEN_SUBVERSION;
}

const char *xen_extra_version(void)
{
    return XEN_EXTRAVERSION;
}

const char *xen_changeset(void)
{
    return XEN_CHANGESET;
}

const char *xen_banner(void)
{
    return XEN_BANNER;
}

const char *xen_deny(void)
{
    return "<denied>";
}

static const void *build_id_p __read_mostly;
static unsigned int build_id_len __read_mostly;

int xen_build_id(const void **p, unsigned int *len)
{
    if ( !build_id_len )
        return -ENODATA;

    *len = build_id_len;
    *p = build_id_p;

    return 0;
}

#ifdef BUILD_ID
/* Defined in linker script. */
extern const Elf_Note __note_gnu_build_id_start[], __note_gnu_build_id_end[];

int xen_build_id_check(const Elf_Note *n, unsigned int n_sz,
                       const void **p, unsigned int *len)
{
    /* Check if we really have a build-id. */
    if ( NT_GNU_BUILD_ID != n->type )
        return -ENODATA;

    if ( n_sz <= sizeof(*n) )
        return -EINVAL;

    if ( n->namesz + n->descsz < n->namesz )
        return -EINVAL;

    if ( n->namesz < 4 /* GNU\0 */)
        return -EINVAL;

    if ( n->namesz + n->descsz > n_sz - sizeof(*n) )
        return -EINVAL;

    /* Sanity check, name should be "GNU" for ld-generated build-id. */
    if ( strncmp(ELFNOTE_NAME(n), "GNU", n->namesz) != 0 )
        return -ENODATA;

    if ( len )
        *len = n->descsz;
    if ( p )
        *p = ELFNOTE_DESC(n);

    return 0;
}

static int __init xen_build_init(void)
{
    const Elf_Note *n = __note_gnu_build_id_start;
    unsigned int sz;

    /* --build-id invoked with wrong parameters. */
    if ( __note_gnu_build_id_end <= &n[0] )
        return -ENODATA;

    /* Check for full Note header. */
    if ( &n[1] > __note_gnu_build_id_end )
        return -ENODATA;;

    sz = (void *)__note_gnu_build_id_end - (void *)n;

    return xen_build_id_check(n, sz, &build_id_p, &build_id_len);
}
__initcall(xen_build_init);
#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
