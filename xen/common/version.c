#include <xen/bug.h>
#include <xen/compile.h>
#include <xen/init.h>
#include <xen/errno.h>
#include <xen/lib.h>
#include <xen/sections.h>
#include <xen/string.h>
#include <xen/types.h>
#include <xen/efi.h>
#include <xen/elf.h>
#include <xen/version.h>

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

static const char build_info[] =
    "debug="
#ifdef CONFIG_DEBUG
    "y"
#else
    "n"
#endif
#ifdef CONFIG_COVERAGE
# ifdef __clang__
    " llvmcov=y"
# else
    " gcov=y"
# endif
#endif
#ifdef CONFIG_UBSAN
    " ubsan=y"
#endif
    "";

const char *xen_build_info(void)
{
    return build_info;
}

void print_version(void)
{
    printk("Xen version %d.%d%s (%s@%s) (%s) %s %s\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           xen_compile_by(), xen_compile_domain(), xen_compiler(),
           xen_build_info(), xen_compile_date());

    printk("Latest ChangeSet: %s\n", xen_changeset());
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

void print_build_id(void)
{
    /*
     * NB: build_id_len may be 0 if XEN_HAS_BUILD_ID=n.
     * Do not print empty build-id.
     */
    if ( build_id_len )
        printk("build-id: %*phN\n", build_id_len, build_id_p);
}

#ifdef BUILD_ID
/* Defined in linker script. */
extern const Elf_Note __note_gnu_build_id_start[], __note_gnu_build_id_end[];

int xen_build_id_check(const Elf_Note *n, unsigned int n_sz,
                       const void **p, unsigned int *len)
{
    /* Check if we really have a build-id. */
    ASSERT(n_sz > sizeof(*n));

    if ( NT_GNU_BUILD_ID != n->type )
        return -ENODATA;

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

struct pe_external_debug_directory
{
    uint32_t characteristics;
    uint32_t time_stamp;
    uint16_t major_version;
    uint16_t minor_version;
#define PE_IMAGE_DEBUG_TYPE_CODEVIEW 2
    uint32_t type;
    uint32_t size;
    uint32_t rva_of_data;
    uint32_t filepos_of_data;
};

struct cv_info_pdb70
{
#define CVINFO_PDB70_CVSIGNATURE 0x53445352 /* "RSDS" */
    uint32_t cv_signature;
    unsigned char signature[16];
    uint32_t age;
    char pdb_filename[];
};

void __init xen_build_init(void)
{
    const Elf_Note *n = __note_gnu_build_id_start;
    unsigned int sz;
    int rc;

    /* --build-id invoked with wrong parameters. */
    if ( __note_gnu_build_id_end <= &n[0] )
        return;

    /* Check for full Note header. */
    if ( &n[1] >= __note_gnu_build_id_end )
        return;

    sz = (uintptr_t)__note_gnu_build_id_end - (uintptr_t)n;

    rc = xen_build_id_check(n, sz, &build_id_p, &build_id_len);

#ifdef CONFIG_X86
    /*
     * xen.efi built with a new enough toolchain will have a CodeView record,
     * not an ELF note.
     */
    if ( rc )
    {
        const struct pe_external_debug_directory *dir = (const void *)n;

        /*
         * Validate that the full-note-header check above won't prevent
         * fall-through to the CodeView case here.
         */
        BUILD_BUG_ON(sizeof(*n) > sizeof(*dir));

        if ( sz > sizeof(*dir) + sizeof(struct cv_info_pdb70) &&
             dir->type == PE_IMAGE_DEBUG_TYPE_CODEVIEW &&
             dir->size > sizeof(struct cv_info_pdb70) &&
             XEN_VIRT_START + dir->rva_of_data == (unsigned long)(dir + 1) )
        {
            const struct cv_info_pdb70 *info = (const void *)(dir + 1);

            if ( info->cv_signature == CVINFO_PDB70_CVSIGNATURE )
            {
                build_id_p = info->signature;
                build_id_len = sizeof(info->signature);
                rc = 0;
            }
        }
    }
#endif /* CONFIG_X86 */
}
#endif /* BUILD_ID */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
