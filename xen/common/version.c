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

const void *__ro_after_init xen_build_id;
unsigned int __ro_after_init xen_build_id_len;

void print_version(void)
{
    printk("Xen version %d.%d%s (%s@%s) (%s) %s %s\n",
           xen_major_version(), xen_minor_version(), xen_extra_version(),
           xen_compile_by(), xen_compile_domain(), xen_compiler(),
           xen_build_info(), xen_compile_date());

    printk("Latest ChangeSet: %s\n", xen_changeset());

    if ( xen_build_id_len )
        printk("build-id: %*phN\n", xen_build_id_len, xen_build_id);
}

#ifdef BUILD_ID
/* Defined in linker script. */
extern const Elf_Note __note_gnu_build_id_start[], __note_gnu_build_id_end[];

/*
 * Check whether @n is a GNU Build ID note.
 *
 * Check that:
 *  - type is NT_GNU_BUILD_ID
 *  - name is GNU\0
 *  - desc is non-empty and fits within the buffer.
 *
 * If this returns true, the contents starts at n + NT_GNU_HDR_SIZE, and is
 * n->descsz long.
 */
bool is_gnu_build_id(const Elf_Note *n, unsigned int len)
{
    const char *name;

    if ( len <= NT_GNU_HDR_SIZE )
        return false;

    if ( n->type != NT_GNU_BUILD_ID ||
         n->namesz != 4 )
        return false;

    name = ELFNOTE_NAME(n);
    if ( strncmp(name, "GNU", 4) != 0 )
        return false;

    if ( n->descsz == 0 ||
         n->descsz > (len - NT_GNU_HDR_SIZE) )
        return false;

    return true;
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

    /* --build-id invoked with wrong parameters. */
    if ( __note_gnu_build_id_end <= &n[0] )
        return;

    /* Check for full Note header. */
    if ( &n[1] >= __note_gnu_build_id_end )
        return;

    sz = (uintptr_t)__note_gnu_build_id_end - (uintptr_t)n;

    if ( is_gnu_build_id(n, sz) )
    {
        xen_build_id     = (const void *)n + NT_GNU_HDR_SIZE;
        xen_build_id_len = n->descsz;
        return;
    }

#ifdef CONFIG_X86
    /*
     * xen.efi built with a new enough toolchain will have a CodeView record,
     * not an ELF note.
     */
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
                xen_build_id = info->signature;
                xen_build_id_len = sizeof(info->signature);
                return;
            }
        }
    }
#endif /* CONFIG_X86 */
}
#endif /* BUILD_ID */

/*
 * This assertion checks compatibility between 'unsigned long', 'void *',
 * and function pointers. This is true for most supported architectures,
 * including X86 (x86_64) and ARM (arm, aarch64).
 *
 * For more context on architecture-specific preprocessor guards, see
 * docs/misc/C-language-toolchain.rst.
 *
 * If porting Xen to a new architecture where this compatibility does not hold,
 * exclude that architecture from these checks and provide suitable commentary
 * and/or alternative checks as appropriate.
 */
static void __init __maybe_unused build_assertions(void)
{
    BUILD_BUG_ON(sizeof(unsigned long) != sizeof(void (*)(void)));
    BUILD_BUG_ON(sizeof(void *) != sizeof(void (*)(void)));

    BUILD_BUG_ON(NT_GNU_HDR_SIZE != sizeof(Elf_Note) + 4);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
