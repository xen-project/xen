#include <xen/lib.h>

#define DECL_SECTION_WITH_LADDR
#include <xen/xen.lds.h>

OUTPUT_ARCH(powerpc:common64)
ENTRY(start)

/* Used by the DECL_SECTION() macro to calculate physical load addresses */
#define __XEN_VIRT_START XEN_VIRT_START

PHDRS
{
    text PT_LOAD ;
#if defined(BUILD_ID)
    note PT_NOTE ;
#endif
}

SECTIONS
{
    . = XEN_VIRT_START;
    _start = .;

    DECL_SECTION(.text) {
        _stext = .;            /* Text section */
        *(.text.header)

        . = ALIGN(256);
        HIDDEN(_stext_exceptions = .);
        *(.text.exceptions)

        *(.text.cold)
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)

        *(.text)
#ifdef CONFIG_CC_SPLIT_SECTIONS
        *(.text.*)
#endif

        *(.fixup)
        *(.gnu.warning)
        . = ALIGN(POINTER_ALIGN);
        _etext = .;             /* End of text section */
    } :text

    . = ALIGN(PAGE_SIZE);
    DECL_SECTION(.rodata) {
        _srodata = .;          /* Read-only data */

        BUGFRAMES

        *(.rodata)
        *(.rodata.*)
        *(.data.rel.ro)
        *(.data.rel.ro.*)

        VPCI_ARRAY

        . = ALIGN(POINTER_ALIGN);
    } :text

    #if defined(BUILD_ID)
    . = ALIGN(4);
    DECL_SECTION(.note.gnu.build-id) {
        __note_gnu_build_id_start = .;
        *(.note.gnu.build-id)
        __note_gnu_build_id_end = .;
    } :note :text
    #endif
    _erodata = .;                /* End of read-only data */

    . = ALIGN(PAGE_SIZE);
    DECL_SECTION(.data.ro_after_init) {
        __ro_after_init_start = .;
        *(.data.ro_after_init)
        . = ALIGN(PAGE_SIZE);
        __ro_after_init_end = .;
    } :text

    DECL_SECTION(.data.read_mostly) {
        *(.data.read_mostly)
    } :text

    . = ALIGN(PAGE_SIZE);
    DECL_SECTION(.data) {                    /* Data */
        *(.data.page_aligned)
        . = ALIGN(8);
        __start_schedulers_array = .;
        *(.data.schedulers)
        __end_schedulers_array = .;

        HYPFS_PARAM

        *(.data .data.*)
        CONSTRUCTORS
    } :text

    DT_DEV_INFO                       /* Devicetree based device info */

    . = ALIGN(PAGE_SIZE);             /* Init code and data */
    __init_begin = .;
    DECL_SECTION(.init.text) {
        _sinittext = .;
        *(.init.text)
        _einittext = .;
        . = ALIGN(PAGE_SIZE);        /* Avoid mapping alt insns executable */
    } :text

    . = ALIGN(PAGE_SIZE);
    DECL_SECTION(init.data) {
        *(.init.rodata)
        *(.init.rodata.*)

        . = ALIGN(POINTER_ALIGN);
        __setup_start = .;
        *(.init.setup)
        __setup_end = .;

        __initcall_start = .;
        *(.initcallpresmp.init)
        __presmp_initcall_end = .;
        *(.initcall1.init)
        __initcall_end = .;

        LOCK_PROFILE_DATA

        *(.init.data)
        *(.init.data.rel)
        *(.init.data.rel.*)

        . = ALIGN(8);
        __ctors_start = .;
        *(.ctors)
        *(.init_array)
        *(SORT(.init_array.*))
        __ctors_end = .;
    } :text

    DECL_SECTION(.got) {
        *(.got .toc)
    } :text

    DECL_SECTION(.got.plt) {
        *(.got.plt)
    } :text

    . = ALIGN(POINTER_ALIGN);
    __init_end = .;

    DECL_SECTION(.bss) {                     /* BSS */
        __bss_start = .;
        *(.bss.stack_aligned)
        *(.bss.page_aligned)
        PERCPU_BSS
        *(.bss .bss.*)
        . = ALIGN(POINTER_ALIGN);
        __bss_end = .;
    } :text

    _end = . ;

    /* Section for the device tree blob (if any). */
    DECL_SECTION(.dtb) { *(.dtb) } :text

    DWARF2_DEBUG_SECTIONS

    DISCARD_SECTIONS

    STABS_DEBUG_SECTIONS

    ELF_DETAILS_SECTIONS
}

ASSERT(IS_ALIGNED(__bss_start,      POINTER_ALIGN), "__bss_start is misaligned")
ASSERT(IS_ALIGNED(__bss_end,        POINTER_ALIGN), "__bss_end is misaligned")

ASSERT(!SIZEOF(.got),      ".got non-empty")
ASSERT(!SIZEOF(.got.plt),  ".got.plt non-empty")

ASSERT(_stext_exceptions == EXCEPTION_VECTORS_START,
       ".text.exceptions not at expected location -- .text.header too big?");
