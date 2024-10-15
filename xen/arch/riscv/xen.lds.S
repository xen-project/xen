#include <xen/lib.h>
#include <xen/xen.lds.h>

OUTPUT_ARCH(riscv)
ENTRY(start)

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
    .text : {
        _stext = .;            /* Text section */
        *(.text.header)

        *(.text.cold)
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)

        *(.text)
#ifdef CONFIG_CC_SPLIT_SECTIONS
        *(.text.*)
#endif

        . = ALIGN(IDENT_AREA_SIZE);
        _ident_start = .;
        *(.text.ident)
        _ident_end = .;

        *(.fixup)
        *(.gnu.warning)
        . = ALIGN(POINTER_ALIGN);
        _etext = .;             /* End of text section */
    } :text

    . = ALIGN(PAGE_SIZE);
    .rodata : {
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
    .note.gnu.build-id : {
        __note_gnu_build_id_start = .;
        *(.note.gnu.build-id)
        __note_gnu_build_id_end = .;
    } :note :text
    #endif
    _erodata = .;                /* End of read-only data */

    . = ALIGN(PAGE_SIZE);
    .data.ro_after_init : {
        __ro_after_init_start = .;
        *(.data.ro_after_init)
        . = ALIGN(PAGE_SIZE);
        __ro_after_init_end = .;
    } : text

    .data.read_mostly : {
        *(.data.read_mostly)
    } :text

    . = ALIGN(PAGE_SIZE);
    .data : {                    /* Data */
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
    .init.text : {
        _sinittext = .;
        *(.init.text)
        _einittext = .;
        . = ALIGN(PAGE_SIZE);        /* Avoid mapping alt insns executable */
    } :text
    . = ALIGN(PAGE_SIZE);
    .init.data : {
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

    .got : {
        *(.got)
    } : text

    .got.plt : {
        *(.got.plt)
    } : text

    . = ALIGN(POINTER_ALIGN);
    __init_end = .;

    .bss : {                     /* BSS */
        . = ALIGN(POINTER_ALIGN);
        __bss_start = .;
        *(.bss.stack_aligned)
        *(.bss.page_aligned)
        PERCPU_BSS
        *(.sbss .sbss.* .bss .bss.*)
        . = ALIGN(POINTER_ALIGN);
        __bss_end = .;
    } :text
    _end = . ;

    /* Section for the device tree blob (if any). */
    .dtb : { *(.dtb) } :text

    DWARF2_DEBUG_SECTIONS

    DISCARD_SECTIONS

    STABS_DEBUG_SECTIONS

    ELF_DETAILS_SECTIONS
}

ASSERT(IS_ALIGNED(__bss_start,      POINTER_ALIGN), "__bss_start is misaligned")
ASSERT(IS_ALIGNED(__bss_end,        POINTER_ALIGN), "__bss_end is misaligned")

ASSERT(!SIZEOF(.got),      ".got non-empty")
ASSERT(!SIZEOF(.got.plt),  ".got.plt non-empty")

/*
 * Changing the size of Xen binary can require an update of
 * PGTBL_INITIAL_COUNT.
 */
ASSERT(_end - _start <= XEN_VIRT_SIZE, "Xen too large for early-boot assumptions")

ASSERT(_ident_end - _ident_start <= IDENT_AREA_SIZE, "identity region is too big");
