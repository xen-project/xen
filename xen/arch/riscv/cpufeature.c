/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Originally taken for Linux kernel v6.12-rc3.
 *
 * Copyright (C) 2015 ARM Ltd.
 * Copyright (C) 2017 SiFive
 * Copyright (C) 2024 Vates
 */

#include <xen/bitmap.h>
#include <xen/bootfdt.h>
#include <xen/ctype.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/sections.h>

#include <asm/cpufeature.h>

#ifdef CONFIG_ACPI
# error "cpufeature.c functions should be updated to support ACPI"
#endif

struct riscv_isa_ext_data {
    unsigned int id;
    const char *name;
};

#define RISCV_ISA_EXT_DATA(ext_name)            \
{                                               \
    .id = RISCV_ISA_EXT_ ## ext_name,           \
    .name = #ext_name,                          \
}

/* Host ISA bitmap */
static __ro_after_init DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX);

static int __init dt_get_cpuid_from_node(const struct dt_device_node *cpu,
                                         unsigned long *dt_cpuid)
{
    const __be32 *prop;
    unsigned int reg_len;

    /*
     * For debug purpose check dt_n_size_cells(cpu) value.
     *
     * Based on DT's bindings [1] and RISC-V's DTS files in kernel #size-cells
     * for cpu node is expected to be 0.
     *
     * [1] https://www.kernel.org/doc/Documentation/devicetree/bindings/riscv/cpus.txt
     */
    if ( dt_n_size_cells(cpu) != 0 )
        printk("DT's cpu node `%s`: #size-cells %d\n",
               dt_node_full_name(cpu), dt_n_size_cells(cpu));

    prop = dt_get_property(cpu, "reg", &reg_len);
    if ( !prop )
    {
        printk("cpu node `%s`: has no reg property\n", dt_node_full_name(cpu));
        return -EINVAL;
    }

    if ( reg_len < dt_cells_to_size(dt_n_addr_cells(cpu)) )
    {
        printk("cpu node `%s`: reg property too short\n",
               dt_node_full_name(cpu));
        return -EINVAL;
    }

    /*
     * It is safe to convert `paddr_t` to `unsigned long` as dt_read_paddr()
     * in the context of this function returns cpuid which according to RISC-V
     * specification could be from 0 to ((1ULL << (MXLEN)) - 1), where
     * MXLEN=32 for RV32 and MXLEN=64 for RV64.
     */
    *dt_cpuid = dt_read_paddr(prop, dt_n_addr_cells(cpu));

    return 0;
}

/*
 * The canonical order of ISA extension names in the ISA string is defined in
 * chapter 27 of the unprivileged specification.
 *
 * The specification uses vague wording, such as should, when it comes to
 * ordering, so for our purposes the following rules apply:
 *
 * 1. All multi-letter extensions must be separated from other extensions by an
 *    underscore.
 *
 * 2. Additional standard extensions (starting with 'Z') must be sorted after
 *    single-letter extensions and before any higher-privileged extensions.
 *
 * 3. The first letter following the 'Z' conventionally indicates the most
 *    closely related alphabetical extension category, IMAFDQLCBKJTPVH.
 *    If multiple 'Z' extensions are named, they must be ordered first by
 *    category, then alphabetically within a category.
 *
 * 4. Standard supervisor-level extensions (starting with 'S') must be listed
 *    after standard unprivileged extensions.  If multiple supervisor-level
 *    extensions are listed, they must be ordered alphabetically.
 *
 * 5. Standard machine-level extensions (starting with 'Zxm') must be listed
 *    after any lower-privileged, standard extensions.  If multiple
 *    machine-level extensions are listed, they must be ordered
 *    alphabetically.
 *
 * 6. Non-standard extensions (starting with 'X') must be listed after all
 *    standard extensions. If multiple non-standard extensions are listed, they
 *    must be ordered alphabetically.
 *
 * An example string following the order is:
 *    rv64imadc_zifoo_zigoo_zafoo_sbar_scar_zxmbaz_xqux_xrux
 *
 * New entries to this struct should follow the ordering rules described above.
 *
 * Extension name must be all lowercase (according to device-tree binding)
 * and strncmp() is used in match_isa_ext() to compare extension names instead
 * of strncasecmp().
 */
const struct riscv_isa_ext_data __initconst riscv_isa_ext[] = {
    RISCV_ISA_EXT_DATA(i),
    RISCV_ISA_EXT_DATA(m),
    RISCV_ISA_EXT_DATA(a),
    RISCV_ISA_EXT_DATA(f),
    RISCV_ISA_EXT_DATA(d),
    RISCV_ISA_EXT_DATA(q),
    RISCV_ISA_EXT_DATA(c),
    RISCV_ISA_EXT_DATA(h),
    RISCV_ISA_EXT_DATA(zicntr),
    RISCV_ISA_EXT_DATA(zicsr),
    RISCV_ISA_EXT_DATA(zifencei),
    RISCV_ISA_EXT_DATA(zihintpause),
    RISCV_ISA_EXT_DATA(zihpm),
    RISCV_ISA_EXT_DATA(zba),
    RISCV_ISA_EXT_DATA(zbb),
    RISCV_ISA_EXT_DATA(zbs),
    RISCV_ISA_EXT_DATA(smaia),
    RISCV_ISA_EXT_DATA(ssaia),
    RISCV_ISA_EXT_DATA(svpbmt),
};

static const struct riscv_isa_ext_data __initconst required_extensions[] = {
    RISCV_ISA_EXT_DATA(i),
    RISCV_ISA_EXT_DATA(m),
    RISCV_ISA_EXT_DATA(a),
#ifdef CONFIG_RISCV_ISA_C
    RISCV_ISA_EXT_DATA(c),
#endif
    RISCV_ISA_EXT_DATA(h),
    RISCV_ISA_EXT_DATA(zicsr),
    RISCV_ISA_EXT_DATA(zifencei),
    RISCV_ISA_EXT_DATA(zihintpause),
    RISCV_ISA_EXT_DATA(zbb),
    RISCV_ISA_EXT_DATA(svpbmt),
};

static bool __init is_lowercase_extension_name(const char *str)
{
    /*
     * `str` could contain full riscv,isa string from device tree so one
     * of the stop conditions is checking for '_' as extensions are
     * separated by '_'.
     */
    for ( unsigned int i = 0; (str[i] != '\0') && (str[i] != '_'); i++ )
        if ( !isdigit(str[i]) && !islower(str[i]) )
            return false;

    return true;
}

static void __init match_isa_ext(const char *name, const char *name_end,
                                 unsigned long *bitmap)
{
    const size_t riscv_isa_ext_count = ARRAY_SIZE(riscv_isa_ext);

    for ( unsigned int i = 0; i < riscv_isa_ext_count; i++ )
    {
        const struct riscv_isa_ext_data *ext = &riscv_isa_ext[i];

        /*
         * `ext->name` (according to initialization of riscv_isa_ext[]
         * elements) must be all in lowercase.
         */
        ASSERT(is_lowercase_extension_name(ext->name));

        if ( (name_end - name == strlen(ext->name)) &&
             !memcmp(name, ext->name, name_end - name) )
        {
            __set_bit(ext->id, bitmap);
            break;
        }
    }
}

static int __init riscv_isa_parse_string(const char *isa,
                                         unsigned long *out_bitmap)
{
    if ( (isa[0] != 'r') && (isa[1] != 'v') )
        return -EINVAL;

#if defined(CONFIG_RISCV_32)
    if ( isa[2] != '3' && isa[3] != '2' )
        return -EINVAL;
#elif defined(CONFIG_RISCV_64)
    if ( isa[2] != '6' && isa[3] != '4' )
        return -EINVAL;
#else
# error "unsupported RISC-V bitness"
#endif

    /*
     * In unpriv. specification (*_20240411) is mentioned the following:
     * (1) A RISC-V ISA is defined as a base integer ISA, which must be
     *     present in any implementation, plus optional extensions to
     *     the base ISA.
     * (2) Chapter 6 describes the RV32E and RV64E subset variants of
     *     the RV32I or RV64I base instruction sets respectively, which
     *     have been added to support small microcontrollers, and which
     *     have half the number of integer registers.
     *
     * What means that isa should contain, at least, I or E.
     *
     * As Xen isn't expected to be run on microcontrollers and according
     * to device tree binding the first extension should be "i".
     */
    if ( isa[4] != 'i' )
        return -EINVAL;

    isa += 4;

    while ( *isa )
    {
        const char *ext = isa++;
        const char *ext_end = isa;

        switch ( *ext )
        {
        case 'x':
            printk_once("Vendor extensions are ignored in riscv,isa\n");
            /*
             * To skip an extension, we find its end.
             * As multi-letter extensions must be split from other multi-letter
             * extensions with an "_", the end of a multi-letter extension will
             * either be the null character or the "_" at the start of the next
             * multi-letter extension.
             */
            for ( ; *isa && *isa != '_'; ++isa )
                if ( unlikely(!isalnum(*isa)) )
                    goto riscv_isa_parse_string_err;

            ext_end = NULL;
            break;

        case 's':
            /*
             * Workaround for invalid single-letter 's' & 'u' (QEMU):
             *   Before QEMU 7.1 it was an issue with misa to ISA string
             *   conversion:
             *     https://patchwork.kernel.org/project/qemu-devel/patch/dee09d708405075420b29115c1e9e87910b8da55.1648270894.git.research_trasio@irq.a4lg.com/#24792587
             *   Additional details of the workaround on Linux kernel side:
             *     https://lore.kernel.org/linux-riscv/ae93358e-e117-b43d-faad-772c529f846c@irq.a4lg.com/#t
             *
             * No need to set the bit in riscv_isa as 's' & 'u' are
             * not valid ISA extensions. It works unless the first
             * multi-letter extension in the ISA string begins with
             * "Su" and is not prefixed with an underscore.
             */
            if ( ext[-1] != '_' && ext[1] == 'u' )
            {
                ++isa;
                ext_end = NULL;
                break;
            }
            fallthrough;
        case 'z':
            /*
             * Before attempting to parse the extension itself, we find its end.
             * As multi-letter extensions must be split from other multi-letter
             * extensions with an "_", the end of a multi-letter extension will
             * either be the null character or the "_" at the start of the next
             * multi-letter extension.
             *
             * Next, as the extensions version is currently ignored, we
             * eliminate that portion. This is done by parsing backwards from
             * the end of the extension, removing any numbers. This may be a
             * major or minor number however, so the process is repeated if a
             * minor number was found.
             *
             * ext_end is intended to represent the first character *after* the
             * name portion of an extension, but will be decremented to the last
             * character itself while eliminating the extensions version number.
             * A simple re-increment solves this problem.
             */
            for ( ; *isa && *isa != '_'; ++isa )
                if ( unlikely(!isalnum(*isa)) )
                    goto riscv_isa_parse_string_err;

            ext_end = isa;

            if ( !isdigit(ext_end[-1]) )
                break;

            while ( isdigit(*--ext_end) )
                ;

            if ( ext_end[0] != 'p' || !isdigit(ext_end[-1]) )
            {
                ++ext_end;
                break;
            }

            while ( isdigit(*--ext_end) )
                ;

            ++ext_end;
            break;

        /*
         * If someone mentioned `b` extension in riscv,isa instead of Zb{a,b,s}
         * explicitly then set bits exlicitly in out_bitmap to satisfy
         * requirement of Zbb (mentioned in required_extensions[]).
         */
        case 'b':
            __set_bit(RISCV_ISA_EXT_zba, out_bitmap);
            __set_bit(RISCV_ISA_EXT_zbb, out_bitmap);
            __set_bit(RISCV_ISA_EXT_zbs, out_bitmap);
            fallthrough;
        default:
            /*
             * Things are a little easier for single-letter extensions, as they
             * are parsed forwards.
             *
             * After checking that our starting position is valid, we need to
             * ensure that, when isa was incremented at the start of the loop,
             * that it arrived at the start of the next extension.
             *
             * If we are already on a non-digit, there is nothing to do. Either
             * we have a multi-letter extension's _, or the start of an
             * extension.
             *
             * Otherwise we have found the current extension's major version
             * number. Parse past it, and a subsequent p/minor version number
             * if present. The `p` extension must not appear immediately after
             * a number, so there is no fear of missing it.
             */
            if ( unlikely(!isalpha(*ext)) )
                goto riscv_isa_parse_string_err;

            if ( !isdigit(*isa) )
                break;

            while ( isdigit(*++isa) )
                ;

            if ( *isa != 'p' )
                break;

            if ( !isdigit(*++isa) )
            {
                --isa;
                break;
            }

            while ( isdigit(*++isa) )
                ;

            break;
        }

        /*
         * The parser expects that at the start of an iteration isa points to the
         * first character of the next extension. As we stop parsing an extension
         * on meeting a non-alphanumeric character, an extra increment is needed
         * where the succeeding extension is a multi-letter prefixed with an "_".
         */
        if ( *isa == '_' )
            ++isa;

        if ( unlikely(!ext_end) )
            continue;

        match_isa_ext(ext, ext_end, out_bitmap);
    }

    return 0;

 riscv_isa_parse_string_err:
    printk("illegal symbol '%c' in riscv,isa string\n", *isa);
    return -EINVAL;
}

static void __init riscv_fill_hwcap_from_isa_string(void)
{
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    const struct dt_device_node *cpu;

    if ( !cpus )
    {
        printk("Missing /cpus node in the device tree?\n");
        return;
    }

    dt_for_each_child_node(cpus, cpu)
    {
        DECLARE_BITMAP(this_isa, RISCV_ISA_EXT_MAX);
        const char *isa;
        unsigned long cpuid;

        bitmap_zero(this_isa, RISCV_ISA_EXT_MAX);

        if ( !dt_device_type_is_equal(cpu, "cpu") )
            continue;

        if ( dt_get_cpuid_from_node(cpu, &cpuid) < 0 )
            continue;

        if ( dt_property_read_string(cpu, "riscv,isa", &isa) )
        {
            printk("Unable to find \"riscv,isa\" devicetree entry "
                   "for DT's cpu%ld node\n", cpuid);
            continue;
        }

        for ( unsigned int i = 0; (isa[i] != '\0'); i++ )
            if ( !isdigit(isa[i]) && (isa[i] != '_') && !islower(isa[i]) )
                panic("According to DT binding riscv,isa must be lowercase\n");

        if ( riscv_isa_parse_string(isa, this_isa) )
            panic("Check riscv,isa in dts file\n");

        if ( bitmap_empty(riscv_isa, RISCV_ISA_EXT_MAX) )
            bitmap_copy(riscv_isa, this_isa, RISCV_ISA_EXT_MAX);
        else
            bitmap_and(riscv_isa, riscv_isa, this_isa, RISCV_ISA_EXT_MAX);
    }
}

static bool __init has_isa_extensions_property(void)
{
    const struct dt_device_node *cpus = dt_find_node_by_path("/cpus");
    const struct dt_device_node *cpu;

    if ( !cpus )
    {
        printk("Missing /cpus node in the device tree?\n");
        return false;
    }

    dt_for_each_child_node(cpus, cpu)
    {
        const char *isa;

        if ( !dt_device_type_is_equal(cpu, "cpu") )
            continue;

        if ( dt_property_read_string(cpu, "riscv,isa-extensions", &isa) )
            continue;

        return true;
    }

    return false;
}

bool riscv_isa_extension_available(const unsigned long *isa_bitmap,
                                   enum riscv_isa_ext_id id)
{
    if ( !isa_bitmap )
        isa_bitmap = riscv_isa;

    if ( id >= RISCV_ISA_EXT_MAX )
        return false;

    return test_bit(id, isa_bitmap);
}

void __init riscv_fill_hwcap(void)
{
    unsigned int i;
    const size_t req_extns_amount = ARRAY_SIZE(required_extensions);
    bool all_extns_available = true;

    riscv_fill_hwcap_from_isa_string();

    if ( bitmap_empty(riscv_isa, RISCV_ISA_EXT_MAX) )
    {
        const char *failure_msg = has_isa_extensions_property() ?
                                  "\"riscv,isa-extension\" isn't supported" :
                                  "\"riscv,isa\" parsing failed";

        panic("HW capabilities parsing failed: %s\n", failure_msg);
    }

    for ( i = 0; i < req_extns_amount; i++ )
    {
        const struct riscv_isa_ext_data ext = required_extensions[i];

        if ( !riscv_isa_extension_available(NULL, ext.id) )
        {
            printk("Xen requires extension: %s\n", ext.name);
            all_extns_available = false;
        }
    }

    if ( !all_extns_available )
        panic("Look why the extensions above are needed in "
              "https://xenbits.xenproject.org/docs/unstable/misc/riscv/booting.txt\n");
}
