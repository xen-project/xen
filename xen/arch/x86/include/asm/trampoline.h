/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef X86_ASM_TRAMPOLINE_H
#define X86_ASM_TRAMPOLINE_H

/*
 * Data in or about the low memory trampoline.
 *
 * x86 systems software typically needs a block of logic below the 1M
 * boundary, commonly called the trampoline, containing 16-bit logic.  Xen has
 * a combined trampoline of all necessary 16-bit logic, formed of two parts.
 *
 * 1) The permanent trampoline; a single 4k page containing:
 *
 *    - The INIT-SIPI-SIPI entrypoint for APs, and
 *    - The S3 wakeup vector.
 *
 *    Both of these are 16-bit entrypoints, responsible for activating paging
 *    and getting into 64-bit mode.  This requires the permanent trampoline to
 *    be identity mapped in idle_pg_table[].
 *
 *    The SIPI64 spec deprecates the 16-bit AP entrypoint, while S0ix (also
 *    called Low Power Idle or Connected Standby) deprecates S3.
 *
 * 2) The boot trampoline:
 *
 *    This is used by the BSP to drop into 16-bit mode, make various BIOS
 *    calls to obtain E820/EDID/etc.  It follows the permanent and exceeds 4k,
 *    but is only used in 16-bit and 32-bit unpaged mode so does not need
 *    mapping in pagetables.
 *
 *    When the BIOS calls are complete, execution does join back with the AP
 *    path, and becomes subject to the same paging requirements.  This path is
 *    not needed for non-BIOS boots.
 *
 * The location of trampoline is not fixed.  The layout of low memory varies
 * greatly from platform to platform.  Therefore, the trampoline is relocated
 * manually as part of placement.
 */

#include <xen/compiler.h>
#include <xen/types.h>

/*
 * Start and end of the trampoline section, as linked into Xen.  It is within
 * the .init section and reclaimed after boot.
 */
/* SAF-0-safe */
extern char trampoline_start[], trampoline_end[];

/*
 * The physical address of trampoline_start[] in low memory.  It must be below
 * the 1M boundary (as the trampoline contains 16-bit code), and must be 4k
 * aligned (SIPI requirement for APs).
 */
extern uint32_t trampoline_phys;

/*
 * Calculate the physical address of a symbol in the trampoline.
 *
 * Should only be used on symbols declared later in this header.  Specifying
 * other symbols will compile but malfunction when used, as will using this
 * helper before the trampoline is placed.
 */
#define bootsym_phys(sym)                                       \
    (trampoline_phys + ((unsigned long)&(sym) -                 \
                        (unsigned long)trampoline_start))

/* Given a trampoline symbol, construct a pointer to it in the directmap. */
#define bootsym(sym) (*((typeof(sym) *)__va(bootsym_phys(sym))))

/* The INIT-SIPI-SIPI entrypoint.  16-bit code. */
void nocall trampoline_realmode_entry(void);

/* The S3 wakeup vector.  16-bit code. */
void nocall wakeup_start(void);

/*
 * A variable in the trampoline, containing Xen's physical address.  Amongst
 * other things, it is used to find idle_pg_table[] in order to enable paging
 * and activate 64-bit mode.  This variable needs keeping in sync with
 * xen_phys_start.
 */
extern uint32_t trampoline_xen_phys_start;

/* A semaphore to indicate signs-of-life at the start of the AP boot path. */
extern uint8_t trampoline_cpu_started;

/*
 * Extra MSR_EFER settings when activating Long Mode.  EFER_NXE is necessary
 * for APs to boot if the BSP found and activated support.
 */
extern uint32_t trampoline_efer;

/*
 * When nonzero, clear the specified bits in MSR_MISC_ENABLE.  This is
 * necessary to clobber XD_DISABLE before trying to set MSR_EFER.NXE.
 */
extern uint64_t trampoline_misc_enable_off;

/* Quirks about video mode-setting on S3 resume. */
extern uint8_t video_flags;

/* BIOS Int 16h, Fn 02h.  The keyboard shift status. */
extern uint8_t kbd_shift_flags;

/* Extended Display Identification Data, gathered from the BIOS. */
extern uint16_t boot_edid_caps;
extern uint8_t boot_edid_info[128];

#endif /* X86_ASM_TRAMPOLINE_H */
