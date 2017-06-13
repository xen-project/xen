/******************************************************************************
 * edd.S
 *
 * BIOS Enhanced Disk Drive support
 * 
 * Copyright (C) 2002, 2003, 2004 Dell, Inc.
 * by Matt Domsch <Matt_Domsch@dell.com> October 2002
 * conformant to T13 Committee www.t13.org
 *   projects 1572D, 1484D, 1386D, 1226DT
 * disk signature read by Matt Domsch <Matt_Domsch@dell.com>
 *      and Andrew Wilks <Andrew_Wilks@dell.com> September 2003, June 2004
 * legacy CHS retrieval by Patrick J. LoPresti <patl@users.sourceforge.net>
 *      March 2004
 * Command line option parsing, Matt Domsch, November 2004
 *
 * Updated and ported for Xen by Keir Fraser <keir@xensource.com> June 2007
 */

#include <asm/edd.h>

        .code16

/* Offset of disc signature in the MBR. */
#define EDD_MBR_SIG_OFFSET      0x1B8

get_edd:
        cmpb    $2, bootsym(opt_edd)            # edd=off ?
        je      edd_done

# Do the BIOS Enhanced Disk Drive calls
# This consists of two calls:
#    int 13h ah=41h "Check Extensions Present"
#    int 13h ah=48h "Get Device Parameters"
#    int 13h ah=08h "Legacy Get Device Parameters"
#
# A buffer of size EDD_INFO_MAX*(EDDEXTSIZE+EDDPARMSIZE) is reserved at
# boot_edd_info, the first four bytes of which are used to store the device
# number, interface support map and version results from fn41. The next four
# bytes are used to store the legacy cylinders, heads, and sectors from fn08.
# The following 74 bytes are used to store the results from fn48.
# This code is sensitive to the size of the structs in edd.h
edd_start:
        /* ds:si points at fn48 results. Fn41 results go immediately before. */
        movw    $bootsym(boot_edd_info)+EDDEXTSIZE, %si
        movb    $0x80, %dl                      # BIOS device 0x80

edd_check_ext:
        movb    $0x41, %ah                      # 0x41 Check Extensions Present
        movw    $0x55AA, %bx                    # magic
        int     $0x13                           # make the call
        jc      edd_done                        # no more BIOS devices

        cmpw    $0xAA55, %bx                    # is magic right?
        jne     edd_next                        # nope, next...

        movb    %dl, %ds:-8(%si)                # store device number
        movb    %ah, %ds:-7(%si)                # store version
        movw    %cx, %ds:-6(%si)                # store extensions
        incb    bootsym(boot_edd_info_nr)       # note that we stored something

edd_get_device_params:
        movw    $EDDPARMSIZE, %ds:(%si)         # put size
        movw    $0x0, %ds:2(%si)                # work around buggy BIOSes
        movb    $0x48, %ah                      # 0x48 Get Device Parameters
        int     $0x13                           # make the call
                                                # Don't check for fail return
                                                # it doesn't matter.
edd_get_legacy_chs:
        xorw    %ax, %ax
        movw    %ax, %ds:-4(%si)
        movw    %ax, %ds:-2(%si)
        # Ralf Brown's Interrupt List says to set ES:DI to
        # 0000h:0000h "to guard against BIOS bugs"
        pushw   %es
        movw    %ax, %es
        movw    %ax, %di
        pushw   %dx                             # legacy call clobbers %dl
        movb    $0x08, %ah                      # 0x08 Legacy Get Device Params
        int     $0x13                           # make the call
        jc      edd_legacy_done                 # failed
        movb    %cl, %al                        # Low 6 bits are max
        andb    $0x3F, %al                      #   sector number
        movb    %al, %ds:-1(%si)                # Record max sect
        movb    %dh, %ds:-2(%si)                # Record max head number
        movb    %ch, %al                        # Low 8 bits of max cyl
        shr     $6, %cl
        movb    %cl, %ah                        # High 2 bits of max cyl
        movw    %ax, %ds:-4(%si)

edd_legacy_done:
        popw    %dx
        popw    %es
        movw    %si, %ax                        # increment si
        addw    $EDDPARMSIZE+EDDEXTSIZE, %ax
        movw    %ax, %si

edd_next:
        incb    %dl                             # increment to next device
        jz      edd_done
        cmpb    $EDD_INFO_MAX,bootsym(boot_edd_info_nr)
        jb      edd_check_ext

edd_done:
        cmpb    $1, bootsym(opt_edd)            # edd=skipmbr ?
        je      .Ledd_mbr_sig_skip

# Read the first sector of each BIOS disk device and store the 4-byte signature
.Ledd_mbr_sig_start:
        pushw   %es
        movb    $0x80, %dl                      # from device 80
        movw    $bootsym(boot_mbr_signature), %bx # store buffer ptr in bx
.Ledd_mbr_sig_read:
        pushw   %bx
        movw    $bootsym(boot_edd_info), %bx
        movzbw  bootsym(boot_edd_info_nr), %cx
        jcxz    .Ledd_mbr_sig_default
.Ledd_mbr_sig_find_info:
        cmpb    %dl, (%bx)
        ja      .Ledd_mbr_sig_default
        je      .Ledd_mbr_sig_get_size
        add     $EDDEXTSIZE+EDDPARMSIZE, %bx
        loop    .Ledd_mbr_sig_find_info
.Ledd_mbr_sig_default:
        movw    $(512 >> 4), %bx
        jmp     .Ledd_mbr_sig_set_buf
.Ledd_mbr_sig_get_size:
        movw    EDDEXTSIZE+0x18(%bx), %bx       # sector size
        shr     $4, %bx                         # convert to paragraphs
        jz      .Ledd_mbr_sig_default
.Ledd_mbr_sig_set_buf:
        movw    %ds, %ax
        subw    %bx, %ax                        # disk's data goes right ahead
        movw    %ax, %es                        # of trampoline
        xorw    %bx, %bx
        movw    %bx, %es:0x1fe(%bx)             # clear BIOS magic just in case
        pushw   %dx                             # work around buggy BIOSes
        stc                                     # work around buggy BIOSes
        movw    $0x0201, %ax                    # read 1 sector
        movb    $0, %dh                         # at head 0
        movw    $1, %cx                         # cylinder 0, sector 0
        int     $0x13
        sti                                     # work around buggy BIOSes
        popw    %dx
        movw    %es:0x1fe(%bx), %si
        movl    %es:EDD_MBR_SIG_OFFSET(%bx), %ecx
        popw    %bx
        jc      .Ledd_mbr_sig_done              # on failure, we're done.
        testb   %ah, %ah                        # some BIOSes do not set CF
        jnz     .Ledd_mbr_sig_done              # on failure, we're done.
        cmpw    $0xaa55, %si
        jne     .Ledd_mbr_sig_next
        movb    %dl, (%bx)                      # store BIOS drive number
        movl    %ecx, 4(%bx)                    # store signature from MBR
        incb    bootsym(boot_mbr_signature_nr)  # note that we stored something
        addw    $8, %bx                         # increment sig buffer ptr
.Ledd_mbr_sig_next:
        incb    %dl                             # increment to next device
        jz      .Ledd_mbr_sig_done
        cmpb    $EDD_MBR_SIG_MAX, bootsym(boot_mbr_signature_nr)
        jb      .Ledd_mbr_sig_read
.Ledd_mbr_sig_done:
        popw    %es
.Ledd_mbr_sig_skip:
        ret

GLOBAL(boot_edd_info_nr)
        .byte   0
GLOBAL(boot_mbr_signature_nr)
        .byte   0
GLOBAL(boot_mbr_signature)
        .fill   EDD_MBR_SIG_MAX*8,1,0
GLOBAL(boot_edd_info)
        .fill   EDD_INFO_MAX * (EDDEXTSIZE + EDDPARMSIZE), 1, 0
