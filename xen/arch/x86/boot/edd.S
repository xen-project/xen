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
        cmpb    $1, bootsym(opt_edd)            # edd=skipmbr ?
        je      edd_start

# Read the first sector of each BIOS disk device and store the 4-byte signature
edd_mbr_sig_start:
        movb    $0x80, %dl                      # from device 80
        movw    $bootsym(boot_mbr_signature),%bx # store buffer ptr in bx
edd_mbr_sig_read:
        pushw   %bx
        movb    $0x02, %ah                      # 0x02 Read Sectors
        movb    $1, %al                         # read 1 sector
        movb    $0, %dh                         # at head 0
        movw    $1, %cx                         # cylinder 0, sector 0
        pushw   %es
        pushw   %ds
        popw    %es
        movw    $bootsym(boot_edd_info), %bx    # disk's data goes into info
        pushw   %dx             # work around buggy BIOSes
        stc                     # work around buggy BIOSes
        int     $0x13
        sti                     # work around buggy BIOSes
        popw    %dx
        popw    %es
        popw    %bx
        jc      edd_mbr_sig_done                # on failure, we're done.
        cmpb    $0, %ah                         # some BIOSes do not set CF
        jne     edd_mbr_sig_done                # on failure, we're done.
        cmpw    $0xaa55, bootsym(boot_edd_info)+0x1fe
        jne     .Ledd_mbr_sig_next
        movl    bootsym(boot_edd_info)+EDD_MBR_SIG_OFFSET,%eax
        movb    %dl, (%bx)                      # store BIOS drive number
        movl    %eax, 4(%bx)                    # store signature from MBR
        incb    bootsym(boot_mbr_signature_nr)  # note that we stored something
        addw    $8, %bx                         # increment sig buffer ptr
.Ledd_mbr_sig_next:
        incb    %dl                             # increment to next device
        jz      edd_mbr_sig_done
        cmpb    $EDD_MBR_SIG_MAX,bootsym(boot_mbr_signature_nr)
        jb      edd_mbr_sig_read
edd_mbr_sig_done:

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
        cmpb    $EDD_INFO_MAX,bootsym(boot_edd_info_nr)
        jb      edd_check_ext

edd_done:
        ret

opt_edd:
        .byte   0                               # edd=on/off/skipmbr

GLOBAL(boot_edd_info_nr)
        .byte   0
GLOBAL(boot_mbr_signature_nr)
        .byte   0
GLOBAL(boot_mbr_signature)
        .fill   EDD_MBR_SIG_MAX*8,1,0
GLOBAL(boot_edd_info)
        .fill   512,1,0                         # big enough for a disc sector
