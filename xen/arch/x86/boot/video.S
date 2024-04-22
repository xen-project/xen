/******************************************************************************
 * video.S
 *
 * Display adapter & video mode setup, version 2.13 (14-May-99)
 *
 * Copyright (C) 1995 -- 1998 Martin Mares <mj@ucw.cz>
 * Based on the original setup.S code (C) Linus Torvalds and Mats Anderson
 *
 * Rewritten to use GNU 'as' by Chris Noe <stiker@northlink.com> May 1999
 *
 * Updated and ported for Xen by Keir Fraser <keir@xensource.com> June 2007
 */

        .code16

#include "video.h"

/* Scratch space layout: trampoline_end to trampoline_end+0x1000. */
#define modelist       bootsym(trampoline_end)   /* 2kB (256 entries) */
#define vesa_glob_info (modelist + 0x800)        /* 1kB */
#define vesa_mode_info (vesa_glob_info + 0x400)  /* 1kB */

/* Retrieve Extended Display Identification Data. */
#define CONFIG_FIRMWARE_EDID

/* Force 400 scan lines for standard modes (hack to fix bad BIOS behaviour */
#undef CONFIG_VIDEO_400_HACK

#define _param(param) bootsym(boot_vid_info)+(param)

video:  xorw    %ax, %ax
        movw    %ax, %gs        # GS is zero
        cld
        call    basic_detect    # Basic adapter type testing (EGA/VGA/MDA/CGA)
        cmpb    $0, _param(BVI_have_vga)
        je      1f                # Bail if there's no VGA
        movw    bootsym(boot_vid_mode), %ax     # User selected video mode
        cmpw    $ASK_VGA, %ax                   # Bring up the menu
        jz      vid2

        call    mode_set                        # Set the mode
        jc      vid1

        movw    $bootsym(badmdt), %si           # Invalid mode ID
        call    prtstr
vid2:   call    mode_menu
vid1:   call    store_edid
        call    mode_params                     # Store mode parameters
1:      ret

# Detect if we have CGA, MDA, EGA or VGA and pass it to the kernel.
basic_detect:
        movb    $0, _param(BVI_have_vga)
        movb    $0x12, %ah                      # Check EGA/VGA
        movb    $0x10, %bl
        int     $0x10
        cmpb    $0x10, %bl                      # No, it's a CGA/MDA/HGA card.
        je      basret
        movw    $0x1a00, %ax                    # Check EGA or VGA?
        int     $0x10
        cmpb    $0x1a, %al                      # 1a means VGA...
        jne     basret                          # anything else is EGA.
        incb    _param(BVI_have_vga)            # We've detected a VGA
basret: ret

# Store the video mode parameters for later usage by the kernel.
# This is done by asking the BIOS except for the rows/columns
# parameters in the default 80x25 mode -- these are set directly,
# because some very obscure BIOSes supply insane values.
mode_params:
        cmpb    $0, bootsym(graphic_mode)
        jnz     mopar_gr
        movb    $0x03, %ah                      # Read cursor position
        xorb    %bh, %bh
        int     $0x10
        movw    %dx, _param(BVI_cursor_pos)
        movb    $0x0f, %ah                      # Read page/mode/width
        int     $0x10
        movw    %ax, _param(BVI_video_mode)     # Video mode and screen width
        movw    %gs:(0x485), %ax                # Font size
        movw    %ax, _param(BVI_font_points)    # (valid only on EGA/VGA)
        movw    bootsym(force_size), %ax        # Forced size?
        orw     %ax, %ax
        jz      mopar1

        movb    %ah, _param(BVI_video_cols)
        movb    %al, _param(BVI_video_lines)
        ret

mopar1: movb    %gs:(0x484), %al                # On EGA/VGA, use the EGA+ BIOS
        incb    %al                             # location of max lines.
mopar2: movb    %al, _param(BVI_video_lines)
        ret

# Fetching of VESA frame buffer parameters
mopar_gr:
        movw    $vesa_mode_info, %di
        movb    $0x23, _param(BVI_have_vga)
        movw    16(%di), %ax
        movw    %ax, _param(BVI_lfb_linelength)
        movw    18(%di), %ax
        movw    %ax, _param(BVI_lfb_width)
        movw    20(%di), %ax
        movw    %ax, _param(BVI_lfb_height)
        movzbw  25(%di), %ax
        movw    %ax, _param(BVI_lfb_depth)
        movl    40(%di), %eax
        movl    %eax, _param(BVI_lfb_base)
        movl    31(%di), %eax
        movl    %eax, _param(BVI_lfb_colors)
        movl    35(%di), %eax
        movl    %eax, _param(BVI_lfb_colors+4)
        movw    0(%di), %ax
        movw    %ax, _param(BVI_vesa_attrib)

# get video mem size
        movw    $vesa_glob_info, %di
        movzwl  18(%di), %eax
        movl    %eax, _param(BVI_lfb_size)

# store mode capabilities
        movl    10(%di), %eax
        movl    %eax, _param(BVI_capabilities)

# switching the DAC to 8-bit is for <= 8 bpp only
        cmpw    $8, _param(BVI_lfb_depth)
        jg      dac_done

# get DAC switching capability
        testb   $1, 10(%di)
        jz      dac_set

# attempt to switch DAC to 8-bit
        movw    $0x4f08, %ax
        movw    $0x0800, %bx
        int     $0x10
        cmpw    $0x004f, %ax
        jne     dac_set
        movb    %bh, bootsym(dac_size)          # store actual DAC size

dac_set:
# set color size to DAC size
        movzbw  bootsym(dac_size), %ax
        movb    %al, _param(BVI_lfb_colors + 0)
        movb    %al, _param(BVI_lfb_colors + 2)
        movb    %al, _param(BVI_lfb_colors + 4)
        movb    %al, _param(BVI_lfb_colors + 6)

# set color offsets to 0
        movb    %ah, _param(BVI_lfb_colors + 1)
        movb    %ah, _param(BVI_lfb_colors + 3)
        movb    %ah, _param(BVI_lfb_colors + 5)
        movb    %ah, _param(BVI_lfb_colors + 7)

dac_done:
# get protected mode interface information
        movw    $0x4f0a, %ax
        xorw    %bx, %bx
        xorw    %di, %di
        int     $0x10
        cmp     $0x004f, %ax
        jnz     no_pm

        movw    %es, _param(BVI_vesapm_seg)
        movw    %di, _param(BVI_vesapm_off)

no_pm:  pushw   %ds
        popw    %es
        ret

# The video mode menu
mode_menu:
        movw    $bootsym(keymsg), %si   # "Return/Space/Timeout" message
        call    prtstr
        call    flush
nokey:  call    getkt

        cmpb    $0x0d, %al              # ENTER ?
        je      listm                   # yes - manual mode selection

        cmpb    $0x20, %al              # SPACE ?
        je      defmd1                  # no - repeat

        call    beep
        jmp     nokey

defmd1: ret                             # No mode chosen? Default 80x25

listm:  call    mode_table              # List mode table
listm0: movw    $bootsym(name_bann), %si # Print adapter name
        call    prtstr
        movw    bootsym(card_name), %si
        orw     %si, %si
        jnz     an2

        movw    $bootsym(vga_name), %si
        jmp     an1

an2:    call    prtstr
        movw    $bootsym(svga_name), %si
an1:    call    prtstr
        movw    $bootsym(listhdr), %si  # Table header
        call    prtstr
        movb    $0x30, %dl              # DL holds mode number
        movw    $modelist, %si
lm1:    cmpw    $ASK_VGA, (%si)         # End?
        jz      lm2

        movb    %dl, %al                # Menu selection number
        call    prtchr
        call    prtsp2
        lodsw
        call    prthw                   # Mode ID
        call    prtsp2
        lodsw
        call    prtdec                  # Width
        movb    $0x78, %al              # the letter 'x'
        call    prtchr
        lodsw
        call    prtdec                  # Height
        testb   $0xff,(%si)
        jnz     1f
        push    %si
        movw    $bootsym(textmode), %si
        call    prtstr
        pop     %si
        lodsw
        jmp     2f
1:      movb    $0x78, %al              # the letter 'x'
        call    prtchr
        lodsw
        call    prtdec                  # Depth
2:      movb    $0x0d, %al              # New line
        call    prtchr
        movb    $0x0a, %al
        call    prtchr
        incb    %dl                     # Next character

        cmpb    $'z'+1, %dl
        jnz     skip_bail
        movw    $bootsym(menu_bail_msg), %si
        call    prtstr
        jmp     lm2

skip_bail:
        cmpb    $'i', %dl
        jnz     skip_pause
        push    %si
        push    %dx
        movw    $bootsym(menu_more_msg), %si # '<press space>'
        call    prtstr
        call    flush
1:      call    getkey
        cmpb    $0x20, %al              # SPACE ?
        jne     1b                      # yes - manual mode selection
        movw    $bootsym(crlft), %si
        call    prtstr
        pop     %dx
        pop     %si

skip_pause:
        cmpb    $'9'+1, %dl
        jnz     lm1
        movb    $'a', %dl
        jmp     lm1

lm2:    movw    $bootsym(prompt), %si   # Mode prompt
        call    prtstr
        movw    $bootsym(edit_buf), %di # Editor buffer
lm3:    call    getkey
        cmpb    $0x0d, %al              # Enter?
        jz      lment

        cmpb    $0x08, %al              # Backspace?
        jz      lmbs

        cmpb    $0x20, %al              # Printable?
        jc      lm3

        cmpw    $bootsym(edit_buf)+4, %di  # Enough space?
        jz      lm3

        stosb
        call    prtchr
        jmp     lm3

lmbs:   cmpw    $bootsym(edit_buf), %di # Backspace
        jz      lm3

        decw    %di
        movb    $0x08, %al
        call    prtchr
        call    prtspc
        movb    $0x08, %al
        call    prtchr
        jmp     lm3
        
lment:  movb    $0, (%di)
        movw    $bootsym(crlft), %si
        call    prtstr
        movw    $bootsym(edit_buf), %si
        cmpb    $0, (%si)               # Empty string = default mode
        jz      lmdef

        cmpb    $0, 1(%si)              # One character = menu selection
        jz      mnusel

        cmpw    $0x656d, (%si)          # 'me'
        jnz     lmhx
        cmpw    $0x756e, 2(%si)         # 'nu'
        jz      listm

lmhx:   xorw    %bx, %bx                # Else => mode ID in hex
lmhex:  lodsb
        orb     %al, %al
        jz      lmuse1

        subb    $0x30, %al
        jc      lmbad

        cmpb    $10, %al
        jc      lmhx1

        subb    $7, %al
        andb    $0xdf, %al
        cmpb    $10, %al
        jc      lmbad

        cmpb    $16, %al
        jnc     lmbad

lmhx1:  shlw    $4, %bx
        orb     %al, %bl
        jmp     lmhex

lmuse1: movw    %bx, %ax
        jmp     lmuse

mnusel: lodsb                           # Menu selection
        xorb    %ah, %ah
        subb    $0x30, %al
        jc      lmbad

        cmpb    $10, %al
        jc      lmuse
        
        cmpb    $0x61-0x30, %al
        jc      lmbad
        
        subb    $0x61-0x30-10, %al
        cmpb    $36, %al
        jnc     lmbad

lmuse:  call    mode_set
        jc      lmdef

lmbad:  movw    $bootsym(unknt), %si
        call    prtstr
        jmp     mode_menu
lmdef:  ret

# Setting of user mode (AX=mode ID) => CF=success
mode_set:
        movw    %ax, bootsym(boot_vid_mode)
        movw    %ax, %bx

        cmpw    $VIDEO_VESA_BY_SIZE, %ax
        je      setvesabysize

        testb   $VIDEO_RECALC>>8, %ah
        jnz     setrec

        cmpb    $VIDEO_FIRST_SPECIAL>>8, %ah
        jz      setspc

        cmpb    $VIDEO_FIRST_VESA>>8, %ah
        jnc     check_vesa

        testb   %ah, %ah
        jz      setmenu

setbad: clc
        ret

setspc: xorb    %bh, %bh                # Set special mode
        cmpb    $VIDEO_LAST_SPECIAL-VIDEO_FIRST_SPECIAL, %bl
        jnc     setbad
        
        addw    %bx, %bx
        jmp     *bootsym(spec_inits)(%bx)

setmenu:
        orb     %al, %al                # 80x25 is an exception
        jz      set_80x25
        
        pushw   %bx                     # Set mode chosen from menu
        call    mode_table              # Build the mode table
        popw    %ax
        shlw    $3, %ax
        addw    %ax, %si
        cmpw    %di, %si
        jnc     setbad
        
        movw    (%si), %ax              # Fetch mode ID
        jmp     mode_set

check_vesa:
        movw    $vesa_glob_info, %di
        movw    $0x4f00, %ax
        int     $0x10
        cmpw    $0x004f, %ax
        jnz     setbad

        movw    $vesa_mode_info, %di    # Get mode information structure
        leaw    -VIDEO_FIRST_VESA(%bx), %cx
        movw    $0x4f01, %ax
        int     $0x10
        cmpw    $0x004f, %ax
        jnz     setbad

        movb    (%di), %al              # Check mode attributes.
        andb    $0x99, %al
        cmpb    $0x99, %al
        jnz     setbad                  # Doh! No linear frame buffer.

        pushw   %bx
        subb    $VIDEO_FIRST_VESA>>8, %bh
        orb     $0x40, %bh              # Use linear frame buffer
        movw    $0x4f02, %ax            # VESA BIOS mode set call
        int     $0x10
        popw    %bx
        cmpw    $0x004f, %ax            # AL=4f if implemented
        jnz     setbad                  # AH=0 if OK

        movb    $1, bootsym(graphic_mode)  # flag graphic mode
        movw    %bx, bootsym(video_mode)
        stc
        ret

# Recalculate vertical display end registers -- this fixes various
# inconsistencies of extended modes on many adapters. Called when
# the VIDEO_RECALC flag is set in the mode ID.

setrec: subb    $VIDEO_RECALC>>8, %ah   # Set the base mode
        call    mode_set
        jnc     rct3

        movw    %gs:(0x485), %ax        # Font size in pixels
        movb    %gs:(0x484), %bl        # Number of rows
        incb    %bl
        mulb    %bl                     # Number of visible
        decw    %ax                     # scan lines - 1
        movw    $0x3d4, %dx
        movw    %ax, %bx
        movb    $0x12, %al              # Lower 8 bits
        movb    %bl, %ah
        outw    %ax, %dx
        movb    $0x07, %al              # Bits 8 and 9 in the overflow register
        call    inidx
        xchgb   %al, %ah
        andb    $0xbd, %ah
        shrb    %bh
        jnc     rct1
        orb     $0x02, %ah
rct1:   shrb    %bh
        jnc     rct2
        orb     $0x40, %ah
rct2:   movb    $0x07, %al
        outw    %ax, %dx
        stc
rct3:   ret

inidx:  outb    %al, %dx                # Read from indexed VGA register
        incw    %dx                    # AL=index, DX=index reg port -> AL=data
        inb     %dx, %al
        decw    %dx
        ret

setvesabysize:
        call    mode_table
        movw    $modelist,%si
1:      add     $8,%si
        movw    -8(%si),%bx
        cmpw    $ASK_VGA,%bx            # End?
        je      setbad
        movw    -6(%si),%ax
        cmpw    %ax,bootsym(vesa_size)+0
        jne     1b
        movw    -4(%si),%ax
        cmpw    %ax,bootsym(vesa_size)+2
        jne     1b
        movw    -2(%si),%ax
        cmpw    %ax,bootsym(vesa_size)+4
        jne     1b
        movw    %bx,bootsym(boot_vid_mode)
        jmp     check_vesa

# Table of routines for setting of the special modes.
spec_inits:
        .word   bootsym(set_80x25)
        .word   bootsym(set_8pixel)
        .word   bootsym(set_80x43)
        .word   bootsym(set_80x28)
        .word   bootsym(set_current)
        .word   bootsym(set_80x30)
        .word   bootsym(set_80x34)
        .word   bootsym(set_80x60)

# Set the 80x25 mode. If already set, do nothing.
set_80x25:
        movw    $0x5019, bootsym(force_size)  # Override possibly broken BIOS
use_80x25:
        movw    $0x1202, %ax            # Force 400 scan lines
        movb    $0x30, %bl
        int     $0x10
        movw    $0x0003, %ax            # Mode 3
        int     $0x10
        stc
        ret

# Set the 80x50/80x43 8-pixel mode. Simple BIOS calls.
set_8pixel:
        call    use_80x25               # The base is 80x25
set_8pt:
        movw    $0x1112, %ax            # Use 8x8 font
        xorb    %bl, %bl
        int     $0x10
        movw    $0x1200, %ax            # Use alternate print screen
        movb    $0x20, %bl
        int     $0x10
        movw    $0x1201, %ax            # Turn off cursor emulation
        movb    $0x34, %bl
        int     $0x10
        movb    $0x01, %ah              # Define cursor scan lines 6-7
        movw    $0x0607, %cx
        int     $0x10
        stc
        ret

# Set the 80x28 mode. This mode works on all VGA's, because it's a standard
# 80x25 mode with 14-point fonts instead of 16-point.
set_80x28:
        call    use_80x25               # The base is 80x25
set14:  movw    $0x1111, %ax            # Use 9x14 font
        xorb    %bl, %bl
        int     $0x10
        movb    $0x01, %ah              # Define cursor scan lines 11-12
        movw    $0x0b0c, %cx
        int     $0x10
        stc
        ret

# Set the 80x43 mode. This mode is works on all VGA's.
# It's a 350-scanline mode with 8-pixel font.
set_80x43:
        movw    $0x1201, %ax            # Set 350 scans
        movb    $0x30, %bl
        int     $0x10
        movw    $0x0003, %ax            # Reset video mode
        int     $0x10
        jmp     set_8pt                 # Use 8-pixel font

# Set the 80x30 mode (all VGA's). 480 scanlines, 16-pixel font.
set_80x30:
        call    use_80x25               # Start with real 80x25
        movw    $0x3cc, %dx             # Get CRTC port
        inb     %dx, %al
        movb    $0xd4, %dl
        rorb    %al                     # Mono or color?
        jc      set48a

        movb    $0xb4, %dl
set48a: movw    $0x0c11, %ax            # Vertical sync end (also unlocks CR0-7)
        call    outidx
        movw    $0x0b06, %ax            # Vertical total
        call    outidx
        movw    $0x3e07, %ax            # (Vertical) overflow
        call    outidx
        movw    $0xea10, %ax            # Vertical sync start
        call    outidx
        movw    $0xdf12, %ax            # Vertical display end
        call    outidx
        movw    $0xe715, %ax            # Vertical blank start
        call    outidx
        movw    $0x0416, %ax            # Vertical blank end
        call    outidx
        pushw   %dx
        movb    $0xcc, %dl              # Misc output register (read)
        inb     %dx, %al
        movb    $0xc2, %dl              # (write)
        andb    $0x0d, %al              # Preserve clock select bits and color bit
        orb     $0xe2, %al              # Set correct sync polarity
        outb    %al, %dx
        popw    %dx
        movw    $0x501e, bootsym(force_size)
        stc                             # That's all.
        ret

# Set the 80x34 mode (all VGA's). 480 scans, 14-pixel font.
set_80x34:
        call    set_80x30               # Set 480 scans
        call    set14                   # And 14-pt font
        movw    $0xdb12, %ax            # VGA vertical display end
        movw    $0x5022, bootsym(force_size)
setvde: call    outidx
        stc
        ret

# Set the 80x60 mode (all VGA's). 480 scans, 8-pixel font.
set_80x60:
        call    set_80x30               # Set 480 scans
        call    set_8pt                 # And 8-pt font
        movw    $0xdf12, %ax            # VGA vertical display end
        movw    $0x503c, bootsym(force_size)
        jmp     setvde

# Write to indexed VGA register (AL=index, AH=data, DX=index reg. port)
outidx: outb    %al, %dx
        pushw   %ax
        movb    %ah, %al
        incw    %dx
        outb    %al, %dx
        decw    %dx
        popw    %ax
        ret

# Build the table of video modes (stored after the setup.S code at the
# `modelist' label. Each video mode record looks like:
#        .word        MODE-ID             (our special mode ID (see above))
#        .word        rows                (number of rows)
#        .word        columns             (number of columns)
#        .word        0                   (color depth; gfx modes only)
# Returns address of the end of the table in DI, the end is marked
# with a ASK_VGA ID.
mode_table:
        movw    bootsym(mt_end), %di    # Already filled?
        orw     %di, %di
        jnz     mtab1

        movw    $modelist, %di          # Store standard modes:
        movw    $bootsym(vga_modes), %si # All modes for std VGA
        movw    $vga_modes_end-vga_modes, %cx
        rep     movsb

        call    vesa_modes              # Detect VESA VGA modes

        movw    $ASK_VGA, (%di)         # End marker
        movw    %di, bootsym(mt_end)
mtab1:  movw    $modelist, %si          # SI=mode list, DI=list end
ret0:   ret

# Modes usable on all standard VGAs
vga_modes:
        .word   VIDEO_80x25, 0x50,0x19,0        # 80x25
        .word   VIDEO_80x50, 0x50,0x32,0        # 80x50
        .word   VIDEO_80x43, 0x50,0x2b,0        # 80x43
        .word   VIDEO_80x28, 0x50,0x1c,0        # 80x28
        .word   VIDEO_80x30, 0x50,0x1e,0        # 80x30
        .word   VIDEO_80x34, 0x50,0x22,0        # 80x34
        .word   VIDEO_80x60, 0x50,0x3c,0        # 80x60
vga_modes_end:

# If the current mode is a VESA graphics one, obtain its parameters.
set_current:
        movw    $vesa_glob_info, %di
        movw    $0x4f00, %ax
        int     $0x10
        cmpw    $0x004f, %ax
        jne     .Lsetc_done

        movw    $0x4f03, %ax
        int     $0x10
        cmpw    $0x004f, %ax
        jne     .Lsetc_done

        movw    $vesa_mode_info, %di    # Get mode information structure
        movw    %bx, %cx
        movw    $0x4f01, %ax
        int     $0x10
        cmpw    $0x004f, %ax
        jne     .Lsetc_done

        movb    (%di), %al              # Check mode attributes
        andb    $0x9b, %al
        cmpb    $0x9b, %al
        jne     .Lsetc_done             # Doh! No linear frame buffer

        movb    $1, bootsym(graphic_mode)
        movw    %bx, bootsym(boot_vid_mode)
        movw    %bx, bootsym(video_mode)

.Lsetc_done:
        stc
        ret

# Detect VESA modes.
vesa_modes:
        movw    %di, %bp                # BP=original mode table end
        movw    $vesa_glob_info, %di
        movw    $0x4f00, %ax            # VESA Get card info call
        int     $0x10
        movw    %di, %si
        movw    %bp, %di
        cmpw    $0x004f, %ax            # Successful?
        jnz     ret0
        
        cmpw    $0x4556, (%si)          # 'VE'
        jnz     ret0
        
        cmpw    $0x4153, 2(%si)         # 'SA'
        jnz     ret0
        
        movw    $bootsym(vesa_name), bootsym(card_name) # Set name to "VESA VGA"
        pushw   %gs
        lgsw    0xe(%si), %si           # GS:SI=mode list
        movw    $128, %cx               # Iteration limit
vesa1:
        gs;     lodsw
        cmpw    $0xffff, %ax            # End of the table?
        jz      vesar
        
        cmpw    $0x0080, %ax            # Check validity of mode ID
        jc      vesa2
        
        orb     %ah, %ah                # Valid IDs 0x0000-0x007f/0x0100-0x07ff
        jz      vesan                   # Certain BIOSes report 0x80-0xff!

        cmpw    $0x0800, %ax
        jnc     vesae

vesa2:  pushw   %cx
        movw    %ax, %cx                # Get mode information structure
        movw    $0x4f01, %ax
        int     $0x10
        movw    %cx, %bx                # BX=mode number
        addb    $VIDEO_FIRST_VESA>>8, %bh
        popw    %cx
        cmpw    $0x004f, %ax
        jnz     vesan                   # Don't report errors (buggy BIOSES)

        movb    (%di), %al              # Check capabilities.
        andb    $0x9b, %al              # LFB gfx mode in color?
        cmpb    $0x9b, %al
        jnz     vesan

        movw    %bx, (%di)              # Store mode number
        movw    0x12(%di), %bx          # Width
        movw    %bx, 2(%di)
        movw    0x14(%di), %bx          # Height
        movw    %bx, 4(%di)
        movzbw  0x19(%di), %bx          # Depth
        movw    %bx, 6(%di)

        addw    $8, %di                 # The mode is valid. Store it.
vesan:  loop    vesa1                   # Next mode. Limit exceeded => error
vesae:  movw    $bootsym(vesaer), %si
        call    prtstr
        movw    %bp, %di                # Discard already found modes.
vesar:  popw    %gs
        ret

# Read a key and return the ASCII code in al, scan code in ah
getkey: xorb    %ah, %ah
        int     $0x16
        ret

# Read a key with a timeout of 30 seconds.
# The hardware clock is used to get the time.
getkt:  call    gettime
        addb    $30, %al                # Wait 30 seconds
        cmpb    $60, %al
        jl      lminute

        subb    $60, %al
lminute:
        movb    %al, %cl
again:  movb    $0x01, %ah
        int     $0x16
        jnz     getkey                  # key pressed, so get it

        call    gettime
        cmpb    %cl, %al
        jne     again

        movb    $0x20, %al              # timeout, return `space'
        ret

# Flush the keyboard buffer
flush:  movb    $0x01, %ah
        int     $0x16
        jz      empty
        
        xorb    %ah, %ah
        int     $0x16
        jmp     flush

empty:  ret

# Print hexadecimal number.
prthw:  pushw   %ax
        movb    %ah, %al
        call    prthb
        popw    %ax
prthb:  pushw   %ax
        shrb    $4, %al
        call    prthn
        popw    %ax
        andb    $0x0f, %al
prthn:  cmpb    $0x0a, %al
        jc      prth1

        addb    $0x07, %al
prth1:  addb    $0x30, %al
        jmp     prtchr

# Print decimal number in ax
prtdec: pushw   %ax
        pushw   %cx
        pushw   %dx
        xorw    %dx, %dx
        movw    $0x0a, %cx
        divw    %cx
        testw   %ax, %ax
        jz      skip10
        cmpw    $0x09, %ax
        jbe     lt100

        call    prtdec
        jmp     skip10

lt100:  addb    $0x30, %al
        call    prtchr
skip10: movb    %dl, %al
        addb    $0x30, %al
        call    prtchr        
        popw    %dx
        popw    %cx
        popw    %ax
        ret

# Routine to print asciiz string at ds:si
prtstr:
        lodsb
        andb    %al, %al
        jz      fin

        call    prtchr
        jmp     prtstr

fin:    ret

# Space printing
prtsp2: call    prtspc                  # Print double space
prtspc: movb    $0x20, %al              # Print single space (note: fall-thru)

# Part of above routine, this one just prints ascii al
prtchr: pushw   %ax
        pushw   %cx
        movw    $7,%bx
        movw    $0x01, %cx
        movb    $0x0e, %ah
        int     $0x10
        popw    %cx
        popw    %ax
        ret

beep:   movb    $0x07, %al
        jmp     prtchr

# Read the cmos clock. Return the seconds in al
gettime:
        pushw   %cx
        movb    $0x02, %ah
        int     $0x1a
        movb    %dh, %al                # %dh contains the seconds
        andb    $0x0f, %al
        movb    %dh, %ah
        shrb    $4, %ah
        aad
        popw    %cx
        ret

store_edid:
#ifdef CONFIG_FIRMWARE_EDID
        pushw   %ax
        pushw   %bx
        pushw   %cx
        pushw   %dx
        pushw   %di

        movb    bootsym(opt_edid), %al
        cmpw    $0x1313, bootsym(boot_edid_caps) # Data already retrieved?
        je      .Lcheck_edid
        cmpb    $2, %al                 # EDID forced on cmdline (edid=force)?
        jne     .Lno_edid

.Lcheck_edid:
        cmpb    $1, %al                 # EDID disabled on cmdline (edid=no)?
        je      .Lno_edid

        movw    $vesa_glob_info, %di
        movw    $0x4f00, %ax
        int     $0x10
        cmpw    $0x004f, %ax
        jne     .Lno_edid
        cmpw    $0x0200, 4(%di)         # only do EDID on >= VBE2.0
        jb      .Lno_edid

        xorw    %di, %di                # Report Capability
        pushw   %di
        popw    %es                     # ES:DI must be 0:0
        movw    $0x4f15, %ax
        xorw    %bx, %bx
        xorw    %cx, %cx
        int     $0x10
        pushw   %ds
        popw    %es
        cmpw    $0x004f, %ax            # Call failed?
        jne     .Lno_edid

        movw    %bx, bootsym(boot_edid_caps)

        cmpb    $2, bootsym(opt_edid)   # EDID forced on cmdline (edid=force)?
        je      .Lforce_edid

        /* EDID not forced on cmdline, so perform further sanity checks. */
        testb   $3,%bl                  # No DDC capabilities?
        jz      .Lno_edid
        cmpb    $5,%bh                  # Longer than 5s to read EDID?
        ja      .Lno_edid

.Lforce_edid:
        movw    $0x4f15, %ax            # do VBE/DDC
        movw    $0x01, %bx
        xorw    %cx, %cx
        xorw    %dx, %dx
        movw    $bootsym(boot_edid_info), %di
        int     $0x10

.Lno_edid:
        popw    %di                     # restore all registers
        popw    %dx
        popw    %cx
        popw    %bx
        popw    %ax
#endif
        ret

                .p2align 1
mt_end:         .word   0       # End of video mode table if built
edit_buf:       .space  6       # Line editor buffer
card_name:      .word   0       # Pointer to adapter name
graphic_mode:   .byte   0       # Graphic mode with a linear frame buffer
dac_size:       .byte   6       # DAC bit depth

# Status messages
keymsg:         .ascii  "Press <RETURN> to see video modes available,"
                .byte   0x0d, 0x0a
                .ascii  "<SPACE> to continue or wait 30 secs"
                .byte   0x0d, 0x0a, 0

listhdr:        .byte   0x0d, 0x0a
                .ascii  "MODE-KEY  MODE-ID  WIDTHxHEIGHTxDEPTH"

crlft:          .byte   0x0d, 0x0a, 0

prompt:         .byte   0x0d, 0x0a
                .asciz  "Enter mode number or 'menu': "

unknt:          .ascii  "Unknown mode ID. Try again."
                .byte   0x0d, 0x0a, 0

badmdt:         .ascii  "You passed an undefined mode number."
                .byte   0x0d, 0x0a, 0

vesaer:         .ascii  "Error: Scanning of VESA modes failed. Please "
                .ascii  "report to <mj@ucw.cz>."
                .byte   0x0d, 0x0a, 0

textmode:       .asciz  " (text)"
menu_more_msg:  .asciz  "<press SPACE for more>"
menu_bail_msg:  .ascii  "<menu truncated>"
                .byte   0x0d, 0x0a, 0

svga_name:      .ascii  " "

vga_name:       .asciz  "VGA"

vesa_name:      .asciz  "VESA"

name_bann:      .asciz  "Video adapter: "

                .p2align 1
force_size:     .word   0       # Use this size instead of the one in BIOS vars

GLOBAL(boot_vid_info)
        .byte   0, 0    /* orig_x, orig_y */
        .byte   3       /* text mode 3    */
        .byte   80, 25  /* 80x25          */
        .byte   1       /* isVGA          */
        .word   16      /* 8x16 font      */
        .space  BVI_size - (. - boot_vid_info)
GLOBAL(boot_edid_info)
        .fill   128,1,0x13
GLOBAL(boot_edid_caps)
        .word   0x1313
