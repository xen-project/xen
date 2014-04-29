/******************************************************************************
 * cmdline.S
 *
 * Early command-line parsing.
 */

        .code32

#include "video.h"

# NB. String pointer on stack is modified to point past parsed digits.
.Latoi:
        push    %ebx
        push    %ecx
        push    %edx
        push    %esi
        xor     %ebx,%ebx       /* %ebx = accumulator */
        mov     $10,%ecx        /* %ecx = base (default base 10) */
        mov     16+4(%esp),%esi /* %esi = pointer into ascii string. */
        lodsb
        cmpb    $'0',%al
        jne     2f
        mov     $8,%ecx         /* Prefix '0' => octal (base 8) */
        lodsb
        cmpb    $'x',%al
        jne     2f
        mov     $16,%ecx        /* Prefix '0x' => hex (base 16) */
1:      lodsb
2:      sub     $'0',%al
        jb      4f
        cmp     $9,%al
        jbe     3f
        sub     $'A'-'0'-10,%al
        jb      4f
        cmp     $15,%al
        jbe     3f
        sub     $'a'-'A',%al
        jb      4f
3:      cmp     %cl,%al
        jae     4f
        movzbl  %al,%eax
        xchg    %eax,%ebx
        mul     %ecx
        xchg    %eax,%ebx
        add     %eax,%ebx
        jmp     1b
4:      mov     %ebx,%eax
        dec     %esi
        mov     %esi,16+4(%esp)
        pop     %esi
        pop     %edx
        pop     %ecx
        pop     %ebx
        ret

.Lstrstr:
        push    %ecx
        push    %edx
        push    %esi
        push    %edi
        xor     %eax,%eax
        xor     %ecx,%ecx
        not     %ecx
        mov     16+4(%esp),%esi
        mov     16+8(%esp),%edi
        repne   scasb
        not     %ecx
        dec     %ecx
        mov     %ecx,%edx
1:      mov     16+8(%esp),%edi
        mov     %esi,%eax
        mov     %edx,%ecx
        repe    cmpsb
        je      2f
        xchg    %eax,%esi
        inc     %esi
        cmpb    $0,-1(%eax)
        jne     1b
        xor     %eax,%eax
2:      pop     %edi
        pop     %esi
        pop     %edx
        pop     %ecx
        ret

.Lstr_prefix:
        push    %esi
        push    %edi
        mov     8+4(%esp),%esi /* 1st arg is prefix string */
        mov     8+8(%esp),%edi /* 2nd arg is main string */
1:      lodsb
        test    %al,%al
        jz      2f
        scasb
        je      1b
        sbb     %eax,%eax
        or      $1,%al
        jmp     3f
2:      xor     %eax,%eax
3:      pop     %edi
        pop     %esi
        ret

.Lstrlen:
        push    %ecx
        push    %esi
        push    %edi
        xor     %eax,%eax
        xor     %ecx,%ecx
        not     %ecx
        mov     12+4(%esp),%edi
        repne   scasb
        not     %ecx
        dec     %ecx
        mov     %ecx,%eax
        pop     %edi
        pop     %esi
        pop     %ecx
        ret

.Lfind_option:
        mov     4(%esp),%eax
        dec     %eax
        push    %ebx
1:      pushl   4+8(%esp)
        inc     %eax
        push    %eax
        call    .Lstrstr
        add     $8,%esp
        test    %eax,%eax
        jz      3f
        cmp     %eax,4+4(%esp)
        je      2f
        cmpb    $' ',-1(%eax)
        jne     1b
2:      mov     %eax,%ebx
        pushl   4+8(%esp)
        call    .Lstrlen
        add     $4,%esp
        xadd    %eax,%ebx
        /* NUL check (as $'\0' == 0x30 in GAS) */
        cmpb    $0,(%ebx)
        je      3f
        cmpb    $' ',(%ebx)
        je      3f
        cmpb    $'=',(%ebx)
        jne     1b
3:      pop     %ebx
        ret

cmdline_parse_early:
        pusha

        /* Bail if there is no command line to parse. */
        mov     sym_phys(multiboot_ptr),%ebx
        mov     MB_flags(%ebx),%eax
        test    $4,%al
        jz      .Lcmdline_exit
        mov     MB_cmdline(%ebx),%eax
        test    %eax,%eax
        jz      .Lcmdline_exit

        /* Check for 'no-real-mode' command-line option. */
        pushl   $sym_phys(.Lno_rm_opt)
        pushl   MB_cmdline(%ebx)
        call    .Lfind_option
        test    %eax,%eax
        setnz   %al
        or      %al,sym_phys(skip_realmode)

        /* Check for 'tboot=' command-line option. */
        movl    $sym_phys(.Ltboot_opt),4(%esp)
        call    .Lfind_option
        test    %eax,%eax
        setnz   %al
        or      %al,sym_phys(skip_realmode) /* tboot= implies no-real-mode */

.Lparse_edd:
        /* Check for 'edd=' command-line option. */
        movl    $sym_phys(.Ledd_opt),4(%esp)
        call    .Lfind_option
        test    %eax,%eax
        jz      .Lparse_edid
        cmpb    $'=',3(%eax)
        jne     .Lparse_edid
        add     $4,%eax
        movb    $2,sym_phys(opt_edd)  /* opt_edd=2: edd=off */
        cmpw    $0x666f,(%eax)            /* 0x666f == "of" */
        je      .Lparse_edid
        decb    sym_phys(opt_edd)     /* opt_edd=1: edd=skipmbr */
        cmpw    $0x6b73,(%eax)            /* 0x6b73 == "sk" */
        je      .Lparse_edid
        decb    sym_phys(opt_edd)     /* opt_edd=0: edd=on (default) */

.Lparse_edid:
        /* Check for 'edid=' command-line option. */
        movl    $sym_phys(.Ledid_opt),4(%esp)
        call    .Lfind_option
        test    %eax,%eax
        jz      .Lparse_vga
        cmpb    $'=',4(%eax)
        jne     .Lparse_vga
        add     $5,%eax
        mov     %eax,%ebx
        push    %ebx
        pushl   $sym_phys(.Ledid_force)
        call    .Lstr_prefix
        add     $8,%esp
        movb    $2,sym_phys(opt_edid) /* opt_edid=2: edid=force */
        test    %eax,%eax
        jz      .Lparse_vga
        push    %ebx
        pushl   $sym_phys(.Ledid_no)
        call    .Lstr_prefix
        add     $8,%esp
        decb    sym_phys(opt_edid)    /* opt_edid=1: edid=no */
        test    %eax,%eax
        jz      .Lparse_vga
        decb    sym_phys(opt_edid)    /* opt_edid=0: default */

.Lparse_vga:
        /* Check for 'vga=' command-line option. */
        movl    $sym_phys(.Lvga_opt),4(%esp)
        call    .Lfind_option
        add     $8,%esp
        test    %eax,%eax
        jz      .Lcmdline_exit
        cmpb    $'=',3(%eax)
        jne     .Lcmdline_exit
        add     $4,%eax

        /* Found the 'vga=' option. Default option is to display vga menu. */
        movw    $ASK_VGA,sym_phys(boot_vid_mode)

        /* Check for 'vga=text-80x<rows>. */
        mov     %eax,%ebx
        push    %ebx
        pushl   $sym_phys(.Lvga_text80)
        call    .Lstr_prefix
        add     $8,%esp
        test    %eax,%eax
        jnz     .Lparse_vga_gfx

        /* We have 'vga=text-80x<rows>'. */
        add     $8,%ebx
        push    %ebx
        call    .Latoi
        add     $4,%esp
        mov     %ax,%bx
        lea     sym_phys(.Lvga_text_modes),%esi
1:      lodsw
        test    %ax,%ax
        jz      .Lcmdline_exit
        cmp     %ax,%bx
        lodsw
        jne     1b
        mov     %ax,sym_phys(boot_vid_mode)
        jmp     .Lcmdline_exit

.Lparse_vga_gfx:
        /* Check for 'vga=gfx-<width>x<height>x<depth>'. */
        push    %ebx
        pushl   $sym_phys(.Lvga_gfx)
        call    .Lstr_prefix
        add     $8,%esp
        test    %eax,%eax
        jnz     .Lparse_vga_mode

        /* We have 'vga=gfx-<width>x<height>x<depth>'. */
        /* skip 'gfx-' */
        add     $4,%ebx
        /* parse <width> */
        push    %ebx
        call    .Latoi
        pop     %esi
        mov     %ax,sym_phys(vesa_size)+0
        /* skip 'x' */
        lodsb
        cmpb    $'x',%al
        jne     .Lcmdline_exit
        /* parse <height> */
        push    %esi
        call    .Latoi
        pop     %esi
        mov     %ax,sym_phys(vesa_size)+2
        /* skip 'x' */
        lodsb
        cmpb    $'x',%al
        jne     .Lcmdline_exit
        /* parse <depth> */
        push    %esi
        call    .Latoi
        pop     %esi
        mov     %ax,sym_phys(vesa_size)+4
        /* commit to vesa mode */
        movw    $VIDEO_VESA_BY_SIZE,sym_phys(boot_vid_mode)
        jmp     .Lcmdline_exit

.Lparse_vga_mode:
        /* Check for 'vga=mode-<mode>'. */
        push    %ebx
        pushl   $sym_phys(.Lvga_mode)
        call    .Lstr_prefix
        add     $8,%esp
        test    %eax,%eax
        jnz     .Lparse_vga_current

        /* We have 'vga=mode-<mode>'. */
        add     $5,%ebx
        push    %ebx
        call    .Latoi
        add     $4,%esp
        mov     %ax,sym_phys(boot_vid_mode)
        jmp     .Lcmdline_exit

.Lparse_vga_current:
        /* Check for 'vga=current'. */
        push    %ebx
        pushl   $sym_phys(.Lvga_current)
        call    .Lstr_prefix
        add     $8,%esp
        test    %eax,%eax
        jnz     .Lcmdline_exit

        /* We have 'vga=current'. */
        movw    $VIDEO_CURRENT_MODE,sym_phys(boot_vid_mode)

.Lcmdline_exit:
        popa
        ret

        .pushsection .init.rodata, "a", @progbits

.Lvga_text_modes: /* rows, mode_number */
        .word   25,VIDEO_80x25
        .word   50,VIDEO_80x50
        .word   43,VIDEO_80x43
        .word   28,VIDEO_80x28
        .word   30,VIDEO_80x30
        .word   34,VIDEO_80x34
        .word   60,VIDEO_80x60
        .word   0

.Lvga_opt:
        .asciz  "vga"
.Lvga_text80:
        .asciz  "text-80x"
.Lvga_gfx:
        .asciz  "gfx-"
.Lvga_mode:
        .asciz  "mode-"
.Lvga_current:
        .asciz  "current"
.Lno_rm_opt:
        .asciz  "no-real-mode"
.Ltboot_opt:
        .asciz  "tboot"
.Ledid_opt:
        .asciz  "edid"
.Ledid_force:
        .asciz  "force"
.Ledid_no:
        .asciz  "no"
.Ledd_opt:
        .asciz  "edd"

        .popsection
