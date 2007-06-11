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
        push    %ebx
        push    4+8(%esp)
        push    4+8(%esp)
        call    .Lstrstr
        add     $8,%esp
        test    %eax,%eax
        jz      3f
        cmp     %eax,4+4(%esp)
        je      1f
        cmpb    $' ',-1(%eax)
        jne     2f
1:      mov     %eax,%ebx
        push    4+8(%esp)
        call    .Lstrlen
        add     $4,%esp
        xchg    %eax,%ebx
        add     %eax,%ebx
        cmpb    $'\0',(%ebx)
        je      3f
        cmpb    $' ',(%ebx)
        je      3f
        cmpb    $'=',(%ebx)
        je      3f
2:      xor     %eax,%eax
3:      pop     %ebx
        ret

/* multiboot_info structure offsets. */
#define MB_flags   0
#define MB_cmdline 16

cmdline_parse_early:
        pusha

        /* Bail if there is no command line to parse. */
        mov     sym_phys(multiboot_ptr),%ebx
        mov     MB_flags(%ebx),%eax
        test    $4,%al
        jz      1f
        mov     MB_cmdline(%ebx),%eax
        test    %eax,%eax
        jz      1f

        /* Check for 'no-real-mode' command-line option. */
        pushl   $sym_phys(.Lno_rm_opt)
        pushl   MB_cmdline(%ebx)
        call    .Lfind_option
        test    %eax,%eax
        setnz   bootsym_phys(skip_realmode)

        /* Check for 'vga=' command-line option. */
        movl    $sym_phys(.Lvga_opt),4(%esp)
        call    .Lfind_option
        add     $8,%esp
        test    %eax,%eax
        jz      1f
        cmpb    $'=',3(%eax)
        jne     1f
        add     $4,%eax

        /* Found the 'vga=' option. Default option is to display vga menu. */
        movw    $ASK_VGA,bootsym_phys(boot_vid_mode)

        /* Check for 'vga=text-80x<rows>. */
        mov     %eax,%ebx
        push    %ebx
        pushl   $sym_phys(.Lvga_text80)
        call    .Lstr_prefix
        add     $8,%esp
        test    %eax,%eax
        jnz     3f

        /* We have 'vga=text-80x<rows>'. */
        add     $8,%ebx
        push    %ebx
        call    .Latoi
        add     $4,%esp
        mov     %ax,%bx
        lea     sym_phys(.Lvga_text_modes),%esi
2:      lodsw
        test    %ax,%ax
        jz      1f
        cmp     %ax,%bx
        lodsw
        jne     2b
        mov     %ax,bootsym_phys(boot_vid_mode)
        jmp     1f

        /* Check for 'vga=gfx-<width>x<height>x<depth>'. */
3:      push    %ebx
        pushl   $sym_phys(.Lvga_gfx)
        call    .Lstr_prefix
        add     $8,%esp
        test    %eax,%eax
        jnz     3f

        /* We have 'vga=gfx-<width>x<height>x<depth>'. */
        /* skip 'gfx-' */
        add     $4,%ebx
        /* parse <width> */
        push    %ebx
        call    .Latoi
        pop     %esi
        mov     %ax,bootsym_phys(vesa_size)+0
        /* skip 'x' */
        lodsb
        cmpb    $'x',%al
        jne     1f
        /* parse <height> */
        push    %esi
        call    .Latoi
        pop     %esi
        mov     %ax,bootsym_phys(vesa_size)+2
        /* skip 'x' */
        lodsb
        cmpb    $'x',%al
        jne     1f
        /* parse <depth> */
        push    %esi
        call    .Latoi
        pop     %esi
        mov     %ax,bootsym_phys(vesa_size)+4
        /* commit to vesa mode */
        movw    $VIDEO_VESA_BY_SIZE,bootsym_phys(boot_vid_mode)
        jmp     1f

        /* Check for 'vga=mode-<mode>'. */
3:      push    %ebx
        pushl   $sym_phys(.Lvga_mode)
        call    .Lstr_prefix
        add     $8,%esp
        test    %eax,%eax
        jnz     1f

        /* We have 'vga=mode-<mode>'. */
        add     $5,%ebx
        push    %ebx
        call    .Latoi
        add     $4,%esp
        mov     %ax,bootsym_phys(boot_vid_mode)

1:      popa
        ret

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
.Lno_rm_opt:
        .asciz  "no-real-mode"
