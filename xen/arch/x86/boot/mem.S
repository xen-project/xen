        .code16

#define SMAP    0x534d4150
#define E820_BIOS_MAX 128

get_memory_map:

.Lmeme820:
        xorl    %ebx, %ebx                      # continuation counter
        movw    $bootsym(e820map), %di             # point into the whitelist
                                                # so we can have the bios
                                                # directly write into it.

1:      movl    $0x0000e820, %eax               # e820, upper word zeroed
        movl    $SMAP,%edx                      # ascii 'SMAP'
        movl    $20,%ecx                        # size of the e820rec
        pushw   %ds                             # data record.
        popw    %es
        int     $0x15
        jc      .Lmem88

        cmpl    $SMAP,%eax                      # check the return is `SMAP'
        jne     .Lmem88

        incw    bootsym(e820nr)
        cmpw    $E820_BIOS_MAX,bootsym(e820nr)  # up to this many entries
        jae     .Lmem88

        movw    %di,%ax
        addw    $20,%ax
        movw    %ax,%di
        testl   %ebx,%ebx                       # check to see if
        jnz     1b                              # %ebx is set to EOF

.Lmem88:
        movb    $0x88, %ah
        int     $0x15
        movw    %ax,bootsym(highmem_kb)

.Lmeme801:
        stc                                     # fix to work around buggy
        xorw    %cx,%cx                         # BIOSes which don't clear/set
        xorw    %dx,%dx                         # carry on pass/error of
                                                # e801h memory size call
                                                # or merely pass cx,dx though
                                                # without changing them.
        movw    $0xe801, %ax
        int     $0x15
        jc      .Lint12

        testw   %cx, %cx                        # Kludge to handle BIOSes
        jnz     1f                              # which report their extended
        testw   %dx, %dx                        # memory in AX/BX rather than
        jnz     1f                              # CX/DX.  The spec I have read
        movw    %ax, %cx                        # seems to indicate AX/BX 
        movw    %bx, %dx                        # are more reasonable anyway...
1:      movzwl  %dx, %edx
        shll    $6,%edx                         # and go from 64k to 1k chunks
        movzwl  %cx, %ecx
        addl    %ecx, %edx                      # add in lower memory
        movl    %edx,bootsym(highmem_kb)        # store extended memory size

.Lint12:
        int     $0x12
        movw    %ax,bootsym(lowmem_kb)

        ret

/*
 * Copy E820 map obtained from BIOS to a buffer allocated by Xen.
 * Input: %rdi: target address of e820 entry array
 *        %esi: maximum number of entries to copy
 * Output: %eax: number of entries copied
 */
        .code64
ENTRY(e820map_copy)
        mov     %esi, %eax
        lea     e820map(%rip), %rsi
        mov     e820nr(%rip), %ecx
        cmp     %ecx, %eax
        cmova   %ecx, %eax                      # number of entries to move
        imul    $5, %eax, %ecx
        rep movsl                               # do the move
        ret

        .align  4
e820map:
        .fill   E820_BIOS_MAX*20,1,0
e820nr:
        .long   0
GLOBAL(lowmem_kb)
        .long   0
GLOBAL(highmem_kb)
        .long   0
