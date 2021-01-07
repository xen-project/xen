        .code16

#define SMAP    0x534d4150
#define E820_BIOS_MAX 128

get_memory_map:
        xorl    %ebx, %ebx                      # continuation counter
        movw    $bootsym(bios_e820map), %di     # point into the whitelist
                                                # so we can have the bios
                                                # directly write into it.

1:      movl    $0x0000e820, %eax               # e820, upper word zeroed
        movl    $SMAP,%edx                      # ascii 'SMAP'
        movl    $20,%ecx                        # size of the e820rec
        pushw   %ds                             # data record.
        popw    %es
        int     $0x15
        jc      .Ldone

        cmpl    $SMAP,%eax                      # check the return is `SMAP'
        jne     .Ldone

        incw    bootsym(bios_e820nr)
        cmpw    $E820_BIOS_MAX, bootsym(bios_e820nr) # up to this many entries
        jae     .Ldone

        movw    %di,%ax
        addw    $20,%ax
        movw    %ax,%di
        testl   %ebx,%ebx                       # check to see if
        jnz     1b                              # %ebx is set to EOF

.Ldone:
        ret

        .align  4
GLOBAL(bios_e820map)
        .fill   E820_BIOS_MAX*20,1,0
GLOBAL(bios_e820nr)
        .long   0
