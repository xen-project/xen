        .code16

#define SMAP    0x534d4150
#define E820MAX 128

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
        cmpw    $E820MAX,bootsym(e820nr)        # up to this many entries
        jae     .Lmem88

        movw    %di,%ax
        addw    $20,%ax
        movw    %ax,%di
        cmpl    $0,%ebx                         # check to see if
        jne     1b                              # %ebx is set to EOF

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

        cmpw    $0x0, %cx                       # Kludge to handle BIOSes
        jne     1f                              # which report their extended
        cmpw    $0x0, %dx                       # memory in AX/BX rather than
        jne     1f                              # CX/DX.  The spec I have read
        movw    %ax, %cx                        # seems to indicate AX/BX 
        movw    %bx, %dx                        # are more reasonable anyway...
1:      andl    $0xffff,%edx                    # clear sign extend
        shll    $6,%edx                         # and go from 64k to 1k chunks
        movl    %edx,bootsym(highmem_kb)        # store extended memory size
        andl    $0xffff,%ecx                    # clear sign extend
        addl    %ecx,bootsym(highmem_kb)        # and add lower memory into

.Lint12:
        int     $0x12
        movw    %ax,bootsym(lowmem_kb)

        ret

        .align  4
GLOBAL(e820map)
        .fill   E820MAX*20,1,0
GLOBAL(e820nr)
        .long   0
GLOBAL(lowmem_kb)
        .long   0
GLOBAL(highmem_kb)
        .long   0
