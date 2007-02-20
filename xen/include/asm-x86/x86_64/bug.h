#ifndef __X86_64_BUG_H__
#define __X86_64_BUG_H__

struct bug_frame {
    unsigned char ud2[2];
    unsigned char mov[2];
    unsigned long filename;
    unsigned char ret;
    unsigned short line;
} __attribute__((packed));

#define BUG_MOV_STR "\x48\xbc"

#define __BUG(file, line)                               \
    asm volatile (                                      \
        "ud2 ; .byte 0x48,0xbc ; .quad %c1 ; ret $%c0"  \
        : : "i" (line), "i" (file) )

#endif /* __X86_64_BUG_H__ */
