#ifndef __X86_64_BUG_H__
#define __X86_64_BUG_H__

struct bug_frame_str {
    unsigned char mov[2];
    unsigned long str;
} __attribute__((packed));
#define BUG_MOV_STR "\x48\xbc"

#define dump_execution_state()                          \
    asm volatile (                                      \
        "ud2 ; ret $%c0"                                \
        : : "i" (BUGFRAME_dump) )

#define WARN()                                          \
    asm volatile (                                      \
        "ud2 ; ret $%c0 ; .byte 0x48,0xbc ; .quad %c1"  \
        : : "i" (BUGFRAME_warn | (__LINE__<<2)),        \
            "i" (__FILE__) )

#define BUG()                                           \
    asm volatile (                                      \
        "ud2 ; ret $%c0 ; .byte 0x48,0xbc ; .quad %c1"  \
        : : "i" (BUGFRAME_bug | (__LINE__<<2)),         \
            "i" (__FILE__) )

#define assert_failed(p)                                \
    asm volatile (                                      \
        "ud2 ; ret $%c0 ; .byte 0x48,0xbc ; .quad %c1"  \
        " ; .byte 0x48,0xbc ; .quad %c2"                \
        : : "i" (BUGFRAME_assert | (__LINE__<<2)),      \
            "i" (__FILE__), "i" (#p) )

#endif /* __X86_64_BUG_H__ */
