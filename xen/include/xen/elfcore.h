/******************************************************************************
 * elfcore.h
 *
 * Based heavily on include/linux/elfcore.h from Linux 2.6.16
 * Naming scheeme based on include/xen/elf.h (not include/linux/elfcore.h)
 *
 */

#ifndef __ELFCOREC_H__
#define __ELFCOREC_H__

#include <xen/types.h>
#include <xen/elf.h>
#include <asm/elf.h>
#include <public/xen.h>

#define NT_PRSTATUS     1

typedef struct
{
    int signo;                       /* signal number */
    int code;                        /* extra code */
    int errno;                       /* errno */
} ELF_Signifo;

/* These seem to be the same length on all architectures on Linux */
typedef int ELF_Pid;
typedef struct {
	long tv_sec;
	long tv_usec;
} ELF_Timeval;

/*
 * Definitions to generate Intel SVR4-like core files.
 * These mostly have the same names as the SVR4 types with "elf_"
 * tacked on the front to prevent clashes with linux definitions,
 * and the typedef forms have been avoided.  This is mostly like
 * the SVR4 structure, but more Linuxy, with things that Linux does
 * not support and which gdb doesn't really use excluded.
 */
typedef struct
{
    ELF_Signifo pr_info;         /* Info associated with signal */
    short pr_cursig;             /* Current signal */
    unsigned long pr_sigpend;    /* Set of pending signals */
    unsigned long pr_sighold;    /* Set of held signals */
    ELF_Pid pr_pid;
    ELF_Pid pr_ppid;
    ELF_Pid pr_pgrp;
    ELF_Pid pr_sid;
    ELF_Timeval pr_utime;        /* User time */
    ELF_Timeval pr_stime;        /* System time */
    ELF_Timeval pr_cutime;       /* Cumulative user time */
    ELF_Timeval pr_cstime;       /* Cumulative system time */
    ELF_Gregset pr_reg;          /* GP registers - from asm header file */
    int pr_fpvalid;              /* True if math co-processor being used.  */
} ELF_Prstatus;

/*
 * The following data structures provide 64-bit ELF notes. In theory it should 
 * be possible to support both 64-bit and 32-bit ELF files, but to keep it 
 * simple we only do 64-bit.
 *
 * Please note that the current code aligns the 64-bit notes in the same
 * way as Linux does. We are not following the 64-bit ELF spec, no one does.
 *
 * We are avoiding two problems by restricting us to 64-bit notes only:
 * - Alignment of notes change with the word size. Ick.
 * - We would need to tell kexec-tools which format we are using in the
 *   hypervisor to make sure the right ELF format is generated.
 *   That requires infrastructure. Let's not.
 */

#define ALIGN(x, n) ((x + ((1 << n) - 1)) / (1 << n))
#define PAD32(x) u32 pad_data[ALIGN(x, 2)]

#define TYPEDEF_NOTE(type, strlen, desctype)    \
    typedef struct {                            \
        union {                                 \
            struct {                            \
                Elf_Note note;                  \
                unsigned char name[strlen];     \
            } note;                             \
            PAD32(sizeof(Elf_Note) + strlen);   \
        } note;                                 \
        union {                                 \
            desctype desc;                      \
            PAD32(sizeof(desctype));            \
        } desc;                                 \
    } __attribute__ ((packed)) type

#define CORE_STR                "CORE"
#define CORE_STR_LEN            5 /* including terminating zero */

TYPEDEF_NOTE(crash_note_core_t, CORE_STR_LEN, ELF_Prstatus);

#define XEN_STR                 "Xen"
#define XEN_STR_LEN             4 /* including terminating zero */

TYPEDEF_NOTE(crash_note_xen_core_t, XEN_STR_LEN, crash_xen_core_t);

typedef struct {
    unsigned long xen_major_version;
    unsigned long xen_minor_version;
    unsigned long xen_extra_version;
    unsigned long xen_changeset;
    unsigned long xen_compiler;
    unsigned long xen_compile_date;
    unsigned long xen_compile_time;
    unsigned long tainted;
} crash_xen_info_t;

TYPEDEF_NOTE(crash_note_xen_info_t, XEN_STR_LEN, crash_xen_info_t);

typedef struct {
    crash_note_core_t core;
    crash_note_xen_core_t xen_regs;
    crash_note_xen_info_t xen_info;
} __attribute__ ((packed)) crash_note_t;

#define setup_crash_note(np, member, str, str_len, id) \
  np->member.note.note.note.namesz = str_len; \
  np->member.note.note.note.descsz = sizeof(np->member.desc.desc); \
  np->member.note.note.note.type = id; \
  memcpy(np->member.note.note.name, str, str_len)

#endif /* __ELFCOREC_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
