/*
 * kdd.h -- Structures, constants and descriptions of the Windows 
 *          kd serial debugger protocol, for the kdd debugging stub.
 *
 * Tim Deegan <Tim.Deegan@citrix.com>
 * 
 * Copyright (c) 2007-2010, Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _KDD_H_
#define _KDD_H_

#include <stdint.h>

#define PACKED __attribute__((packed))

/*****************************************************************************
 * Serial line protocol: Sender sends a 16-byte header with an optional
 * payload following it.  Receiver responds to each packet with an
 * acknowledgment (16-byte header only).
 *
 * Packet headers start with ASCII "0000" and there is a trailing byte
 * 0xAA after the (optional) payload.  Ack headers start with ASCII
 * "iiii"; no trailing byte).  Each packet and ack has a major type in
 * the packet header; for packets with payload, a minor type is encoded
 * in ASCII in the first four bytes of the payload.
 *
 * Packet IDs seem to start at 0x80800000 and alternate between that and
 * 0x80800001; not clear whether the client's ID is always the ID of the
 * last packet from the kernel or whether they're just oscillating in
 * phase.  Either way there's clearly some state machine in the kernel
 * that requires this exact behaviour from the client.
 *
 * All acks have length 0, id = id of the packet they ack.
 */

#define KDD_DIR_PKT 0x30303030   /* "0000" */
#define KDD_DIR_ACK 0x69696969   /* "iiii" */

typedef struct {
    uint32_t dir;     /* KDD_DIR_PKT or KDD_DIR_ACK */
    uint16_t type;    /* Major type. */
    uint16_t len;     /* Payload length, excl. header and trailing byte */
    uint32_t id;      /* Echoed in responses */
    uint32_t sum;     /* Unsigned sum of all payload bytes */
    uint8_t payload[0];
} PACKED kdd_hdr;

#define KDD_PKT_CMD 0x0002      /* Debugger commands (and replies to them) */
#define KDD_PKT_MSG 0x0003      /* Kernel messages for the user */
#define KDD_PKT_STC 0x0007      /* State change notification */
#define KDD_PKT_REG 0x000b      /* Registry change notification (?) */
#define KDD_PKT_MAX 0x000b

#define KDD_ACK_OK  0x0004      /* Checksum, ID and type all fine */
#define KDD_ACK_BAD 0x0005      /* Something is bogus */
#define KDD_ACK_RST 0x0006      /* Not really an ack; one each way to resync */


/*****************************************************************************
 * Debugger commands, carried over the serial line.  In this protocol,
 * we ignore the serial-level acking; when we talk about a response,
 * it's another packet, sent after the request was acked, and which will
 * itself be acked.
 *
 * The debugger client sends commands to the kernel, all of which have
 * major type 2 and are 56 bytes long (not including the serial header).
 * Not all the 56 bytes are used in every command, but the client
 * doesn't bother to zero unused fields.  Most commands are responded to
 * by a packet with the same subtype, containing at least a status code
 * to indicate success or failure.
 */

#define KDD_STATUS_SUCCESS  0x00000000
#define KDD_STATUS_FAILURE  0xc0000001
#define KDD_STATUS_PENDING  0x00000103

/* Memory access.  Read commands are echoed in the response with the
 * status and length_rsp fields updated, and the read data appended to the
 * packet.  Writes are the same, but with the data appended to the
 * write command, not the response. */

#define KDD_CMD_READ_VA     0x00003130  /* "01" */
#define KDD_CMD_WRITE_VA    0x00003131  /* "11" */
#define KDD_CMD_READ_CTRL   0x00003137  /* "71" */
#define KDD_CMD_WRITE_CTRL  0x00003138  /* "81" */
#define KDD_CMD_READ_PA     0x0000313D  /* "=1" */
#define KDD_CMD_WRITE_PA    0x0000313E  /* ">1" */

/* Not sure what this is, but it doesn't require a response */
#define KDD_CMD_WRITE_Z     0x0000315A  /* "Z1" */

typedef struct {
    uint32_t u1;
    uint32_t status;            /* IN: STATUS_PENDING; OUT: result status. */
    uint32_t u2;
    uint64_t addr;              /* IN: address of start of read/write */
    uint32_t length_req;        /* IN: bytes to read/write */
    uint32_t length_rsp;        /* OUT: bytes successfully read/written */
} PACKED kdd_cmd_mem;

/* CPU register access.  As for memory accesses, but the data is a
 * fixed-length block of register info. */

#define KDD_CMD_READ_REGS   0x00003132  /* "21" */
#define KDD_CMD_WRITE_REGS  0x00003133  /* "31" */

typedef struct {
    uint16_t u1;
    uint16_t cpu;               /* IN: Zero-based processor ID */
    uint32_t status;            /* IN: STATUS_PENDING; OUT: result status. */
} PACKED kdd_cmd_regs;

#define KDD_CMD_READ_MSR    0x00003152  /* "R1" */
#define KDD_CMD_WRITE_MSR   0x00003153  /* "S1" */

typedef struct {
    uint32_t u1;
    uint32_t status;            /* IN: STATUS_PENDING; OUT: result status. */
    uint32_t u2;
    uint32_t msr;               /* IN/OUT: MSR number */
    uint64_t val;               /* IN/OUT: MSR contents */
} PACKED kdd_cmd_msr;

/* Breakpoint commands. */

#define KDD_CMD_SOFT_BP     0x00003135  /* "51" */

typedef struct {
    uint32_t u1;
    uint32_t status;            /* IN: STATUS_PENDING; OUT: result status. */
    uint32_t u2;
    uint32_t bp;                /* IN: ID of breakpoint to operate on */
} PACKED kdd_cmd_soft_bp;

#define KDD_CMD_HARD_BP     0x0000315C  /* "\1" */

typedef struct {
    uint32_t u1;
    uint32_t status;            /* IN: STATUS_PENDING; OUT: result status. */
    uint32_t u2;
    uint64_t address;           /* IN: Address to trap on */
    uint64_t u3;
    uint64_t u4;
    uint64_t u5;
    uint64_t u6;
} PACKED kdd_cmd_hard_bp;

/* Flow control commands.  These commands are _not_ responded to.  */

#define KDD_CMD_CONT1       0x00003136  /* "61" */
#define KDD_CMD_CONT2       0x0000313c  /* "<1" */

#define KDD_DBG_EXCEPTION_HANDLED    0x00010001
#define KDD_DBG_CONTINUE             0x00010002

typedef struct {
    uint32_t u1;
    uint32_t reason1;           /* IN: KDD_DBG_* */
    uint32_t u2;
    uint64_t reason2;           /* IN: always same as reason1 */
} PACKED kdd_cmd_cont;

/* Handshake command. */

#define KDD_CMD_SHAKE       0x00003146 /* "F1" */

#define KDD_MACH_x32        0x014c
#define KDD_MACH_x64        0x8664

#define KDD_FLAGS_MP        0x0001
#define KDD_FLAGS_64        0x0008

typedef struct {
    uint32_t u1;
    uint32_t status;            /* IN: STATUS_PENDING; OUT: result status. */
    uint32_t u2;
    uint16_t v_major;           /* OUT: OS major version (0xf for NT) */
    uint16_t v_minor;           /* OUT: OS minor version (NT build number) */
    uint16_t proto;             /* OUT: Protocol version (6) */
    uint16_t flags;             /* OUT: Some flags (at least 0x3) */
    uint16_t machine;           /* OUT: Machine type */
    uint8_t pkts;               /* OUT: Number of packet types understood */
    uint8_t states;             /* OUT: Number of state-change types used */
    uint8_t manips;             /* OUT: number of "manipulation" types used */
    uint8_t u3[3];
    int64_t kern_addr;          /* OUT: KernBase */
    int64_t mods_addr;          /* OUT: PsLoadedModuleList */
    int64_t data_addr;          /* OUT: DebuggerDataList */
} PACKED kdd_cmd_shake;

/* Change active CPU.  This command is _not_ responded to */

#define KDD_CMD_SETCPU      0x00003150 /* "P1" */

typedef struct {
    uint16_t u1;
    uint16_t cpu;               /* IN: Zero-based processor ID */
    uint32_t status;            /* IN: STATUS_PENDING */
} PACKED kdd_cmd_setcpu;

typedef struct {
    uint32_t subtype;           /* IN: KDD_CMD_x */
    union {
        kdd_cmd_mem mem;
        kdd_cmd_regs regs;
        kdd_cmd_msr msr;
        kdd_cmd_soft_bp sbp;
        kdd_cmd_hard_bp hbp;
        kdd_cmd_cont cont;
        kdd_cmd_shake shake;
        kdd_cmd_setcpu setcpu;
        uint8_t pad[52];
    };
    uint8_t data[0];
} PACKED kdd_cmd;


/*****************************************************************************
 * Kernel messages to the debugger.  The debugger does not respond to these
 * beyond ACKing them and printing approprate things on the debugger
 * console.
 */

/* Messages for the console */

#define KDD_MSG_PRINT       0x00003230  /* "02" */

typedef struct {
    uint32_t subtype;           /* KDD_MSG_PRINT */
    uint32_t u1;
    uint32_t length;            /* Length in bytes of trailing string */
    uint32_t u2;
    uint8_t string[0];          /* Non-terminated character string */
} PACKED kdd_msg;

/* Registry updates (Hive loads?) */

#define KDD_REG_CHANGE      0x00003430  /* "04" */

typedef struct {
    uint32_t subtype;           /* KDD_REG_CHANGE */
    uint32_t u1[15];
    uint16_t string[0];         /* Null-terminated wchar string */
} PACKED kdd_reg;

/* State changes.  After sending a state-change message the kernel halts
 * until it receives a continue command from the debugger. */

#define KDD_STC_STOP        0x00003030  /* "00" : Bug-check */
#define KDD_STC_LOAD        0x00003031  /* "01" : Loaded a module */

#define KDD_STC_STATUS_BREAKPOINT 0x80000003

typedef struct {
    uint16_t u1;
    uint16_t cpu;               /* Zero-based processor ID */
    uint32_t ncpus;             /* Number of processors */
    uint32_t u2;
    int64_t kthread;            /* Kernel thread structure */
    int64_t rip1;               /* Instruction pointer, sign-extended */
    uint64_t status;            /* KDD_STC_STATUS_x */
    uint64_t u3;
    int64_t rip2;               /* Same as rip1 */
    uint64_t nparams;           /* Number of stopcode parameters */
    uint64_t params[15];        /* Stopcode parameters */
    uint64_t first_chance;      /* OS exn handlers not yet been run? */
    uint32_t u4[2];
    uint32_t ilen;              /* Number of bytes of instruction following */
    uint8_t inst[36];           /* VA contents from %eip onwards */
} PACKED kdd_stc_stop;

typedef struct {
    uint32_t u1[3];
    uint64_t u2;
    uint64_t rip;               /* Instruction pointer, sign-extended */
    uint64_t u3[26];
    uint8_t path[0];            /* Null-terminated ASCII path to loaded mod. */
} PACKED kdd_stc_load;

typedef struct {
    uint32_t subtype;           /* KDD_STC_x */
    union {
        kdd_stc_stop stop;
        kdd_stc_load load;
    };
} PACKED kdd_stc;


/*****************************************************************************
 * Overall packet type
 */

typedef struct {
    kdd_hdr h;                  /* Major type disambiguates union below */
    union {
        kdd_cmd cmd;
        kdd_msg msg;
        kdd_reg reg;
        kdd_stc stc;
        uint8_t payload[0];
    };
} PACKED kdd_pkt;


/*****************************************************************************
 * Processor state layouts
 */

/* User-visible register files */
typedef union {
    uint32_t pad[179];
    struct {
        uint32_t u1[7];         /* Flags, DRx?? */
        uint8_t fp[112];        /* FP save state (why 112 not 108?) */
        int32_t gs;
        int32_t fs;
        int32_t es;
        int32_t ds;
        int32_t edi;
        int32_t esi;
        int32_t ebx;
        int32_t edx;
        int32_t ecx;
        int32_t eax;
        int32_t ebp;
        int32_t eip;
        int32_t cs;
        int32_t eflags;
        int32_t esp;
        int32_t ss;
        uint32_t sp2[37];       /* More 0x20202020. fp? */
        uint32_t sp3;           /* 0x00202020 */
    };
} PACKED kdd_regs_x86_32;

typedef union {
    uint64_t pad[154];
    struct {

        uint64_t u1[7];

        uint16_t cs; //2*1c
        uint16_t ds;
        uint16_t es;
        uint16_t fs;
        uint16_t gs;
        uint16_t ss;
        uint32_t rflags;
        uint64_t dr0;
        uint64_t dr1;
        uint64_t dr2;
        uint64_t dr3;
        uint64_t dr6;
        uint64_t dr7;
        int64_t rax;
        int64_t rcx;
        int64_t rdx;
        int64_t rbx;
        int64_t rsp;
        int64_t rbp;
        int64_t rsi;
        int64_t rdi;
        int64_t r8;
        int64_t r9;
        int64_t r10;
        int64_t r11;
        int64_t r12;
        int64_t r13;
        int64_t r14;
        int64_t r15;
        int64_t rip; //2*7c

        uint64_t u2[32];
        
        uint8_t fp[512]; // fp @2*100 .. 150 (+ more??)

        uint64_t u3[26];
    };
} PACKED kdd_regs_x86_64;

typedef union {
    kdd_regs_x86_32 r32;
    kdd_regs_x86_64 r64;
} PACKED kdd_regs;

/* System registers */
typedef struct {
    uint32_t cr0;
    uint32_t cr2;
    uint32_t cr3;
    uint32_t cr4;
    uint32_t dr0;
    uint32_t dr1;
    uint32_t dr2;
    uint32_t dr3;
    uint32_t dr6;
    uint32_t dr7;
    uint16_t gdt_pad;
    uint16_t gdt_limit;
    uint32_t gdt_base;
    uint16_t idt_pad;
    uint16_t idt_limit;
    uint32_t idt_base;
    uint16_t tss_sel;
    uint16_t ldt_sel;
    uint8_t u1[24];
} PACKED kdd_ctrl_x86_32;

typedef struct {
    uint64_t cr0;
    uint64_t cr2;
    uint64_t cr3; 
    uint64_t cr4;
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;
    uint64_t dr7;   
    uint8_t  gdt_pad[6];
    uint16_t gdt_limit;
    uint64_t gdt_base;
    uint8_t  idt_pad[6];
    uint16_t idt_limit;
    uint64_t idt_base;
    uint16_t tss_sel;
    uint16_t ldt_sel;
    uint8_t u1[44];
    uint64_t cr8;
    uint8_t u2[40];
    uint64_t efer; // XXX find out where EFER actually goes
} PACKED kdd_ctrl_x86_64;

typedef union {
    kdd_ctrl_x86_32 c32;
    kdd_ctrl_x86_64 c64;
} kdd_ctrl;

/*****************************************************************************
 * Functions required from the emulator/hypervisor for the stub to work.
 */

typedef struct kdd_guest kdd_guest;

/* Init and teardown guest-specific state */
extern kdd_guest *kdd_guest_init(char *arg, FILE *log, int verbosity);
extern void kdd_guest_teardown(kdd_guest *g);
extern char *kdd_guest_identify(kdd_guest *g);

/* Halt and restart the running guest */
extern void kdd_halt(kdd_guest *g);
extern void kdd_run(kdd_guest *g);

/* How many CPUs are there? */
extern int kdd_count_cpus(kdd_guest *g);

/* Accessor for guest physical memory, returning bytes read/written */
extern uint32_t kdd_access_physical(kdd_guest *g, uint64_t addr, 
                                    uint32_t len, uint8_t *buf, int write);

/* Accessors for guest registers, returning 0 for success */
extern int kdd_get_regs(kdd_guest *g, int cpuid, kdd_regs *r, int w64);
extern int kdd_set_regs(kdd_guest *g, int cpuid, kdd_regs *r, int w64);

/* Accessors for guest control registers, returning 0 for success */
extern int kdd_get_ctrl(kdd_guest *g, int cpuid, kdd_ctrl *ctrl, int w64);
extern int kdd_set_ctrl(kdd_guest *g, int cpuid, kdd_ctrl *ctrl, int w64);

/* Accessors for guest MSRs, returning 0 for success */
extern int kdd_wrmsr(kdd_guest *g, int cpuid, uint32_t msr, uint64_t value);
extern int kdd_rdmsr(kdd_guest *g, int cpuid, uint32_t msr, uint64_t *value);


/*****************************************************************************
 * Logfile usefulness
 */

/* Verbosity:
 * 0: errors (default)
 * 1: operations
 * 2: packets
 * 3: _everything_ */

#define KDD_LOG_IF(_v, _s, _fmt, _a...) do {    \
        if ((_s)->verbosity >= (_v)) {          \
        fprintf((_s)->log, (_fmt), ##_a);       \
        (void) fflush((_s)->log);               \
    }                                           \
} while (0)

#define KDD_LOG(_s, _fmt, _a...) KDD_LOG_IF(1, (_s), (_fmt), ##_a)
#define KDD_DEBUG(_s, _fmt, _a...) KDD_LOG_IF(3, (_s), (_fmt), ##_a)

#endif /* _KDD_H_ */
