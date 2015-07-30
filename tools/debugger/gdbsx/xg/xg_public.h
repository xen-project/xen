/*
 * Copyright (C) 2009, Mukesh Rathor, Oracle Corp.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#define XGERR(...)   \
           do {(xgprt(__FUNCTION__,__VA_ARGS__));} while (0)
#define XGTRC(...)   \
           do {(xgtrc_on) ? (xgtrc(__FUNCTION__,__VA_ARGS__)):0;} while (0)
#define XGTRC1(...)  \
           do {(xgtrc_on==2) ? (xgtrc(__FUNCTION__,__VA_ARGS__)):0;} while (0)

#if defined(__x86_64__)
    #define  XGFM64  "%lx"
    #define  XGF64   "%016lx"
#else
    #define  XGFM64  "%llx"
    #define  XGF64   "%016llx"
#endif


typedef enum {
    XG_GPRS=1,          /* general purpose user regs */
    XG_FPRS=2,          /* floating point user regs */
} regstype_t;


typedef uint32_t vcpuid_t;

extern int xgtrc_on;

/* what gdb wants to receive during register read, or sends during write.
 * this from : regformats/reg-i386-linux.dat in gdbserver */
struct xg_gdb_regs32 {
    uint32_t  eax;
    uint32_t  ecx;
    uint32_t  edx;
    uint32_t  ebx;
    uint32_t  esp;
    uint32_t  ebp;
    uint32_t  esi;
    uint32_t  edi;
    uint32_t  eip;
    uint32_t  eflags;
    uint32_t  cs;
    uint32_t  ss;
    uint32_t  ds;
    uint32_t  es;
    uint32_t  fs;
    uint32_t  gs;
};  

/* this from: regformats/reg-x86-64.dat in gdbserver */
struct xg_gdb_regs64 {
    uint64_t  rax;
    uint64_t  rbx;
    uint64_t  rcx;
    uint64_t  rdx;
    uint64_t  rsi;
    uint64_t  rdi;
    uint64_t  rbp;
    uint64_t  rsp;
    uint64_t  r8;
    uint64_t  r9;
    uint64_t  r10;
    uint64_t  r11;
    uint64_t  r12;
    uint64_t  r13;
    uint64_t  r14;
    uint64_t  r15;
    uint64_t  rip;
    uint64_t  rflags;
    uint64_t  cs;
    uint64_t  ss;
    uint64_t  ds;
    uint64_t  es;
    uint64_t  fs;
    uint64_t  gs;
};

union xg_gdb_regs {
    struct xg_gdb_regs32 gregs_32;
    struct xg_gdb_regs64 gregs_64;
};


int xg_init(void);
int xg_attach(int, int);
void xg_detach_deinit(void);
int xg_step(vcpuid_t, int);
vcpuid_t xg_resume_n_wait(int);
int xg_regs_read(regstype_t, vcpuid_t, union xg_gdb_regs *, int);
int xg_regs_write(regstype_t, vcpuid_t, union xg_gdb_regs *, int);
int xg_read_mem(uint64_t, char *, int, uint64_t);
int xg_write_mem(uint64_t, char *, int, uint64_t);
void xgprt(const char *fn, const char *fmt, ...);
void xgtrc(const char *fn, const char *fmt, ...);
