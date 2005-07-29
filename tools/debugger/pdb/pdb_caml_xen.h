/*
 * pdb_caml_xen.h
 *
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 * generic xen definitions
 *
 */

#ifndef _PDB_CAML_XEN_DEFINED_
#define _PDB_CAML_XEN_DEFINED_

enum gdb_registers { /* 32 */ GDB_EAX, GDB_ECX, GDB_EDX, GDB_EBX,
                              GDB_ESP, GDB_EBP, GDB_ESI, GDB_EDI,
                              GDB_EIP, GDB_EFL, 
                     /* 16 */ GDB_CS,  GDB_SS,  GDB_DS,  GDB_ES,
                              GDB_FS,  GDB_GS };
#define GDB_REGISTER_FRAME_SIZE 16

/* this order comes from linux-2.6.11/include/asm-i386/ptrace.h */
enum x86_registers { LINUX_EBX, LINUX_ECX, LINUX_EDX, LINUX_ESI, LINUX_EDI,
                     LINUX_EBP, LINUX_EAX, LINUX_DS,  LINUX_ES,  LINUX_FS,
                     LINUX_GS,  LINUX_ORIG_EAX, LINUX_EIP, LINUX_CS, LINUX_EFL,
                     LINUX_ESP, LINUX_SS };
#define REGISTER_FRAME_SIZE 17


/* hack: this is also included from the pdb linux module which
   has PAGE_SIZE defined */
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

extern int xc_handle;

void dump_regs (cpu_user_regs_t *ctx);

#endif

