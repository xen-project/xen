
#ifndef _PDB_CAML_XEN_DEFINED_
#define _PDB_CAML_XEN_DEFINED_

enum gdb_registers { GDB_EAX, GDB_ECX, GDB_EDX, GDB_EBX,
                     GDB_ESP, GDB_EBP, GDB_ESI, GDB_EDI,
                     GDB_EIP, GDB_EFL, 
                     GDB_CS,  GDB_SS,  GDB_DS,  GDB_ES,
                     GDB_FS,  GDB_GS };

#define PAGE_SIZE 4096

extern int xc_handle;

void dump_regs (cpu_user_regs_t *ctx);

#endif

