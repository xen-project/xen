
/*
 * pervasive debugger
 * www.cl.cam.ac.uk/netos/pdb
 *
 * alex ho
 * 2004
 * university of cambridge computer laboratory
 *
 * code adapted originally from kgdb, nemesis, & gdbserver
 */

#include <xen/lib.h>
#include <xen/sched.h>
#include <asm/ptrace.h>
#include <xen/keyhandler.h> 
//#include <asm/apic.h>
#include <asm/domain_page.h>                           /* [un]map_domain_mem */
#include <asm/processor.h>
#include <asm/pdb.h>
#include <xen/list.h>
#include <xen/serial.h>

#define __PDB_GET_VAL 1
#define __PDB_SET_VAL 2

/*
 * Read or write memory in an address space
 */
int pdb_change_values(u_char *buffer, int length,
		      unsigned long cr3, unsigned long addr, int rw)
{
	dummy();
	return 0;
}

/*
 * Set memory in a domain's address space
 * Set "length" bytes at "address" from "domain" to the values in "buffer".
 * Return the number of bytes set, 0 if there was a problem.
 */

int pdb_set_values(u_char *buffer, int length,
		   unsigned long cr3, unsigned long addr)
{
    int count = pdb_change_values(buffer, length, cr3, addr, __PDB_SET_VAL);
    return count;
}

/*
 * Read memory from a domain's address space.
 * Fetch "length" bytes at "address" from "domain" into "buffer".
 * Return the number of bytes read, 0 if there was a problem.
 */

int pdb_get_values(u_char *buffer, int length,
		   unsigned long cr3, unsigned long addr)
{
  return pdb_change_values(buffer, length, cr3, addr, __PDB_GET_VAL);
}

