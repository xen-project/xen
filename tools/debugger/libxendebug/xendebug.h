/*
 * xendebug.h
 *
 * alex ho
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 */

#ifndef _XENDEBUG_H_DEFINED
#define _XENDEBUG_H_DEFINED

#include <xc.h>

int xendebug_attach(int xc_handle,
		    u32 domid,
		    u32 vcpu);

int xendebug_detach(int xc_handle,
		    u32 domid,
		    u32 vcpu);

int xendebug_read_registers(int xc_handle,
			    u32 domid,
			    u32 vcpu,
			    cpu_user_regs_t **regs);

int xendebug_read_fpregisters (int xc_handle,
			       u32 domid,
			       u32 vcpu,
			       char **regs);

int xendebug_write_registers(int xc_handle,
			     u32 domid,
			     u32 vcpu,
			     cpu_user_regs_t *regs);

int xendebug_step(int xc_handle,
		  u32 domid,
		  u32 vcpu);

int xendebug_continue(int xc_handle,
		      u32 domid,
		      u32 vcpu);

int xendebug_read_memory(int xc_handle,
			 u32 domid,
			 u32 vcpu,
			 unsigned long address,
			 u32 length,
			 u8 *data);


int xendebug_write_memory(int xc_handle,
			  u32 domid,
			  u32 vcpu,
			  unsigned long address,
			  u32 length,
			  u8 *data);


int xendebug_insert_memory_breakpoint(int xc_handle,
				      u32 domid,
				      u32 vcpu,
				      unsigned long address,
				      u32 length);

int xendebug_remove_memory_breakpoint(int xc_handle,
				      u32 domid,
				      u32 vcpu,
				      unsigned long address,
				      u32 length);

int xendebug_query_domain_stop(int xc_handle,
			       int *dom_list, 
			       int dom_list_size);


#endif /* _XENDEBUG_H_DEFINED */
