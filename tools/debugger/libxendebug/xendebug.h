/*
 * xendebug.h
 *
 * alex ho
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 */

#ifndef _XENDEBUG_H_DEFINED
#define _XENDEBUG_H_DEFINED

#include <xenctrl.h>

int xendebug_attach(int xc_handle,
		    uint32_t domid,
		    uint32_t vcpu);

int xendebug_detach(int xc_handle,
		    uint32_t domid,
		    uint32_t vcpu);

int xendebug_read_registers(int xc_handle,
			    uint32_t domid,
			    uint32_t vcpu,
			    cpu_user_regs_t **regs);

int xendebug_read_fpregisters (int xc_handle,
			       uint32_t domid,
			       uint32_t vcpu,
			       char **regs);

int xendebug_write_registers(int xc_handle,
			     uint32_t domid,
			     uint32_t vcpu,
			     cpu_user_regs_t *regs);

int xendebug_step(int xc_handle,
		  uint32_t domid,
		  uint32_t vcpu);

int xendebug_continue(int xc_handle,
		      uint32_t domid,
		      uint32_t vcpu);

int xendebug_read_memory(int xc_handle,
			 uint32_t domid,
			 uint32_t vcpu,
			 unsigned long address,
			 uint32_t length,
			 uint8_t *data);


int xendebug_write_memory(int xc_handle,
			  uint32_t domid,
			  uint32_t vcpu,
			  unsigned long address,
			  uint32_t length,
			  uint8_t *data);


int xendebug_insert_memory_breakpoint(int xc_handle,
				      uint32_t domid,
				      uint32_t vcpu,
				      unsigned long address,
				      uint32_t length);

int xendebug_remove_memory_breakpoint(int xc_handle,
				      uint32_t domid,
				      uint32_t vcpu,
				      unsigned long address,
				      uint32_t length);

int xendebug_query_domain_stop(int xc_handle,
			       int *dom_list, 
			       int dom_list_size);


#endif /* _XENDEBUG_H_DEFINED */
