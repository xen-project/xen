/*
 * xc_debug.h
 *
 * alex ho
 * http://www.cl.cam.ac.uk/netos/pdb
 *
 */

#ifndef _XC_DEBUG_H_DEFINED
#define _XC_DEBUG_H_DEFINED

int xc_debug_attach(int xc_handle,
		    u32 domid,
		    u32 vcpu);

int xc_debug_detach(int xc_handle,
		    u32 domid,
		    u32 vcpu);

int xc_debug_read_registers(int xc_handle,
			    u32 domid,
			    u32 vcpu,
			    cpu_user_regs_t **regs);

int xc_debug_read_fpregisters (int xc_handle,
			       u32 domid,
			       u32 vcpu,
			       char **regs);

int xc_debug_write_registers(int xc_handle,
			     u32 domid,
			     u32 vcpu,
			     cpu_user_regs_t *regs);

int xc_debug_step(int xc_handle,
		  u32 domid,
		  u32 vcpu);

int xc_debug_continue(int xc_handle,
		      u32 domid,
		      u32 vcpu);

int xc_debug_read_memory(int xc_handle,
			 u32 domid,
			 u32 vcpu,
			 memory_t address,
			 u32 length,
			 u8 *data);


int xc_debug_write_memory(int xc_handle,
			  u32 domid,
			  u32 vcpu,
			  memory_t address,
			  u32 length,
			  u8 *data);


int xc_debug_insert_memory_breakpoint(int xc_handle,
				      u32 domid,
				      u32 vcpu,
				      memory_t address,
				      u32 length);

int xc_debug_remove_memory_breakpoint(int xc_handle,
				      u32 domid,
				      u32 vcpu,
				      memory_t address,
				      u32 length);

int xc_debug_query_domain_stop(int xc_handle,
			       int *dom_list, 
			       int dom_list_size);


#endif /* _XC_DEBUG_H_DEFINED */
