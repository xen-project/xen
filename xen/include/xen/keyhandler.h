/* 
** We keep an array of 'handlers' for each key code between 0 and 255; 
** this is intended to allow very simple debugging routines (toggle 
** debug flag, dump registers, reboot, etc) to be hooked in in a slightly
** nicer fashion than just editing the serial/keyboard drivers. 
*/
#include <xen/sched.h>

typedef void key_handler(unsigned char key, void *dev_id, 
			 struct xen_regs *regs); 

extern void add_key_handler(unsigned char key, 
			    key_handler *handler, char *desc); 

extern key_handler *get_key_handler(unsigned char key); 

