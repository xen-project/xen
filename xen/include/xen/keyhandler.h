/* 
** We keep an array of 'handlers' for each key code between 0 and 255; 
** this is intended to allow very simple debugging routines (toggle 
** debug flag, dump registers, reboot, etc) to be hooked in in a slightly
** nicer fashion than just editing the serial/keyboard drivers. 
*/
struct xen_regs;

typedef void key_handler(unsigned char key);

extern void add_key_handler(unsigned char key, 
			    key_handler *handler, char *desc); 
extern void add_key_handler_no_defer(unsigned char key, 
                                     key_handler *handler, char *desc); 

extern void handle_keypress(unsigned char key, struct xen_regs *regs);
