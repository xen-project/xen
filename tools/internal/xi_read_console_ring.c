/* 
 * Usage: <executable> [-c]
 */

#include "dom0_defs.h"

#define CONSOLE_RING_SIZE	16392
#define CONSOLE_RING_CLEAR	1

static char *argv0 = "read_console_ring";

static long read_console_ring(unsigned long str, unsigned count, unsigned int cmd)
{
    int ret;
    dom0_op_t op;

    op.cmd = DOM0_READCONSOLE;
    op.u.readconsole.str = str;
    op.u.readconsole.count = count;
    op.u.readconsole.cmd = cmd;

    ret = do_dom0_op(&op);
    if (ret > 0) {
        *((char *)str + ret) = '\0';
    }

    return ret;
}    

int main(int argc, char **argv)
{
    char str[CONSOLE_RING_SIZE+1];
    unsigned int cmd = 0;
    
    if ( argv[0] != NULL ) 
        argv0 = argv[0];
    
    if ( argc > 2 || (argc == 2 && strcmp(argv[1], "-c")) ) {
        fprintf(stderr, "Usage: %s [-c]\n", argv0);
        return 1;
    }

    if ( argc == 2) {
	cmd |= CONSOLE_RING_CLEAR;
    }
    
    if ( mlock(str, CONSOLE_RING_SIZE+1) != 0) {
        PERROR("Could not lock memory for user space read console ring buffer");
        return 1;
    }
    
    if ( read_console_ring((unsigned long)str, CONSOLE_RING_SIZE, cmd) < 0 ) {
	printf("Read console ring error.\n");
        return 1;
    }

    printf("%s", str);
	
    return 0;
}
