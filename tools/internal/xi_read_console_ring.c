/* 
 * Usage: <executable> [-c]
 */

#include "dom0_defs.h"

#define CONSOLE_RING_SIZE 16392
static char *argv0 = "read_console_ring";

static long read_console_ring(char *str, unsigned count)
{
    int ret;
    dom0_op_t op;

    op.cmd = DOM0_READCONSOLE;
    op.u.readconsole.str = str;
    op.u.readconsole.count = count;

    ret = do_dom0_op(&op);
    if (ret > 0) {
        *(str + ret) = '\0';
    }

    return ret;
}    

int main(int argc, char **argv)
{
    char str[CONSOLE_RING_SIZE];

    if ( argv[0] != NULL ) 
        argv0 = argv[0];
    
    if ( argc > 2) {
        fprintf(stderr, "Usage: %s [-r]\n", argv0);
        return 1;
    }
    
    if ( read_console_ring(str, CONSOLE_RING_SIZE) < 0 ) {
	printf("Read console ring error.\n");
	printf("%s", str);
        return 1;
    }

    printf("%s", str);
    return 0;
}
