
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_sched_global";

int main(int argc, char **argv)
{
    dom0_op_t op;

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc != 2 ) 
    {
        fprintf(stderr, "Usage: %s <ctxt allowance>\n", argv0);
        return 1;
    }

    op.cmd = DOM0_BVTCTL;
    op.u.bvtctl.ctx_allow = atol(argv[1]);
    if ( do_dom0_op(&op) < 0 )
        return 1;

    return 0;
}
