
#include "hypervisor-ifs/dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_sched_domain";

int main(int argc, char **argv)
{
    dom0_op_t op;

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc != 6 ) 
    {
        fprintf(stderr, "Usage: %s <domain> <mcu_adv> "
                "<warp> <warpl> <warpu>\n", argv0);
        return 1;
    }

    op.cmd = DOM0_ADJUSTDOM;
    op.u.adjustdom.domain  = atoi(argv[1]);
    op.u.adjustdom.mcu_adv = atol(argv[2]);
    op.u.adjustdom.warp    = atol(argv[3]);
    op.u.adjustdom.warpl   = atol(argv[4]);
    op.u.adjustdom.warpu   = atol(argv[5]);
    if ( do_dom0_op(&op) < 0 )
        return 1;

    return 0;
}
