
#include "hypervisor-ifs/dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_start";

static int start_domain(int id)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_STARTDOMAIN;
    op.u.meminfo.domain = id;

    err = do_dom0_op(&op);

    return (err < 0) ? -1 : 0;
}    

int main(int argc, char **argv)
{
    int rc, dom;

    if ( argv[0] != NULL ) 
        argv0 = argv[0];

    if ( argc != 2 ) 
    {
        fprintf(stderr, "Usage: %s <domain-id>\n", argv0);
        return 1;
    }

    dom = atoi(argv[1]);
    if ( dom == 0 )
    {
        ERROR("Did you really mean domain 0?");
        return 1;
    }

    rc = start_domain(dom);;

    return (rc != 0) ? 1 : 0;
}
