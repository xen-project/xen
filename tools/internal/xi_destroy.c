
#include "hypervisor-ifs/dom0_ops.h"
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_stop";

static int kill_domain(int dom_id, int force)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_DESTROYDOMAIN;
    op.u.killdomain.domain = dom_id;
    op.u.killdomain.force  = force;

    err = do_dom0_op(&op);

    return (err < 0) ? -1 : 0;
}

int main(int argc, char **argv)
{
    int ret;
    
    if ( argv[0] != NULL ) 
        argv0 = argv[0];
    
    if ( (argc < 2) || (argc > 3) )
    {
    usage:
        fprintf(stderr, "Usage: %s [-f] <domain_id>\n", argv0);
        fprintf(stderr, " -f: Forces immediate destruction of <domain_id>\n");
        return 1;
    }
    
    if ( (argc == 3) && strcmp("-f", argv[1]) )
        goto usage;
    
    ret = kill_domain(atoi(argv[argc-1]), argc == 3);
    
    return (ret != 0) ? 1 : 0;
}
