
#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_stop";

static int kill_domain(int dom_id, int force)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_DESTROYDOMAIN;
    op.u.destroydomain.domain = dom_id;
    op.u.destroydomain.force  = force;

    err = do_dom0_op(&op);

    return (err < 0) ? -1 : 0;
}

int main(int argc, char **argv)
{
    int ret, dom;
    
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
    
    dom = atoi(argv[argc-1]);
    if ( dom == 0 )
    {
        ERROR("Did you really mean domain 0?");
        return 1;
    }

    ret = kill_domain(dom, argc == 3);
    
    return (ret != 0) ? 1 : 0;
}
