/* 
 * XenoDomainBuilder, copyright (c) Boris Dragovic, bd240@cl.cam.ac.uk
 * This code is released under terms and conditions of GNU GPL :).
 * Usage: <executable> <mem_kb> <os image> <num_vifs> 
 */

#include "dom0_defs.h"
#include "mem_defs.h"

static char *argv0 = "internal_domain_create";

static int create_new_domain(long req_mem, char *name)
{
    int err;
    dom0_op_t op;

    op.cmd = DOM0_CREATEDOMAIN;
    op.u.newdomain.memory_kb = req_mem;
    strncpy(op.u.newdomain.name, name, MAX_DOMAIN_NAME);
    op.u.newdomain.name[MAX_DOMAIN_NAME-1] = '\0';

    err = do_dom0_op(&op);

    return (err < 0) ? err : op.u.newdomain.domain;
}    

int main(int argc, char **argv)
{
    int dom_id;
    
    if ( argv[0] != NULL ) 
        argv0 = argv[0];
    
    if ( argc != 3 ) 
    {
        fprintf(stderr, "Usage: %s <kbytes-mem> <domain-name>\n", argv0);
        return 1;
    }
    
    dom_id = create_new_domain(atol(argv[1]), argv[2]);
    if ( dom_id < 0 )
        return 1;
    
    printf("%d\n", dom_id);
    return 0;
}
