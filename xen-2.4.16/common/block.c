/* block.c
 *
 * ring data structures for buffering messages between hypervisor and
 * guestos's. 
 *
 */

#include <hypervisor-ifs/block.h>
#include <xeno/lib.h>

/*
 * create_block_ring
 *
 * domain:
 *
 * allocates space for a particular domain's block io ring.
 */
blk_ring_t *create_block_ring(int domain)
{
    printk ("XEN create block ring <not implemented>");
    return (blk_ring_t *)NULL; 
}
