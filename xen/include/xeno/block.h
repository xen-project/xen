/* block.h
 * 
 * this is the hypervisor end of the block io code. 
 */

#include <hypervisor-ifs/block.h>

/* vif prototypes */
blk_ring_t *create_block_ring(int domain);
void destroy_block_ring(struct task_struct *p);

