#ifndef __HYP_IFS_VBD_H__
#define __HYP_IFS_VBD_H__


/* 
 * Block I/O trap operations and associated structures.
 */

#define BLOCK_IO_OP_SIGNAL       0    /* let xen know we have work to do */ 
#define BLOCK_IO_OP_RESET        1    /* reset ring indexes on quiescent i/f */
#define BLOCK_IO_OP_RING_ADDRESS 2    /* returns machine address of I/O ring */
#define BLOCK_IO_OP_VBD_CREATE   3    /* create a new VBD for a given domain */
#define BLOCK_IO_OP_VBD_ADD      4    /* add an extent to a given VBD */
#define BLOCK_IO_OP_VBD_REMOVE   5    /* remove an extent from a given VBD */
#define BLOCK_IO_OP_VBD_DELETE   6    /* delete a VBD */


typedef struct _xen_extent { 
    u16       device; 
    u16       unused;                 // pad 
    ulong     start_sector; 
    ulong     nr_sectors;
} xen_extent_t; 



#define VBD_MODE_R         0x1
#define VBD_MODE_W         0x2

#define VBD_CAN_READ(_v)  ((_v)->mode & VBD_MODE_R)
#define VBD_CAN_WRITE(_v) ((_v)->mode & VBD_MODE_W)

  
typedef struct _vbd_create { 
    unsigned  domain; 
    u16       vdevice; 
    u16       mode; 
} vbd_create_t; 

typedef struct _vbd_add { 
    unsigned     domain; 
    u16          vdevice; 
    xen_extent_t extent; 
} vbd_add_t; 

typedef struct _vbd_remove { 
    unsigned     domain; 
    u16          vdevice; 
    xen_extent_t extent; 
} vbd_remove_t; 


typedef struct _vbd_delete { 
    unsigned  domain; 
    u16       vdevice; 
} vbd_delete_t; 



typedef struct block_io_op_st
{
    unsigned long cmd;
    union
    {
        /* no entry for BLOCK_IO_OP_SIGNAL */
        /* no entry for BLOCK_IO_OP_RESET  */
	unsigned long ring_mfn; 
	vbd_create_t  create_info; 
	vbd_add_t     add_info; 
	vbd_remove_t  remove_info; 
	vbd_delete_t  delete_info; 
    }
    u;
} block_io_op_t;




#endif /* __HYP_IFS_VBD_H__ */
