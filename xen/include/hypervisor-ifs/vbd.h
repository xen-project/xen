#ifndef __HYP_IFS_VBD_H__
#define __HYP_IFS_VBD_H__


#define PHYSDISK_MODE_R 1
#define PHYSDISK_MODE_W 2

#if 0
typedef struct xp_disk
{
  int mode; /* 0 -> revoke existing access, otherwise bitmask of
	       PHYSDISK_MODE_? constants */
  int domain;
  unsigned short device; /* XENDEV_??? + idx */
  unsigned short partition; /* partition number */
  unsigned long start_sect;
  unsigned long n_sectors;
} xp_disk_t;

#define PHYSDISK_MAX_ACES_PER_REQUEST 254 /* Make it fit in one page */
typedef struct {
  int n_aces;
  int domain;
  int start_ind;
  struct {
    unsigned short device; /* XENDEV_??? + idx */
    unsigned short partition; /* partition number */
    unsigned long start_sect;
    unsigned long n_sectors;
    unsigned mode;
  } entries[PHYSDISK_MAX_ACES_PER_REQUEST];
} physdisk_probebuf_t;
#endif


/* Block I/O trap operations and associated structures.
 */

#define BLOCK_IO_OP_SIGNAL      0    /* let xen know we have work to do */ 
#define BLOCK_IO_OP_RESET       1    /* reset ring indexes on quiescent i/f */
#define BLOCK_IO_OP_VBD_CREATE  2    /* create a new VBD for a given domain */
#define BLOCK_IO_OP_VBD_ADD     3    /* add an extent to a given VBD */
#define BLOCK_IO_OP_VBD_REMOVE  4    /* remove an extent from a given VBD */
#define BLOCK_IO_OP_VBD_DELETE  5    /* delete a VBD */


typedef struct _xen_extent { 
    u16       device; 
    ulong     start_sector; 
    ulong     nr_sectors;
    u16       mode; 
} xen_extent_t; 

  
typedef struct _vbd_create { 
    unsigned  domain; 
    u16       vdevice; 
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
	vbd_create_t  create_info; 
	vbd_add_t     add_info; 
	vbd_remove_t  remove_info; 
	vbd_delete_t  delete_info; 
        /* no entry for BLOCK_IO_OP_RESET  */
    }
    u;
} block_io_op_t;




#endif /* __HYP_IFS_VBD_H__ */
