/**************************************************************************
 * 
 * vdi.h
 *
 * Virtual Disk Image (VDI) Interfaces
 *
 */

#ifndef __VDI_H__
#define __VDI_H__

#include "blktaplib.h"
#include "snaplog.h"

#define VDI_HEIGHT     35
#define VDI_REG_HEIGHT 35 /* why not? */

#define VDI_NAME_SZ 256

typedef struct vdi {
    u64         id;               /* unique vdi id -- used by the registry   */
    u64         block;            /* block where this vdi lives (also unique)*/
    u64         radix_root;       /* radix root node for block mappings      */
    snap_id_t   snap;             /* next snapshot slot for this VDI         */
    struct vdi *next;             /* used to hash-chain in blkif.            */
    blkif_vdev_t vdevice;         /* currently mounted as...                 */
    char        name[VDI_NAME_SZ];/* human readable vdi name                 */
} vdi_t;

#define VDI_REG_MAGIC   0xff00ff0bb0ff00ffLL

typedef struct vdi_registry {
    u64     magic;
    u64     nr_vdis;
} vdi_registry_t;


int __init_vdi(void);

vdi_t *vdi_get(u64 vdi_id);
vdi_registry_t *get_vdi_registry(void);
vdi_t *vdi_create(snap_id_t *parent_snap, char *name);
u64 vdi_lookup_block(vdi_t *vdi, u64 vdi_block, int *writable);
void vdi_update_block(vdi_t *vdi, u64 vdi_block, u64 g_block);
void vdi_snapshot(vdi_t *vdi);


#endif /* __VDI_H__ */
