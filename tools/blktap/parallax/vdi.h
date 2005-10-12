#ifndef _VDI_H_
#define _VDI_H_
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

#define VDI_HEIGHT     27 /* Note that these are now hard-coded */
#define VDI_REG_HEIGHT 27 /* in the async lookup code           */

#define VDI_NAME_SZ 256


typedef struct vdi {
    uint64_t         id;               /* unique vdi id -- used by the registry   */
    uint64_t         block;            /* block where this vdi lives (also unique)*/
    uint64_t         radix_root;       /* radix root node for block mappings      */
    snap_id_t   snap;             /* next snapshot slot for this VDI         */
    struct vdi *next;             /* used to hash-chain in blkif.            */
    blkif_vdev_t vdevice;         /* currently mounted as...                 */
    struct radix_lock *radix_lock;/* per-line L1 RW lock for parallel reqs   */
    char        name[VDI_NAME_SZ];/* human readable vdi name                 */
} vdi_t;

#define VDI_REG_MAGIC   0xff00ff0bb0ff00ffLL

typedef struct vdi_registry {
    uint64_t     magic;
    uint64_t     nr_vdis;
} vdi_registry_t;


int __init_vdi(void);

vdi_t *vdi_get(uint64_t vdi_id);
void vdi_put(vdi_t *vdi);
vdi_registry_t *get_vdi_registry(void);
vdi_t *vdi_create(snap_id_t *parent_snap, char *name);
uint64_t vdi_lookup_block(vdi_t *vdi, uint64_t vdi_block, int *writable);
void vdi_update_block(vdi_t *vdi, uint64_t vdi_block, uint64_t g_block);
void vdi_snapshot(vdi_t *vdi);


#endif /* __VDI_H__ */

#endif //_VDI_H_
