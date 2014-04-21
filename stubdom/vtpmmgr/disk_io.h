#ifndef __VTPMMGR_DISK_IO_H
#define __VTPMMGR_DISK_IO_H

void* disk_read_sector(sector_t sector);
void disk_write_sector(sector_t sector, void* buf, size_t siz);
void* disk_write_buf(void);
void disk_write_barrier(void);

sector_t disk_find_free(const struct mem_tpm_mgr *mgr);
void disk_flush_slot(const struct mem_tpm_mgr *mgr);
void disk_set_used(sector_t loc, const struct mem_tpm_mgr *mgr);

void disk_write_all(struct mem_tpm_mgr *mgr);

static inline sector_t seal_loc(struct mem_tpm_mgr *mgr)
{
	return native_be32(mgr->active_root);
}

static inline sector_t root_loc(struct mem_tpm_mgr *mgr)
{
	return native_be32(2 + mgr->active_root);
}

#endif
