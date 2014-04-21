#include <console.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <mini-os/byteorder.h>

#include "vtpm_manager.h"
#include "log.h"
#include "uuid.h"

#include "vtpmmgr.h"
#include "vtpm_disk.h"
#include "disk_crypto.h"
#include "disk_format.h"
#include "disk_io.h"
#include "disk_tpm.h"

struct mem_tpm_mgr *g_mgr;

int vtpm_sync_disk(struct mem_tpm_mgr *mgr, int depth)
{
	int old_active_root = mgr->active_root;
	int new_active_root = !old_active_root;
	int rc = 0;
	struct tpm_authdata prev;
	struct mem_group *group0 = mgr->groups[0].v;

	// don't bother writing if we will never be able to read
	if (!group0 || !group0->nr_seals)
		return 0;

	mgr->sequence++;
	mgr->active_root = new_active_root;

	switch (depth) {
	case CTR_UPDATE:
	{
		uint32_t ctr = be32_native(mgr->counter_value);
		mgr->counter_value = native_be32(ctr + 1);
		break;
	}
	case MGR_KEY_UPDATE:
	{
		int i;
		mgr->root_seals_valid = 0;
		do_random(&mgr->tm_key, 16);
		aes_setup(&mgr->tm_key_e, &mgr->tm_key);
		do_random(&mgr->nv_key, 16);
		for(i=0; i < mgr->nr_groups; i++) {
			abort(); // TODO use raw re-encryption to handle unopened groups
		}
		break;
	}
	case CTR_AUTH_UPDATE:
		mgr->root_seals_valid = 0;
		memcpy(&prev, &mgr->counter_auth, 20);
		do_random(&mgr->counter_auth, 20);
		break;
	case NV_AUTH_UPDATE:
		mgr->root_seals_valid = 0;
		memcpy(&prev, &mgr->nvram_auth, 20);
		do_random(&mgr->nvram_auth, 20);
		break;
	}

	disk_write_all(mgr);

	switch (depth) {
	case SEQ_UPDATE:
		break;

	case CTR_UPDATE:
		rc = TPM_disk_incr_counter(mgr->counter_index, mgr->counter_auth);
		if (rc) {
			uint32_t ctr = be32_native(mgr->counter_value);
			mgr->counter_value = native_be32(ctr - 1);
			mgr->active_root = old_active_root;
			return rc;
		}
		break;

	case MGR_KEY_UPDATE:
		rc = TPM_disk_nvwrite(&mgr->nv_key, 16, mgr->nvram_slot, mgr->nvram_auth);
		if (rc)
			abort();
		break;

	case CTR_AUTH_UPDATE:
		rc = TPM_disk_change_counter(mgr->counter_index, prev, mgr->counter_auth);
		if (rc)
			abort();
		break;

	case NV_AUTH_UPDATE:
		rc = TPM_disk_nvchange(mgr->nvram_slot, prev, mgr->nvram_auth);
		if (rc)
			abort();
		break;
	}

	return rc;
}

static struct mem_group_hdr* find_mem_group_hdr(struct mem_tpm_mgr *mgr, struct mem_group *group)
{
	int i;
	for (i = 0; i < mgr->nr_groups; i++) {
		struct mem_group_hdr *hdr = mgr->groups + i;
		if (hdr->v == group)
			return hdr;
	}
	return NULL;
}

int vtpm_sync_group(struct mem_group *group, int depth)
{
	struct mem_group_hdr* hdr = find_mem_group_hdr(g_mgr, group);
	uint64_t seq = be64_native(group->details.sequence);

	if (!hdr)
		abort();

	hdr->disk_loc.value = 0;
	group->details.sequence = native_be64(1 + seq);

	if (depth == GROUP_KEY_UPDATE) {
		int i;
		do_random(&group->group_key, 16);
		do_random(&group->rollback_mac_key, 16);
		group->flags &= ~MEM_GROUP_FLAG_SEAL_VALID;
		for (i = 0; i < group->nr_pages; i++)
			group->data[i].disk_loc.value = 0;
		depth = CTR_UPDATE;
	}

	return vtpm_sync_disk(g_mgr, depth);
}

static struct mem_vtpm_page* find_mem_vtpm_page(struct mem_group *group, struct mem_vtpm *vtpm)
{
	int pgidx = vtpm->index_in_parent / VTPMS_PER_SECTOR;
	return group->data + pgidx;
}

int vtpm_sync(struct mem_group *group, struct mem_vtpm *vtpm)
{
	struct mem_vtpm_page *pg = find_mem_vtpm_page(group, vtpm);
	if (!pg)
		return 1;
	pg->disk_loc.value = 0;
	return vtpm_sync_group(group, SEQ_UPDATE);
}

/************************************************************************/

int create_vtpm(struct mem_group *group, struct mem_vtpm **vtpmp, const uuid_t uuid)
{
	int pgidx = group->nr_vtpms / VTPMS_PER_SECTOR;
	int vtidx = group->nr_vtpms % VTPMS_PER_SECTOR;
	struct mem_vtpm *vtpm = calloc(1, sizeof(*vtpm));

	struct mem_vtpm_page *page = group->data + pgidx;
	if (pgidx >= group->nr_pages) {
		if (pgidx != group->nr_pages)
			abort(); // nr_vtpms inconsistent with nr_pages
		group->nr_pages++;
		group->data = realloc(group->data, group->nr_pages * sizeof(*page));
		page = group->data + pgidx;
		memset(page, 0, sizeof(*page));
	}
	if (page->size != vtidx)
		abort(); // nr_vtpms inconsistent with page->size
	page->size++;

	page->vtpms[vtidx] = vtpm;
	vtpm->index_in_parent = group->nr_vtpms;
	vtpm->flags = 0;

	group->nr_vtpms++;

	memcpy(vtpm->uuid, uuid, 16);
	*vtpmp = vtpm;
	return 0;
}

int delete_vtpm(struct mem_group *group, struct mem_vtpm *vtpm)
{
	struct mem_vtpm_page *pg = find_mem_vtpm_page(group, vtpm);
	struct mem_vtpm_page *last_pg = group->data + (group->nr_pages - 1);
	struct mem_vtpm *last = last_pg->vtpms[last_pg->size - 1];
	int vtidx = vtpm->index_in_parent % VTPMS_PER_SECTOR;

	if (vtpm->flags & VTPM_FLAG_OPEN)
		return 1;

	last->index_in_parent = vtpm->index_in_parent;
	pg->vtpms[vtidx] = last;
	pg->disk_loc.value = 0;

	last_pg->vtpms[last_pg->size - 1] = NULL;
	last_pg->disk_loc.value = 0;
	last_pg->size--;

	if (last_pg->size == 0)
		group->nr_pages--;
	group->nr_vtpms--;
	free(vtpm);
	return 0;
}

int find_vtpm(struct mem_group **groupp, struct mem_vtpm **vtpmp, const uuid_t uuid)
{
	struct mem_group *group;
	int i, j, k;

	for (i = 0; i < g_mgr->nr_groups; i++) {
		group = g_mgr->groups[i].v;
		if (!group)
			continue;
		for (j = 0; j < group->nr_pages; j++) {
			struct mem_vtpm_page *pg = &group->data[j];
			for (k = 0; k < pg->size; k++) {
				struct mem_vtpm *vt = pg->vtpms[k];
				if (!memcmp(uuid, vt->uuid, 16)) {
					*groupp = group;
					*vtpmp = vt;
					return 0;
				}
			}
		}
	}

	return 1;
}
