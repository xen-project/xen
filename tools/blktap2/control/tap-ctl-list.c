/*
 * Copyright (c) 2008, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <glob.h>

#include "tap-ctl.h"
#include "blktap2.h"
#include "list.h"

static void
free_list(tap_list_t *entry)
{
	if (entry->type) {
		free(entry->type);
		entry->type = NULL;
	}

	if (entry->path) {
		free(entry->path);
		entry->path = NULL;
	}

	free(entry);
}

int
_parse_params(const char *params, char **type, char **path)
{
	char *ptr;
	size_t len;

	ptr = strchr(params, ':');
	if (!ptr)
		return -EINVAL;

	len = ptr - params;

	*type = strndup(params, len);
	*path =  strdup(params + len + 1);

	if (!*type || !*path) {
		free(*type);
		*type = NULL;

		free(*path);
		*path = NULL;

		return -errno;
	}

	return 0;
}

static int
init_list(tap_list_t *entry,
	  int tap_id, pid_t tap_pid, int vbd_minor, int vbd_state,
	  const char *params)
{
	int err = 0;

	entry->id     = tap_id;
	entry->pid    = tap_pid;
	entry->minor  = vbd_minor;
	entry->state  = vbd_state;

	if (params)
		err = _parse_params(params, &entry->type, &entry->path);

	return err;
}

void
tap_ctl_free_list(tap_list_t **list)
{
	tap_list_t **_entry;

	for (_entry = list; *_entry != NULL; ++_entry)
		free_list(*_entry);

	free(list);
}

static tap_list_t**
tap_ctl_alloc_list(int n)
{
	tap_list_t **list, *entry;
	size_t size;
	int i;

	size = sizeof(tap_list_t*) * (n+1);
	list = malloc(size);
	if (!list)
		goto fail;

	memset(list, 0, size);

	for (i = 0; i < n; ++i) {
		tap_list_t *entry;

		entry = malloc(sizeof(tap_list_t));
		if (!entry)
			goto fail;

		memset(entry, 0, sizeof(tap_list_t));

		list[i] = entry;
	}

	return list;

fail:
	if (list)
		tap_ctl_free_list(list);

	return NULL;
}

static int
tap_ctl_list_length(const tap_list_t **list)
{
	const tap_list_t **_entry;
	int n;

	n = 0;
	for (_entry = list; *_entry != NULL; ++_entry)
		n++;

	return n;
}

static int
_tap_minor_cmp(const void *a, const void *b)
{
	return *(int*)a - *(int*)b;
}

int
_tap_ctl_find_minors(int **_minorv)
{
	glob_t glbuf = { 0 };
	const char *pattern, *format;
	int *minorv = NULL, n_minors = 0;
	int err, i;

	pattern = BLKTAP2_SYSFS_DIR"/blktap*";
	format  = BLKTAP2_SYSFS_DIR"/blktap%d";

	n_minors = 0;
	minorv   = NULL;

	err = glob(pattern, 0, NULL, &glbuf);
	switch (err) {
	case GLOB_NOMATCH:
		goto done;

	case GLOB_ABORTED:
	case GLOB_NOSPACE:
		err = -errno;
		EPRINTF("%s: glob failed, err %d", pattern, err);
		goto fail;
	}

	minorv = malloc(sizeof(int) * glbuf.gl_pathc);
	if (!minorv) {
		err = -errno;
		goto fail;
	}

	for (i = 0; i < glbuf.gl_pathc; ++i) {
		int n;

		n = sscanf(glbuf.gl_pathv[i], format, &minorv[n_minors]);
		if (n != 1)
			continue;

		n_minors++;
	}

	qsort(minorv, n_minors, sizeof(int), _tap_minor_cmp);

done:
	*_minorv = minorv;
	err = 0;

out:
	if (glbuf.gl_pathv)
		globfree(&glbuf);

	return err ? : n_minors;

fail:
	if (minorv)
		free(minorv);

	goto out;
}

struct tapdisk {
	int    id;
	pid_t  pid;
	struct list_head list;
};

static int
_tap_tapdisk_cmp(const void *a, const void *b)
{
	return ((struct tapdisk*)a)->id - ((struct tapdisk*)b)->id;
}

int
_tap_ctl_find_tapdisks(struct tapdisk **_tapv)
{
	glob_t glbuf = { 0 };
	const char *pattern, *format;
	struct tapdisk *tapv = NULL;
	int err, i, n_taps = 0;

	pattern = BLKTAP2_CONTROL_DIR"/"BLKTAP2_CONTROL_SOCKET"*";
	format  = BLKTAP2_CONTROL_DIR"/"BLKTAP2_CONTROL_SOCKET"%d";

	n_taps = 0;
	tapv   = NULL;

	err = glob(pattern, 0, NULL, &glbuf);
	switch (err) {
	case GLOB_NOMATCH:
		goto done;

	case GLOB_ABORTED:
	case GLOB_NOSPACE:
		err = -errno;
		EPRINTF("%s: glob failed, err %d", pattern, err);
		goto fail;
	}

	tapv = malloc(sizeof(struct tapdisk) * glbuf.gl_pathc);
	if (!tapv) {
		err = -errno;
		goto fail;
	}

	for (i = 0; i < glbuf.gl_pathc; ++i) {
		struct tapdisk *tap;
		int n;

		tap = &tapv[n_taps];

		err = sscanf(glbuf.gl_pathv[i], format, &tap->id);
		if (err != 1)
			continue;

		tap->pid = tap_ctl_get_pid(tap->id);
		if (tap->pid < 0)
			continue;

		n_taps++;
	}

	qsort(tapv, n_taps, sizeof(struct tapdisk), _tap_tapdisk_cmp);

	for (i = 0; i < n_taps; ++i)
		INIT_LIST_HEAD(&tapv[i].list);

done:
	*_tapv = tapv;
	err = 0;

out:
	if (glbuf.gl_pathv)
		globfree(&glbuf);

	return err ? : n_taps;

fail:
	if (tapv)
		free(tapv);

	goto out;
}

struct tapdisk_list {
	int  minor;
	int  state;
	char *params;
	struct list_head entry;
};

int
_tap_ctl_list_tapdisk(int id, struct list_head *_list)
{
	tapdisk_message_t message;
	struct list_head list;
	struct tapdisk_list *tl, *next;
	int err, sfd;

	err = tap_ctl_connect_id(id, &sfd);
	if (err)
		return err;

	memset(&message, 0, sizeof(message));
	message.type   = TAPDISK_MESSAGE_LIST;
	message.cookie = -1;

	err = tap_ctl_write_message(sfd, &message, 2);
	if (err)
		return err;

	INIT_LIST_HEAD(&list);
	do {
		err = tap_ctl_read_message(sfd, &message, 2);
		if (err) {
			err = -EPROTO;
			break;
		}

		if (message.u.list.count == 0)
			break;

		tl = malloc(sizeof(struct tapdisk_list));
		if (!tl) {
			err = -ENOMEM;
			break;
		}

		tl->minor  = message.u.list.minor;
		tl->state  = message.u.list.state;
		if (message.u.list.path[0] != 0) {
			tl->params = strndup(message.u.list.path,
					     sizeof(message.u.list.path));
			if (!tl->params) {
				err = -errno;
				break;
			}
		} else
			tl->params = NULL;

		list_add(&tl->entry, &list);
	} while (1);

	if (err)
		list_for_each_entry_safe(tl, next, &list, entry) {
			list_del(&tl->entry);
			free(tl->params);
			free(tl);
		}

	close(sfd);
	list_splice(&list, _list);
	return err;
}

void
_tap_ctl_free_tapdisks(struct tapdisk *tapv, int n_taps)
{
	struct tapdisk *tap;

	for (tap = tapv; tap < &tapv[n_taps]; ++tap) {
		struct tapdisk_list *tl, *next;

		list_for_each_entry_safe(tl, next, &tap->list, entry) {
			free(tl->params);
			free(tl);
		}
	}

	free(tapv);
}

int
_tap_list_join3(int n_minors, int *minorv, int n_taps, struct tapdisk *tapv,
		tap_list_t ***_list)
{
	tap_list_t **list, **_entry, *entry;
	int i, _m, err;

	list = tap_ctl_alloc_list(n_minors + n_taps);
	if (!list) {
		err = -ENOMEM;
		goto fail;
	}

	_entry = list;

	for (i = 0; i < n_taps; ++i) {
		struct tapdisk *tap = &tapv[i];
		struct tapdisk_list *tl;

		/* orphaned tapdisk */
		if (list_empty(&tap->list)) {
			err = init_list(*_entry++, tap->id, tap->pid, -1, -1, NULL);
			if (err)
				goto fail;
			continue;
		}

		list_for_each_entry(tl, &tap->list, entry) {

			err = init_list(*_entry++,
					tap->id, tap->pid,
					tl->minor, tl->state, tl->params);
			if (err)
				goto fail;

			if (tl->minor >= 0) {
				/* clear minor */
				for (_m = 0; _m < n_minors; ++_m) {
					if (minorv[_m] == tl->minor) {
						minorv[_m] = -1;
						break;
					}
				}
			}
		}
	}

	/* orphaned minors */
	for (_m = 0; _m < n_minors; ++_m) {
		int minor = minorv[_m];
		if (minor >= 0) {
			err = init_list(*_entry++, -1, -1, minor, -1, NULL);
			if (err)
				goto fail;
		}
	}

	/* free extraneous list entries */
	for (; *_entry != NULL; ++entry) {
		free_list(*_entry);
		*_entry = NULL;
	}

	*_list = list;

	return 0;

fail:
	if (list)
		tap_ctl_free_list(list);

	return err;
}

int
tap_ctl_list(tap_list_t ***list)
{
	int n_taps, n_minors, err, *minorv;
	struct tapdisk *tapv, *tap;

	n_taps   = -1;
	n_minors = -1;

	err = n_minors = _tap_ctl_find_minors(&minorv);
	if (err < 0)
		goto out;

	err = n_taps = _tap_ctl_find_tapdisks(&tapv);
	if (err < 0)
		goto out;

	for (tap = tapv; tap < &tapv[n_taps]; ++tap) {
		err = _tap_ctl_list_tapdisk(tap->id, &tap->list);
		if (err)
			goto out;
	}

	err = _tap_list_join3(n_minors, minorv, n_taps, tapv, list);

out:
	if (n_taps > 0)
		_tap_ctl_free_tapdisks(tapv, n_taps);

	if (n_minors > 0)
		free(minorv);

	return err;
}

int
tap_ctl_find(const char *type, const char *path, tap_list_t *tap)
{
	tap_list_t **list, **_entry;
	int ret = -ENOENT, err;

	err = tap_ctl_list(&list);
	if (err)
		return err;

	for (_entry = list; *_entry != NULL; ++_entry) {
		tap_list_t *entry  = *_entry;

		if (type && (!entry->type || strcmp(entry->type, type)))
			continue;

		if (path && (!entry->path || strcmp(entry->path, path)))
			continue;

		*tap = *entry;
		tap->type = tap->path = NULL;
		ret = 0;
		break;
	}

	tap_ctl_free_list(list);

	return ret;
}
