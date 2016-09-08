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
#include <stdlib.h>

#include "tapdisk-driver.h"
#include "tapdisk-server.h"
#include "tapdisk-disktype.h"

td_driver_t *
tapdisk_driver_allocate(int type, char *name, td_flag_t flags, int storage)
{
	int err;
	td_driver_t *driver;
	const struct tap_disk *ops;

	ops = tapdisk_disk_drivers[type];
	if (!ops)
		return NULL;

	driver = calloc(1, sizeof(td_driver_t));
	if (!driver)
		return NULL;

	err = tapdisk_namedup(&driver->name, name);
	if (err)
		goto fail;

	driver->ops     = ops;
	driver->type    = type;
	driver->storage = storage;
	driver->data    = calloc(1, ops->private_data_size);
	if (!driver->data)
		goto fail;

	if (td_flag_test(flags, TD_OPEN_RDONLY))
		td_flag_set(driver->state, TD_DRIVER_RDONLY);

	return driver;

fail:
	free(driver->name);
	free(driver->data);
	free(driver);
	return NULL;
}

void
tapdisk_driver_free(td_driver_t *driver)
{
	if (!driver)
		return;

	if (driver->refcnt)
		return;

	if (td_flag_test(driver->state, TD_DRIVER_OPEN))
		EPRINTF("freeing open driver %s (state 0x%08x)\n",
			driver->name, driver->state);

	free(driver->name);
	free(driver->data);
	free(driver);
}

void
tapdisk_driver_queue_tiocb(td_driver_t *driver, struct tiocb *tiocb)
{
	tapdisk_server_queue_tiocb(tiocb);
}

void
tapdisk_driver_debug(td_driver_t *driver)
{
	if (driver->ops->td_debug)
		driver->ops->td_debug(driver);
}
