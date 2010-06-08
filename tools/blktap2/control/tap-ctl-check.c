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
#include <unistd.h>
#include <string.h>

#include "tap-ctl.h"
#include "blktap2.h"

int
tap_ctl_check_blktap(const char **msg)
{
	FILE *f;
	int err = 0, minor;
	char name[32];

	memset(name, 0, sizeof(name));

	f = fopen("/proc/misc", "r");
	if (!f) {
		*msg = "failed to open /proc/misc";
		return -errno;
	}

	while (fscanf(f, "%d %32s", &minor, name) == 2) {
		if (!strcmp(name, BLKTAP2_CONTROL_NAME))
			goto out;
	}

	err = -ENOSYS;
	*msg = "blktap kernel module not installed";

out:
	fclose(f);
	return err;
}

int
tap_ctl_check(const char **msg)
{
	int err;
	uid_t uid;

	err = tap_ctl_check_blktap(msg);
	if (err)
		goto out;

	err  = 0;
	*msg = "ok";

out:
	return err;
}
