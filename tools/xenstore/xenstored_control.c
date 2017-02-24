/*
    Interactive commands for Xen Store Daemon.
    Copyright (C) 2017 Juergen Gross, SUSE Linux GmbH

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>

#include "utils.h"
#include "xenstored_core.h"
#include "xenstored_control.h"

int do_control(struct connection *conn, struct buffered_data *in)
{
	int num;

	if (conn->id != 0)
		return EACCES;

	num = xs_count_strings(in->buffer, in->used);

	if (streq(in->buffer, "print")) {
		if (num < 2)
			return EINVAL;
		xprintf("control: %s", in->buffer + strlen(in->buffer) + 1);
	}

	if (streq(in->buffer, "check"))
		check_store();

	send_ack(conn, XS_CONTROL);

	return 0;
}
