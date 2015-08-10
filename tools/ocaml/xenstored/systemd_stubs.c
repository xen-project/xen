/*
 * Copyright (C) 2014 Luis R. Rodriguez <mcgrof@suse.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/signals.h>
#include <caml/fail.h>

#if defined(HAVE_SYSTEMD)

#include <sys/socket.h>
#include <systemd/sd-daemon.h>

/* Will work regardless of the order systemd gives them to us */
static int oxen_get_sd_fd(const char *connect_to)
{
	int fd = SD_LISTEN_FDS_START;
	int r;

	while (fd <= SD_LISTEN_FDS_START + 1) {
		r = sd_is_socket_unix(fd, SOCK_STREAM, 1, connect_to, 0);
		if (r > 0)
			return fd;
		fd++;
	}

	return -EBADR;
}

static int oxen_verify_socket_socket(const char *connect_to)
{
	if ((strcmp("/var/run/xenstored/socket_ro", connect_to) != 0) &&
	    (strcmp("/var/run/xenstored/socket", connect_to) != 0)) {
		sd_notifyf(0, "STATUS=unexpected socket: %s\n"
			   "ERRNO=%i",
			   connect_to,
			   EBADR);
		return -EBADR;
	}

	return oxen_get_sd_fd(connect_to);
}

CAMLprim value ocaml_sd_listen_fds(value connect_to)
{
	CAMLparam1(connect_to);
	CAMLlocal1(sock_ret);
	int sock = -EBADR, n;

	n = sd_listen_fds(0);
	if (n <= 0) {
		sd_notifyf(0, "STATUS=Failed to get any active sockets: %s\n"
			   "ERRNO=%i",
			   strerror(errno),
			   errno);
		caml_failwith("ocaml_sd_listen_fds() failed to get any sockets");
	} else if (n != 2) {
		fprintf(stderr, SD_ERR "Expected 2 fds but given %d\n", n);
		sd_notifyf(0, "STATUS=Mismatch on number (2): %s\n"
			   "ERRNO=%d",
			   strerror(EBADR),
			   EBADR);
		caml_failwith("ocaml_sd_listen_fds() mismatch");
	}

	sock = oxen_verify_socket_socket(String_val(connect_to));
	if (sock <= 0) {
		fprintf(stderr, "failed to verify sock %s\n",
			String_val(connect_to));
		caml_failwith("ocaml_sd_listen_fds_init() invalid socket");
	}

	sock_ret = Val_int(sock);

	CAMLreturn(sock_ret);
}

CAMLprim value ocaml_launched_by_systemd(value ignore)
{
	CAMLparam1(ignore);
	CAMLlocal1(ret);

	ret = Val_false;

	if (sd_listen_fds(0) > 0)
		ret = Val_true;

	CAMLreturn(ret);
}

CAMLprim value ocaml_sd_notify_ready(value ignore)
{
	CAMLparam1(ignore);
	CAMLlocal1(ret);

	ret = Val_int(0);

	sd_notify(1, "READY=1");

	CAMLreturn(ret);
}

#else

CAMLprim value ocaml_sd_listen_fds(value connect_to)
{
	CAMLparam1(connect_to);
	CAMLlocal1(sock_ret);

	sock_ret = Val_int(-1);

	CAMLreturn(sock_ret);
}

CAMLprim value ocaml_launched_by_systemd(value ignore)
{
	CAMLparam1(ignore);
	CAMLlocal1(ret);

	ret = Val_false;

	CAMLreturn(ret);
}

CAMLprim value ocaml_sd_notify_ready(value ignore)
{
	CAMLparam1(ignore);
	CAMLlocal1(ret);

	ret = Val_int(-1);

	CAMLreturn(ret);
}
#endif
